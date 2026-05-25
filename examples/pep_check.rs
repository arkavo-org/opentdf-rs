//! Example PEP: take a platform access_token and run a local ALLOW/DENY check.
//!
//! End-to-end story: authnz-rs → opentdf-platform → opentdf-rs.
//!
//! The platform's `POST /v2/authorization/token` endpoint now returns a
//! **CWT** by default (RFC 8392 COSE_Sign1 / ES256, raw CBOR body with
//! content-type `application/cwt+cbor`). This example takes that CWT —
//! base64url-encoded for CLI convenience — verifies it against the
//! platform's published COSE Key Set (or by inspection only with
//! `--insecure`), extracts the `authorization_details` claim, and runs
//! [`opentdf::pdp::AccessPdp::check`] against a supplied (action, resource)
//! tuple.
//!
//! ## Quick start
//!
//! ```bash
//! # 1. Get a CWT from the platform (default response type now).
//! curl -X POST http://localhost:8080/v2/authorization/token \
//!   -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
//!   -d subject_token=<CWT_FROM_AUTHNZ_RS> \
//!   -d subject_token_type=urn:ietf:params:oauth:token-type:cwt \
//!   --output /tmp/token.cwt
//!
//! # 2. Base64url-encode the bytes for the CLI.
//! TOKEN=$(base64 < /tmp/token.cwt | tr -d '=' | tr '/+' '_-')
//!
//! # 3. Run the PEP check.
//! cargo run --example pep_check -- \
//!   --token "$TOKEN" \
//!   --action read \
//!   --resource https://example.com/attr/classification/value/secret \
//!   --cose-keys-url http://localhost:8080/v2/authorization/cose-keys
//! ```
//!
//! ## JWT fallback
//!
//! Clients that opt back into the JSON envelope by sending
//! `requested_token_type=urn:ietf:params:oauth:token-type:jwt` to the
//! platform get a JWT. Pass `--format jwt` here to decode that path
//! instead (no signature verification — example only).
//!
//! The bundled policy matches `integrationPolicy` in
//! `opentdf-platform/service/authorization/v2/rar_test.go` so a token from a
//! local platform configured against that fixture exchanges cleanly.

use std::collections::HashMap;
use std::fs;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::Value as CborValue;
use clap::{Parser, ValueEnum};
use coset::{CborSerializable, CoseKey, CoseSign1};
use opentdf::pdp::{
    AccessDecision, AccessPdp, Action, Attribute, AttributeRule, Entitlements, PdpOptions, Value,
};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

const GRANT_TYPE_ATTRIBUTE: &str = "opentdf_attribute";
const AUTHORIZATION_DETAILS_CLAIM: &str = "authorization_details";

#[derive(Parser)]
#[command(about = "Local ALLOW/DENY check against a platform-issued access_token")]
struct Args {
    /// Access token returned by POST /v2/authorization/token.
    /// For CWT (default): base64url-encoded COSE_Sign1 bytes.
    /// For JWT: the standard three-segment JWT string.
    #[arg(long)]
    token: String,

    /// Token format. Defaults to CWT (the platform's new default).
    #[arg(long, value_enum, default_value_t = TokenFormat::Cwt)]
    format: TokenFormat,

    /// Path or URL to the platform's COSE Key Set
    /// (typically `<base>/v2/authorization/cose-keys`). When omitted with
    /// CWT, signature verification is skipped — pair with `--insecure`
    /// to acknowledge that.
    #[arg(long)]
    cose_keys_url: Option<String>,

    /// Skip CWT signature verification. Convenient for local debugging;
    /// never in production.
    #[arg(long)]
    insecure: bool,

    /// Action verb to check (e.g. read, create, update).
    #[arg(long, default_value = "read")]
    action: String,

    /// Attribute value FQN(s) tagged on the resource being requested.
    /// Repeat for multi-tag resources.
    #[arg(long, required = true)]
    resource: Vec<String>,

    /// Dump extracted entitlements before deciding.
    #[arg(long)]
    verbose: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum TokenFormat {
    Cwt,
    Jwt,
}

#[derive(Debug)]
struct Grant {
    grant_type: String,
    actions: Vec<String>,
    locations: Vec<String>,
    obligations: Vec<String>,
}

fn main() {
    let args = Args::parse();
    match run(&args) {
        Ok(decision) => exit_with(decision, args.verbose),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    }
}

fn run(args: &Args) -> Result<AccessDecision, Box<dyn std::error::Error>> {
    let grants = match args.format {
        TokenFormat::Cwt => grants_from_cwt(args)?,
        TokenFormat::Jwt => grants_from_jwt(&args.token)?,
    };
    if grants.is_empty() {
        return Err(
            "token has no authorization_details; was it minted by /v2/authorization/token?".into(),
        );
    }
    let entitlements = entitlements_from_grants(&grants);

    if args.verbose {
        eprintln!("Decoded {} grant(s):", grants.len());
        for g in &grants {
            eprintln!(
                "  type={} actions={:?} locations={:?} obligations={:?}",
                g.grant_type, g.actions, g.locations, g.obligations
            );
        }
        eprintln!();
        eprintln!("Flattened to {} entitlement(s):", entitlements.len());
        for (fqn, actions) in &entitlements {
            eprintln!("  {fqn} → {actions:?}");
        }
        eprintln!();
        eprintln!(
            "Checking action={} against resource={:?}",
            args.action, args.resource
        );
    }

    let pdp = AccessPdp::new(default_policy(), PdpOptions::default())?;
    Ok(pdp.check(&entitlements, &Action::new(&args.action), &args.resource)?)
}

fn exit_with(decision: AccessDecision, _verbose: bool) {
    match decision {
        AccessDecision::Allow => {
            println!("ALLOW");
            std::process::exit(0);
        }
        AccessDecision::Deny { failures } => {
            println!("DENY");
            for f in failures {
                println!("  - {} (action: {})", f.attribute_value_fqn, f.action_name);
            }
            std::process::exit(1);
        }
    }
}

// --- CWT path ---------------------------------------------------------------

fn grants_from_cwt(args: &Args) -> Result<Vec<Grant>, Box<dyn std::error::Error>> {
    let raw = URL_SAFE_NO_PAD
        .decode(&args.token)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&args.token))?;
    // Strip the RFC 8392 §6 CWT tag prefix (0xd8, 0x3d) if present so coset
    // can parse the bare COSE_Sign1.
    let bytes = if raw.starts_with(&[0xd8, 0x3d]) {
        &raw[2..]
    } else {
        raw.as_slice()
    };

    let cose1 = CoseSign1::from_slice(bytes).map_err(|e| format!("parse COSE_Sign1: {e:?}"))?;

    if !args.insecure {
        let url = args
            .cose_keys_url
            .as_deref()
            .ok_or("--cose-keys-url is required unless --insecure is set")?;
        let key_set_bytes = fetch_or_read(url)?;
        verify_cose_sign1(&cose1, &key_set_bytes)?;
    }

    let payload = cose1.payload.ok_or("CWT payload is empty")?;
    parse_authorization_details(&payload)
}

/// Fetch the COSE Key Set from an HTTP URL or read it from a local file path.
fn fetch_or_read(url_or_path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if url_or_path.starts_with("http://") || url_or_path.starts_with("https://") {
        // Minimal blocking fetch via std (no extra dep). For real PEPs use reqwest.
        let resp = ureq_get(url_or_path)?;
        Ok(resp)
    } else {
        Ok(fs::read(url_or_path)?)
    }
}

/// Tiny std-only HTTP GET. Returns the body bytes on 2xx, error otherwise.
/// Production code should use reqwest or a similar client — this is just
/// enough to demo the verify flow without adding a dep.
fn ureq_get(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let (scheme, rest) = url.split_once("://").ok_or("malformed url")?;
    if scheme != "http" {
        return Err(format!(
            "this example's tiny HTTP client only supports http://; use --cose-keys-url \
             pointing at a local file or wire reqwest in for {scheme}"
        )
        .into());
    }
    let (host_port, path) = rest
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((rest, "/".into()));
    let host_port = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:80")
    };
    let host = host_port.split(':').next().unwrap();

    let mut stream = TcpStream::connect(&host_port)?;
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nAccept: application/cose-key-set+cbor\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes())?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;

    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no headers/body split")?;
    let head = std::str::from_utf8(&buf[..split]).unwrap_or("");
    if !head.lines().next().unwrap_or("").contains(" 200 ") {
        return Err(format!(
            "cose-keys fetch failed: {}",
            head.lines().next().unwrap_or("")
        )
        .into());
    }
    Ok(buf[split + 4..].to_vec())
}

fn verify_cose_sign1(
    cose1: &CoseSign1,
    cose_key_set_cbor: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    // The platform publishes a CBOR array of COSE_Keys. Parse and try each.
    let value: CborValue = ciborium::de::from_reader(cose_key_set_cbor)
        .map_err(|e| format!("parse COSE Key Set: {e}"))?;
    let arr = match value {
        CborValue::Array(a) => a,
        _ => return Err("COSE Key Set is not a CBOR array".into()),
    };
    for k in arr {
        let bytes = serialize_cbor(&k)?;
        let cose_key = match CoseKey::from_slice(&bytes) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let pubkey = match ec2_to_p256(&cose_key) {
            Some(p) => p,
            None => continue,
        };
        let verified = cose1.verify_signature(&[], |sig, payload| {
            let s = Signature::from_slice(sig).map_err(|e| format!("bad sig bytes: {e}"))?;
            pubkey
                .verify(payload, &s)
                .map_err(|e| format!("verify: {e}"))
        });
        if verified.is_ok() {
            return Ok(());
        }
    }
    Err("no key in the published COSE Key Set verified the CWT signature".into())
}

fn serialize_cbor(v: &CborValue) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(v, &mut out)?;
    Ok(out)
}

/// Byte length of an X9.62 P-256 coordinate.
const P256_COORD_LEN: usize = 32;

/// Pull X/Y out of an EC2 COSE_Key on P-256, build a SEC1 uncompressed
/// point, and parse as a p256 VerifyingKey.
///
/// COSE_Key coordinates can legitimately arrive shorter than the curve's
/// natural byte length when their leading bytes are zero (CBOR / big-int
/// representations strip these). SEC1 uncompressed points require fixed
/// 32-byte coordinates for P-256, so left-pad each to length before
/// concatenating; reject anything that's too long (a sign the input isn't
/// a P-256 point).
fn ec2_to_p256(k: &CoseKey) -> Option<VerifyingKey> {
    let mut x: Option<Vec<u8>> = None;
    let mut y: Option<Vec<u8>> = None;
    for (label, value) in &k.params {
        // EC2 keys: -2 = X, -3 = Y per RFC 9052.
        let label_int = match label {
            coset::Label::Int(i) => *i,
            _ => continue,
        };
        let bytes = match value {
            CborValue::Bytes(b) => b.clone(),
            _ => continue,
        };
        match label_int {
            -2 => x = Some(bytes),
            -3 => y = Some(bytes),
            _ => {}
        }
    }
    let x = pad_p256_coord(&x?)?;
    let y = pad_p256_coord(&y?)?;
    let mut sec1 = Vec::with_capacity(1 + 2 * P256_COORD_LEN);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    VerifyingKey::from_sec1_bytes(&sec1).ok()
}

/// Left-pad an X9.62 coordinate to [`P256_COORD_LEN`] bytes. Returns
/// `None` if the input is already longer than the curve coordinate
/// length, which would indicate the COSE key is not on P-256.
fn pad_p256_coord(b: &[u8]) -> Option<[u8; P256_COORD_LEN]> {
    if b.len() > P256_COORD_LEN {
        return None;
    }
    let mut out = [0u8; P256_COORD_LEN];
    out[P256_COORD_LEN - b.len()..].copy_from_slice(b);
    Some(out)
}

fn parse_authorization_details(payload: &[u8]) -> Result<Vec<Grant>, Box<dyn std::error::Error>> {
    let value: CborValue =
        ciborium::de::from_reader(payload).map_err(|e| format!("decode CWT claims: {e}"))?;
    let map = match value {
        CborValue::Map(m) => m,
        _ => return Err("CWT claims is not a CBOR map".into()),
    };
    for (k, v) in map {
        if let CborValue::Text(name) = k
            && name == AUTHORIZATION_DETAILS_CLAIM
        {
            return parse_grants_array(&v);
        }
    }
    Ok(Vec::new())
}

fn parse_grants_array(v: &CborValue) -> Result<Vec<Grant>, Box<dyn std::error::Error>> {
    let arr = match v {
        CborValue::Array(a) => a,
        _ => return Err("authorization_details is not a CBOR array".into()),
    };
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        if let Some(g) = parse_grant(entry)? {
            out.push(g);
        }
    }
    Ok(out)
}

fn parse_grant(v: &CborValue) -> Result<Option<Grant>, Box<dyn std::error::Error>> {
    let m = match v {
        CborValue::Map(m) => m,
        _ => return Ok(None),
    };
    let mut g = Grant {
        grant_type: String::new(),
        actions: Vec::new(),
        locations: Vec::new(),
        obligations: Vec::new(),
    };
    for (k, val) in m {
        let key = match k {
            CborValue::Text(s) => s.as_str(),
            _ => continue,
        };
        match key {
            "type" => {
                if let CborValue::Text(s) = val {
                    g.grant_type = s.clone();
                }
            }
            "actions" => g.actions = cbor_string_array(val),
            "locations" => g.locations = cbor_string_array(val),
            "obligations" => g.obligations = cbor_string_array(val),
            _ => {}
        }
    }
    Ok(Some(g))
}

fn cbor_string_array(v: &CborValue) -> Vec<String> {
    match v {
        CborValue::Array(a) => a
            .iter()
            .filter_map(|e| match e {
                CborValue::Text(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

// --- JWT path (kept for backwards compat / debugging) -----------------------

#[derive(serde::Deserialize)]
struct JwtClaims {
    #[serde(default)]
    authorization_details: Vec<JwtGrant>,
}

#[derive(serde::Deserialize)]
struct JwtGrant {
    #[serde(rename = "type")]
    grant_type: String,
    #[serde(default)]
    actions: Vec<String>,
    #[serde(default)]
    locations: Vec<String>,
    #[serde(default)]
    obligations: Vec<String>,
}

fn grants_from_jwt(jwt: &str) -> Result<Vec<Grant>, Box<dyn std::error::Error>> {
    let mut parts = jwt.split('.');
    let _header = parts.next().ok_or("malformed JWT: missing header")?;
    let payload = parts.next().ok_or("malformed JWT: missing payload")?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload)?;
    let claims: JwtClaims = serde_json::from_slice(&payload_bytes)?;
    Ok(claims
        .authorization_details
        .into_iter()
        .map(|g| Grant {
            grant_type: g.grant_type,
            actions: g.actions,
            locations: g.locations,
            obligations: g.obligations,
        })
        .collect())
}

// --- shared (CWT and JWT both produce a Vec<Grant>) -------------------------

fn entitlements_from_grants(grants: &[Grant]) -> Entitlements {
    let mut out: Entitlements = HashMap::new();
    for g in grants {
        if g.grant_type != GRANT_TYPE_ATTRIBUTE {
            continue;
        }
        for loc in &g.locations {
            let entry = out.entry(loc.to_ascii_lowercase()).or_default();
            for a in &g.actions {
                if !entry
                    .iter()
                    .any(|existing| existing.eq_ignore_ascii_case(a))
                {
                    entry.push(a.clone());
                }
            }
        }
    }
    out
}

/// In-memory attribute catalog the PDP evaluates against. Fork this for
/// your own policy; in a real PEP, build it from a periodic refresh of
/// the platform's attribute service.
fn default_policy() -> Vec<Attribute> {
    let class_def = "https://example.com/attr/classification";
    vec![Attribute {
        fqn: class_def.into(),
        rule: AttributeRule::AnyOf,
        values: vec![
            Value {
                fqn: format!("{class_def}/value/secret"),
                value: "secret".into(),
                ..Default::default()
            },
            Value {
                fqn: format!("{class_def}/value/public"),
                value: "public".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;

    fn make_test_jwt(claims: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        format!("{header}.{body}.")
    }

    #[test]
    fn jwt_path_extracts_grants() {
        let jwt = make_test_jwt(json!({
            "authorization_details": [{
                "type": "opentdf_attribute",
                "actions": ["read", "decrypt"],
                "locations": ["https://example.com/attr/classification/value/secret"]
            }]
        }));
        let grants = grants_from_jwt(&jwt).unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].actions, vec!["read", "decrypt"]);
    }

    #[test]
    fn cartesian_flatten_dedupes_per_fqn() {
        let grants = vec![
            Grant {
                grant_type: "opentdf_attribute".into(),
                actions: vec!["read".into()],
                locations: vec![
                    "https://example.com/attr/classification/value/secret".into(),
                    "https://example.com/attr/classification/value/public".into(),
                ],
                obligations: vec![],
            },
            // Overlap on secret: read action should not duplicate.
            Grant {
                grant_type: "opentdf_attribute".into(),
                actions: vec!["read".into(), "update".into()],
                locations: vec!["https://example.com/attr/classification/value/secret".into()],
                obligations: vec![],
            },
        ];
        let ents = entitlements_from_grants(&grants);
        let secret = ents
            .get("https://example.com/attr/classification/value/secret")
            .unwrap();
        assert_eq!(secret.len(), 2);
    }

    #[test]
    fn skips_non_attribute_grant_types() {
        let grants = vec![Grant {
            grant_type: "something_else".into(),
            actions: vec!["read".into()],
            locations: vec!["https://example.com/attr/classification/value/secret".into()],
            obligations: vec![],
        }];
        assert!(entitlements_from_grants(&grants).is_empty());
    }

    /// Round-trip: build a CWT payload like the platform would, decode it
    /// with parse_authorization_details, assert the grants come back.
    #[test]
    fn cwt_payload_parser_handles_platform_shape() {
        // CBOR map with text key "authorization_details" → array of one map.
        let mut payload = Vec::new();
        ciborium::ser::into_writer(
            &CborValue::Map(vec![(
                CborValue::Text("authorization_details".into()),
                CborValue::Array(vec![CborValue::Map(vec![
                    (
                        CborValue::Text("type".into()),
                        CborValue::Text("opentdf_attribute".into()),
                    ),
                    (
                        CborValue::Text("actions".into()),
                        CborValue::Array(vec![CborValue::Text("read".into())]),
                    ),
                    (
                        CborValue::Text("locations".into()),
                        CborValue::Array(vec![CborValue::Text(
                            "https://example.com/attr/classification/value/secret".into(),
                        )]),
                    ),
                ])]),
            )]),
            &mut payload,
        )
        .unwrap();
        let grants = parse_authorization_details(&payload).unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].grant_type, "opentdf_attribute");
        assert_eq!(grants[0].actions, vec!["read"]);
    }

    // Regression for the gitar-bot finding on PR #78: ec2_to_p256 used to
    // concatenate X/Y unpadded, so a coordinate with a leading zero byte
    // (legitimate; CBOR / big-int strips it) produced a 64-byte SEC1
    // string instead of 65 and from_sec1_bytes rejected it.
    #[test]
    fn pad_p256_coord_left_pads_short_input() {
        let padded = pad_p256_coord(&[0x42]).unwrap();
        assert_eq!(padded.len(), P256_COORD_LEN);
        assert_eq!(padded[P256_COORD_LEN - 1], 0x42);
        assert!(padded[..P256_COORD_LEN - 1].iter().all(|b| *b == 0));
    }

    #[test]
    fn pad_p256_coord_passes_through_full_length() {
        let input = [0xab; P256_COORD_LEN];
        let padded = pad_p256_coord(&input).unwrap();
        assert_eq!(padded, input);
    }

    #[test]
    fn pad_p256_coord_rejects_over_length() {
        // 33 bytes — would indicate a key that isn't on P-256.
        assert!(pad_p256_coord(&[0u8; P256_COORD_LEN + 1]).is_none());
    }
}
