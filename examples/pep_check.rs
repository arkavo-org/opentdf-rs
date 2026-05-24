//! Example PEP: take a platform access_token and run a local ALLOW/DENY check.
//!
//! This binary is the missing piece for the end-to-end walkthrough across
//! authnz-rs → opentdf-platform → opentdf-rs. It takes a JWT minted by the
//! platform's `POST /v2/authorization/token` endpoint, extracts the
//! `authorization_details` (RFC 9396) claim into an entitlement map, and
//! feeds it to [`opentdf::pdp::AccessPdp`] for a single resource check.
//!
//! ## Quick start
//!
//! ```bash
//! cargo run --example pep_check -- \
//!     --token <ACCESS_TOKEN_FROM_PLATFORM> \
//!     --action read \
//!     --resource https://example.com/attr/classification/value/secret
//! ```
//!
//! The bundled policy matches `integrationPolicy` in
//! `opentdf-platform/service/authorization/v2/rar_test.go` so a token from a
//! local platform configured against that fixture exchanges cleanly. For a
//! custom policy, fork [`default_policy`] below.
//!
//! ## End-to-end happy path (5 minutes)
//!
//! 1. **Stand up authnz-rs** (mints CWTs; publishes `/.well-known/cose-keys`).
//! 2. **Stand up opentdf-platform** with the CWT subject-token verifier
//!    enabled and `cose_keys_url` pointing at authnz-rs.
//! 3. **Get a CWT** from authnz-rs (WebAuthn or OIDC code exchange).
//! 4. **Exchange it** at the platform's token endpoint:
//!    ```bash
//!    curl -X POST http://localhost:8080/v2/authorization/token \
//!      -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
//!      -d subject_token=<CWT_B64URL> \
//!      -d subject_token_type=urn:ietf:params:oauth:token-type:cwt
//!    ```
//! 5. **Run this example** with the returned `access_token`.
//!
//! ## Production caveat
//!
//! This example does NOT verify the JWT signature — it only decodes the
//! payload. A real PEP must fetch the platform's JWKS from
//! `GET /v2/authorization/jwks.json` and verify the EdDSA signature before
//! trusting the embedded grants. See `opentdf::kas` and the `jsonwebtoken`
//! crate for verification patterns.

use std::collections::HashMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Parser;
use opentdf::pdp::{
    AccessDecision, AccessPdp, Action, Attribute, AttributeRule, Entitlements, PdpOptions, Value,
};
use serde::Deserialize;

const GRANT_TYPE_ATTRIBUTE: &str = "opentdf_attribute";

#[derive(Parser)]
#[command(about = "Local ALLOW/DENY check against a platform-issued access_token")]
struct Args {
    /// Access token returned by POST /v2/authorization/token (JWT, signed
    /// by the platform). Pass the full three-segment string.
    #[arg(long)]
    token: String,

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

/// JWT payload shape we care about — the `authorization_details` claim is
/// the only thing this PEP needs. Everything else (`sub`, `iss`, `exp`,
/// ...) is ignored here; a production PEP would verify those.
#[derive(Deserialize)]
struct Claims {
    #[serde(default)]
    authorization_details: Vec<Grant>,
}

/// One RFC 9396 grant as emitted by the platform's RAR endpoint. Matches
/// the `local.Grant` struct on the Go side.
#[derive(Deserialize, Debug)]
struct Grant {
    #[serde(rename = "type")]
    grant_type: String,
    #[serde(default)]
    actions: Vec<String>,
    #[serde(default)]
    locations: Vec<String>,
    #[serde(default)]
    obligations: Vec<String>,
}

fn main() {
    let args = Args::parse();

    let claims = match decode_jwt_claims(&args.token) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: cannot decode JWT payload: {e}");
            std::process::exit(2);
        }
    };

    if claims.authorization_details.is_empty() {
        eprintln!(
            "error: token has no authorization_details claim; was it minted by \
             the platform's /v2/authorization/token endpoint?"
        );
        std::process::exit(2);
    }

    let entitlements = entitlements_from_grants(&claims.authorization_details);

    if args.verbose {
        eprintln!("Decoded {} grant(s):", claims.authorization_details.len());
        for g in &claims.authorization_details {
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

    let pdp = match AccessPdp::new(default_policy(), PdpOptions::default()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: building PDP: {e}");
            std::process::exit(2);
        }
    };

    let decision = match pdp.check(&entitlements, &Action::new(&args.action), &args.resource) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: pdp check: {e}");
            std::process::exit(2);
        }
    };

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

/// Decode a JWT's payload (middle segment) without verifying the signature.
/// Caller is responsible for verification — this is example-only.
fn decode_jwt_claims(jwt: &str) -> Result<Claims, Box<dyn std::error::Error>> {
    let mut parts = jwt.split('.');
    let _header = parts.next().ok_or("malformed JWT: missing header")?;
    let payload = parts.next().ok_or("malformed JWT: missing payload")?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload)?;
    let claims: Claims = serde_json::from_slice(&payload_bytes)?;
    Ok(claims)
}

/// Flatten the platform's `authorization_details` grant array into the
/// per-FQN entitlement map [`AccessPdp::check`] expects. Each grant is a
/// Cartesian product of `actions × locations`, so a single grant covering
/// N actions across M locations becomes N entries per location.
///
/// Grants whose `type` is not `opentdf_attribute` are skipped — the platform
/// reserves other types for future use (registered resources, etc.).
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
/// your own policy; or, in a real PEP, build it from a periodic refresh of
/// the platform's attribute service.
///
/// The defaults below match the platform's `integrationPolicy` test fixture
/// (see `service/authorization/v2/rar_test.go`), so a token obtained from a
/// platform running that fixture decodes and decides cleanly.
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
        // unsigned alg=none JWT — fine for example tests, never for production.
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        format!("{header}.{body}.")
    }

    #[test]
    fn decode_extracts_grants_from_token() {
        let jwt = make_test_jwt(json!({
            "sub": "user-1",
            "authorization_details": [
                {
                    "type": "opentdf_attribute",
                    "actions": ["read", "decrypt"],
                    "locations": ["https://example.com/attr/classification/value/secret"]
                }
            ]
        }));
        let claims = decode_jwt_claims(&jwt).unwrap();
        assert_eq!(claims.authorization_details.len(), 1);
        let g = &claims.authorization_details[0];
        assert_eq!(g.grant_type, "opentdf_attribute");
        assert_eq!(g.actions, vec!["read", "decrypt"]);
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
            // Overlap on secret: the read action should not duplicate.
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
        assert_eq!(secret.len(), 2, "expected dedup: {secret:?}");
        assert!(secret.iter().any(|a| a == "read"));
        assert!(secret.iter().any(|a| a == "update"));
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

    #[test]
    fn end_to_end_allow_against_default_policy() {
        let jwt = make_test_jwt(json!({
            "authorization_details": [{
                "type": "opentdf_attribute",
                "actions": ["read"],
                "locations": ["https://example.com/attr/classification/value/secret"]
            }]
        }));
        let claims = decode_jwt_claims(&jwt).unwrap();
        let ents = entitlements_from_grants(&claims.authorization_details);
        let pdp = AccessPdp::new(default_policy(), PdpOptions::default()).unwrap();
        let res = pdp
            .check(
                &ents,
                &Action::new("read"),
                &["https://example.com/attr/classification/value/secret".to_string()],
            )
            .unwrap();
        assert_eq!(res, AccessDecision::Allow);
    }

    #[test]
    fn end_to_end_deny_when_resource_not_entitled() {
        // Token grants on /public but resource is /secret → ANY_OF rule
        // sees only one value, lookups miss → deny.
        let jwt = make_test_jwt(json!({
            "authorization_details": [{
                "type": "opentdf_attribute",
                "actions": ["read"],
                "locations": ["https://example.com/attr/classification/value/public"]
            }]
        }));
        let claims = decode_jwt_claims(&jwt).unwrap();
        let ents = entitlements_from_grants(&claims.authorization_details);
        let pdp = AccessPdp::new(default_policy(), PdpOptions::default()).unwrap();
        let res = pdp
            .check(
                &ents,
                &Action::new("read"),
                &["https://example.com/attr/classification/value/secret".to_string()],
            )
            .unwrap();
        assert!(res.is_deny());
    }
}
