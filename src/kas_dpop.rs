//! Caller-key proof of possession for KAS rewrap (RFC 9449 DPoP).
//!
//! An agent's access token names the agent's own key in `cnf`. The KAS
//! releases a key only when the request proves possession of that key: a
//! DPoP proof binds key to token (`ath`) and to the call (`htm`, `htu`), and
//! the signed request token is verified with the same key.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use opentdf_protocol::KasError;
use rand::RngCore as _;
use serde::Serialize;
use std::fmt;

use crate::p256::ecdsa::Signature as P256Signature;
use crate::sha2::{Digest, Sha256};

/// Random bytes in a DPoP `jti`: 128 bits keeps collisions out of reach of
/// any replay cache the KAS keeps.
const JTI_BYTES: usize = 16;

/// Lifetime of a signed request token, matching the ephemeral-key path.
const SRT_LIFETIME_SECS: i64 = 60;

/// Method of every Connect unary call, and so the DPoP `htm` of a rewrap.
pub(crate) const REWRAP_HTM: &str = "POST";

/// DPoP `htu` for a rewrap. The platform compares `htu` with the Connect
/// procedure rather than the request URL, so the proof stays valid behind a
/// reverse proxy that rewrites scheme and host.
pub(crate) const CONNECT_REWRAP_PROCEDURE: &str = "/kas.AccessService/Rewrap";

/// The caller's own signing key, the key its access token names in `cnf`.
///
/// Set it with [`crate::kas::KasClient::with_caller_key`].
#[derive(Clone)]
pub enum CallerKey {
    /// Ed25519, signed as JWS `EdDSA` (RFC 8037).
    Ed25519(ed25519_dalek::SigningKey),
    /// NIST P-256, signed as JWS `ES256` (RFC 7518 §3.4).
    P256(crate::p256::ecdsa::SigningKey),
}

/// Public JWK as embedded in the DPoP header. Field order is fixed so a proof
/// is byte-stable for a given key, claims and signature.
#[derive(Serialize)]
struct Jwk {
    kty: &'static str,
    crv: &'static str,
    x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    y: Option<String>,
}

#[derive(Serialize)]
struct DpopHeader {
    typ: &'static str,
    alg: &'static str,
    jwk: Jwk,
}

#[derive(Serialize)]
struct DpopClaims<'a> {
    htm: &'a str,
    htu: &'a str,
    iat: i64,
    jti: &'a str,
    ath: String,
}

#[derive(Serialize)]
struct SrtHeader {
    alg: &'static str,
    typ: &'static str,
}

#[derive(Serialize)]
struct SrtClaims<'a> {
    #[serde(rename = "requestBody")]
    request_body: &'a str,
    iat: i64,
    exp: i64,
}

impl CallerKey {
    /// A DPoP proof (RFC 9449) for one request carrying `access_token`.
    ///
    /// [`crate::kas::KasClient`] calls this for every rewrap. It is public so
    /// a caller can prove possession on another Connect procedure of the same
    /// platform, where `htu` is that procedure's path.
    pub fn dpop_proof(&self, htm: &str, htu: &str, access_token: &str) -> Result<String, KasError> {
        self.dpop_proof_at(
            htm,
            htu,
            access_token,
            chrono::Utc::now().timestamp(),
            &new_jti(),
        )
    }

    fn dpop_proof_at(
        &self,
        htm: &str,
        htu: &str,
        access_token: &str,
        iat: i64,
        jti: &str,
    ) -> Result<String, KasError> {
        let header = serde_json::to_vec(&DpopHeader {
            typ: "dpop+jwt",
            alg: self.algorithm(),
            jwk: self.jwk(),
        })?;
        let claims = serde_json::to_vec(&DpopClaims {
            htm,
            htu,
            iat,
            jti,
            ath: access_token_hash(access_token),
        })?;
        self.sign_compact(&header, &claims)
    }

    /// Signed request token over `request_body`, signed by this key.
    ///
    /// The KAS verifies the SRT with the key the caller proved possession of
    /// through DPoP, so a caller-bound token needs this key here as well.
    pub(crate) fn signed_request_token_at(
        &self,
        request_body: &str,
        iat: i64,
    ) -> Result<String, KasError> {
        let header = serde_json::to_vec(&SrtHeader {
            alg: self.algorithm(),
            typ: "JWT",
        })?;
        let claims = serde_json::to_vec(&SrtClaims {
            request_body,
            iat,
            exp: iat + SRT_LIFETIME_SECS,
        })?;
        self.sign_compact(&header, &claims)
    }

    fn algorithm(&self) -> &'static str {
        match self {
            CallerKey::Ed25519(_) => "EdDSA",
            CallerKey::P256(_) => "ES256",
        }
    }

    fn jwk(&self) -> Jwk {
        match self {
            CallerKey::Ed25519(key) => Jwk {
                kty: "OKP",
                crv: "Ed25519",
                x: B64URL.encode(key.verifying_key().to_bytes()),
                y: None,
            },
            CallerKey::P256(key) => {
                // Uncompressed SEC1 is 0x04 || X || Y with 32-byte coordinates,
                // so leading zero bytes survive as RFC 7518 §6.2.1.2 requires.
                let point = key.verifying_key().to_encoded_point(false);
                let bytes = point.as_bytes();
                Jwk {
                    kty: "EC",
                    crv: "P-256",
                    x: B64URL.encode(&bytes[1..33]),
                    y: Some(B64URL.encode(&bytes[33..65])),
                }
            }
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KasError> {
        match self {
            CallerKey::Ed25519(key) => {
                let signature: ed25519_dalek::Signature = ed25519_dalek::Signer::sign(key, message);
                Ok(signature.to_bytes().to_vec())
            }
            CallerKey::P256(key) => {
                let signature: P256Signature =
                    crate::p256::ecdsa::signature::Signer::try_sign(key, message).map_err(|e| {
                        KasError::CryptoError {
                            operation: "ES256_sign".to_string(),
                            reason: e.to_string(),
                        }
                    })?;
                // JWS carries ES256 as fixed-width r||s (RFC 7518 §3.4), not DER.
                Ok(signature.to_bytes().to_vec())
            }
        }
    }

    /// JWS compact serialization over raw header and payload bytes.
    fn sign_compact(&self, header: &[u8], payload: &[u8]) -> Result<String, KasError> {
        let signing_input = format!("{}.{}", B64URL.encode(header), B64URL.encode(payload));
        let signature = self.sign(signing_input.as_bytes())?;
        Ok(format!("{}.{}", signing_input, B64URL.encode(signature)))
    }
}

impl fmt::Debug for CallerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Private key material must never reach logs.
        f.debug_struct("CallerKey")
            .field("alg", &self.algorithm())
            .finish_non_exhaustive()
    }
}

fn access_token_hash(access_token: &str) -> String {
    B64URL.encode(Sha256::digest(access_token.as_bytes()))
}

fn new_jti() -> String {
    let mut bytes = [0u8; JTI_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    B64URL.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
    use serde_json::{Value, json};
    use std::collections::HashSet;

    const REWRAP: &str = "/kas.AccessService/Rewrap";

    /// RFC 8032 §7.1 TEST 1 secret key, the key RFC 8037 Appendix A uses.
    fn rfc8037_key() -> CallerKey {
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        CallerKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    /// RFC 6979 §A.2.5 P-256 private key.
    fn rfc6979_signing_key() -> crate::p256::ecdsa::SigningKey {
        let d = hex::decode("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
            .unwrap();
        crate::p256::ecdsa::SigningKey::from_slice(&d).unwrap()
    }

    fn rfc6979_key() -> CallerKey {
        CallerKey::P256(rfc6979_signing_key())
    }

    fn part(jws: &str, index: usize) -> Value {
        let segment = jws.split('.').nth(index).expect("JWS segment");
        serde_json::from_slice(&B64URL.decode(segment).expect("base64url")).expect("JSON")
    }

    fn verify_with(key: &CallerKey, jws: &str) {
        use crate::p256::ecdsa::signature::Verifier as _;
        let (signing_input, signature) = jws.rsplit_once('.').expect("compact JWS");
        let signature = B64URL.decode(signature).expect("base64url signature");
        match key {
            CallerKey::Ed25519(k) => k
                .verifying_key()
                .verify_strict(
                    signing_input.as_bytes(),
                    &ed25519_dalek::Signature::from_slice(&signature).unwrap(),
                )
                .expect("EdDSA signature verifies"),
            CallerKey::P256(k) => k
                .verifying_key()
                .verify(
                    signing_input.as_bytes(),
                    &P256Signature::from_slice(&signature).expect("64-byte r||s"),
                )
                .expect("ES256 signature verifies"),
        }
    }

    fn validation_for(key: &CallerKey) -> Validation {
        let mut validation = Validation::new(match key {
            CallerKey::Ed25519(_) => Algorithm::EdDSA,
            CallerKey::P256(_) => Algorithm::ES256,
        });
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation
    }

    #[test]
    fn ed25519_compact_jws_matches_rfc8037_a4() {
        let jws = rfc8037_key()
            .sign_compact(br#"{"alg":"EdDSA"}"#, b"Example of Ed25519 signing")
            .unwrap();
        assert_eq!(
            jws,
            "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
        );
    }

    #[test]
    fn ed25519_jwk_matches_rfc8037_a2() {
        assert_eq!(
            serde_json::to_value(rfc8037_key().jwk()).unwrap(),
            json!({"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})
        );
    }

    #[test]
    fn p256_jwk_matches_rfc6979_public_key() {
        assert_eq!(
            serde_json::to_value(rfc6979_key().jwk()).unwrap(),
            json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "YP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Y",
                "y": "eQP-EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk"
            })
        );
    }

    #[test]
    fn es256_signature_is_raw_r_and_s() {
        let key = rfc6979_key();
        let jws = key.sign_compact(b"{}", b"payload").unwrap();
        let signature = B64URL.decode(jws.rsplit('.').next().unwrap()).unwrap();
        assert_eq!(
            signature.len(),
            64,
            "JWS ES256 is fixed-width r||s, not DER"
        );
        verify_with(&key, &jws);
    }

    #[test]
    fn dpop_proof_structure_and_signature_both_algs() {
        for key in [rfc8037_key(), rfc6979_key()] {
            let proof = key
                .dpop_proof("POST", REWRAP, "vector-access-token")
                .unwrap();

            let header = part(&proof, 0);
            assert_eq!(header["typ"], "dpop+jwt");
            assert_eq!(header["alg"], key.algorithm());
            assert_eq!(header["jwk"], serde_json::to_value(key.jwk()).unwrap());
            assert!(
                header["jwk"].get("d").is_none(),
                "private key in DPoP header"
            );

            // Independent JOSE implementation: header jwk → key → verify.
            let parsed = decode_header(&proof).unwrap();
            assert_eq!(parsed.typ.as_deref(), Some("dpop+jwt"));
            let jwk = parsed.jwk.expect("jwk in header");
            let claims = decode::<Value>(
                &proof,
                &DecodingKey::from_jwk(&jwk).unwrap(),
                &validation_for(&key),
            )
            .unwrap()
            .claims;
            verify_with(&key, &proof);

            let names: HashSet<&str> = claims
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(names, HashSet::from(["htm", "htu", "iat", "jti", "ath"]));
            assert_eq!(claims["htm"], "POST");
            assert_eq!(claims["htu"], REWRAP);
            let iat = claims["iat"].as_i64().unwrap();
            assert!((chrono::Utc::now().timestamp() - iat).abs() <= 5);
            assert_eq!(claims["ath"], "wSv7o_jGd5w9-_euwLflNt2x3eaE7OVdfOCEWWqWUKE");
        }
    }

    #[test]
    fn ath_binds_the_access_token() {
        let key = rfc8037_key();
        let first = part(&key.dpop_proof("POST", REWRAP, "token-a").unwrap(), 1);
        let second = part(&key.dpop_proof("POST", REWRAP, "token-b").unwrap(), 1);
        assert_eq!(first["ath"], B64URL.encode(Sha256::digest(b"token-a")));
        assert_eq!(second["ath"], B64URL.encode(Sha256::digest(b"token-b")));
        assert_ne!(first["ath"], second["ath"]);
    }

    #[test]
    fn jti_is_unique_and_128_bit() {
        let key = rfc6979_key();
        let jtis: HashSet<String> = (0..1000)
            .map(|_| {
                let jti = part(&key.dpop_proof("POST", REWRAP, "t").unwrap(), 1)["jti"]
                    .as_str()
                    .unwrap()
                    .to_string();
                assert_eq!(B64URL.decode(&jti).unwrap().len(), 16);
                jti
            })
            .collect();
        assert_eq!(jtis.len(), 1000);
    }

    #[test]
    fn altered_claims_fail_verification() {
        for key in [rfc8037_key(), rfc6979_key()] {
            let proof = key.dpop_proof("POST", REWRAP, "t").unwrap();
            let forged_claims = B64URL.encode(
                br#"{"htm":"POST","htu":"/kas.AccessService/PublicKey","iat":0,"jti":"x","ath":"y"}"#,
            );
            let mut segments: Vec<&str> = proof.split('.').collect();
            segments[1] = &forged_claims;
            let forged = segments.join(".");
            let jwk: jsonwebtoken::jwk::Jwk =
                serde_json::from_value(part(&proof, 0)["jwk"].clone()).unwrap();
            assert!(
                decode::<Value>(
                    &forged,
                    &DecodingKey::from_jwk(&jwk).unwrap(),
                    &validation_for(&key)
                )
                .is_err()
            );
        }
    }

    #[test]
    fn debug_does_not_reveal_private_key() {
        let rendered = format!("{:?} {:?}", rfc8037_key(), rfc6979_key());
        assert!(rendered.contains("EdDSA") && rendered.contains("ES256"));
        let ed_seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let p256_d = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
        let encodings = [
            ed_seed[..8].to_string(),
            B64URL.encode(hex::decode(ed_seed).unwrap())[..8].to_string(),
            p256_d[..8].to_string(),
            p256_d[..8].to_lowercase(),
            B64URL.encode(hex::decode(p256_d).unwrap())[..8].to_string(),
        ];
        for secret in encodings {
            assert!(!rendered.contains(&secret), "Debug leaked {secret}");
        }
    }

    #[test]
    fn signed_request_token_is_signed_by_the_caller_key() {
        let body = r#"{"clientPublicKey":"pem","requests":[]}"#;
        for key in [rfc8037_key(), rfc6979_key()] {
            let srt = key.signed_request_token_at(body, 1_780_000_000).unwrap();
            assert_eq!(part(&srt, 0), json!({"alg": key.algorithm(), "typ": "JWT"}));
            assert_eq!(
                part(&srt, 1),
                json!({"requestBody": body, "iat": 1_780_000_000, "exp": 1_780_000_060})
            );
            verify_with(&key, &srt);
        }
    }

    const VECTOR_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/dpop_interop_vectors.json"
    );
    const VECTOR_IAT: i64 = 1_780_000_000;
    const VECTOR_TOKEN: &str = "vector-access-token";

    /// A real UnsignedRewrapRequest body, so the harness also proves the
    /// platform parses what this crate signs.
    ///
    /// Both vectors in `interop_vectors` share this one request body. Its
    /// `clientPublicKey` is the P-256 test key regardless of which key signs
    /// the vector's SRT/DPoP proof, because the platform only parses the
    /// request body — the rewrap key inside it is unrelated to the signing
    /// key under test.
    fn vector_request_body() -> String {
        use crate::p256::pkcs8::{EncodePublicKey, LineEnding};
        use base64::engine::general_purpose::STANDARD as BASE64;
        use opentdf_protocol::{
            KasPolicy, KasPolicyBinding, KeyAccessObject, KeyAccessObjectWrapper, PolicyRequest,
            UnsignedRewrapRequest,
        };
        let client_public_key = crate::p256::PublicKey::from(rfc6979_signing_key().verifying_key())
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let request = UnsignedRewrapRequest {
            client_public_key,
            requests: vec![PolicyRequest {
                algorithm: None,
                policy: KasPolicy {
                    id: "00000000-0000-0000-0000-000000000000".to_string(),
                    body: BASE64.encode(b"{}"),
                },
                key_access_objects: vec![KeyAccessObjectWrapper {
                    key_access_object_id: "kao-0".to_string(),
                    key_access_object: KeyAccessObject {
                        key_type: "wrapped".to_string(),
                        url: "https://platform.arkavo.net".to_string(),
                        protocol: "kas".to_string(),
                        wrapped_key: BASE64.encode([0u8; 32]),
                        policy_binding: KasPolicyBinding {
                            hash: BASE64.encode([0u8; 32]),
                            algorithm: Some("HS256".to_string()),
                        },
                        encrypted_metadata: None,
                        kid: None,
                        header: None,
                        ephemeral_public_key: None,
                    },
                }],
            }],
        };
        serde_json::to_string(&request).unwrap()
    }

    fn interop_vectors() -> Value {
        let body = vector_request_body();
        Value::Array(
            [("ed25519", rfc8037_key()), ("p256", rfc6979_key())]
                .into_iter()
                .map(|(name, key)| {
                    let jti = format!("opentdf-rs-interop-{name}");
                    json!({
                        "name": name,
                        "alg": key.algorithm(),
                        "public_jwk": key.jwk(),
                        "access_token": VECTOR_TOKEN,
                        "htm": REWRAP_HTM,
                        "htu": CONNECT_REWRAP_PROCEDURE,
                        "iat": VECTOR_IAT,
                        "jti": jti,
                        "request_body": body,
                        "dpop": key
                            .dpop_proof_at(
                                REWRAP_HTM,
                                CONNECT_REWRAP_PROCEDURE,
                                VECTOR_TOKEN,
                                VECTOR_IAT,
                                &jti,
                            )
                            .unwrap(),
                        "signed_request_token": key
                            .signed_request_token_at(&body, VECTOR_IAT)
                            .unwrap(),
                    })
                })
                .collect(),
        )
    }

    #[test]
    fn interop_vectors_reproduce_the_recorded_fixture() {
        let recorded: Value = serde_json::from_str(
            &std::fs::read_to_string(VECTOR_PATH)
                .expect("fixture missing; record it with write_interop_vectors (Task 4)"),
        )
        .unwrap();
        assert_eq!(
            recorded["vectors"],
            interop_vectors(),
            "signing or request-body serialization drifted from the vectors the platform verifier accepted"
        );
    }

    #[test]
    #[ignore = "records tests/data/dpop_interop_vectors.json; run only when re-verifying against opentdf-platform"]
    fn write_interop_vectors() {
        let commit = std::env::var("OPENTDF_PLATFORM_COMMIT").expect(
            "set OPENTDF_PLATFORM_COMMIT to the fork commit the Go harness verifies against",
        );
        let file = json!({
            "provenance": {
                "generator": "cargo test --lib kas_dpop::tests::write_interop_vectors -- --ignored",
                "verifier": "tests/interop/opentdf_platform_dpop_vectors_test.go, copied into opentdf-platform service/internal/auth/ and run with go test",
                "opentdf_platform_repo": "https://github.com/arkavo-org/opentdf-platform",
                "opentdf_platform_commit": commit,
                "checks": [
                    "validateDPoP accepts the proof with receiverInfo{/kas.AccessService/Rewrap, POST} and cnf.jkt = thumbprint(public_jwk)",
                    "validateDPoP rejects the proof for a different access token (ath)",
                    "validateDPoP rejects the proof when the expected htu is the full URL",
                    "the SRT verifies with the DPoP key under its alg, and requestBody protojson-parses as kas.UnsignedRewrapRequest"
                ],
                "keys": "Ed25519: RFC 8032 section 7.1 TEST 1; P-256: RFC 6979 A.2.5"
            },
            "vectors": interop_vectors(),
        });
        std::fs::write(
            VECTOR_PATH,
            serde_json::to_string_pretty(&file).unwrap() + "\n",
        )
        .unwrap();
    }
}
