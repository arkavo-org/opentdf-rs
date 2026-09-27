//! KasClient caller-key mode against a recording fake KAS.
//!
//! The fake wraps a known DEK to the SRT's clientPublicKey, as a permitting
//! KAS would, so every test also proves the rewrap still unwraps.

#![cfg(feature = "kas-client")]

use std::sync::{Arc, Mutex};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as B64URL},
};
use mockito::{Mock, Request, Server, ServerGuard};
use opentdf::{
    AttributeIdentifier, AttributePolicy, AttributeValue, Operator, Policy, TdfManifest,
    ed25519_dalek,
    kas::{CallerKey, KasClient},
    kas_discovery::OpentdfConfiguration,
    manifest::TdfManifestExt,
    p256, wrap_key_with_rsa_oaep,
};
use serde_json::{Value, json};

const DEK: [u8; 32] = [0x42; 32];
const REWRAP: &str = "/kas.AccessService/Rewrap";

/// What the fake KAS saw on one rewrap.
#[derive(Clone, Debug)]
struct Seen {
    authorization: Option<String>,
    dpop: Vec<String>,
    connect_protocol_version: Option<String>,
    srt: String,
}

fn header_values(req: &Request, name: &str) -> Vec<String> {
    req.header(name)
        .iter()
        .map(|v| v.to_str().expect("ASCII header").to_string())
        .collect()
}

fn jws_part(jws: &str, index: usize) -> Value {
    let segment = jws.split('.').nth(index).expect("JWS segment");
    serde_json::from_slice(&B64URL.decode(segment).expect("base64url")).expect("JSON")
}

async fn recording_kas(path: &str, hits: usize) -> (ServerGuard, Mock, Arc<Mutex<Vec<Seen>>>) {
    let mut server = Server::new_async().await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let mock = server
        .mock("POST", path)
        .expect(hits)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body_from_request(move |req| {
            let body: Value = serde_json::from_slice(req.body().expect("body")).expect("JSON");
            let srt = body["signedRequestToken"]
                .as_str()
                .expect("signedRequestToken")
                .to_string();
            let request_body: Value = serde_json::from_str(
                jws_part(&srt, 1)["requestBody"]
                    .as_str()
                    .expect("requestBody"),
            )
            .expect("requestBody JSON");
            let wrapped = wrap_key_with_rsa_oaep(
                &DEK,
                request_body["clientPublicKey"]
                    .as_str()
                    .expect("clientPublicKey"),
            )
            .expect("wrap DEK");
            sink.lock().unwrap().push(Seen {
                authorization: header_values(req, "authorization").into_iter().next(),
                dpop: header_values(req, "dpop"),
                connect_protocol_version: header_values(req, "connect-protocol-version")
                    .into_iter()
                    .next(),
                srt,
            });
            json!({
                "responses": [{
                    "policyId": "00000000-0000-0000-0000-000000000000",
                    "results": [{
                        "keyAccessObjectId": "kao-0",
                        "status": "permit",
                        "kasWrappedKey": wrapped
                    }]
                }]
            })
            .to_string()
            .into_bytes()
        })
        .create_async()
        .await;
    (server, mock, seen)
}

fn manifest(kas_url: String) -> TdfManifest {
    let policy = Policy::new(
        "00000000-0000-0000-0000-000000000000".to_string(),
        vec![AttributePolicy::condition(
            AttributeIdentifier {
                namespace: "example.com".to_string(),
                name: "clearance".to_string(),
            },
            Operator::Equals,
            AttributeValue::String("secret".to_string()),
        )],
        vec![],
    );
    let mut manifest = TdfManifest::new("0.payload".to_string(), kas_url);
    manifest.encryption_information.key_access[0].wrapped_key =
        BASE64.encode(b"dummy-wrapped-key-32-bytes-long!");
    manifest.set_policy(&policy).unwrap();
    manifest
}

fn ed25519_key() -> CallerKey {
    CallerKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]))
}

fn p256_key() -> CallerKey {
    CallerKey::P256(p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap())
}

fn verify_with(key: &CallerKey, jws: &str) {
    use p256::ecdsa::signature::Verifier as _;
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
                &p256::ecdsa::Signature::from_slice(&signature).expect("64-byte r||s"),
            )
            .expect("ES256 signature verifies"),
    }
}

fn expected_alg(key: &CallerKey) -> &'static str {
    match key {
        CallerKey::Ed25519(_) => "EdDSA",
        CallerKey::P256(_) => "ES256",
    }
}

#[tokio::test]
async fn no_caller_key_keeps_bearer_and_rs256_request_token() {
    let (server, mock, seen) = recording_kas(REWRAP, 1).await;
    let client = KasClient::new(
        &OpentdfConfiguration::for_kas_connect(server.url()),
        "service-token",
    )
    .unwrap();

    let dek = client
        .rewrap_standard_tdf(&manifest(server.url()))
        .await
        .unwrap();

    mock.assert_async().await;
    assert_eq!(dek, DEK);
    let seen = seen.lock().unwrap()[0].clone();
    assert_eq!(seen.authorization.as_deref(), Some("Bearer service-token"));
    assert!(seen.dpop.is_empty());
    assert_eq!(seen.connect_protocol_version, None);
    assert_eq!(jws_part(&seen.srt, 0)["alg"], "RS256");
}

#[tokio::test]
async fn caller_key_signs_the_request_token() {
    for key in [ed25519_key(), p256_key()] {
        let (server, mock, seen) = recording_kas(REWRAP, 1).await;
        let client = KasClient::new(
            &OpentdfConfiguration::for_kas_connect(server.url()),
            "agent-token",
        )
        .unwrap()
        .with_caller_key(key.clone());

        let dek = client
            .rewrap_standard_tdf(&manifest(server.url()))
            .await
            .unwrap();

        mock.assert_async().await;
        assert_eq!(dek, DEK);
        let seen = seen.lock().unwrap()[0].clone();
        assert_eq!(jws_part(&seen.srt, 0)["alg"], expected_alg(&key));
        verify_with(&key, &seen.srt);
    }
}

fn expected_jwk(key: &CallerKey) -> Value {
    match key {
        CallerKey::Ed25519(k) => json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": B64URL.encode(k.verifying_key().to_bytes()),
        }),
        CallerKey::P256(k) => {
            let point = k.verifying_key().to_encoded_point(false);
            json!({
                "kty": "EC",
                "crv": "P-256",
                "x": B64URL.encode(point.x().unwrap()),
                "y": B64URL.encode(point.y().unwrap()),
            })
        }
    }
}

fn ath(token: &str) -> String {
    use opentdf::sha2::{Digest, Sha256};
    B64URL.encode(Sha256::digest(token.as_bytes()))
}

#[tokio::test]
async fn caller_key_sends_dpop_proof_bound_to_token_and_procedure() {
    for key in [ed25519_key(), p256_key()] {
        let (server, mock, seen) = recording_kas(REWRAP, 1).await;
        let client = KasClient::new(
            &OpentdfConfiguration::for_kas_connect(server.url()),
            "agent-token",
        )
        .unwrap()
        .with_caller_key(key.clone());

        let dek = client
            .rewrap_standard_tdf(&manifest(server.url()))
            .await
            .unwrap();

        mock.assert_async().await;
        assert_eq!(dek, DEK);
        let seen = seen.lock().unwrap()[0].clone();
        assert_eq!(seen.authorization.as_deref(), Some("DPoP agent-token"));
        assert_eq!(seen.connect_protocol_version.as_deref(), Some("1"));
        assert_eq!(seen.dpop.len(), 1, "exactly one DPoP header");

        let proof = &seen.dpop[0];
        let header = jws_part(proof, 0);
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], expected_alg(&key));
        assert_eq!(header["jwk"], expected_jwk(&key));
        verify_with(&key, proof);

        let claims = jws_part(proof, 1);
        assert_eq!(claims["htm"], "POST");
        // The server listens on http://127.0.0.1:<port>; only the bare
        // procedure matches what the platform compares against.
        assert_eq!(claims["htu"], REWRAP);
        assert_eq!(claims["ath"], ath("agent-token"));

        // Proof and request token are signed by the same key.
        assert_eq!(jws_part(&seen.srt, 0)["alg"], header["alg"]);
        verify_with(&key, &seen.srt);
    }
}

#[tokio::test]
async fn refreshed_access_token_is_bound_on_the_next_rewrap() {
    let (server, mock, seen) = recording_kas(REWRAP, 2).await;
    let mut client = KasClient::new(
        &OpentdfConfiguration::for_kas_connect(server.url()),
        "agent-token-1",
    )
    .unwrap()
    .with_caller_key(ed25519_key());

    client
        .rewrap_standard_tdf(&manifest(server.url()))
        .await
        .unwrap();
    client.set_access_token("agent-token-2");
    client
        .rewrap_standard_tdf(&manifest(server.url()))
        .await
        .unwrap();

    mock.assert_async().await;
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen[1].authorization.as_deref(), Some("DPoP agent-token-2"));
    let first = jws_part(&seen[0].dpop[0], 1);
    let second = jws_part(&seen[1].dpop[0], 1);
    assert_eq!(first["ath"], ath("agent-token-1"));
    assert_eq!(second["ath"], ath("agent-token-2"));
    assert_ne!(first["jti"], second["jti"], "jti must differ per request");
}

#[tokio::test]
async fn caller_key_refuses_legacy_rest_before_sending() {
    let (server, mock, _seen) = recording_kas("/kas/v2/rewrap", 0).await;
    let client = KasClient::new(
        &OpentdfConfiguration::for_kas_legacy_rest(server.url()),
        "agent-token",
    )
    .unwrap()
    .with_caller_key(p256_key());

    let err = client
        .rewrap_standard_tdf(&manifest(server.url()))
        .await
        .unwrap_err();

    mock.assert_async().await;
    assert!(
        matches!(err, opentdf::KasError::ConfigError { .. }),
        "got: {err}"
    );
}
