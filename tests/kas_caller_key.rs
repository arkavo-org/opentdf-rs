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
