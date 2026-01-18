//! Mock KAS (Key Access Service) Server for Cross-SDK Integration Testing
//!
//! This lightweight HTTP server implements the KAS v2 protocol for testing
//! cross-SDK compatibility between opentdf-rs and OpenTDFKit.
//!
//! # Endpoints
//!
//! - `GET /kas/v2/kas_public_key` - Returns RSA-2048 public key (PEM)
//! - `POST /kas/v2/rewrap` - Handles key unwrap requests
//! - `POST /token` - Returns mock OAuth access token
//! - `GET /health` - Health check
//!
//! # Usage
//!
//! ```bash
//! cargo run --example mock_kas_server --features kas-client,cbor
//! ```
//!
//! The server listens on port 9080 by default. Set `MOCK_KAS_PORT` to change.

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::KeyPair;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// ============================================================================
// Server State
// ============================================================================

/// Shared server state containing keys and wrapped key store
#[derive(Clone)]
struct AppState {
    /// RSA private key for unwrapping (DER format)
    rsa_private_key_der: Vec<u8>,
    /// RSA public key PEM for clients
    rsa_public_key_pem: String,
    /// EC private key for NanoTDF unwrapping
    ec_private_key_pem: String,
    /// EC public key PEM for clients
    ec_public_key_pem: String,
    /// Store mapping policy_id -> symmetric key (for deterministic testing)
    #[allow(dead_code)]
    key_store: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl AppState {
    fn new() -> Self {
        // Generate RSA-2048 key pair using aws-lc-rs
        let rsa_private = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
            .expect("Failed to generate RSA key pair");

        let private_key_der = rsa_private
            .as_der()
            .expect("Failed to export RSA private key")
            .as_ref()
            .to_vec();

        let public_key_der = rsa_private.public_key().as_ref().to_vec();

        let public_key_pem = pem::encode(&pem::Pem::new("PUBLIC KEY", public_key_der));

        // Generate EC P-256 key pair
        let ec_secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let ec_public = ec_secret.public_key();

        use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
        let ec_private_pem = ec_secret
            .to_pkcs8_pem(LineEnding::LF)
            .expect("Failed to encode EC private key")
            .to_string();
        let ec_public_pem = ec_public
            .to_public_key_pem(LineEnding::LF)
            .expect("Failed to encode EC public key");

        Self {
            rsa_private_key_der: private_key_der,
            rsa_public_key_pem: public_key_pem,
            ec_private_key_pem: ec_private_pem,
            ec_public_key_pem: ec_public_pem,
            key_store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Store a symmetric key for a policy ID
    #[allow(dead_code)]
    fn store_key(&self, policy_id: &str, key: Vec<u8>) {
        let mut store = self.key_store.write().unwrap();
        store.insert(policy_id.to_string(), key);
    }

    /// Retrieve a symmetric key for a policy ID
    #[allow(dead_code)]
    fn get_key(&self, policy_id: &str) -> Option<Vec<u8>> {
        let store = self.key_store.read().unwrap();
        store.get(policy_id).cloned()
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize)]
struct PublicKeyResponse {
    #[serde(rename = "publicKey")]
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct SignedRewrapRequest {
    #[serde(rename = "signedRequestToken")]
    signed_request_token: String,
}

#[derive(Debug, Deserialize)]
struct UnsignedRewrapRequest {
    #[serde(rename = "clientPublicKey")]
    client_public_key: String,
    requests: Vec<PolicyRequest>,
}

#[derive(Debug, Deserialize)]
struct PolicyRequest {
    #[allow(dead_code)]
    algorithm: Option<String>,
    policy: Policy,
    #[serde(rename = "keyAccessObjects")]
    key_access_objects: Vec<KeyAccessObjectWrapper>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Policy {
    id: String,
    body: String,
}

#[derive(Debug, Deserialize)]
struct KeyAccessObjectWrapper {
    #[serde(rename = "keyAccessObjectId")]
    key_access_object_id: String,
    #[serde(rename = "keyAccessObject")]
    key_access_object: KeyAccessObject,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct KeyAccessObject {
    #[serde(rename = "type")]
    key_type: String,
    url: String,
    protocol: String,
    #[serde(rename = "wrappedKey")]
    wrapped_key: String,
    #[serde(rename = "policyBinding")]
    policy_binding: KasPolicyBinding,
    #[serde(rename = "encryptedMetadata")]
    encrypted_metadata: Option<String>,
    kid: Option<String>,
    header: Option<String>,
    #[serde(rename = "ephemeralPublicKey")]
    ephemeral_public_key: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct KasPolicyBinding {
    hash: String,
    algorithm: Option<String>,
}

#[derive(Debug, Serialize)]
struct RewrapResponse {
    responses: Vec<PolicyRewrapResponse>,
    #[serde(rename = "sessionPublicKey", skip_serializing_if = "Option::is_none")]
    session_public_key: Option<String>,
}

#[derive(Debug, Serialize)]
struct PolicyRewrapResponse {
    id: String,
    results: Vec<KeyAccessResult>,
}

#[derive(Debug, Serialize)]
struct KeyAccessResult {
    id: String,
    status: String,
    #[serde(rename = "kasWrappedKey", skip_serializing_if = "Option::is_none")]
    kas_wrapped_key: Option<String>,
    #[serde(rename = "entityWrappedKey", skip_serializing_if = "Option::is_none")]
    entity_wrapped_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    message: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// Health check endpoint
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: "1.0.0".to_string(),
    })
}

/// Get KAS public key (header-based algorithm selection)
#[allow(dead_code)]
async fn get_public_key(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    // Check for algorithm query parameter in Accept header or use RSA default
    let algorithm = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");

    // If the request specifically asks for EC key
    let public_key = if algorithm.contains("ec") {
        state.ec_public_key_pem.clone()
    } else {
        state.rsa_public_key_pem.clone()
    };

    Json(PublicKeyResponse { public_key })
}

/// Get KAS public key with algorithm query parameter
async fn get_public_key_with_algorithm(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let algorithm = params.get("algorithm").map(|s| s.as_str()).unwrap_or("");

    let public_key = if algorithm.starts_with("ec:") || algorithm == "ec" {
        state.ec_public_key_pem.clone()
    } else {
        state.rsa_public_key_pem.clone()
    };

    Json(PublicKeyResponse { public_key })
}

/// Rewrap key endpoint
async fn rewrap(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SignedRewrapRequest>,
) -> Result<Json<RewrapResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Verify authorization header exists (we don't validate it for mock)
    let _auth = headers.get("authorization").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "unauthorized".to_string(),
                message: "Missing Authorization header".to_string(),
            }),
        )
    })?;

    // Parse the JWT (we skip signature verification for mock)
    let jwt_parts: Vec<&str> = request.signed_request_token.split('.').collect();
    if jwt_parts.len() != 3 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_request".to_string(),
                message: "Invalid JWT format".to_string(),
            }),
        ));
    }

    // Decode the payload
    let payload_b64 = jwt_parts[1];
    let payload_bytes = BASE64
        .decode(payload_b64)
        .or_else(|_| {
            // Try URL-safe base64
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            URL_SAFE_NO_PAD.decode(payload_b64)
        })
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_request".to_string(),
                    message: format!("Failed to decode JWT payload: {}", e),
                }),
            )
        })?;

    // Parse JWT claims
    #[derive(Deserialize)]
    struct JwtClaims {
        #[serde(rename = "requestBody")]
        request_body: String,
    }

    let claims: JwtClaims = serde_json::from_slice(&payload_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_request".to_string(),
                message: format!("Failed to parse JWT claims: {}", e),
            }),
        )
    })?;

    // Parse the unsigned request from the JWT requestBody
    let unsigned_request: UnsignedRewrapRequest = serde_json::from_str(&claims.request_body)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_request".to_string(),
                    message: format!("Failed to parse rewrap request: {}", e),
                }),
            )
        })?;

    println!(
        "[KAS] Rewrap request: {} policy requests",
        unsigned_request.requests.len()
    );

    // Process each policy request
    let mut policy_responses = Vec::new();
    let mut session_public_key = None;

    for policy_req in &unsigned_request.requests {
        let mut results = Vec::new();

        for kao_wrapper in &policy_req.key_access_objects {
            let kao = &kao_wrapper.key_access_object;
            println!(
                "[KAS] Processing KAO: id={}, type={}",
                kao_wrapper.key_access_object_id, kao.key_type
            );

            // Check if this is a NanoTDF request (has header field)
            if kao.header.is_some() {
                // NanoTDF: Extract and return the symmetric key directly
                // For mock, we generate a deterministic key based on policy ID
                let symmetric_key = derive_symmetric_key(&policy_req.policy.id);

                results.push(KeyAccessResult {
                    id: kao_wrapper.key_access_object_id.clone(),
                    status: "permit".to_string(),
                    kas_wrapped_key: None,
                    entity_wrapped_key: Some(BASE64.encode(&symmetric_key)),
                    error: None,
                });
            } else if let Some(ephemeral_public_key) = &kao.ephemeral_public_key {
                // EC key wrapping (TDF-JSON, TDF-CBOR)
                match unwrap_ec_wrapped_key(
                    &state,
                    ephemeral_public_key,
                    &kao.wrapped_key,
                    &unsigned_request.client_public_key,
                ) {
                    Ok((wrapped_key, session_pk)) => {
                        session_public_key = Some(session_pk);
                        results.push(KeyAccessResult {
                            id: kao_wrapper.key_access_object_id.clone(),
                            status: "permit".to_string(),
                            kas_wrapped_key: Some(wrapped_key),
                            entity_wrapped_key: None,
                            error: None,
                        });
                    }
                    Err(e) => {
                        results.push(KeyAccessResult {
                            id: kao_wrapper.key_access_object_id.clone(),
                            status: "deny".to_string(),
                            kas_wrapped_key: None,
                            entity_wrapped_key: None,
                            error: Some(e),
                        });
                    }
                }
            } else {
                // RSA key wrapping (Standard TDF)
                match unwrap_rsa_wrapped_key(
                    &state,
                    &kao.wrapped_key,
                    &unsigned_request.client_public_key,
                ) {
                    Ok((wrapped_key, session_pk)) => {
                        session_public_key = Some(session_pk);
                        results.push(KeyAccessResult {
                            id: kao_wrapper.key_access_object_id.clone(),
                            status: "permit".to_string(),
                            kas_wrapped_key: Some(wrapped_key),
                            entity_wrapped_key: None,
                            error: None,
                        });
                    }
                    Err(e) => {
                        results.push(KeyAccessResult {
                            id: kao_wrapper.key_access_object_id.clone(),
                            status: "deny".to_string(),
                            kas_wrapped_key: None,
                            entity_wrapped_key: None,
                            error: Some(e),
                        });
                    }
                }
            }
        }

        policy_responses.push(PolicyRewrapResponse {
            id: policy_req.policy.id.clone(),
            results,
        });
    }

    Ok(Json(RewrapResponse {
        responses: policy_responses,
        session_public_key,
    }))
}

/// Generate a mock OAuth token
async fn token() -> Json<TokenResponse> {
    Json(TokenResponse {
        access_token: "mock-access-token-for-testing".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
    })
}

// ============================================================================
// Key Operations
// ============================================================================

/// Derive a deterministic symmetric key from policy ID (for testing)
fn derive_symmetric_key(policy_id: &str) -> Vec<u8> {
    use opentdf_crypto::sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"mock-kas-key-derivation:");
    hasher.update(policy_id.as_bytes());
    hasher.finalize().to_vec()
}

/// Unwrap an RSA-wrapped key and re-wrap for the client
fn unwrap_rsa_wrapped_key(
    state: &AppState,
    wrapped_key_b64: &str,
    client_public_key_pem: &str,
) -> Result<(String, String), String> {
    use aws_lc_rs::rsa::{OAEP_SHA1_MGF1SHA1, OaepPrivateDecryptingKey, PrivateDecryptingKey};

    // Decode the wrapped key
    let wrapped_key = BASE64
        .decode(wrapped_key_b64)
        .map_err(|e| format!("Failed to decode wrapped key: {}", e))?;

    // Load the KAS private key
    let private_key = PrivateDecryptingKey::from_pkcs8(&state.rsa_private_key_der)
        .map_err(|e| format!("Failed to load KAS private key: {:?}", e))?;

    let oaep_key = OaepPrivateDecryptingKey::new(private_key)
        .map_err(|e| format!("Failed to create OAEP key: {:?}", e))?;

    // Decrypt the wrapped key
    let mut plaintext = vec![0u8; oaep_key.min_output_size()];
    let decrypted = oaep_key
        .decrypt(&OAEP_SHA1_MGF1SHA1, &wrapped_key, &mut plaintext, None)
        .map_err(|e| format!("RSA decryption failed: {:?}", e))?;

    let symmetric_key = decrypted.to_vec();

    // Try to parse client's public key as EC first
    match parse_ec_public_key(client_public_key_pem) {
        Ok(client_public) => {
            // Generate a session key pair for re-wrapping to the client
            let session_private = p256::SecretKey::random(&mut rand::rngs::OsRng);
            let session_public = session_private.public_key();

            // For EC client key, use ECDH + AES-GCM
            let wrapped_for_client =
                wrap_key_for_ec_client(&session_private, &client_public, &symmetric_key)?;

            use p256::pkcs8::EncodePublicKey;
            let session_public_pem = session_public
                .to_public_key_pem(p256::pkcs8::LineEnding::LF)
                .map_err(|e| format!("Failed to encode session public key: {}", e))?;

            Ok((wrapped_for_client, session_public_pem))
        }
        Err(_) => {
            // Fall back to RSA wrapping
            parse_rsa_public_key_and_wrap(&symmetric_key, client_public_key_pem)
        }
    }
}

/// Unwrap an EC-wrapped key and re-wrap for the client
fn unwrap_ec_wrapped_key(
    state: &AppState,
    ephemeral_public_key_b64: &str,
    wrapped_key_b64: &str,
    client_public_key_pem: &str,
) -> Result<(String, String), String> {
    // Decode ephemeral public key
    let ephemeral_pk_bytes = BASE64
        .decode(ephemeral_public_key_b64)
        .map_err(|e| format!("Failed to decode ephemeral public key: {}", e))?;

    // Parse KAS EC private key
    use p256::pkcs8::DecodePrivateKey;
    let kas_private = p256::SecretKey::from_pkcs8_pem(&state.ec_private_key_pem)
        .map_err(|e| format!("Failed to parse KAS EC private key: {}", e))?;

    // Parse ephemeral public key (SEC1 compressed/uncompressed format)
    let ephemeral_public = p256::PublicKey::from_sec1_bytes(&ephemeral_pk_bytes)
        .map_err(|e| format!("Failed to parse ephemeral public key: {}", e))?;

    // Perform ECDH
    let shared_secret = p256::ecdh::diffie_hellman(
        kas_private.to_nonzero_scalar(),
        ephemeral_public.as_affine(),
    );

    // Derive symmetric key using HKDF
    use opentdf_crypto::hkdf::Hkdf;
    use opentdf_crypto::sha2::Sha256;

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes());
    let mut unwrap_key = [0u8; 32];
    hkdf.expand(&[], &mut unwrap_key)
        .map_err(|e| format!("HKDF expansion failed: {}", e))?;

    // Decode and decrypt the wrapped key
    let wrapped_key = BASE64
        .decode(wrapped_key_b64)
        .map_err(|e| format!("Failed to decode wrapped key: {}", e))?;

    // AES-GCM decrypt: nonce (12 bytes) || ciphertext || tag (16 bytes)
    if wrapped_key.len() < 28 {
        return Err(format!(
            "Wrapped key too short: {} bytes",
            wrapped_key.len()
        ));
    }

    use aes_gcm::{
        Aes256Gcm, Nonce,
        aead::{Aead, KeyInit},
    };

    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&wrapped_key[..12]);
    let ciphertext_and_tag = &wrapped_key[12..];

    #[allow(deprecated)]
    let cipher = Aes256Gcm::new_from_slice(&unwrap_key)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;

    #[allow(deprecated)]
    let symmetric_key = cipher
        .decrypt(nonce, ciphertext_and_tag)
        .map_err(|e| format!("AES-GCM decryption failed: {}", e))?;

    // Generate session key pair for re-wrapping
    let session_private = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let session_public = session_private.public_key();

    // Parse client's public key
    let client_public = parse_ec_public_key(client_public_key_pem)?;

    // Wrap key for client
    let wrapped_for_client =
        wrap_key_for_ec_client(&session_private, &client_public, &symmetric_key)?;

    use p256::pkcs8::EncodePublicKey;
    let session_public_pem = session_public
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|e| format!("Failed to encode session public key: {}", e))?;

    Ok((wrapped_for_client, session_public_pem))
}

/// Parse an EC public key from PEM
fn parse_ec_public_key(pem: &str) -> Result<p256::PublicKey, String> {
    use p256::pkcs8::DecodePublicKey;
    p256::PublicKey::from_public_key_pem(pem)
        .map_err(|e| format!("Failed to parse EC public key: {}", e))
}

/// Wrap a symmetric key for an RSA client
fn parse_rsa_public_key_and_wrap(
    symmetric_key: &[u8],
    client_public_key_pem: &str,
) -> Result<(String, String), String> {
    use aws_lc_rs::rsa::{OAEP_SHA1_MGF1SHA1, OaepPublicEncryptingKey, PublicEncryptingKey};

    // Parse the PEM
    let pem =
        pem::parse(client_public_key_pem).map_err(|e| format!("Failed to parse PEM: {}", e))?;

    // Load the public key
    let public_key = PublicEncryptingKey::from_der(pem.contents())
        .map_err(|e| format!("Failed to load RSA public key: {:?}", e))?;

    let oaep_key = OaepPublicEncryptingKey::new(public_key)
        .map_err(|e| format!("Failed to create OAEP key: {:?}", e))?;

    // Encrypt
    let mut ciphertext = vec![0u8; oaep_key.ciphertext_size()];
    let result = oaep_key
        .encrypt(&OAEP_SHA1_MGF1SHA1, symmetric_key, &mut ciphertext, None)
        .map_err(|e| format!("RSA encryption failed: {:?}", e))?;

    // No session key for RSA-only flow
    Ok((BASE64.encode(result), String::new()))
}

/// Wrap a symmetric key for an EC client using ECDH + AES-GCM
fn wrap_key_for_ec_client(
    session_private: &p256::SecretKey,
    client_public: &p256::PublicKey,
    symmetric_key: &[u8],
) -> Result<String, String> {
    // Perform ECDH
    let shared_secret = p256::ecdh::diffie_hellman(
        session_private.to_nonzero_scalar(),
        client_public.as_affine(),
    );

    // Derive wrapping key using HKDF
    use opentdf_crypto::hkdf::Hkdf;
    use opentdf_crypto::sha2::Sha256;

    // Use same salt as the client will use
    let mut salt_hasher = opentdf_crypto::sha2::Sha256::new();
    use opentdf_crypto::sha2::Digest;
    salt_hasher.update(b"TDF");
    let salt = salt_hasher.finalize();

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret.raw_secret_bytes());
    let mut wrap_key = [0u8; 32];
    hkdf.expand(&[], &mut wrap_key)
        .map_err(|e| format!("HKDF expansion failed: {}", e))?;

    // Generate random nonce
    use aes_gcm::{
        Aes256Gcm,
        aead::{Aead, AeadCore, KeyInit},
    };
    use rand::rngs::OsRng;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let cipher = Aes256Gcm::new_from_slice(&wrap_key)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;

    #[allow(deprecated)]
    let ciphertext = cipher
        .encrypt(&nonce, symmetric_key)
        .map_err(|e| format!("AES-GCM encryption failed: {}", e))?;

    // Concatenate nonce + ciphertext
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(&result))
}

// ============================================================================
// Main Server
// ============================================================================

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("MOCK_KAS_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9080);

    let state = AppState::new();

    // Save public keys to temp files for CLI testing
    let temp_dir = std::path::Path::new("/tmp/xtest");
    std::fs::create_dir_all(temp_dir).expect("Failed to create temp directory");

    let rsa_key_path = temp_dir.join("kas_public_rsa.pem");
    std::fs::write(&rsa_key_path, &state.rsa_public_key_pem)
        .expect("Failed to write RSA public key");

    let ec_key_path = temp_dir.join("kas_public_ec.pem");
    std::fs::write(&ec_key_path, &state.ec_public_key_pem).expect("Failed to write EC public key");

    println!("=== Mock KAS Server ===");
    println!("Port: {}", port);
    println!("RSA public key: {}", rsa_key_path.display());
    println!("EC public key: {}", ec_key_path.display());
    println!();
    println!("Endpoints:");
    println!("  GET  /health                  - Health check");
    println!("  GET  /kas/v2/kas_public_key   - Get KAS public key");
    println!("  POST /kas/v2/rewrap           - Rewrap key");
    println!("  POST /token                   - Get OAuth token");
    println!();

    let app = Router::new()
        .route("/health", get(health))
        .route("/kas/v2/kas_public_key", get(get_public_key_with_algorithm))
        .route("/kas/v2/rewrap", post(rewrap))
        .route("/token", post(token))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind");

    println!("Listening on http://{}", addr);
    println!("Press Ctrl+C to stop");
    println!();

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("Server error");
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C handler");
    println!("\nShutting down...");
}
