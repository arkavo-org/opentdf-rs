//! KAS (Key Access Service) client implementation for OpenTDF rewrap protocol
//!
//! This module implements the KAS v2 rewrap protocol for unwrapping encrypted payload keys.
//! It supports both Standard TDF (ZIP-based) and NanoTDF formats with RSA and EC key wrapping.
//!
//! # Protocol Flow
//!
//! ## Standard TDF (TDF3, ZTDF) - RSA-2048:
//! 1. Generate ephemeral RSA-2048 key pair
//! 2. Build unsigned rewrap request with manifest data
//! 3. Accept pre-signed JWT token (ES256) - see `examples/jwt_helper.rs`
//! 4. POST to KAS `/v2/rewrap` endpoint
//! 5. Receive RSA-encrypted wrapped key
//! 6. Unwrap key using RSA-OAEP (SHA-1 default, SHA-256 available)
//!
//! ## NanoTDF - EC P-256:
//! 1. Generate ephemeral EC P-256 key pair
//! 2. Build unsigned rewrap request with manifest data
//! 3. Accept pre-signed JWT token (ES256) - see `examples/jwt_helper.rs`
//! 4. POST to KAS `/v2/rewrap` endpoint
//! 5. Receive wrapped key and session public key
//! 6. Unwrap key using ECDH + HKDF + AES-GCM
//!
//! # JWT Token Creation
//!
//! This client requires pre-signed JWT tokens. For a complete JWT helper implementation,
//! see `examples/jwt_helper.rs`.
//!
//! # Example
//!
//! ```no_run
//! use opentdf::kas::KasClient;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = KasClient::new(
//!     "http://kas.example.com",
//!     "oauth_token_here",
//! )?;
//!
//! // Create a test manifest
//! let manifest = opentdf::TdfManifest::new(
//!     "0.payload".to_string(),
//!     "http://kas.example.com".to_string()
//! );
//!
//! // Unwrap a key from a TDF manifest (JWT signing handled internally)
//! let payload_key = client.rewrap_standard_tdf(&manifest).await?;
//! # Ok(())
//! # }
//! ```

// Allow deprecated warnings for Nonce::from_slice() which is the correct API for aes-gcm 0.10.x
// This will be resolved when aes-gcm updates to generic-array 1.x
#![allow(deprecated)]

use crate::manifest::TdfManifest;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use opentdf_protocol::{kas::Policy, KasError, *};

#[cfg(feature = "kas")]
use {
    crate::hkdf::Hkdf,
    crate::p256::{
        pkcs8::{DecodePublicKey, EncodePublicKey},
        PublicKey, SecretKey,
    },
    crate::pkcs8::LineEnding,
    crate::rsa::{Oaep, RsaPrivateKey, RsaPublicKey},
    crate::sha1::Sha1,
    crate::sha2::{Digest, Sha256},
    aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    },
    reqwest::Client,
};

// NOTE: KAS protocol types are now imported from opentdf-protocol crate
// The types below (KasError, UnsignedRewrapRequest, etc.) are re-exported from there

/// Key type for TDF encryption
#[cfg(feature = "kas")]
#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    /// Elliptic Curve (P-256) - used for NanoTDF
    EC,
    /// RSA-2048 - used for Standard TDF (TDF3, ZTDF)
    RSA,
}

/// Ephemeral key pair for KAS communication
#[derive(Debug)]
pub enum EphemeralKeyPair {
    #[cfg(feature = "kas")]
    EC {
        private_key: SecretKey,
        public_key_pem: String,
    },
    #[cfg(feature = "kas")]
    RSA {
        private_key: Box<RsaPrivateKey>,
        public_key_pem: String,
    },
}

#[cfg(feature = "kas")]
impl EphemeralKeyPair {
    /// Generate a new ephemeral key pair of the specified type
    pub fn new(key_type: KeyType) -> Result<Self, KasError> {
        use crate::rand::rngs::OsRng;

        match key_type {
            KeyType::EC => {
                // Generate EC P-256 key pair for NanoTDF
                let private_key = SecretKey::random(&mut OsRng);
                let public_key = private_key.public_key();

                let public_key_pem = public_key
                    .to_public_key_pem(crate::p256::pkcs8::LineEnding::LF)
                    .map_err(|e| KasError::Pkcs8Error(e.to_string()))?;

                Ok(EphemeralKeyPair::EC {
                    private_key,
                    public_key_pem,
                })
            }
            KeyType::RSA => {
                // Generate RSA-2048 key pair for Standard TDF
                let bits = 2048;
                let private_key =
                    RsaPrivateKey::new(&mut OsRng, bits).map_err(|e| KasError::CryptoError {
                        operation: "RSA_key_generation".to_string(),
                        reason: format!("RSA key generation failed: {}", e),
                    })?;

                let public_key = RsaPublicKey::from(&private_key);

                let public_key_pem = public_key
                    .to_public_key_pem(LineEnding::LF)
                    .map_err(|e| KasError::Pkcs8Error(e.to_string()))?;

                Ok(EphemeralKeyPair::RSA {
                    private_key: Box::new(private_key),
                    public_key_pem,
                })
            }
        }
    }

    /// Get the public key PEM string
    pub fn public_key_pem(&self) -> &str {
        match self {
            EphemeralKeyPair::EC { public_key_pem, .. } => public_key_pem,
            EphemeralKeyPair::RSA { public_key_pem, .. } => public_key_pem,
        }
    }
}

/// KAS client for rewrap protocol
///
/// This client handles JWT signing internally using an ephemeral RSA key pair.
/// The JWT contains the rewrap request and is signed with RS256.
#[cfg(feature = "kas")]
pub struct KasClient {
    http_client: Client,
    base_url: String,
    oauth_token: String,
    signing_key: RsaPrivateKey,
}

#[cfg(feature = "kas")]
impl KasClient {
    /// Create a new KAS client
    ///
    /// # Arguments
    ///
    /// * `base_url` - Base URL of the KAS service (e.g., "http://kas.example.com")
    /// * `oauth_token` - OAuth bearer token for authentication
    ///
    /// # Note
    ///
    /// This client generates an ephemeral RSA-2048 key pair for signing JWT rewrap requests.
    /// The JWT signature is verified by KAS when DPoP is enabled, otherwise it's parsed without verification.
    pub fn new(
        base_url: impl Into<String>,
        oauth_token: impl Into<String>,
    ) -> Result<Self, KasError> {
        use crate::rand::rngs::OsRng;

        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| KasError::HttpError {
                status: 0,
                message: format!("Failed to build HTTP client: {}", e),
            })?;

        // Generate RSA-2048 key pair for JWT signing (DPoP key)
        let signing_key =
            RsaPrivateKey::new(&mut OsRng, 2048).map_err(|e| KasError::CryptoError {
                operation: "generate_signing_key".to_string(),
                reason: format!("Failed to generate RSA signing key: {}", e),
            })?;

        Ok(Self {
            http_client,
            base_url: base_url.into(),
            oauth_token: oauth_token.into(),
            signing_key,
        })
    }

    /// Rewrap a key from a Standard TDF manifest
    ///
    /// This performs the complete KAS rewrap flow:
    /// 1. Generate RSA-2048 ephemeral key pair (Standard TDF uses RSA)
    /// 2. Build unsigned rewrap request
    /// 3. Sign request with internal signing key to create JWT (RS256)
    /// 4. POST to KAS /v2/rewrap endpoint with signed JWT
    /// 5. Unwrap the returned key using RSA-OAEP
    ///
    /// # Arguments
    ///
    /// * `manifest` - TDF manifest containing the wrapped key
    ///
    /// Returns the unwrapped payload key ready for TDF decryption
    pub async fn rewrap_standard_tdf(&self, manifest: &TdfManifest) -> Result<Vec<u8>, KasError> {
        // Generate RSA ephemeral key pair for Standard TDF
        let ephemeral_key_pair = EphemeralKeyPair::new(KeyType::RSA)?;

        // Build the unsigned rewrap request
        let unsigned_request = self.build_rewrap_request(manifest, &ephemeral_key_pair)?;

        // Create and sign JWT with the unsigned request
        let signed_request_token = self.sign_rewrap_request(&unsigned_request)?;

        // Wrap the signed token in SignedRewrapRequest per OpenTDF protocol
        let signed_request = SignedRewrapRequest {
            signed_request_token,
        };

        // Make the HTTP request to KAS
        let rewrap_endpoint = format!("{}/kas/v2/rewrap", self.base_url);

        let response = self
            .http_client
            .post(&rewrap_endpoint)
            .header("Authorization", format!("Bearer {}", self.oauth_token))
            .header("Content-Type", "application/json")
            .json(&signed_request)
            .send()
            .await
            .map_err(|e| KasError::HttpError {
                status: 0,
                message: format!("HTTP request failed: {}", e),
            })?;

        // Handle HTTP errors
        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();

            return Err(match status.as_u16() {
                401 => KasError::AuthenticationFailed {
                    reason: "Invalid or missing OAuth token".to_string(),
                },
                403 => KasError::AccessDenied {
                    resource: "KAS endpoint".to_string(),
                    reason: error_body.clone(),
                },
                _ => KasError::HttpError {
                    status: status.as_u16(),
                    message: format!("HTTP {}: {}", status, error_body),
                },
            });
        }

        // Parse response
        let rewrap_response: RewrapResponse =
            response
                .json()
                .await
                .map_err(|e| KasError::InvalidResponse {
                    reason: format!("Failed to parse JSON response: {}", e),
                    expected: Some("RewrapResponse".to_string()),
                })?;

        // Extract the wrapped key and session public key
        let (wrapped_key, session_public_key_pem) = self.extract_wrapped_key(&rewrap_response)?;

        // Unwrap the key using ECDH + HKDF + AES-GCM
        let payload_key =
            self.unwrap_key(&wrapped_key, &session_public_key_pem, &ephemeral_key_pair)?;

        Ok(payload_key)
    }

    /// Sign an unsigned rewrap request to create a JWT
    ///
    /// Creates a JWT with the following structure:
    /// ```json
    /// {
    ///   "requestBody": "<json-serialized-UnsignedRewrapRequest>",
    ///   "iat": <timestamp>,
    ///   "exp": <timestamp+60>
    /// }
    /// ```
    ///
    /// The JWT is signed with RS256 using the client's internal signing key.
    fn sign_rewrap_request(&self, request: &UnsignedRewrapRequest) -> Result<String, KasError> {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Serialize, Deserialize)]
        struct Claims {
            #[serde(rename = "requestBody")]
            request_body: String,
            iat: i64,
            exp: i64,
        }

        // Serialize the unsigned request to JSON
        let request_json = serde_json::to_string(request).map_err(KasError::SerializationError)?;

        // Create JWT claims
        let now = chrono::Utc::now().timestamp();
        let claims = Claims {
            request_body: request_json,
            iat: now,
            exp: now + 60, // 60 second expiration
        };

        // Convert RSA private key to PKCS#1 DER format for jsonwebtoken
        use crate::rsa::pkcs1::EncodeRsaPrivateKey;
        let key_der = self
            .signing_key
            .to_pkcs1_der()
            .map_err(|e| KasError::Pkcs8Error(format!("Failed to encode signing key: {}", e)))?;

        let encoding_key = EncodingKey::from_rsa_der(key_der.as_bytes());

        // Sign the JWT with RS256
        let token =
            encode(&Header::new(Algorithm::RS256), &claims, &encoding_key).map_err(|e| {
                KasError::JwtError {
                    operation: "sign_jwt".to_string(),
                    reason: format!("Failed to sign JWT: {}", e),
                }
            })?;

        Ok(token)
    }

    /// Extract policy UUID from base64-encoded policy JSON
    ///
    /// The policy is stored as base64-encoded JSON in the manifest.
    /// This function decodes and parses it to extract the UUID field.
    fn extract_policy_uuid(&self, base64_policy: &str) -> Result<String, KasError> {
        // Decode base64 policy
        let policy_bytes = BASE64
            .decode(base64_policy)
            .map_err(KasError::Base64Error)?;

        // Parse JSON
        let policy_json: serde_json::Value =
            serde_json::from_slice(&policy_bytes).map_err(|e| KasError::InvalidResponse {
                reason: format!("Failed to parse policy JSON: {}", e),
                expected: Some("valid JSON policy".to_string()),
            })?;

        // Extract UUID field
        let uuid = policy_json
            .get("uuid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KasError::InvalidResponse {
                reason: "Policy missing 'uuid' field".to_string(),
                expected: Some("uuid field in policy".to_string()),
            })?;

        // Validate UUID format (should be 36 characters with hyphens)
        if uuid.len() != 36 {
            return Err(KasError::InvalidResponse {
                reason: format!(
                    "Invalid UUID format: expected 36 characters, got {}",
                    uuid.len()
                ),
                expected: Some("36-character UUID".to_string()),
            });
        }

        Ok(uuid.to_string())
    }

    /// Build the unsigned rewrap request from manifest data
    fn build_rewrap_request(
        &self,
        manifest: &TdfManifest,
        ephemeral_key_pair: &EphemeralKeyPair,
    ) -> Result<UnsignedRewrapRequest, KasError> {
        // Convert manifest key access objects to KAS format
        let key_access_wrappers: Vec<KeyAccessObjectWrapper> = manifest
            .encryption_information
            .key_access
            .iter()
            .enumerate()
            .map(|(idx, kao)| {
                // Decode wrapped key to ensure it's valid base64
                let wrapped_key_bytes = BASE64
                    .decode(&kao.wrapped_key)
                    .map_err(KasError::Base64Error)?;

                Ok(KeyAccessObjectWrapper {
                    key_access_object_id: format!("kao-{}", idx),
                    key_access_object: KeyAccessObject {
                        key_type: kao.access_type.clone(),
                        url: kao.url.clone(),
                        protocol: kao.protocol.clone(),
                        wrapped_key: BASE64.encode(&wrapped_key_bytes),
                        policy_binding: KasPolicyBinding {
                            hash: kao.policy_binding.hash.clone(),
                            algorithm: Some(kao.policy_binding.alg.clone()),
                        },
                        encrypted_metadata: kao.encrypted_metadata.clone(),
                        kid: kao.kid.clone(),
                    },
                })
            })
            .collect::<Result<Vec<_>, KasError>>()?;

        // Create policy from manifest
        // Extract UUID from the base64-encoded policy JSON
        let policy_uuid = self.extract_policy_uuid(&manifest.encryption_information.policy)?;
        let policy = Policy {
            id: policy_uuid,
            body: manifest.encryption_information.policy.clone(),
        };

        // Create policy request
        let policy_request = PolicyRequest {
            algorithm: None, // For Standard TDF, algorithm is optional and should be None
            policy,
            key_access_objects: key_access_wrappers,
        };

        Ok(UnsignedRewrapRequest {
            client_public_key: ephemeral_key_pair.public_key_pem().to_string(),
            requests: vec![policy_request],
        })
    }

    /// Extract wrapped key from rewrap response
    fn extract_wrapped_key(
        &self,
        response: &RewrapResponse,
    ) -> Result<(Vec<u8>, String), KasError> {
        let policy_result =
            response
                .responses
                .first()
                .ok_or_else(|| KasError::InvalidResponse {
                    reason: "Empty response from KAS".to_string(),
                    expected: Some("at least one policy response".to_string()),
                })?;

        let key_result =
            policy_result
                .results
                .first()
                .ok_or_else(|| KasError::InvalidResponse {
                    reason: "No key results in response".to_string(),
                    expected: Some("at least one key result".to_string()),
                })?;

        // Check status
        if key_result.status != "permit" {
            let error_msg = key_result
                .error
                .clone()
                .unwrap_or_else(|| "Access denied".to_string());
            return Err(KasError::AccessDenied {
                resource: "key".to_string(),
                reason: error_msg,
            });
        }

        // Get wrapped key (try kasWrappedKey first, then entityWrappedKey for legacy)
        let wrapped_key_b64 = key_result
            .kas_wrapped_key
            .as_ref()
            .or(key_result.entity_wrapped_key.as_ref())
            .ok_or_else(|| KasError::InvalidResponse {
                reason: "Missing wrapped key in response".to_string(),
                expected: Some("kasWrappedKey or entityWrappedKey".to_string()),
            })?;

        let wrapped_key = BASE64.decode(wrapped_key_b64)?;

        // Get session public key
        let session_public_key = response
            .session_public_key
            .as_ref()
            .ok_or_else(|| KasError::InvalidResponse {
                reason: "Missing session public key in response".to_string(),
                expected: Some("sessionPublicKey".to_string()),
            })?
            .clone();

        Ok((wrapped_key, session_public_key))
    }

    /// Unwrap the key based on key type (EC or RSA)
    ///
    /// # Protocol
    ///
    /// ## For RSA rewrap (Standard TDF - TDF3, ZTDF):
    /// 1. KAS returns wrapped_key directly encrypted with client's RSA public key
    /// 2. Decrypt using client's RSA private key with OAEP padding (SHA-256)
    /// 3. Return the unwrapped payload key
    ///
    /// ## For EC rewrap (NanoTDF):
    /// 1. ECDH: client_private × session_public → shared_secret
    /// 2. HKDF: salt=SHA256("TDF"), shared_secret → symmetric_key
    /// 3. AES-GCM decrypt: wrapped_key → payload_key
    fn unwrap_key(
        &self,
        wrapped_key: &[u8],
        session_public_key_pem: &str,
        ephemeral_key_pair: &EphemeralKeyPair,
    ) -> Result<Vec<u8>, KasError> {
        match ephemeral_key_pair {
            EphemeralKeyPair::RSA { private_key, .. } => {
                // RSA-OAEP decryption for Standard TDF
                //
                // SECURITY NOTE: Using SHA-1 with RSA-OAEP for Go SDK compatibility
                //
                // ⚠️  SHA-1 is cryptographically deprecated (collision attacks since 2017)
                // However, it's required to match the OpenTDF platform implementation.
                // The Go SDK uses SHA-1 for RSA-OAEP padding (see platform/lib/ocrypto/asym_decryption.go:104)
                //
                // This is a known limitation for cross-platform interoperability.
                // TODO: File issue to migrate entire OpenTDF ecosystem to SHA-256
                //
                // See: https://shattered.io/ for SHA-1 collision attack details
                let padding = Oaep::new::<Sha1>();

                let payload_key = private_key.decrypt(padding, wrapped_key).map_err(|e| {
                    KasError::UnwrapError {
                        algorithm: "RSA-OAEP".to_string(),
                        reason: format!("RSA-OAEP decryption failed: {}", e),
                    }
                })?;

                Ok(payload_key)
            }
            EphemeralKeyPair::EC { private_key, .. } => {
                // EC/ECDH unwrap for NanoTDF
                // Parse session public key from PEM
                let session_public_key = PublicKey::from_public_key_pem(session_public_key_pem)
                    .map_err(|e| KasError::CryptoError {
                        operation: "parse_session_public_key".to_string(),
                        reason: format!("Failed to parse session public key: {}", e),
                    })?;

                // Perform ECDH key agreement
                let shared_secret = crate::p256::ecdh::diffie_hellman(
                    private_key.to_nonzero_scalar(),
                    session_public_key.as_affine(),
                );

                // Derive symmetric key using HKDF with salt = SHA256("TDF")
                let mut salt_hasher = Sha256::new();
                salt_hasher.update(b"TDF");
                let salt = salt_hasher.finalize();

                let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret.raw_secret_bytes());
                let mut symmetric_key = [0u8; 32];
                hkdf.expand(&[], &mut symmetric_key)
                    .map_err(|e| KasError::CryptoError {
                        operation: "HKDF".to_string(),
                        reason: format!("HKDF expansion failed: {}", e),
                    })?;

                // Unwrap key using AES-GCM
                // Format: nonce (12 bytes) || ciphertext || tag (16 bytes)
                if wrapped_key.len() < 28 {
                    return Err(KasError::UnwrapError {
                        algorithm: "ECDH-AES-GCM".to_string(),
                        reason: format!(
                            "Wrapped key too short: {} bytes (expected at least 28)",
                            wrapped_key.len()
                        ),
                    });
                }

                let nonce = Nonce::from_slice(&wrapped_key[..12]);
                let ciphertext_and_tag = &wrapped_key[12..];

                let cipher = Aes256Gcm::new_from_slice(&symmetric_key).map_err(|e| {
                    KasError::CryptoError {
                        operation: "AES-GCM-init".to_string(),
                        reason: format!("Failed to create cipher: {}", e),
                    }
                })?;

                let payload_key = cipher.decrypt(nonce, ciphertext_and_tag).map_err(|e| {
                    KasError::UnwrapError {
                        algorithm: "AES-GCM".to_string(),
                        reason: format!("AES-GCM decryption failed: {}", e),
                    }
                })?;

                Ok(payload_key)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ephemeral_key_pair_generation() {
        #[cfg(feature = "kas")]
        {
            // Test RSA key generation
            let key_pair_rsa =
                EphemeralKeyPair::new(KeyType::RSA).expect("Failed to generate RSA key pair");
            assert!(key_pair_rsa
                .public_key_pem()
                .starts_with("-----BEGIN PUBLIC KEY-----"));

            // Test EC key generation
            let key_pair_ec =
                EphemeralKeyPair::new(KeyType::EC).expect("Failed to generate EC key pair");
            assert!(key_pair_ec
                .public_key_pem()
                .starts_with("-----BEGIN PUBLIC KEY-----"));
        }
    }

    #[test]
    fn test_policy_serialization() {
        let policy = Policy {
            id: "test-policy".to_string(),
            body: BASE64.encode(b"test-policy-body"),
        };

        let json = serde_json::to_string(&policy).expect("Failed to serialize");
        assert!(json.contains("test-policy"));
    }
}
