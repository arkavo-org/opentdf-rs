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
//! 3. Sign request with JWT (ES256)
//! 4. POST to KAS `/v2/rewrap` endpoint
//! 5. Receive RSA-encrypted wrapped key
//! 6. Unwrap key using RSA-OAEP (SHA-256)
//!
//! ## NanoTDF - EC P-256:
//! 1. Generate ephemeral EC P-256 key pair
//! 2. Build unsigned rewrap request with manifest data
//! 3. Sign request with JWT (ES256)
//! 4. POST to KAS `/v2/rewrap` endpoint
//! 5. Receive wrapped key and session public key
//! 6. Unwrap key using ECDH + HKDF + AES-GCM
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
//! // Unwrap a key from a TDF manifest
//! let payload_key = client.rewrap_standard_tdf(&manifest).await?;
//! # Ok(())
//! # }
//! ```

use crate::manifest::TdfManifest;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "kas")]
use {
    aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    },
    hkdf::Hkdf,
    p256::{
        ecdsa::{signature::Signer, SigningKey},
        pkcs8::{DecodePublicKey, EncodePublicKey},
        PublicKey, SecretKey,
    },
    pkcs8::LineEnding,
    reqwest::Client,
    rsa::{Oaep, RsaPrivateKey, RsaPublicKey},
    serde_json::json,
    sha1::Sha1,
    sha2::{Digest, Sha256},
    std::time::{SystemTime, UNIX_EPOCH},
};

/// KAS client errors
#[derive(Debug, Error)]
pub enum KasError {
    #[error("HTTP error: {0}")]
    HttpError(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Key unwrapping failed: {0}")]
    UnwrapError(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("JSON serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[cfg(feature = "kas")]
    #[error("Reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),

    #[cfg(feature = "kas")]
    #[error("JWT error: {0}")]
    JwtError(String),

    #[cfg(feature = "kas")]
    #[error("PKCS8 error: {0}")]
    Pkcs8Error(String),
}

/// Unsigned rewrap request structure (before JWT signing)
#[derive(Debug, Serialize, Deserialize)]
pub struct UnsignedRewrapRequest {
    #[serde(rename = "clientPublicKey")]
    pub client_public_key: String,
    pub requests: Vec<PolicyRequest>,
}

/// Individual policy request entry
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    pub policy: Policy,
    #[serde(rename = "keyAccessObjects")]
    pub key_access_objects: Vec<KeyAccessObjectWrapper>,
}

/// Policy structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub body: String, // Base64-encoded policy
}

/// Key access object wrapper
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyAccessObjectWrapper {
    #[serde(rename = "keyAccessObjectId")]
    pub key_access_object_id: String,
    #[serde(rename = "keyAccessObject")]
    pub key_access_object: KeyAccessObject,
}

/// Key access object details
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyAccessObject {
    #[serde(rename = "type")]
    pub key_type: String,
    pub url: String,
    pub protocol: String,
    #[serde(rename = "wrappedKey")]
    pub wrapped_key: String,
    #[serde(rename = "policyBinding")]
    pub policy_binding: KasPolicyBinding,
    #[serde(rename = "encryptedMetadata", skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// Policy binding for KAS requests
#[derive(Debug, Serialize, Deserialize)]
pub struct KasPolicyBinding {
    pub hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
}

/// Signed rewrap request wrapper
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedRewrapRequest {
    pub signed_request_token: String,
}

/// Rewrap response structure
#[derive(Debug, Serialize, Deserialize)]
pub struct RewrapResponse {
    pub responses: Vec<PolicyRewrapResult>,
    #[serde(rename = "sessionPublicKey")]
    pub session_public_key: Option<String>,
}

/// Policy rewrap result
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyRewrapResult {
    #[serde(rename = "policyId")]
    pub policy_id: String,
    pub results: Vec<KeyAccessRewrapResult>,
}

/// Individual key access rewrap result
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyAccessRewrapResult {
    #[serde(rename = "keyAccessObjectId")]
    pub key_access_object_id: String,
    pub status: String,
    #[serde(rename = "kasWrappedKey")]
    pub kas_wrapped_key: Option<String>,
    #[serde(rename = "entityWrappedKey")]
    pub entity_wrapped_key: Option<String>, // Legacy field
    pub error: Option<String>,
}

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
        private_key: RsaPrivateKey,
        public_key_pem: String,
    },
}

#[cfg(feature = "kas")]
impl EphemeralKeyPair {
    /// Generate a new ephemeral key pair of the specified type
    pub fn new(key_type: KeyType) -> Result<Self, KasError> {
        use rand::rngs::OsRng;

        match key_type {
            KeyType::EC => {
                // Generate EC P-256 key pair for NanoTDF
                let private_key = SecretKey::random(&mut OsRng);
                let public_key = private_key.public_key();

                let public_key_pem = public_key
                    .to_public_key_pem(p256::pkcs8::LineEnding::LF)
                    .map_err(|e| KasError::Pkcs8Error(e.to_string()))?;

                Ok(EphemeralKeyPair::EC {
                    private_key,
                    public_key_pem,
                })
            }
            KeyType::RSA => {
                // Generate RSA-2048 key pair for Standard TDF
                let bits = 2048;
                let private_key = RsaPrivateKey::new(&mut OsRng, bits).map_err(|e| {
                    KasError::CryptoError(format!("RSA key generation failed: {}", e))
                })?;

                let public_key = RsaPublicKey::from(&private_key);

                let public_key_pem = public_key
                    .to_public_key_pem(LineEnding::LF)
                    .map_err(|e| KasError::Pkcs8Error(e.to_string()))?;

                Ok(EphemeralKeyPair::RSA {
                    private_key,
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
#[cfg(feature = "kas")]
pub struct KasClient {
    http_client: Client,
    base_url: String,
    oauth_token: String,
    signing_key: SigningKey,
}

#[cfg(feature = "kas")]
impl KasClient {
    /// Create a new KAS client
    ///
    /// # Arguments
    ///
    /// * `base_url` - Base URL of the KAS service (e.g., "http://kas.example.com")
    /// * `oauth_token` - OAuth bearer token for authentication
    pub fn new(
        base_url: impl Into<String>,
        oauth_token: impl Into<String>,
    ) -> Result<Self, KasError> {
        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| KasError::HttpError(e.to_string()))?;

        // Generate signing key for JWT
        let signing_key = SigningKey::random(&mut rand::rngs::OsRng);

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
    /// 2. Build and sign rewrap request
    /// 3. POST to KAS
    /// 4. Unwrap the returned key using RSA-OAEP
    ///
    /// Returns the unwrapped payload key ready for TDF decryption
    pub async fn rewrap_standard_tdf(&self, manifest: &TdfManifest) -> Result<Vec<u8>, KasError> {
        // Generate RSA ephemeral key pair for Standard TDF
        let ephemeral_key_pair = EphemeralKeyPair::new(KeyType::RSA)?;

        // Build the rewrap request
        let unsigned_request = self.build_rewrap_request(manifest, &ephemeral_key_pair)?;

        // Sign the request with JWT
        let signed_token = self.create_signed_jwt(&unsigned_request)?;
        let signed_request = SignedRewrapRequest {
            signed_request_token: signed_token,
        };

        // Make the HTTP request to KAS
        let rewrap_endpoint = format!("{}/v2/rewrap", self.base_url);

        let response = self
            .http_client
            .post(&rewrap_endpoint)
            .header("Authorization", format!("Bearer {}", self.oauth_token))
            .header("Content-Type", "application/json")
            .json(&signed_request)
            .send()
            .await?;

        // Handle HTTP errors
        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();

            return Err(match status.as_u16() {
                401 => KasError::AuthenticationFailed,
                403 => KasError::AccessDenied(error_body.clone()),
                _ => KasError::HttpError(format!("HTTP {}: {}", status, error_body)),
            });
        }

        // Parse response
        let rewrap_response: RewrapResponse = response.json().await?;

        // Extract the wrapped key and session public key
        let (wrapped_key, session_public_key_pem) = self.extract_wrapped_key(&rewrap_response)?;

        // Unwrap the key using ECDH + HKDF + AES-GCM
        let payload_key =
            self.unwrap_key(&wrapped_key, &session_public_key_pem, &ephemeral_key_pair)?;

        Ok(payload_key)
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
        let policy_json: serde_json::Value = serde_json::from_slice(&policy_bytes)
            .map_err(|e| KasError::HttpError(format!("Failed to parse policy JSON: {}", e)))?;

        // Extract UUID field
        let uuid = policy_json
            .get("uuid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KasError::HttpError("Policy missing 'uuid' field".to_string()))?;

        // Validate UUID format (should be 36 characters with hyphens)
        if uuid.len() != 36 {
            return Err(KasError::HttpError(format!(
                "Invalid UUID format: expected 36 characters, got {}",
                uuid.len()
            )));
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

    /// Create a signed JWT (ES256) for the rewrap request
    fn create_signed_jwt(&self, request: &UnsignedRewrapRequest) -> Result<String, KasError> {
        // Serialize request body to JSON
        let request_body = serde_json::to_string(request)?;

        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| KasError::JwtError(e.to_string()))?
            .as_secs();

        // Create custom JWT with requestBody claim
        let header = json!({
            "alg": "ES256",
            "typ": "JWT"
        });

        // IMPORTANT: requestBody MUST be a string, not a JSON object
        // The KAS server expects: token.Get("requestBody").(string)
        // See platform/service/kas/access/rewrap.go:146-149
        let payload = json!({
            "requestBody": request_body,
            "iat": now,
            "exp": now + 60
        });

        // Encode header and payload as base64url
        let header_b64 = self.base64url_encode(&serde_json::to_vec(&header)?);
        let payload_b64 = self.base64url_encode(&serde_json::to_vec(&payload)?);

        // Create signing input
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        // Sign with P-256 key
        let signature: p256::ecdsa::Signature = self.signing_key.sign(signing_input.as_bytes());

        // Encode signature as base64url
        let signature_b64 = self.base64url_encode(&signature.to_bytes());

        Ok(format!("{}.{}", signing_input, signature_b64))
    }

    /// Encode data as base64url (URL-safe, no padding)
    fn base64url_encode(&self, data: &[u8]) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        URL_SAFE_NO_PAD.encode(data)
    }

    /// Extract wrapped key from rewrap response
    fn extract_wrapped_key(
        &self,
        response: &RewrapResponse,
    ) -> Result<(Vec<u8>, String), KasError> {
        let policy_result = response
            .responses
            .first()
            .ok_or_else(|| KasError::InvalidResponse("Empty response".to_string()))?;

        let key_result = policy_result
            .results
            .first()
            .ok_or_else(|| KasError::InvalidResponse("No key results".to_string()))?;

        // Check status
        if key_result.status != "permit" {
            let error_msg = key_result
                .error
                .clone()
                .unwrap_or_else(|| "Access denied".to_string());
            return Err(KasError::AccessDenied(error_msg));
        }

        // Get wrapped key (try kasWrappedKey first, then entityWrappedKey for legacy)
        let wrapped_key_b64 = key_result
            .kas_wrapped_key
            .as_ref()
            .or(key_result.entity_wrapped_key.as_ref())
            .ok_or_else(|| KasError::InvalidResponse("Missing wrapped key".to_string()))?;

        let wrapped_key = BASE64.decode(wrapped_key_b64)?;

        // Get session public key
        let session_public_key = response
            .session_public_key
            .as_ref()
            .ok_or_else(|| KasError::InvalidResponse("Missing session public key".to_string()))?
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
                // IMPORTANT: Must use SHA1 to match Go SDK implementation
                // See: platform/lib/ocrypto/asym_decryption.go:104
                let padding = Oaep::new::<Sha1>();

                let payload_key = private_key.decrypt(padding, wrapped_key).map_err(|e| {
                    KasError::UnwrapError(format!("RSA-OAEP decryption failed: {}", e))
                })?;

                Ok(payload_key)
            }
            EphemeralKeyPair::EC { private_key, .. } => {
                // EC/ECDH unwrap for NanoTDF
                // Parse session public key from PEM
                let session_public_key = PublicKey::from_public_key_pem(session_public_key_pem)
                    .map_err(|e| {
                        KasError::CryptoError(format!("Failed to parse session public key: {}", e))
                    })?;

                // Perform ECDH key agreement
                let shared_secret = p256::elliptic_curve::ecdh::diffie_hellman(
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
                    .map_err(|e| KasError::CryptoError(format!("HKDF expansion failed: {}", e)))?;

                // Unwrap key using AES-GCM
                // Format: nonce (12 bytes) || ciphertext || tag (16 bytes)
                if wrapped_key.len() < 28 {
                    return Err(KasError::UnwrapError(format!(
                        "Wrapped key too short: {} bytes",
                        wrapped_key.len()
                    )));
                }

                let nonce = Nonce::from_slice(&wrapped_key[..12]);
                let ciphertext_and_tag = &wrapped_key[12..];

                let cipher = Aes256Gcm::new_from_slice(&symmetric_key).map_err(|e| {
                    KasError::CryptoError(format!("Failed to create cipher: {}", e))
                })?;

                let payload_key = cipher.decrypt(nonce, ciphertext_and_tag).map_err(|e| {
                    KasError::UnwrapError(format!("AES-GCM decryption failed: {}", e))
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
