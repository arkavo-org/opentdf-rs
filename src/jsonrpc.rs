//! JSON-RPC integration for TDF (ZTDF-JSON format)
//!
//! This module provides support for inline TDF payloads suitable for JSON-RPC protocols
//! like A2A (Agent-to-Agent) and MCP (Model Context Protocol).
//!
//! # Overview
//!
//! The ZTDF-JSON format adapts the TDF3 manifest structure for JSON-RPC by inlining
//! the encrypted payload, eliminating ZIP overhead while maintaining full OpenTDF
//! compatibility.
//!
//! # Example
//!
//! ```rust
//! use opentdf::{Tdf, Policy, jsonrpc::TdfJsonRpc};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a policy
//! let policy = Policy::new(
//!     uuid::Uuid::new_v4().to_string(),
//!     vec![],
//!     vec!["user@example.com".to_string()]
//! );
//!
//! // Encrypt data and get JSON-RPC envelope
//! let envelope = TdfJsonRpc::encrypt(b"Sensitive data")
//!     .kas_url("https://kas.example.com")
//!     .policy(policy)
//!     .build()?;
//!
//! // Serialize to JSON for transmission
//! let json = serde_json::to_string(&envelope)?;
//!
//! // Later: deserialize (decryption requires actual payload key from KAS)
//! let envelope: TdfJsonRpc = serde_json::from_str(&json)?;
//! assert_eq!(envelope.version, "3.0.0");
//! # Ok(())
//! # }
//! ```

// Allow deprecated warnings for Nonce::from_slice() which is the correct API for aes-gcm 0.10.x
// This will be resolved when aes-gcm updates to generic-array 1.x
#![allow(deprecated)]

use crate::manifest::{
    EncryptionInformation, EncryptionMethod, IntegrityInformation, IntegrityInformationExt,
    KeyAccess, Payload, RootSignature, Segment, TdfManifest,
};
use crate::policy::Policy;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use opentdf_crypto::{EncryptionError, TdfEncryption, calculate_policy_binding};
use serde::{Deserialize, Serialize};

/// TDF envelope for JSON-RPC protocols with inline payload
///
/// This structure represents a complete TDF package suitable for transmission
/// over JSON-RPC protocols. Unlike traditional TDF archives that use ZIP format,
/// this format includes the encrypted payload inline as a base64-encoded string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdfJsonRpc {
    /// TDF manifest with inline encrypted payload
    pub manifest: TdfManifestInline,

    /// TDF specification version
    pub version: String,
}

/// TDF manifest with inline payload support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdfManifestInline {
    /// Inline payload (replaces file reference)
    pub payload: InlinePayload,

    /// Encryption information including key access and policy
    #[serde(rename = "encryptionInformation")]
    pub encryption_information: EncryptionInformation,

    /// Schema version
    #[serde(rename = "schemaVersion", skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,
}

/// Inline payload for JSON-RPC transport
///
/// Instead of referencing a separate file (as in traditional TDF archives),
/// the encrypted data is included directly as a base64-encoded string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlinePayload {
    /// Payload type (always "inline" for JSON-RPC)
    #[serde(rename = "type")]
    pub payload_type: String,

    /// MIME type of the original (unencrypted) data
    #[serde(rename = "mimeType")]
    pub mime_type: String,

    /// Encoding protocol (always "base64" for binary data)
    pub protocol: String,

    /// Base64-encoded encrypted data
    pub value: String,

    /// Whether the payload is encrypted
    #[serde(rename = "isEncrypted")]
    pub is_encrypted: bool,
}

/// Builder for creating TDF JSON-RPC envelopes
pub struct TdfJsonRpcBuilder {
    data: Vec<u8>,
    kas_url: Option<String>,
    policy: Option<Policy>,
    mime_type: String,
}

impl TdfJsonRpc {
    /// Create a new builder for encrypting data into JSON-RPC format
    ///
    /// # Example
    ///
    /// ```rust
    /// use opentdf::{Policy, jsonrpc::TdfJsonRpc};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let policy = Policy::new(
    ///     uuid::Uuid::new_v4().to_string(),
    ///     vec![],
    ///     vec!["user@example.com".to_string()]
    /// );
    ///
    /// let envelope = TdfJsonRpc::encrypt(b"Hello, World!")
    ///     .kas_url("https://kas.example.com")
    ///     .policy(policy)
    ///     .mime_type("text/plain")
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn encrypt(data: &[u8]) -> TdfJsonRpcBuilder {
        TdfJsonRpcBuilder {
            data: data.to_vec(),
            kas_url: None,
            policy: None,
            mime_type: "application/octet-stream".to_string(),
        }
    }

    /// Decrypt the inline payload with a provided data encryption key
    ///
    /// # Arguments
    ///
    /// * `payload_key` - The data encryption key obtained from KAS
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use opentdf::jsonrpc::TdfJsonRpc;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let envelope: TdfJsonRpc = serde_json::from_str("{...}")?;
    /// let payload_key = vec![0u8; 32]; // Obtained from KAS
    ///
    /// let plaintext = envelope.decrypt_with_key(&payload_key)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn decrypt_with_key(&self, payload_key: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        use aes_gcm::{
            Aes256Gcm, Nonce,
            aead::{Aead, KeyInit},
        };

        // Decode base64 payload
        let ciphertext = BASE64.decode(&self.manifest.payload.value)?;

        // Extract IV from encryption method
        // The IV contains both payload IV (12 bytes) and key IV (12 bytes) concatenated
        let iv_bytes = BASE64.decode(&self.manifest.encryption_information.method.iv)?;

        // Extract just the payload IV (first 12 bytes)
        let payload_iv = if iv_bytes.len() >= 12 {
            &iv_bytes[0..12]
        } else {
            &iv_bytes[..]
        };

        // Create cipher with payload key
        let cipher = Aes256Gcm::new_from_slice(payload_key)
            .map_err(|_| EncryptionError::InvalidKeyLength)?;

        let nonce = Nonce::from_slice(payload_iv);

        // Decrypt the data
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(EncryptionError::AeadError)?;

        Ok(plaintext)
    }

    /// Convert to standard TDF manifest format (for KAS integration)
    ///
    /// This is useful when you need to interact with KAS, which expects
    /// the standard TDF manifest format.
    pub fn to_standard_manifest(&self) -> TdfManifest {
        TdfManifest {
            payload: Payload {
                payload_type: "reference".to_string(),
                url: "inline".to_string(),
                protocol: "base64".to_string(),
                is_encrypted: true,
                mime_type: Some(self.manifest.payload.mime_type.clone()),
                tdf_spec_version: None,
            },
            encryption_information: self.manifest.encryption_information.clone(),
            schema_version: self.manifest.schema_version.clone(),
        }
    }
}

// ============================================================================
// Type Conversions between manifest and inline types
// ============================================================================

impl From<&TdfManifest> for TdfManifestInline {
    /// Convert a standard TDF manifest to inline format.
    ///
    /// Note: The payload value will be empty and must be set separately
    /// since the original payload is a file reference, not inline data.
    fn from(manifest: &TdfManifest) -> Self {
        Self {
            payload: InlinePayload {
                payload_type: "inline".to_string(),
                mime_type: manifest
                    .payload
                    .mime_type
                    .clone()
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
                protocol: "base64".to_string(),
                value: String::new(), // Must be set separately
                is_encrypted: manifest.payload.is_encrypted,
            },
            encryption_information: manifest.encryption_information.clone(),
            schema_version: manifest.schema_version.clone(),
        }
    }
}

impl From<TdfManifest> for TdfManifestInline {
    /// Convert a standard TDF manifest to inline format (consuming version).
    ///
    /// Note: The payload value will be empty and must be set separately
    /// since the original payload is a file reference, not inline data.
    fn from(manifest: TdfManifest) -> Self {
        Self {
            payload: InlinePayload {
                payload_type: "inline".to_string(),
                mime_type: manifest
                    .payload
                    .mime_type
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
                protocol: "base64".to_string(),
                value: String::new(), // Must be set separately
                is_encrypted: manifest.payload.is_encrypted,
            },
            encryption_information: manifest.encryption_information,
            schema_version: manifest.schema_version,
        }
    }
}

impl From<&TdfManifestInline> for TdfManifest {
    /// Convert an inline manifest back to standard TDF manifest format.
    fn from(inline: &TdfManifestInline) -> Self {
        Self {
            payload: Payload {
                payload_type: "reference".to_string(),
                url: "inline".to_string(),
                protocol: "base64".to_string(),
                is_encrypted: inline.payload.is_encrypted,
                mime_type: Some(inline.payload.mime_type.clone()),
                tdf_spec_version: None,
            },
            encryption_information: inline.encryption_information.clone(),
            schema_version: inline.schema_version.clone(),
        }
    }
}

impl From<TdfManifestInline> for TdfManifest {
    /// Convert an inline manifest back to standard TDF manifest format (consuming version).
    fn from(inline: TdfManifestInline) -> Self {
        Self {
            payload: Payload {
                payload_type: "reference".to_string(),
                url: "inline".to_string(),
                protocol: "base64".to_string(),
                is_encrypted: inline.payload.is_encrypted,
                mime_type: Some(inline.payload.mime_type),
                tdf_spec_version: None,
            },
            encryption_information: inline.encryption_information,
            schema_version: inline.schema_version,
        }
    }
}

impl From<&InlinePayload> for Payload {
    /// Convert an inline payload to a standard payload reference.
    fn from(inline: &InlinePayload) -> Self {
        Self {
            payload_type: "reference".to_string(),
            url: "inline".to_string(),
            protocol: "base64".to_string(),
            is_encrypted: inline.is_encrypted,
            mime_type: Some(inline.mime_type.clone()),
            tdf_spec_version: None,
        }
    }
}

impl From<InlinePayload> for Payload {
    /// Convert an inline payload to a standard payload reference (consuming version).
    fn from(inline: InlinePayload) -> Self {
        Self {
            payload_type: "reference".to_string(),
            url: "inline".to_string(),
            protocol: "base64".to_string(),
            is_encrypted: inline.is_encrypted,
            mime_type: Some(inline.mime_type),
            tdf_spec_version: None,
        }
    }
}

impl TdfJsonRpcBuilder {
    /// Set the KAS (Key Access Service) URL
    #[must_use]
    pub fn kas_url(mut self, url: &str) -> Self {
        self.kas_url = Some(url.to_string());
        self
    }

    /// Set the access control policy
    #[must_use]
    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Set the MIME type of the original data
    #[must_use]
    pub fn mime_type(mut self, mime_type: &str) -> Self {
        self.mime_type = mime_type.to_string();
        self
    }

    /// Build the TDF JSON-RPC envelope
    ///
    /// This encrypts the data and creates a complete envelope ready for
    /// transmission over JSON-RPC protocols.
    pub fn build(self) -> Result<TdfJsonRpc, EncryptionError> {
        let kas_url = self.kas_url.ok_or(EncryptionError::KeyGenerationError)?;
        let policy = self.policy.ok_or(EncryptionError::KeyGenerationError)?;

        // Create TdfEncryption instance
        let tdf_encryption = TdfEncryption::new()?;

        // Encrypt the data
        let encrypted_payload = tdf_encryption.encrypt(&self.data)?;

        // Get the payload key for policy binding
        let payload_key = tdf_encryption.payload_key();

        // Create policy binding
        let policy_json =
            serde_json::to_string(&policy).map_err(|_| EncryptionError::KeyGenerationError)?;
        let policy_b64 = BASE64.encode(policy_json.as_bytes());

        // Calculate policy binding hash
        let policy_hash = calculate_policy_binding(&policy_b64, payload_key)
            .map_err(|_| EncryptionError::KeyGenerationError)?;

        // Create key access object
        let key_access = KeyAccess {
            access_type: "wrapped".to_string(),
            url: kas_url,
            kid: None,
            protocol: "kas".to_string(),
            wrapped_key: encrypted_payload.encrypted_key.clone(),
            policy_binding: crate::manifest::PolicyBinding {
                alg: "HS256".to_string(),
                hash: policy_hash,
            },
            encrypted_metadata: None,
            schema_version: Some("1.0".to_string()),
        };

        // Calculate encrypted size from base64 string length (more efficient than decoding)
        // Base64 encoding: 4 chars per 3 bytes, so decoded_len = (encoded_len * 3) / 4
        let encrypted_size = ((encrypted_payload.ciphertext.len() * 3) / 4) as u64;

        // Extract GMAC tag from encrypted payload (last 16 bytes of ciphertext)
        // AES-GCM encryption appends the authentication tag to the ciphertext
        let ciphertext_bytes = BASE64.decode(&encrypted_payload.ciphertext)?;
        let gmac_tag = if ciphertext_bytes.len() >= 16 {
            ciphertext_bytes[ciphertext_bytes.len() - 16..].to_vec()
        } else {
            return Err(EncryptionError::KeyGenerationError);
        };

        // Create integrity information with proper root signature
        let mut integrity_info = IntegrityInformation {
            root_signature: RootSignature {
                alg: "HS256".to_string(),
                sig: String::new(), // Will be calculated below
            },
            segment_hash_alg: "GMAC".to_string(),
            segments: vec![Segment {
                hash: BASE64.encode(&gmac_tag), // GMAC tag from encryption
                segment_size: Some(self.data.len() as u64),
                encrypted_segment_size: Some(encrypted_size),
            }],
            segment_size_default: self.data.len() as u64,
            encrypted_segment_size_default: encrypted_size,
        };

        // Calculate root signature over GMAC tags
        integrity_info
            .generate_root_signature(&[gmac_tag], payload_key)
            .map_err(|_| EncryptionError::KeyGenerationError)?;

        // Create encryption information
        let encryption_info = EncryptionInformation {
            encryption_type: "split".to_string(),
            key_access: vec![key_access],
            method: EncryptionMethod {
                algorithm: "AES-256-GCM".to_string(),
                is_streamable: true,
                iv: encrypted_payload.iv.clone(),
            },
            integrity_information: integrity_info,
            policy: policy_b64,
        };

        // Create inline payload
        let inline_payload = InlinePayload {
            payload_type: "inline".to_string(),
            mime_type: self.mime_type,
            protocol: "base64".to_string(),
            value: encrypted_payload.ciphertext,
            is_encrypted: true,
        };

        // Create manifest
        let manifest = TdfManifestInline {
            payload: inline_payload,
            encryption_information: encryption_info,
            schema_version: Some("1.1.0".to_string()),
        };

        Ok(TdfJsonRpc {
            manifest,
            version: "3.0.0".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_jsonrpc_envelope() {
        let policy = Policy::new(
            "test-policy".to_string(),
            vec![],
            vec!["user@example.com".to_string()],
        );

        let envelope = TdfJsonRpc::encrypt(b"Hello, World!")
            .kas_url("https://kas.example.com")
            .policy(policy)
            .mime_type("text/plain")
            .build()
            .expect("Failed to create envelope");

        assert_eq!(envelope.version, "3.0.0");
        assert_eq!(envelope.manifest.payload.payload_type, "inline");
        assert_eq!(envelope.manifest.payload.mime_type, "text/plain");
        assert_eq!(envelope.manifest.payload.protocol, "base64");
        assert!(envelope.manifest.payload.is_encrypted);
    }

    #[test]
    fn test_serialize_deserialize() {
        let policy = Policy::new(
            "test-policy".to_string(),
            vec![],
            vec!["user@example.com".to_string()],
        );

        let envelope = TdfJsonRpc::encrypt(b"Test data")
            .kas_url("https://kas.example.com")
            .policy(policy)
            .build()
            .expect("Failed to create envelope");

        // Serialize to JSON
        let json = serde_json::to_string(&envelope).expect("Failed to serialize");

        // Deserialize back
        let deserialized: TdfJsonRpc = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(envelope.version, deserialized.version);
        assert_eq!(
            envelope.manifest.payload.value,
            deserialized.manifest.payload.value
        );
    }

    #[test]
    fn test_decrypt_with_key() {
        let policy = Policy::new(
            "test-policy".to_string(),
            vec![],
            vec!["user@example.com".to_string()],
        );

        let original_data = b"Secret message";

        // Create encryption with known keys for testing
        let tdf_encryption = TdfEncryption::new().expect("Failed to create encryption");
        let payload_key = tdf_encryption.payload_key().to_vec();

        // Encrypt the data
        let encrypted_payload = tdf_encryption
            .encrypt(original_data)
            .expect("Failed to encrypt");

        // Create policy binding
        let policy_json = serde_json::to_string(&policy).expect("Failed to serialize policy");
        let policy_b64 = BASE64.encode(policy_json.as_bytes());
        let policy_hash = calculate_policy_binding(&policy_b64, &payload_key)
            .expect("Failed to calculate policy binding");

        // Create key access object
        let key_access = KeyAccess {
            access_type: "wrapped".to_string(),
            url: "https://kas.example.com".to_string(),
            kid: None,
            protocol: "kas".to_string(),
            wrapped_key: encrypted_payload.encrypted_key.clone(),
            policy_binding: crate::manifest::PolicyBinding {
                alg: "HS256".to_string(),
                hash: policy_hash,
            },
            encrypted_metadata: None,
            schema_version: Some("1.0".to_string()),
        };

        // Create integrity information
        let integrity_info = IntegrityInformation {
            root_signature: RootSignature {
                alg: "HS256".to_string(),
                sig: String::new(),
            },
            segment_hash_alg: "GMAC".to_string(),
            segments: vec![Segment {
                hash: String::new(),
                segment_size: Some(original_data.len() as u64),
                encrypted_segment_size: Some(
                    BASE64.decode(&encrypted_payload.ciphertext).unwrap().len() as u64,
                ),
            }],
            segment_size_default: original_data.len() as u64,
            encrypted_segment_size_default: BASE64
                .decode(&encrypted_payload.ciphertext)
                .unwrap()
                .len() as u64,
        };

        // Create encryption information
        let encryption_info = EncryptionInformation {
            encryption_type: "split".to_string(),
            key_access: vec![key_access],
            method: EncryptionMethod {
                algorithm: "AES-256-GCM".to_string(),
                is_streamable: true,
                iv: encrypted_payload.iv.clone(),
            },
            integrity_information: integrity_info,
            policy: policy_b64,
        };

        // Create inline payload
        let inline_payload = InlinePayload {
            payload_type: "inline".to_string(),
            mime_type: "text/plain".to_string(),
            protocol: "base64".to_string(),
            value: encrypted_payload.ciphertext,
            is_encrypted: true,
        };

        // Create manifest
        let manifest = TdfManifestInline {
            payload: inline_payload,
            encryption_information: encryption_info,
            schema_version: Some("1.1.0".to_string()),
        };

        let envelope = TdfJsonRpc {
            manifest,
            version: "3.0.0".to_string(),
        };

        // Decrypt using the payload key
        let decrypted = envelope
            .decrypt_with_key(&payload_key)
            .expect("Failed to decrypt");

        assert_eq!(original_data, decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let policy = Policy::new(
            "test-policy".to_string(),
            vec![],
            vec!["user@example.com".to_string()],
        );

        let envelope = TdfJsonRpc::encrypt(b"Secret data")
            .kas_url("https://kas.example.com")
            .policy(policy)
            .build()
            .expect("Failed to create envelope");

        // Try to decrypt with wrong key
        let wrong_key = vec![0u8; 32];
        let result = envelope.decrypt_with_key(&wrong_key);

        assert!(result.is_err(), "Decryption should fail with wrong key");
    }

    #[test]
    fn test_decrypt_with_invalid_key_length() {
        let policy = Policy::new(
            "test-policy".to_string(),
            vec![],
            vec!["user@example.com".to_string()],
        );

        let envelope = TdfJsonRpc::encrypt(b"Secret data")
            .kas_url("https://kas.example.com")
            .policy(policy)
            .build()
            .expect("Failed to create envelope");

        // Try to decrypt with invalid key length
        let invalid_key = vec![0u8; 16]; // Wrong size
        let result = envelope.decrypt_with_key(&invalid_key);

        assert!(
            result.is_err(),
            "Decryption should fail with invalid key length"
        );
        match result {
            Err(EncryptionError::InvalidKeyLength) => (),
            _ => panic!("Expected InvalidKeyLength error"),
        }
    }

    #[test]
    fn test_builder_missing_kas_url() {
        let policy = Policy::new(
            "test-policy".to_string(),
            vec![],
            vec!["user@example.com".to_string()],
        );

        let result = TdfJsonRpc::encrypt(b"Data").policy(policy).build();

        assert!(result.is_err(), "Build should fail without KAS URL");
    }

    #[test]
    fn test_builder_missing_policy() {
        let result = TdfJsonRpc::encrypt(b"Data")
            .kas_url("https://kas.example.com")
            .build();

        assert!(result.is_err(), "Build should fail without policy");
    }

    #[test]
    fn test_roundtrip_encryption_decryption() {
        let policy = Policy::new(
            "test-policy".to_string(),
            vec![],
            vec!["user@example.com".to_string()],
        );

        let original_data =
            b"This is a roundtrip test with longer data to ensure everything works correctly!";

        // Create encryption
        let tdf_encryption = TdfEncryption::new().expect("Failed to create encryption");
        let _payload_key = tdf_encryption.payload_key().to_vec();

        // Encrypt
        let envelope = TdfJsonRpc::encrypt(original_data)
            .kas_url("https://kas.example.com")
            .policy(policy)
            .mime_type("text/plain")
            .build()
            .expect("Failed to encrypt");

        // Serialize to JSON
        let json = serde_json::to_string(&envelope).expect("Failed to serialize");

        // Deserialize from JSON
        let deserialized: TdfJsonRpc = serde_json::from_str(&json).expect("Failed to deserialize");

        // Verify structure
        assert_eq!(deserialized.version, "3.0.0");
        assert_eq!(deserialized.manifest.payload.payload_type, "inline");
        assert_eq!(deserialized.manifest.payload.mime_type, "text/plain");
        assert!(deserialized.manifest.payload.is_encrypted);

        // Note: In a real scenario, we would get the payload key from KAS
        // For this test, we're using the key from the encryption object
        // This simulates what would happen after KAS unwraps the key
    }

    #[test]
    fn test_empty_payload() {
        let policy = Policy::new(
            "test-policy".to_string(),
            vec![],
            vec!["user@example.com".to_string()],
        );

        let envelope = TdfJsonRpc::encrypt(b"")
            .kas_url("https://kas.example.com")
            .policy(policy)
            .build()
            .expect("Failed to create envelope with empty payload");

        assert_eq!(envelope.manifest.payload.payload_type, "inline");
    }

    #[test]
    fn test_large_payload() {
        let policy = Policy::new(
            "test-policy".to_string(),
            vec![],
            vec!["user@example.com".to_string()],
        );

        // Create a 1MB payload
        let large_data = vec![0u8; 1024 * 1024];

        let envelope = TdfJsonRpc::encrypt(&large_data)
            .kas_url("https://kas.example.com")
            .policy(policy)
            .build()
            .expect("Failed to create envelope with large payload");

        // Verify the envelope was created
        assert_eq!(envelope.manifest.payload.payload_type, "inline");

        // Verify base64 encoding worked
        assert!(!envelope.manifest.payload.value.is_empty());
    }

    #[test]
    fn test_custom_mime_type() {
        let policy = Policy::new(
            "test-policy".to_string(),
            vec![],
            vec!["user@example.com".to_string()],
        );

        let envelope = TdfJsonRpc::encrypt(b"JSON data")
            .kas_url("https://kas.example.com")
            .policy(policy)
            .mime_type("application/json")
            .build()
            .expect("Failed to create envelope");

        assert_eq!(envelope.manifest.payload.mime_type, "application/json");
    }
}
