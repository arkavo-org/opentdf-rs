//! TDF-CBOR format implementation (per TDF-CBOR specification draft-00)
//!
//! This module provides support for CBOR-encoded TDF payloads optimized for
//! binary protocols and size-constrained environments.
//!
//! # Overview
//!
//! TDF-CBOR defines a CBOR-based container format for TDF that:
//! - Uses integer keys for compact encoding
//! - Stores binary payloads directly (no base64)
//! - Includes self-describe CBOR tag for format detection
//!
//! # Example
//!
//! ```rust,no_run
//! # #[cfg(feature = "cbor")]
//! use opentdf::{Policy, tdf_cbor::TdfCbor};
//!
//! # #[cfg(feature = "cbor")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a policy
//! let policy = opentdf::Policy::new(
//!     uuid::Uuid::new_v4().to_string(),
//!     vec![],
//!     vec!["user@example.com".to_string()]
//! );
//!
//! // Encrypt data and get TDF-CBOR container
//! let container = TdfCbor::encrypt(b"Sensitive data")
//!     .kas_url("https://kas.example.com")
//!     .policy(policy)
//!     .build()?;
//!
//! // Serialize to CBOR bytes
//! let cbor_bytes = container.to_bytes()?;
//!
//! // Later: parse from bytes
//! let parsed = TdfCbor::from_bytes(&cbor_bytes)?;
//! assert_eq!(parsed.tdf, "cbor");
//! assert_eq!(parsed.version, [1, 0, 0]);
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "cbor"))]
//! # fn main() {}
//! ```

use crate::manifest::{
    EncryptionInformation, EncryptionMethod, IntegrityInformation, IntegrityInformationExt,
    KeyAccess, RootSignature, Segment,
};
use crate::policy::Policy;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use opentdf_crypto::{EncryptionError, TdfEncryption, calculate_policy_binding};
use serde::{Deserialize, Serialize};

// ============================================================================
// TDF-CBOR Magic Bytes
// ============================================================================

/// Self-describe CBOR tag (55799) + map marker
/// D9 D9F7 = tag(55799)
/// A5 = map(5) for 5 top-level elements
pub const CBOR_MAGIC: [u8; 4] = [0xD9, 0xD9, 0xF7, 0xA5];

/// Integer key mappings per TDF-CBOR spec section 3.1
pub mod key {
    pub const TDF: u64 = 1;
    pub const VERSION: u64 = 2;
    pub const CREATED: u64 = 3;
    pub const MANIFEST: u64 = 4;
    pub const PAYLOAD: u64 = 5;
}

// ============================================================================
// TDF-CBOR Spec-Compliant Types
// ============================================================================

/// TDF-CBOR envelope for binary payload transmission (spec-compliant)
///
/// This structure represents a complete TDF-CBOR package per the TDF-CBOR
/// specification draft-00. The format uses integer keys and binary payloads
/// for optimal size and parsing efficiency.
///
/// # Integer Key Mapping
///
/// | Key | Field    | Type                |
/// |-----|----------|---------------------|
/// | 1   | tdf      | string "cbor"       |
/// | 2   | version  | [u8; 3] semver      |
/// | 3   | created  | u64 Unix timestamp  |
/// | 4   | manifest | TdfCborManifest     |
/// | 5   | payload  | CborPayload         |
#[derive(Debug, Clone)]
pub struct TdfCbor {
    /// Format identifier. MUST be "cbor" for TDF-CBOR documents.
    pub tdf: String,

    /// Semantic version as [major, minor, patch] array
    pub version: [u8; 3],

    /// Unix timestamp of document creation (optional)
    pub created: Option<u64>,

    /// TDF manifest containing encryption and policy information
    pub manifest: TdfCborManifest,

    /// Binary encrypted payload container
    pub payload: CborPayload,
}

/// TDF manifest for TDF-CBOR format
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdfCborManifest {
    /// Encryption information including key access and policy
    pub encryption_information: EncryptionInformation,

    /// Optional assertions for additional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertions: Option<Vec<serde_json::Value>>,
}

/// Binary payload for TDF-CBOR transport
///
/// Contains the encrypted data directly as binary bytes (no base64 encoding).
#[derive(Debug, Clone)]
pub struct CborPayload {
    /// Payload type. MUST be "inline" for TDF-CBOR
    pub payload_type: String,

    /// Protocol. MUST be "binary" for TDF-CBOR (not "base64")
    pub protocol: String,

    /// MIME type of the original (unencrypted) data
    pub mime_type: Option<String>,

    /// Whether the payload is encrypted. MUST be true
    pub is_encrypted: bool,

    /// Raw encrypted bytes (not base64 encoded)
    pub value: Vec<u8>,
}

// ============================================================================
// TDF-CBOR Error Types
// ============================================================================

/// Errors specific to TDF-CBOR parsing and validation
#[derive(Debug)]
pub enum TdfCborError {
    /// Invalid or missing CBOR magic bytes
    InvalidMagicBytes,
    /// Invalid tdf identifier
    InvalidTdfIdentifier(String),
    /// Unexpected integer key in CBOR structure
    UnexpectedKey { expected: u64, got: u64 },
    /// CBOR encoding error
    EncodingError(String),
    /// CBOR decoding error
    DecodingError(String),
    /// Missing required field
    MissingField(String),
    /// Encryption error
    EncryptionError(EncryptionError),
}

impl std::fmt::Display for TdfCborError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagicBytes => write!(f, "Invalid or missing CBOR magic bytes"),
            Self::InvalidTdfIdentifier(s) => {
                write!(f, "Invalid tdf identifier: expected 'cbor', got '{}'", s)
            }
            Self::UnexpectedKey { expected, got } => {
                write!(f, "Expected integer key {}, got {}", expected, got)
            }
            Self::EncodingError(e) => write!(f, "CBOR encoding error: {}", e),
            Self::DecodingError(e) => write!(f, "CBOR decoding error: {}", e),
            Self::MissingField(s) => write!(f, "Missing required field: {}", s),
            Self::EncryptionError(e) => write!(f, "Encryption error: {}", e),
        }
    }
}

impl std::error::Error for TdfCborError {}

impl From<EncryptionError> for TdfCborError {
    fn from(e: EncryptionError) -> Self {
        Self::EncryptionError(e)
    }
}

impl From<base64::DecodeError> for TdfCborError {
    fn from(e: base64::DecodeError) -> Self {
        Self::DecodingError(format!("Base64 decode error: {}", e))
    }
}

// ============================================================================
// TDF-CBOR Builder
// ============================================================================

/// Builder for creating TDF-CBOR containers
pub struct TdfCborBuilder {
    data: Vec<u8>,
    kas_url: Option<String>,
    policy: Option<Policy>,
    mime_type: Option<String>,
    include_created: bool,
}

impl TdfCbor {
    /// Create a new builder for encrypting data into TDF-CBOR format
    pub fn encrypt(data: &[u8]) -> TdfCborBuilder {
        TdfCborBuilder {
            data: data.to_vec(),
            kas_url: None,
            policy: None,
            mime_type: None,
            include_created: true,
        }
    }

    /// Format identifier (always "cbor")
    pub fn format_id(&self) -> &str {
        &self.tdf
    }

    /// Check if data starts with CBOR self-describe tag
    ///
    /// The self-describe CBOR tag is 0xD9 0xD9 0xF7 (tag 55799)
    pub fn has_magic_bytes(data: &[u8]) -> bool {
        data.len() >= 3 && data[0] == 0xD9 && data[1] == 0xD9 && data[2] == 0xF7
    }

    /// Parse TDF-CBOR from bytes
    #[cfg(feature = "cbor")]
    pub fn from_bytes(data: &[u8]) -> Result<Self, TdfCborError> {
        use ciborium::Value;

        // Verify magic bytes (at least the self-describe tag)
        if data.len() < 3 || data[0] != 0xD9 || data[1] != 0xD9 || data[2] != 0xF7 {
            return Err(TdfCborError::InvalidMagicBytes);
        }

        // Parse CBOR
        let value: Value = ciborium::from_reader(&data[3..])
            .map_err(|e| TdfCborError::DecodingError(e.to_string()))?;

        // Extract map
        let map = match value {
            Value::Map(m) => m,
            _ => return Err(TdfCborError::DecodingError("Expected CBOR map".to_string())),
        };

        // Parse fields by integer key
        let mut tdf = None;
        let mut version = None;
        let mut created = None;
        let mut manifest = None;
        let mut payload = None;

        for (k, v) in map {
            let key = match k {
                Value::Integer(i) => {
                    let i128_val: i128 = i.into();
                    i128_val as u64
                }
                _ => continue,
            };

            match key {
                key::TDF => {
                    if let Value::Text(s) = v {
                        tdf = Some(s);
                    }
                }
                key::VERSION => {
                    if let Value::Array(arr) = v {
                        if arr.len() == 3 {
                            let mut ver = [0u8; 3];
                            for (i, val) in arr.iter().enumerate() {
                                if let Value::Integer(n) = val {
                                    let i128_val: i128 = (*n).into();
                                    ver[i] = i128_val as u8;
                                }
                            }
                            version = Some(ver);
                        }
                    }
                }
                key::CREATED => {
                    if let Value::Integer(i) = v {
                        let i128_val: i128 = i.into();
                        created = Some(i128_val as u64);
                    }
                }
                key::MANIFEST => {
                    // Manifest is stored as JSON string in CBOR
                    if let Value::Text(s) = v {
                        let m: TdfCborManifest = serde_json::from_str(&s)
                            .map_err(|e| TdfCborError::DecodingError(e.to_string()))?;
                        manifest = Some(m);
                    }
                }
                key::PAYLOAD => {
                    if let Value::Map(payload_map) = v {
                        let mut payload_type = String::new();
                        let mut protocol = String::new();
                        let mut mime_type = None;
                        let mut is_encrypted = true;
                        let mut value = Vec::new();

                        for (pk, pv) in payload_map {
                            let pkey = match pk {
                                Value::Text(s) => s,
                                _ => continue,
                            };

                            match pkey.as_str() {
                                "type" => {
                                    if let Value::Text(s) = pv {
                                        payload_type = s;
                                    }
                                }
                                "protocol" => {
                                    if let Value::Text(s) = pv {
                                        protocol = s;
                                    }
                                }
                                "mimeType" => {
                                    if let Value::Text(s) = pv {
                                        mime_type = Some(s);
                                    }
                                }
                                "isEncrypted" => {
                                    if let Value::Bool(b) = pv {
                                        is_encrypted = b;
                                    }
                                }
                                "value" => {
                                    if let Value::Bytes(b) = pv {
                                        value = b;
                                    }
                                }
                                _ => {}
                            }
                        }

                        payload = Some(CborPayload {
                            payload_type,
                            protocol,
                            mime_type,
                            is_encrypted,
                            value,
                        });
                    }
                }
                _ => {}
            }
        }

        let tdf_value = tdf.ok_or_else(|| TdfCborError::MissingField("tdf".to_string()))?;
        if tdf_value != "cbor" {
            return Err(TdfCborError::InvalidTdfIdentifier(tdf_value));
        }

        Ok(TdfCbor {
            tdf: tdf_value,
            version: version.ok_or_else(|| TdfCborError::MissingField("version".to_string()))?,
            created,
            manifest: manifest
                .ok_or_else(|| TdfCborError::MissingField("manifest".to_string()))?,
            payload: payload.ok_or_else(|| TdfCborError::MissingField("payload".to_string()))?,
        })
    }

    /// Serialize to CBOR bytes with magic header
    #[cfg(feature = "cbor")]
    pub fn to_bytes(&self) -> Result<Vec<u8>, TdfCborError> {
        use ciborium::Value;

        // Build the map with integer keys
        let manifest_json = serde_json::to_string(&self.manifest)
            .map_err(|e| TdfCborError::EncodingError(e.to_string()))?;

        let mut map = vec![
            (
                Value::Integer(key::TDF.into()),
                Value::Text(self.tdf.clone()),
            ),
            (
                Value::Integer(key::VERSION.into()),
                Value::Array(vec![
                    Value::Integer(self.version[0].into()),
                    Value::Integer(self.version[1].into()),
                    Value::Integer(self.version[2].into()),
                ]),
            ),
        ];

        if let Some(ts) = self.created {
            map.push((Value::Integer(key::CREATED.into()), Value::Integer(ts.into())));
        }

        map.push((
            Value::Integer(key::MANIFEST.into()),
            Value::Text(manifest_json),
        ));

        // Build payload map
        let mut payload_map = vec![
            (
                Value::Text("type".to_string()),
                Value::Text(self.payload.payload_type.clone()),
            ),
            (
                Value::Text("protocol".to_string()),
                Value::Text(self.payload.protocol.clone()),
            ),
            (
                Value::Text("isEncrypted".to_string()),
                Value::Bool(self.payload.is_encrypted),
            ),
            (
                Value::Text("value".to_string()),
                Value::Bytes(self.payload.value.clone()),
            ),
        ];

        if let Some(ref mt) = self.payload.mime_type {
            payload_map.push((Value::Text("mimeType".to_string()), Value::Text(mt.clone())));
        }

        map.push((
            Value::Integer(key::PAYLOAD.into()),
            Value::Map(payload_map),
        ));

        let cbor_value = Value::Map(map);

        // Encode with self-describe tag
        let mut result = vec![0xD9, 0xD9, 0xF7]; // Self-describe CBOR tag(55799)
        ciborium::into_writer(&cbor_value, &mut result)
            .map_err(|e| TdfCborError::EncodingError(e.to_string()))?;

        Ok(result)
    }

    /// Decrypt the payload with a provided data encryption key
    pub fn decrypt_with_key(&self, payload_key: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        use aes_gcm::{
            Aes256Gcm, Nonce,
            aead::{Aead, KeyInit},
        };

        let ciphertext = &self.payload.value;

        // Extract IV from encryption method
        let iv_bytes = BASE64.decode(&self.manifest.encryption_information.method.iv)?;

        let payload_iv = if iv_bytes.len() >= 12 {
            &iv_bytes[0..12]
        } else {
            &iv_bytes[..]
        };

        let cipher =
            Aes256Gcm::new_from_slice(payload_key).map_err(|_| EncryptionError::InvalidKeyLength)?;

        #[allow(deprecated)]
        let nonce = Nonce::from_slice(payload_iv);

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(EncryptionError::AeadError)?;

        Ok(plaintext)
    }
}

impl TdfCborBuilder {
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
        self.mime_type = Some(mime_type.to_string());
        self
    }

    /// Include created timestamp (default: true)
    #[must_use]
    pub fn include_created(mut self, include: bool) -> Self {
        self.include_created = include;
        self
    }

    /// Build the TDF-CBOR container
    pub fn build(self) -> Result<TdfCbor, TdfCborError> {
        let kas_url = self
            .kas_url
            .ok_or_else(|| TdfCborError::MissingField("kas_url".to_string()))?;
        let policy = self
            .policy
            .ok_or_else(|| TdfCborError::MissingField("policy".to_string()))?;

        // Create encryption instance
        let tdf_encryption = TdfEncryption::new()?;

        // Encrypt the data
        let encrypted_payload = tdf_encryption.encrypt(&self.data)?;

        // Get the payload key for policy binding
        let payload_key = tdf_encryption.payload_key();

        // Create policy binding
        let policy_json =
            serde_json::to_string(&policy).map_err(|e| TdfCborError::EncodingError(e.to_string()))?;
        let policy_b64 = BASE64.encode(policy_json.as_bytes());

        // Calculate policy binding hash
        let policy_hash = calculate_policy_binding(&policy_b64, payload_key)
            .map_err(|e| TdfCborError::EncodingError(e.to_string()))?;

        // Decode the base64 ciphertext to get raw bytes
        let ciphertext_bytes = BASE64.decode(&encrypted_payload.ciphertext)?;

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
            ephemeral_public_key: None,
        };

        // Extract GMAC tag from encrypted payload (last 16 bytes)
        let gmac_tag = if ciphertext_bytes.len() >= 16 {
            ciphertext_bytes[ciphertext_bytes.len() - 16..].to_vec()
        } else {
            return Err(TdfCborError::EncodingError(
                "Ciphertext too short for GMAC tag".to_string(),
            ));
        };

        // Create integrity information
        let mut integrity_info = IntegrityInformation {
            root_signature: RootSignature {
                alg: "HS256".to_string(),
                sig: String::new(),
            },
            segment_hash_alg: "GMAC".to_string(),
            segments: vec![Segment {
                hash: BASE64.encode(&gmac_tag),
                segment_size: Some(self.data.len() as u64),
                encrypted_segment_size: Some(ciphertext_bytes.len() as u64),
            }],
            segment_size_default: self.data.len() as u64,
            encrypted_segment_size_default: ciphertext_bytes.len() as u64,
        };

        // Calculate root signature
        integrity_info
            .generate_root_signature(&[gmac_tag], payload_key)
            .map_err(|e| TdfCborError::EncodingError(e))?;

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

        // Create manifest
        let manifest = TdfCborManifest {
            encryption_information: encryption_info,
            assertions: None,
        };

        // Create payload with raw binary (not base64)
        let payload = CborPayload {
            payload_type: "inline".to_string(),
            protocol: "binary".to_string(), // Key difference from TDF-JSON
            mime_type: self.mime_type,
            is_encrypted: true,
            value: ciphertext_bytes,
        };

        // Create timestamp
        let created = if self.include_created {
            Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            )
        } else {
            None
        };

        Ok(TdfCbor {
            tdf: "cbor".to_string(),
            version: [1, 0, 0],
            created,
            manifest,
            payload,
        })
    }
}

// ============================================================================
// Format Detection
// ============================================================================

/// Detect if data is a TDF-CBOR document
pub fn is_tdf_cbor(data: &[u8]) -> bool {
    TdfCbor::has_magic_bytes(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbor_magic_bytes() {
        assert_eq!(CBOR_MAGIC, [0xD9, 0xD9, 0xF7, 0xA5]);
    }

    #[test]
    fn test_has_magic_bytes() {
        // Valid self-describe tag + any map
        let valid = [0xD9, 0xD9, 0xF7, 0xA5, 0x01, 0x02];
        assert!(TdfCbor::has_magic_bytes(&valid));

        // Valid self-describe tag + different map size
        let valid2 = [0xD9, 0xD9, 0xF7, 0xB8, 0x05];
        assert!(TdfCbor::has_magic_bytes(&valid2));

        let invalid = [0x00, 0x01, 0x02, 0x03];
        assert!(!TdfCbor::has_magic_bytes(&invalid));

        let short = [0xD9, 0xD9];
        assert!(!TdfCbor::has_magic_bytes(&short));
    }

    #[test]
    fn test_create_cbor_envelope() {
        let policy = Policy::new(
            "test-policy".to_string(),
            vec![],
            vec!["user@example.com".to_string()],
        );

        let container = TdfCbor::encrypt(b"Hello, World!")
            .kas_url("https://kas.example.com")
            .policy(policy)
            .mime_type("text/plain")
            .build()
            .expect("Failed to create container");

        assert_eq!(container.tdf, "cbor");
        assert_eq!(container.version, [1, 0, 0]);
        assert!(container.created.is_some());
        assert_eq!(container.payload.payload_type, "inline");
        assert_eq!(container.payload.protocol, "binary");
        assert_eq!(container.payload.mime_type, Some("text/plain".to_string()));
        assert!(container.payload.is_encrypted);
        assert!(!container.payload.value.is_empty());
    }

    #[cfg(feature = "cbor")]
    #[test]
    fn test_cbor_roundtrip() {
        let policy = Policy::new(
            "test-policy".to_string(),
            vec![],
            vec!["user@example.com".to_string()],
        );

        let original = TdfCbor::encrypt(b"Test data for CBOR")
            .kas_url("https://kas.example.com")
            .policy(policy)
            .include_created(false)
            .build()
            .expect("Failed to create container");

        // Serialize to bytes
        let bytes = original.to_bytes().expect("Failed to serialize");

        // Verify magic bytes
        assert!(TdfCbor::has_magic_bytes(&bytes));

        // Parse back
        let parsed = TdfCbor::from_bytes(&bytes).expect("Failed to parse");

        assert_eq!(parsed.tdf, "cbor");
        assert_eq!(parsed.version, [1, 0, 0]);
        assert_eq!(parsed.payload.value, original.payload.value);
    }

    #[test]
    fn test_builder_missing_kas_url() {
        let policy = Policy::new(
            "test-policy".to_string(),
            vec![],
            vec!["user@example.com".to_string()],
        );

        let result = TdfCbor::encrypt(b"Data").policy(policy).build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_missing_policy() {
        let result = TdfCbor::encrypt(b"Data")
            .kas_url("https://kas.example.com")
            .build();

        assert!(result.is_err());
    }
}
