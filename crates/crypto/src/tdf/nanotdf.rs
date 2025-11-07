//! NanoTDF implementation (planned)
//!
//! NanoTDF is a compact TDF format designed for constrained environments.
//! It uses EC-based key wrapping and a binary header format for efficiency.
//!
//! # Specification
//!
//! See: https://github.com/opentdf/spec/blob/main/schema/NanoTDF.md
//!
//! # Key Features
//!
//! - Compact binary format (no JSON manifest)
//! - EC P-256 key wrapping (ECDH + HKDF + AES-GCM)
//! - Policy binding with HMAC
//! - Optimized for small payloads
//!
//! # Implementation Status
//!
//! This module provides the API structure and documentation.
//! Full implementation is planned for a future release (0.6.0 target).

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NanoTdfError {
    #[error("NanoTDF not yet implemented")]
    NotImplemented,

    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Policy binding verification failed")]
    PolicyBindingFailed,
}

/// NanoTDF structure
///
/// Binary format: [Header][Payload][Signature]
///
/// # Format (Version 3)
///
/// ```text
/// Header:
///   - Magic number (3 bytes): "L1L"
///   - Version (2 bytes): 0x0003
///   - KAS URL length + URL
///   - ECC mode (1 byte): 0 = P-256
///   - Policy type (1 byte)
///   - Policy body
///   - Ephemeral public key (33 bytes compressed)
///   - Policy binding (32 bytes)
///
/// Payload:
///   - IV (3 bytes)
///   - Ciphertext (variable)
///   - Auth tag (16 bytes)
///
/// Signature:
///   - Public key (33 bytes)
///   - Signature (64 bytes)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NanoTdf {
    /// NanoTDF header
    pub header: NanoTdfHeader,

    /// Encrypted payload
    pub payload: Vec<u8>,

    /// Optional signature
    pub signature: Option<NanoTdfSignature>,
}

/// NanoTDF header structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NanoTdfHeader {
    /// Magic number ("L1L")
    pub magic: [u8; 3],

    /// Version (0x0003 for version 3)
    pub version: u16,

    /// KAS resource locator
    pub kas_locator: String,

    /// ECC mode (0 = P-256)
    pub ecc_mode: u8,

    /// Policy type
    pub policy_type: PolicyType,

    /// Policy body
    pub policy_body: Vec<u8>,

    /// Ephemeral EC public key (compressed P-256, 33 bytes)
    pub ephemeral_key: Vec<u8>,

    /// Policy binding HMAC
    pub policy_binding: Vec<u8>,
}

/// Policy type enumeration
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PolicyType {
    /// Remote policy (policy UUID)
    Remote = 0,
    /// Embedded policy (full policy in body)
    Embedded = 1,
    /// Encrypted policy
    EncryptedRemote = 2,
    /// Encrypted embedded policy
    EncryptedEmbedded = 3,
}

/// Optional NanoTDF signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NanoTdfSignature {
    /// Public key (compressed P-256, 33 bytes)
    pub public_key: Vec<u8>,

    /// ECDSA signature (64 bytes)
    pub signature: Vec<u8>,
}

/// Builder for creating NanoTDF files
///
/// # Example (Planned API)
///
/// ```rust,ignore
/// use opentdf_crypto::tdf::NanoTdfBuilder;
/// use opentdf_crypto::types::EcPrivateKey;
///
/// let builder = NanoTdfBuilder::new()
///     .kas_url("https://kas.example.com")
///     .policy_remote("policy-uuid-here")
///     .ephemeral_key(EcPrivateKey::generate_p256());
///
/// let nanotdf = builder.encrypt(b"sensitive data")?;
/// let bytes = nanotdf.to_bytes()?;
/// ```
pub struct NanoTdfBuilder {
    kas_url: Option<String>,
    policy: Option<PolicyConfig>,
}

enum PolicyConfig {
    Remote(String),
    Embedded(Vec<u8>),
}

impl NanoTdfBuilder {
    /// Create a new NanoTDF builder
    pub fn new() -> Self {
        NanoTdfBuilder {
            kas_url: None,
            policy: None,
        }
    }

    /// Set the KAS URL
    #[must_use]
    pub fn kas_url(mut self, url: impl Into<String>) -> Self {
        self.kas_url = Some(url.into());
        self
    }

    /// Set a remote policy (policy UUID)
    #[must_use]
    pub fn policy_remote(mut self, uuid: impl Into<String>) -> Self {
        self.policy = Some(PolicyConfig::Remote(uuid.into()));
        self
    }

    /// Set an embedded policy
    #[must_use]
    pub fn policy_embedded(mut self, policy: Vec<u8>) -> Self {
        self.policy = Some(PolicyConfig::Embedded(policy));
        self
    }

    /// Encrypt data and build NanoTDF
    ///
    /// # Implementation Notes (Future)
    ///
    /// 1. Generate ephemeral EC P-256 key pair
    /// 2. Perform ECDH with recipient public key
    /// 3. Derive encryption key using HKDF-SHA256
    /// 4. Encrypt payload with AES-256-GCM (3-byte IV)
    /// 5. Calculate policy binding HMAC
    /// 6. Assemble header + payload
    /// 7. Optionally sign with ECDSA
    pub fn encrypt(self, _data: &[u8]) -> Result<NanoTdf, NanoTdfError> {
        Err(NanoTdfError::NotImplemented)
    }
}

impl Default for NanoTdfBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NanoTdf {
    /// Serialize NanoTDF to binary format
    pub fn to_bytes(&self) -> Result<Vec<u8>, NanoTdfError> {
        Err(NanoTdfError::NotImplemented)
    }

    /// Deserialize NanoTDF from binary format
    pub fn from_bytes(_bytes: &[u8]) -> Result<Self, NanoTdfError> {
        Err(NanoTdfError::NotImplemented)
    }

    /// Decrypt NanoTDF payload
    ///
    /// # Implementation Notes (Future)
    ///
    /// 1. Parse header and extract ephemeral public key
    /// 2. Perform ECDH with recipient private key
    /// 3. Derive decryption key using HKDF-SHA256
    /// 4. Verify policy binding HMAC
    /// 5. Decrypt payload with AES-256-GCM
    /// 6. Verify optional signature
    pub fn decrypt(&self, _recipient_private_key: &[u8]) -> Result<Vec<u8>, NanoTdfError> {
        Err(NanoTdfError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_api() {
        let builder = NanoTdfBuilder::new()
            .kas_url("https://kas.example.com")
            .policy_remote("test-uuid");

        let result = builder.encrypt(b"test data");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NanoTdfError::NotImplemented));
    }

    #[test]
    fn test_policy_type_values() {
        assert_eq!(PolicyType::Remote as u8, 0);
        assert_eq!(PolicyType::Embedded as u8, 1);
        assert_eq!(PolicyType::EncryptedRemote as u8, 2);
        assert_eq!(PolicyType::EncryptedEmbedded as u8, 3);
    }
}
