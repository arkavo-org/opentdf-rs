//! OpenTDF Cryptographic Operations
//!
//! This crate provides cryptographic operations for OpenTDF with security hardening:
//! - Zeroizing key types that automatically clear memory
//! - Constant-time HMAC verification
//! - KEM abstractions for RSA, EC, and future post-quantum algorithms
//! - Segment-based encryption for standard TDF
//! - NanoTDF API structure (implementation pending)
//!
//! # Security Features
//!
//! - **Zeroization**: All key material uses `zeroize` to clear memory on drop
//! - **Constant-time comparison**: MAC verification uses `subtle::ConstantTimeEq`
//! - **Future-ready**: Abstractions for post-quantum cryptography (ML-KEM)

// Allow dead code for NanoTDF stub implementation
#![allow(dead_code)]
//!
//! # Example
//!
//! ```
//! use opentdf_crypto::tdf::TdfEncryption;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create encryption instance with generated keys
//! let tdf = TdfEncryption::new()?;
//!
//! // Encrypt data
//! let data = b"sensitive information";
//! let encrypted = tdf.encrypt(data)?;
//!
//! // Decrypt (legacy format)
//! let decrypted = TdfEncryption::decrypt_legacy(tdf.policy_key(), &encrypted)?;
//! assert_eq!(data, decrypted.as_slice());
//! # Ok(())
//! # }
//! ```

pub mod helpers;
pub mod hmac;
pub mod kem;
pub mod tdf;
pub mod types;

// Re-export commonly used types
pub use helpers::{create_aes_cipher, generate_key_32, generate_nonce, CryptoError};
pub use hmac::{
    calculate_hmac, calculate_policy_binding, calculate_root_signature, verify_root_signature,
    HmacError,
};
pub use kem::{KemError, KeyEncapsulation};
pub use tdf::{
    EncryptedPayload, NanoTdf, NanoTdfBuilder, NanoTdfHeader, SegmentInfo, SegmentedPayload,
    TdfEncryption,
};
pub use types::{AesKey, KeyError, Nonce96, PayloadKey, PolicyKey};

// Re-export KAS feature types
#[cfg(feature = "kas")]
pub use kem::rsa::{wrap_key_with_rsa_oaep, OaepHash, RsaOaepKem};

#[cfg(feature = "kas")]
pub use kem::ec::{EcCurve, EcdhKem};

#[cfg(feature = "kas")]
pub use kem::pqc::{HybridKem, MlKemLevel, MlKemWrapper};

#[cfg(feature = "kas")]
pub use types::EcPrivateKey;

// Re-export underlying crypto libraries for KAS
#[cfg(feature = "kas")]
pub use hkdf;

#[cfg(feature = "kas")]
pub use p256;

#[cfg(feature = "kas")]
pub use pkcs8;

#[cfg(feature = "kas")]
pub use rand;

#[cfg(feature = "kas")]
pub use rsa;

#[cfg(feature = "kas")]
pub use sha1;

#[cfg(feature = "kas")]
pub use sha2;

// Re-export encryption error
pub use tdf::encryption::EncryptionError;
