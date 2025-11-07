//! OpenTDF - Trusted Data Format for Rust
//!
//! This crate provides a Rust implementation of the OpenTDF (Trusted Data Format) standard,
//! supporting:
//! - Standard TDF (TDF3, ZTDF) with segment-based encryption
//! - Attribute-Based Access Control (ABAC) policies
//! - Key Access Service (KAS) integration
//! - JSON-RPC format (ZTDF-JSON)
//! - Security hardening (zeroizing keys, constant-time verification)
//!
//! # Architecture
//!
//! - **`opentdf-protocol`**: Protocol types and structures (no crypto)
//! - **`opentdf-crypto`**: Cryptographic operations with security hardening
//! - **`opentdf`**: High-level TDF API and integration
//!
//! # Example
//!
//! ```no_run
//! use opentdf::{Tdf, Policy};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a policy
//! let policy = Policy::new("uuid".to_string(), vec![], vec!["user@example.com".to_string()]);
//!
//! // Encrypt data to a TDF file
//! Tdf::encrypt(b"sensitive data")
//!     .kas_url("https://kas.example.com")
//!     .policy(policy)
//!     .to_file("output.tdf")?;
//! # Ok(())
//! # }
//! ```

mod archive;
pub mod manifest;
mod policy;
mod tdf;

#[cfg(feature = "kas")]
pub mod kas;

#[cfg(feature = "kas")]
pub mod kas_key;

// JSON-RPC integration (ZTDF-JSON format)
pub mod jsonrpc;

// Re-export protocol types
pub use opentdf_protocol::{
    EncryptionInformation, EncryptionMethod, IntegrityInformation, KeyAccess, Payload,
    PolicyBinding, RootSignature, Segment, TdfManifest,
};

// Re-export crypto types
pub use opentdf_crypto::{
    EncryptedPayload, EncryptionError, SegmentInfo, SegmentedPayload, TdfEncryption,
};

// Re-export KAS types (from protocol)
pub use opentdf_protocol::{
    KasError, KasPolicyBinding, KeyAccessObject, KeyAccessObjectWrapper, KeyAccessRewrapResult,
    PolicyRequest, PolicyRewrapResult, RewrapResponse, SignedRewrapRequest, UnsignedRewrapRequest,
};

// Re-export security types
pub use opentdf_crypto::{AesKey, KeyError, PayloadKey, PolicyKey};

// High-level API (primary interface)
pub use tdf::{Tdf, TdfEncryptBuilder, TdfEncryptFileBuilder};

// Core types
pub use archive::{TdfArchive, TdfArchiveBuilder, TdfArchiveMemoryBuilder, TdfError};

// Policy types
pub use policy::{
    AttributeCondition, AttributeIdentifier, AttributePolicy, AttributeValue, LogicalOperator,
    Operator, Policy, PolicyBody, PolicyError,
};

// KAS feature types
#[cfg(feature = "kas")]
pub use kas::{KasClient, KeyType};

#[cfg(feature = "kas")]
pub use kas_key::{
    fetch_kas_public_key, validate_rsa_public_key_pem, KasKeyError, KasPublicKeyResponse,
};

#[cfg(feature = "kas")]
pub use opentdf_crypto::{wrap_key_with_rsa_oaep, EcdhKem, OaepHash, RsaOaepKem};

// JSON-RPC types
pub use jsonrpc::{InlinePayload, TdfJsonRpc, TdfJsonRpcBuilder, TdfManifestInline};
