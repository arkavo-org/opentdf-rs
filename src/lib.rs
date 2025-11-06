mod archive;
mod crypto;
pub mod manifest;
mod policy;
mod tdf;

#[cfg(feature = "kas")]
pub mod kas;

#[cfg(feature = "kas")]
pub mod kas_key;

// JSON-RPC integration (ZTDF-JSON format)
pub mod jsonrpc;

// High-level API (primary interface)
pub use tdf::{Tdf, TdfEncryptBuilder, TdfEncryptFileBuilder};

// Core types
pub use archive::{TdfArchive, TdfArchiveBuilder, TdfArchiveMemoryBuilder, TdfError};
pub use crypto::{EncryptedPayload, EncryptionError, SegmentInfo, SegmentedPayload, TdfEncryption};
pub use manifest::TdfManifest;

#[cfg(feature = "kas")]
pub use crypto::wrap_key_with_rsa_oaep;
pub use policy::{
    AttributeCondition, AttributeIdentifier, AttributePolicy, AttributeValue, LogicalOperator,
    Operator, Policy, PolicyBody, PolicyError,
};

#[cfg(feature = "kas")]
pub use kas::{EphemeralKeyPair, KasClient, KasError};

#[cfg(feature = "kas")]
pub use kas_key::{
    fetch_kas_public_key, validate_rsa_public_key_pem, KasKeyError, KasPublicKeyResponse,
};

// JSON-RPC types
pub use jsonrpc::{InlinePayload, TdfJsonRpc, TdfJsonRpcBuilder, TdfManifestInline};
