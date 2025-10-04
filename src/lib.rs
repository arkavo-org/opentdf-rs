mod archive;
mod crypto;
mod manifest;
mod policy;

#[cfg(feature = "kas")]
pub mod kas;

#[cfg(feature = "kas")]
pub mod kas_key;

pub use archive::{TdfArchive, TdfArchiveBuilder};
pub use crypto::{EncryptedPayload, EncryptionError, TdfEncryption};
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
