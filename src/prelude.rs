//! OpenTDF Prelude
//!
//! The prelude module provides a convenient way to import commonly used types and traits.
//!
//! # Example
//!
//! ```rust
//! use opentdf::prelude::*;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Now you can use extension traits without explicit imports
//! let mut manifest = TdfManifest::new("payload".to_string(), "https://kas.example.com".to_string());
//! let policy = PolicyBuilder::new()
//!     .id_auto()
//!     .dissemination(["user@example.com"])
//!     .build()?;
//! manifest.set_policy(&policy)?; // Works without importing TdfManifestExt
//! # Ok(())
//! # }
//! ```

// Re-export core types
pub use crate::archive::{TdfArchive, TdfArchiveBuilder, TdfArchiveMemoryBuilder, TdfError};
pub use crate::fqn::{AttributeFqn, FqnValidationRules, NamespaceRegistry};
pub use crate::policy::{
    AttributeCondition, AttributeIdentifier, AttributePolicy, AttributeValue, FqnError,
    FqnErrorKind, LogicalOperator, Operator, Policy, PolicyBuilder, PolicyError, ValidationError,
    ValidationErrorType,
};
pub use crate::tdf::{Tdf, TdfEncryptBuilder, TdfEncryptFileBuilder};

#[cfg(feature = "kas-client")]
pub use crate::tdf::{TdfDecryptBuilder, TdfDecryptFileBuilder};

// Re-export protocol types
pub use opentdf_protocol::{
    EncryptionInformation, EncryptionMethod, IntegrityInformation, KeyAccess, Payload,
    PolicyBinding, RootSignature, Segment, TdfManifest,
};

// Re-export crypto types
pub use opentdf_crypto::{
    EncryptedPayload, EncryptionError, SegmentInfo, SegmentedPayload, TdfEncryption,
};

// **Auto-import extension traits** - this is the key improvement!
// Users don't need to explicitly import these anymore
pub use crate::manifest::{IntegrityInformationExt, KeyAccessExt, TdfManifestExt};

// KAS types (when feature enabled)
#[cfg(feature = "kas-client")]
pub use crate::kas::KasClient;

#[cfg(feature = "kas-client")]
pub use opentdf_protocol::KasError;
