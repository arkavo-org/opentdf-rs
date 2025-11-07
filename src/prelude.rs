//! OpenTDF Prelude
//!
//! The prelude module provides a convenient way to import commonly used types and traits.
//!
//! # Example
//!
//! ```rust
//! use opentdf::prelude::*;
//!
//! // Now you can use extension traits without explicit imports
//! let mut manifest = TdfManifest::new("payload".to_string(), "https://kas.example.com".to_string());
//! let policy = Policy::new(/* ... */);
//! manifest.set_policy(&policy)?; // Works without importing TdfManifestExt
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

// Re-export core types
pub use crate::archive::{TdfArchive, TdfArchiveBuilder, TdfError};
pub use crate::fqn::{AttributeFqn, FqnValidationRules, NamespaceRegistry};
pub use crate::policy::{
    AttributeCondition, AttributeIdentifier, AttributePolicy, AttributeValue, FqnError,
    LogicalOperator, Operator, Policy, PolicyBuilder, PolicyError, ValidationError,
    ValidationErrorType,
};
pub use crate::tdf::{Tdf, TdfEncryptBuilder, TdfEncryptFileBuilder};

#[cfg(feature = "kas")]
pub use crate::tdf::{TdfDecryptBuilder, TdfDecryptFileBuilder};

// Re-export protocol types
pub use opentdf_protocol::{
    EncryptionInformation, EncryptionMethod, IntegrityInformation, KeyAccess, Payload,
    PolicyBinding, RootSignature, Segment, TdfManifest,
};

// **Auto-import extension traits** - this is the key improvement!
// Users don't need to explicitly import these anymore
pub use crate::manifest::{IntegrityInformationExt, KeyAccessExt, TdfManifestExt};

// KAS types (when feature enabled)
#[cfg(feature = "kas")]
pub use crate::kas::KasClient;

#[cfg(feature = "kas")]
pub use opentdf_protocol::KasError;
