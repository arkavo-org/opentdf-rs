//! TDF encryption implementations
//!
//! This module contains encryption implementations for:
//! - Standard TDF (TDF3, ZTDF) - segment-based AES-256-GCM
//! - NanoTDF - compact format with EC key wrapping (planned)

pub mod encryption;
pub mod nanotdf;

pub use encryption::{EncryptedPayload, SegmentInfo, SegmentedPayload, TdfEncryption};
pub use nanotdf::{NanoTdf, NanoTdfBuilder, NanoTdfHeader};
