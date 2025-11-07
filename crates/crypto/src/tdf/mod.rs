//! TDF encryption implementations
//!
//! This module contains encryption implementations for:
//! - Standard TDF (TDF3, ZTDF) - segment-based AES-256-GCM
//! - NanoTDF - compact format with EC key wrapping

pub mod encryption;
pub mod nanotdf;
pub mod nanotdf_crypto;

pub use encryption::{EncryptedPayload, SegmentInfo, SegmentedPayload, TdfEncryption};
pub use nanotdf::{NanoTdf, NanoTdfBuilder, NanoTdfHeader};
pub use nanotdf_crypto::{
    decrypt, encrypt, generate_gmac, verify_gmac, NanoTdfCryptoError, NanoTdfIv, TagSize,
};
