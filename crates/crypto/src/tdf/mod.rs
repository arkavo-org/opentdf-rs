//! TDF encryption implementations
//!
//! This module contains encryption implementations for:
//! - Standard TDF (TDF3, ZTDF) - segment-based AES-256-GCM
//! - NanoTDF - compact format with EC key wrapping
//!
//! ## NanoTDF Crypto Backend
//! - Default: Mbed TLS (supports 64-128 bit GCM tags, 64-bit is NanoTDF default)
//! - Without `nanotdf-mbedtls`: RustCrypto (pure Rust, supports 96-128 bit tags only)

pub mod encryption;
pub mod nanotdf;

// Conditional backend selection for NanoTDF crypto
#[cfg(feature = "nanotdf-mbedtls")]
pub mod nanotdf_crypto_mbedtls;
#[cfg(feature = "nanotdf-mbedtls")]
pub use nanotdf_crypto_mbedtls as nanotdf_crypto;

#[cfg(not(feature = "nanotdf-mbedtls"))]
pub mod nanotdf_crypto;

pub use encryption::{EncryptedPayload, SegmentInfo, SegmentedPayload, TdfEncryption};
pub use nanotdf::{NanoTdf, NanoTdfBuilder, NanoTdfError, NanoTdfPayload, NanoTdfSignature};
pub use nanotdf_crypto::{
    decrypt, encrypt, generate_gmac, verify_gmac, NanoTdfCryptoError, NanoTdfIv, TagSize,
};
