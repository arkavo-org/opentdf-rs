//! NanoTDF Protocol Types
//!
//! This module implements the NanoTDF v1 binary format specification.
//! NanoTDF is a compact binary encoding format designed for IoT, embedded systems,
//! and bandwidth-constrained environments.
//!
//! ## Format Overview
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │          Header (43-584 bytes)      │
//! ├─────────────────────────────────────┤
//! │        Payload (14-16MB)            │
//! ├─────────────────────────────────────┤
//! │   Signature (97-133 bytes, optional)│
//! └─────────────────────────────────────┘
//! ```
//!
//! ## Specification
//!
//! - Version: NanoTDF v1
//! - Magic Number: `L1L` (base64) = `0x4C314C` (hex)
//! - All multi-byte integers are big-endian
//! - Minimum overhead: < 200 bytes
//!
//! ## References
//!
//! - [OpenTDF NanoTDF Specification](https://github.com/opentdf/spec/tree/main/schema/nanotdf)

pub mod collection;
pub mod header;
pub mod policy;
pub mod resource_locator;

pub use collection::{CollectionItem, DEFAULT_ROTATION_THRESHOLD, MAX_IV, RESERVED_POLICY_IV};
pub use header::{
    EccAndBindingMode, EccMode, Header, MagicNumberAndVersion, PayloadSignatureMode,
    SymmetricAndPayloadConfig, SymmetricCipher,
};
pub use policy::{Policy, PolicyBody, PolicyType};
pub use resource_locator::{Protocol, ResourceLocator};

/// NanoTDF version 1 (version 12 - "L1L" in base64)
pub const NANOTDF_VERSION: u8 = 12;

/// Magic number (18 bits) + version (6 bits) = "L1L" when base64 encoded
/// 0100 1100 0011 0001 0100 1100 = 0x4C314C
pub const MAGIC_NUMBER_AND_VERSION: [u8; 3] = [0x4C, 0x31, 0x4C];

/// HKDF salt for NanoTDF key derivation
/// SHA256(MAGIC_NUMBER + VERSION) = SHA256(0x4C314C)
pub const HKDF_SALT: [u8; 32] = [
    0x3d, 0xe3, 0xca, 0x1e, 0x50, 0xcf, 0x62, 0xd8, 0xb6, 0xab, 0xa6, 0x03, 0xa9, 0x6f, 0xca, 0x67,
    0x61, 0x38, 0x7a, 0x7a, 0xc8, 0x6c, 0x3d, 0x3a, 0xfe, 0x85, 0xae, 0x2d, 0x18, 0x12, 0xed, 0xfc,
];

/// Reserved IV for encrypted policy (must not be reused with same key)
pub const POLICY_IV: [u8; 3] = [0x00, 0x00, 0x00];

/// Maximum payload length (3 bytes = 16,777,215 bytes ~= 16 MB)
pub const MAX_PAYLOAD_LENGTH: u32 = 0x00FF_FFFF;

/// Minimum NanoTDF size (header only, no payload, no signature):
/// 3 (magic) + 2 (empty KAS locator) + 1 (ECC mode) + 1 (sym config)
/// + 1 (policy type) + 2 (empty policy len) + 8 (GMAC binding) + 33 (P-256 key) = 51 bytes.
pub const MIN_NANOTDF_SIZE: usize = 51;

/// Maximum NanoTDF size (max header + max payload + max P-521 signature):
///
/// - max header = 3 (magic) + 289 (KAS locator: 2 + 255 + 32) + 1 (ECC) + 1 (sym)
///   + 1 (policy type) + 2 (policy len) + 65535 (policy) + 289 (policy KAS locator)
///   + 67 (P-521 policy epk) + 132 (P-521 ECDSA binding) + 67 (P-521 header epk) = 66,387 bytes
/// - max payload = 3 (len) + 16,777,215 = 16,777,218 bytes
/// - max P-521 signature = 67 (pubkey) + 132 (r||s) = 199 bytes
pub const MAX_NANOTDF_SIZE: usize = 66_387 + 16_777_218 + 199;
