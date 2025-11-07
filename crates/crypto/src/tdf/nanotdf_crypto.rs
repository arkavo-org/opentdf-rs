//! NanoTDF Cryptographic Operations
//!
//! This module implements NanoTDF-specific encryption with:
//! - Variable-length GCM tags (64-128 bits)
//! - 3-byte IVs (24 bits)
//! - GMAC policy binding
//! - ECDSA signature support

use crate::types::AesKey;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use thiserror::Error;

/// NanoTDF encryption errors
#[derive(Debug, Error)]
pub enum NanoTdfCryptoError {
    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Invalid IV length: expected 3 bytes, got {0}")]
    InvalidIvLength(usize),

    #[error("Invalid tag length: expected {expected}, got {actual}")]
    InvalidTagLength { expected: usize, actual: usize },

    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("Payload too large: {0} bytes (max 16777215)")]
    PayloadTooLarge(usize),
}

/// Tag size for AES-256-GCM
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagSize {
    /// 64-bit tag (8 bytes)
    Bits64 = 8,
    /// 96-bit tag (12 bytes)
    Bits96 = 12,
    /// 104-bit tag (13 bytes)
    Bits104 = 13,
    /// 112-bit tag (14 bytes)
    Bits112 = 14,
    /// 120-bit tag (15 bytes)
    Bits120 = 15,
    /// 128-bit tag (16 bytes) - standard GCM
    Bits128 = 16,
}

impl TagSize {
    /// Get tag size in bytes
    pub fn bytes(self) -> usize {
        self as usize
    }

    /// Get tag size in bits
    pub fn bits(self) -> usize {
        self.bytes() * 8
    }

    /// Create from byte count
    pub fn from_bytes(bytes: usize) -> Result<Self, NanoTdfCryptoError> {
        match bytes {
            8 => Ok(TagSize::Bits64),
            12 => Ok(TagSize::Bits96),
            13 => Ok(TagSize::Bits104),
            14 => Ok(TagSize::Bits112),
            15 => Ok(TagSize::Bits120),
            16 => Ok(TagSize::Bits128),
            _ => Err(NanoTdfCryptoError::InvalidTagLength {
                expected: 16,
                actual: bytes,
            }),
        }
    }
}

/// NanoTDF IV (3 bytes)
#[derive(Debug, Clone, Copy)]
pub struct NanoTdfIv([u8; 3]);

impl NanoTdfIv {
    /// Create a new random IV
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let mut iv = [0u8; 3];
        rng.fill_bytes(&mut iv);
        Self(iv)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 3]) -> Self {
        Self(bytes)
    }

    /// Create from slice
    pub fn from_slice(bytes: &[u8]) -> Result<Self, NanoTdfCryptoError> {
        if bytes.len() != 3 {
            return Err(NanoTdfCryptoError::InvalidIvLength(bytes.len()));
        }
        let mut iv = [0u8; 3];
        iv.copy_from_slice(bytes);
        Ok(Self(iv))
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 3] {
        &self.0
    }

    /// Convert to 12-byte nonce for AES-GCM (pad with zeros)
    pub fn to_gcm_nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..3].copy_from_slice(&self.0);
        nonce
    }

    /// Reserved IV for encrypted policy (must not be reused)
    pub const POLICY_IV: Self = Self([0x00, 0x00, 0x00]);
}

/// Encrypt data with AES-256-GCM using NanoTDF parameters
///
/// # Arguments
/// * `key` - AES-256 key
/// * `iv` - 3-byte IV (will be padded to 12 bytes)
/// * `plaintext` - Data to encrypt
/// * `tag_size` - Desired tag size (currently only 128-bit supported)
///
/// # Returns
/// Ciphertext || Tag (tag is appended to ciphertext)
///
/// # Note
/// The current implementation uses the standard aes-gcm crate which only
/// supports 128-bit tags. Variable tag sizes (64-120 bits) specified in
/// the NanoTDF spec would require a different crypto implementation.
/// For now, tag_size must be TagSize::Bits128.
pub fn encrypt(
    key: &AesKey,
    iv: &NanoTdfIv,
    plaintext: &[u8],
    tag_size: TagSize,
) -> Result<Vec<u8>, NanoTdfCryptoError> {
    // TODO: Support variable tag sizes once we have a crypto library that supports it
    // For now, only support 128-bit tags
    if tag_size != TagSize::Bits128 {
        return Err(NanoTdfCryptoError::InvalidTagLength {
            expected: 16,
            actual: tag_size.bytes(),
        });
    }

    // Create cipher
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));

    // Convert 3-byte IV to 12-byte nonce
    let nonce_bytes = iv.to_gcm_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| NanoTdfCryptoError::EncryptionFailed)
}

/// Decrypt data with AES-256-GCM using NanoTDF parameters
///
/// # Arguments
/// * `key` - AES-256 key
/// * `iv` - 3-byte IV (will be padded to 12 bytes)
/// * `ciphertext_and_tag` - Ciphertext with appended tag
/// * `tag_size` - Expected tag size (currently only 128-bit supported)
///
/// # Returns
/// Decrypted plaintext
///
/// # Note
/// The current implementation uses the standard aes-gcm crate which only
/// supports 128-bit tags. Variable tag sizes (64-120 bits) specified in
/// the NanoTDF spec would require a different crypto implementation.
/// For now, tag_size must be TagSize::Bits128.
pub fn decrypt(
    key: &AesKey,
    iv: &NanoTdfIv,
    ciphertext_and_tag: &[u8],
    tag_size: TagSize,
) -> Result<Vec<u8>, NanoTdfCryptoError> {
    // TODO: Support variable tag sizes once we have a crypto library that supports it
    // For now, only support 128-bit tags
    if tag_size != TagSize::Bits128 {
        return Err(NanoTdfCryptoError::InvalidTagLength {
            expected: 16,
            actual: tag_size.bytes(),
        });
    }

    // Validate minimum length
    if ciphertext_and_tag.len() < 16 {
        return Err(NanoTdfCryptoError::InvalidTagLength {
            expected: 16,
            actual: ciphertext_and_tag.len(),
        });
    }

    // Create cipher
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));

    // Convert 3-byte IV to 12-byte nonce
    let nonce_bytes = iv.to_gcm_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Decrypt
    cipher
        .decrypt(nonce, ciphertext_and_tag)
        .map_err(|_| NanoTdfCryptoError::DecryptionFailed)
}

/// Generate GMAC tag for policy binding
///
/// GMAC is GCM with empty plaintext - the AAD becomes the message to authenticate
pub fn generate_gmac(
    key: &AesKey,
    iv: &NanoTdfIv,
    data: &[u8],
) -> Result<[u8; 8], NanoTdfCryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
    let nonce_bytes = iv.to_gcm_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // GMAC: encrypt empty plaintext with AAD
    let payload = Payload {
        msg: &[],
        aad: data,
    };

    let result = cipher
        .encrypt(nonce, payload)
        .map_err(|_| NanoTdfCryptoError::EncryptionFailed)?;

    // Result is just the tag (16 bytes), truncate to 8 for GMAC
    if result.len() < 8 {
        return Err(NanoTdfCryptoError::InvalidTagLength {
            expected: 8,
            actual: result.len(),
        });
    }

    let mut gmac = [0u8; 8];
    gmac.copy_from_slice(&result[..8]);
    Ok(gmac)
}

/// Verify GMAC tag for policy binding
pub fn verify_gmac(
    key: &AesKey,
    iv: &NanoTdfIv,
    data: &[u8],
    expected_tag: &[u8; 8],
) -> Result<bool, NanoTdfCryptoError> {
    let computed_tag = generate_gmac(key, iv, data)?;
    Ok(&computed_tag == expected_tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iv_conversion() {
        let iv = NanoTdfIv::from_bytes([0x01, 0x02, 0x03]);
        let nonce = iv.to_gcm_nonce();
        assert_eq!(&nonce[0..3], &[0x01, 0x02, 0x03]);
        assert_eq!(&nonce[3..12], &[0u8; 9]); // Rest is zeros
    }

    #[test]
    fn test_encrypt_decrypt_128bit_tag() {
        let key = AesKey::from_slice(&[0x42u8; 32]).unwrap();
        let iv = NanoTdfIv::random();
        let plaintext = b"Hello, NanoTDF!";

        let ciphertext = encrypt(&key, &iv, plaintext, TagSize::Bits128).unwrap();
        let decrypted = decrypt(&key, &iv, &ciphertext, TagSize::Bits128).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_variable_tag_sizes_not_yet_supported() {
        let key = AesKey::from_slice(&[0x42u8; 32]).unwrap();
        let iv = NanoTdfIv::random();
        let plaintext = b"Test variable tags";

        // Variable tag sizes should return an error for now
        let result = encrypt(&key, &iv, plaintext, TagSize::Bits64);
        assert!(result.is_err());

        let result = encrypt(&key, &iv, plaintext, TagSize::Bits96);
        assert!(result.is_err());
    }

    #[test]
    fn test_128bit_tag_supported() {
        let key = AesKey::from_slice(&[0x42u8; 32]).unwrap();
        let iv = NanoTdfIv::random();
        let plaintext = b"Test 128-bit tag support";

        // 128-bit tags should work
        let ciphertext = encrypt(&key, &iv, plaintext, TagSize::Bits128).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let decrypted = decrypt(&key, &iv, &ciphertext, TagSize::Bits128).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_gmac_generation() {
        let key = AesKey::from_slice(&[0x42u8; 32]).unwrap();
        let iv = NanoTdfIv::from_bytes([0x01, 0x02, 0x03]);
        let data = b"Policy data to authenticate";

        let gmac = generate_gmac(&key, &iv, data).unwrap();
        assert_eq!(gmac.len(), 8);

        // Verify returns true for correct tag
        assert!(verify_gmac(&key, &iv, data, &gmac).unwrap());

        // Verify returns false for wrong tag
        let wrong_gmac = [0u8; 8];
        assert!(!verify_gmac(&key, &iv, data, &wrong_gmac).unwrap());
    }

    #[test]
    fn test_policy_iv_reserved() {
        let iv = NanoTdfIv::POLICY_IV;
        assert_eq!(iv.as_bytes(), &[0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_wrong_tag_size_fails() {
        let key = AesKey::from_slice(&[0x42u8; 32]).unwrap();
        let iv = NanoTdfIv::random();
        let plaintext = b"Test";

        // Encrypt with 128-bit tag
        let ciphertext = encrypt(&key, &iv, plaintext, TagSize::Bits128).unwrap();

        // Try to decrypt with 64-bit tag size (should fail - wrong tag size specified)
        let result = decrypt(&key, &iv, &ciphertext, TagSize::Bits64);
        assert!(result.is_err());
    }
}
