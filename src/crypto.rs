// Allow deprecated warnings for Nonce::from_slice() which is the correct API for aes-gcm 0.10.x
// This will be resolved when aes-gcm updates to generic-array 1.x
#![allow(deprecated)]

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("Encryption failed: {0}")]
    AeadError(aes_gcm::Error),
    #[error("Key generation failed")]
    KeyGenerationError,
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub ciphertext: String,      // Base64 encoded encrypted data
    pub iv: String,              // Base64 encoded initialization vector
    pub encrypted_key: String,   // Base64 encoded encrypted payload key
    pub policy_key_hash: String, // Hash of the policy key for verification
}

pub struct TdfEncryption {
    policy_key: Vec<u8>,
    payload_key: Vec<u8>,
}

impl TdfEncryption {
    /// Create a new TdfEncryption instance with generated keys
    pub fn new() -> Result<Self, EncryptionError> {
        let mut policy_key = vec![0u8; 32]; // 256-bit key
        let mut payload_key = vec![0u8; 32]; // 256-bit key

        OsRng.fill_bytes(&mut policy_key);
        OsRng.fill_bytes(&mut payload_key);

        Ok(Self {
            policy_key,
            payload_key,
        })
    }

    /// Create a TdfEncryption instance with an existing policy key
    pub fn with_policy_key(policy_key: &[u8]) -> Result<Self, EncryptionError> {
        if policy_key.len() != 32 {
            return Err(EncryptionError::InvalidKeyLength);
        }

        let mut payload_key = vec![0u8; 32];
        OsRng.fill_bytes(&mut payload_key);

        Ok(Self {
            policy_key: policy_key.to_vec(),
            payload_key,
        })
    }

    /// Create TdfEncryption with a known payload key (for KAS decryption)
    ///
    /// When decrypting a TDF with KAS, the unwrapped key from KAS IS the payload key.
    /// This constructor uses that key directly without generating a new random one.
    pub fn with_payload_key(payload_key: &[u8]) -> Result<Self, EncryptionError> {
        if payload_key.len() != 32 {
            return Err(EncryptionError::InvalidKeyLength);
        }

        Ok(Self {
            policy_key: vec![0u8; 32], // Not used for decryption
            payload_key: payload_key.to_vec(),
        })
    }

    /// Encrypt data using the payload key and then encrypt the payload key using the policy key
    pub fn encrypt(&self, data: &[u8]) -> Result<EncryptedPayload, EncryptionError> {
        // Generate random IV for payload encryption
        let mut payload_iv = vec![0u8; 12]; // 96-bit IV for AES-GCM
        OsRng.fill_bytes(&mut payload_iv);

        // Encrypt the actual data using the payload key
        let payload_cipher = Aes256Gcm::new_from_slice(&self.payload_key)
            .map_err(|_| EncryptionError::InvalidKeyLength)?;
        let nonce = Nonce::from_slice(&payload_iv);
        let ciphertext = payload_cipher
            .encrypt(nonce, data)
            .map_err(EncryptionError::AeadError)?;

        // Generate random IV for key encryption
        let mut key_iv = vec![0u8; 12];
        OsRng.fill_bytes(&mut key_iv);

        // Encrypt the payload key using the policy key
        let policy_cipher = Aes256Gcm::new_from_slice(&self.policy_key)
            .map_err(|_| EncryptionError::InvalidKeyLength)?;
        let key_nonce = Nonce::from_slice(&key_iv);
        let encrypted_key = policy_cipher
            .encrypt(key_nonce, self.payload_key.as_ref())
            .map_err(EncryptionError::AeadError)?;

        // Calculate policy key hash for verification
        let mut hasher = Sha256::new();
        hasher.update(&self.policy_key);
        let policy_key_hash = hasher.finalize();

        Ok(EncryptedPayload {
            ciphertext: BASE64.encode(ciphertext),
            iv: BASE64.encode([payload_iv.as_slice(), key_iv.as_slice()].concat()),
            encrypted_key: BASE64.encode(encrypted_key),
            policy_key_hash: BASE64.encode(policy_key_hash),
        })
    }

    /// Decrypt data using the policy key to first decrypt the payload key
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        iv: &[u8],
        encrypted_key: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        // First decrypt the payload key using the policy key
        let policy_cipher = Aes256Gcm::new_from_slice(&self.policy_key)
            .map_err(|_| EncryptionError::InvalidKeyLength)?;
        let nonce = Nonce::from_slice(iv);

        self.payload_key = policy_cipher
            .decrypt(nonce, encrypted_key)
            .map_err(EncryptionError::AeadError)?;

        // Then decrypt the actual data using the decrypted payload key
        let payload_cipher = Aes256Gcm::new_from_slice(&self.payload_key)
            .map_err(|_| EncryptionError::InvalidKeyLength)?;
        let payload_nonce = Nonce::from_slice(iv); // Use the same IV for simplicity
        let plaintext = payload_cipher
            .decrypt(payload_nonce, ciphertext)
            .map_err(EncryptionError::AeadError)?;

        Ok(plaintext)
    }

    /// Decrypt using the old format with combined IVs (for backward compatibility)
    pub fn decrypt_legacy(
        policy_key: &[u8],
        encrypted_payload: &EncryptedPayload,
    ) -> Result<Vec<u8>, EncryptionError> {
        // Decode base64 values
        let ciphertext = BASE64.decode(&encrypted_payload.ciphertext)?;
        let combined_iv = BASE64.decode(&encrypted_payload.iv)?;
        let encrypted_key = BASE64.decode(&encrypted_payload.encrypted_key)?;

        // Split combined IV into payload and key IVs
        let (payload_iv, key_iv) = combined_iv.split_at(12);

        // First decrypt the payload key using the policy key
        let policy_cipher =
            Aes256Gcm::new_from_slice(policy_key).map_err(|_| EncryptionError::InvalidKeyLength)?;
        let key_nonce = Nonce::from_slice(key_iv);
        let payload_key = policy_cipher
            .decrypt(key_nonce, encrypted_key.as_ref())
            .map_err(EncryptionError::AeadError)?;

        // Then decrypt the actual data using the decrypted payload key
        let payload_cipher = Aes256Gcm::new_from_slice(&payload_key)
            .map_err(|_| EncryptionError::InvalidKeyLength)?;
        let payload_nonce = Nonce::from_slice(payload_iv);
        let plaintext = payload_cipher
            .decrypt(payload_nonce, ciphertext.as_ref())
            .map_err(EncryptionError::AeadError)?;

        Ok(plaintext)
    }

    /// Get the policy key
    pub fn policy_key(&self) -> &[u8] {
        &self.policy_key
    }

    /// Get the payload key
    pub fn payload_key(&self) -> &[u8] {
        &self.payload_key
    }

    /// Encrypt data using segment-based encryption for OpenTDF compatibility
    ///
    /// This implements the OpenTDF standard segment-based encryption:
    /// - Splits payload into segments (default 2MB)
    /// - Encrypts each segment with AES-256-GCM
    /// - Extracts GMAC tag (last 16 bytes) from each encrypted segment
    /// - Returns segment data and metadata for manifest generation
    pub fn encrypt_with_segments(
        &self,
        data: &[u8],
        segment_size: usize,
    ) -> Result<SegmentedPayload, EncryptionError> {
        const GCM_IV_SIZE: usize = 12; // 96-bit IV
        const GCM_TAG_SIZE: usize = 16; // 128-bit authentication tag

        let cipher = Aes256Gcm::new_from_slice(&self.payload_key)
            .map_err(|_| EncryptionError::InvalidKeyLength)?;
        let mut segments = Vec::new();
        let mut segment_info = Vec::new();
        let mut gmac_tags = Vec::new();

        // Process data in segments
        for chunk in data.chunks(segment_size) {
            // Generate unique IV for this segment
            let mut iv = vec![0u8; GCM_IV_SIZE];
            OsRng.fill_bytes(&mut iv);
            let nonce = Nonce::from_slice(&iv);

            // Encrypt segment
            let ciphertext = cipher
                .encrypt(nonce, chunk)
                .map_err(EncryptionError::AeadError)?;

            // AES-GCM output format: [encrypted_data][16-byte auth tag]
            // GMAC is the authentication tag (last 16 bytes)
            let gmac_tag = ciphertext[ciphertext.len() - GCM_TAG_SIZE..].to_vec();
            gmac_tags.push(gmac_tag.clone());

            // Prepend IV to ciphertext for storage (OpenTDF format)
            let mut segment_data = iv;
            segment_data.extend_from_slice(&ciphertext);

            segment_info.push(SegmentInfo {
                hash: BASE64.encode(&gmac_tag),
                plaintext_size: chunk.len() as u64,
                encrypted_size: segment_data.len() as u64,
            });

            segments.push(segment_data);
        }

        Ok(SegmentedPayload {
            segments,
            segment_info,
            gmac_tags,
        })
    }

    /// Decrypt data using segment-based decryption for OpenTDF compatibility
    ///
    /// This implements the OpenTDF standard segment-based decryption:
    /// - Parses payload into segments based on segment metadata
    /// - Each segment format: [IV (12 bytes)][Ciphertext + Tag]
    /// - Decrypts each segment with AES-256-GCM
    /// - Extracts GMAC tag (last 16 bytes) from each encrypted segment
    /// - Returns plaintext and GMAC tags for root signature verification
    ///
    /// # Arguments
    ///
    /// * `payload` - The encrypted payload bytes (concatenated segments)
    /// * `segments` - Segment metadata from manifest
    ///
    /// # Returns
    ///
    /// Tuple of (plaintext, gmac_tags) for verification
    pub fn decrypt_with_segments(
        &self,
        payload: &[u8],
        segments: &[crate::manifest::Segment],
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>), EncryptionError> {
        const GCM_IV_SIZE: usize = 12; // 96-bit IV
        const GCM_TAG_SIZE: usize = 16; // 128-bit authentication tag

        let cipher = Aes256Gcm::new_from_slice(&self.payload_key)
            .map_err(|_| EncryptionError::InvalidKeyLength)?;
        let mut plaintext = Vec::new();
        let mut gmac_tags = Vec::new();
        let mut offset = 0;

        for segment_meta in segments {
            // Get encrypted segment size from metadata
            let encrypted_size = segment_meta
                .encrypted_segment_size
                .ok_or(EncryptionError::KeyGenerationError)?
                as usize;

            // Ensure we don't read past the payload
            if offset + encrypted_size > payload.len() {
                return Err(EncryptionError::KeyGenerationError);
            }

            // Extract segment data
            let segment_data = &payload[offset..offset + encrypted_size];

            // Parse segment: [IV (12)][Ciphertext + Tag]
            if segment_data.len() < GCM_IV_SIZE + GCM_TAG_SIZE {
                return Err(EncryptionError::KeyGenerationError);
            }

            let iv = &segment_data[..GCM_IV_SIZE];
            let ciphertext_and_tag = &segment_data[GCM_IV_SIZE..];

            // Decrypt segment
            let nonce = Nonce::from_slice(iv);
            let decrypted = cipher
                .decrypt(nonce, ciphertext_and_tag)
                .map_err(EncryptionError::AeadError)?;

            // Extract GMAC tag (last 16 bytes of ciphertext_and_tag before decryption)
            let gmac_tag = ciphertext_and_tag[ciphertext_and_tag.len() - GCM_TAG_SIZE..].to_vec();
            gmac_tags.push(gmac_tag);

            plaintext.extend_from_slice(&decrypted);
            offset += encrypted_size;
        }

        Ok((plaintext, gmac_tags))
    }
}

/// Information about an encrypted segment
#[derive(Debug, Clone)]
pub struct SegmentInfo {
    pub hash: String,        // Base64 encoded GMAC tag
    pub plaintext_size: u64, // Size before encryption
    pub encrypted_size: u64, // Size after encryption (includes IV + tag)
}

/// Result of segment-based encryption
#[derive(Debug)]
pub struct SegmentedPayload {
    pub segments: Vec<Vec<u8>>, // Encrypted segment data (IV + ciphertext + tag)
    pub segment_info: Vec<SegmentInfo>, // Metadata for manifest
    pub gmac_tags: Vec<Vec<u8>>, // Raw GMAC tags for root signature
}

/// Wrap a payload key using RSA-OAEP encryption
///
/// This function wraps a symmetric payload key with an RSA public key using OAEP padding.
/// This is used to create TDF files that can be decrypted via the KAS rewrap protocol.
///
/// The algorithm used is RSA-OAEP with SHA1 hash, matching the OpenTDF platform specification.
///
/// # Arguments
///
/// * `payload_key` - The symmetric key to wrap (typically 32 bytes for AES-256)
/// * `kas_public_key_pem` - PEM-encoded RSA public key from KAS
///
/// # Returns
///
/// Base64-encoded wrapped key ready for inclusion in TDF manifest
///
/// # Example
///
/// ```no_run
/// use opentdf::wrap_key_with_rsa_oaep;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let payload_key = &[0u8; 32]; // Your AES-256 key
/// let kas_public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----";
///
/// let wrapped_key = wrap_key_with_rsa_oaep(payload_key, kas_public_key_pem)?;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "kas")]
pub fn wrap_key_with_rsa_oaep(
    payload_key: &[u8],
    kas_public_key_pem: &str,
) -> Result<String, EncryptionError> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::{Oaep, RsaPublicKey};
    use sha1::Sha1;

    // Parse the PEM-encoded public key
    let public_key = RsaPublicKey::from_public_key_pem(kas_public_key_pem).map_err(|_| {
        EncryptionError::KeyGenerationError // Could add a more specific error variant
    })?;

    // Create OAEP padding with SHA1 (matching Go SDK implementation)
    let padding = Oaep::new::<Sha1>();

    // Encrypt the payload key with RSA-OAEP
    let wrapped_key = public_key
        .encrypt(&mut rand::rngs::OsRng, padding, payload_key)
        .map_err(|_| EncryptionError::AeadError(aes_gcm::Error))?;

    // Encode as base64 for storage in manifest
    Ok(BASE64.encode(&wrapped_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() -> Result<(), EncryptionError> {
        // Create new encryption instance
        let tdf = TdfEncryption::new()?;

        // Test data
        let data = b"Hello, TDF!";

        // Encrypt
        let encrypted = tdf.encrypt(data)?;

        // Decrypt using legacy method
        let decrypted = TdfEncryption::decrypt_legacy(tdf.policy_key(), &encrypted)?;

        assert_eq!(data, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_with_existing_policy_key() -> Result<(), EncryptionError> {
        // Create a policy key
        let mut policy_key = vec![0u8; 32];
        OsRng.fill_bytes(&mut policy_key);

        // Create encryption instance with existing policy key
        let tdf = TdfEncryption::with_policy_key(&policy_key)?;

        // Test data
        let data = b"Test with existing policy key";

        // Encrypt
        let encrypted = tdf.encrypt(data)?;

        // Decrypt using legacy method
        let decrypted = TdfEncryption::decrypt_legacy(&policy_key, &encrypted)?;

        assert_eq!(data, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_new_decrypt_method() -> Result<(), EncryptionError> {
        // Create new encryption instance
        let tdf = TdfEncryption::new()?;
        let policy_key = tdf.policy_key().to_vec();

        // Test data
        let data = b"Testing the new decrypt method";

        // Generate IVs and encrypt directly (avoiding the combined IV issue)
        let mut payload_iv = vec![0u8; 12]; // 96-bit IV for AES-GCM
        OsRng.fill_bytes(&mut payload_iv);

        // Encrypt payload directly
        let payload_cipher = Aes256Gcm::new_from_slice(tdf.payload_key())
            .map_err(|_| EncryptionError::InvalidKeyLength)?;
        let nonce = Nonce::from_slice(&payload_iv);
        let ciphertext = payload_cipher
            .encrypt(nonce, data.as_ref())
            .map_err(EncryptionError::AeadError)?;

        // Encrypt the payload key
        let policy_cipher = Aes256Gcm::new_from_slice(&policy_key)
            .map_err(|_| EncryptionError::InvalidKeyLength)?;
        let encrypted_key = policy_cipher
            .encrypt(nonce, tdf.payload_key())
            .map_err(EncryptionError::AeadError)?;

        // Create a new instance with the same policy key
        let mut decryptor = TdfEncryption::with_policy_key(&policy_key)?;

        // Use the new decrypt method
        let decrypted = decryptor.decrypt(&ciphertext, &payload_iv, &encrypted_key)?;

        assert_eq!(data, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_invalid_policy_key_length() {
        // Try to create with invalid key length
        let result = TdfEncryption::with_policy_key(&[0u8; 16]);
        assert!(matches!(result, Err(EncryptionError::InvalidKeyLength)));
    }

    #[test]
    fn test_key_verification() -> Result<(), EncryptionError> {
        let tdf = TdfEncryption::new()?;
        let data = b"Verify policy key";
        let encrypted = tdf.encrypt(data)?;

        // Calculate hash of policy key
        let mut hasher = Sha256::new();
        hasher.update(tdf.policy_key());
        let key_hash = BASE64.encode(hasher.finalize());

        // Verify hash matches
        assert_eq!(encrypted.policy_key_hash, key_hash);
        Ok(())
    }

    #[test]
    fn test_segment_encryption_and_decryption() -> Result<(), EncryptionError> {
        use crate::manifest::Segment;

        // Create encryption instance
        let tdf = TdfEncryption::new()?;
        let plaintext =
            b"Hello from segment test! This is a test of segment-based encryption and decryption.";

        // Encrypt with segments (use small segment size for testing)
        const SEGMENT_SIZE: usize = 32;
        let segmented = tdf.encrypt_with_segments(plaintext, SEGMENT_SIZE)?;

        // Verify we got the expected number of segments
        let expected_segments = plaintext.len().div_ceil(SEGMENT_SIZE);
        assert_eq!(segmented.segments.len(), expected_segments);
        assert_eq!(segmented.segment_info.len(), expected_segments);
        assert_eq!(segmented.gmac_tags.len(), expected_segments);

        // Create segment metadata for decryption
        let segments: Vec<Segment> = segmented
            .segment_info
            .iter()
            .map(|info| Segment {
                hash: info.hash.clone(),
                segment_size: Some(info.plaintext_size),
                encrypted_segment_size: Some(info.encrypted_size),
            })
            .collect();

        // Concatenate all segment data
        let mut payload = Vec::new();
        for segment in &segmented.segments {
            payload.extend_from_slice(segment);
        }

        // Decrypt
        let (decrypted, gmac_tags) = tdf.decrypt_with_segments(&payload, &segments)?;

        // Verify plaintext matches
        assert_eq!(plaintext, decrypted.as_slice());

        // Verify GMAC tags match
        assert_eq!(gmac_tags.len(), segmented.gmac_tags.len());
        for (extracted, original) in gmac_tags.iter().zip(segmented.gmac_tags.iter()) {
            assert_eq!(extracted, original);
        }

        Ok(())
    }

    #[test]
    fn test_segment_decryption_with_root_signature() -> Result<(), EncryptionError> {
        use crate::manifest::{IntegrityInformation, RootSignature, Segment};

        // Create encryption instance
        let tdf = TdfEncryption::new()?;
        let plaintext = b"Testing root signature verification with segments";

        // Encrypt with segments
        const SEGMENT_SIZE: usize = 20;
        let segmented = tdf.encrypt_with_segments(plaintext, SEGMENT_SIZE)?;

        // Create integrity information with root signature
        let mut integrity_info = IntegrityInformation {
            root_signature: RootSignature {
                alg: "HS256".to_string(),
                sig: String::new(),
            },
            segment_hash_alg: "GMAC".to_string(),
            segments: Vec::new(),
            segment_size_default: SEGMENT_SIZE as u64,
            encrypted_segment_size_default: (SEGMENT_SIZE + 12 + 16) as u64,
        };

        // Generate root signature
        integrity_info
            .generate_root_signature(&segmented.gmac_tags, tdf.payload_key())
            .expect("Failed to generate root signature");

        // Create segment metadata
        let segments: Vec<Segment> = segmented
            .segment_info
            .iter()
            .map(|info| Segment {
                hash: info.hash.clone(),
                segment_size: Some(info.plaintext_size),
                encrypted_segment_size: Some(info.encrypted_size),
            })
            .collect();

        // Concatenate payload
        let mut payload = Vec::new();
        for segment in &segmented.segments {
            payload.extend_from_slice(segment);
        }

        // Decrypt and extract GMAC tags
        let (decrypted, gmac_tags) = tdf.decrypt_with_segments(&payload, &segments)?;

        // Verify root signature
        integrity_info
            .verify_root_signature(&gmac_tags, tdf.payload_key())
            .expect("Root signature verification failed");

        // Verify plaintext
        assert_eq!(plaintext, decrypted.as_slice());

        Ok(())
    }
}
