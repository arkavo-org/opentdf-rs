//! TDF Encryption implementation with zeroizing keys
//!
//! This module implements segment-based encryption for OpenTDF standard TDF format.
//! All cryptographic key material uses zeroizing types for secure memory handling.

// Allow deprecated warnings for Nonce::from_slice() which is the correct API for aes-gcm 0.10.x
#![allow(deprecated)]

use crate::helpers::{generate_key_32, generate_nonce};
use crate::hmac::{HmacError, verify_segment_hash};
use crate::types::{PayloadKey, PolicyKey};
use aes_gcm::{
    Aes256Gcm, Nonce, Tag,
    aead::{Aead, AeadInPlace, KeyInit},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("Encryption failed: {0}")]
    AeadError(aes_gcm::Error),

    #[error("Key generation failed")]
    KeyGenerationError,

    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("Invalid IV length: {0} bytes, expected 12")]
    InvalidIvLength(usize),

    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("Segment error: {0}")]
    SegmentError(String),

    /// A segment decrypted under the payload key, but its GCM tag is not the
    /// one the manifest lists for it: the segment was swapped, reordered or
    /// replaced, or the manifest's segment hash was edited.
    #[error("Segment integrity check failed: GMAC tag does not match the expected segment hash")]
    SegmentHashMismatch,
}

/// One encrypted OpenTDF segment: `IV[12] || ciphertext || tag[16]`.
///
/// Produced by [`TdfEncryption::encrypt_segment`], which encrypts exactly one
/// caller-chosen slice. Profiles with variable-length segments (such as a GGUF
/// header followed by fixed-cap weight windows) cannot express their plan
/// through [`TdfEncryption::encrypt_with_segments`], which cuts uniform chunks
/// out of a fully buffered payload.
#[derive(Debug, Clone)]
pub struct EncryptedSegment {
    /// Member bytes as written to storage.
    pub bytes: Vec<u8>,
    /// The 16-byte GCM tag, which is also the OpenTDF GMAC segment hash.
    pub tag: [u8; 16],
}

/// Encrypted payload structure
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedPayload {
    /// Base64 encoded encrypted data
    pub ciphertext: String,

    /// Base64 encoded initialization vector
    pub iv: String,

    /// Base64 encoded encrypted payload key
    pub encrypted_key: String,

    /// Hash of the policy key for verification
    pub policy_key_hash: String,
}

/// TDF encryption engine with zeroizing keys
pub struct TdfEncryption {
    policy_key: PolicyKey,
    payload_key: PayloadKey,
}

impl TdfEncryption {
    /// Create a new TdfEncryption instance with generated keys
    pub fn new() -> Result<Self, EncryptionError> {
        let policy_key_bytes = generate_key_32();
        let payload_key_bytes = generate_key_32();

        Ok(Self {
            policy_key: PolicyKey::from_slice(&policy_key_bytes)
                .map_err(|_| EncryptionError::InvalidKeyLength)?,
            payload_key: PayloadKey::from_slice(&payload_key_bytes)
                .map_err(|_| EncryptionError::InvalidKeyLength)?,
        })
    }

    /// Create a TdfEncryption instance with an existing policy key
    pub fn with_policy_key(policy_key: &[u8]) -> Result<Self, EncryptionError> {
        let payload_key_bytes = generate_key_32();

        Ok(Self {
            policy_key: PolicyKey::from_slice(policy_key)
                .map_err(|_| EncryptionError::InvalidKeyLength)?,
            payload_key: PayloadKey::from_slice(&payload_key_bytes)
                .map_err(|_| EncryptionError::InvalidKeyLength)?,
        })
    }

    /// Create TdfEncryption with a known payload key (for KAS decryption)
    ///
    /// When decrypting a TDF with KAS, the unwrapped key from KAS IS the payload key.
    /// This constructor uses that key directly without generating a new random one.
    pub fn with_payload_key(payload_key: &[u8]) -> Result<Self, EncryptionError> {
        let policy_key_bytes = [0u8; 32]; // Not used for decryption

        Ok(Self {
            policy_key: PolicyKey::from_slice(&policy_key_bytes)
                .map_err(|_| EncryptionError::InvalidKeyLength)?,
            payload_key: PayloadKey::from_slice(payload_key)
                .map_err(|_| EncryptionError::InvalidKeyLength)?,
        })
    }

    /// Encrypt data using the payload key and then encrypt the payload key using the policy key
    pub fn encrypt(&self, data: &[u8]) -> Result<EncryptedPayload, EncryptionError> {
        // Generate random IV for payload encryption
        let payload_iv = generate_nonce();

        // Encrypt the actual data using the payload key
        let payload_cipher = Aes256Gcm::new_from_slice(self.payload_key.as_slice())
            .map_err(|_| EncryptionError::InvalidKeyLength)?;
        let nonce = Nonce::from_slice(payload_iv.as_slice());
        let ciphertext = payload_cipher
            .encrypt(nonce, data)
            .map_err(EncryptionError::AeadError)?;

        // Generate random IV for key encryption
        let key_iv = generate_nonce();

        // Encrypt the payload key using the policy key
        let policy_cipher = Aes256Gcm::new_from_slice(self.policy_key.as_slice())
            .map_err(|_| EncryptionError::InvalidKeyLength)?;
        let key_nonce = Nonce::from_slice(key_iv.as_slice());
        let encrypted_key = policy_cipher
            .encrypt(key_nonce, self.payload_key.as_slice())
            .map_err(EncryptionError::AeadError)?;

        // Calculate policy key hash for verification
        let mut hasher = Sha256::new();
        hasher.update(self.policy_key.as_slice());
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
        let policy_cipher = Aes256Gcm::new_from_slice(self.policy_key.as_slice())
            .map_err(|_| EncryptionError::InvalidKeyLength)?;
        let nonce = Nonce::from_slice(iv);

        let decrypted_payload_key = policy_cipher
            .decrypt(nonce, encrypted_key)
            .map_err(EncryptionError::AeadError)?;

        // Update payload key
        self.payload_key = PayloadKey::from_slice(&decrypted_payload_key)
            .map_err(|_| EncryptionError::InvalidKeyLength)?;

        // Then decrypt the actual data using the decrypted payload key
        let payload_cipher = Aes256Gcm::new_from_slice(self.payload_key.as_slice())
            .map_err(|_| EncryptionError::InvalidKeyLength)?;
        let payload_nonce = Nonce::from_slice(iv);
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
        self.policy_key.as_slice()
    }

    /// Get the payload key
    pub fn payload_key(&self) -> &[u8] {
        self.payload_key.as_slice()
    }

    /// Encrypt exactly one pre-cut segment.
    ///
    /// The caller chooses the boundary, so a source is never fully buffered
    /// and segments may vary in length.
    pub fn encrypt_segment(&self, plaintext: &[u8]) -> Result<EncryptedSegment, EncryptionError> {
        const GCM_TAG_SIZE: usize = 16;

        let cipher = Aes256Gcm::new_from_slice(self.payload_key.as_slice())
            .map_err(|_| EncryptionError::InvalidKeyLength)?;
        let iv = generate_nonce();
        let nonce = Nonce::from_slice(iv.as_slice());

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(EncryptionError::AeadError)?;

        if ciphertext.len() < GCM_TAG_SIZE {
            return Err(EncryptionError::SegmentError(
                "AES-GCM output shorter than its tag".to_string(),
            ));
        }

        let mut tag = [0u8; GCM_TAG_SIZE];
        tag.copy_from_slice(&ciphertext[ciphertext.len() - GCM_TAG_SIZE..]);

        let mut bytes = Vec::with_capacity(12 + ciphertext.len());
        bytes.extend_from_slice(iv.as_slice());
        bytes.extend_from_slice(&ciphertext);

        Ok(EncryptedSegment { bytes, tag })
    }

    /// Decrypt one segment member into `dest` in place, verifying the GCM tag.
    ///
    /// `dest.len()` must equal `member.len() - 28`. `dest` is the only
    /// plaintext buffer this function touches: the ciphertext body is
    /// copied into it and then decrypted in place via
    /// [`AeadInPlace::decrypt_in_place_detached`], so the function performs
    /// no heap allocation and no second plaintext is ever created (and left
    /// unzeroized on drop). Bounding the destination keeps a reader's
    /// scratch allocation fixed at the manifest's declared `segmentSize`
    /// instead of growing with the archive.
    ///
    /// If tag verification fails, `dest` is zeroized before the error is
    /// returned, so a caller can never observe a partially transformed or
    /// stale buffer.
    ///
    /// Returns the verified 16-byte tag so the caller can compare it with the
    /// manifest's segment hash and detect a tag/manifest swap.
    pub fn decrypt_segment_into(
        &self,
        member: &[u8],
        dest: &mut [u8],
    ) -> Result<[u8; 16], EncryptionError> {
        const IV_SIZE: usize = 12;
        const GCM_TAG_SIZE: usize = 16;
        const OVERHEAD: usize = IV_SIZE + GCM_TAG_SIZE;

        if member.len() < OVERHEAD {
            return Err(EncryptionError::SegmentError(format!(
                "segment member is {} bytes, shorter than the {OVERHEAD}-byte overhead",
                member.len()
            )));
        }
        if member.len() - OVERHEAD != dest.len() {
            return Err(EncryptionError::SegmentError(format!(
                "destination is {} bytes but member holds {} plaintext bytes",
                dest.len(),
                member.len() - OVERHEAD
            )));
        }

        let cipher = Aes256Gcm::new_from_slice(self.payload_key.as_slice())
            .map_err(|_| EncryptionError::InvalidKeyLength)?;
        let nonce = Nonce::from_slice(&member[..IV_SIZE]);

        let ciphertext_end = member.len() - GCM_TAG_SIZE;
        dest.copy_from_slice(&member[IV_SIZE..ciphertext_end]);
        let tag = Tag::from_slice(&member[ciphertext_end..]);

        if let Err(e) = cipher.decrypt_in_place_detached(nonce, b"", dest, tag) {
            dest.zeroize();
            return Err(EncryptionError::AeadError(e));
        }

        let mut tag_bytes = [0u8; GCM_TAG_SIZE];
        tag_bytes.copy_from_slice(&member[member.len() - GCM_TAG_SIZE..]);
        Ok(tag_bytes)
    }

    /// Decrypt one segment member into `dest` in place and check it against
    /// the manifest's hash for that segment.
    ///
    /// This is [`decrypt_segment_into`](Self::decrypt_segment_into) followed
    /// by the comparison its caller must otherwise remember to make:
    /// `expected_hash_b64` is the manifest's
    /// `integrityInformation.segments[i].hash`, `base64(raw 16-byte GMAC
    /// tag)`, and it is compared with the member's verified tag in constant
    /// time. The GCM tag alone proves the member was written under this
    /// payload key; the manifest hash is what proves it is the member that
    /// belongs at this position, so a reader that skips the comparison
    /// accepts segments swapped within, or spliced between, archives sharing
    /// a key.
    ///
    /// `dest.len()` must equal `member.len() - 28`, as for
    /// `decrypt_segment_into`.
    ///
    /// # Errors
    ///
    /// - [`EncryptionError::AeadError`] if the GCM tag does not verify.
    /// - [`EncryptionError::Base64Error`] if `expected_hash_b64` is not
    ///   valid base64.
    /// - [`EncryptionError::SegmentHashMismatch`] if the tag differs from the
    ///   expected hash, including an expected hash that is not 16 bytes.
    /// - [`EncryptionError::SegmentError`] for a member or destination of the
    ///   wrong length.
    ///
    /// In the first three cases `dest` is zeroized before the error is
    /// returned, so plaintext that failed either check never reaches the
    /// caller.
    pub fn decrypt_segment_into_verified(
        &self,
        member: &[u8],
        dest: &mut [u8],
        expected_hash_b64: &str,
    ) -> Result<(), EncryptionError> {
        let tag = self.decrypt_segment_into(member, dest)?;

        verify_segment_hash(expected_hash_b64, &tag).map_err(|e| {
            dest.zeroize();
            match e {
                HmacError::Base64Error(source) => EncryptionError::Base64Error(source),
                HmacError::InitFailed | HmacError::VerificationFailed => {
                    EncryptionError::SegmentHashMismatch
                }
            }
        })
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
        const GCM_TAG_SIZE: usize = 16; // 128-bit authentication tag

        let cipher = Aes256Gcm::new_from_slice(self.payload_key.as_slice())
            .map_err(|_| EncryptionError::InvalidKeyLength)?;

        // Pre-allocate vectors with expected capacity for performance
        let segment_count = data.len().div_ceil(segment_size);
        let mut segments = Vec::with_capacity(segment_count);
        let mut segment_info = Vec::with_capacity(segment_count);
        let mut gmac_tags = Vec::with_capacity(segment_count);

        // Process data in segments
        for chunk in data.chunks(segment_size) {
            // Generate unique IV for this segment
            let iv = generate_nonce();
            let nonce = Nonce::from_slice(iv.as_slice());

            // Encrypt segment
            let ciphertext = cipher
                .encrypt(nonce, chunk)
                .map_err(EncryptionError::AeadError)?;

            // AES-GCM output format: [encrypted_data][16-byte auth tag]
            // GMAC is the authentication tag (last 16 bytes)
            let gmac_tag = ciphertext[ciphertext.len() - GCM_TAG_SIZE..].to_vec();

            // Prepend IV to ciphertext for storage (OpenTDF format)
            let mut segment_data = iv.as_slice().to_vec();
            segment_data.extend_from_slice(&ciphertext);

            segment_info.push(SegmentInfo {
                hash: BASE64.encode(&gmac_tag),
                plaintext_size: chunk.len() as u64,
                encrypted_size: segment_data.len() as u64,
            });

            segments.push(segment_data);
            gmac_tags.push(gmac_tag);
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
    /// * `segments` - Segment metadata (encrypted sizes)
    ///
    /// # Returns
    ///
    /// Tuple of (plaintext, gmac_tags) for verification.
    ///
    /// # Security Note
    ///
    /// The returned plaintext is the caller's responsibility. Consider wrapping
    /// in `zeroize::Zeroizing` if the content is sensitive and should be wiped
    /// from memory when no longer needed.
    pub fn decrypt_with_segments(
        &self,
        payload: &[u8],
        segments: &[(u64, u64)], // (plaintext_size, encrypted_size)
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>), EncryptionError> {
        const GCM_IV_SIZE: usize = 12; // 96-bit IV
        const GCM_TAG_SIZE: usize = 16; // 128-bit authentication tag

        let cipher = Aes256Gcm::new_from_slice(self.payload_key.as_slice())
            .map_err(|_| EncryptionError::InvalidKeyLength)?;

        // Pre-allocate with expected capacity. The declared sizes come from a
        // manifest that is not authenticated yet, and plaintext is never
        // longer than the ciphertext it is decrypted from, so the reservation
        // is capped at the payload length: a hostile size cannot make this
        // overflow or reserve more memory than the caller already holds.
        let declared_plaintext_size = segments.iter().fold(0usize, |total, (pt, _)| {
            total.saturating_add(usize::try_from(*pt).unwrap_or(usize::MAX))
        });
        let mut plaintext = Vec::with_capacity(declared_plaintext_size.min(payload.len()));
        let mut gmac_tags = Vec::with_capacity(segments.len());
        let mut offset = 0usize;

        for (_plaintext_size, encrypted_size) in segments {
            // Ensure we don't read past the payload. Checked arithmetic: an
            // encrypted size near `u64::MAX` must fail here, not wrap.
            let segment_end = usize::try_from(*encrypted_size)
                .ok()
                .and_then(|encrypted_size| offset.checked_add(encrypted_size))
                .filter(|segment_end| *segment_end <= payload.len())
                .ok_or_else(|| {
                    EncryptionError::SegmentError("Segment extends beyond payload".to_string())
                })?;

            // Extract segment data
            let segment_data = &payload[offset..segment_end];

            // Parse segment: [IV (12)][Ciphertext + Tag]
            if segment_data.len() < GCM_IV_SIZE + GCM_TAG_SIZE {
                return Err(EncryptionError::SegmentError(
                    "Segment too small".to_string(),
                ));
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
            offset = segment_end;
        }

        Ok((plaintext, gmac_tags))
    }
}

impl Default for TdfEncryption {
    fn default() -> Self {
        Self::new().expect("Failed to generate keys")
    }
}

/// Information about an encrypted segment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentInfo {
    /// Base64 encoded GMAC tag
    pub hash: String,

    /// Size before encryption
    pub plaintext_size: u64,

    /// Size after encryption (includes IV + tag)
    pub encrypted_size: u64,
}

/// Result of segment-based encryption
#[derive(Debug)]
pub struct SegmentedPayload {
    /// Encrypted segment data (IV + ciphertext + tag)
    pub segments: Vec<Vec<u8>>,

    /// Metadata for manifest
    pub segment_info: Vec<SegmentInfo>,

    /// Raw GMAC tags for root signature
    pub gmac_tags: Vec<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() -> Result<(), EncryptionError> {
        let tdf = TdfEncryption::new()?;
        let data = b"Hello, TDF!";

        let encrypted = tdf.encrypt(data)?;
        let decrypted = TdfEncryption::decrypt_legacy(tdf.policy_key(), &encrypted)?;

        assert_eq!(data, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_segment_encryption_and_decryption() -> Result<(), EncryptionError> {
        let tdf = TdfEncryption::new()?;
        let plaintext =
            b"Hello from segment test! This is a test of segment-based encryption and decryption.";

        const SEGMENT_SIZE: usize = 32;
        let segmented = tdf.encrypt_with_segments(plaintext, SEGMENT_SIZE)?;

        let expected_segments = plaintext.len().div_ceil(SEGMENT_SIZE);
        assert_eq!(segmented.segments.len(), expected_segments);

        // Create segment metadata for decryption
        let segments: Vec<(u64, u64)> = segmented
            .segment_info
            .iter()
            .map(|info| (info.plaintext_size, info.encrypted_size))
            .collect();

        // Concatenate all segment data
        let mut payload = Vec::new();
        for segment in &segmented.segments {
            payload.extend_from_slice(segment);
        }

        // Decrypt
        let (decrypted, gmac_tags) = tdf.decrypt_with_segments(&payload, &segments)?;

        assert_eq!(plaintext, decrypted.as_slice());
        assert_eq!(gmac_tags.len(), segmented.gmac_tags.len());

        Ok(())
    }

    /// Segment sizes reach `decrypt_with_segments` from a manifest that has
    /// not been authenticated. Hostile values must produce an error or be
    /// ignored, never an overflow, a capacity panic or a huge reservation.
    #[test]
    fn decrypt_with_segments_survives_hostile_declared_sizes() -> Result<(), EncryptionError> {
        let tdf = TdfEncryption::new()?;
        let plaintext = b"sixteen byte msg";
        let segmented = tdf.encrypt_with_segments(plaintext, plaintext.len())?;
        let payload = segmented.segments.concat();
        let encrypted_size = payload.len() as u64;

        // A declared plaintext size is only a capacity hint.
        for declared in [u64::MAX, 1 << 60] {
            let (decrypted, tags) =
                tdf.decrypt_with_segments(&payload, &[(declared, encrypted_size)])?;
            assert_eq!(decrypted, plaintext);
            assert_eq!(tags.len(), 1);
        }

        // An encrypted size past the payload, including one that would wrap
        // the running offset, is a segment error.
        for segments in [
            vec![(0, u64::MAX)],
            vec![(0, encrypted_size + 1)],
            vec![(0, encrypted_size), (0, u64::MAX)],
        ] {
            let err = tdf
                .decrypt_with_segments(&payload, &segments)
                .expect_err("segment extends beyond the payload");
            assert!(matches!(err, EncryptionError::SegmentError(_)), "{err:?}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod single_segment_tests {
    use super::*;

    #[test]
    fn encrypt_segment_layout_and_round_trip() {
        let enc = TdfEncryption::new().unwrap();
        let plaintext = vec![0xABu8; 300];

        let seg = enc.encrypt_segment(&plaintext).unwrap();
        // IV(12) || ciphertext(300) || tag(16)
        assert_eq!(seg.bytes.len(), plaintext.len() + 28);
        assert_eq!(&seg.bytes[seg.bytes.len() - 16..], &seg.tag[..]);

        // Distinct IVs under the same payload key.
        let seg2 = enc.encrypt_segment(&plaintext).unwrap();
        assert_ne!(seg.bytes[..12], seg2.bytes[..12]);

        let mut dest = vec![0u8; plaintext.len()];
        let tag = enc.decrypt_segment_into(&seg.bytes, &mut dest).unwrap();
        assert_eq!(dest, plaintext);
        assert_eq!(tag, seg.tag);
    }

    #[test]
    fn encrypt_segment_handles_empty_and_large_slices() {
        let enc = TdfEncryption::new().unwrap();

        let empty = enc.encrypt_segment(&[]).unwrap();
        assert_eq!(empty.bytes.len(), 28);
        let mut dest = Vec::new();
        assert_eq!(
            enc.decrypt_segment_into(&empty.bytes, &mut dest).unwrap(),
            empty.tag
        );

        let big = vec![7u8; 4 * 1024 * 1024];
        let seg = enc.encrypt_segment(&big).unwrap();
        assert_eq!(seg.bytes.len(), big.len() + 28);
        let mut dest = vec![0u8; big.len()];
        enc.decrypt_segment_into(&seg.bytes, &mut dest).unwrap();
        assert_eq!(dest, big);
    }

    #[test]
    fn decrypt_segment_rejects_tampering_and_bad_length() {
        let enc = TdfEncryption::new().unwrap();
        let seg = enc.encrypt_segment(b"weights").unwrap();

        let mut flipped = seg.bytes.clone();
        flipped[20] ^= 0x01;
        let mut dest = vec![0u8; 7];
        assert!(enc.decrypt_segment_into(&flipped, &mut dest).is_err());

        // Destination length must equal member length - 28.
        let mut wrong = vec![0u8; 8];
        assert!(enc.decrypt_segment_into(&seg.bytes, &mut wrong).is_err());

        // Member shorter than IV + tag.
        let mut tiny = Vec::new();
        assert!(
            enc.decrypt_segment_into(&seg.bytes[..20], &mut tiny)
                .is_err()
        );
    }

    #[test]
    fn decrypt_segment_rejects_a_foreign_key() {
        let a = TdfEncryption::new().unwrap();
        let b = TdfEncryption::new().unwrap();
        let seg = a.encrypt_segment(b"secret weights").unwrap();
        let mut dest = vec![0u8; 14];
        assert!(b.decrypt_segment_into(&seg.bytes, &mut dest).is_err());
    }

    #[test]
    fn decrypt_segment_into_zeroizes_dest_on_tag_failure() {
        let enc = TdfEncryption::new().unwrap();
        let plaintext = vec![0x11u8; 4096];
        let seg = enc.encrypt_segment(&plaintext).unwrap();

        // Flip a ciphertext byte (past the 12-byte IV) so the GCM tag fails
        // to verify.
        let mut tampered = seg.bytes.clone();
        tampered[12] ^= 0x01;

        let mut dest = vec![0xAAu8; plaintext.len()];
        let err = enc.decrypt_segment_into(&tampered, &mut dest).unwrap_err();
        assert!(matches!(err, EncryptionError::AeadError(_)));
        assert!(
            dest.iter().all(|b| *b == 0),
            "dest must be zeroized after a failed decrypt, not left holding partial/garbage plaintext"
        );
    }

    #[test]
    fn decrypt_segment_into_verified_accepts_the_manifest_hash() {
        let enc = TdfEncryption::new().unwrap();
        let plaintext = vec![0x5Au8; 300];
        let seg = enc.encrypt_segment(&plaintext).unwrap();

        // The hash a writer puts in the manifest: base64 of the raw tag,
        // which is also what `encrypt_with_segments` records.
        let manifest_hash = BASE64.encode(seg.tag);
        let streamed = enc
            .encrypt_with_segments(&plaintext, plaintext.len())
            .unwrap();

        let mut dest = vec![0u8; plaintext.len()];
        enc.decrypt_segment_into_verified(&seg.bytes, &mut dest, &manifest_hash)
            .unwrap();
        assert_eq!(dest, plaintext);

        let mut dest = vec![0u8; plaintext.len()];
        enc.decrypt_segment_into_verified(
            &streamed.segments[0],
            &mut dest,
            &streamed.segment_info[0].hash,
        )
        .unwrap();
        assert_eq!(dest, plaintext);
    }

    /// Two segments under one payload key both pass GCM. Only the manifest
    /// hash tells them apart, so a swapped member must be refused and its
    /// plaintext must not be left in `dest`.
    #[test]
    fn decrypt_segment_into_verified_rejects_a_swapped_segment() {
        let enc = TdfEncryption::new().unwrap();
        let first = enc.encrypt_segment(&[0x11u8; 64]).unwrap();
        let second = enc.encrypt_segment(&[0x22u8; 64]).unwrap();
        let first_hash = BASE64.encode(first.tag);

        let mut dest = vec![0xAAu8; 64];
        let err = enc
            .decrypt_segment_into_verified(&second.bytes, &mut dest, &first_hash)
            .unwrap_err();
        assert!(
            matches!(err, EncryptionError::SegmentHashMismatch),
            "{err:?}"
        );
        assert!(
            dest.iter().all(|b| *b == 0),
            "dest must be zeroized when the segment is not the one the manifest names"
        );

        // A single flipped bit anywhere in the expected tag is a mismatch.
        for position in [0, 7, 15] {
            let mut wrong = first.tag;
            wrong[position] ^= 0x01;
            let mut dest = vec![0u8; 64];
            let err = enc
                .decrypt_segment_into_verified(&first.bytes, &mut dest, &BASE64.encode(wrong))
                .unwrap_err();
            assert!(
                matches!(err, EncryptionError::SegmentHashMismatch),
                "position {position}: {err:?}"
            );
        }
    }

    #[test]
    fn decrypt_segment_into_verified_rejects_malformed_expected_hashes() {
        let enc = TdfEncryption::new().unwrap();
        let plaintext = [0x33u8; 48];
        let seg = enc.encrypt_segment(&plaintext).unwrap();

        // Not base64 at all.
        let mut dest = vec![0xAAu8; plaintext.len()];
        let err = enc
            .decrypt_segment_into_verified(&seg.bytes, &mut dest, "not base64!")
            .unwrap_err();
        assert!(matches!(err, EncryptionError::Base64Error(_)), "{err:?}");
        assert!(dest.iter().all(|b| *b == 0), "dest must be zeroized");

        // Valid base64 of the wrong length: a truncated tag, an over-long
        // one that starts with the real tag, and the empty string.
        let mut long = seg.tag.to_vec();
        long.push(0);
        for wrong_length in [
            BASE64.encode(&seg.tag[..15]),
            BASE64.encode(&long),
            String::new(),
        ] {
            let mut dest = vec![0xAAu8; plaintext.len()];
            let err = enc
                .decrypt_segment_into_verified(&seg.bytes, &mut dest, &wrong_length)
                .unwrap_err();
            assert!(
                matches!(err, EncryptionError::SegmentHashMismatch),
                "{wrong_length:?}: {err:?}"
            );
            assert!(dest.iter().all(|b| *b == 0), "dest must be zeroized");
        }
    }

    /// The GCM check still comes first: a tampered member fails as an AEAD
    /// error even when the expected hash is the tampered member's own tag.
    #[test]
    fn decrypt_segment_into_verified_keeps_the_gcm_check() {
        let enc = TdfEncryption::new().unwrap();
        let seg = enc.encrypt_segment(&[0x44u8; 32]).unwrap();
        let hash = BASE64.encode(seg.tag);

        let mut tampered = seg.bytes.clone();
        tampered[12] ^= 0x01;
        let mut dest = vec![0xAAu8; 32];
        let err = enc
            .decrypt_segment_into_verified(&tampered, &mut dest, &hash)
            .unwrap_err();
        assert!(matches!(err, EncryptionError::AeadError(_)), "{err:?}");
        assert!(dest.iter().all(|b| *b == 0));

        // Length errors are reported as for `decrypt_segment_into`.
        let mut wrong = vec![0u8; 31];
        let err = enc
            .decrypt_segment_into_verified(&seg.bytes, &mut wrong, &hash)
            .unwrap_err();
        assert!(matches!(err, EncryptionError::SegmentError(_)), "{err:?}");
    }

    #[test]
    fn segment_tag_matches_encrypt_with_segments_gmac() {
        // The single-segment API must produce the same member layout the
        // existing streaming API produces, so manifests stay interchangeable.
        let enc = TdfEncryption::new().unwrap();
        let data = vec![3u8; 64];
        let streamed = enc.encrypt_with_segments(&data, 64).unwrap();
        let single = enc.encrypt_segment(&data).unwrap();

        assert_eq!(streamed.segments[0].len(), single.bytes.len());
        assert_eq!(
            streamed.segment_info[0].encrypted_size,
            single.bytes.len() as u64
        );
        assert_eq!(streamed.gmac_tags[0].len(), single.tag.len());
    }
}
