//! Rewrap operations for KAS server
//!
//! Provides HKDF key derivation and AES-GCM encryption for rewrapping DEKs.

use crate::error::KasServerError;
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// NanoTDF-compatible rewrap operation
///
/// Derives the actual DEK from ECDH shared secret, then wraps it for transport.
///
/// The DEK salt and session salt are separate because they serve different purposes:
/// - `dek_salt`: Version-dependent salt for deriving the DEK (matches NanoTDF header version)
/// - `session_salt`: Always v1.2 salt (SHA256("L1L")) for the session key, since the session
///   key exchange is a transport-layer concern independent of the NanoTDF format version.
///   The Go reference KAS and all SDK clients hardcode v1.2 for session key derivation.
///
/// # Steps
/// 1. Derive DEK from dek_shared_secret using HKDF with dek_salt
/// 2. Derive wrapping key from session_shared_secret using HKDF with session_salt
/// 3. Encrypt derived DEK with AES-256-GCM using wrapping key
pub fn rewrap_dek(
    dek_shared_secret: &[u8],
    session_shared_secret: &[u8],
    dek_salt: &[u8],
    session_salt: &[u8],
    info: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), KasServerError> {
    if dek_shared_secret.is_empty() {
        return Err(KasServerError::EcdhError(
            "DEK shared secret must not be empty".to_string(),
        ));
    }
    if session_shared_secret.is_empty() {
        return Err(KasServerError::EcdhError(
            "session shared secret must not be empty".to_string(),
        ));
    }

    // Derive the actual DEK from the TDF ECDH shared secret
    let dek_hkdf = Hkdf::<Sha256>::new(Some(dek_salt), dek_shared_secret);
    let mut dek = Zeroizing::new([0u8; 32]);
    dek_hkdf.expand(info, dek.as_mut())?;

    // Derive the wrapping key from the session shared secret (always v1.2 salt)
    let session_hkdf = Hkdf::<Sha256>::new(Some(session_salt), session_shared_secret);
    let mut wrapping_key = Zeroizing::new([0u8; 32]);
    session_hkdf.expand(info, wrapping_key.as_mut())?;

    // Generate random nonce (12 bytes for AES-GCM)
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce_ga = GenericArray::from_slice(&nonce);

    // Wrap the derived DEK with AES-256-GCM (avoid copying key out of Zeroizing)
    let cipher = Aes256Gcm::new_from_slice(wrapping_key.as_ref())
        .map_err(|_| KasServerError::AesGcmError("invalid AES-256 wrapping key".to_string()))?;
    let wrapped_dek = cipher.encrypt(nonce_ga, &dek[..])?;

    Ok((nonce.to_vec(), wrapped_dek))
}

/// Simple rewrap for RSA-unwrapped DEKs
///
/// Encrypts the DEK directly with session shared secret using HKDF-SHA256
/// with salt = `SHA256("TDF")` (matching OpenTDF platform `security.TDFSalt()`
/// and `opentdf::KasClient::unwrap_key`) + AES-256-GCM.
pub fn rewrap_dek_simple(
    dek: &[u8],
    session_shared_secret: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), KasServerError> {
    if dek.len() != 16 && dek.len() != 32 {
        return Err(KasServerError::InvalidKeySize {
            expected: 32,
            got: dek.len(),
        });
    }
    if session_shared_secret.is_empty() {
        return Err(KasServerError::EcdhError(
            "session shared secret must not be empty".to_string(),
        ));
    }

    // Derive symmetric key using HKDF-SHA256 with salt = SHA256("TDF"), empty info
    let salt = Sha256::digest(b"TDF");
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), session_shared_secret);
    let mut derived_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"", derived_key.as_mut())?;

    // Generate random nonce (12 bytes for AES-GCM)
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce_ga = GenericArray::from_slice(&nonce);

    // Encrypt DEK with AES-256-GCM (avoid copying key out of Zeroizing)
    let cipher = Aes256Gcm::new_from_slice(derived_key.as_ref())
        .map_err(|_| KasServerError::AesGcmError("invalid AES-256 derived key".to_string()))?;
    let wrapped_dek = cipher.encrypt(nonce_ga, dek)?;

    Ok((nonce.to_vec(), wrapped_dek))
}

/// Combine nonce and wrapped DEK into a single base64-encoded string
pub fn encode_wrapped_key(nonce: &[u8], wrapped_dek: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut combined = Vec::with_capacity(nonce.len() + wrapped_dek.len());
    combined.extend_from_slice(nonce);
    combined.extend_from_slice(wrapped_dek);
    STANDARD.encode(&combined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::salt::{NanoTdfVersion, compute_nanotdf_salt};

    #[test]
    fn test_rewrap_dek() {
        let dek_secret = b"test_dek_shared_secret__32bytes!";
        let session_secret = b"test_session_shared_secret__32b!";
        let dek_salt = compute_nanotdf_salt(NanoTdfVersion::V12);
        let session_salt = compute_nanotdf_salt(NanoTdfVersion::V12);

        let result = rewrap_dek(dek_secret, session_secret, &dek_salt, &session_salt, b"");
        assert!(result.is_ok());

        let (nonce, wrapped) = result.unwrap();
        assert_eq!(nonce.len(), 12);
        // Wrapped should be 32-byte DEK + 16-byte tag = 48 bytes
        assert_eq!(wrapped.len(), 48);
    }

    #[test]
    fn test_rewrap_dek_split_salts() {
        let dek_secret = b"test_dek_shared_secret__32bytes!";
        let session_secret = b"test_session_shared_secret__32b!";
        // DEK uses v1.3 salt, session always uses v1.2 (matches Go reference KAS)
        let dek_salt = compute_nanotdf_salt(NanoTdfVersion::V13);
        let session_salt = compute_nanotdf_salt(NanoTdfVersion::V12);

        let result = rewrap_dek(dek_secret, session_secret, &dek_salt, &session_salt, b"");
        assert!(result.is_ok());

        let (nonce, wrapped) = result.unwrap();
        assert_eq!(nonce.len(), 12);
        assert_eq!(wrapped.len(), 48);
    }

    #[test]
    fn test_rewrap_dek_simple() {
        let dek = b"test_data_encryption_key_32bytes";
        let session_secret = b"test_session_shared_secret__32b!";

        let result = rewrap_dek_simple(dek, session_secret);
        assert!(result.is_ok());

        let (nonce, wrapped) = result.unwrap();
        assert_eq!(nonce.len(), 12);
        // Wrapped should be ciphertext + 16-byte auth tag
        assert_eq!(wrapped.len(), dek.len() + 16);
    }

    #[test]
    fn test_encode_wrapped_key() {
        let nonce = vec![0u8; 12];
        let wrapped = vec![1u8; 48];

        let encoded = encode_wrapped_key(&nonce, &wrapped);
        assert!(!encoded.is_empty());

        // Decode and verify
        use base64::{Engine, engine::general_purpose::STANDARD};
        let decoded = STANDARD.decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 60); // 12 + 48
    }

    #[test]
    fn test_rewrap_rejects_empty_shared_secret() {
        let dek_salt = compute_nanotdf_salt(NanoTdfVersion::V12);
        assert!(rewrap_dek(&[], b"session", &dek_salt, &dek_salt, b"").is_err());
        assert!(rewrap_dek(b"dek", &[], &dek_salt, &dek_salt, b"").is_err());
        assert!(rewrap_dek_simple(b"dek-32-bytes-0000000000000000000", &[]).is_err());
        // Invalid DEK lengths (0 bytes, 8 bytes) must be rejected; 16-byte AES-128 accepted
        assert!(rewrap_dek_simple(&[], b"session_secret").is_err());
        assert!(rewrap_dek_simple(&[0u8; 8], b"session_secret").is_err());
        assert!(rewrap_dek_simple(&[0u8; 16], b"session_secret").is_ok());
    }
}
