//! RSA-OAEP Key Encapsulation Mechanism
//!
//! This module implements RSA-OAEP key wrapping for OpenTDF.
//! SHA-1 is used by default for compatibility with the OpenTDF Go SDK,
//! but SHA-256 is also supported and recommended for new deployments.

use super::{KemError, KeyEncapsulation};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::rngs::OsRng;
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use sha1::Sha1;
use sha2::Sha256;

/// OAEP hash algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OaepHash {
    /// SHA-1 (default for OpenTDF Go SDK compatibility)
    ///
    /// Note: SHA-1 is cryptographically weak but required for interoperability
    /// with existing OpenTDF implementations. Use SHA-256 for new deployments.
    #[default]
    Sha1,

    /// SHA-256 (recommended for new deployments)
    Sha256,
}

/// RSA-OAEP key encapsulation mechanism
pub struct RsaOaepKem {
    /// Hash algorithm for OAEP padding
    pub hash: OaepHash,
}

impl Default for RsaOaepKem {
    fn default() -> Self {
        RsaOaepKem {
            hash: OaepHash::Sha1, // Default to SHA-1 for Go SDK compatibility
        }
    }
}

impl RsaOaepKem {
    /// Create a new RSA-OAEP KEM with the specified hash algorithm
    pub fn new(hash: OaepHash) -> Self {
        RsaOaepKem { hash }
    }

    /// Create with SHA-1 (default, for OpenTDF compatibility)
    pub fn with_sha1() -> Self {
        RsaOaepKem {
            hash: OaepHash::Sha1,
        }
    }

    /// Create with SHA-256 (recommended)
    pub fn with_sha256() -> Self {
        RsaOaepKem {
            hash: OaepHash::Sha256,
        }
    }
}

impl KeyEncapsulation for RsaOaepKem {
    type PublicKey = String; // PEM-encoded public key
    type PrivateKey = String; // PEM-encoded private key
    type WrappedKey = String; // Base64-encoded ciphertext

    fn wrap(&self, key: &[u8], public_key_pem: &Self::PublicKey) -> Result<String, KemError> {
        // Parse PEM-encoded public key
        let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
            .map_err(|e| KemError::InvalidKey(format!("Failed to parse RSA public key: {}", e)))?;

        // Encrypt with OAEP padding using the selected hash
        let wrapped = match self.hash {
            OaepHash::Sha1 => {
                let padding = Oaep::new::<Sha1>();
                public_key.encrypt(&mut OsRng, padding, key).map_err(|e| {
                    KemError::WrapError(format!("RSA-OAEP encryption failed: {}", e))
                })?
            }
            OaepHash::Sha256 => {
                let padding = Oaep::new::<Sha256>();
                public_key.encrypt(&mut OsRng, padding, key).map_err(|e| {
                    KemError::WrapError(format!("RSA-OAEP encryption failed: {}", e))
                })?
            }
        };

        // Base64 encode for storage in manifest
        Ok(BASE64.encode(&wrapped))
    }

    fn unwrap(
        &self,
        wrapped_b64: &Self::WrappedKey,
        private_key_pem: &Self::PrivateKey,
    ) -> Result<Vec<u8>, KemError> {
        // Decode base64 wrapped key
        let wrapped = BASE64
            .decode(wrapped_b64)
            .map_err(|e| KemError::EncodingError(format!("Base64 decode failed: {}", e)))?;

        // Parse PEM-encoded private key
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
            .map_err(|e| KemError::InvalidKey(format!("Failed to parse RSA private key: {}", e)))?;

        // Decrypt with OAEP padding using the selected hash
        let key = match self.hash {
            OaepHash::Sha1 => {
                let padding = Oaep::new::<Sha1>();
                private_key.decrypt(padding, &wrapped).map_err(|e| {
                    KemError::UnwrapError(format!("RSA-OAEP decryption failed: {}", e))
                })?
            }
            OaepHash::Sha256 => {
                let padding = Oaep::new::<Sha256>();
                private_key.decrypt(padding, &wrapped).map_err(|e| {
                    KemError::UnwrapError(format!("RSA-OAEP decryption failed: {}", e))
                })?
            }
        };

        Ok(key)
    }
}

/// Convenience function to wrap a key with RSA-OAEP (SHA-1 default)
///
/// This function wraps a symmetric payload key with an RSA public key using OAEP padding.
/// It uses SHA-1 by default for compatibility with the OpenTDF Go SDK.
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
/// use opentdf_crypto::kem::rsa::wrap_key_with_rsa_oaep;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let payload_key = &[0u8; 32]; // Your AES-256 key
/// let kas_public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----";
///
/// let wrapped_key = wrap_key_with_rsa_oaep(payload_key, kas_public_key_pem)?;
/// # Ok(())
/// # }
/// ```
pub fn wrap_key_with_rsa_oaep(
    payload_key: &[u8],
    kas_public_key_pem: &str,
) -> Result<String, KemError> {
    let kem = RsaOaepKem::default();
    kem.wrap(payload_key, &kas_public_key_pem.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::EncodePublicKey;

    fn generate_test_keypair() -> (String, String) {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let private_pem = private_key.to_pkcs8_pem(pkcs8::LineEnding::LF).unwrap();
        let public_pem = public_key.to_public_key_pem(pkcs8::LineEnding::LF).unwrap();

        (public_pem, private_pem.to_string())
    }

    #[test]
    fn test_rsa_oaep_roundtrip_sha1() {
        let (public_pem, private_pem) = generate_test_keypair();
        let kem = RsaOaepKem::with_sha1();

        let key = b"test_payload_key_32_bytes_long!";
        let wrapped = kem.wrap(key, &public_pem).unwrap();
        let unwrapped = kem.unwrap(&wrapped, &private_pem).unwrap();

        assert_eq!(key, unwrapped.as_slice());
    }

    #[test]
    fn test_rsa_oaep_roundtrip_sha256() {
        let (public_pem, private_pem) = generate_test_keypair();
        let kem = RsaOaepKem::with_sha256();

        let key = b"test_payload_key_32_bytes_long!";
        let wrapped = kem.wrap(key, &public_pem).unwrap();
        let unwrapped = kem.unwrap(&wrapped, &private_pem).unwrap();

        assert_eq!(key, unwrapped.as_slice());
    }

    #[test]
    fn test_convenience_function() {
        let (public_pem, _private_pem) = generate_test_keypair();
        let key = b"test_payload_key_32_bytes_long!";

        let wrapped = wrap_key_with_rsa_oaep(key, &public_pem).unwrap();
        assert!(!wrapped.is_empty());
        // Should be base64 encoded
        assert!(BASE64.decode(&wrapped).is_ok());
    }
}
