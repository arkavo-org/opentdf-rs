use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
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
    pub fn with_policy_key(policy_key: Vec<u8>) -> Result<Self, EncryptionError> {
        if policy_key.len() != 32 {
            return Err(EncryptionError::InvalidKeyLength);
        }

        let mut payload_key = vec![0u8; 32];
        OsRng.fill_bytes(&mut payload_key);

        Ok(Self {
            policy_key,
            payload_key,
        })
    }

    /// Encrypt data using the payload key and then encrypt the payload key using the policy key
    pub fn encrypt(&self, data: &[u8]) -> Result<EncryptedPayload, EncryptionError> {
        // Generate random IV for payload encryption
        let mut payload_iv = vec![0u8; 12]; // 96-bit IV for AES-GCM
        OsRng.fill_bytes(&mut payload_iv);

        // Encrypt the actual data using the payload key
        let payload_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.payload_key));
        let nonce = Nonce::from_slice(&payload_iv);
        let ciphertext = payload_cipher
            .encrypt(nonce, data)
            .map_err(EncryptionError::AeadError)?;

        // Generate random IV for key encryption
        let mut key_iv = vec![0u8; 12];
        OsRng.fill_bytes(&mut key_iv);

        // Encrypt the payload key using the policy key
        let policy_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.policy_key));
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
        let policy_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(policy_key));
        let key_nonce = Nonce::from_slice(key_iv);
        let payload_key = policy_cipher
            .decrypt(key_nonce, encrypted_key.as_ref())
            .map_err(EncryptionError::AeadError)?;

        // Then decrypt the actual data using the decrypted payload key
        let payload_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&payload_key));
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

        // Decrypt
        let decrypted = TdfEncryption::decrypt(tdf.policy_key(), &encrypted)?;

        assert_eq!(data, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_with_existing_policy_key() -> Result<(), EncryptionError> {
        // Create a policy key
        let mut policy_key = vec![0u8; 32];
        OsRng.fill_bytes(&mut policy_key);

        // Create encryption instance with existing policy key
        let tdf = TdfEncryption::with_policy_key(policy_key.clone())?;

        // Test data
        let data = b"Test with existing policy key";

        // Encrypt
        let encrypted = tdf.encrypt(data)?;

        // Decrypt
        let decrypted = TdfEncryption::decrypt(&policy_key, &encrypted)?;

        assert_eq!(data, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_invalid_policy_key_length() {
        // Try to create with invalid key length
        let result = TdfEncryption::with_policy_key(vec![0u8; 16]);
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
}
