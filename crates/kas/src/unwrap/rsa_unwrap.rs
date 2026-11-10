//! RSA (Standard TDF) unwrap operations
//!
//! Provides RSA-OAEP decryption for Standard TDF wrapped keys.
//!
//! # SHA-1 Usage in RSA-OAEP
//!
//! This module uses SHA-1 as the hash function for RSA-OAEP padding. This is
//! intentional for compatibility with the OpenTDF specification and existing
//! TDF files created by other OpenTDF implementations.
//!
//! **Security Note**: SHA-1's collision vulnerabilities do not affect OAEP
//! security. OAEP requires only preimage resistance, which SHA-1 still
//! provides. The use of SHA-1 here is safe and follows the OpenTDF spec.

use crate::error::KasServerError;
use crate::rewrap::{encode_wrapped_key, rewrap_dek_simple};
use rsa::PrivateKey;
use sha1::Sha1;

/// Full RSA unwrap flow for Standard TDF
///
/// Decrypts RSA-OAEP wrapped DEK and rewraps for client session.
///
/// # Arguments
/// * `wrapped_key_bytes` - RSA-OAEP encrypted DEK (256 bytes for RSA-2048)
/// * `rsa_private_key` - KAS RSA private key
/// * `session_shared_secret` - ECDH shared secret with client
pub fn rsa_unwrap(
    wrapped_key_bytes: &[u8],
    rsa_private_key: &PrivateKey,
    session_shared_secret: &[u8],
) -> Result<String, KasServerError> {
    // Validate wrapped key size (RSA-2048 produces 256-byte ciphertext)
    if wrapped_key_bytes.len() != 256 {
        return Err(KasServerError::InvalidKeySize {
            expected: 256,
            got: wrapped_key_bytes.len(),
        });
    }

    // Unwrap DEK using RSA-OAEP with SHA-1 for the label hash and MGF1 (OpenTDF
    // compatibility). The private-key operation is blinded with the system RNG.
    let dek = rsa_private_key
        .oaep_decrypt::<Sha1>(wrapped_key_bytes)
        .map_err(|e| KasServerError::RsaError(e.to_string()))?;

    // Re-wrap DEK with session shared secret
    let (nonce, wrapped_dek) = rewrap_dek_simple(&dek, session_shared_secret)?;

    // Encode as base64 (nonce + wrapped_dek)
    Ok(encode_wrapped_key(&nonce, &wrapped_dek))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key};
    use hkdf::Hkdf;
    use sha2::Sha256;

    const DEK: &[u8; 32] = b"test_data_encryption_key_32byte!";
    const SESSION_SECRET: &[u8; 32] = b"test_session_shared_secret__32b!";

    fn generate_key() -> PrivateKey {
        PrivateKey::new(&mut getrandom::SysRng, 2048).unwrap()
    }

    /// Reverse `rewrap_dek_simple`: what a client does with the rewrapped key
    fn open_rewrapped(encoded: &str, session_shared_secret: &[u8]) -> Vec<u8> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let decoded = STANDARD.decode(encoded).unwrap();
        // 12 (nonce) + 32 (DEK) + 16 (tag) = 60 bytes
        assert_eq!(decoded.len(), 60);
        let (nonce, wrapped_dek) = decoded.split_at(12);

        let mut derived_key = [0u8; 32];
        Hkdf::<Sha256>::new(None, session_shared_secret)
            .expand(b"", &mut derived_key)
            .unwrap();
        Aes256Gcm::new(&Key::<Aes256Gcm>::from(derived_key))
            .decrypt(GenericArray::from_slice(nonce), wrapped_dek)
            .unwrap()
    }

    #[test]
    fn test_rsa_unwrap() {
        let rsa_private = generate_key();

        // Wrap a test DEK the way a client does
        let wrapped = rsa_private
            .as_public_key()
            .oaep_encrypt::<Sha1>(DEK)
            .unwrap();

        let encoded = rsa_unwrap(&wrapped, &rsa_private, SESSION_SECRET).unwrap();

        assert_eq!(open_rewrapped(&encoded, SESSION_SECRET), DEK);
    }

    #[test]
    fn test_rsa_unwrap_invalid_key_size() {
        let rsa_private = generate_key();

        // Wrong size (128 instead of 256)
        let bad_wrapped = [0u8; 128];
        let result = rsa_unwrap(&bad_wrapped, &rsa_private, SESSION_SECRET);

        assert!(matches!(result, Err(KasServerError::InvalidKeySize { .. })));
    }

    #[test]
    fn test_rsa_unwrap_rejects_other_oaep_hash() {
        let rsa_private = generate_key();

        // OAEP with SHA-256 is not what `rsa_unwrap` takes
        let wrapped = rsa_private
            .as_public_key()
            .oaep_encrypt::<rsa::sha2::Sha256>(DEK)
            .unwrap();

        let result = rsa_unwrap(&wrapped, &rsa_private, SESSION_SECRET);
        assert!(matches!(result, Err(KasServerError::RsaError(_))));
    }

    /// A DEK wrapped by aws-lc-rs, the default client backend, unwraps here: once to a
    /// key this crate generated and published as PEM, and once to a key aws-lc-rs
    /// generated and this crate imported from PKCS#8.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_rsa_unwrap_of_aws_lc_wrapped_key() {
        use crate::keypair::KasRsaKeypair;
        use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
        use aws_lc_rs::rsa::{
            KeySize, OAEP_SHA1_MGF1SHA1, OaepPublicEncryptingKey, PrivateDecryptingKey,
            PublicEncryptingKey,
        };

        fn aws_lc_wrap(public_key_pem: &str) -> Vec<u8> {
            let spki = pem::parse(public_key_pem).unwrap();
            let public_key = PublicEncryptingKey::from_der(spki.contents()).unwrap();
            let oaep_key = OaepPublicEncryptingKey::new(public_key).unwrap();
            let mut ciphertext = vec![0u8; oaep_key.ciphertext_size()];
            let len = oaep_key
                .encrypt(&OAEP_SHA1_MGF1SHA1, DEK, &mut ciphertext, None)
                .unwrap()
                .len();
            ciphertext.truncate(len);
            ciphertext
        }

        let generated_here = KasRsaKeypair::generate().unwrap();

        let aws_lc_key = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        let pkcs8 = AsDer::<Pkcs8V1Der>::as_der(&aws_lc_key).unwrap();
        let pkcs8_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8.as_ref()));
        let imported = KasRsaKeypair::from_pkcs8_pem(&pkcs8_pem).unwrap();

        for keypair in [generated_here, imported] {
            let wrapped = aws_lc_wrap(keypair.public_key_pem());
            let encoded = rsa_unwrap(&wrapped, keypair.private_key(), SESSION_SECRET).unwrap();
            assert_eq!(open_rewrapped(&encoded, SESSION_SECRET), DEK);
        }
    }
}
