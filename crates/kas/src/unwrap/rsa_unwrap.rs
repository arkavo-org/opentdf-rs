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
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, Mac};
use rsa::{PrivateKey, traits::PublicKeyParts};
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Decode 64 ASCII hex characters into 32 bytes (returns `None` if invalid hex).
fn decode_hex_32(hex_bytes: &[u8]) -> Option<[u8; 32]> {
    if hex_bytes.len() != 64 {
        return None;
    }
    let hex_val = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    };
    let (pairs, _) = hex_bytes.as_chunks::<2>();
    let mut out = [0u8; 32];
    for (i, &[hi_b, lo_b]) in pairs.iter().enumerate() {
        let hi = hex_val(hi_b)?;
        let lo = hex_val(lo_b)?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Verify Standard TDF HMAC-SHA256 policy binding in constant time.
///
/// Accepts both OpenTDF standard formats:
/// - `Base64(raw 32-byte HMAC-SHA256(dek, base64_policy))`
/// - `Base64(hex(HMAC-SHA256(dek, base64_policy)))` (64 ASCII hex bytes, emitted by the OpenTDF Go SDK)
pub fn verify_standard_policy_binding(
    dek: &[u8],
    base64_policy: &str,
    expected_binding_b64: &str,
) -> Result<(), KasServerError> {
    let decoded = BASE64
        .decode(expected_binding_b64)
        .map_err(|e| KasServerError::PolicyBindingFailed(format!("invalid base64 binding: {e}")))?;

    let expected_mac: [u8; 32] = match decoded.len() {
        32 => decoded.as_slice().try_into().expect("checked len == 32"),
        64 => decode_hex_32(&decoded).ok_or_else(|| {
            KasServerError::PolicyBindingFailed("invalid hex policy binding".to_string())
        })?,
        other => {
            return Err(KasServerError::PolicyBindingFailed(format!(
                "invalid policy binding length: {other} bytes (expected 32 raw or 64 hex)"
            )));
        }
    };

    let mut mac = Hmac::<Sha256>::new_from_slice(dek)
        .map_err(|e| KasServerError::PolicyBindingFailed(format!("invalid HMAC key: {e}")))?;
    mac.update(base64_policy.as_bytes());
    let computed = mac.finalize().into_bytes();

    if !bool::from(computed.as_slice().ct_eq(&expected_mac)) {
        return Err(KasServerError::PolicyBindingFailed(
            "policy binding mismatch".to_string(),
        ));
    }
    Ok(())
}

/// Full RSA unwrap flow for Standard TDF with cryptographic policy binding verification.
///
/// Unwraps the RSA-OAEP DEK, verifies `HMAC-SHA256(dek, base64_policy) == policy_binding_b64`
/// in constant time, and rewraps the DEK for the client session.
pub fn rsa_unwrap_with_policy_binding(
    wrapped_key_bytes: &[u8],
    rsa_private_key: &PrivateKey,
    session_shared_secret: &[u8],
    base64_policy: &str,
    policy_binding_b64: &str,
) -> Result<String, KasServerError> {
    let expected_size = rsa_private_key.size();
    if wrapped_key_bytes.len() != expected_size {
        return Err(KasServerError::InvalidKeySize {
            expected: expected_size,
            got: wrapped_key_bytes.len(),
        });
    }

    let dek = Zeroizing::new(
        rsa_private_key
            .oaep_decrypt::<Sha1>(wrapped_key_bytes)
            .map_err(|e| KasServerError::RsaError(e.to_string()))?,
    );

    verify_standard_policy_binding(&dek, base64_policy, policy_binding_b64)?;

    let (nonce, wrapped_dek) = rewrap_dek_simple(&dek, session_shared_secret)?;
    Ok(encode_wrapped_key(&nonce, &wrapped_dek))
}

/// Full RSA unwrap flow for Standard TDF (without policy binding check).
///
/// Prefer [`rsa_unwrap_with_policy_binding`] in production KAS servers to prevent
/// policy-substitution attacks.
pub fn rsa_unwrap(
    wrapped_key_bytes: &[u8],
    rsa_private_key: &PrivateKey,
    session_shared_secret: &[u8],
) -> Result<String, KasServerError> {
    let expected_size = rsa_private_key.size();
    if wrapped_key_bytes.len() != expected_size {
        return Err(KasServerError::InvalidKeySize {
            expected: expected_size,
            got: wrapped_key_bytes.len(),
        });
    }

    // Unwrap DEK using RSA-OAEP with SHA-1 for the label hash and MGF1 (OpenTDF
    // compatibility). The private-key operation is blinded with the system RNG.
    let dek = Zeroizing::new(
        rsa_private_key
            .oaep_decrypt::<Sha1>(wrapped_key_bytes)
            .map_err(|e| KasServerError::RsaError(e.to_string()))?,
    );

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

        use sha2::Digest;
        let salt = Sha256::digest(b"TDF");
        let mut derived_key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&salt), session_shared_secret)
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

    #[test]
    fn test_rsa_unwrap_with_policy_binding() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let rsa_private = generate_key();
        let wrapped = rsa_private
            .as_public_key()
            .oaep_encrypt::<Sha1>(DEK)
            .unwrap();

        let policy_b64 = STANDARD.encode(br#"{"uuid":"test","body":{}}"#);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(DEK).unwrap();
        mac.update(policy_b64.as_bytes());
        let raw_mac = mac.finalize().into_bytes();
        let expected_hash = STANDARD.encode(raw_mac);

        let encoded = rsa_unwrap_with_policy_binding(
            &wrapped,
            &rsa_private,
            SESSION_SECRET,
            &policy_b64,
            &expected_hash,
        )
        .unwrap();
        assert_eq!(open_rewrapped(&encoded, SESSION_SECRET), DEK);

        // Go-SDK format: Base64(hex(HMAC)) (64 ASCII hex bytes)
        let hex_mac: String = raw_mac.iter().map(|b| format!("{b:02x}")).collect();
        let go_sdk_hash = STANDARD.encode(hex_mac.as_bytes());
        let encoded_go = rsa_unwrap_with_policy_binding(
            &wrapped,
            &rsa_private,
            SESSION_SECRET,
            &policy_b64,
            &go_sdk_hash,
        )
        .unwrap();
        assert_eq!(open_rewrapped(&encoded_go, SESSION_SECRET), DEK);

        // Invalid hex of length 64 is rejected
        let bad_hex = STANDARD.encode([b'z'; 64]);
        assert!(matches!(
            verify_standard_policy_binding(DEK, &policy_b64, &bad_hex),
            Err(KasServerError::PolicyBindingFailed(_))
        ));

        let err = rsa_unwrap_with_policy_binding(
            &wrapped,
            &rsa_private,
            SESSION_SECRET,
            &STANDARD.encode(br#"{"uuid":"tampered","body":{}}"#),
            &expected_hash,
        )
        .unwrap_err();
        assert!(matches!(err, KasServerError::PolicyBindingFailed(_)));
    }
}
