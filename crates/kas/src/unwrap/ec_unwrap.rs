//! EC (NanoTDF) unwrap operations
//!
//! Provides ECDH key agreement and NanoTDF-compatible rewrap.

use crate::error::KasServerError;
use crate::rewrap::{encode_wrapped_key, rewrap_dek};
use crate::salt::{NanoTdfVersion, compute_nanotdf_salt, detect_nanotdf_version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use opentdf_protocol::binary::{BinaryRead, BinaryWrite};
use opentdf_protocol::nanotdf::{EccMode, Header, PolicyBody};
use p256::elliptic_curve::point::AffineCoordinates;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use std::io::Cursor;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Performs ECDH key agreement and returns x-coordinate as shared secret
///
/// This matches the behavior of OpenTDFKit's custom_ecdh implementation.
/// The x-coordinate is used as the raw shared secret for HKDF derivation.
pub fn custom_ecdh(
    private_key: &SecretKey,
    public_key: &PublicKey,
) -> Result<Vec<u8>, KasServerError> {
    let scalar = private_key.to_nonzero_scalar();
    let public_key_point = public_key.to_projective();
    let shared_point = (public_key_point * *scalar).to_affine();
    let x_coordinate = shared_point.x();
    Ok(x_coordinate.to_vec())
}

/// Full EC unwrap flow for NanoTDF with header validation and policy binding verification.
///
/// Parses the complete NanoTDF header, verifies that it uses P-256, verifies the
/// keyed HMAC-SHA256 policy binding against the derived DEK in constant time, and
/// rewraps the DEK for the client session.
pub fn ec_unwrap_with_policy_binding(
    header_bytes: &[u8],
    kas_private_key: &SecretKey,
    session_shared_secret: &[u8],
) -> Result<String, KasServerError> {
    let version = detect_nanotdf_version(header_bytes).ok_or_else(|| {
        KasServerError::InvalidHeader("unrecognized or truncated NanoTDF magic/version".to_string())
    })?;

    let mut cursor = Cursor::new(header_bytes);
    let header = Header::read_from(&mut cursor).map_err(|e| {
        KasServerError::InvalidHeader(format!("failed to parse NanoTDF header: {e}"))
    })?;

    if header.ecc_and_binding_mode.ecc_mode != EccMode::Secp256r1 {
        return Err(KasServerError::InvalidHeader(format!(
            "unsupported NanoTDF ECC curve {:?} (only P-256 is supported)",
            header.ecc_and_binding_mode.ecc_mode
        )));
    }
    if header.ecc_and_binding_mode.use_ecdsa_binding {
        return Err(KasServerError::PolicyBindingFailed(
            "ECDSA policy binding verification is not supported".to_string(),
        ));
    }

    let ephemeral_public_key = PublicKey::from_sec1_bytes(&header.ephemeral_public_key)
        .map_err(|e| KasServerError::InvalidPublicKey(e.to_string()))?;

    let dek_shared_secret = Zeroizing::new(custom_ecdh(kas_private_key, &ephemeral_public_key)?);
    let dek_salt = compute_nanotdf_salt(version);
    let session_salt = compute_nanotdf_salt(NanoTdfVersion::V12);

    // Derive DEK to verify the keyed policy binding before rewrapping
    let mut dek = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&dek_salt), &dek_shared_secret).expand(b"", dek.as_mut())?;

    let policy_bytes = match &header.policy.body {
        PolicyBody::Remote(locator) => {
            let mut buf = Vec::new();
            locator.write_to(&mut buf).map_err(|e| {
                KasServerError::InvalidHeader(format!("failed to serialize policy locator: {e}"))
            })?;
            buf
        }
        PolicyBody::EmbeddedPlaintext(content)
        | PolicyBody::EmbeddedEncrypted(content)
        | PolicyBody::EmbeddedEncryptedWithKeyAccess { content, .. } => content.clone(),
    };

    let digest = Sha256::digest(&policy_bytes);
    let reference = &digest[24..];

    let mut mac = Hmac::<Sha256>::new_from_slice(dek.as_ref())
        .map_err(|e| KasServerError::PolicyBindingFailed(format!("invalid HMAC key: {e}")))?;
    mac.update(&policy_bytes);
    let computed = mac.finalize().into_bytes();
    let keyed = &computed[24..];

    let b = header.policy.binding.as_slice();
    if b.len() != 8 || !(bool::from(b.ct_eq(keyed)) | bool::from(b.ct_eq(reference))) {
        return Err(KasServerError::PolicyBindingFailed(
            "NanoTDF policy binding mismatch".to_string(),
        ));
    }

    let (nonce, wrapped_dek) = rewrap_dek(
        &dek_shared_secret,
        session_shared_secret,
        &dek_salt,
        &session_salt,
        b"",
    )?;

    Ok(encode_wrapped_key(&nonce, &wrapped_dek))
}

/// Full EC unwrap flow for NanoTDF
///
/// Performs ECDH between KAS private key and TDF ephemeral public key,
/// then rewraps the derived DEK for the client session.
///
/// Prefer [`ec_unwrap_with_policy_binding`] in production KAS servers to verify
/// the NanoTDF policy binding before releasing the DEK.
pub fn ec_unwrap(
    header_bytes: &[u8],
    ephemeral_public_key_bytes: &[u8],
    kas_private_key: &SecretKey,
    session_shared_secret: &[u8],
) -> Result<String, KasServerError> {
    // Validate ephemeral key size (compressed P-256 = 33 bytes)
    if ephemeral_public_key_bytes.len() != 33 {
        return Err(KasServerError::InvalidKeySize {
            expected: 33,
            got: ephemeral_public_key_bytes.len(),
        });
    }

    // Require a recognized NanoTDF magic/version — never silently fall back to V12
    let version = detect_nanotdf_version(header_bytes).ok_or_else(|| {
        KasServerError::InvalidHeader("unrecognized or truncated NanoTDF magic/version".to_string())
    })?;

    // If a complete header was supplied, verify curve & ephemeral key consistency
    let mut cursor = Cursor::new(header_bytes);
    if let Ok(header) = Header::read_from(&mut cursor) {
        if header.ecc_and_binding_mode.ecc_mode != EccMode::Secp256r1 {
            return Err(KasServerError::InvalidHeader(format!(
                "unsupported NanoTDF ECC curve {:?} (only P-256 is supported)",
                header.ecc_and_binding_mode.ecc_mode
            )));
        }
        if header.ephemeral_public_key.as_slice() != ephemeral_public_key_bytes {
            return Err(KasServerError::InvalidHeader(
                "ephemeral public key does not match NanoTDF header".to_string(),
            ));
        }
    }

    // Parse ephemeral public key
    let ephemeral_public_key = PublicKey::from_sec1_bytes(ephemeral_public_key_bytes)
        .map_err(|e| KasServerError::InvalidPublicKey(e.to_string()))?;

    // Perform ECDH to get DEK shared secret (zeroized on drop)
    let dek_shared_secret = Zeroizing::new(custom_ecdh(kas_private_key, &ephemeral_public_key)?);

    // Compute DEK salt for the detected version
    let dek_salt = compute_nanotdf_salt(version);

    // Session salt is always v1.2 — the session key exchange is a transport-layer
    // concern, not a TDF-format concern. The Go reference KAS and all SDK clients
    // (including OpenTDFKit) hardcode v1.2 salt for session key derivation.
    let session_salt = compute_nanotdf_salt(NanoTdfVersion::V12);

    // Rewrap DEK using NanoTDF-compatible HKDF (empty info per spec)
    let (nonce, wrapped_dek) = rewrap_dek(
        &dek_shared_secret,
        session_shared_secret,
        &dek_salt,
        &session_salt,
        b"", // Empty info per NanoTDF spec
    )?;

    // Encode as base64 (nonce + wrapped_dek)
    Ok(encode_wrapped_key(&nonce, &wrapped_dek))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdh::EphemeralSecret;
    use p256::elliptic_curve::Generate;
    use p256::elliptic_curve::sec1::ToSec1Point;

    #[test]
    fn test_custom_ecdh() {
        // Generate two keypairs
        let private1 = SecretKey::generate();
        let public1 = private1.public_key();

        let private2 = SecretKey::generate();
        let public2 = private2.public_key();

        // ECDH should produce same shared secret both ways
        let shared1 = custom_ecdh(&private1, &public2).unwrap();
        let shared2 = custom_ecdh(&private2, &public1).unwrap();

        assert_eq!(shared1, shared2);
        assert_eq!(shared1.len(), 32); // P-256 x-coordinate is 32 bytes
    }

    #[test]
    fn test_ec_unwrap() {
        // Generate KAS keypair
        let kas_private = SecretKey::generate();

        // Generate ephemeral keypair (simulating TDF client)
        let ephemeral = EphemeralSecret::generate();
        let ephemeral_public = PublicKey::from(&ephemeral);
        let ephemeral_public_bytes = ephemeral_public.to_sec1_point(true);

        // Generate session shared secret (simulating client-KAS session)
        let session_secret = b"test_session_shared_secret__32b!";

        // Create NanoTDF v1.2 header
        let header = b"L1L\x00\x00"; // Minimal header with v1.2 magic

        // Perform EC unwrap
        let result = ec_unwrap(
            header,
            ephemeral_public_bytes.as_bytes(),
            &kas_private,
            session_secret,
        );

        assert!(result.is_ok());
        let encoded = result.unwrap();
        assert!(!encoded.is_empty());

        // Decode and verify structure
        use base64::{Engine, engine::general_purpose::STANDARD};
        let decoded = STANDARD.decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 60); // 12 (nonce) + 32 (DEK) + 16 (tag)
    }

    #[test]
    fn test_ec_unwrap_invalid_key_size() {
        let kas_private = SecretKey::generate();
        let session_secret = b"test_session_shared_secret__32b!";
        let header = b"L1L\x00\x00";

        // Wrong key size (32 instead of 33)
        let bad_key = [0u8; 32];
        let result = ec_unwrap(header, &bad_key, &kas_private, session_secret);

        assert!(matches!(result, Err(KasServerError::InvalidKeySize { .. })));
    }

    #[test]
    fn test_ec_unwrap_rejects_unknown_header_and_bad_policy_binding() {
        use opentdf_protocol::nanotdf::{
            EccAndBindingMode, MagicNumberAndVersion, PayloadSignatureMode, Policy, Protocol,
            ResourceLocator, SymmetricAndPayloadConfig, SymmetricCipher,
        };

        let kas_private = SecretKey::generate();
        let kas_public = kas_private.public_key();
        let ephemeral_private = SecretKey::generate();
        let ephemeral_public = ephemeral_private.public_key();
        let ephemeral_bytes = ephemeral_public.to_sec1_point(true);
        let session_secret = b"test_session_shared_secret__32b!";

        // Unknown header magic must be rejected (no silent V12 fallback)
        let err = ec_unwrap(
            b"BAD\x00\x00",
            ephemeral_bytes.as_bytes(),
            &kas_private,
            session_secret,
        )
        .unwrap_err();
        assert!(matches!(err, KasServerError::InvalidHeader(_)));

        // Build a valid V12 header with OpenTDF reference SHA-256 policy binding
        let shared = custom_ecdh(&ephemeral_private, &kas_public).unwrap();
        let dek_salt = compute_nanotdf_salt(NanoTdfVersion::V12);
        let mut dek = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&dek_salt), &shared)
            .expand(b"", &mut dek)
            .unwrap();
        let policy_content = b"policy-bytes".to_vec();
        let ref_binding = Sha256::digest(&policy_content)[24..32].to_vec();

        let mut header = Header {
            magic_number_and_version: MagicNumberAndVersion::new(),
            kas: ResourceLocator::new(Protocol::Https, b"kas.example.com".to_vec()),
            ecc_and_binding_mode: EccAndBindingMode {
                use_ecdsa_binding: false,
                ecc_mode: EccMode::Secp256r1,
            },
            symmetric_and_payload_config: SymmetricAndPayloadConfig::new(
                PayloadSignatureMode::none(),
                SymmetricCipher::Aes256Gcm128,
            ),
            policy: Policy {
                body: PolicyBody::EmbeddedPlaintext(policy_content.clone()),
                binding: ref_binding,
            },
            ephemeral_public_key: ephemeral_bytes.as_bytes().to_vec(),
        };

        let mut ref_bytes = Vec::new();
        header.write_to(&mut ref_bytes).unwrap();
        assert!(ec_unwrap_with_policy_binding(&ref_bytes, &kas_private, session_secret).is_ok());

        // Keyed HMAC-SHA256 binding is also accepted
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&dek).unwrap();
        mac.update(&policy_content);
        header.policy.binding = mac.finalize().into_bytes()[24..32].to_vec();
        let mut keyed_bytes = Vec::new();
        header.write_to(&mut keyed_bytes).unwrap();
        assert!(ec_unwrap_with_policy_binding(&keyed_bytes, &kas_private, session_secret).is_ok());

        // Tamper policy content without recomputing binding -> PolicyBindingFailed
        header.policy.body = PolicyBody::EmbeddedPlaintext(b"tampered-policy".to_vec());
        let mut tampered_bytes = Vec::new();
        header.write_to(&mut tampered_bytes).unwrap();
        let tampered_err =
            ec_unwrap_with_policy_binding(&tampered_bytes, &kas_private, session_secret)
                .unwrap_err();
        assert!(matches!(
            tampered_err,
            KasServerError::PolicyBindingFailed(_)
        ));
    }
}
