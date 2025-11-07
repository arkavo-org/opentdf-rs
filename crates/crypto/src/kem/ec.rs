//! Elliptic Curve Key Encapsulation for NanoTDF
//!
//! This module will implement ECDH-based key wrapping for NanoTDF.
//! Implementation is planned for a future release.

use super::{KemError, KeyEncapsulation};

/// Elliptic curve selection for ECDH
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum EcCurve {
    /// NIST P-256 (secp256r1) - Primary curve for NanoTDF
    P256,
    /// NIST P-384 (secp384r1)
    P384,
    /// NIST P-521 (secp521r1)
    P521,
}

/// ECDH key encapsulation mechanism (NanoTDF)
///
/// This implementation uses ECDH key agreement followed by HKDF key derivation
/// and AES-GCM key wrapping.
///
/// # Protocol Flow
///
/// 1. Generate ephemeral EC key pair
/// 2. Perform ECDH with recipient's public key → shared secret
/// 3. Derive wrapping key using HKDF-SHA256
/// 4. Wrap payload key with AES-256-GCM
/// 5. Return ephemeral public key + wrapped key
pub struct EcdhKem {
    /// Elliptic curve to use
    pub curve: EcCurve,
}

impl Default for EcdhKem {
    fn default() -> Self {
        EcdhKem {
            curve: EcCurve::P256,
        }
    }
}

impl KeyEncapsulation for EcdhKem {
    type PublicKey = Vec<u8>; // Compressed or uncompressed EC point
    type PrivateKey = Vec<u8>; // Scalar
    type WrappedKey = Vec<u8>; // Ephemeral public key || wrapped key

    fn wrap(&self, _key: &[u8], _public_key: &Self::PublicKey) -> Result<Vec<u8>, KemError> {
        // TODO: Implement ECDH + HKDF + AES-GCM wrapping
        // This will be implemented in the NanoTDF feature release
        Err(KemError::UnsupportedAlgorithm(
            "ECDH KEM not yet implemented - planned for NanoTDF support".to_string(),
        ))
    }

    fn unwrap(
        &self,
        _wrapped: &Self::WrappedKey,
        _private_key: &Self::PrivateKey,
    ) -> Result<Vec<u8>, KemError> {
        // TODO: Implement ECDH + HKDF + AES-GCM unwrapping
        Err(KemError::UnsupportedAlgorithm(
            "ECDH KEM not yet implemented - planned for NanoTDF support".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_kem_not_implemented() {
        let kem = EcdhKem::default();
        let key = b"test_key";
        let pubkey = vec![0u8; 65]; // Placeholder

        let result = kem.wrap(key, &pubkey);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KemError::UnsupportedAlgorithm(_)
        ));
    }
}
