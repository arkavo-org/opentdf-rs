//! Post-Quantum Cryptography (ML-KEM & Hybrid KEM)
//!
//! This module provides FIPS 203 ML-KEM key encapsulation (`MlKemWrapper`)
//! backed by `aws-lc-rs` (when `aws-lc-provider` is enabled) and a generic
//! 2-of-2 secret-splitting hybrid KEM (`HybridKem`) combining a classical KEM
//! (such as RSA-OAEP or ECDH) with a post-quantum KEM.
//!
//! # Security Design
//!
//! - **ML-KEM wrapping (`MlKemWrapper`)**:
//!   1. Encapsulates a 32-byte shared secret against the recipient's FIPS 203
//!      ML-KEM encapsulation key (`ML-KEM-512`, `ML-KEM-768`, or `ML-KEM-1024`).
//!   2. Derives a 256-bit key-encryption key (KEK) via HKDF-SHA256 with a
//!      domain-separated salt (`OpenTDF-ML-KEM-v1`) and parameter-set label.
//!   3. Wraps the payload key with AES-256-GCM using a fresh 96-bit random nonce
//!      and AAD binding both the parameter-set label and the ML-KEM ciphertext.
//!   4. Outputs `ml_kem_ciphertext || nonce (12 bytes) || aes_gcm_ciphertext_and_tag`.
//!
//! - **Hybrid wrapping (`HybridKem`)**:
//!   Uses 2-of-2 XOR secret splitting so the wrapped key remains confidential
//!   as long as **either** the classical KEM or the post-quantum KEM remains
//!   secure:
//!   1. Draws a uniform random `share_classical` of `key.len()` bytes.
//!   2. Computes `share_pqc = key XOR share_classical`.
//!   3. Wraps `share_classical` with the classical KEM and `share_pqc` with the
//!      post-quantum KEM.
//!   4. Unwrapping recovers both shares and recombines them via XOR, zeroizing
//!      intermediate shares on drop.

use std::fmt;

use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

use super::{KemError, KeyEncapsulation};

/// ML-KEM security level
///
/// Based on NIST FIPS 203 (ML-KEM standard)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemLevel {
    /// ML-KEM-512: 128-bit security (Category 1)
    ///
    /// - Public key: 800 bytes
    /// - Private key: 1632 bytes
    /// - Ciphertext: 768 bytes
    /// - Shared secret: 32 bytes
    Kem512,

    /// ML-KEM-768: 192-bit security (Category 3) - Recommended
    ///
    /// - Public key: 1184 bytes
    /// - Private key: 2400 bytes
    /// - Ciphertext: 1088 bytes
    /// - Shared secret: 32 bytes
    Kem768,

    /// ML-KEM-1024: 256-bit security (Category 5)
    ///
    /// - Public key: 1568 bytes
    /// - Private key: 3168 bytes
    /// - Ciphertext: 1568 bytes
    /// - Shared secret: 32 bytes
    Kem1024,
}

impl MlKemLevel {
    /// Encapsulation (public) key length in bytes per FIPS 203.
    pub const fn public_key_size(self) -> usize {
        match self {
            MlKemLevel::Kem512 => 800,
            MlKemLevel::Kem768 => 1184,
            MlKemLevel::Kem1024 => 1568,
        }
    }

    /// Decapsulation (private) key length in bytes per FIPS 203.
    pub const fn private_key_size(self) -> usize {
        match self {
            MlKemLevel::Kem512 => 1632,
            MlKemLevel::Kem768 => 2400,
            MlKemLevel::Kem1024 => 3168,
        }
    }

    /// ML-KEM ciphertext length in bytes per FIPS 203.
    pub const fn ciphertext_size(self) -> usize {
        match self {
            MlKemLevel::Kem512 => 768,
            MlKemLevel::Kem768 => 1088,
            MlKemLevel::Kem1024 => 1568,
        }
    }

    /// Domain separation label for HKDF info and AES-GCM AAD.
    pub const fn domain_label(self) -> &'static [u8] {
        match self {
            MlKemLevel::Kem512 => b"OpenTDF-ML-KEM-512",
            MlKemLevel::Kem768 => b"OpenTDF-ML-KEM-768",
            MlKemLevel::Kem1024 => b"OpenTDF-ML-KEM-1024",
        }
    }
}

/// ML-KEM (Module Lattice-based KEM, FIPS 203) wrapper.
///
/// When the `aws-lc-provider` feature is enabled, this uses AWS-LC's FIPS 203
/// ML-KEM implementation combined with HKDF-SHA256 and AES-256-GCM key wrapping.
/// Without `aws-lc-provider` (e.g., WASM builds), `wrap` and `unwrap` return
/// `KemError::UnsupportedAlgorithm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MlKemWrapper {
    /// Security level (determines parameter set)
    pub security_level: MlKemLevel,
}

impl MlKemWrapper {
    /// Create a new ML-KEM wrapper for the specified FIPS 203 parameter set.
    pub const fn new(security_level: MlKemLevel) -> Self {
        Self { security_level }
    }
}

impl Default for MlKemWrapper {
    fn default() -> Self {
        MlKemWrapper {
            security_level: MlKemLevel::Kem768, // 192-bit security recommended
        }
    }
}

#[cfg(feature = "aws-lc-provider")]
mod aws_lc_ml_kem {
    use super::*;
    use aes_gcm::{
        Aes256Gcm, KeyInit, Nonce,
        aead::{Aead, Payload},
    };
    use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
    use aws_lc_rs::kem::{
        Algorithm, AlgorithmId, Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_512,
        ML_KEM_768, ML_KEM_1024,
    };

    const HKDF_SALT: &[u8] = b"OpenTDF-ML-KEM-v1";
    const NONCE_LEN: usize = 12;
    const GCM_TAG_LEN: usize = 16;

    struct Aes256KeyType;

    impl KeyType for Aes256KeyType {
        fn len(&self) -> usize {
            32
        }
    }

    fn algorithm_for(level: MlKemLevel) -> &'static Algorithm<AlgorithmId> {
        match level {
            MlKemLevel::Kem512 => &ML_KEM_512,
            MlKemLevel::Kem768 => &ML_KEM_768,
            MlKemLevel::Kem1024 => &ML_KEM_1024,
        }
    }

    fn derive_wrapping_key(
        shared_secret: &[u8],
        level: MlKemLevel,
    ) -> Result<Zeroizing<[u8; 32]>, KemError> {
        let salt = Salt::new(HKDF_SHA256, HKDF_SALT);
        let prk = salt.extract(shared_secret);
        let info = [level.domain_label()];
        let okm = prk
            .expand(&info, Aes256KeyType)
            .map_err(|_| KemError::KeyDerivationFailed)?;
        let mut kek = Zeroizing::new([0u8; 32]);
        okm.fill(kek.as_mut())
            .map_err(|_| KemError::KeyDerivationFailed)?;
        Ok(kek)
    }

    fn build_aad(level: MlKemLevel, ml_kem_ciphertext: &[u8]) -> Vec<u8> {
        let label = level.domain_label();
        let mut aad = Vec::with_capacity(label.len() + ml_kem_ciphertext.len());
        aad.extend_from_slice(label);
        aad.extend_from_slice(ml_kem_ciphertext);
        aad
    }

    impl MlKemWrapper {
        /// Generate a fresh FIPS 203 ML-KEM keypair.
        ///
        /// Returns `(encapsulation_key_bytes, decapsulation_key_bytes)` where
        /// the decapsulation key is wrapped in `Zeroizing` so secret key material
        /// is wiped on drop.
        pub fn generate_keypair(&self) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), KemError> {
            let alg = algorithm_for(self.security_level);
            let decapsulation_key = DecapsulationKey::generate(alg).map_err(|_| {
                KemError::WrapError("Failed to generate ML-KEM keypair".to_string())
            })?;
            let encapsulation_key = decapsulation_key.encapsulation_key().map_err(|_| {
                KemError::WrapError("Failed to derive ML-KEM encapsulation key".to_string())
            })?;
            let pub_bytes = encapsulation_key
                .key_bytes()
                .map_err(|_| {
                    KemError::WrapError("Failed to serialize ML-KEM public key".to_string())
                })?
                .as_ref()
                .to_vec();
            let priv_bytes = Zeroizing::new(
                decapsulation_key
                    .key_bytes()
                    .map_err(|_| {
                        KemError::WrapError("Failed to serialize ML-KEM private key".to_string())
                    })?
                    .as_ref()
                    .to_vec(),
            );
            Ok((pub_bytes, priv_bytes))
        }
    }

    impl KeyEncapsulation for MlKemWrapper {
        type PublicKey = Vec<u8>; // Raw FIPS 203 ML-KEM encapsulation key bytes
        type PrivateKey = Vec<u8>; // Raw FIPS 203 ML-KEM decapsulation key bytes
        type WrappedKey = Vec<u8>; // ML-KEM ciphertext || 12-byte nonce || AES-256-GCM ciphertext+tag

        fn wrap(&self, key: &[u8], public_key: &Self::PublicKey) -> Result<Vec<u8>, KemError> {
            if key.is_empty() {
                return Err(KemError::WrapError("Cannot wrap an empty key".to_string()));
            }

            let alg = algorithm_for(self.security_level);
            let encap_key = EncapsulationKey::new(alg, public_key).map_err(|e| {
                KemError::InvalidKey(format!(
                    "Invalid {:?} encapsulation key (expected {} bytes, got {}): {:?}",
                    self.security_level,
                    self.security_level.public_key_size(),
                    public_key.len(),
                    e
                ))
            })?;

            let (ciphertext, shared_secret) = encap_key
                .encapsulate()
                .map_err(|_| KemError::WrapError("ML-KEM encapsulation failed".to_string()))?;

            let kek = derive_wrapping_key(shared_secret.as_ref(), self.security_level)?;

            let mut nonce_bytes = [0u8; NONCE_LEN];
            aws_lc_rs::rand::fill(&mut nonce_bytes)
                .map_err(|_| KemError::WrapError("Failed to generate random nonce".to_string()))?;

            let cipher = Aes256Gcm::new_from_slice(kek.as_ref())
                .map_err(|_| KemError::KeyDerivationFailed)?;
            let aad = build_aad(self.security_level, ciphertext.as_ref());
            let encrypted_key = cipher
                .encrypt(
                    Nonce::from_slice(&nonce_bytes),
                    Payload {
                        msg: key,
                        aad: &aad,
                    },
                )
                .map_err(|_| KemError::WrapError("AES-256-GCM key wrapping failed".to_string()))?;

            let ct_bytes = ciphertext.as_ref();
            let mut out = Vec::with_capacity(ct_bytes.len() + NONCE_LEN + encrypted_key.len());
            out.extend_from_slice(ct_bytes);
            out.extend_from_slice(&nonce_bytes);
            out.extend_from_slice(&encrypted_key);
            Ok(out)
        }

        fn unwrap(
            &self,
            wrapped: &Self::WrappedKey,
            private_key: &Self::PrivateKey,
        ) -> Result<Vec<u8>, KemError> {
            let ct_len = self.security_level.ciphertext_size();
            let min_len = ct_len + NONCE_LEN + GCM_TAG_LEN + 1;
            if wrapped.len() < min_len {
                return Err(KemError::UnwrapError(format!(
                    "Wrapped key too short for {:?}: got {} bytes, need at least {}",
                    self.security_level,
                    wrapped.len(),
                    min_len
                )));
            }

            let alg = algorithm_for(self.security_level);
            let decap_key = DecapsulationKey::new(alg, private_key).map_err(|e| {
                KemError::InvalidKey(format!(
                    "Invalid {:?} decapsulation key (expected {} bytes, got {}): {:?}",
                    self.security_level,
                    self.security_level.private_key_size(),
                    private_key.len(),
                    e
                ))
            })?;

            let (ct_bytes, rest) = wrapped.split_at(ct_len);
            let (nonce_bytes, encrypted_key) = rest.split_at(NONCE_LEN);

            let shared_secret = decap_key
                .decapsulate(Ciphertext::from(ct_bytes))
                .map_err(|_| KemError::UnwrapError("ML-KEM decapsulation failed".to_string()))?;

            let kek = derive_wrapping_key(shared_secret.as_ref(), self.security_level)?;
            let cipher = Aes256Gcm::new_from_slice(kek.as_ref())
                .map_err(|_| KemError::KeyDerivationFailed)?;
            let aad = build_aad(self.security_level, ct_bytes);

            cipher
                .decrypt(
                    Nonce::from_slice(nonce_bytes),
                    Payload {
                        msg: encrypted_key,
                        aad: &aad,
                    },
                )
                .map_err(|_| {
                    KemError::UnwrapError(
                        "ML-KEM key unwrap failed (authentication tag mismatch)".to_string(),
                    )
                })
        }
    }
}

#[cfg(not(feature = "aws-lc-provider"))]
impl KeyEncapsulation for MlKemWrapper {
    type PublicKey = Vec<u8>;
    type PrivateKey = Vec<u8>;
    type WrappedKey = Vec<u8>;

    fn wrap(&self, _key: &[u8], _public_key: &Self::PublicKey) -> Result<Vec<u8>, KemError> {
        Err(KemError::UnsupportedAlgorithm(
            "ML-KEM requires the `aws-lc-provider` feature".to_string(),
        ))
    }

    fn unwrap(
        &self,
        _wrapped: &Self::WrappedKey,
        _private_key: &Self::PrivateKey,
    ) -> Result<Vec<u8>, KemError> {
        Err(KemError::UnsupportedAlgorithm(
            "ML-KEM requires the `aws-lc-provider` feature".to_string(),
        ))
    }
}

/// Byte-oriented adapter for [`super::rsa::RsaOaepKem`] so it can be composed
/// directly inside [`HybridKem`].
///
/// - `PublicKey`: UTF-8 bytes of the PEM-encoded RSA public key
/// - `PrivateKey`: UTF-8 bytes of the PEM-encoded RSA private key
/// - `WrappedKey`: UTF-8 bytes of the base64-encoded RSA-OAEP ciphertext
#[cfg(all(
    feature = "kem-rsa",
    any(feature = "aws-lc-provider", feature = "rustcrypto-provider")
))]
pub struct RsaOaepBytesKem {
    inner: super::rsa::RsaOaepKem,
}

#[cfg(all(
    feature = "kem-rsa",
    any(feature = "aws-lc-provider", feature = "rustcrypto-provider")
))]
impl RsaOaepBytesKem {
    /// Create a byte-oriented RSA-OAEP KEM with the specified OAEP hash algorithm.
    pub fn new(hash: super::rsa::OaepHash) -> Self {
        Self {
            inner: super::rsa::RsaOaepKem::new(hash),
        }
    }
}

#[cfg(all(
    feature = "kem-rsa",
    any(feature = "aws-lc-provider", feature = "rustcrypto-provider")
))]
impl KeyEncapsulation for RsaOaepBytesKem {
    type PublicKey = Vec<u8>;
    type PrivateKey = Vec<u8>;
    type WrappedKey = Vec<u8>;

    fn wrap(&self, key: &[u8], public_key: &Self::PublicKey) -> Result<Vec<u8>, KemError> {
        let pem = std::str::from_utf8(public_key)
            .map_err(|e| KemError::InvalidKey(format!("RSA public key PEM is not UTF-8: {e}")))?
            .to_string();
        let wrapped_b64 = self.inner.wrap(key, &pem)?;
        Ok(wrapped_b64.into_bytes())
    }

    fn unwrap(
        &self,
        wrapped: &Self::WrappedKey,
        private_key: &Self::PrivateKey,
    ) -> Result<Vec<u8>, KemError> {
        let wrapped_b64 = std::str::from_utf8(wrapped)
            .map_err(|e| KemError::EncodingError(format!("RSA wrapped key is not UTF-8: {e}")))?
            .to_string();
        let pem = Zeroizing::new(
            std::str::from_utf8(private_key)
                .map_err(|e| {
                    KemError::InvalidKey(format!("RSA private key PEM is not UTF-8: {e}"))
                })?
                .to_string(),
        );
        self.inner.unwrap(&wrapped_b64, &pem)
    }
}

/// Hybrid classical + post-quantum KEM
///
/// Combines a classical KEM (e.g., RSA-OAEP or ECDH) with a post-quantum KEM
/// (ML-KEM) using 2-of-2 XOR secret splitting so the wrapped key remains secure
/// as long as **either** component KEM remains secure.
///
/// # Key Wrapping Protocol
///
/// 1. Generate a uniform random share `share_classical` of length `key.len()`
/// 2. Compute `share_pqc = key XOR share_classical`
/// 3. Wrap `share_classical` with `self.classical` → `classical_wrapped`
/// 4. Wrap `share_pqc` with `self.pqc` → `pqc_wrapped`
///
/// # Key Unwrapping Protocol
///
/// 1. Unwrap `classical_wrapped` → `share_classical`
/// 2. Unwrap `pqc_wrapped` → `share_pqc`
/// 3. Verify equal lengths and reconstruct `key = share_classical XOR share_pqc`
pub struct HybridKem {
    /// Classical KEM (RSA-OAEP, ECDH, etc.)
    pub classical:
        Box<dyn KeyEncapsulation<PublicKey = Vec<u8>, PrivateKey = Vec<u8>, WrappedKey = Vec<u8>>>,

    /// Post-quantum KEM (ML-KEM)
    pub pqc:
        Box<dyn KeyEncapsulation<PublicKey = Vec<u8>, PrivateKey = Vec<u8>, WrappedKey = Vec<u8>>>,
}

impl HybridKem {
    /// Construct a hybrid KEM from any boxed classical and post-quantum KEMs.
    pub fn new(
        classical: Box<
            dyn KeyEncapsulation<PublicKey = Vec<u8>, PrivateKey = Vec<u8>, WrappedKey = Vec<u8>>,
        >,
        pqc: Box<
            dyn KeyEncapsulation<PublicKey = Vec<u8>, PrivateKey = Vec<u8>, WrappedKey = Vec<u8>>,
        >,
    ) -> Self {
        Self { classical, pqc }
    }

    /// Construct an RSA-OAEP + ML-KEM hybrid KEM.
    #[cfg(all(feature = "kem-rsa", feature = "aws-lc-provider"))]
    pub fn rsa_ml_kem(oaep_hash: super::rsa::OaepHash, ml_kem_level: MlKemLevel) -> Self {
        Self::new(
            Box::new(RsaOaepBytesKem::new(oaep_hash)),
            Box::new(MlKemWrapper::new(ml_kem_level)),
        )
    }
}

impl KeyEncapsulation for HybridKem {
    type PublicKey = HybridPublicKey;
    type PrivateKey = HybridPrivateKey;
    type WrappedKey = HybridWrappedKey;

    fn wrap(&self, key: &[u8], public_key: &Self::PublicKey) -> Result<Self::WrappedKey, KemError> {
        if key.is_empty() {
            return Err(KemError::WrapError("Cannot wrap an empty key".to_string()));
        }

        let mut share_classical = Zeroizing::new(vec![0u8; key.len()]);
        OsRng.fill_bytes(&mut share_classical);

        let share_pqc = Zeroizing::new(
            key.iter()
                .zip(share_classical.iter())
                .map(|(k, c)| k ^ c)
                .collect::<Vec<u8>>(),
        );

        let classical_wrapped = self
            .classical
            .wrap(&share_classical, &public_key.classical)?;
        let pqc_wrapped = self.pqc.wrap(&share_pqc, &public_key.pqc)?;

        Ok(HybridWrappedKey {
            classical_wrapped,
            pqc_wrapped,
        })
    }

    fn unwrap(
        &self,
        wrapped: &Self::WrappedKey,
        private_key: &Self::PrivateKey,
    ) -> Result<Vec<u8>, KemError> {
        let share_classical = Zeroizing::new(
            self.classical
                .unwrap(&wrapped.classical_wrapped, &private_key.classical)?,
        );
        let share_pqc = Zeroizing::new(self.pqc.unwrap(&wrapped.pqc_wrapped, &private_key.pqc)?);

        if share_classical.is_empty() || share_classical.len() != share_pqc.len() {
            return Err(KemError::UnwrapError(
                "Hybrid KEM component share length mismatch".to_string(),
            ));
        }

        let recovered = share_classical
            .iter()
            .zip(share_pqc.iter())
            .map(|(c, p)| c ^ p)
            .collect();

        Ok(recovered)
    }
}

/// Hybrid public key (classical + PQC)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridPublicKey {
    /// Classical public key
    pub classical: Vec<u8>,
    /// Post-quantum public key
    pub pqc: Vec<u8>,
}

/// Hybrid private key (classical + PQC).
///
/// Automatically zeroizes both component private keys on drop.
#[derive(Clone)]
pub struct HybridPrivateKey {
    /// Classical private key
    pub classical: Vec<u8>,
    /// Post-quantum private key
    pub pqc: Vec<u8>,
}

impl fmt::Debug for HybridPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridPrivateKey")
            .field("classical", &"[REDACTED]")
            .field("pqc", &"[REDACTED]")
            .finish()
    }
}

impl Drop for HybridPrivateKey {
    fn drop(&mut self) {
        self.classical.zeroize();
        self.pqc.zeroize();
    }
}

/// Hybrid wrapped key (classical + PQC ciphertexts)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridWrappedKey {
    /// Classical wrapped key share
    pub classical_wrapped: Vec<u8>,
    /// Post-quantum wrapped key share
    pub pqc_wrapped: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_levels() {
        assert_eq!(MlKemLevel::Kem512 as i32, 0);
        assert_eq!(MlKemLevel::Kem768 as i32, 1);
        assert_eq!(MlKemLevel::Kem1024 as i32, 2);

        assert_eq!(MlKemLevel::Kem512.public_key_size(), 800);
        assert_eq!(MlKemLevel::Kem768.public_key_size(), 1184);
        assert_eq!(MlKemLevel::Kem1024.public_key_size(), 1568);

        assert_eq!(MlKemLevel::Kem512.ciphertext_size(), 768);
        assert_eq!(MlKemLevel::Kem768.ciphertext_size(), 1088);
        assert_eq!(MlKemLevel::Kem1024.ciphertext_size(), 1568);

        let kem = MlKemWrapper::default();
        assert_eq!(kem.security_level, MlKemLevel::Kem768);
    }

    #[cfg(not(feature = "aws-lc-provider"))]
    #[test]
    fn test_ml_kem_requires_aws_lc_provider() {
        let kem = MlKemWrapper::default();
        let key = b"test_key_32_bytes_long_for_aes!!";
        let pubkey = vec![0u8; 1184];

        let result = kem.wrap(key, &pubkey);
        assert!(matches!(result, Err(KemError::UnsupportedAlgorithm(_))));
    }

    #[cfg(feature = "aws-lc-provider")]
    mod aws_lc_tests {
        use super::*;

        #[test]
        fn test_ml_kem_round_trip_all_levels() {
            let key = [0x42u8; 32];
            for level in [MlKemLevel::Kem512, MlKemLevel::Kem768, MlKemLevel::Kem1024] {
                let kem = MlKemWrapper::new(level);
                let (pub_key, priv_key) = kem.generate_keypair().expect("keygen");
                assert_eq!(pub_key.len(), level.public_key_size());
                assert_eq!(priv_key.len(), level.private_key_size());

                let wrapped = kem.wrap(&key, &pub_key).expect("wrap");
                assert_eq!(wrapped.len(), level.ciphertext_size() + 12 + key.len() + 16);

                let unwrapped = kem.unwrap(&wrapped, &priv_key).expect("unwrap");
                assert_eq!(unwrapped, key);
            }
        }

        #[test]
        fn test_ml_kem_wrong_key_and_tampering_fail() {
            let kem = MlKemWrapper::new(MlKemLevel::Kem768);
            let key = [0xA5u8; 32];
            let (pub_key, priv_key) = kem.generate_keypair().expect("keygen 1");
            let (_, wrong_priv_key) = kem.generate_keypair().expect("keygen 2");

            let wrapped = kem.wrap(&key, &pub_key).expect("wrap");

            // Wrong private key (ML-KEM implicit rejection -> wrong KEK -> GCM tag mismatch)
            assert!(matches!(
                kem.unwrap(&wrapped, &wrong_priv_key),
                Err(KemError::UnwrapError(_))
            ));

            // Tamper with ML-KEM ciphertext, nonce, and AES-GCM ciphertext/tag
            for idx in [0, 500, 1088, wrapped.len() - 1] {
                let mut tampered = wrapped.clone();
                tampered[idx] ^= 0x01;
                assert!(
                    matches!(
                        kem.unwrap(&tampered, &priv_key),
                        Err(KemError::UnwrapError(_))
                    ),
                    "tampering byte {idx} must fail unwrap"
                );
            }

            // Truncated wrapped key
            assert!(matches!(
                kem.unwrap(&wrapped[..100].to_vec(), &priv_key),
                Err(KemError::UnwrapError(_))
            ));

            // Invalid key sizes
            assert!(matches!(
                kem.wrap(&key, &vec![0u8; 16]),
                Err(KemError::InvalidKey(_))
            ));
            assert!(matches!(
                kem.unwrap(&wrapped, &vec![0u8; 16]),
                Err(KemError::InvalidKey(_))
            ));

            // Empty key rejected
            assert!(matches!(
                kem.wrap(&[], &pub_key),
                Err(KemError::WrapError(_))
            ));
        }

        #[cfg(feature = "kem-rsa")]
        #[test]
        fn test_hybrid_rsa_ml_kem_round_trip_and_isolation() {
            use crate::kem::rsa::OaepHash;
            use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
            use aws_lc_rs::rsa::{KeySize, PrivateDecryptingKey};

            fn gen_rsa_pem() -> (Vec<u8>, Vec<u8>) {
                let priv_key = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
                let pub_key = priv_key.public_key();
                let priv_der = AsDer::<Pkcs8V1Der>::as_der(&priv_key).unwrap();
                let pub_der = AsDer::<PublicKeyX509Der>::as_der(&pub_key).unwrap();
                let priv_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", priv_der.as_ref()));
                let pub_pem = pem::encode(&pem::Pem::new("PUBLIC KEY", pub_der.as_ref()));
                (pub_pem.into_bytes(), priv_pem.into_bytes())
            }

            let dek = [0x3Cu8; 32];
            for level in [MlKemLevel::Kem768, MlKemLevel::Kem1024] {
                let hybrid = HybridKem::rsa_ml_kem(OaepHash::Sha256, level);
                let (rsa_pub, rsa_priv) = gen_rsa_pem();
                let (pqc_pub, pqc_priv) = MlKemWrapper::new(level).generate_keypair().unwrap();

                let pub_key = HybridPublicKey {
                    classical: rsa_pub,
                    pqc: pqc_pub,
                };
                let priv_key = HybridPrivateKey {
                    classical: rsa_priv.clone(),
                    pqc: pqc_priv.to_vec(),
                };

                let wrapped = hybrid.wrap(&dek, &pub_key).expect("hybrid wrap");
                let recovered = hybrid.unwrap(&wrapped, &priv_key).expect("hybrid unwrap");
                assert_eq!(recovered, dek);

                // Neither component share alone equals the DEK
                let rsa_share = RsaOaepBytesKem::new(OaepHash::Sha256)
                    .unwrap(&wrapped.classical_wrapped, &rsa_priv)
                    .unwrap();
                let pqc_share = MlKemWrapper::new(level)
                    .unwrap(&wrapped.pqc_wrapped, &pqc_priv)
                    .unwrap();
                assert_ne!(rsa_share, dek);
                assert_ne!(pqc_share, dek);

                // Wrong classical key fails unwrap
                let (_, other_rsa_priv) = gen_rsa_pem();
                let bad_classical = HybridPrivateKey {
                    classical: other_rsa_priv,
                    pqc: pqc_priv.to_vec(),
                };
                assert!(hybrid.unwrap(&wrapped, &bad_classical).is_err());

                // Wrong PQC key fails unwrap
                let (_, other_pqc_priv) = MlKemWrapper::new(level).generate_keypair().unwrap();
                let bad_pqc = HybridPrivateKey {
                    classical: rsa_priv,
                    pqc: other_pqc_priv.to_vec(),
                };
                assert!(hybrid.unwrap(&wrapped, &bad_pqc).is_err());
            }
        }
    }
}
