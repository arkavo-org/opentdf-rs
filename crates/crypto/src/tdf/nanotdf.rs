//! NanoTDF Implementation
//!
//! NanoTDF is a compact TDF format designed for constrained environments (IoT, mobile).
//! It uses EC-based key agreement (ECDH + HKDF) and binary encoding for efficiency.
//!
//! # Specification
//!
//! See: https://github.com/opentdf/spec/blob/main/schema/NanoTDF.md
//!
//! # Binary Format
//!
//! ```text
//! [Magic/Version (3B)] [Header] [Payload] [Optional Signature]
//!
//! Header:
//!   - Resource Locator (KAS)
//!   - ECC/SymmetricAndPayloadConfig (1 byte bitfield)
//!   - Policy Info
//!   - Ephemeral Public Key (33/49/67/33 bytes for P-256/P-384/P-521/secp256k1)
//!   - Policy Binding (GMAC tag)
//!
//! Payload:
//!   - Length (3 bytes, big-endian, max 16MB)
//!   - IV (3 bytes)
//!   - Ciphertext (variable)
//!   - Auth Tag (8-16 bytes GCM tag)
//!
//! Signature (optional):
//!   - Public Key (33-67 bytes compressed)
//!   - Signature (64-132 bytes ECDSA)
//! ```

use crate::hmac::calculate_hmac;
use crate::kem::ec::{EcCurve, EcdhKem};
use crate::tdf::nanotdf_crypto::{NanoTdfIv, TagSize, decrypt, encrypt};
use opentdf_protocol::binary::{BinaryRead, BinaryWrite, read_bytes, read_u24_be, write_u24_be};
use opentdf_protocol::nanotdf::{
    MagicNumberAndVersion,
    header::{
        EccAndBindingMode, EccMode, Header, PayloadSignatureMode, SymmetricAndPayloadConfig,
        SymmetricCipher,
    },
    policy::{Policy, PolicyBody},
    resource_locator::{Protocol, ResourceLocator},
};
use sha2::{Digest, Sha256};
use std::io::{self, Cursor, Read, Write};
use subtle::ConstantTimeEq;
use thiserror::Error;

/// NanoTDF errors
#[derive(Debug, Error)]
pub enum NanoTdfError {
    #[error("Invalid magic number or version")]
    InvalidMagic,

    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    #[error("Invalid payload: {0}")]
    InvalidPayload(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Policy binding verification failed")]
    PolicyBindingFailed,

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("KEM error: {0}")]
    Kem(#[from] crate::kem::KemError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::tdf::nanotdf_crypto::NanoTdfCryptoError),

    #[error("Unsupported feature: {0}")]
    Unsupported(String),

    // Collection/Dataset errors
    #[error(
        "Collection IV exhausted (max 16,777,215 items). Create new collection with fresh DEK."
    )]
    IvExhausted,

    #[error("Collection rotation threshold reached ({0} items). Consider creating new collection.")]
    RotationThresholdReached(u32),

    #[error("Invalid DEK length: expected 32 bytes, got {0}")]
    InvalidDekLength(usize),

    #[error("KAS URL not configured")]
    MissingKasUrl,

    #[error("Policy not configured")]
    MissingPolicy,
}

/// Complete NanoTDF structure
#[derive(Debug, Clone)]
pub struct NanoTdf {
    /// Magic number and version (L1L)
    pub magic: MagicNumberAndVersion,

    /// NanoTDF header
    pub header: Header,

    /// Encrypted payload (length + IV + ciphertext + tag)
    pub payload: NanoTdfPayload,

    /// Optional ECDSA signature
    pub signature: Option<NanoTdfSignature>,
}

/// NanoTDF encrypted payload
#[derive(Debug, Clone)]
pub struct NanoTdfPayload {
    /// Payload length (3 bytes, max 16MB)
    pub length: u32,

    /// Initialization vector (3 bytes)
    pub iv: NanoTdfIv,

    /// Ciphertext + authentication tag (combined)
    pub ciphertext_and_tag: Vec<u8>,
}

/// Optional ECDSA signature for policy enforcement
#[derive(Debug, Clone)]
pub struct NanoTdfSignature {
    /// Signing public key (compressed EC point)
    pub public_key: Vec<u8>,

    /// ECDSA signature over header + payload
    pub signature: Vec<u8>,
}

/// Builder for creating NanoTDF files
///
/// # Example
///
/// ```rust,ignore
/// use opentdf_crypto::tdf::NanoTdfBuilder;
///
/// let nanotdf = NanoTdfBuilder::new()
///     .kas_url("http://localhost:8080/kas")
///     .policy_remote_body(b"policy-uuid-here".to_vec())
///     .use_ecdh_binding(false)
///     .encrypt(b"sensitive data", &kas_public_key)?;
///
/// let bytes = nanotdf.to_bytes()?;
/// ```
#[derive(Clone)]
pub struct NanoTdfBuilder {
    kas_url: Option<String>,
    kas_kid: Option<Vec<u8>>,
    policy_body: Option<PolicyBody>,
    ecc_mode: EccMode,
    use_ecdh_binding: bool,
}

impl NanoTdfBuilder {
    /// Create a new NanoTDF builder with defaults (P-256, GMAC binding)
    pub fn new() -> Self {
        NanoTdfBuilder {
            kas_url: None,
            kas_kid: None,
            policy_body: None,
            ecc_mode: EccMode::Secp256r1,
            use_ecdh_binding: false,
        }
    }

    /// Set the KAS URL
    #[must_use]
    pub fn kas_url(mut self, url: impl Into<String>) -> Self {
        self.kas_url = Some(url.into());
        self
    }

    /// Set the KAS URL with a key ID (kid)
    #[must_use]
    pub fn kas_url_with_kid(mut self, url: impl Into<String>, kid: &[u8]) -> Self {
        self.kas_url = Some(url.into());
        self.kas_kid = Some(kid.to_vec());
        self
    }

    /// Set a remote policy body (URL starting with `http://`/`https://` or raw resource identifier bytes)
    #[must_use]
    pub fn policy_remote_body(mut self, body: Vec<u8>) -> Self {
        let locator = std::str::from_utf8(&body)
            .ok()
            .and_then(|s| ResourceLocator::from_url(s).ok())
            .unwrap_or_else(|| ResourceLocator::new(Protocol::SharedResourceDirectory, body));
        self.policy_body = Some(PolicyBody::Remote(locator));
        self
    }

    /// Set an embedded plaintext policy
    #[must_use]
    pub fn policy_plaintext(mut self, body: Vec<u8>) -> Self {
        self.policy_body = Some(PolicyBody::EmbeddedPlaintext(body));
        self
    }

    /// Set the ECC curve (default: P-256)
    #[must_use]
    pub fn ecc_mode(mut self, mode: EccMode) -> Self {
        self.ecc_mode = mode;
        self
    }

    /// Use ECDH-based policy binding instead of GMAC (default: false)
    #[must_use]
    pub fn use_ecdh_binding(mut self, enabled: bool) -> Self {
        self.use_ecdh_binding = enabled;
        self
    }

    /// Encrypt data and build NanoTDF
    ///
    /// # Process
    ///
    /// 1. Generate ephemeral EC key pair for selected curve
    /// 2. Perform ECDH with recipient KAS public key
    /// 3. Derive AES-256 key using HKDF-SHA256 with NanoTDF salt
    /// 4. Encrypt payload with AES-256-GCM (3-byte IV, variable tag size)
    /// 5. Calculate policy binding (GMAC or ECDH-based)
    /// 6. Assemble header + payload
    pub fn encrypt(self, plaintext: &[u8], kas_public_key: &[u8]) -> Result<NanoTdf, NanoTdfError> {
        // Tag size: default to 96-bit (12 bytes) for RustCrypto compatibility
        let tag_size = TagSize::Bits96;

        // Validate payload size: 3-byte u24 length field carries IV (3) + ciphertext + tag
        let max_plaintext_size: usize = 0x00FF_FFFF - 3 - tag_size.bytes();
        if plaintext.len() > max_plaintext_size {
            return Err(NanoTdfError::InvalidPayload(format!(
                "Payload too large: {} bytes (max {} bytes plaintext for 3-byte payload length)",
                plaintext.len(),
                max_plaintext_size
            )));
        }

        let kas_url = self
            .kas_url
            .ok_or_else(|| NanoTdfError::InvalidHeader("KAS URL not set".to_string()))?;

        let policy_body = self
            .policy_body
            .ok_or_else(|| NanoTdfError::InvalidHeader("Policy not set".to_string()))?;

        // Convert EccMode to EcCurve
        let curve = match self.ecc_mode {
            EccMode::Secp256r1 => EcCurve::P256,
            EccMode::Secp384r1 => EcCurve::P384,
            EccMode::Secp521r1 => EcCurve::P521,
            EccMode::Secp256k1 => EcCurve::Secp256k1,
        };

        // Create ECDH KEM for the selected curve
        let kem = EcdhKem::new(curve);

        // Perform ECDH + HKDF to derive encryption key and get ephemeral public key
        let (aes_key, ephemeral_public_key) = kem.derive_key_with_ephemeral(kas_public_key)?;

        // Generate random 3-byte IV
        let iv = NanoTdfIv::random();

        // Encrypt payload with AES-256-GCM
        let ciphertext_and_tag = encrypt(&aes_key, &iv, plaintext, tag_size)?;

        // Calculate policy binding: last 8 bytes of SHA-256 over policy body
        // Matches OpenTDF Go SDK / platform KAS reference format for L1L v1.2 interop.
        let policy_binding = if self.use_ecdh_binding {
            // ECDSA binding (future)
            return Err(NanoTdfError::Unsupported(
                "ECDSA policy binding not yet implemented".to_string(),
            ));
        } else {
            let policy_bytes = serialize_policy_body_for_binding(&policy_body)?;
            let digest = Sha256::digest(&policy_bytes);
            digest[24..].to_vec() // Last 8 bytes
        };

        // Create KAS resource locator
        let mut kas_locator = ResourceLocator::from_url(&kas_url)
            .map_err(|e| NanoTdfError::InvalidHeader(format!("Invalid KAS URL: {}", e)))?;

        // Add key ID if provided
        if let Some(kid) = self.kas_kid {
            kas_locator = kas_locator
                .with_identifier(kid)
                .map_err(|e| NanoTdfError::InvalidHeader(format!("Invalid key ID: {}", e)))?;
        }

        // Create policy with binding
        let policy = Policy {
            body: policy_body,
            binding: policy_binding,
        };

        // Create header config
        let signature_mode = PayloadSignatureMode::none();
        let symmetric_cipher = SymmetricCipher::Aes256Gcm96;
        let config = SymmetricAndPayloadConfig::new(signature_mode, symmetric_cipher);

        // Create ECC and binding mode
        let ecc_and_binding_mode = EccAndBindingMode::new(false, self.ecc_mode);

        // Create header using the constructor (not struct literal)
        let header = Header::new(
            kas_locator,
            ecc_and_binding_mode,
            config,
            policy,
            ephemeral_public_key.to_vec(),
        )?;

        // Create payload
        // Note: length includes IV (3 bytes) + ciphertext + tag
        let payload = NanoTdfPayload {
            length: (3 + ciphertext_and_tag.len()) as u32,
            iv,
            ciphertext_and_tag,
        };

        Ok(NanoTdf {
            magic: MagicNumberAndVersion::new(),
            header,
            payload,
            signature: None,
        })
    }
}

impl Default for NanoTdfBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NanoTdf {
    /// Serialize NanoTDF to binary format
    pub fn to_bytes(&self) -> Result<Vec<u8>, NanoTdfError> {
        let mut buffer = Vec::new();

        // Write header (includes magic + version)
        self.header.write_to(&mut buffer)?;

        // Write payload
        self.payload.write_to(&mut buffer)?;

        // Write optional signature
        if let Some(sig) = &self.signature {
            sig.write_to(&mut buffer)?;
        }

        Ok(buffer)
    }

    /// Deserialize NanoTDF from binary format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NanoTdfError> {
        let mut cursor = Cursor::new(bytes);

        // Read header (includes magic + version)
        let header = Header::read_from(&mut cursor)?;

        // Read payload
        let payload = NanoTdfPayload::read_from(&mut cursor)?;

        // Read optional signature
        let signature = if header
            .symmetric_and_payload_config
            .signature_mode
            .has_signature
        {
            let sig_ecc_mode = header
                .symmetric_and_payload_config
                .signature_mode
                .signature_ecc_mode
                .ok_or_else(|| {
                    NanoTdfError::InvalidHeader("Signature ECC mode missing".to_string())
                })?;
            Some(NanoTdfSignature::read_from(&mut cursor, sig_ecc_mode)?)
        } else {
            None
        };

        Ok(NanoTdf {
            magic: header.magic_number_and_version,
            header,
            payload,
            signature,
        })
    }

    /// Decrypt NanoTDF payload
    ///
    /// # Process
    ///
    /// 1. Parse header and extract ephemeral public key
    /// 2. Perform ECDH with recipient private key
    /// 3. Derive decryption key using HKDF-SHA256 with NanoTDF salt
    /// 4. Verify policy binding
    /// 5. Verify optional ECDSA payload signature (self-consistency against embedded key)
    /// 6. Decrypt payload with AES-256-GCM
    ///
    /// **Security note**: If a payload signature is present, this method verifies it against
    /// the public key embedded in the trailer without checking a trust anchor, and does not
    /// require a signature to be present. To enforce a trusted signer key set and prevent
    /// signature stripping, use [`decrypt_with_trusted_signers`](Self::decrypt_with_trusted_signers).
    pub fn decrypt(&self, kas_private_key: &[u8]) -> Result<Vec<u8>, NanoTdfError> {
        self.decrypt_inner(kas_private_key, None, false)
    }

    /// Decrypt NanoTDF payload while verifying the payload signature against a caller-supplied
    /// set of trusted compressed SEC1 signer public keys.
    ///
    /// - When `require_signature` is `true`, an unsigned NanoTDF (or one whose signature trailer
    ///   was stripped) is rejected with `NanoTdfError::DecryptionFailed`.
    /// - When a signature is present, its embedded public key MUST match one of `trusted_signers`
    ///   (compared in constant time) before the ECDSA signature is verified.
    pub fn decrypt_with_trusted_signers(
        &self,
        kas_private_key: &[u8],
        trusted_signers: &[&[u8]],
        require_signature: bool,
    ) -> Result<Vec<u8>, NanoTdfError> {
        self.decrypt_inner(kas_private_key, Some(trusted_signers), require_signature)
    }

    fn decrypt_inner(
        &self,
        kas_private_key: &[u8],
        trusted_signers: Option<&[&[u8]]>,
        require_signature: bool,
    ) -> Result<Vec<u8>, NanoTdfError> {
        // Convert EccMode to EcCurve
        let curve = match self.header.ecc_and_binding_mode.ecc_mode {
            EccMode::Secp256r1 => EcCurve::P256,
            EccMode::Secp384r1 => EcCurve::P384,
            EccMode::Secp521r1 => EcCurve::P521,
            EccMode::Secp256k1 => EcCurve::Secp256k1,
        };

        // Create ECDH KEM for the curve
        let kem = EcdhKem::new(curve);

        // Perform ECDH + HKDF to derive decryption key using ephemeral public key
        let aes_key =
            kem.derive_key_with_private(kas_private_key, &self.header.ephemeral_public_key)?;

        // Verify policy binding in constant time.
        // Accepts either the OpenTDF Go SDK/KAS reference binding (SHA-256 tail)
        // or the keyed HMAC-SHA256(aes_key, policy_bytes) tail.
        if self.header.ecc_and_binding_mode.use_ecdsa_binding {
            return Err(NanoTdfError::Unsupported(
                "ECDSA policy binding verification not yet implemented".to_string(),
            ));
        }
        {
            let policy_bytes = serialize_policy_body_for_binding(&self.header.policy.body)?;
            let digest = Sha256::digest(&policy_bytes);
            let reference = &digest[24..];
            let mac = calculate_hmac(aes_key.as_slice(), &policy_bytes).map_err(|e| {
                NanoTdfError::DecryptionFailed(format!("Policy binding HMAC failed: {e}"))
            })?;
            let keyed = &mac[24..];

            let b = self.header.policy.binding.as_slice();
            if b.len() != 8 || !(bool::from(b.ct_eq(keyed)) | bool::from(b.ct_eq(reference))) {
                return Err(NanoTdfError::PolicyBindingFailed);
            }
        }

        // Verify optional/required ECDSA payload signature before returning plaintext
        let sig_mode = self.header.symmetric_and_payload_config.signature_mode;
        if sig_mode.has_signature || self.signature.is_some() {
            let sig = self.signature.as_ref().ok_or_else(|| {
                NanoTdfError::DecryptionFailed(
                    "Header declares payload signature but signature is absent".to_string(),
                )
            })?;
            if let Some(trusted) = trusted_signers {
                let is_trusted = trusted.iter().any(|k| {
                    k.len() == sig.public_key.len() && bool::from(k.ct_eq(&sig.public_key))
                });
                if !is_trusted {
                    return Err(NanoTdfError::DecryptionFailed(
                        "Payload signature public key is not in trusted signer set".to_string(),
                    ));
                }
            }
            let sig_ecc_mode = sig_mode.signature_ecc_mode.ok_or_else(|| {
                NanoTdfError::InvalidHeader("Signature ECC mode missing".to_string())
            })?;
            let mut signed_data = Vec::new();
            self.header.write_to(&mut signed_data)?;
            self.payload.write_to(&mut signed_data)?;
            verify_nanotdf_signature(sig_ecc_mode, sig, &signed_data)?;
        } else if require_signature {
            return Err(NanoTdfError::DecryptionFailed(
                "Payload signature is required but missing".to_string(),
            ));
        }

        // Determine tag size from config
        let tag_size = match self.header.symmetric_and_payload_config.symmetric_cipher {
            SymmetricCipher::Aes256Gcm64 => {
                #[cfg(feature = "nanotdf-mbedtls")]
                {
                    TagSize::Bits64
                }
                #[cfg(not(feature = "nanotdf-mbedtls"))]
                {
                    return Err(NanoTdfError::Unsupported(
                        "64-bit GCM tags require nanotdf-mbedtls feature".to_string(),
                    ));
                }
            }
            SymmetricCipher::Aes256Gcm96 => TagSize::Bits96,
            SymmetricCipher::Aes256Gcm104 => TagSize::Bits104,
            SymmetricCipher::Aes256Gcm112 => TagSize::Bits112,
            SymmetricCipher::Aes256Gcm120 => TagSize::Bits120,
            SymmetricCipher::Aes256Gcm128 => TagSize::Bits128,
        };

        // Decrypt payload
        let plaintext = decrypt(
            &aes_key,
            &self.payload.iv,
            &self.payload.ciphertext_and_tag,
            tag_size,
        )?;

        Ok(plaintext)
    }
}

// Binary serialization for NanoTdfPayload
impl BinaryWrite for NanoTdfPayload {
    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        // Write length (3 bytes, big-endian)
        write_u24_be(writer, self.length)?;

        // Write IV (3 bytes)
        writer.write_all(self.iv.as_bytes())?;

        // Write ciphertext + tag
        writer.write_all(&self.ciphertext_and_tag)?;

        Ok(())
    }

    fn serialized_size(&self) -> usize {
        3 + 3 + self.ciphertext_and_tag.len()
    }
}

impl BinaryRead for NanoTdfPayload {
    fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
        // Read length (3 bytes, big-endian)
        // Note: This length includes IV + ciphertext + tag
        let length = read_u24_be(reader)?;

        if length < 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Payload length too small: {} (must be at least 3 for IV)",
                    length
                ),
            ));
        }

        // Read all payload data (IV + ciphertext + tag) using bounded/chunked reader
        let payload_data = read_bytes(reader, length as usize)?;

        // Extract IV from first 3 bytes
        let iv = NanoTdfIv::from_bytes([payload_data[0], payload_data[1], payload_data[2]]);

        // Remaining bytes are ciphertext + tag
        let ciphertext_and_tag = payload_data[3..].to_vec();

        Ok(NanoTdfPayload {
            length,
            iv,
            ciphertext_and_tag,
        })
    }
}

pub(crate) fn serialize_policy_body_for_binding(
    policy_body: &PolicyBody,
) -> Result<Vec<u8>, NanoTdfError> {
    match policy_body {
        PolicyBody::Remote(locator) => {
            let mut buf = Vec::new();
            locator.write_to(&mut buf).map_err(|e| {
                NanoTdfError::InvalidHeader(format!("Failed to serialize policy: {}", e))
            })?;
            Ok(buf)
        }
        PolicyBody::EmbeddedPlaintext(content)
        | PolicyBody::EmbeddedEncrypted(content)
        | PolicyBody::EmbeddedEncryptedWithKeyAccess { content, .. } => Ok(content.clone()),
    }
}

fn verify_nanotdf_signature(
    ecc_mode: EccMode,
    sig: &NanoTdfSignature,
    message: &[u8],
) -> Result<(), NanoTdfError> {
    match ecc_mode {
        EccMode::Secp256r1 => {
            use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let vk = VerifyingKey::from_sec1_bytes(&sig.public_key).map_err(|e| {
                NanoTdfError::DecryptionFailed(format!("Invalid P-256 signature public key: {e}"))
            })?;
            let signature = Signature::from_slice(&sig.signature).map_err(|e| {
                NanoTdfError::DecryptionFailed(format!("Invalid P-256 signature bytes: {e}"))
            })?;
            vk.verify(message, &signature).map_err(|_| {
                NanoTdfError::DecryptionFailed("P-256 payload signature verification failed".into())
            })
        }
        EccMode::Secp384r1 => {
            use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let vk = VerifyingKey::from_sec1_bytes(&sig.public_key).map_err(|e| {
                NanoTdfError::DecryptionFailed(format!("Invalid P-384 signature public key: {e}"))
            })?;
            let signature = Signature::from_slice(&sig.signature).map_err(|e| {
                NanoTdfError::DecryptionFailed(format!("Invalid P-384 signature bytes: {e}"))
            })?;
            vk.verify(message, &signature).map_err(|_| {
                NanoTdfError::DecryptionFailed("P-384 payload signature verification failed".into())
            })
        }
        EccMode::Secp521r1 => {
            use p521::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let vk = VerifyingKey::from_sec1_bytes(&sig.public_key).map_err(|e| {
                NanoTdfError::DecryptionFailed(format!("Invalid P-521 signature public key: {e}"))
            })?;
            let signature = Signature::from_slice(&sig.signature).map_err(|e| {
                NanoTdfError::DecryptionFailed(format!("Invalid P-521 signature bytes: {e}"))
            })?;
            vk.verify(message, &signature).map_err(|_| {
                NanoTdfError::DecryptionFailed("P-521 payload signature verification failed".into())
            })
        }
        EccMode::Secp256k1 => {
            use k256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let vk = VerifyingKey::from_sec1_bytes(&sig.public_key).map_err(|e| {
                NanoTdfError::DecryptionFailed(format!(
                    "Invalid secp256k1 signature public key: {e}"
                ))
            })?;
            let signature = Signature::from_slice(&sig.signature).map_err(|e| {
                NanoTdfError::DecryptionFailed(format!("Invalid secp256k1 signature bytes: {e}"))
            })?;
            vk.verify(message, &signature).map_err(|_| {
                NanoTdfError::DecryptionFailed(
                    "secp256k1 payload signature verification failed".into(),
                )
            })
        }
    }
}

// Binary serialization for NanoTdfSignature
impl NanoTdfSignature {
    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.public_key)?;
        writer.write_all(&self.signature)?;
        Ok(())
    }

    fn read_from<R: Read>(reader: &mut R, ecc_mode: EccMode) -> io::Result<Self> {
        let public_key_size = ecc_mode.public_key_size();
        let signature_size = ecc_mode.signature_size();

        let mut public_key = vec![0u8; public_key_size];
        reader.read_exact(&mut public_key)?;

        let mut signature = vec![0u8; signature_size];
        reader.read_exact(&mut signature)?;

        Ok(NanoTdfSignature {
            public_key,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_api() {
        let builder = NanoTdfBuilder::new()
            .kas_url("http://localhost:8080/kas")
            .policy_remote_body(b"test-uuid".to_vec())
            .ecc_mode(EccMode::Secp256r1);

        // Verify builder state
        assert!(builder.kas_url.is_some());
        assert!(builder.policy_body.is_some());
    }

    #[test]
    fn test_payload_size_limit() {
        let builder = NanoTdfBuilder::new()
            .kas_url("http://localhost:8080/kas")
            .policy_remote_body(b"test-uuid".to_vec());

        // Create a dummy KAS key (won't work for encryption but tests size validation)
        let dummy_key = vec![0u8; 33];

        // Test max plaintext size (16MB - 1 - 3-byte IV - 12-byte 96-bit tag)
        let max_payload = vec![0u8; 0x00FF_FFFF - 3 - 12];
        let result = builder.clone().encrypt(&max_payload, &dummy_key);
        // Will fail on crypto (invalid dummy key), not on size validation
        assert!(result.is_err());
        assert!(!matches!(result, Err(NanoTdfError::InvalidPayload(_))));

        // Test over-size plaintext (exceeds u24 once IV + tag are added)
        let oversized_payload = vec![0u8; 0x00FF_FFFF - 3 - 11];
        let result = builder.encrypt(&oversized_payload, &dummy_key);
        assert!(matches!(result, Err(NanoTdfError::InvalidPayload(_))));
    }

    #[test]
    fn test_nanotdf_policy_binding_and_signature_verification() {
        use p256::SecretKey;
        use p256::ecdsa::{SigningKey, signature::Signer};
        use p256::elliptic_curve::Generate;
        use pkcs8::EncodePrivateKey;

        let kas_secret = SecretKey::generate();
        let kas_public = kas_secret.public_key().to_sec1_bytes();
        let kas_priv_der = kas_secret.to_pkcs8_der().unwrap();

        let mut ntdf = NanoTdfBuilder::new()
            .kas_url("https://kas.example.com")
            .policy_plaintext(b"secret-policy".to_vec())
            .encrypt(b"hello nanotdf", &kas_public)
            .unwrap();

        // Default builder emits OpenTDF Go SDK/KAS reference binding (SHA-256 tail)
        let policy_bytes = serialize_policy_body_for_binding(&ntdf.header.policy.body).unwrap();
        let sha = Sha256::digest(&policy_bytes);
        assert_eq!(ntdf.header.policy.binding.as_slice(), &sha[24..]);

        // Normal decrypt succeeds
        assert_eq!(
            ntdf.decrypt(kas_priv_der.as_bytes()).unwrap(),
            b"hello nanotdf"
        );

        // Tampering policy body must fail policy binding verification
        let mut tampered_policy = ntdf.clone();
        tampered_policy.header.policy.body =
            PolicyBody::EmbeddedPlaintext(b"tampered-policy".to_vec());
        assert!(matches!(
            tampered_policy.decrypt(kas_priv_der.as_bytes()),
            Err(NanoTdfError::PolicyBindingFailed)
        ));

        // Keyed HMAC-SHA256 binding is also accepted on verification
        let kem = EcdhKem::new(EcCurve::P256);
        let aes_key = kem
            .derive_key_with_private(kas_priv_der.as_bytes(), &ntdf.header.ephemeral_public_key)
            .unwrap();
        let mut keyed = ntdf.clone();
        let mac = calculate_hmac(aes_key.as_slice(), &policy_bytes).unwrap();
        keyed.header.policy.binding = mac[24..].to_vec();
        assert_eq!(
            keyed.decrypt(kas_priv_der.as_bytes()).unwrap(),
            b"hello nanotdf"
        );

        // Corrupting the binding bytes must fail verification
        let mut bad_binding = ntdf.clone();
        bad_binding.header.policy.binding[0] ^= 0xFF;
        assert!(matches!(
            bad_binding.decrypt(kas_priv_der.as_bytes()),
            Err(NanoTdfError::PolicyBindingFailed)
        ));

        // Payload ECDSA signature verification: valid signature passes, forged fails
        let signing_key = SigningKey::from(&SecretKey::generate());
        let verifying_key = signing_key.verifying_key();
        ntdf.header
            .symmetric_and_payload_config
            .signature_mode
            .has_signature = true;
        ntdf.header
            .symmetric_and_payload_config
            .signature_mode
            .signature_ecc_mode = Some(EccMode::Secp256r1);
        let mut msg = Vec::new();
        ntdf.header.write_to(&mut msg).unwrap();
        ntdf.payload.write_to(&mut msg).unwrap();
        let sig: p256::ecdsa::Signature = signing_key.sign(&msg);
        ntdf.signature = Some(NanoTdfSignature {
            public_key: verifying_key.to_sec1_point(true).as_bytes().to_vec(),
            signature: sig.to_bytes().to_vec(),
        });
        assert_eq!(
            ntdf.decrypt(kas_priv_der.as_bytes()).unwrap(),
            b"hello nanotdf"
        );

        // Trusted signer verification: trusted key passes, attacker key rejected, stripped signature rejected
        let trusted_pk = verifying_key.to_sec1_point(true).as_bytes().to_vec();
        assert_eq!(
            ntdf.decrypt_with_trusted_signers(
                kas_priv_der.as_bytes(),
                &[trusted_pk.as_slice()],
                true
            )
            .unwrap(),
            b"hello nanotdf"
        );
        let other_pk = SigningKey::from(&SecretKey::generate())
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec();
        assert!(
            ntdf.decrypt_with_trusted_signers(
                kas_priv_der.as_bytes(),
                &[other_pk.as_slice()],
                true
            )
            .is_err()
        );

        // Stripping signature when require_signature=true must fail
        let mut stripped = ntdf.clone();
        stripped
            .header
            .symmetric_and_payload_config
            .signature_mode
            .has_signature = false;
        stripped
            .header
            .symmetric_and_payload_config
            .signature_mode
            .signature_ecc_mode = None;
        stripped.signature = None;
        assert!(
            stripped
                .decrypt_with_trusted_signers(
                    kas_priv_der.as_bytes(),
                    &[trusted_pk.as_slice()],
                    true,
                )
                .is_err()
        );

        // Flip a signature byte -> must reject
        ntdf.signature.as_mut().unwrap().signature[0] ^= 0xFF;
        assert!(ntdf.decrypt(kas_priv_der.as_bytes()).is_err());
    }
}
