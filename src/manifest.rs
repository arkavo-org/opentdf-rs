//! TDF Manifest extension methods
//!
//! This module provides extension methods for manifest types from `opentdf-protocol`
//! that require dependencies on Policy and crypto operations.

use crate::policy::{Policy, PolicyError};
use opentdf_crypto::{
    HmacError, PayloadKey, calculate_policy_binding, calculate_root_signature,
    verify_root_signature, verify_segment_hash,
};

// Re-export protocol types for backward compatibility
pub use opentdf_protocol::{
    Assertion, AssertionBinding, AssertionStatement, EncryptionInformation, EncryptionMethod,
    IntegrityInformation, KeyAccess, Payload, PolicyBinding, PolicyBindingError, RootSignature,
    Segment, TDF_SPEC_VERSION, TdfManifest,
};

/// Why a TDF failed integrity verification while being decrypted.
///
/// The wording is part of the cross-SDK conformance contract: a harness greps
/// the decrypt failure output for `root`, `segment` and `signature`.
#[derive(Debug, thiserror::Error)]
pub enum IntegrityError {
    /// The manifest describes a different number of segments than the payload
    /// decrypted into.
    #[error(
        "integrity: manifest lists {manifest} segments but {computed} segments were decrypted from the payload"
    )]
    SegmentCountMismatch { manifest: usize, computed: usize },

    /// A `segments[i].hash` is not decodable base64.
    #[error("integrity: segment {index} signature is not valid base64: {reason}")]
    SegmentHashEncoding { index: usize, reason: String },

    /// A `segments[i].hash` does not match the GMAC tag of that segment's
    /// ciphertext, i.e. the manifest was tampered with.
    #[error("integrity: segment {index} signature does not match the decrypted ciphertext")]
    SegmentHashMismatch { index: usize },

    /// `rootSignature.sig` does not match the aggregate of the segment tags.
    #[error("integrity: root signature verification failed: {0}")]
    RootSignature(String),

    /// A `segments[i].hash` decodes to something other than a 16-byte GMAC
    /// tag, so the rows cannot be the input the root signature was computed
    /// over.
    #[error("integrity: segment {index} signature is {length} bytes, expected a 16-byte GMAC tag")]
    SegmentHashLength { index: usize, length: usize },
}

/// Length in bytes of a GMAC segment tag, the AES-GCM authentication tag.
const GMAC_TAG_LENGTH: usize = 16;

/// Extension trait for IntegrityInformation that requires crypto operations
pub trait IntegrityInformationExt {
    fn generate_root_signature(
        &mut self,
        gmac_tags: &[Vec<u8>],
        payload_key: &[u8],
    ) -> Result<(), String>;

    fn verify_root_signature(
        &self,
        gmac_tags: &[Vec<u8>],
        payload_key: &[u8],
    ) -> Result<(), String>;

    /// Verify a decrypted payload against **both** integrity checks the spec
    /// requires: every `segments[i].hash`, then the root signature.
    fn verify_segments_and_root_signature(
        &self,
        gmac_tags: &[Vec<u8>],
        payload_key: &[u8],
    ) -> Result<(), IntegrityError>;

    /// Verify the root signature against the manifest's own segment rows,
    /// before any segment has been decrypted.
    fn verify_root_signature_from_rows(&self, payload_key: &[u8]) -> Result<(), IntegrityError>;
}

impl IntegrityInformationExt for IntegrityInformation {
    /// Generate root signature from GMAC tags using constant-time HMAC
    ///
    /// The root signature is calculated as:
    /// Base64(HMAC-SHA256(payloadKey, concat(gmac1, gmac2, ...)))
    ///
    /// This uses the constant-time implementation from `opentdf-crypto`
    /// to prevent timing attacks.
    fn generate_root_signature(
        &mut self,
        gmac_tags: &[Vec<u8>],
        payload_key: &[u8],
    ) -> Result<(), String> {
        let payload_key = PayloadKey::from_slice(payload_key)
            .map_err(|e| format!("Invalid payload key: {}", e))?;

        let signature = calculate_root_signature(gmac_tags, &payload_key)
            .map_err(|e| format!("Failed to calculate root signature: {}", e))?;

        self.root_signature.sig = signature;
        self.root_signature.alg = "HS256".to_string();

        Ok(())
    }

    /// Verify root signature against GMAC tags using constant-time comparison
    ///
    /// This validates the integrity of encrypted segments by:
    /// 1. Concatenating all GMAC tags as raw bytes
    /// 2. Calculating HMAC-SHA256 over concatenated tags using payload key
    /// 3. Comparing result with stored root signature in constant time
    ///
    /// Returns Ok(()) if signature is valid, Err otherwise.
    ///
    /// # Security Note
    ///
    /// This uses `subtle::ConstantTimeEq` from the crypto crate to prevent
    /// timing attacks.
    fn verify_root_signature(
        &self,
        gmac_tags: &[Vec<u8>],
        payload_key: &[u8],
    ) -> Result<(), String> {
        let payload_key = PayloadKey::from_slice(payload_key)
            .map_err(|e| format!("Invalid payload key: {}", e))?;

        verify_root_signature(gmac_tags, &payload_key, &self.root_signature.sig)
            .map_err(|e| format!("Signature verification failed: {}", e))
    }

    /// Verify each manifest segment hash against the GMAC tag computed from the
    /// ciphertext, then verify the root signature. Both checks always run.
    ///
    /// The root signature alone is not sufficient: it is derived from the tags
    /// the ciphertext actually produced, so it still verifies after an attacker
    /// edits `integrityInformation.segments[i].hash`. Per
    /// `spec/schema/OpenTDF/integrity_information.md` the segment hashes
    /// authenticate each segment, so they are compared here too, in constant
    /// time.
    fn verify_segments_and_root_signature(
        &self,
        gmac_tags: &[Vec<u8>],
        payload_key: &[u8],
    ) -> Result<(), IntegrityError> {
        if self.segments.len() != gmac_tags.len() {
            return Err(IntegrityError::SegmentCountMismatch {
                manifest: self.segments.len(),
                computed: gmac_tags.len(),
            });
        }

        for (index, (segment, gmac_tag)) in self.segments.iter().zip(gmac_tags).enumerate() {
            verify_segment_hash(&segment.hash, gmac_tag).map_err(|e| match e {
                HmacError::Base64Error(source) => IntegrityError::SegmentHashEncoding {
                    index,
                    reason: source.to_string(),
                },
                _ => IntegrityError::SegmentHashMismatch { index },
            })?;
        }

        self.verify_root_signature(gmac_tags, payload_key)
            .map_err(IntegrityError::RootSignature)
    }

    /// Recompute `HMAC-SHA256(payloadKey, concat(raw 16-byte tags))` from
    /// `segments[i].hash` and compare it with `rootSignature.sig` in constant
    /// time. This is the verifying counterpart of
    /// [`generate_root_signature`](Self::generate_root_signature) for a
    /// reader that holds the manifest and the payload key but has not
    /// decrypted the payload.
    ///
    /// Success means the segment rows are the ones the key holder signed, in
    /// that order. A random-access reader checks this once at open and then
    /// trusts each row as the expected hash for
    /// `TdfEncryption::decrypt_segment_into_verified`. Without it, rows and
    /// their members can be reordered, dropped or repeated together, since
    /// every member still passes its own GCM check.
    ///
    /// Every row must decode to exactly 16 bytes
    /// ([`IntegrityError::SegmentHashLength`] otherwise). The signature is
    /// over the concatenation, which does not record where one tag ends, so
    /// rows of other lengths could re-split the same signed bytes into a
    /// different list of tags. This also means only the `GMAC` segment hash
    /// encoding this crate writes is accepted.
    ///
    /// Like [`verify_root_signature`](Self::verify_root_signature), this
    /// does not compare the rows with any ciphertext; decrypting a segment
    /// against its row does that.
    fn verify_root_signature_from_rows(&self, payload_key: &[u8]) -> Result<(), IntegrityError> {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

        let mut gmac_tags = Vec::with_capacity(self.segments.len());
        for (index, segment) in self.segments.iter().enumerate() {
            let tag =
                BASE64
                    .decode(&segment.hash)
                    .map_err(|e| IntegrityError::SegmentHashEncoding {
                        index,
                        reason: e.to_string(),
                    })?;
            if tag.len() != GMAC_TAG_LENGTH {
                return Err(IntegrityError::SegmentHashLength {
                    index,
                    length: tag.len(),
                });
            }
            gmac_tags.push(tag);
        }

        self.verify_root_signature(&gmac_tags, payload_key)
            .map_err(IntegrityError::RootSignature)
    }
}

/// Extension trait for KeyAccess that requires crypto operations
pub trait KeyAccessExt {
    fn generate_policy_binding_raw(&mut self, policy: &str, key: &[u8]) -> Result<(), String>;

    fn generate_policy_binding(&mut self, policy: &Policy, key: &[u8]) -> Result<(), PolicyError>;
}

impl KeyAccessExt for KeyAccess {
    /// Generate policy binding using HMAC-SHA256 from raw policy string
    ///
    /// Writes the spec binding `Base64(HMAC-SHA256(key, Base64(policy)))`; see
    /// `opentdf_crypto::calculate_policy_binding`.
    fn generate_policy_binding_raw(&mut self, policy: &str, key: &[u8]) -> Result<(), String> {
        let binding = calculate_policy_binding(policy, key)
            .map_err(|e| format!("Failed to calculate policy binding: {}", e))?;

        self.policy_binding.hash = binding;
        self.policy_binding.alg = "HS256".to_string();
        Ok(())
    }

    /// Generate policy binding using HMAC-SHA256 from a Policy object
    fn generate_policy_binding(&mut self, policy: &Policy, key: &[u8]) -> Result<(), PolicyError> {
        let policy_json = policy.to_json()?;
        self.generate_policy_binding_raw(&policy_json, key)
            .map_err(|e| PolicyError::EvaluationError {
                reason: format!("Failed to generate policy binding: {}", e),
                attribute: None,
            })?;
        Ok(())
    }
}

/// Extension trait for TdfManifest that requires Policy operations
pub trait TdfManifestExt {
    fn set_policy(&mut self, policy: &Policy) -> Result<(), PolicyError>;
    fn get_policy(&self) -> Result<Policy, PolicyError>;
}

impl TdfManifestExt for TdfManifest {
    /// Set the policy for the manifest using a Policy object
    fn set_policy(&mut self, policy: &Policy) -> Result<(), PolicyError> {
        let policy_json = policy.to_json()?;
        self.set_policy_raw(&policy_json);
        Ok(())
    }

    /// Get the policy from the manifest as a Policy object
    fn get_policy(&self) -> Result<Policy, PolicyError> {
        let policy_json = match self.get_policy_raw() {
            Ok(json) => json,
            Err(e) => {
                return Err(PolicyError::SerializationError(serde_json::Error::io(
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
                )));
            }
        };
        Policy::from_json(&policy_json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_access_metadata() {
        let mut key_access = KeyAccess::new("http://example.com".to_string());

        assert!(key_access.encrypted_metadata.is_none());
        key_access.set_encrypted_metadata("test metadata");
        assert!(key_access.encrypted_metadata.is_some());
        key_access.clear_encrypted_metadata();
        assert!(key_access.encrypted_metadata.is_none());
    }

    #[test]
    fn test_key_access_policy_binding_raw() {
        use crate::manifest::KeyAccessExt;

        let mut key_access = KeyAccess::new("http://kas.example.com:4000".to_string());
        let policy = r#"{"uuid":"test","body":{"attributes":[],"dissem":["user@example.com"]}}"#;
        let key = b"test-key-for-hmac";

        key_access.generate_policy_binding_raw(policy, key).unwrap();
        assert!(!key_access.policy_binding.hash.is_empty());
        assert_eq!(key_access.policy_binding.alg, "HS256");
    }

    #[test]
    fn test_key_access_policy_binding_object() {
        use crate::manifest::KeyAccessExt;
        use crate::policy::{Policy, PolicyBody};

        let mut key_access = KeyAccess::new("http://kas.example.com:4000".to_string());
        let policy = Policy {
            uuid: "test".to_string(),
            valid_from: None,
            valid_to: None,
            body: PolicyBody {
                attributes: vec![],
                dissem: vec!["user@example.com".to_string()],
            },
        };
        let key = b"test-key-for-hmac";

        key_access.generate_policy_binding(&policy, key).unwrap();
        assert!(!key_access.policy_binding.hash.is_empty());
        assert_eq!(key_access.policy_binding.alg, "HS256");
    }

    #[test]
    fn test_manifest_serialization() {
        let manifest = TdfManifest::new(
            "0.payload".to_string(),
            "http://kas.example.com:4000".to_string(),
        );

        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let deserialized: TdfManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(manifest.payload.url, deserialized.payload.url);
        assert_eq!(
            manifest.encryption_information.key_access[0].url,
            deserialized.encryption_information.key_access[0].url
        );
    }

    #[test]
    fn test_payload_omits_tdf_spec_version_by_default() {
        // go platform Payload has no tdf_spec_version field; Python ManifestPayload
        // is a strict dataclass without it. Emitting the field breaks rust→python.
        let manifest = TdfManifest::new(
            "0.payload".to_string(),
            "http://kas.example.com:4000".to_string(),
        );
        assert!(manifest.payload.tdf_spec_version.is_none());

        let value = serde_json::to_value(&manifest).unwrap();
        let payload = value.get("payload").expect("payload object");
        assert!(
            payload.get("tdf_spec_version").is_none(),
            "default encrypt path must not serialize payload.tdf_spec_version: {payload}"
        );
        // Root schemaVersion remains the peer-visible version signal.
        assert_eq!(
            value.get("schemaVersion").and_then(|v| v.as_str()),
            Some("4.3.0")
        );

        // Still accept the field when reading peer manifests that include it.
        let with_spec = r#"{
            "payload": {
                "type": "reference",
                "url": "0.payload",
                "protocol": "zip",
                "isEncrypted": true,
                "tdf_spec_version": "4.3.0"
            },
            "encryptionInformation": {
                "type": "split",
                "keyAccess": [],
                "method": {"algorithm": "AES-256-GCM", "isStreamable": true, "iv": ""},
                "integrityInformation": {
                    "rootSignature": {"alg": "HS256", "sig": ""},
                    "segmentHashAlg": "GMAC",
                    "segments": [],
                    "segmentSizeDefault": 0,
                    "encryptedSegmentSizeDefault": 0
                },
                "policy": ""
            },
            "schemaVersion": "4.3.0"
        }"#;
        let read: TdfManifest = serde_json::from_str(with_spec).unwrap();
        assert_eq!(read.payload.tdf_spec_version.as_deref(), Some("4.3.0"));
    }

    #[test]
    fn test_policy_raw_encoding() {
        let mut manifest = TdfManifest::new(
            "0.payload".to_string(),
            "http://kas.example.com:4000".to_string(),
        );

        let policy = r#"{"uuid":"test","body":{"attributes":[],"dissem":["user@example.com"]}}"#;
        manifest.set_policy_raw(policy);

        let decoded_policy = manifest.get_policy_raw().unwrap();
        assert_eq!(policy, decoded_policy);
    }

    #[test]
    fn test_policy_object_encoding() {
        use crate::manifest::TdfManifestExt;
        use crate::policy::{Policy, PolicyBody};

        let mut manifest = TdfManifest::new(
            "0.payload".to_string(),
            "http://kas.example.com:4000".to_string(),
        );

        let policy = Policy {
            uuid: "test".to_string(),
            valid_from: None,
            valid_to: None,
            body: PolicyBody {
                attributes: vec![],
                dissem: vec!["user@example.com".to_string()],
            },
        };

        manifest.set_policy(&policy).unwrap();

        let retrieved_policy = manifest.get_policy().unwrap();
        assert_eq!(policy.uuid, retrieved_policy.uuid);
        assert_eq!(policy.body.dissem, retrieved_policy.body.dissem);
    }

    const ROOT_KEY: [u8; 32] = [0x42; 32];

    fn b64(bytes: &[u8]) -> String {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
        BASE64.encode(bytes)
    }

    /// Integrity information as a writer leaves it: one row per tag and a
    /// root signature over the raw tags.
    fn signed_rows(tags: &[Vec<u8>]) -> IntegrityInformation {
        let mut integrity = IntegrityInformation::default();
        integrity
            .generate_root_signature(tags, &ROOT_KEY)
            .expect("root signature");
        for tag in tags {
            integrity.segments.push(Segment {
                hash: b64(tag),
                segment_size: None,
                encrypted_segment_size: None,
            });
        }
        integrity
    }

    fn three_tags() -> Vec<Vec<u8>> {
        vec![vec![0x01; 16], vec![0x02; 16], vec![0x03; 16]]
    }

    #[test]
    fn root_signature_verifies_from_manifest_rows() {
        let integrity = signed_rows(&three_tags());
        integrity
            .verify_root_signature_from_rows(&ROOT_KEY)
            .expect("rows are the ones that were signed");

        // The rows agree with the tag-based verifier, which is what a reader
        // that has decrypted every segment uses.
        integrity
            .verify_segments_and_root_signature(&three_tags(), &ROOT_KEY)
            .expect("tags match rows");
    }

    #[test]
    fn root_signature_from_rows_rejects_changed_rows() {
        type Tamper = fn(&mut IntegrityInformation);

        let tampers: [(&str, Tamper); 5] = [
            ("reordered", |integrity| integrity.segments.swap(0, 2)),
            ("dropped", |integrity| {
                integrity.segments.pop();
            }),
            ("repeated", |integrity| {
                let first = integrity.segments[0].clone();
                integrity.segments.push(first);
            }),
            ("edited", |integrity| {
                let mut tag = vec![0x02; 16];
                tag[15] ^= 0x01;
                integrity.segments[1].hash = b64(&tag);
            }),
            ("resigned with another key", |integrity| {
                integrity
                    .generate_root_signature(&three_tags(), &[0x43; 32])
                    .expect("root signature");
            }),
        ];
        for (name, tamper) in tampers {
            let mut integrity = signed_rows(&three_tags());
            tamper(&mut integrity);
            let err = integrity
                .verify_root_signature_from_rows(&ROOT_KEY)
                .expect_err(name);
            assert!(
                matches!(err, IntegrityError::RootSignature(_)),
                "{name}: {err:?}"
            );
        }

        // The right rows under the wrong key, and a key of the wrong length.
        let integrity = signed_rows(&three_tags());
        for key in [&[0x43u8; 32][..], &[0x42u8; 16][..]] {
            let err = integrity
                .verify_root_signature_from_rows(key)
                .expect_err("wrong key");
            assert!(matches!(err, IntegrityError::RootSignature(_)), "{err:?}");
        }
    }

    /// The signature covers the concatenated tags, not their boundaries.
    /// Rows of 8 and 24 bytes carry the same 32 signed bytes as two real
    /// tags, so only the per-row length check tells the lists apart.
    #[test]
    fn root_signature_from_rows_rejects_rows_that_are_not_16_bytes() {
        let tags = vec![vec![0xA1; 16], vec![0xB2; 16]];
        let signed_bytes = tags.concat();
        let resplit = vec![signed_bytes[..8].to_vec(), signed_bytes[8..].to_vec()];

        let mut integrity = signed_rows(&tags);
        integrity
            .verify_root_signature_from_rows(&ROOT_KEY)
            .expect("16-byte rows verify");

        for (row, tag) in integrity.segments.iter_mut().zip(&resplit) {
            row.hash = b64(tag);
        }
        // The HMAC input is unchanged, so the tag-based check still passes.
        integrity
            .verify_root_signature(&resplit, &ROOT_KEY)
            .expect("same concatenated bytes");

        let err = integrity
            .verify_root_signature_from_rows(&ROOT_KEY)
            .expect_err("an 8-byte row is not a GMAC tag");
        assert!(
            matches!(
                err,
                IntegrityError::SegmentHashLength {
                    index: 0,
                    length: 8
                }
            ),
            "{err:?}"
        );

        // A long row is refused too, wherever it sits.
        let mut integrity = signed_rows(&tags);
        integrity.segments[1].hash = b64(&[0xB2; 24]);
        let err = integrity
            .verify_root_signature_from_rows(&ROOT_KEY)
            .expect_err("a 24-byte row is not a GMAC tag");
        assert!(
            matches!(
                err,
                IntegrityError::SegmentHashLength {
                    index: 1,
                    length: 24
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn root_signature_from_rows_rejects_undecodable_rows_and_signatures() {
        let mut integrity = signed_rows(&three_tags());
        integrity.segments[2].hash = "not base64!".to_string();
        let err = integrity
            .verify_root_signature_from_rows(&ROOT_KEY)
            .expect_err("row is not base64");
        assert!(
            matches!(err, IntegrityError::SegmentHashEncoding { index: 2, .. }),
            "{err:?}"
        );

        let mut integrity = signed_rows(&three_tags());
        let mut sig = base64_decode(&integrity.root_signature.sig);
        sig[0] ^= 0x01;
        integrity.root_signature.sig = b64(&sig);
        let err = integrity
            .verify_root_signature_from_rows(&ROOT_KEY)
            .expect_err("signature was edited");
        assert!(matches!(err, IntegrityError::RootSignature(_)), "{err:?}");

        integrity.root_signature.sig = "not base64!".to_string();
        let err = integrity
            .verify_root_signature_from_rows(&ROOT_KEY)
            .expect_err("signature is not base64");
        assert!(matches!(err, IntegrityError::RootSignature(_)), "{err:?}");
    }

    fn base64_decode(value: &str) -> Vec<u8> {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
        BASE64.decode(value).expect("base64")
    }
}
