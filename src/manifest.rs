use crate::policy::{Policy, PolicyError};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hmac::{
    digest::{KeyInit, MacError},
    Hmac, Mac,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Debug, Serialize, Deserialize)]
pub struct TdfManifest {
    pub payload: Payload,
    #[serde(rename = "encryptionInformation")]
    pub encryption_information: EncryptionInformation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Payload {
    #[serde(rename = "type")]
    pub payload_type: String,
    pub url: String,
    pub protocol: String,
    #[serde(rename = "isEncrypted")]
    pub is_encrypted: bool,
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(rename = "tdf_spec_version", skip_serializing_if = "Option::is_none")]
    pub tdf_spec_version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionInformation {
    #[serde(rename = "type")]
    pub encryption_type: String,
    #[serde(rename = "keyAccess")]
    pub key_access: Vec<KeyAccess>,
    pub method: EncryptionMethod,
    #[serde(rename = "integrityInformation")]
    pub integrity_information: IntegrityInformation,
    pub policy: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyBinding {
    pub alg: String,
    pub hash: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyAccess {
    #[serde(rename = "type")]
    pub access_type: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    pub protocol: String,
    #[serde(rename = "wrappedKey")]
    pub wrapped_key: String,
    #[serde(rename = "policyBinding")]
    pub policy_binding: PolicyBinding,
    #[serde(rename = "encryptedMetadata", skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<String>,
    #[serde(rename = "tdf_spec_version", skip_serializing_if = "Option::is_none")]
    pub tdf_spec_version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionMethod {
    pub algorithm: String,
    #[serde(rename = "isStreamable")]
    pub is_streamable: bool,
    pub iv: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IntegrityInformation {
    #[serde(rename = "rootSignature")]
    pub root_signature: RootSignature,
    #[serde(rename = "segmentHashAlg")]
    pub segment_hash_alg: String,
    pub segments: Vec<Segment>,
    #[serde(rename = "segmentSizeDefault")]
    pub segment_size_default: u64,
    #[serde(rename = "encryptedSegmentSizeDefault")]
    pub encrypted_segment_size_default: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RootSignature {
    pub alg: String,
    pub sig: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Segment {
    pub hash: String,
    #[serde(rename = "segmentSize", skip_serializing_if = "Option::is_none")]
    pub segment_size: Option<u64>,
    #[serde(
        rename = "encryptedSegmentSize",
        skip_serializing_if = "Option::is_none"
    )]
    pub encrypted_segment_size: Option<u64>,
}

impl KeyAccess {
    /// Creates a new KeyAccess object with default values
    pub fn new(url: String) -> Self {
        KeyAccess {
            access_type: "wrapped".to_string(), // Default type for TDF 3.x and newer
            url,
            kid: None,
            protocol: "kas".to_string(),
            wrapped_key: String::new(),
            policy_binding: PolicyBinding {
                alg: "HS256".to_string(),
                hash: String::new(),
            },
            encrypted_metadata: None,
            tdf_spec_version: None,
        }
    }

    /// Generate policy binding using HMAC-SHA256 from raw policy string
    pub fn generate_policy_binding_raw(
        &mut self,
        policy: &str,
        key: &[u8],
    ) -> Result<(), MacError> {
        type HmacSha256 = Hmac<Sha256>;

        let policy_base64 = BASE64.encode(policy);
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).map_err(|_| MacError)?;
        mac.update(policy_base64.as_bytes());
        let result = mac.finalize();
        self.policy_binding.hash = BASE64.encode(result.into_bytes());
        self.policy_binding.alg = "HS256".to_string();
        Ok(())
    }

    /// Generate policy binding using HMAC-SHA256 from a Policy object
    pub fn generate_policy_binding(
        &mut self,
        policy: &Policy,
        key: &[u8],
    ) -> Result<(), PolicyError> {
        let policy_json = policy.to_json()?;
        self.generate_policy_binding_raw(&policy_json, key)
            .map_err(|e| {
                PolicyError::EvaluationError(format!("Failed to generate policy binding: {}", e))
            })?;
        Ok(())
    }

    /// Set encrypted metadata
    pub fn set_encrypted_metadata(&mut self, metadata: &str) {
        self.encrypted_metadata = Some(BASE64.encode(metadata));
    }

    /// Clear encrypted metadata
    pub fn clear_encrypted_metadata(&mut self) {
        self.encrypted_metadata = None;
    }
}

impl TdfManifest {
    /// Create a new TdfManifest with default values
    pub fn new(payload_url: String, kas_url: String) -> Self {
        TdfManifest {
            payload: Payload {
                payload_type: "reference".to_string(),
                url: payload_url,
                protocol: "zip".to_string(),
                is_encrypted: true,
                mime_type: None,
                tdf_spec_version: None,
            },
            encryption_information: EncryptionInformation {
                encryption_type: "split".to_string(),
                key_access: vec![KeyAccess::new(kas_url)],
                method: EncryptionMethod {
                    algorithm: "AES-256-GCM".to_string(),
                    is_streamable: true,
                    iv: String::new(),
                },
                integrity_information: IntegrityInformation {
                    root_signature: RootSignature {
                        alg: "HS256".to_string(),
                        sig: String::new(),
                    },
                    segment_hash_alg: "GMAC".to_string(),
                    segments: Vec::new(),
                    segment_size_default: 1000000,
                    encrypted_segment_size_default: 1000028,
                },
                policy: String::new(),
            },
        }
    }

    /// Parse a JSON string into a TdfManifest
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Convert the TdfManifest to a JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Set the policy for the manifest using a raw string
    pub fn set_policy_raw(&mut self, policy: &str) {
        self.encryption_information.policy = BASE64.encode(policy);
    }

    /// Get the decoded policy from the manifest as a raw string
    pub fn get_policy_raw(&self) -> Result<String, base64::DecodeError> {
        let bytes = BASE64.decode(&self.encryption_information.policy)?;
        String::from_utf8(bytes)
            .map_err(|err| base64::DecodeError::InvalidByte(err.utf8_error().valid_up_to(), 0))
    }

    /// Set the policy for the manifest using a Policy object
    pub fn set_policy(&mut self, policy: &Policy) -> Result<(), PolicyError> {
        let policy_json = policy.to_json()?;
        self.set_policy_raw(&policy_json);
        Ok(())
    }

    /// Get the policy from the manifest as a Policy object
    pub fn get_policy(&self) -> Result<Policy, PolicyError> {
        let policy_json = match self.get_policy_raw() {
            Ok(json) => json,
            Err(e) => {
                return Err(PolicyError::SerializationError(serde_json::Error::io(
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
                )))
            }
        };
        Policy::from_json(&policy_json)
    }

    /// Add a segment to the manifest
    pub fn add_segment(
        &mut self,
        hash: String,
        segment_size: Option<u64>,
        encrypted_segment_size: Option<u64>,
    ) {
        self.encryption_information
            .integrity_information
            .segments
            .push(Segment {
                hash,
                segment_size,
                encrypted_segment_size,
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_access_metadata() {
        let mut key_access = KeyAccess::new("http://example.com".to_string());

        // Initially should be None
        assert!(key_access.encrypted_metadata.is_none());

        // Set metadata
        key_access.set_encrypted_metadata("test metadata");
        assert!(key_access.encrypted_metadata.is_some());

        // Clear metadata
        key_access.clear_encrypted_metadata();
        assert!(key_access.encrypted_metadata.is_none());
    }

    #[test]
    fn test_manifest_deserialization() {
        let json = r#"{
            "encryptionInformation": {
                "type": "split",
                "keyAccess": [{
                    "type": "wrapped",
                    "url": "http://localhost:8080",
                    "protocol": "kas",
                    "wrappedKey": "abc123",
                    "policyBinding": {
                        "alg": "HS256",
                        "hash": "def456"
                    },
                    "kid": "r1"
                }],
                "method": {
                    "algorithm": "AES-256-GCM",
                    "iv": "",
                    "isStreamable": true
                },
                "integrityInformation": {
                  "rootSignature": {
                    "alg": "HS256",
                    "sig": "M2E2MTI5YmMxMWU0ODIzZDA4YTdkNTY2MzdlNDM4OGRlZDE2MTFhZjU1YTY1YzBhYWNlMWVjYjlmODUzNmNiZQ=="
                  },
                  "segmentHashAlg": "GMAC",
                  "segments": [
                      {
                          "hash": "NzhlZDg5OWMwZWVhZDBjMWEzZTQyYmFlODA0NjNlMDM=",
                          "segmentSize": 14056,
                          "encryptedSegmentSize": 14084
                        }
                  ],
                  "segmentSizeDefault": 1000000,
                  "encryptedSegmentSizeDefault": 1000028
                },
                "policy": "base64policy"
            },
            "payload": {
                "type": "reference",
                "url": "0.payload",
                "protocol": "zip",
                "mimeType": "application/octet-stream",
                "isEncrypted": true
            }
        }"#;

        let manifest = TdfManifest::from_json(json).unwrap();
        assert_eq!(
            manifest.encryption_information.key_access[0]
                .policy_binding
                .alg,
            "HS256"
        );
    }

    #[test]
    fn test_manifest_deserialization_without_metadata() {
        let json = r#"{
            "type": "wrapped",
            "url": "http://localhost:8080",
            "protocol": "kas",
            "wrappedKey": "abc123",
            "policyBinding": {
                "alg": "HS256",
                "hash": "def456"
            },
            "kid": "r1"
        }"#;

        let key_access: KeyAccess = serde_json::from_str(json).unwrap();
        assert!(key_access.encrypted_metadata.is_none());
    }

    #[test]
    fn test_key_access_policy_binding_raw() {
        let mut key_access = KeyAccess::new("http://kas.example.com:4000".to_string());
        let policy = r#"{"uuid":"test","body":{"attributes":[],"dissem":["user@example.com"]}}"#;
        let key = b"test-key-for-hmac";

        key_access.generate_policy_binding_raw(policy, key).unwrap();
        assert!(!key_access.policy_binding.hash.is_empty());
        assert_eq!(key_access.policy_binding.alg, "HS256");
    }

    #[test]
    fn test_key_access_policy_binding_object() {
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

        let json = manifest.to_json().unwrap();
        let deserialized = TdfManifest::from_json(&json).unwrap();

        assert_eq!(manifest.payload.url, deserialized.payload.url);
        assert_eq!(
            manifest.encryption_information.key_access[0].url,
            deserialized.encryption_information.key_access[0].url
        );
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
        use crate::policy::{Policy, PolicyBody};

        let mut manifest = TdfManifest::new(
            "0.payload".to_string(),
            "http://kas.example.com:4000".to_string(),
        );

        // Create a simple policy object
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

        // Retrieve and verify
        let retrieved_policy = manifest.get_policy().unwrap();
        assert_eq!(policy.uuid, retrieved_policy.uuid);
        assert_eq!(policy.body.dissem, retrieved_policy.body.dissem);
    }
}
