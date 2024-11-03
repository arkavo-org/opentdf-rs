use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

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

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyAccess {
    #[serde(rename = "type")]
    pub access_type: String,
    pub url: String,
    pub protocol: String,
    #[serde(rename = "wrappedKey")]
    pub wrapped_key: String,
    #[serde(rename = "policyBinding")]
    pub policy_binding: String,
    #[serde(rename = "encryptedMetadata")]
    pub encrypted_metadata: String,
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
    #[serde(rename = "encryptedSegmentSize", skip_serializing_if = "Option::is_none")]
    pub encrypted_segment_size: Option<u64>,
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
                key_access: vec![KeyAccess {
                    access_type: "wrapped".to_string(),
                    url: kas_url,
                    protocol: "kas".to_string(),
                    wrapped_key: String::new(),
                    policy_binding: String::new(),
                    encrypted_metadata: String::new(),
                }],
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

    /// Set the policy for the manifest
    pub fn set_policy(&mut self, policy: &str) {
        self.encryption_information.policy = BASE64.encode(policy);
    }

    /// Get the decoded policy from the manifest
    pub fn get_policy(&self) -> Result<String, base64::DecodeError> {
        let bytes = BASE64.decode(&self.encryption_information.policy)?;
        String::from_utf8(bytes).map_err(|err| base64::DecodeError::InvalidByte(err.utf8_error().valid_up_to(), 0))
    }

    /// Add a segment to the manifest
    pub fn add_segment(&mut self, hash: String, segment_size: Option<u64>, encrypted_segment_size: Option<u64>) {
        self.encryption_information.integrity_information.segments.push(Segment {
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
    fn test_policy_encoding() {
        let mut manifest = TdfManifest::new(
            "0.payload".to_string(),
            "http://kas.example.com:4000".to_string(),
        );

        let policy = r#"{"uuid":"test","body":{"attributes":[],"dissem":["user@example.com"]}}"#;
        manifest.set_policy(policy);

        let decoded_policy = manifest.get_policy().unwrap();
        assert_eq!(policy, decoded_policy);
    }
}