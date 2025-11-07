//! KAS (Key Access Service) protocol types
//!
//! This module contains the data structures used in the KAS v2 rewrap protocol.
//! These types define the request/response format for key unwrapping operations.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// KAS client errors
#[derive(Debug, Error)]
pub enum KasError {
    #[error("HTTP error: {0}")]
    HttpError(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Key unwrapping failed: {0}")]
    UnwrapError(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("JSON serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("JWT error: {0}")]
    JwtError(String),

    #[error("PKCS8 error: {0}")]
    Pkcs8Error(String),

    #[error("HTTP request error: {0}")]
    RequestError(String),
}

/// Unsigned rewrap request structure (before JWT signing)
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct UnsignedRewrapRequest {
    #[serde(rename = "clientPublicKey")]
    pub client_public_key: String,
    pub requests: Vec<PolicyRequest>,
}

/// Individual policy request entry
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PolicyRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    pub policy: Policy,
    #[serde(rename = "keyAccessObjects")]
    pub key_access_objects: Vec<KeyAccessObjectWrapper>,
}

/// Policy structure for KAS requests
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Policy {
    pub id: String,
    pub body: String, // Base64-encoded policy JSON
}

/// Key access object wrapper
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KeyAccessObjectWrapper {
    #[serde(rename = "keyAccessObjectId")]
    pub key_access_object_id: String,
    #[serde(rename = "keyAccessObject")]
    pub key_access_object: KeyAccessObject,
}

/// Key access object details
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KeyAccessObject {
    #[serde(rename = "type")]
    pub key_type: String,
    pub url: String,
    pub protocol: String,
    #[serde(rename = "wrappedKey")]
    pub wrapped_key: String,
    #[serde(rename = "policyBinding")]
    pub policy_binding: KasPolicyBinding,
    #[serde(rename = "encryptedMetadata", skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// Policy binding for KAS requests
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KasPolicyBinding {
    pub hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
}

/// Signed rewrap request wrapper
///
/// The `signed_request_token` field contains a complete JWT token.
/// Applications are responsible for creating this JWT externally.
/// See the examples directory for JWT creation patterns.
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SignedRewrapRequest {
    pub signed_request_token: String,
}

/// Rewrap response structure
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RewrapResponse {
    pub responses: Vec<PolicyRewrapResult>,
    #[serde(rename = "sessionPublicKey")]
    pub session_public_key: Option<String>,
}

/// Policy rewrap result
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PolicyRewrapResult {
    #[serde(rename = "policyId")]
    pub policy_id: String,
    pub results: Vec<KeyAccessRewrapResult>,
}

/// Individual key access rewrap result
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KeyAccessRewrapResult {
    #[serde(rename = "keyAccessObjectId")]
    pub key_access_object_id: String,
    pub status: String,
    #[serde(rename = "kasWrappedKey")]
    pub kas_wrapped_key: Option<String>,
    #[serde(rename = "entityWrappedKey")]
    pub entity_wrapped_key: Option<String>, // Legacy field
    pub error: Option<String>,
}
