//! KAS (Key Access Service) protocol types
//!
//! This module contains the data structures used in the KAS v2 rewrap protocol.
//! These types define the request/response format for key unwrapping operations.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// KAS client errors
#[derive(Debug, Error)]
pub enum KasError {
    #[error("HTTP error: {status} - {message}")]
    HttpError { status: u16, message: String },

    #[error("Access denied for resource '{resource}': {reason}")]
    AccessDenied { resource: String, reason: String },

    #[error("Authentication failed: {reason}")]
    AuthenticationFailed { reason: String },

    #[error("Invalid response from KAS: {reason}")]
    InvalidResponse {
        reason: String,
        expected: Option<String>,
    },

    #[error("Key unwrapping failed for algorithm '{algorithm}': {reason}")]
    UnwrapError { algorithm: String, reason: String },

    #[error("Cryptographic error: {operation} failed - {reason}")]
    CryptoError { operation: String, reason: String },

    #[error("JSON serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("JWT error: {operation} - {reason}")]
    JwtError { operation: String, reason: String },

    #[error("PKCS8 error: {0}")]
    Pkcs8Error(String),

    #[error("HTTP request failed: {method} {url} - {reason}")]
    RequestError {
        method: String,
        url: String,
        reason: String,
    },

    #[error("Network timeout after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    #[error("Invalid KAS configuration: {reason}")]
    ConfigError { reason: String },
}

impl KasError {
    /// Returns true if this error might be resolved by retrying the operation
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            KasError::HttpError { status, .. } if *status >= 500 && *status < 600,
        ) || matches!(self, KasError::Timeout { .. })
    }

    /// Returns a suggestion for how to fix this error, if available
    pub fn suggestion(&self) -> Option<&str> {
        match self {
            KasError::AuthenticationFailed { .. } => {
                Some("Verify OAuth token is valid and not expired")
            }
            KasError::AccessDenied { .. } => {
                Some("Check that the user has permissions for this resource")
            }
            KasError::Timeout { .. } => {
                Some("Check network connectivity or increase timeout value")
            }
            KasError::InvalidResponse { .. } => Some("Verify KAS server version compatibility"),
            _ => None,
        }
    }

    /// Returns an error code for programmatic error handling
    pub fn error_code(&self) -> &'static str {
        match self {
            KasError::HttpError { .. } => "HTTP_ERROR",
            KasError::AccessDenied { .. } => "ACCESS_DENIED",
            KasError::AuthenticationFailed { .. } => "AUTHENTICATION_FAILED",
            KasError::InvalidResponse { .. } => "INVALID_RESPONSE",
            KasError::UnwrapError { .. } => "UNWRAP_ERROR",
            KasError::CryptoError { .. } => "CRYPTO_ERROR",
            KasError::SerializationError(_) => "SERIALIZATION_ERROR",
            KasError::Base64Error(_) => "BASE64_ERROR",
            KasError::JwtError { .. } => "JWT_ERROR",
            KasError::Pkcs8Error(_) => "PKCS8_ERROR",
            KasError::RequestError { .. } => "REQUEST_ERROR",
            KasError::Timeout { .. } => "TIMEOUT",
            KasError::ConfigError { .. } => "CONFIG_ERROR",
        }
    }
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
