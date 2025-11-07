//! KAS public key retrieval and parsing
//!
//! This module provides functionality to fetch and parse KAS public keys
//! from an OpenTDF platform for RSA key wrapping operations.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "kas")]
use reqwest::Client;

#[cfg(feature = "kas")]
use crate::rsa::{pkcs8::DecodePublicKey, RsaPublicKey};

/// Errors that can occur during KAS public key operations
#[derive(Debug, Error)]
pub enum KasKeyError {
    #[error("HTTP error: {0}")]
    HttpError(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("JSON parse error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("RSA parse error: {0}")]
    RsaParseError(String),

    #[cfg(feature = "kas")]
    #[error("Reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),
}

/// Response structure from KAS public key endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct KasPublicKeyResponse {
    #[serde(rename = "publicKey")]
    pub public_key: String, // PEM-encoded RSA public key
    pub kid: String, // Key ID
}

/// Fetch the KAS public key from the platform
///
/// # Arguments
///
/// * `kas_url` - Base URL of the KAS service (e.g., "http://localhost:8080/kas")
/// * `http_client` - HTTP client to use for the request
///
/// # Returns
///
/// The PEM-encoded RSA public key as a String
#[cfg(feature = "kas")]
pub async fn fetch_kas_public_key(
    kas_url: &str,
    http_client: &Client,
) -> Result<KasPublicKeyResponse, KasKeyError> {
    // Construct the public key endpoint URL
    let endpoint = if kas_url.ends_with("/kas") {
        format!("{}/v2/kas_public_key", kas_url)
    } else if kas_url.ends_with('/') {
        format!("{}v2/kas_public_key", kas_url)
    } else {
        format!("{}/v2/kas_public_key", kas_url)
    };

    // Make the HTTP GET request
    let response = http_client.get(&endpoint).send().await?;

    // Check for HTTP errors
    let status = response.status();
    if !status.is_success() {
        let error_body = response.text().await.unwrap_or_default();
        return Err(KasKeyError::HttpError(format!(
            "HTTP {}: {}",
            status, error_body
        )));
    }

    // Parse the JSON response
    let key_response: KasPublicKeyResponse = response.json().await?;

    Ok(key_response)
}

/// Parse and validate a PEM-encoded RSA public key
///
/// This function validates that the key is in proper PEM format and can be parsed as an RSA public key.
///
/// # Arguments
///
/// * `pem` - PEM-encoded RSA public key string
///
/// # Returns
///
/// The validated PEM string if parsing succeeds
#[cfg(feature = "kas")]
pub fn validate_rsa_public_key_pem(pem: &str) -> Result<String, KasKeyError> {
    // Try to parse the PEM to validate it
    RsaPublicKey::from_public_key_pem(pem).map_err(|e| {
        KasKeyError::RsaParseError(format!("Failed to parse RSA public key: {}", e))
    })?;

    Ok(pem.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kas_public_key_response_deserialization() {
        let json = r#"{
            "publicKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----\n",
            "kid": "r1"
        }"#;

        let response: KasPublicKeyResponse = serde_json::from_str(json).unwrap();
        assert!(response
            .public_key
            .starts_with("-----BEGIN PUBLIC KEY-----"));
        assert_eq!(response.kid, "r1");
    }

    #[cfg(feature = "kas")]
    #[test]
    fn test_validate_rsa_public_key_pem() {
        // This is a valid test RSA public key
        let valid_pem = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2dMTGDH4QhhB4aYg4d48
SrapeZD128mpRTRCvbQa5ZaDykVvs8jJ5USJSZErNZ/HVvPyX6gqvQv4HeprAT7i
En445s6sOqObeAYWc5FUatvk3R5KPtgqHOgQIPtXQXnahT7HwvZPCjYoawc2MGax
ejRg20the6MtJHh1K2hUGJ/ic7Hbvk2QMHqYvwjFva4q4Uz3cjiA4RXn4joxm8SE
gLUOPV7pWvv7JzZRRLYiXQAcTb4QvJMIwY997/r228sr+fgYjxK6O0QKPZI2iJ5H
PvJX+E+ceUD7JIZc87FvaA5OqwFUFXqJfYNU4ZE7d6ovRja8JwnErHa+7pEk6KkN
8wIDAQAB
-----END PUBLIC KEY-----"#;

        let result = validate_rsa_public_key_pem(valid_pem);
        assert!(result.is_ok());

        let invalid_pem = "not a valid pem";
        let result = validate_rsa_public_key_pem(invalid_pem);
        assert!(result.is_err());
    }
}
