//! KAS (Key Access Service) client for WASM
//!
//! This module provides KAS integration for browser environments,
//! enabling secure key wrapping and rewrap protocol.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

/// KAS public key response structure
#[derive(Debug, Serialize, Deserialize)]
pub struct KasPublicKeyResponse {
    #[serde(rename = "publicKey")]
    pub public_key: String, // PEM-encoded RSA public key
    pub kid: String,        // Key ID
}

/// Fetch the KAS public key from the platform
///
/// Uses browser's Fetch API to retrieve the KAS public key.
///
/// # Arguments
///
/// * `kas_url` - Base URL of the KAS service (e.g., "http://localhost:8080/kas")
///
/// # Returns
///
/// The KAS public key response with PEM-encoded RSA public key and key ID
pub async fn fetch_kas_public_key(kas_url: &str) -> Result<KasPublicKeyResponse, String> {
    // Construct the public key endpoint URL
    let endpoint = if kas_url.ends_with("/kas") {
        format!("{}/v2/kas_public_key", kas_url)
    } else if kas_url.ends_with('/') {
        format!("{}v2/kas_public_key", kas_url)
    } else {
        format!("{}/v2/kas_public_key", kas_url)
    };

    // Create request
    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(&endpoint, &opts)
        .map_err(|e| format!("Failed to create request: {:?}", e))?;

    // Add headers
    request
        .headers()
        .set("Accept", "application/json")
        .map_err(|e| format!("Failed to set headers: {:?}", e))?;

    // Make the request using browser's fetch API
    let window = web_sys::window().ok_or("No window object available")?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("Fetch failed: {:?}", e))?;

    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| "Response is not a Response object")?;

    // Check status
    if !resp.ok() {
        return Err(format!("HTTP error: {}", resp.status()));
    }

    // Parse JSON
    let json = JsFuture::from(
        resp.json()
            .map_err(|e| format!("Failed to get JSON: {:?}", e))?,
    )
    .await
    .map_err(|e| format!("Failed to parse JSON: {:?}", e))?;

    // Convert to Rust struct
    let key_response: KasPublicKeyResponse = serde_wasm_bindgen::from_value(json)
        .map_err(|e| format!("Failed to deserialize response: {:?}", e))?;

    Ok(key_response)
}

/// Wrap a payload key with RSA-OAEP using KAS public key
///
/// This function wraps a symmetric payload key with an RSA public key using OAEP padding.
/// Uses SHA-1 for compatibility with the OpenTDF Go SDK.
///
/// # Arguments
///
/// * `payload_key` - The symmetric key to wrap (typically 32 bytes for AES-256)
/// * `kas_public_key_pem` - PEM-encoded RSA public key from KAS
///
/// # Returns
///
/// Base64-encoded wrapped key ready for inclusion in TDF manifest
pub fn wrap_key_with_rsa_oaep(
    payload_key: &[u8],
    kas_public_key_pem: &str,
) -> Result<String, String> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::{Oaep, RsaPublicKey};
    use sha1::Sha1;

    // Parse the PEM-encoded public key
    let public_key = RsaPublicKey::from_public_key_pem(kas_public_key_pem)
        .map_err(|e| format!("Failed to parse RSA public key: {}", e))?;

    // Create OAEP padding with SHA1 (for Go SDK compatibility)
    let padding = Oaep::new::<Sha1>();

    // Encrypt the payload key with RSA-OAEP
    let mut rng = rand::rngs::OsRng;
    let wrapped_key = public_key
        .encrypt(&mut rng, padding, payload_key)
        .map_err(|e| format!("Failed to wrap key: {}", e))?;

    // Encode as base64 for storage in manifest
    Ok(BASE64.encode(&wrapped_key))
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
}
