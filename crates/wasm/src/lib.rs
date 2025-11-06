use opentdf::{AttributeIdentifier, AttributePolicy, AttributeValue, Policy, Tdf, TdfArchive};
use std::collections::HashMap;
use std::io::Cursor;
use wasm_bindgen::prelude::*;

// Set up panic hook for better error messages in the browser
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Result type for WASM operations
#[wasm_bindgen]
pub struct WasmResult {
    success: bool,
    data: Option<String>,
    error: Option<String>,
}

#[wasm_bindgen]
impl WasmResult {
    #[wasm_bindgen(getter)]
    pub fn success(&self) -> bool {
        self.success
    }

    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Option<String> {
        self.data.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn error(&self) -> Option<String> {
        self.error.clone()
    }
}

impl WasmResult {
    fn ok(data: String) -> Self {
        WasmResult {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn err(error: String) -> Self {
        WasmResult {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

/// Create a TDF archive with encrypted data
///
/// # Arguments
/// * `data` - Base64-encoded data to encrypt
/// * `kas_url` - KAS (Key Access Service) URL
/// * `policy_json` - JSON string containing the policy
///
/// # Returns
/// Base64-encoded TDF archive
#[wasm_bindgen]
pub fn tdf_create(data: &str, kas_url: &str, policy_json: &str) -> WasmResult {
    match _tdf_create_impl(data, kas_url, policy_json) {
        Ok(result) => WasmResult::ok(result),
        Err(e) => WasmResult::err(e),
    }
}

fn _tdf_create_impl(data: &str, kas_url: &str, policy_json: &str) -> Result<String, String> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    // Decode base64 input data
    let data_bytes = BASE64
        .decode(data)
        .map_err(|e| format!("Failed to decode data: {}", e))?;

    // Parse policy
    let policy: Policy =
        serde_json::from_str(policy_json).map_err(|e| format!("Failed to parse policy: {}", e))?;

    // Create TDF
    let tdf_bytes = Tdf::encrypt(data_bytes)
        .kas_url(kas_url)
        .policy(policy)
        .to_bytes()
        .map_err(|e| format!("Failed to create TDF: {}", e))?;

    // Encode result as base64
    Ok(BASE64.encode(&tdf_bytes))
}

/// Read a TDF archive and return its manifest
///
/// # Arguments
/// * `tdf_data` - Base64-encoded TDF archive
///
/// # Returns
/// JSON string containing the TDF manifest
#[wasm_bindgen]
pub fn tdf_read(tdf_data: &str) -> WasmResult {
    match _tdf_read_impl(tdf_data) {
        Ok(result) => WasmResult::ok(result),
        Err(e) => WasmResult::err(e),
    }
}

fn _tdf_read_impl(tdf_data: &str) -> Result<String, String> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    // Decode base64 TDF data
    let tdf_bytes = BASE64
        .decode(tdf_data)
        .map_err(|e| format!("Failed to decode TDF: {}", e))?;

    // Open TDF archive from bytes using Cursor
    let cursor = Cursor::new(tdf_bytes);
    let mut archive = TdfArchive::new(cursor).map_err(|e| format!("Failed to open TDF: {}", e))?;

    // Get entry and manifest
    let entry = archive
        .by_index()
        .map_err(|e| format!("Failed to read TDF entry: {}", e))?;

    // Serialize manifest to JSON
    serde_json::to_string(&entry.manifest)
        .map_err(|e| format!("Failed to serialize manifest: {}", e))
}

/// Create a policy from JSON
///
/// # Arguments
/// * `policy_json` - JSON string containing policy definition
///
/// # Returns
/// JSON string of the validated policy
#[wasm_bindgen]
pub fn policy_create(policy_json: &str) -> WasmResult {
    match _policy_create_impl(policy_json) {
        Ok(result) => WasmResult::ok(result),
        Err(e) => WasmResult::err(e),
    }
}

fn _policy_create_impl(policy_json: &str) -> Result<String, String> {
    let policy: Policy =
        serde_json::from_str(policy_json).map_err(|e| format!("Failed to parse policy: {}", e))?;

    serde_json::to_string(&policy).map_err(|e| format!("Failed to serialize policy: {}", e))
}

/// Evaluate attribute-based access control policy
///
/// # Arguments
/// * `policy_json` - JSON string containing the attribute policy
/// * `attributes_json` - JSON string containing user attributes as key-value pairs
///
/// # Returns
/// Boolean indicating whether access should be granted
#[wasm_bindgen]
pub fn access_evaluate(policy_json: &str, attributes_json: &str) -> WasmResult {
    match _access_evaluate_impl(policy_json, attributes_json) {
        Ok(result) => WasmResult::ok(result.to_string()),
        Err(e) => WasmResult::err(e),
    }
}

fn _access_evaluate_impl(policy_json: &str, attributes_json: &str) -> Result<bool, String> {
    // Parse attribute policy
    let policy: AttributePolicy =
        serde_json::from_str(policy_json).map_err(|e| format!("Failed to parse policy: {}", e))?;

    // Parse user attributes
    let attrs: HashMap<String, serde_json::Value> = serde_json::from_str(attributes_json)
        .map_err(|e| format!("Failed to parse attributes: {}", e))?;

    // Convert to AttributeIdentifier -> AttributeValue map
    let mut user_attrs: HashMap<AttributeIdentifier, AttributeValue> = HashMap::new();
    for (key, value) in attrs {
        let attr_id = AttributeIdentifier::from_string(&key)
            .map_err(|e| format!("Invalid attribute identifier '{}': {}", key, e))?;

        let attr_value = match value {
            serde_json::Value::String(s) => AttributeValue::String(s),
            serde_json::Value::Number(n) => AttributeValue::Number(n.as_f64().unwrap_or(0.0)),
            serde_json::Value::Bool(b) => AttributeValue::Boolean(b),
            serde_json::Value::Array(arr) => {
                // Try to determine array type from first element
                if let Some(first) = arr.first() {
                    match first {
                        serde_json::Value::String(_) => {
                            let strings: Vec<String> = arr
                                .iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect();
                            AttributeValue::StringArray(strings)
                        }
                        serde_json::Value::Number(_) => {
                            let numbers: Vec<f64> = arr.iter().filter_map(|v| v.as_f64()).collect();
                            AttributeValue::NumberArray(numbers)
                        }
                        _ => {
                            return Err(format!(
                                "Unsupported array element type for attribute '{}'",
                                key
                            ))
                        }
                    }
                } else {
                    AttributeValue::StringArray(vec![])
                }
            }
            _ => return Err(format!("Unsupported value type for attribute '{}'", key)),
        };

        user_attrs.insert(attr_id, attr_value);
    }

    // Evaluate policy
    policy
        .evaluate(&user_attrs)
        .map_err(|e| format!("Policy evaluation failed: {}", e))
}

/// Create an attribute identifier from namespace:name format
///
/// # Arguments
/// * `identifier` - String in format "namespace:name"
///
/// # Returns
/// JSON string containing the attribute identifier
#[wasm_bindgen]
pub fn attribute_identifier_create(identifier: &str) -> WasmResult {
    match _attribute_identifier_create_impl(identifier) {
        Ok(result) => WasmResult::ok(result),
        Err(e) => WasmResult::err(e),
    }
}

fn _attribute_identifier_create_impl(identifier: &str) -> Result<String, String> {
    let attr_id = AttributeIdentifier::from_string(identifier)
        .map_err(|e| format!("Failed to create attribute identifier: {}", e))?;

    serde_json::to_string(&attr_id)
        .map_err(|e| format!("Failed to serialize attribute identifier: {}", e))
}

/// Get version information
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_version() {
        let v = version();
        assert!(!v.is_empty());
    }

    #[wasm_bindgen_test]
    fn test_attribute_identifier_create() {
        let result = attribute_identifier_create("gov.example:clearance");
        assert!(result.success());
        assert!(result.data().is_some());
    }

    #[wasm_bindgen_test]
    fn test_policy_create() {
        let policy_json = r#"{
            "uuid": "test-uuid",
            "body": {
                "attributes": [],
                "dissem": ["user@example.com"]
            }
        }"#;

        let result = policy_create(policy_json);
        assert!(result.success());
        assert!(result.data().is_some());
    }
}
