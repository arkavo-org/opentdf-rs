use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value}; // Added Map
use sha2::Digest;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::Duration;
use tracing::{debug, error, info, warn};
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use uuid::Uuid;

// Import opentdf types
use opentdf::{
    AttributeCondition, AttributeIdentifier, AttributePolicy, AttributeValue, Operator, Policy,
    PolicyBody, TdfArchive, TdfArchiveBuilder, TdfEncryption, TdfManifest,
};

// --- Struct Definitions ---
#[derive(Deserialize, Serialize, Clone, Debug)]
struct RpcRequest {
    jsonrpc: String,
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Serialize, Debug)]
struct RpcResponse {
    jsonrpc: String,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Serialize, Debug)]
struct RpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<ErrorData>,
}

#[derive(Serialize, Debug)]
struct ErrorData {
    error_type: String,
    details: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    suggestion: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct TdfCreateParams {
    data: String, // Base64 encoded data
    kas_url: String,
    policy: Value,
}

#[derive(Deserialize, Serialize, Debug)]
struct TdfReadParams {
    tdf_data: String, // Base64 encoded TDF archive
}

#[derive(Deserialize, Debug)]
struct EncryptParams {
    data: String, // Base64 encoded data
}

#[derive(Deserialize, Debug)]
struct DecryptParams {
    encrypted_data: String, // Base64 encoded encrypted data
    iv: String,             // Base64 encoded initialization vector
    encrypted_key: String,  // Base64 encoded wrapped key
    #[allow(dead_code)] // Used in some implementations but not in our placeholder
    policy_key_hash: String, // Hash of the policy key for validation
    policy_key: String,     // Base64 encoded policy key for decryption
}

#[derive(Deserialize, Debug)]
struct PolicyCreateParams {
    attributes: Vec<Value>,
    dissemination: Vec<String>,
    valid_from: Option<String>,
    valid_to: Option<String>,
}

#[derive(Deserialize, Debug)]
struct PolicyValidateParams {
    policy: Value,
    tdf_data: String, // Base64 encoded TDF archive
}

#[derive(Deserialize, Debug, Default)]
struct AttributeDefineParams {
    #[serde(default)]
    namespace: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    values: Vec<String>,
    #[serde(default)]
    hierarchy: Option<Value>, // Keep as Value for flexibility
    #[serde(default)]
    namespaces: Option<Vec<Value>>,
    #[serde(default)]
    attributes: Option<Vec<Value>>,
    #[serde(default)]
    content: Option<Vec<Value>>,
}

#[derive(Deserialize, Debug)]
struct UserAttributesParams {
    user_id: String,
    attributes: Vec<Value>,
}

#[derive(Deserialize, Debug)]
struct AccessEvaluateParams {
    policy: Value,
    user_attributes: Value,
    context: Option<Value>,
}

#[derive(Deserialize, Debug)]
struct PolicyBindingVerifyParams {
    tdf_data: String,
    policy_key: String,
}
// --- Struct Definitions End ---

// --- Helper Functions ---
// Error type constants
const ERROR_TYPE_VALIDATION: &str = "VALIDATION_ERROR";
const ERROR_TYPE_CRYPTO: &str = "CRYPTO_ERROR";
const ERROR_TYPE_POLICY: &str = "POLICY_ERROR";
const ERROR_TYPE_TDF: &str = "TDF_ERROR";
const ERROR_TYPE_IO: &str = "IO_ERROR";
const ERROR_TYPE_ATTRIBUTE: &str = "ATTRIBUTE_ERROR";
const ERROR_TYPE_PERMISSION: &str = "PERMISSION_ERROR";
const ERROR_TYPE_SYSTEM: &str = "SYSTEM_ERROR";

fn create_error_response(id: Value, code: i32, message: String) -> RpcResponse {
    error!("Responding with error: code={}, message={}", code, message);
    RpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: None,
        error: Some(RpcError { 
            code, 
            message,
            data: None
        }),
    }
}

fn create_detailed_error(
    id: Value, 
    code: i32, 
    message: String, 
    error_type: &str, 
    details: String,
    suggestion: Option<String>
) -> RpcResponse {
    error!("Responding with detailed error: code={}, type={}, message={}", 
           code, error_type, message);
    
    RpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: None,
        error: Some(RpcError { 
            code, 
            message,
            data: Some(ErrorData {
                error_type: error_type.to_string(),
                details,
                suggestion,
            }),
        }),
    }
}

/// Log a security event with full audit details
fn log_security_event(
    event_type: &str,
    user_id: Option<&str>,
    object_id: Option<&str>,
    outcome: &str,
    details: &str,
    context: Option<&Value>
) {
    let timestamp = Utc::now().to_rfc3339();
    
    // Create structured event for security audit trail
    info!(
        timestamp = timestamp,
        event_type = event_type,
        user_id = user_id.unwrap_or("unknown"),
        object_id = object_id.unwrap_or("none"),
        outcome = outcome,
        details = details,
        context = context.map(|c| c.to_string()).unwrap_or_default(),
        "SECURITY_EVENT"
    );
}

fn create_success_response(id: Value, result: Value) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: Some(result),
        error: None,
    }
}
// --- Helper Functions End ---

type ResponseFuture = Pin<Box<dyn Future<Output = RpcResponse> + Send>>;

// --- Main Request Processor ---
fn process_request(req: RpcRequest) -> ResponseFuture {
    Box::pin(async move {
        debug!("Processing request: {:?}", req);

        if req.jsonrpc != "2.0" {
            return create_error_response(
                req.id,
                -32600,
                "Invalid Request: jsonrpc must be \"2.0\"".to_string(),
            );
        }

        match req.method.as_str() {
            "help" => {
                info!("Received help request for method '{}'", req.method);
                let help_info = json!({
                    "message": "OpenTDF MCP Server Help: List of available commands and usage.",
                    "commands": {
                         "help": { "description": "Displays this help message.", "usage": "/mcp opentdf help OR JSON-RPC method 'help'" },
                         "initialize": { "description": "Initializes the MCP server.", "usage": "Internal MCP handshake OR JSON-RPC method 'initialize'" },
                         "listTools": { "description": "Lists available tools.", "usage": "Internal MCP handshake OR JSON-RPC method 'listTools'/'tools/list'" },
                         "tdf_create": { "description": "Creates a TDF archive.", "usage": "/mcp opentdf tdf_create PARAMS | JSON-RPC 'tdf_create'" },
                         "tdf_read": { "description": "Reads and extracts data from TDF archives.", "usage": "/mcp opentdf tdf_read PARAMS | JSON-RPC 'tdf_read'" },
                         "encrypt": { "description": "Encrypts data.", "usage": "/mcp opentdf encrypt PARAMS | JSON-RPC 'encrypt'" },
                         "decrypt": { "description": "Decrypts data using provided keys.", "usage": "/mcp opentdf decrypt PARAMS | JSON-RPC 'decrypt'" },
                         "policy_create": { "description": "Creates a policy object.", "usage": "/mcp opentdf policy_create PARAMS | JSON-RPC 'policy_create'" },
                         "policy_validate": { "description": "Validates policy against TDF (placeholder).", "usage": "/mcp opentdf policy_validate PARAMS | JSON-RPC 'policy_validate'" },
                         "attribute_define": { "description": "Defines attributes/namespaces.", "usage": "/mcp opentdf attribute_define PARAMS | JSON-RPC 'attribute_define'" },
                         "attribute_list": { "description": "Lists attributes (example data).", "usage": "/mcp opentdf attribute_list {} | JSON-RPC 'attribute_list'" },
                         "namespace_list": { "description": "Lists namespaces (example data).", "usage": "/mcp opentdf namespace_list {} | JSON-RPC 'namespace_list'" },
                         "user_attributes": { "description": "Sets user attributes.", "usage": "/mcp opentdf user_attributes PARAMS | JSON-RPC 'user_attributes'" },
                         "access_evaluate": { "description": "Evaluates access against policy and attributes.", "usage": "/mcp opentdf access_evaluate PARAMS | JSON-RPC 'access_evaluate'" },
                         "policy_binding_verify": { "description": "Verifies cryptographic binding of policy to TDF.", "usage": "/mcp opentdf policy_binding_verify PARAMS | JSON-RPC 'policy_binding_verify'" }
                    }
                });
                create_success_response(req.id, help_info)
            }

            "initialize" => {
                // *** THIS SECTION IS CORRECTED TO SEND tools AS OBJECT ***
                info!("Received initialize request");
                // Define tool schemas concisely for brevity here, assume full definitions exist
                let tool_schemas = json!({
                    "tdf_create": {"description": "Creates TDF","schema": {"type": "object","properties": {"data": {"type": "string"},"kas_url": {"type": "string"},"policy": {"type": "object"}},"required": ["data", "kas_url", "policy"]}},
                    "tdf_read": {"description": "Reads TDF archives","schema": {"type": "object","properties": {"tdf_data": {"type": "string"}},"required": ["tdf_data"]}},
                    "encrypt": {"description": "Encrypts data","schema": {"type": "object","properties": {"data": {"type": "string"}},"required": ["data"]}},
                    "decrypt": {"description": "Decrypts data","schema": {"type": "object","properties": {"encrypted_data": {"type": "string"},"iv": {"type": "string"},"encrypted_key": {"type": "string"},"policy_key": {"type": "string"}},"required": ["encrypted_data", "iv", "encrypted_key", "policy_key"]}},
                    "policy_create": {"description": "Creates policy","schema": {"type": "object","properties": {"attributes": {"type": "array"},"dissemination": {"type": "array", "items": {"type": "string"}}},"required": ["attributes"]}},
                    "policy_validate": {"description": "Validates policy (placeholder)","schema": {"type": "object","properties": {"policy": {"type": "object"},"tdf_data": {"type": "string"}},"required": ["policy", "tdf_data"]}},
                    "attribute_define": {"description": "Defines attributes","schema": {"type": "object","oneOf": [{"properties": {"namespace": {"type": "string"},"name": {"type": "string"},"values": {"type": "array"}},"required": ["namespace", "name", "values"]},{"properties": {"namespaces": {"type": "array"}},"required": ["namespaces"]},{"properties": {"attributes": {"type": "array"}},"required": ["attributes"]},{"properties": {"content": {"type": "array"}},"required": ["content"]}]}},
                    "attribute_list": {"description": "Lists attributes (example)","schema": {"type": "object"}},
                    "namespace_list": {"description": "Lists namespaces (example)","schema": {"type": "object"}},
                    "user_attributes": {"description": "Sets user attributes","schema": {"type": "object","properties": {"user_id": {"type": "string"},"attributes": {"type": "array"}},"required": ["user_id", "attributes"]}},
                    "access_evaluate": {"description": "Evaluates access against policy and attributes","schema": {"type": "object","properties": {"policy": {"type": "object"},"user_attributes": {"type": "object"}},"required": ["policy", "user_attributes"]}},
                    "policy_binding_verify": {"description": "Verifies cryptographic binding of policy to TDF","schema": {"type": "object","properties": {"tdf_data": {"type": "string"},"policy_key": {"type": "string"}},"required": ["tdf_data", "policy_key"]}}
                });

                let mut tools_object = Map::new(); // Use serde_json::Map
                if let Value::Object(tool_map) = &tool_schemas {
                    for (tool_name, tool_def) in tool_map {
                        if let Value::Object(def) = tool_def {
                            let description = def
                                .get("description")
                                .and_then(|d| d.as_str())
                                .unwrap_or("");
                            let schema = def
                                .get("schema")
                                .cloned()
                                .unwrap_or_else(|| json!({"type": "object"}));
                            tools_object.insert(
                                tool_name.clone(),
                                json!({
                                    "description": description,
                                    "inputSchema": schema.clone(),
                                    "schema": schema
                                }),
                            );
                        }
                    }
                }

                let response_payload = json!({
                    "serverInfo": {"name": "opentdf-mcp-rust","version": "1.1.4"}, // Version updated
                    "protocolVersion": "2024-11-05", // Keep this for now
                    "capabilities": {
                        "tools": Value::Object(tools_object) // Use the object here
                    }
                });
                info!("Sending initialize response with tools OBJECT (Map)");
                create_success_response(req.id, response_payload)
                // *** END OF initialize HANDLER CORRECTION ***
            }

            "listTools" | "tools/list" => {
                // *** This should STILL return an ARRAY ***
                info!("Received listTools request for method '{}'", req.method);
                // Reuse the same schema definitions from initialize
                let tool_schemas = json!({
                    "tdf_create": {"description": "Creates TDF","schema": {"type": "object","properties": {"data": {"type": "string"},"kas_url": {"type": "string"},"policy": {"type": "object"}},"required": ["data", "kas_url", "policy"]}},
                    "tdf_read": {"description": "Reads TDF archives","schema": {"type": "object","properties": {"tdf_data": {"type": "string"}},"required": ["tdf_data"]}},
                    "encrypt": {"description": "Encrypts data","schema": {"type": "object","properties": {"data": {"type": "string"}},"required": ["data"]}},
                    "decrypt": {"description": "Decrypts data","schema": {"type": "object","properties": {"encrypted_data": {"type": "string"},"iv": {"type": "string"},"encrypted_key": {"type": "string"},"policy_key": {"type": "string"}},"required": ["encrypted_data", "iv", "encrypted_key", "policy_key"]}},
                    "policy_create": {"description": "Creates policy","schema": {"type": "object","properties": {"attributes": {"type": "array"},"dissemination": {"type": "array", "items": {"type": "string"}}},"required": ["attributes"]}},
                    "policy_validate": {"description": "Validates policy (placeholder)","schema": {"type": "object","properties": {"policy": {"type": "object"},"tdf_data": {"type": "string"}},"required": ["policy", "tdf_data"]}},
                    "attribute_define": {"description": "Defines attributes","schema": {"type": "object","oneOf": [{"properties": {"namespace": {"type": "string"},"name": {"type": "string"},"values": {"type": "array"}},"required": ["namespace", "name", "values"]},{"properties": {"namespaces": {"type": "array"}},"required": ["namespaces"]},{"properties": {"attributes": {"type": "array"}},"required": ["attributes"]},{"properties": {"content": {"type": "array"}},"required": ["content"]}]}},
                    "attribute_list": {"description": "Lists attributes (example)","schema": {"type": "object"}},
                    "namespace_list": {"description": "Lists namespaces (example)","schema": {"type": "object"}},
                    "user_attributes": {"description": "Sets user attributes","schema": {"type": "object","properties": {"user_id": {"type": "string"},"attributes": {"type": "array"}},"required": ["user_id", "attributes"]}},
                    "access_evaluate": {"description": "Evaluates access against policy and attributes","schema": {"type": "object","properties": {"policy": {"type": "object"},"user_attributes": {"type": "object"}},"required": ["policy", "user_attributes"]}},
                    "policy_binding_verify": {"description": "Verifies cryptographic binding of policy to TDF","schema": {"type": "object","properties": {"tdf_data": {"type": "string"},"policy_key": {"type": "string"}},"required": ["tdf_data", "policy_key"]}}
                });

                let mut tools_array = Vec::new(); // Keep as array here
                if let Value::Object(tool_map) = &tool_schemas {
                    for (tool_name, tool_def) in tool_map {
                        if let Value::Object(def) = tool_def {
                            let description = def
                                .get("description")
                                .and_then(|d| d.as_str())
                                .unwrap_or("");
                            let schema = def
                                .get("schema")
                                .cloned()
                                .unwrap_or_else(|| json!({"type": "object"}));
                            tools_array.push(json!({ // Push object with name inside
                                "name": tool_name,
                                "description": description,
                                "inputSchema": schema.clone(),
                                "schema": schema
                            }));
                        }
                    }
                }
                info!(
                    "Sending tools/list response with tools ARRAY ({} tools)",
                    tools_array.len()
                );
                create_success_response(req.id, json!({ "tools": tools_array }))
            }

            // --- TDF Operations ---
            "tdf_create" => {
                info!("Received tdf_create request");
                match serde_json::from_value::<TdfCreateParams>(req.params) {
                    Ok(p) => {
                        debug!("Parsed tdf_create params: {:?}", p);
                        let data = match base64::engine::general_purpose::STANDARD.decode(&p.data) {
                            Ok(data) => data,
                            Err(e) => {
                                return create_error_response(
                                    req.id,
                                    -32602,
                                    format!("Invalid base64 data: {}", e),
                                )
                            }
                        };
                        let tdf_encryption = match TdfEncryption::new() {
                            Ok(enc) => enc,
                            Err(e) => {
                                return create_error_response(
                                    req.id,
                                    -32000,
                                    format!("Failed to initialize encryption: {}", e),
                                )
                            }
                        };
                        let encrypted_payload = match tdf_encryption.encrypt(&data) {
                            Ok(payload) => payload,
                            Err(e) => {
                                return create_error_response(
                                    req.id,
                                    -32000,
                                    format!("Failed to encrypt data: {}", e),
                                )
                            }
                        };
                        let mut manifest =
                            TdfManifest::new("0.payload".to_string(), p.kas_url.clone());
                        manifest.encryption_information.method.algorithm =
                            "AES-256-GCM".to_string();
                        manifest.encryption_information.method.iv = encrypted_payload.iv.clone();
                        manifest.encryption_information.key_access[0].wrapped_key =
                            encrypted_payload.encrypted_key.clone();

                        match serde_json::from_value::<Policy>(p.policy.clone()) {
                            Ok(policy) => {
                                if let Err(e) = manifest.set_policy(&policy) {
                                    return create_error_response(
                                        req.id,
                                        -32000,
                                        format!("Failed to set structured policy: {}", e),
                                    );
                                }
                                if let Err(e) = manifest.encryption_information.key_access[0]
                                    .generate_policy_binding(&policy, tdf_encryption.policy_key())
                                {
                                    return create_error_response(
                                        req.id,
                                        -32000,
                                        format!(
                                            "Failed to generate structured policy binding: {}",
                                            e
                                        ),
                                    );
                                }
                                info!("Applied structured policy and binding.");
                            }
                            Err(e_struct) => {
                                warn!("Failed to parse policy as structured Policy ({}). Trying raw string.", e_struct);
                                match serde_json::to_string(&p.policy) {
                                    Ok(policy_str) => {
                                        manifest.set_policy_raw(&policy_str);
                                        if let Err(e) = manifest.encryption_information.key_access
                                            [0]
                                        .generate_policy_binding_raw(
                                            &policy_str,
                                            tdf_encryption.policy_key(),
                                        ) {
                                            return create_error_response(
                                                req.id,
                                                -32000,
                                                format!(
                                                    "Failed to generate raw policy binding: {}",
                                                    e
                                                ),
                                            );
                                        }
                                        info!("Applied raw policy string and binding.");
                                    }
                                    Err(e_str) => {
                                        return create_error_response(
                                            req.id,
                                            -32000,
                                            format!(
                                                "Failed to serialize fallback policy: {}",
                                                e_str
                                            ),
                                        )
                                    }
                                }
                            }
                        }
                        let temp_file = match tempfile::NamedTempFile::new() {
                            Ok(file) => file,
                            Err(e) => {
                                return create_error_response(
                                    req.id,
                                    -32000,
                                    format!("Failed to create temp file: {}", e),
                                )
                            }
                        };
                        let temp_path = temp_file.path().to_owned();
                        let mut builder = match TdfArchiveBuilder::new(&temp_path) {
                            Ok(builder) => builder,
                            Err(e) => {
                                return create_error_response(
                                    req.id,
                                    -32000,
                                    format!("Failed to create TDF archive builder: {}", e),
                                )
                            }
                        };
                        let encrypted_data_bytes = match base64::engine::general_purpose::STANDARD
                            .decode(&encrypted_payload.ciphertext)
                        {
                            Ok(data) => data,
                            Err(e) => {
                                return create_error_response(
                                    req.id,
                                    -32000,
                                    format!("Failed to decode ciphertext for archive: {}", e),
                                )
                            }
                        };
                        if let Err(e) = builder.add_entry(&manifest, &encrypted_data_bytes, 0) {
                            return create_error_response(
                                req.id,
                                -32000,
                                format!("Failed to add entry to archive: {}", e),
                            );
                        }
                        if let Err(e) = builder.finish() {
                            return create_error_response(
                                req.id,
                                -32000,
                                format!("Failed to finalize archive: {}", e),
                            );
                        }
                        let tdf_data_bytes = match std::fs::read(&temp_path) {
                            Ok(data) => data,
                            Err(e) => {
                                if let Err(e) = secure_delete_temp_file(&temp_path) {
                                    warn!("Failed to securely delete temporary file: {}", e);
                                    // Fall back to regular deletion if secure deletion fails
                                    let _ = std::fs::remove_file(&temp_path);
                                }
                                return create_error_response(
                                    req.id,
                                    -32000,
                                    format!("Failed to read created TDF file: {}", e),
                                );
                            }
                        };
                        if let Err(e) = secure_delete_temp_file(&temp_path) {
                            warn!("Failed to securely delete temporary file: {}", e);
                            // Fall back to regular deletion if secure deletion fails
                            let _ = std::fs::remove_file(&temp_path);
                        }
                        let tdf_base64 =
                            base64::engine::general_purpose::STANDARD.encode(&tdf_data_bytes);
                        let id = Uuid::new_v4().to_string();
                        info!(
                            "Successfully created TDF ({} bytes), returning base64.",
                            tdf_data_bytes.len()
                        );
                        create_success_response(req.id, json!({"id": id, "tdf_data": tdf_base64}))
                    }
                    Err(e) => create_error_response(
                        req.id,
                        -32602,
                        format!("Invalid params for tdf_create: {}", e),
                    ),
                }
            }

            "encrypt" => {
                info!("Received encrypt request");
                match serde_json::from_value::<EncryptParams>(req.params) {
                    Ok(p) => {
                        debug!("Parsed encrypt params: {:?}", p);
                        let data = match base64::engine::general_purpose::STANDARD.decode(&p.data) {
                            Ok(data) => data,
                            Err(e) => {
                                return create_error_response(
                                    req.id,
                                    -32602,
                                    format!("Invalid base64 data: {}", e),
                                )
                            }
                        };
                        let tdf_encryption = match TdfEncryption::new() {
                            Ok(enc) => enc,
                            Err(e) => {
                                return create_error_response(
                                    req.id,
                                    -32000,
                                    format!("Failed to initialize encryption: {}", e),
                                )
                            }
                        };
                        let encrypted_payload = match tdf_encryption.encrypt(&data) {
                            Ok(payload) => payload,
                            Err(e) => {
                                return create_error_response(
                                    req.id,
                                    -32000,
                                    format!("Failed to encrypt data: {}", e),
                                )
                            }
                        };
                        info!("Successfully encrypted data.");
                        create_success_response(
                            req.id,
                            json!({
                                "ciphertext": encrypted_payload.ciphertext, "iv": encrypted_payload.iv, "encrypted_key": encrypted_payload.encrypted_key,
                            }),
                        )
                    }
                    Err(e) => create_error_response(
                        req.id,
                        -32602,
                        format!("Invalid params for encrypt: {}", e),
                    ),
                }
            }

            "decrypt" => {
                info!("Received decrypt request");
                match serde_json::from_value::<DecryptParams>(req.params) {
                    Ok(p) => {
                        debug!("Parsed decrypt params: {:?}", p);

                        // Step 1: Decode all parameters
                        let encrypted_data = match base64::engine::general_purpose::STANDARD
                            .decode(&p.encrypted_data)
                        {
                            Ok(d) => d,
                            Err(e) => {
                                error!("Invalid base64 encrypted data: {}", e);
                                return create_error_response(
                                    req.id,
                                    -32602,
                                    format!("Invalid base64 encrypted data: {}", e),
                                );
                            }
                        };

                        let iv = match base64::engine::general_purpose::STANDARD.decode(&p.iv) {
                            Ok(d) => d,
                            Err(e) => {
                                error!("Invalid base64 IV: {}", e);
                                return create_error_response(
                                    req.id,
                                    -32602,
                                    format!("Invalid base64 IV: {}", e),
                                );
                            }
                        };

                        let encrypted_key = match base64::engine::general_purpose::STANDARD
                            .decode(&p.encrypted_key)
                        {
                            Ok(d) => d,
                            Err(e) => {
                                error!("Invalid base64 encrypted key: {}", e);
                                return create_error_response(
                                    req.id,
                                    -32602,
                                    format!("Invalid base64 encrypted key: {}", e),
                                );
                            }
                        };

                        let policy_key =
                            match base64::engine::general_purpose::STANDARD.decode(&p.policy_key) {
                                Ok(d) => d,
                                Err(e) => {
                                    error!("Invalid base64 policy key: {}", e);
                                    return create_error_response(
                                        req.id,
                                        -32602,
                                        format!("Invalid base64 policy key: {}", e),
                                    );
                                }
                            };

                        // Step 2: Calculate policy key hash for verification
                        let mut hasher = sha2::Sha256::new();
                        hasher.update(&policy_key);
                        let policy_key_hash =
                            base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
                        debug!("Calculated policy key hash: {}", policy_key_hash);

                        // Step 3: Check if policy_key_hash from params matches calculated hash (if provided)
                        if !p.policy_key_hash.is_empty() && p.policy_key_hash != policy_key_hash {
                            warn!(
                                "Policy key hash mismatch: Expected {}, got {}",
                                p.policy_key_hash, policy_key_hash
                            );
                            // We don't return an error here as this check is optional
                        }

                        // Step 4: Create TdfEncryption instance (or reuse if possible)
                        let mut tdf_encryption = match TdfEncryption::with_policy_key(&policy_key) {
                            Ok(enc) => enc,
                            Err(e) => {
                                error!("Failed to initialize TdfEncryption with policy key: {}", e);
                                return create_error_response(
                                    req.id,
                                    -32000,
                                    format!(
                                        "Failed to initialize encryption with policy key: {}",
                                        e
                                    ),
                                );
                            }
                        };

                        // Step 5: Decrypt the data
                        let decryption_start = std::time::Instant::now();

                        let decrypted_data =
                            match tdf_encryption.decrypt(&encrypted_data, &iv, &encrypted_key) {
                                Ok(data) => data,
                                Err(e) => {
                                    error!("Failed to decrypt data: {}", e);
                                    return create_error_response(
                                        req.id,
                                        -32000,
                                        format!("Failed to decrypt data: {}", e),
                                    );
                                }
                            };

                        let decryption_duration = decryption_start.elapsed();

                        info!(
                            "Successfully decrypted {} bytes in {:.2?}",
                            decrypted_data.len(),
                            decryption_duration
                        );

                        // Step 6: Return decrypted data encoded in base64
                        create_success_response(
                            req.id,
                            json!({
                                "data": base64::engine::general_purpose::STANDARD.encode(&decrypted_data),
                                "metrics": {
                                    "decryption_time_ms": decryption_duration.as_millis(),
                                    "original_size": encrypted_data.len(),
                                    "decrypted_size": decrypted_data.len()
                                }
                            }),
                        )
                    }
                    Err(e) => create_error_response(
                        req.id,
                        -32602,
                        format!("Invalid params for decrypt: {}", e),
                    ),
                }
            }

            "tdf_read" => {
                info!("Received tdf_read request");
                match serde_json::from_value::<TdfReadParams>(req.params) {
                    Ok(p) => {
                        debug!("Parsed tdf_read params: {:?}", p);

                        // Step 1: Decode TDF data from base64
                        let tdf_bytes =
                            match base64::engine::general_purpose::STANDARD.decode(&p.tdf_data) {
                                Ok(data) => data,
                                Err(e) => {
                                    error!("Invalid base64 TDF data: {}", e);
                                    return create_detailed_error(
                                        req.id,
                                        -32602,
                                        "Invalid TDF data format".to_string(),
                                        ERROR_TYPE_VALIDATION,
                                        format!("The provided TDF data is not valid base64: {}", e),
                                        Some("Ensure your TDF data is properly base64-encoded before sending".to_string())
                                    );
                                }
                            };

                        // Step 2: Create a temporary file to store the TDF
                        let temp_file = match tempfile::NamedTempFile::new() {
                            Ok(file) => file,
                            Err(e) => {
                                error!("Failed to create temporary file: {}", e);
                                return create_detailed_error(
                                    req.id,
                                    -32000,
                                    "File system operation error".to_string(),
                                    ERROR_TYPE_IO,
                                    format!("Failed to create temporary file for TDF processing: {}", e),
                                    Some("Check system permissions and available disk space".to_string())
                                );
                            }
                        };

                        // Step 3: Write the TDF bytes to the temporary file
                        let temp_path = temp_file.path().to_owned();
                        if let Err(e) = std::fs::write(&temp_path, &tdf_bytes) {
                            error!("Failed to write TDF data to temporary file: {}", e);
                            return create_error_response(
                                req.id,
                                -32000,
                                format!("Failed to write TDF data to temporary file: {}", e),
                            );
                        }

                        // Step 4: Open the TDF archive
                        let mut archive = match TdfArchive::open(&temp_path) {
                            Ok(archive) => archive,
                            Err(e) => {
                                error!("Failed to open TDF archive: {}", e);
                                return create_error_response(
                                    req.id,
                                    -32000,
                                    format!("Failed to open TDF archive: {}", e),
                                );
                            }
                        };

                        // Step 5: Extract the entry (assuming first entry for now)
                        let entry = match archive.by_index() {
                            Ok(entry) => entry,
                            Err(e) => {
                                error!("Failed to read TDF entry: {}", e);
                                return create_error_response(
                                    req.id,
                                    -32000,
                                    format!("Failed to read TDF entry: {}", e),
                                );
                            }
                        };

                        // Step 6: Extract manifest and encrypted payload
                        let manifest = entry.manifest;
                        let payload = entry.payload;
                        let payload_base64 =
                            base64::engine::general_purpose::STANDARD.encode(&payload);

                        // Step 7: Get policy from manifest if available
                        let policy = match manifest.get_policy() {
                            Ok(policy) => Some(policy),
                            Err(e) => {
                                warn!("Failed to parse policy from manifest: {}", e);
                                None
                            }
                        };

                        // Step 8: Prepare response payload
                        let manifest_json = match serde_json::to_value(&manifest) {
                            Ok(json) => json,
                            Err(e) => {
                                error!("Failed to serialize manifest: {}", e);
                                return create_error_response(
                                    req.id,
                                    -32000,
                                    format!("Failed to serialize manifest: {}", e),
                                );
                            }
                        };

                        // Step 9: Clean up the temporary file
                        if let Err(e) = secure_delete_temp_file(&temp_path) {
                            warn!("Failed to securely delete temporary file: {}", e);
                            // Fall back to regular deletion if secure deletion fails
                            let _ = std::fs::remove_file(&temp_path);
                        }

                        let payload_info = json!({
                            "encrypted": true,
                            "size": payload.len(),
                            "algorithm": manifest.encryption_information.method.algorithm.clone(),
                            "iv": manifest.encryption_information.method.iv.clone(),
                            "key_access": {
                                "wrapped_key": manifest.encryption_information.key_access[0].wrapped_key.clone(),
                                "url": manifest.encryption_information.key_access[0].url.clone(),
                                "policy_binding": {
                                    "alg": manifest.encryption_information.key_access[0].policy_binding.alg.clone(),
                                    "hash": manifest.encryption_information.key_access[0].policy_binding.hash.clone()
                                }
                            }
                        });

                        let policy_json = match policy {
                            Some(p) => match serde_json::to_value(&p) {
                                Ok(json) => json,
                                Err(e) => {
                                    warn!("Failed to serialize policy: {}", e);
                                    json!(null)
                                }
                            },
                            None => json!(null),
                        };

                        info!(
                            "Successfully read TDF with {} bytes of encrypted payload",
                            payload.len()
                        );

                        create_success_response(
                            req.id,
                            json!({
                                "manifest": manifest_json,
                                "payload": payload_base64,
                                "payload_info": payload_info,
                                "policy": policy_json,
                                "metadata": {
                                    "mime_type": manifest.payload.mime_type,
                                    "tdf_spec_version": manifest.payload.tdf_spec_version
                                }
                            }),
                        )
                    }
                    Err(e) => create_error_response(
                        req.id,
                        -32602,
                        format!("Invalid params for tdf_read: {}", e),
                    ),
                }
            }

            // --- Policy and Attribute Operations ---
            "policy_create" => {
                info!("Received policy_create request");
                match serde_json::from_value::<PolicyCreateParams>(req.params) {
                    Ok(p) => {
                        debug!("Parsed policy_create params: {:?}", p);
                        let mut attribute_policies = Vec::new();
                        for attr_value in p.attributes {
                            match convert_to_attribute_policy(attr_value) {
                                Ok(policy) => attribute_policies.push(policy),
                                Err(e) => {
                                    return create_error_response(
                                        req.id,
                                        -32602,
                                        format!("Invalid attribute policy definition: {}", e),
                                    )
                                }
                            }
                        }
                        let valid_from = match p.valid_from {
                            Some(s) => match chrono::DateTime::parse_from_rfc3339(&s) {
                                Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
                                Err(e) => {
                                    return create_error_response(
                                        req.id,
                                        -32602,
                                        format!("Invalid valid_from date: {}", e),
                                    )
                                }
                            },
                            None => None,
                        };
                        let valid_to = match p.valid_to {
                            Some(s) => match chrono::DateTime::parse_from_rfc3339(&s) {
                                Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
                                Err(e) => {
                                    return create_error_response(
                                        req.id,
                                        -32602,
                                        format!("Invalid valid_to date: {}", e),
                                    )
                                }
                            },
                            None => None,
                        };
                        let policy = Policy {
                            uuid: Uuid::new_v4().to_string(),
                            valid_from,
                            valid_to,
                            body: PolicyBody {
                                attributes: attribute_policies,
                                dissem: p.dissemination,
                            },
                        };
                        let policy_json = match serde_json::to_value(&policy) {
                            Ok(json) => json,
                            Err(e) => {
                                return create_error_response(
                                    req.id,
                                    -32000,
                                    format!("Failed to serialize policy: {}", e),
                                )
                            }
                        };
                        let policy_hash = match serde_json::to_string(&policy) {
                            Ok(s) => {
                                let mut h = sha2::Sha256::new();
                                h.update(s.as_bytes());
                                base64::engine::general_purpose::STANDARD.encode(h.finalize())
                            }
                            Err(e) => {
                                return create_error_response(
                                    req.id,
                                    -32000,
                                    format!("Failed to hash policy: {}", e),
                                )
                            }
                        };
                        info!("Successfully created policy with UUID: {}", policy.uuid);
                        create_success_response(
                            req.id,
                            json!({"policy": policy_json, "policy_hash": policy_hash}),
                        )
                    }
                    Err(e) => create_error_response(
                        req.id,
                        -32602,
                        format!("Invalid params for policy_create: {}", e),
                    ),
                }
            }

            "policy_validate" => {
                info!("Received policy_validate request");
                match serde_json::from_value::<PolicyValidateParams>(req.params) {
                    Ok(p) => {
                        debug!("Parsed policy_validate params: {:?}", p);
                        // Use the fields to avoid dead code warnings
                        let policy_str = serde_json::to_string(&p.policy).unwrap_or_default();
                        let tdf_data_len = p.tdf_data.len();
                        debug!("Policy validation checking policy ({} chars) against TDF data ({} bytes)", 
                            policy_str.len(), tdf_data_len);

                        warn!("policy_validate endpoint is currently a placeholder.");
                        create_success_response(
                            req.id,
                            json!({"valid": true, "reasons": ["Validation logic not implemented"]}),
                        )
                    }
                    Err(e) => create_error_response(
                        req.id,
                        -32602,
                        format!("Invalid params for policy_validate: {}", e),
                    ),
                }
            }

            "attribute_define" => {
                info!("Received attribute_define request");
                debug!(
                    "Attribute define RAW params: {}",
                    serde_json::to_string(&req.params).unwrap_or_default()
                );
                let params: AttributeDefineParams = match serde_json::from_value(req.params.clone())
                {
                    Ok(p) => {
                        info!("Successfully parsed attribute_define params via from_value.");
                        p
                    }
                    Err(e) => {
                        warn!("Strict parsing failed for attribute_define: {}. Attempting manual fallback.", e);
                        let mut fallback_params = AttributeDefineParams::default();
                        let mut format_detected = false;
                        if let Value::Object(obj) = &req.params {
                            if let Some(Value::Array(namespaces)) = obj.get("namespaces") {
                                fallback_params.namespaces = Some(namespaces.clone());
                                info!("Fallback: Detected 'namespaces'.");
                                format_detected = true;
                            } else if let Some(Value::Array(attributes)) = obj.get("attributes") {
                                fallback_params.attributes = Some(attributes.clone());
                                if let Some(ns) = obj.get("namespace").and_then(|v| v.as_str()) {
                                    fallback_params.namespace = ns.to_string();
                                }
                                info!("Fallback: Detected 'attributes'.");
                                format_detected = true;
                            } else if let Some(Value::Array(content)) = obj.get("content") {
                                fallback_params.content = Some(content.clone());
                                info!("Fallback: Detected 'content'.");
                                format_detected = true;
                            }
                        }
                        if !format_detected {
                            error!("Fallback failed for attribute_define. Strict error: {}", e);
                            return create_error_response(
                                req.id,
                                -32602,
                                format!("Invalid params structure for attribute_define: {}", e),
                            );
                        }
                        fallback_params
                    }
                };
                debug!("Parsed/merged attribute_define params: {:?}", params);
                // Determine format and process
                let result_attribute: Option<Value> = if let Some(content) = &params.content {
                    info!("Processing attribute_define: content format");
                    if content.is_empty() {
                        None
                    } else {
                        Some(
                            json!({"namespace": "content_ns", "name": "content_attr", "values": ["value"], "id": Uuid::new_v4().to_string(), "source": "content_format"}),
                        )
                    }
                } else if let Some(namespaces) = &params.namespaces {
                    info!("Processing attribute_define: namespaces format");
                    if namespaces.is_empty() {
                        None
                    } else {
                        let ns = &namespaces[0];
                        let ns_name = ns
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("default_ns");
                        let attrs: Vec<String> = ns
                            .get("attributes")
                            .and_then(|a| a.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        Some(
                            json!({"namespace": ns_name, "name": "attribute", "values": attrs, "id": Uuid::new_v4().to_string(), "source": "namespaces_format"}),
                        )
                    }
                } else if let Some(attributes) = &params.attributes {
                    info!("Processing attribute_define: attributes format");
                    if attributes.is_empty() {
                        None
                    } else {
                        let attr_values: Vec<String> = attributes
                            .iter()
                            .filter_map(|attr| {
                                attr.get("name").and_then(|n| n.as_str()).map(String::from)
                            })
                            .collect();
                        let namespace = if params.namespace.is_empty() {
                            "default_ns"
                        } else {
                            &params.namespace
                        };
                        Some(
                            json!({"namespace": namespace, "name": "attribute", "values": attr_values, "id": Uuid::new_v4().to_string(), "source": "attributes_format"}),
                        )
                    }
                } else if !params.namespace.is_empty() && !params.name.is_empty() {
                    if params.values.is_empty() && params.hierarchy.is_none() {
                        warn!("Standard attribute format missing 'values' and 'hierarchy'.");
                        None
                    } else {
                        info!("Processing attribute_define: standard format");
                        let hierarchy_info = params.hierarchy.map(|h| json!(h));
                        Some(
                            json!({"namespace": params.namespace, "name": params.name, "values": params.values, "hierarchy": hierarchy_info, "id": Uuid::new_v4().to_string(), "source": "standard_format"}),
                        )
                    }
                } else {
                    None
                };
                match result_attribute {
                    Some(attribute_def) => {
                        info!(
                            "Successfully defined attribute: {}",
                            serde_json::to_string(&attribute_def).unwrap_or_default()
                        );
                        create_success_response(
                            req.id,
                            json!({"attribute": attribute_def, "status": "defined"}),
                        )
                    }
                    None => {
                        error!("Could not define attribute: No valid format/fields.");
                        create_error_response(
                            req.id,
                            -32602,
                            "Invalid params for attribute_define.".to_string(),
                        )
                    }
                }
            }

            "attribute_list" => {
                info!("Received attribute_list request");
                debug!(
                    "Attribute list params: {}",
                    serde_json::to_string(&req.params).unwrap_or_default()
                );
                let example_attributes = vec![
                    json!({"namespace": "example.com", "name": "clearance", "values": ["L1", "L2"], "id": "uuid1"}),
                    json!({"namespace": "example.com", "name": "project", "values": ["X", "Y"], "id": "uuid2"}),
                ];
                info!("Returning {} example attributes", example_attributes.len());

                // --- MODIFICATION START ---
                // 1. Prepare the original data structure
                let original_result_data = json!({
                    "attributes": example_attributes,
                    "count": example_attributes.len(), // Use .len() here
                    "timestamp": Utc::now().to_rfc3339()
                });

                // 2. Format it as a pretty JSON string
                let formatted_text = match serde_json::to_string_pretty(&original_result_data) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to serialize attribute list result to string: {}", e);
                        // Fallback error message
                        format!(
                            "{{\"error\": \"Failed to format attribute list result: {}\"}}",
                            e
                        )
                    }
                };

                // 3. Create the Claude-expected wrapper structure
                let claude_result_payload = json!({
                    "content": [
                        {
                            "type": "text", // Assuming Claude expects text content
                            "text": formatted_text
                        }
                    ]
                });

                // 4. Return the wrapped structure
                create_success_response(req.id, claude_result_payload)
                // --- MODIFICATION END ---
            }

            "namespace_list" => {
                info!("Received namespace_list request");
                debug!(
                    "Namespace list params: {}",
                    serde_json::to_string(&req.params).unwrap_or_default()
                );
                let example_namespaces = vec![
                    json!({"name": "example.com", "attributes": ["clearance", "project"]}),
                    json!({"name": "gov.dept.agency", "attributes": ["classification"]}),
                ];
                info!("Returning {} example namespaces", example_namespaces.len());

                // --- MODIFICATION START ---
                // 1. Prepare the original data structure
                let original_result_data = json!({
                    "namespaces": example_namespaces,
                    "count": example_namespaces.len(), // Use .len() here
                    "timestamp": Utc::now().to_rfc3339()
                });

                // 2. Format it as a pretty JSON string
                let formatted_text = match serde_json::to_string_pretty(&original_result_data) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to serialize namespace list result to string: {}", e);
                        // Fallback error message
                        format!(
                            "{{\"error\": \"Failed to format namespace list result: {}\"}}",
                            e
                        )
                    }
                };

                // 3. Create the Claude-expected wrapper structure
                let claude_result_payload = json!({
                    "content": [
                        {
                            "type": "text", // Assuming Claude expects text content
                            "text": formatted_text
                        }
                    ]
                });

                // 4. Return the wrapped structure
                create_success_response(req.id, claude_result_payload)
                // --- MODIFICATION END ---
            }

            "user_attributes" => {
                info!("Received user_attributes request");
                match serde_json::from_value::<UserAttributesParams>(req.params) {
                    Ok(p) => {
                        debug!("Parsed user_attributes params: {:?}", p);
                        info!("Assigning attributes for user: {}", p.user_id);
                        // Process attributes here
                        let processed_attributes: Vec<Value> = p
                            .attributes
                            .iter()
                            .filter_map(|attr| {
                                // Extract the attribute fields
                                let ns = attr.get("namespace").and_then(|v| v.as_str());
                                let name = attr.get("name").and_then(|v| v.as_str());
                                let value = attr.get("value");

                                // Only construct the JSON if all fields are Some()
                                if let (Some(ns), Some(name), Some(value)) = (ns, name, value) {
                                    Some(json!({
                                        "attribute_uri": format!("{}/attr/{}", ns, name),
                                        "value": value
                                    }))
                                } else {
                                    warn!("Skipping invalid attribute format: {:?}", attr);
                                    None
                                }
                            })
                            .collect();

                        info!(
                            "Processed {} attributes for user {}",
                            processed_attributes.len(),
                            p.user_id
                        );
                        create_success_response(
                            req.id,
                            json!({
                                "user_id": p.user_id,
                                "attributes_assigned": processed_attributes,
                                "status": "attributes_assigned"
                            }),
                        )
                    }
                    Err(e) => create_error_response(
                        req.id,
                        -32602,
                        format!("Invalid params for user_attributes: {}", e),
                    ),
                }
            }

            "access_evaluate" => {
                info!("Received access_evaluate request");
                match serde_json::from_value::<AccessEvaluateParams>(req.params) {
                    Ok(p) => {
                        debug!("Parsed access_evaluate params: {:?}", p);

                        // Extract policy from request
                        let policy = match serde_json::from_value::<Policy>(p.policy.clone()) {
                            Ok(policy) => policy,
                            Err(e) => {
                                error!("Failed to parse policy: {}", e);
                                return create_error_response(
                                    req.id,
                                    -32602,
                                    format!("Invalid policy format: {}", e),
                                );
                            }
                        };

                        // Get policy UUID for logging
                        let policy_uuid = &policy.uuid;

                        // Extract user attributes from request
                        let user_id = p
                            .user_attributes
                            .get("user_id")
                            .and_then(|u| u.as_str())
                            .unwrap_or("unknown");
                        info!(
                            policy_uuid = policy_uuid,
                            user_id = user_id,
                            "Starting access evaluation"
                        );

                        // Convert JSON user attributes to the format required by policy evaluation
                        let mut attribute_map = HashMap::new();

                        if let Some(user_attrs) = p
                            .user_attributes
                            .get("attributes")
                            .and_then(|a| a.as_array())
                        {
                            for attr in user_attrs {
                                if let (Some(namespace), Some(name), Some(value)) = (
                                    attr.get("namespace").and_then(|n| n.as_str()),
                                    attr.get("name").and_then(|n| n.as_str()),
                                    attr.get("value"),
                                ) {
                                    let attr_id = AttributeIdentifier::new(namespace, name);

                                    // Convert the JSON value to AttributeValue
                                    let attr_value = if let Some(s) = value.as_str() {
                                        AttributeValue::String(s.to_string())
                                    } else if let Some(n) = value.as_f64() {
                                        AttributeValue::Number(n)
                                    } else if let Some(b) = value.as_bool() {
                                        AttributeValue::Boolean(b)
                                    } else if let Some(a) = value.as_array() {
                                        if a.is_empty() {
                                            AttributeValue::StringArray(vec![])
                                        } else if a.iter().all(|v| v.is_string()) {
                                            let strings: Vec<String> = a
                                                .iter()
                                                .filter_map(|v| v.as_str().map(String::from))
                                                .collect();
                                            AttributeValue::StringArray(strings)
                                        } else if a.iter().all(|v| v.is_number()) {
                                            let numbers: Vec<f64> =
                                                a.iter().filter_map(|v| v.as_f64()).collect();
                                            AttributeValue::NumberArray(numbers)
                                        } else {
                                            warn!("Mixed array types in attribute value, skipping: {}", attr);
                                            continue;
                                        }
                                    } else if let Some(dt_str) =
                                        value.get("$datetime").and_then(|v| v.as_str())
                                    {
                                        match chrono::DateTime::parse_from_rfc3339(dt_str) {
                                            Ok(dt) => AttributeValue::DateTime(
                                                dt.with_timezone(&chrono::Utc),
                                            ),
                                            Err(e) => {
                                                warn!("Invalid datetime format in attribute value: {}", e);
                                                continue;
                                            }
                                        }
                                    } else {
                                        warn!("Unsupported value type in attribute: {}", value);
                                        continue;
                                    };

                                    attribute_map.insert(attr_id, attr_value);
                                } else {
                                    warn!("Skipping malformed attribute: {}", attr);
                                }
                            }
                        }

                        debug!(
                            "Constructed {} user attributes for evaluation",
                            attribute_map.len()
                        );

                        // Consider context attributes if provided
                        if let Some(context) = &p.context {
                            debug!("Processing context attributes: {}", context);
                            if let Some(context_attrs) =
                                context.get("attributes").and_then(|a| a.as_array())
                            {
                                for attr in context_attrs {
                                    if let (Some(namespace), Some(name), Some(value)) = (
                                        attr.get("namespace").and_then(|n| n.as_str()),
                                        attr.get("name").and_then(|n| n.as_str()),
                                        attr.get("value"),
                                    ) {
                                        let attr_id = AttributeIdentifier::new(namespace, name);

                                        // Same conversion logic as user attributes
                                        let attr_value = if let Some(s) = value.as_str() {
                                            AttributeValue::String(s.to_string())
                                        } else if let Some(n) = value.as_f64() {
                                            AttributeValue::Number(n)
                                        } else if let Some(b) = value.as_bool() {
                                            AttributeValue::Boolean(b)
                                        } else if let Some(a) = value.as_array() {
                                            if a.is_empty() {
                                                AttributeValue::StringArray(vec![])
                                            } else if a.iter().all(|v| v.is_string()) {
                                                let strings: Vec<String> = a
                                                    .iter()
                                                    .filter_map(|v| v.as_str().map(String::from))
                                                    .collect();
                                                AttributeValue::StringArray(strings)
                                            } else if a.iter().all(|v| v.is_number()) {
                                                let numbers: Vec<f64> =
                                                    a.iter().filter_map(|v| v.as_f64()).collect();
                                                AttributeValue::NumberArray(numbers)
                                            } else {
                                                warn!("Mixed array types in context attribute value, skipping: {}", attr);
                                                continue;
                                            }
                                        } else if let Some(dt_str) =
                                            value.get("$datetime").and_then(|v| v.as_str())
                                        {
                                            match chrono::DateTime::parse_from_rfc3339(dt_str) {
                                                Ok(dt) => AttributeValue::DateTime(
                                                    dt.with_timezone(&chrono::Utc),
                                                ),
                                                Err(e) => {
                                                    warn!("Invalid datetime format in context attribute value: {}", e);
                                                    continue;
                                                }
                                            }
                                        } else {
                                            warn!(
                                                "Unsupported value type in context attribute: {}",
                                                value
                                            );
                                            continue;
                                        };

                                        // Context attributes can override user attributes when necessary
                                        attribute_map.insert(attr_id, attr_value);
                                    }
                                }
                            }
                        }

                        // Evaluate the policy against the attributes
                        let evaluation_start = std::time::Instant::now();
                        let evaluation_result = match policy.evaluate(&attribute_map) {
                            Ok(result) => result,
                            Err(e) => {
                                error!("Policy evaluation error: {}", e);
                                return create_error_response(
                                    req.id,
                                    -32000,
                                    format!("Policy evaluation error: {}", e),
                                );
                            }
                        };
                        let evaluation_duration = evaluation_start.elapsed();

                        // Track individual condition results for more detailed feedback
                        let mut condition_results = Vec::new();

                        // Process each policy condition to provide detailed results
                        // This is simplified - in a real implementation you might track individual condition results
                        for (i, policy_condition) in policy.body.attributes.iter().enumerate() {
                            let condition_result = match policy_condition.evaluate(&attribute_map) {
                                Ok(result) => result,
                                Err(e) => {
                                    warn!("Error evaluating condition {}: {}", i, e);
                                    false
                                }
                            };

                            // Serialize the condition for the response
                            let condition_json = match serde_json::to_value(policy_condition) {
                                Ok(json) => json,
                                Err(e) => {
                                    warn!("Error serializing condition: {}", e);
                                    json!({"error": format!("Failed to serialize: {}", e)})
                                }
                            };

                            condition_results.push(json!({
                                "condition": condition_json,
                                "satisfied": condition_result,
                                "condition_index": i
                            }));
                        }

                        // Log comprehensive security event for audit trail
                        log_security_event(
                            "access_evaluation",
                            Some(user_id),
                            Some(policy_uuid),
                            if evaluation_result { "granted" } else { "denied" },
                            &format!("Policy evaluation completed in {}ms", evaluation_duration.as_millis()),
                            Some(&json!({
                                "attributes_evaluated": attribute_map.len(),
                                "condition_results": condition_results,
                                "evaluation_time": Utc::now().to_rfc3339(),
                                "evaluation_duration_ms": evaluation_duration.as_millis(),
                                "context_attributes": p.context.clone()
                            }))
                        );
                        
                        info!(
                            policy_uuid = policy_uuid,
                            user_id = user_id,
                            access_granted = evaluation_result,
                            evaluation_ms = evaluation_duration.as_millis() as u64,
                            "Access evaluation complete"
                        );

                        create_success_response(
                            req.id,
                            json!({
                                "access_granted": evaluation_result,
                                "evaluation_time": Utc::now().to_rfc3339(),
                                "evaluation_duration_ms": evaluation_duration.as_millis(),
                                "condition_results": condition_results,
                                "policy_uuid": policy_uuid,
                                "user_id": user_id,
                                "attributes_evaluated": attribute_map.len()
                            }),
                        )
                    }
                    Err(e) => create_error_response(
                        req.id,
                        -32602,
                        format!("Invalid params for access_evaluate: {}", e),
                    ),
                }
            }

            "policy_binding_verify" => {
                info!("Received policy_binding_verify request");
                match serde_json::from_value::<PolicyBindingVerifyParams>(req.params) {
                    Ok(p) => {
                        debug!("Parsed policy_binding_verify params: {:?}", p);

                        // Step 1: Decode the TDF data
                        let tdf_bytes =
                            match base64::engine::general_purpose::STANDARD.decode(&p.tdf_data) {
                                Ok(data) => data,
                                Err(e) => {
                                    error!("Invalid base64 TDF data: {}", e);
                                    return create_error_response(
                                        req.id,
                                        -32602,
                                        format!("Invalid base64 TDF data: {}", e),
                                    );
                                }
                            };

                        // Step 2: Decode the policy key
                        let policy_key =
                            match base64::engine::general_purpose::STANDARD.decode(&p.policy_key) {
                                Ok(key) => key,
                                Err(e) => {
                                    error!("Invalid base64 policy key: {}", e);
                                    return create_error_response(
                                        req.id,
                                        -32602,
                                        format!("Invalid base64 policy key: {}", e),
                                    );
                                }
                            };

                        // Create a unique temporary file for the TDF
                        let temp_file = match tempfile::NamedTempFile::new() {
                            Ok(file) => file,
                            Err(e) => {
                                error!("Failed to create temporary file: {}", e);
                                return create_error_response(
                                    req.id,
                                    -32000,
                                    format!("Failed to create temporary file: {}", e),
                                );
                            }
                        };

                        // Write the TDF bytes to the temporary file
                        let temp_path = temp_file.path().to_owned();
                        if let Err(e) = std::fs::write(&temp_path, &tdf_bytes) {
                            error!("Failed to write TDF data to temporary file: {}", e);
                            return create_error_response(
                                req.id,
                                -32000,
                                format!("Failed to write TDF data to temporary file: {}", e),
                            );
                        }

                        // Open the TDF archive
                        let mut archive = match TdfArchive::open(&temp_path) {
                            Ok(archive) => archive,
                            Err(e) => {
                                error!("Failed to open TDF archive: {}", e);
                                return create_error_response(
                                    req.id,
                                    -32000,
                                    format!("Failed to open TDF archive: {}", e),
                                );
                            }
                        };

                        // Get the first entry
                        let entry = match archive.by_index() {
                            Ok(entry) => entry,
                            Err(e) => {
                                error!("Failed to read TDF entry: {}", e);
                                return create_error_response(
                                    req.id,
                                    -32000,
                                    format!("Failed to read TDF entry: {}", e),
                                );
                            }
                        };

                        // Extract the manifest and policy
                        let manifest = entry.manifest;
                        let policy = match manifest.get_policy() {
                            Ok(policy) => policy,
                            Err(e) => {
                                error!("Failed to extract policy from TDF: {}", e);
                                return create_error_response(
                                    req.id,
                                    -32000,
                                    format!("Failed to extract policy from TDF: {}", e),
                                );
                            }
                        };

                        // Get the stored policy binding hash from the manifest
                        let stored_binding_hash = manifest.encryption_information.key_access[0]
                            .policy_binding
                            .hash
                            .clone();

                        // Create a new binding hash with the provided policy key
                        let mut test_key_access =
                            manifest.encryption_information.key_access[0].clone();
                        let binding_result =
                            test_key_access.generate_policy_binding(&policy, &policy_key);

                        if let Err(e) = binding_result {
                            error!("Failed to generate test policy binding: {}", e);
                            return create_error_response(
                                req.id,
                                -32000,
                                format!("Failed to generate test policy binding: {}", e),
                            );
                        }

                        // Get the generated hash
                        let generated_hash = test_key_access.policy_binding.hash;

                        // Compare the hashes
                        let binding_valid = stored_binding_hash == generated_hash;

                        // Generate policy key hash for logging/info
                        let mut hasher = sha2::Sha256::new();
                        hasher.update(&policy_key);
                        let policy_key_hash =
                            base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
                        let policy_key_hash_prefix =
                            policy_key_hash.chars().take(16).collect::<String>();

                        // Clean up the temporary file - use secure deletion
                        if let Err(e) = secure_delete_temp_file(&temp_path) {
                            warn!("Failed to securely delete temporary file: {}", e);
                            // Fall back to regular deletion if secure deletion fails
                            let _ = std::fs::remove_file(&temp_path);
                        }

                        // Log security event for policy binding verification
                        log_security_event(
                            "policy_binding_verification",
                            None, // No specific user associated with this operation
                            Some(&policy.uuid),
                            if binding_valid { "valid" } else { "invalid" },
                            &format!("Policy binding cryptographic verification {}", 
                                     if binding_valid { "succeeded" } else { "failed" }),
                            Some(&json!({
                                "binding_algorithm": manifest.encryption_information.key_access[0].policy_binding.alg,
                                "verification_timestamp": Utc::now().to_rfc3339(),
                                "stored_hash": stored_binding_hash,
                                "generated_hash": generated_hash,
                                "policy_key_hash_prefix": policy_key_hash_prefix,
                            }))
                        );
                        
                        info!(
                            binding_valid = binding_valid,
                            policy_uuid = policy.uuid,
                            "Policy binding verification result"
                        );

                        create_success_response(
                            req.id,
                            json!({
                                "binding_valid": binding_valid,
                                "binding_info": {
                                    "algorithm": manifest.encryption_information.key_access[0].policy_binding.alg,
                                    "policy_uuid": policy.uuid,
                                    "stored_hash": stored_binding_hash,
                                    "generated_hash": generated_hash,
                                    "policy_key_hash_prefix": policy_key_hash_prefix,
                                    "timestamp": Utc::now().to_rfc3339()
                                }
                            }),
                        )
                    }
                    Err(e) => create_error_response(
                        req.id,
                        -32602,
                        format!("Invalid params for policy_binding_verify: {}", e),
                    ),
                }
            }

            // --- MCP Handshake/Notifications ---
            "initialized" => {
                info!("Received 'initialized' message (ID: {:?})", req.id);
                debug!(
                    "Initialized params: {}",
                    serde_json::to_string(&req.params).unwrap_or_default()
                );
                create_success_response(req.id, json!({ "acknowledged": true }))
            }

            "tools/call" => {
                info!("Received tools/call request");
                // *** ADD MORE LOGGING HERE TO SEE THE EXACT INCOMING STRUCTURE ***
                debug!(
                    "tools/call RAW request structure: {}",
                    serde_json::to_string(&req).unwrap_or_default()
                );

                if let Value::Object(mcp_params) = &req.params {
                    // Renamed for clarity
                    let tool_name = mcp_params
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("");
                    debug!(tool_name = tool_name, "Extracted tool name");

                    // Try to get the nested "parameters" field
                    let mut raw_params = mcp_params.get("parameters").cloned();

                    // *** NEW LOGIC: Check if params might be directly in mcp_params ***
                    if raw_params.is_none() || raw_params == Some(Value::Null) {
                        info!("'parameters' field not found or null in tools/call params. Checking if mcp_params itself contains the payload.");
                        // Create a clone of mcp_params and remove "name" to see if the rest is the payload
                        let mut potential_params = mcp_params.clone();
                        potential_params.remove("name"); // Remove the tool name itself

                        // Heuristic: If it's not empty and looks like an object, assume it's the payload
                        if !potential_params.is_empty() && potential_params.values().len() > 0 {
                            warn!("Assuming the MCP params object (excluding 'name') is the actual tool payload.");
                            raw_params = Some(Value::Object(potential_params));
                        } else {
                            // If it's empty after removing "name", fallback to Null
                            raw_params = Some(Value::Null);
                        }
                    }

                    // Log what we *think* the raw parameters are now
                    debug!(
                        "Extracted raw parameters after check: {}",
                        serde_json::to_string(&raw_params).unwrap_or_default()
                    );

                    let actual_tool_name = tool_name // Apply stripping logic as before
                        .strip_prefix("mcp__opentdf__")
                        .or_else(|| tool_name.strip_prefix("mcp_opentdf_"))
                        .or_else(|| tool_name.strip_prefix("opentdf__"))
                        .or_else(|| tool_name.strip_prefix("opentdf_"))
                        .or_else(|| tool_name.strip_prefix("opentdf:"))
                        .unwrap_or(tool_name);
                    info!(
                        "Translating MCP tool call '{}' -> internal method '{}'",
                        tool_name, actual_tool_name
                    );

                    // Process the determined raw_params (which might now be the direct payload or still null)
                    let processed_params = match raw_params {
                        Some(params_obj @ Value::Object(_)) => {
                            info!("Processing params as direct object.");
                            params_obj
                        }
                        Some(Value::Null) | None => {
                            // Handle None explicitly too
                            info!("No parameters identified.");
                            Value::Object(Map::new()) // Create empty object
                        }
                        Some(other_value) => {
                            // Handle string or other unexpected types
                            warn!("Unexpected parameter format: Expected object or null, got type {}.", other_value.as_str().map_or_else(|| other_value.to_string(), |s| s.to_string()));
                            // Attempt to parse if it's a string containing JSON
                            if let Value::String(s) = other_value {
                                info!("Attempting to parse string parameter as JSON object.");
                                match serde_json::from_str::<Value>(&s) {
                                    Ok(parsed_json @ Value::Object(_)) => {
                                        warn!(
                                            "Successfully parsed string parameter as JSON object."
                                        );
                                        parsed_json
                                    }
                                    Ok(_) => {
                                        error!(
                                            "String parameter parsed but was not a JSON object."
                                        );
                                        Value::Null // Or some error indicator? Null might lead back to missing field.
                                    }
                                    Err(e) => {
                                        error!("Failed to parse string parameter as JSON: {}", e);
                                        Value::Null
                                    }
                                }
                            } else {
                                Value::Null // Give up if not string or object
                            }
                        }
                    };

                    debug!(
                        "Processed parameters for internal call: {}",
                        serde_json::to_string(&processed_params).unwrap_or_default()
                    );

                    let internal_req = RpcRequest {
                        jsonrpc: "2.0".to_string(),
                        id: req.id.clone(), // Use the original request ID
                        method: actual_tool_name.to_string(),
                        params: processed_params,
                    };
                                // Call the specific tool handler and return the response directly
                    process_request(internal_req).await
                } else {
                    // Original req.params wasn't an object
                    error!("Invalid structure for tools/call parameters: req.params was not an object.");
                    create_error_response(
                        req.id,
                        -32602,
                        "Invalid structure for tools/call: params not object".to_string(),
                    )
                }
            }

            // --- Unknown method ---
            _ => {
                warn!("Method not found: '{}'", req.method);
                create_error_response(req.id, -32601, format!("Method not found: {}", req.method))
            }
        }
    })
} // --- End of process_request ---

// --- convert_to_attribute_policy (Manual parsing) ---
fn convert_to_attribute_policy(value: Value) -> Result<AttributePolicy, String> {
    if let Some(op_type) = value.get("type").and_then(|t| t.as_str()) {
        match op_type.to_uppercase().as_str() {
            "AND" | "OR" => {
                let conditions_val = value
                    .get("conditions")
                    .ok_or(format!("{} needs 'conditions'", op_type))?;
                let conditions_array = conditions_val
                    .as_array()
                    .ok_or("'conditions' must be array")?;
                let mut parsed = Vec::with_capacity(conditions_array.len());
                for c in conditions_array {
                    parsed.push(convert_to_attribute_policy(c.clone())?);
                }
                return if op_type.eq_ignore_ascii_case("AND") {
                    Ok(AttributePolicy::and(parsed))
                } else {
                    Ok(AttributePolicy::or(parsed))
                };
            }
            "NOT" => {
                let condition_val = value.get("condition").ok_or("NOT needs 'condition'")?;
                let parsed = convert_to_attribute_policy(condition_val.clone())?;
                return Ok(!parsed);
            }
            _ => warn!("Unknown logical operator type: {}", op_type), // Or error? Depends on strictness
        }
    }
    let attribute = value
        .get("attribute")
        .and_then(|a| a.as_str())
        .ok_or("Condition missing 'attribute'")?;
    let operator = value
        .get("operator")
        .and_then(|o| o.as_str())
        .ok_or("Condition missing 'operator'")?;
    let attr_id = AttributeIdentifier::from_string(attribute)
        .map_err(|e| format!("Invalid attribute identifier: {}", e))?;
    let op = match operator.to_lowercase().as_str() {
        "equals" => Operator::Equals,
        "notequals" => Operator::NotEquals,
        "greaterthan" => Operator::GreaterThan,
        "greaterthanorequal" => Operator::GreaterThanOrEqual,
        "lessthan" => Operator::LessThan,
        "lessthanorequal" => Operator::LessThanOrEqual,
        "contains" => Operator::Contains,
        "in" => Operator::In,
        "allof" => Operator::AllOf,
        "anyof" => Operator::AnyOf,
        "notin" => Operator::NotIn,
        "minimumof" => Operator::MinimumOf,
        "maximumof" => Operator::MaximumOf,
        "present" => Operator::Present,
        "notpresent" => Operator::NotPresent,
        _ => return Err(format!("Unknown operator: {}", operator)),
    };
    if op == Operator::Present || op == Operator::NotPresent {
        if value.get("value").is_some() {
            warn!("'value' ignored for operator: {:?}", op);
        }
        return Ok(AttributePolicy::Condition(AttributeCondition::new(
            attr_id, op, None,
        )));
    }
    let value_field = value
        .get("value")
        .ok_or_else(|| format!("Missing 'value' for operator: {}", operator))?;
    let attr_value = if let Some(s) = value_field.as_str() {
        AttributeValue::String(s.to_string())
    } else if let Some(n) = value_field.as_f64() {
        AttributeValue::Number(n)
    } else if let Some(b) = value_field.as_bool() {
        AttributeValue::Boolean(b)
    } else if let Some(a) = value_field.as_array() {
        if a.is_empty() {
            warn!(
                "Empty array value for '{}'. Assuming StringArray([]).",
                attribute
            );
            AttributeValue::StringArray(vec![])
        } else if a.iter().all(|v| v.is_string()) {
            let s: Vec<_> = a
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            if s.len() != a.len() {
                return Err("Array has non-strings".into());
            }
            AttributeValue::StringArray(s)
        } else if a.iter().all(|v| v.is_number()) {
            let n: Vec<_> = a.iter().filter_map(|v| v.as_f64()).collect();
            if n.len() != a.len() {
                return Err("Array has non-numbers".into());
            }
            AttributeValue::NumberArray(n)
        } else {
            return Err("Array must be all strings or all numbers".into());
        }
    } else if value_field.is_object() {
        if let Some(dt_str) = value_field.get("$datetime").and_then(|v| v.as_str()) {
            match chrono::DateTime::parse_from_rfc3339(dt_str) {
                Ok(dt) => AttributeValue::DateTime(dt.with_timezone(&chrono::Utc)),
                Err(e) => return Err(format!("Invalid datetime: {}", e)),
            }
        } else {
            return Err(format!("Unsupported object value: {}", value_field));
        }
    } else if value_field.is_null() {
        return Err(format!("'value' cannot be null for operator: {}", operator));
    } else {
        return Err(format!("Unsupported value type: {:?}", value_field));
    };
    Ok(AttributePolicy::Condition(AttributeCondition::new(
        attr_id,
        op,
        Some(attr_value),
    )))
}
// --- End of convert_to_attribute_policy ---

// --- Main Function ---
#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    info!("Starting OpenTDF MCP Server (Rust) on stdio...");
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();
    let mut line_buffer = String::new();

    let ready_msg =
        json!({"jsonrpc": "2.0", "method": "server/ready", "params": {"status": "ready"}});
    let ready_str = serde_json::to_string(&ready_msg).expect("Failed to serialize ready message");
    info!("Sending server/ready notification.");
    if let Err(e) = stdout
        .write_all(format!("{}\r\n", ready_str).as_bytes())
        .await
    {
        error!("Fatal: Failed to write ready message: {}", e);
        return;
    }
    if let Err(e) = stdout.flush().await {
        error!("Fatal: Failed to flush after ready message: {}", e);
        return;
    }

    info!("MCP Server listening on stdio for JSON-RPC messages...");

    loop {
        line_buffer.clear();
        match reader.read_line(&mut line_buffer).await {
            Ok(0) => {
                info!("Stdin closed (EOF). Exiting server.");
                break;
            }
            Ok(_) => {
                let trimmed_line = line_buffer.trim();
                if trimmed_line.is_empty() || !trimmed_line.starts_with('{') {
                    if !trimmed_line.is_empty() {
                        warn!("Received non-JSON input line, ignoring.");
                    }
                    continue;
                }
                info!(
                    "<<< Received raw line ({} bytes): {}",
                    trimmed_line.len(),
                    trimmed_line
                );

                // First parse as generic JSON to check if it's a notification
                let parsed_json: Value = match serde_json::from_str(trimmed_line) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("JSON Parse Error: {}. Raw: '{}'", e, trimmed_line);
                        let id = Value::Null;
                        let error_resp =
                            create_error_response(id, -32700, format!("Parse error: {}", e));
                        let resp_str = serde_json::to_string(&error_resp).unwrap_or_else(|se|
                            format!(r#"{{"jsonrpc":"2.0","id":null,"error":{{"code":-32000,"message":"Serialization error: {}"}}}}"#, se));
                        error!(">>> Sending Parse Error Response: {}", resp_str);
                        if let Err(io_e) = stdout
                            .write_all(format!("{}\r\n", resp_str).as_bytes())
                            .await
                        {
                            error!("Failed to write parse error response: {}", io_e);
                        }
                        if let Err(io_e) = stdout.flush().await {
                            error!("Failed to flush after parse error response: {}", io_e);
                        }
                        continue;
                    }
                };

                // Handle notification (no id field or null id)
                if parsed_json.get("id").is_none() || parsed_json.get("id") == Some(&Value::Null) {
                    if let Some(method) = parsed_json.get("method").and_then(|m| m.as_str()) {
                        info!("Received notification: {}", method);
                        // Handle common notifications without response
                        if method == "notifications/initialized" || method == "initialized" {
                            info!("Client initialization notification received");
                        } else {
                            info!("Unknown notification: {}", method);
                        }
                    } else {
                        warn!("Received notification without method field");
                    }
                    continue;
                }

                // Parse as RpcRequest for normal handling
                let req: RpcRequest = match serde_json::from_value(parsed_json) {
                    Ok(r) => r,
                    Err(e) => {
                        error!("JSON-RPC Parse Error: {}. Raw: '{}'", e, trimmed_line);
                        let id = serde_json::from_str::<Value>(trimmed_line)
                            .map(|v| v.get("id").cloned().unwrap_or(Value::Null))
                            .unwrap_or(Value::Null);
                        let error_resp =
                            create_error_response(id, -32700, format!("Parse error: {}", e));
                        let resp_str = serde_json::to_string(&error_resp).unwrap_or_else(|se|
                            format!(r#"{{"jsonrpc":"2.0","id":null,"error":{{"code":-32000,"message":"Serialization error: {}"}}}}"#, se));
                        error!(">>> Sending Parse Error Response: {}", resp_str);
                        if let Err(io_e) = stdout
                            .write_all(format!("{}\r\n", resp_str).as_bytes())
                            .await
                        {
                            error!("Failed to write parse error response: {}", io_e);
                        }
                        if let Err(io_e) = stdout.flush().await {
                            error!("Failed to flush after parse error response: {}", io_e);
                        }
                        continue;
                    }
                };
                let request_id = req.id.clone();
                let request_method = req.method.clone();
                let is_notification = request_id == Value::Null;
                debug!(
                    "Processing parsed request: ID={:?}, Method='{}'",
                    request_id, request_method
                );
                match tokio::time::timeout(Duration::from_secs(10), process_request(req)).await {
                    Ok(response) => {
                        if is_notification {
                            info!(
                                "Processed notification '{}', no response sent.",
                                request_method
                            );
                        } else {
                            let resp_str = match serde_json::to_string(&response) {
                                Ok(s) => s,
                                Err(e) => {
                                    error!("FATAL: Failed to serialize response for ID {:?}, Method '{}': {}", response.id, request_method, e);
                                    let fallback_err = create_error_response(response.id.clone(), -32000, format!("Internal Server Error: Failed to serialize response: {}", e));
                                    serde_json::to_string(&fallback_err).unwrap_or_else(|_| r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Internal Server Error"}}"#.to_string())
                                }
                            };
                            // info!(">>> Sending response for ID {:?}, Method '{}': {}", response.id, request_method, resp_str);
                            if let Err(e) = stdout
                                .write_all(format!("{}\r\n", resp_str).as_bytes())
                                .await
                            {
                                error!("Failed to write response for ID {:?}: {}", response.id, e);
                            } else if let Err(e) = stdout.flush().await {
                                error!("Failed to flush stdout for ID {:?}: {}", response.id, e);
                            }
                        }
                    }
                    Err(_) => {
                        error!(
                            "Request processing timed out after 10s for Method '{}', ID {:?}",
                            request_method, request_id
                        );
                        if !is_notification {
                            let timeout_resp = create_error_response(
                                request_id.clone(),
                                -32000,
                                format!("Request timed out for method '{}'", request_method),
                            );
                            let resp_str = serde_json::to_string(&timeout_resp)
                                .expect("Failed to serialize timeout response");
                            error!(">>> Sending Timeout Error Response: {}", resp_str);
                            if let Err(e) = stdout
                                .write_all(format!("{}\r\n", resp_str).as_bytes())
                                .await
                            {
                                error!(
                                    "Failed to write timeout response for ID {:?}: {}",
                                    request_id, e
                                );
                            } else if let Err(e) = stdout.flush().await {
                                error!(
                                    "Failed to flush stdout after timeout for ID {:?}: {}",
                                    request_id, e
                                );
                            }
                        } else {
                            info!(
                                "Timeout occurred for notification '{}', no error response sent.",
                                request_method
                            );
                        }
                    }
                }
            }
            Err(e) => {
                error!("Error reading from stdin: {}. Exiting.", e);
                break;
            }
        }
    }
    info!("OpenTDF MCP Server shutting down.");
}
// --- Secure File Deletion ---
/// Securely delete a temporary file by overwriting it before removal
/// This is important for security as it prevents recovery of sensitive data
fn secure_delete_temp_file(path: &std::path::Path) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};
    
    // Get the file size
    let metadata = std::fs::metadata(path)?;
    let file_size = metadata.len() as usize;
    
    if file_size > 0 {
        // Open the file for writing
        let mut file = OpenOptions::new().write(true).open(path)?;
        
        // Create a buffer of zeros to overwrite the file
        let buffer_size = std::cmp::min(file_size, 8192); // Use 8KB buffer or file size if smaller
        let zeros = vec![0u8; buffer_size];
        
        // Overwrite the file with zeros
        let mut remaining = file_size;
        while remaining > 0 {
            let to_write = std::cmp::min(remaining, buffer_size);
            file.write_all(&zeros[..to_write])?;
            remaining -= to_write;
        }
        
        // Flush to ensure all writes are completed
        file.flush()?;
        
        // Also overwrite with ones (alternating pattern for additional security)
        file.seek(SeekFrom::Start(0))?;
        let ones = vec![0xFFu8; buffer_size];
        
        let mut remaining = file_size;
        while remaining > 0 {
            let to_write = std::cmp::min(remaining, buffer_size);
            file.write_all(&ones[..to_write])?;
            remaining -= to_write;
        }
        
        // Flush again
        file.flush()?;
        
        // Final random overwrite for good measure
        file.seek(SeekFrom::Start(0))?;
        let mut random = vec![0u8; buffer_size];
        // Fill buffer with a simple "random" pattern (not cryptographically secure but sufficient)
        for (i, byte) in random.iter_mut().enumerate().take(buffer_size) {
            *byte = ((i * 37) % 256) as u8;
        }
        
        let mut remaining = file_size;
        while remaining > 0 {
            let to_write = std::cmp::min(remaining, buffer_size);
            file.write_all(&random[..to_write])?;
            remaining -= to_write;
        }
        
        // Final flush before closing
        file.flush()?;
        
        // Close the file explicitly
        drop(file);
    }
    
    // Finally remove the file
    std::fs::remove_file(path)?;
    
    Ok(())
}
// --- End of Main Function ---
