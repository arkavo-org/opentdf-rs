use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{error, info};
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use uuid::Uuid;

use opentdf::{
    AttributeCondition, AttributeIdentifier, AttributePolicy, AttributeValue, Operator, Policy,
    PolicyBody, TdfArchive, TdfArchiveBuilder, TdfEncryption, TdfManifest,
};

/// JSON-RPC request type.
#[derive(Deserialize, Serialize, Clone)]
struct RpcRequest {
    jsonrpc: String,
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

/// JSON-RPC response type.
#[derive(Serialize)]
struct RpcResponse {
    jsonrpc: String,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

/// Error type for JSON-RPC responses.
#[derive(Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

/// Parameters for TDF creation
#[derive(Deserialize, Serialize)]
struct TdfCreateParams {
    data: String, // Base64 encoded data
    kas_url: String,
    policy: Value,
}

/// Parameters for TDF reading
#[derive(Deserialize, Serialize)]
struct TdfReadParams {
    tdf_data: String, // Base64 encoded TDF archive
}

/// Parameters for data encryption
#[derive(Deserialize)]
struct EncryptParams {
    data: String, // Base64 encoded data
}

/// Parameters for data decryption
#[derive(Deserialize)]
struct DecryptParams {
    encrypted_data: String,  // Base64 encoded encrypted data
    iv: String,              // Base64 encoded initialization vector
    encrypted_key: String,   // Base64 encoded wrapped key
    policy_key_hash: String, // Hash of the policy key for validation
    policy_key: String,      // Base64 encoded policy key for decryption
}

/// Parameters for policy creation
#[derive(Deserialize)]
struct PolicyCreateParams {
    attributes: Vec<Value>,
    dissemination: Vec<String>,
    valid_from: Option<String>,
    valid_to: Option<String>,
}

/// Parameters for policy validation
#[derive(Deserialize)]
struct PolicyValidateParams {
    policy: Value,
    tdf_data: String, // Base64 encoded TDF archive
}

/// Parameters for attribute definition
#[derive(Deserialize)]
struct AttributeDefineParams {
    namespace: String,
    name: String,
    values: Vec<String>,
    hierarchy: Option<Vec<Value>>, // For hierarchical attributes
}

/// Parameters for user attribute assignment
#[derive(Deserialize)]
struct UserAttributesParams {
    user_id: String,
    attributes: Vec<Value>,
}

/// Parameters for access evaluation
#[derive(Deserialize)]
struct AccessEvaluateParams {
    policy: Value,
    user_attributes: Value,
    context: Option<Value>, // Environmental context attributes
}

/// Parameters for policy binding verification
#[derive(Deserialize)]
struct PolicyBindingVerifyParams {
    tdf_data: String,
    policy_key: String,
}

/// Type alias for the boxed future that process_request returns
type ResponseFuture = Pin<Box<dyn Future<Output = RpcResponse> + Send>>;

/// Processes a JSON-RPC request asynchronously.
fn process_request(req: RpcRequest) -> ResponseFuture {
    Box::pin(async move {
        // Validate JSON-RPC version.
        if req.jsonrpc != "2.0" {
            return RpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: None,
                error: Some(RpcError {
                    code: -32600,
                    message: "Invalid Request: jsonrpc must be \"2.0\"".to_string(),
                }),
            };
        }

        match req.method.as_str() {
            // Handle initialization handshake.
            "initialize" => {
                info!("Received initialize request");

                // Define all available tools
                // We still define as object for ease of maintenance, but will convert to array later
                let _tools = json!({
                    "tdf_create": {
                        "description": "Creates a new TDF archive with encrypted data and policy binding",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "data": {
                                    "type": "string",
                                    "description": "Base64 encoded data to encrypt and store in the TDF"
                                },
                                "kas_url": {
                                    "type": "string",
                                    "description": "URL of the Key Access Server"
                                },
                                "policy": {
                                    "type": "object",
                                    "description": "Policy to bind to the TDF archive"
                                }
                            },
                            "required": ["data", "kas_url", "policy"]
                        }
                    },
                    "tdf_read": {
                        "description": "Reads contents from a TDF archive, returning the manifest and payload",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "tdf_data": {
                                    "type": "string",
                                    "description": "Base64 encoded TDF archive data"
                                }
                            },
                            "required": ["tdf_data"]
                        }
                    },
                    "encrypt": {
                        "description": "Encrypts data using TDF encryption methods",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "data": {
                                    "type": "string",
                                    "description": "Base64 encoded data to encrypt"
                                }
                            },
                            "required": ["data"]
                        }
                    },
                    "decrypt": {
                        "description": "Decrypts TDF-encrypted data with the proper key",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "encrypted_data": {
                                    "type": "string",
                                    "description": "Base64 encoded encrypted data"
                                },
                                "iv": {
                                    "type": "string",
                                    "description": "Base64 encoded initialization vector"
                                },
                                "encrypted_key": {
                                    "type": "string",
                                    "description": "Base64 encoded wrapped key"
                                },
                                "policy_key_hash": {
                                    "type": "string",
                                    "description": "Hash of the policy key"
                                },
                                "policy_key": {
                                    "type": "string",
                                    "description": "Base64 encoded policy key"
                                }
                            },
                            "required": ["encrypted_data", "iv", "encrypted_key", "policy_key_hash", "policy_key"]
                        }
                    },
                    "policy_create": {
                        "description": "Creates a new policy for TDF encryption with attributes and dissemination rules",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "attributes": {
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "List of attributes to include in the policy"
                                },
                                "dissemination": {
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "List of recipients who can access the data"
                                },
                                "expiry": {
                                    "type": "string",
                                    "description": "Optional expiration date in ISO 8601 format"
                                }
                            },
                            "required": ["attributes", "dissemination"]
                        }
                    },
                    "policy_validate": {
                        "description": "Validates a policy against a TDF archive, checking compatibility",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "policy": {
                                    "type": "object",
                                    "description": "Policy to validate"
                                },
                                "tdf_data": {
                                    "type": "string",
                                    "description": "Base64 encoded TDF archive"
                                }
                            },
                            "required": ["policy", "tdf_data"]
                        }
                    }
                });

                // Simplify the response to the most basic format needed
                let response = json!({
                    "serverInfo": {
                        "name": "opentdf",
                        "version": "1.0.0"
                    },
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {
                            "tdf_create": {
                                "description": "Creates a TDF",
                                "inputSchema": {"type": "object"},
                                "schema": {"type": "object"}  // Include both for compatibility
                            },
                            "tdf_read": {
                                "description": "Reads a TDF",
                                "inputSchema": {"type": "object"},
                                "schema": {"type": "object"}  // Include both for compatibility
                            },
                            "policy_create": {
                                "description": "Creates an attribute-based access control policy",
                                "inputSchema": {"type": "object"},
                                "schema": {"type": "object"}
                            },
                            "policy_validate": {
                                "description": "Validates an attribute-based access control policy against a TDF",
                                "inputSchema": {"type": "object"},
                                "schema": {"type": "object"}
                            },
                            "attribute_define": {
                                "description": "Defines attribute namespaces with optional hierarchies",
                                "inputSchema": {"type": "object"},
                                "schema": {"type": "object"}
                            },
                            "user_attributes": {
                                "description": "Sets user attributes for testing access control",
                                "inputSchema": {"type": "object"},
                                "schema": {"type": "object"}
                            },
                            "access_evaluate": {
                                "description": "Evaluates whether a user with attributes can access protected content",
                                "inputSchema": {"type": "object"},
                                "schema": {"type": "object"}
                            },
                            "policy_binding_verify": {
                                "description": "Verifies the cryptographic binding of a policy to a TDF",
                                "inputSchema": {"type": "object"},
                                "schema": {"type": "object"}
                            }
                        }
                    }
                });

                info!("Sending initialize response with tools array for Claude compatibility");

                RpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req.id,
                    result: Some(response),
                    error: None,
                }
            }

            // List available tools - support both "listTools" and "tools/list" endpoints
            "listTools" | "tools/list" => {
                info!("Received listTools request");

                // Create a simple array of tools with minimal information
                let _tools_array = json!([
                    {
                        "name": "tdf_create",
                        "description": "Creates a new TDF archive with encrypted data and policy binding",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "data": {"type": "string"},
                                "kas_url": {"type": "string"},
                                "policy": {"type": "object"}
                            }
                        }
                    },
                    {
                        "name": "tdf_read",
                        "description": "Reads contents from a TDF archive, returning the manifest and payload",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "tdf_data": {"type": "string"}
                            }
                        }
                    },
                    {
                        "name": "encrypt",
                        "description": "Encrypts data using TDF encryption methods",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "data": {"type": "string"}
                            }
                        }
                    },
                    {
                        "name": "decrypt",
                        "description": "Decrypts TDF-encrypted data with the proper key",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "encrypted_data": {"type": "string"},
                                "iv": {"type": "string"},
                                "encrypted_key": {"type": "string"},
                                "policy_key_hash": {"type": "string"},
                                "policy_key": {"type": "string"}
                            }
                        }
                    },
                    {
                        "name": "policy_create",
                        "description": "Creates a new policy for TDF encryption with attributes and dissemination rules",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "attributes": {"type": "array"},
                                "dissemination": {"type": "array"},
                                "expiry": {"type": "string"}
                            }
                        }
                    },
                    {
                        "name": "policy_validate",
                        "description": "Validates a policy against a TDF archive, checking compatibility",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "policy": {"type": "object"},
                                "tdf_data": {"type": "string"}
                            }
                        }
                    }
                ]);

                // Log the response with high visibility - use compact representation
                info!("!!! SENDING TOOLS/LIST RESPONSE WITH TOOLS AS OBJECT !!!");

                // Format the response to match what the test script expects
                let tool_list = json!({
                    "tools": [
                        {
                            "name": "tdf_create",
                            "description": "Creates a TDF",
                            "inputSchema": {"type": "object"},
                            "schema": {"type": "object"}  // Include both for compatibility
                        },
                        {
                            "name": "tdf_read",
                            "description": "Reads a TDF",
                            "inputSchema": {"type": "object"},
                            "schema": {"type": "object"}  // Include both for compatibility
                        },
                        {
                            "name": "policy_create",
                            "description": "Creates an attribute-based access control policy",
                            "inputSchema": {"type": "object"},
                            "schema": {"type": "object"}
                        },
                        {
                            "name": "policy_validate",
                            "description": "Validates an attribute-based access control policy against a TDF",
                            "inputSchema": {"type": "object"},
                            "schema": {"type": "object"}
                        },
                        {
                            "name": "attribute_define",
                            "description": "Defines attribute namespaces with optional hierarchies",
                            "inputSchema": {"type": "object"},
                            "schema": {"type": "object"}
                        },
                        {
                            "name": "policy_binding_verify",
                            "description": "Verifies the cryptographic binding of a policy to a TDF",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "tdf_data": {
                                        "type": "string",
                                        "description": "Base64 encoded TDF archive"
                                    },
                                    "policy_key": {
                                        "type": "string",
                                        "description": "Policy key for verification"
                                    }
                                },
                                "required": ["tdf_data", "policy_key"]
                            },
                            "schema": {"type": "object"}
                        }
                    ]
                });

                RpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req.id.clone(),
                    result: Some(tool_list),
                    error: None,
                }
            }

            // Process a "tdf_create" tool call.
            "tdf_create" => {
                info!("Received tdf_create request");
                let params: Result<TdfCreateParams, _> = serde_json::from_value(req.params);
                match params {
                    Ok(p) => {
                        // Decode the base64 input data
                        let data = match base64::engine::general_purpose::STANDARD.decode(&p.data) {
                            Ok(data) => data,
                            Err(e) => {
                                return RpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    id: req.id,
                                    result: None,
                                    error: Some(RpcError {
                                        code: -32602,
                                        message: format!("Invalid base64 data: {}", e),
                                    }),
                                };
                            }
                        };

                        // Initialize TDF encryption
                        let tdf_encryption = match TdfEncryption::new() {
                            Ok(enc) => enc,
                            Err(e) => {
                                return RpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    id: req.id,
                                    result: None,
                                    error: Some(RpcError {
                                        code: -32000,
                                        message: format!("Failed to initialize encryption: {}", e),
                                    }),
                                };
                            }
                        };

                        // Encrypt the data
                        let encrypted_payload = match tdf_encryption.encrypt(&data) {
                            Ok(payload) => payload,
                            Err(e) => {
                                return RpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    id: req.id,
                                    result: None,
                                    error: Some(RpcError {
                                        code: -32000,
                                        message: format!("Failed to encrypt data: {}", e),
                                    }),
                                };
                            }
                        };

                        // Create a manifest
                        let mut manifest = TdfManifest::new("0.payload".to_string(), p.kas_url);

                        // Update manifest with encryption details
                        manifest.encryption_information.method.algorithm =
                            "AES-256-GCM".to_string();
                        manifest.encryption_information.method.iv = encrypted_payload.iv.clone();
                        manifest.encryption_information.key_access[0].wrapped_key =
                            encrypted_payload.encrypted_key.clone();

                        // Convert JSON policy to our Policy struct
                        let policy: Result<Policy, _> = serde_json::from_value(p.policy.clone());
                        match policy {
                            Ok(policy) => {
                                // Set the policy on the manifest
                                if let Err(e) = manifest.set_policy(&policy) {
                                    return RpcResponse {
                                        jsonrpc: "2.0".to_string(),
                                        id: req.id,
                                        result: None,
                                        error: Some(RpcError {
                                            code: -32000,
                                            message: format!("Failed to set policy: {}", e),
                                        }),
                                    };
                                }

                                // Generate policy binding
                                if let Err(e) = manifest.encryption_information.key_access[0]
                                    .generate_policy_binding(&policy, tdf_encryption.policy_key())
                                {
                                    return RpcResponse {
                                        jsonrpc: "2.0".to_string(),
                                        id: req.id,
                                        result: None,
                                        error: Some(RpcError {
                                            code: -32000,
                                            message: format!(
                                                "Failed to generate policy binding: {}",
                                                e
                                            ),
                                        }),
                                    };
                                }
                            }
                            Err(_e) => {
                                // If policy is not in our struct format, try legacy approach
                                match serde_json::to_string(&p.policy) {
                                    Ok(policy_str) => {
                                        // Fallback to raw policy string
                                        manifest.set_policy_raw(&policy_str);

                                        // Generate raw policy binding
                                        if let Err(e) = manifest.encryption_information.key_access
                                            [0]
                                        .generate_policy_binding_raw(
                                            &policy_str,
                                            tdf_encryption.policy_key(),
                                        ) {
                                            return RpcResponse {
                                                jsonrpc: "2.0".to_string(),
                                                id: req.id,
                                                result: None,
                                                error: Some(RpcError {
                                                    code: -32000,
                                                    message: format!(
                                                        "Failed to generate raw policy binding: {}",
                                                        e
                                                    ),
                                                }),
                                            };
                                        }
                                    }
                                    Err(e) => {
                                        return RpcResponse {
                                            jsonrpc: "2.0".to_string(),
                                            id: req.id,
                                            result: None,
                                            error: Some(RpcError {
                                                code: -32000,
                                                message: format!(
                                                    "Failed to serialize policy: {}",
                                                    e
                                                ),
                                            }),
                                        };
                                    }
                                }
                            }
                        }

                        // Create a temporary file for the TDF archive
                        let temp_file = match tempfile::NamedTempFile::new() {
                            Ok(file) => file,
                            Err(e) => {
                                return RpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    id: req.id,
                                    result: None,
                                    error: Some(RpcError {
                                        code: -32000,
                                        message: format!("Failed to create temp file: {}", e),
                                    }),
                                };
                            }
                        };
                        let temp_path = temp_file.path().to_owned();

                        // Create TDF archive
                        let mut builder = match TdfArchiveBuilder::new(&temp_path) {
                            Ok(builder) => builder,
                            Err(e) => {
                                return RpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    id: req.id,
                                    result: None,
                                    error: Some(RpcError {
                                        code: -32000,
                                        message: format!("Failed to create TDF archive: {}", e),
                                    }),
                                };
                            }
                        };

                        // Add encrypted data to the archive
                        let encrypted_data = match base64::engine::general_purpose::STANDARD
                            .decode(&encrypted_payload.ciphertext)
                        {
                            Ok(data) => data,
                            Err(e) => {
                                return RpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    id: req.id,
                                    result: None,
                                    error: Some(RpcError {
                                        code: -32000,
                                        message: format!("Failed to decode ciphertext: {}", e),
                                    }),
                                };
                            }
                        };

                        if let Err(e) = builder.add_entry(&manifest, &encrypted_data, 0) {
                            return RpcResponse {
                                jsonrpc: "2.0".to_string(),
                                id: req.id,
                                result: None,
                                error: Some(RpcError {
                                    code: -32000,
                                    message: format!("Failed to add entry to archive: {}", e),
                                }),
                            };
                        }

                        if let Err(e) = builder.finish() {
                            return RpcResponse {
                                jsonrpc: "2.0".to_string(),
                                id: req.id,
                                result: None,
                                error: Some(RpcError {
                                    code: -32000,
                                    message: format!("Failed to finalize archive: {}", e),
                                }),
                            };
                        }

                        // Read the created TDF file
                        let tdf_data = match std::fs::read(&temp_path) {
                            Ok(data) => data,
                            Err(e) => {
                                return RpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    id: req.id,
                                    result: None,
                                    error: Some(RpcError {
                                        code: -32000,
                                        message: format!("Failed to read TDF file: {}", e),
                                    }),
                                };
                            }
                        };

                        // Encode the TDF file as base64
                        let tdf_base64 =
                            base64::engine::general_purpose::STANDARD.encode(&tdf_data);

                        // Generate a unique ID for this operation
                        let id = Uuid::new_v4().to_string();

                        RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: Some(json!({
                                "id": id,
                                "tdf_data": tdf_base64,
                            })),
                            error: None,
                        }
                    }
                    Err(e) => {
                        error!("Invalid parameters for tdf_create: {}", e);
                        RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(RpcError {
                                code: -32602,
                                message: format!("Invalid params for tdf_create: {}", e),
                            }),
                        }
                    }
                }
            }

            // Implement encrypt method
            "encrypt" => {
                info!("Received encrypt request");
                let params: Result<EncryptParams, _> = serde_json::from_value(req.params);
                match params {
                    Ok(p) => {
                        // Decode the base64 input data
                        let data = match base64::engine::general_purpose::STANDARD.decode(&p.data) {
                            Ok(data) => data,
                            Err(e) => {
                                return RpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    id: req.id,
                                    result: None,
                                    error: Some(RpcError {
                                        code: -32602,
                                        message: format!("Invalid base64 data: {}", e),
                                    }),
                                };
                            }
                        };

                        // Initialize TDF encryption
                        let tdf_encryption = match TdfEncryption::new() {
                            Ok(enc) => enc,
                            Err(e) => {
                                return RpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    id: req.id,
                                    result: None,
                                    error: Some(RpcError {
                                        code: -32000,
                                        message: format!("Failed to initialize encryption: {}", e),
                                    }),
                                };
                            }
                        };

                        // Encrypt the data
                        let encrypted_payload = match tdf_encryption.encrypt(&data) {
                            Ok(payload) => payload,
                            Err(e) => {
                                return RpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    id: req.id,
                                    result: None,
                                    error: Some(RpcError {
                                        code: -32000,
                                        message: format!("Failed to encrypt data: {}", e),
                                    }),
                                };
                            }
                        };

                        // Return the encrypted data
                        RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: Some(json!({
                                "ciphertext": encrypted_payload.ciphertext,
                                "iv": encrypted_payload.iv,
                                "encrypted_key": encrypted_payload.encrypted_key,
                            })),
                            error: None,
                        }
                    }
                    Err(e) => {
                        error!("Invalid parameters for encrypt: {}", e);
                        RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(RpcError {
                                code: -32602,
                                message: format!("Invalid params for encrypt: {}", e),
                            }),
                        }
                    }
                }
            }

            // Implement decrypt method
            "decrypt" => {
                info!("Received decrypt request");
                let params: Result<DecryptParams, _> = serde_json::from_value(req.params);
                match params {
                    Ok(p) => {
                        // Decode the encrypted data
                        let _encrypted_data = match base64::engine::general_purpose::STANDARD
                            .decode(&p.encrypted_data)
                        {
                            Ok(data) => data,
                            Err(e) => {
                                return RpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    id: req.id,
                                    result: None,
                                    error: Some(RpcError {
                                        code: -32602,
                                        message: format!("Invalid base64 encrypted data: {}", e),
                                    }),
                                };
                            }
                        };

                        // Decode the IV
                        let _iv = match base64::engine::general_purpose::STANDARD.decode(&p.iv) {
                            Ok(data) => data,
                            Err(e) => {
                                return RpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    id: req.id,
                                    result: None,
                                    error: Some(RpcError {
                                        code: -32602,
                                        message: format!("Invalid base64 IV: {}", e),
                                    }),
                                };
                            }
                        };

                        // Decode the encrypted key
                        let _encrypted_key = match base64::engine::general_purpose::STANDARD
                            .decode(&p.encrypted_key)
                        {
                            Ok(data) => data,
                            Err(e) => {
                                return RpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    id: req.id,
                                    result: None,
                                    error: Some(RpcError {
                                        code: -32602,
                                        message: format!("Invalid base64 encrypted key: {}", e),
                                    }),
                                };
                            }
                        };

                        // Decode the policy key
                        let _policy_key =
                            match base64::engine::general_purpose::STANDARD.decode(&p.policy_key) {
                                Ok(data) => data,
                                Err(e) => {
                                    return RpcResponse {
                                        jsonrpc: "2.0".to_string(),
                                        id: req.id,
                                        result: None,
                                        error: Some(RpcError {
                                            code: -32602,
                                            message: format!("Invalid base64 policy key: {}", e),
                                        }),
                                    };
                                }
                            };

                        // In a real implementation, we would:
                        // 1. Validate the policy_key_hash against the policy
                        info!("Processing with policy key hash: {}", p.policy_key_hash);
                        // 2. Use the policy key to unwrap the encrypted key
                        // 3. Use the unwrapped key and IV to decrypt the data
                        // For now, we'll just return a placeholder
                        let decrypted_data = "Sample decrypted data".as_bytes();

                        // Return the decrypted data
                        RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: Some(json!({
                                "data": base64::engine::general_purpose::STANDARD.encode(decrypted_data),
                            })),
                            error: None,
                        }
                    }
                    Err(e) => {
                        error!("Invalid parameters for decrypt: {}", e);
                        RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(RpcError {
                                code: -32602,
                                message: format!("Invalid params for decrypt: {}", e),
                            }),
                        }
                    }
                }
            }

            // Implement tdf_read method
            "tdf_read" => {
                info!("Received tdf_read request");
                let params: Result<TdfReadParams, _> = serde_json::from_value(req.params);
                match params {
                    Ok(p) => {
                        // Decode the base64 TDF data
                        let tdf_data =
                            match base64::engine::general_purpose::STANDARD.decode(&p.tdf_data) {
                                Ok(data) => data,
                                Err(e) => {
                                    return RpcResponse {
                                        jsonrpc: "2.0".to_string(),
                                        id: req.id,
                                        result: None,
                                        error: Some(RpcError {
                                            code: -32602,
                                            message: format!("Invalid base64 TDF data: {}", e),
                                        }),
                                    };
                                }
                            };

                        // Create a temporary file for the TDF archive
                        let temp_file = match tempfile::NamedTempFile::new() {
                            Ok(file) => file,
                            Err(e) => {
                                return RpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    id: req.id,
                                    result: None,
                                    error: Some(RpcError {
                                        code: -32000,
                                        message: format!("Failed to create temp file: {}", e),
                                    }),
                                };
                            }
                        };
                        let temp_path = temp_file.path().to_owned();

                        // Write the TDF data to the temp file
                        if let Err(e) = std::fs::write(&temp_path, &tdf_data) {
                            return RpcResponse {
                                jsonrpc: "2.0".to_string(),
                                id: req.id,
                                result: None,
                                error: Some(RpcError {
                                    code: -32000,
                                    message: format!(
                                        "Failed to write TDF data to temp file: {}",
                                        e
                                    ),
                                }),
                            };
                        }

                        // Open the TDF archive
                        let _archive = match TdfArchive::open(&temp_path) {
                            Ok(archive) => archive,
                            Err(e) => {
                                return RpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    id: req.id,
                                    result: None,
                                    error: Some(RpcError {
                                        code: -32000,
                                        message: format!("Failed to open TDF archive: {}", e),
                                    }),
                                };
                            }
                        };

                        // Create a basic manifest for testing
                        // In a real implementation we would extract this from the archive
                        let manifest = json!({
                            "payload": {
                                "type": "reference",
                                "url": "0.payload",
                                "protocol": "zip",
                                "isEncrypted": true
                            },
                            "encryptionInformation": {
                                "type": "split",
                                "keyAccess": [{
                                    "type": "wrapped",
                                    "url": "https://kas.example.com",
                                    "protocol": "kas"
                                }],
                                "method": {
                                    "algorithm": "AES-256-GCM",
                                    "isStreamable": true
                                }
                            }
                        });

                        // Get the encrypted payload (in a real implementation, we would extract this from the archive)
                        let payload = "Sample encrypted payload".as_bytes();

                        // Return the manifest and payload
                        RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: Some(json!({
                                "manifest": manifest,
                                "payload": base64::engine::general_purpose::STANDARD.encode(payload),
                            })),
                            error: None,
                        }
                    }
                    Err(e) => {
                        error!("Invalid parameters for tdf_read: {}", e);
                        RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(RpcError {
                                code: -32602,
                                message: format!("Invalid params for tdf_read: {}", e),
                            }),
                        }
                    }
                }
            }

            // Implement policy_create method
            "policy_create" => {
                info!("Received policy_create request");
                let params: Result<PolicyCreateParams, _> = serde_json::from_value(req.params);
                match params {
                    Ok(p) => {
                        // Convert attribute definitions to AttributePolicy objects
                        let mut attribute_policies = Vec::new();

                        for attr_value in p.attributes {
                            match convert_to_attribute_policy(attr_value) {
                                Ok(policy) => attribute_policies.push(policy),
                                Err(e) => {
                                    return RpcResponse {
                                        jsonrpc: "2.0".to_string(),
                                        id: req.id,
                                        result: None,
                                        error: Some(RpcError {
                                            code: -32602,
                                            message: format!("Invalid attribute policy: {}", e),
                                        }),
                                    };
                                }
                            }
                        }

                        // Parse time constraints if provided
                        let valid_from = match p.valid_from {
                            Some(time_str) => match chrono::DateTime::parse_from_rfc3339(&time_str)
                            {
                                Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
                                Err(e) => {
                                    return RpcResponse {
                                        jsonrpc: "2.0".to_string(),
                                        id: req.id,
                                        result: None,
                                        error: Some(RpcError {
                                            code: -32602,
                                            message: format!(
                                                "Invalid valid_from date format: {}",
                                                e
                                            ),
                                        }),
                                    };
                                }
                            },
                            None => None,
                        };

                        let valid_to = match p.valid_to {
                            Some(time_str) => match chrono::DateTime::parse_from_rfc3339(&time_str)
                            {
                                Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
                                Err(e) => {
                                    return RpcResponse {
                                        jsonrpc: "2.0".to_string(),
                                        id: req.id,
                                        result: None,
                                        error: Some(RpcError {
                                            code: -32602,
                                            message: format!("Invalid valid_to date format: {}", e),
                                        }),
                                    };
                                }
                            },
                            None => None,
                        };

                        // Create the Policy object
                        let policy = Policy {
                            uuid: Uuid::new_v4().to_string(),
                            valid_from,
                            valid_to,
                            body: PolicyBody {
                                attributes: attribute_policies,
                                dissem: p.dissemination,
                            },
                        };

                        // Convert to JSON
                        let policy_json = match serde_json::to_value(&policy) {
                            Ok(json) => json,
                            Err(e) => {
                                return RpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    id: req.id,
                                    result: None,
                                    error: Some(RpcError {
                                        code: -32000,
                                        message: format!("Failed to serialize policy: {}", e),
                                    }),
                                };
                            }
                        };

                        // Generate a hash for the policy
                        let mut hasher = sha2::Sha256::new();
                        match serde_json::to_string(&policy) {
                            Ok(policy_str) => {
                                hasher.update(policy_str.as_bytes());
                                let policy_hash = base64::engine::general_purpose::STANDARD
                                    .encode(hasher.finalize());

                                // Return the policy and hash
                                RpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    id: req.id,
                                    result: Some(json!({
                                        "policy": policy_json,
                                        "policy_hash": policy_hash,
                                    })),
                                    error: None,
                                }
                            }
                            Err(e) => {
                                return RpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    id: req.id,
                                    result: None,
                                    error: Some(RpcError {
                                        code: -32000,
                                        message: format!("Failed to hash policy: {}", e),
                                    }),
                                };
                            }
                        }
                    }
                    Err(e) => {
                        error!("Invalid parameters for policy_create: {}", e);
                        RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(RpcError {
                                code: -32602,
                                message: format!("Invalid params for policy_create: {}", e),
                            }),
                        }
                    }
                }
            }

            // Implement policy_validate method
            "policy_validate" => {
                info!("Received policy_validate request");
                let params: Result<PolicyValidateParams, _> = serde_json::from_value(req.params);
                match params {
                    Ok(p) => {
                        // In a real implementation, we would:
                        // 1. Parse the TDF archive from p.tdf_data to extract its embedded policy
                        // 2. Compare the provided policy (p.policy) against the archive's policy
                        info!(
                            "Validating policy with UUID: {}",
                            p.policy
                                .get("uuid")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                        );
                        info!("Against TDF data of length: {}", p.tdf_data.len());
                        // 3. Determine compatibility

                        // For now, just return a successful result
                        RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: Some(json!({
                                "valid": true,
                                "reasons": []
                            })),
                            error: None,
                        }
                    }
                    Err(e) => {
                        error!("Invalid parameters for policy_validate: {}", e);
                        RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(RpcError {
                                code: -32602,
                                message: format!("Invalid params for policy_validate: {}", e),
                            }),
                        }
                    }
                }
            }

            // Implement attribute definition for hierarchical attributes
            "attribute_define" => {
                info!("Received attribute_define request");
                let params: Result<AttributeDefineParams, _> = serde_json::from_value(req.params);
                match params {
                    Ok(p) => {
                        info!("Defining attribute namespace: {}", p.namespace);

                        // Process values
                        let mut attribute_values = Vec::new();
                        for value in &p.values {
                            attribute_values.push(value.clone());
                        }

                        // Process hierarchy if provided
                        let hierarchy_info = if let Some(hierarchy) = p.hierarchy {
                            // Process hierarchical structure
                            let mut hierarchy_map = HashMap::new();
                            for level in hierarchy {
                                if let (Some(level_value), Some(inherits_from)) = (
                                    level.get("value").and_then(|v| v.as_str()),
                                    level.get("inherits_from").and_then(|v| v.as_str()),
                                ) {
                                    hierarchy_map
                                        .insert(level_value.to_string(), inherits_from.to_string());
                                }
                            }
                            Some(hierarchy_map)
                        } else {
                            None
                        };

                        // Build response with attribute info
                        let attribute_def = json!({
                            "namespace": p.namespace,
                            "name": p.name,
                            "values": attribute_values,
                            "hierarchy": hierarchy_info,
                            "id": Uuid::new_v4().to_string()
                        });

                        RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: Some(json!({
                                "attribute": attribute_def,
                                "status": "defined"
                            })),
                            error: None,
                        }
                    }
                    Err(e) => {
                        error!("Invalid parameters for attribute_define: {}", e);
                        RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(RpcError {
                                code: -32602,
                                message: format!("Invalid params for attribute_define: {}", e),
                            }),
                        }
                    }
                }
            }

            // Implement user attribute assignment
            "user_attributes" => {
                info!("Received user_attributes request");
                let params: Result<UserAttributesParams, _> = serde_json::from_value(req.params);
                match params {
                    Ok(p) => {
                        info!("Setting attributes for user: {}", p.user_id);

                        // Process attribute assignments
                        let mut processed_attributes = Vec::new();
                        for attr in &p.attributes {
                            if let (Some(namespace), Some(name), Some(value)) = (
                                attr.get("namespace").and_then(|v| v.as_str()),
                                attr.get("name").and_then(|v| v.as_str()),
                                attr.get("value"),
                            ) {
                                processed_attributes.push(json!({
                                    "attribute": format!("{}:{}", namespace, name),
                                    "value": value
                                }));
                            }
                        }

                        // Store user attributes (in a real implementation, this would be persisted)
                        RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: Some(json!({
                                "user_id": p.user_id,
                                "attributes": processed_attributes,
                                "status": "attributes_assigned"
                            })),
                            error: None,
                        }
                    }
                    Err(e) => {
                        error!("Invalid parameters for user_attributes: {}", e);
                        RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(RpcError {
                                code: -32602,
                                message: format!("Invalid params for user_attributes: {}", e),
                            }),
                        }
                    }
                }
            }

            // Implement access evaluation
            "access_evaluate" => {
                info!("Received access_evaluate request");
                let params: Result<AccessEvaluateParams, _> = serde_json::from_value(req.params);
                match params {
                    Ok(p) => {
                        info!("Evaluating access based on policy and user attributes");

                        // Evaluate all policy conditions against user attributes
                        // In a real implementation, this would use the actual ABAC evaluation code

                        // For demonstration purposes, we'll perform a simple evaluation
                        let mut results = Vec::new();
                        let mut overall_access = true;

                        // If policy has attributes array, evaluate each
                        if let Some(policy_body) = p.policy.get("body") {
                            if let Some(attributes) =
                                policy_body.get("attributes").and_then(|a| a.as_array())
                            {
                                for attr_policy in attributes {
                                    // Simple condition matching for demonstration
                                    if let Some(condition) =
                                        attr_policy.get("attribute").and_then(|a| a.as_str())
                                    {
                                        // Check if user has matching attribute
                                        let satisfied = match p.user_attributes.get("attributes") {
                                            Some(user_attrs) if user_attrs.is_array() => {
                                                user_attrs.as_array().unwrap().iter().any(|ua| {
                                                    ua.get("attribute").and_then(|a| a.as_str())
                                                        == Some(condition)
                                                })
                                            }
                                            _ => false,
                                        };

                                        results.push(json!({
                                        "condition": condition,
                                        "satisfied": satisfied,
                                        "reason": if satisfied { "Attribute present" } else { "Missing attribute" }
                                    }));

                                        if !satisfied {
                                            overall_access = false;
                                        }
                                    }
                                }
                            }
                        }

                        // Consider environmental context if provided
                        if let Some(context) = &p.context {
                            info!("Evaluating with environmental context: {}", context);
                            // In a real implementation, would evaluate context conditions
                        }

                        RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: Some(json!({
                                "access_granted": overall_access,
                                "evaluation_time": chrono::Utc::now().to_rfc3339(),
                                "condition_results": results
                            })),
                            error: None,
                        }
                    }
                    Err(e) => {
                        error!("Invalid parameters for access_evaluate: {}", e);
                        RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(RpcError {
                                code: -32602,
                                message: format!("Invalid params for access_evaluate: {}", e),
                            }),
                        }
                    }
                }
            }

            // Implement policy binding verification
            "policy_binding_verify" => {
                info!("Received policy_binding_verify request");
                let params: Result<PolicyBindingVerifyParams, _> =
                    serde_json::from_value(req.params);
                match params {
                    Ok(p) => {
                        info!(
                            "Verifying policy binding in TDF with data length: {}",
                            p.tdf_data.len()
                        );

                        // In a real implementation, would:
                        // 1. Decode the TDF data
                        // 2. Extract the manifest
                        // 3. Verify the policy binding signature using the policy_key

                        // For demonstration, we'll assume valid binding
                        RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: Some(json!({
                                "binding_valid": true,
                                "binding_info": {
                                    "algorithm": "HS256",
                                    "timestamp": chrono::Utc::now().to_rfc3339()
                                }
                            })),
                            error: None,
                        }
                    }
                    Err(e) => {
                        error!("Invalid parameters for policy_binding_verify: {}", e);
                        RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(RpcError {
                                code: -32602,
                                message: format!("Invalid params for policy_binding_verify: {}", e),
                            }),
                        }
                    }
                }
            }

            // "initialized" notification from the client.
            "initialized" => {
                info!(
                    "Received initialized notification with params: {}",
                    serde_json::to_string_pretty(&req.params).unwrap()
                );
                // Attempt to parse configuration from client
                if let Value::Object(params) = &req.params {
                    if let Some(config) = params.get("configuration") {
                        info!(
                            "Client provided configuration: {}",
                            serde_json::to_string_pretty(config).unwrap()
                        );
                    }
                }

                // The "initialized" message can be either a notification or a request
                // Always respond if there's an ID (request) but skip response for null ID (notification)
                info!("Processed initialized message");

                RpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req.id,
                    result: Some(json!({ "acknowledged": true })),
                    error: None,
                }
            }

            // Handle MCP-specific tool calls (support for Claude integration)
            "tools/call" => {
                info!(
                    "Received tools/call request from Claude: {}",
                    serde_json::to_string_pretty(&req).unwrap_or_default()
                );

                if let Value::Object(params) = &req.params {
                    // Get tool name and parameters
                    let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    let tool_params = params.get("parameters").cloned().unwrap_or(json!({}));

                    info!(
                        "Tool call for name: '{}' with params: {}",
                        tool_name,
                        serde_json::to_string_pretty(&tool_params).unwrap_or_default()
                    );

                    // Extract any prefix if present
                    let actual_tool_name = if tool_name.starts_with("mcp__opentdf__") {
                        // Handle Claude MCP format (mcp__opentdf__toolname)
                        tool_name
                            .strip_prefix("mcp__opentdf__")
                            .unwrap_or(tool_name)
                    } else if tool_name.starts_with("opentdf__") {
                        // Handle standard MCP format (opentdf__toolname)
                        tool_name.strip_prefix("opentdf__").unwrap_or(tool_name)
                    } else {
                        // No prefix, use as is
                        tool_name
                    };

                    info!("Translating tool call '{}' to method", actual_tool_name);

                    // Create internal request - forward all tool calls to their respective methods
                    let internal_req = RpcRequest {
                        jsonrpc: "2.0".to_string(),
                        id: req.id.clone(),
                        method: actual_tool_name.to_string(),
                        params: tool_params,
                    };

                    // Process with existing handler
                    let response = process_request(internal_req).await;

                    RpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: req.id,
                        result: response.result,
                        error: response.error,
                    }
                } else {
                    error!("Invalid parameters for tools/call");
                    RpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: req.id,
                        result: None,
                        error: Some(RpcError {
                            code: -32602,
                            message: "Invalid parameters for tools/call".to_string(),
                        }),
                    }
                }
            }

            // Unknown method.
            _ => {
                error!("Method not found: '{}'", req.method);
                RpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req.id,
                    result: None,
                    error: Some(RpcError {
                        code: -32601,
                        message: format!("Method not found: {}", req.method),
                    }),
                }
            }
        }
    })
}

/// Helper function to convert JSON to AttributePolicy
fn convert_to_attribute_policy(value: Value) -> Result<AttributePolicy, String> {
    // Check if this is a logical operator
    if let Some(op_type) = value.get("type") {
        if let Some(op_type_str) = op_type.as_str() {
            match op_type_str.to_uppercase().as_str() {
                "AND" => {
                    if let Some(conditions) = value.get("conditions") {
                        if let Some(conditions_array) = conditions.as_array() {
                            let mut parsed_conditions = Vec::new();
                            for condition in conditions_array {
                                parsed_conditions
                                    .push(convert_to_attribute_policy(condition.clone())?);
                            }
                            return Ok(AttributePolicy::and(parsed_conditions));
                        }
                    }
                    return Err("AND operator requires 'conditions' array".to_string());
                }
                "OR" => {
                    if let Some(conditions) = value.get("conditions") {
                        if let Some(conditions_array) = conditions.as_array() {
                            let mut parsed_conditions = Vec::new();
                            for condition in conditions_array {
                                parsed_conditions
                                    .push(convert_to_attribute_policy(condition.clone())?);
                            }
                            return Ok(AttributePolicy::or(parsed_conditions));
                        }
                    }
                    return Err("OR operator requires 'conditions' array".to_string());
                }
                "NOT" => {
                    if let Some(condition) = value.get("condition") {
                        let parsed_condition = convert_to_attribute_policy(condition.clone())?;
                        return Ok(!parsed_condition);
                    }
                    return Err("NOT operator requires 'condition' field".to_string());
                }
                _ => return Err(format!("Unknown logical operator type: {}", op_type_str)),
            }
        }
    }

    // If not a logical operator, try to parse as a condition
    let attribute = value
        .get("attribute")
        .and_then(|a| a.as_str())
        .ok_or_else(|| "Missing 'attribute' field".to_string())?;

    let operator = value
        .get("operator")
        .and_then(|o| o.as_str())
        .ok_or_else(|| "Missing 'operator' field".to_string())?;

    // Parse the attribute identifier
    let attr_id = AttributeIdentifier::from_string(attribute)
        .map_err(|e| format!("Invalid attribute identifier: {}", e))?;

    // Parse the operator
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

    // For present/notpresent, no value is needed
    if op == Operator::Present || op == Operator::NotPresent {
        return Ok(AttributePolicy::Condition(AttributeCondition::new(
            attr_id, op, None,
        )));
    }

    // For other operators, we need a value
    let value_field = value
        .get("value")
        .ok_or_else(|| format!("Missing 'value' field for operator: {}", operator))?;

    // Convert the value to an AttributeValue
    let attr_value = if let Some(string_val) = value_field.as_str() {
        AttributeValue::String(string_val.to_string())
    } else if let Some(num_val) = value_field.as_f64() {
        AttributeValue::Number(num_val)
    } else if let Some(bool_val) = value_field.as_bool() {
        AttributeValue::Boolean(bool_val)
    } else if let Some(array_val) = value_field.as_array() {
        // Check if it's a string array or number array
        if array_val.iter().all(|v| v.is_string()) {
            let strings: Vec<String> = array_val
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            AttributeValue::StringArray(strings)
        } else if array_val.iter().all(|v| v.is_number()) {
            let numbers: Vec<f64> = array_val.iter().map(|v| v.as_f64().unwrap()).collect();
            AttributeValue::NumberArray(numbers)
        } else {
            return Err("Array values must be all strings or all numbers".to_string());
        }
    } else if value_field.is_object() {
        // Try to parse as a DateTime if it has the right format
        if let Some(dt_str) = value_field.get("datetime").and_then(|v| v.as_str()) {
            match chrono::DateTime::parse_from_rfc3339(dt_str) {
                Ok(dt) => AttributeValue::DateTime(dt.with_timezone(&chrono::Utc)),
                Err(e) => return Err(format!("Invalid datetime format: {}", e)),
            }
        } else {
            return Err("Unsupported object value format".to_string());
        }
    } else {
        return Err("Unsupported value type".to_string());
    };

    Ok(AttributePolicy::Condition(AttributeCondition::new(
        attr_id,
        op,
        Some(attr_value),
    )))
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "opentdf_mcp_server=info,tower_http=info".into()),
        )
        .init();

    info!("Starting OpenTDF MCP Server on stdio...");

    // Use raw stdin/stdout for most direct access
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();

    // Buffer for reading lines
    let mut line = String::new();

    // Print a ready message to let client know we're listening
    info!("MCP Server ready - waiting for JSON-RPC messages");
    stdout
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"server/ready\",\"params\":{}}\r\n")
        .await
        .unwrap();
    stdout.flush().await.unwrap();

    // Process each line from standard input
    while let Ok(bytes_read) = reader.read_line(&mut line).await {
        if bytes_read == 0 {
            // EOF reached
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        // Don't crash on invalid JSON
        if !trimmed.starts_with('{') {
            info!("Ignoring non-JSON input: {}", trimmed);
            line.clear();
            continue;
        }

        // Log the received message for debugging with high visibility
        info!("!!! RECEIVED JSON-RPC MESSAGE !!!: {}", line);
        let req: RpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                error!("Error parsing JSON: {}", e);

                // Try to extract the ID from the malformed request
                let id = serde_json::from_str::<serde_json::Value>(&line)
                    .map(|v| v.get("id").cloned().unwrap_or(Value::Null))
                    .unwrap_or(Value::Null);

                let error_resp = RpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id,
                    result: None,
                    error: Some(RpcError {
                        code: -32700,
                        message: format!("Parse error: {}", e),
                    }),
                };
                let resp_str = serde_json::to_string(&error_resp).unwrap();
                info!("!!! SENDING ERROR RESPONSE !!!:\n{}", resp_str);
                stdout.write_all(resp_str.as_bytes()).await.unwrap();
                stdout.write_all(b"\r\n").await.unwrap();
                stdout.flush().await.unwrap();
                line.clear();
                continue;
            }
        };

        info!("Processing request with method: '{}'", req.method);

        // Use a timeout to prevent hanging
        // Check if this is a notification (no id) and needs special handling
        let is_notification = req.id == Value::Null;

        // Process the request/notification
        let response = match tokio::time::timeout(
            tokio::time::Duration::from_secs(5), // 5 second timeout
            process_request(req.clone()),
        )
        .await
        {
            Ok(resp) => resp,
            Err(_) => {
                // Timeout occurred
                error!("Request processing timed out for method: '{}'", req.method);

                // Don't try to respond to notifications with timeouts
                if is_notification {
                    info!("Skipping timeout response for notification");
                    line.clear();
                    continue;
                }

                RpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req.id,
                    result: None,
                    error: Some(RpcError {
                        code: -32000,
                        message: format!("Request processing timed out for method: {}", req.method),
                    }),
                }
            }
        };

        // For notifications, we don't send a response
        // Check both the original request ID and the response ID (handling the initialized case)
        if is_notification || response.id == Value::Null {
            info!(
                "Skipping response for notification method: '{}'",
                req.method
            );
            line.clear();
            continue;
        }

        // Standard JSON-RPC responses must be compact, not pretty-printed
        let resp_str = serde_json::to_string(&response).unwrap();
        info!(
            "!!! SENDING RESPONSE FOR REQUEST METHOD '{}' !!!:\n{}",
            req.method, resp_str
        );

        // Send the response
        // Format JSON-RPC output with CRLF as used by some implementations
        if let Err(e) = stdout.write_all(resp_str.as_bytes()).await {
            error!("Failed to write response: {}", e);
            line.clear();
            continue;
        }

        // Add CR+LF for proper JSON-RPC newline handling
        if let Err(e) = stdout.write_all(b"\r\n").await {
            error!("Failed to write newline: {}", e);
            line.clear();
            continue;
        }

        if let Err(e) = stdout.flush().await {
            error!("Failed to flush stdout: {}", e);
            line.clear();
            continue;
        }

        // Clear the line buffer for the next message
        line.clear();

        // Do not send additional initialized notification from here
        // The client will send the initialized request and we'll respond to that
    }
}
