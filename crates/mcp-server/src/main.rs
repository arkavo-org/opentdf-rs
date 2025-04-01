use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{info, Level};
use tracing_subscriber::{fmt, prelude::*};
use uuid::Uuid;

use opentdf::{TdfArchive, TdfArchiveBuilder, TdfEncryption, TdfManifest};

/// Application state shared across handlers
#[derive(Clone)]
struct AppState {
    /// For demonstration, we'll keep a simple counter of requests
    request_counter: Arc<std::sync::atomic::AtomicUsize>,
}

/// MCP API errors
#[derive(Debug, Error)]
enum ApiError {
    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("TDF operation failed: {0}")]
    TdfError(#[from] anyhow::Error),

    #[error("Internal server error: {0}")]
    InternalError(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::TdfError(err) => (StatusCode::UNPROCESSABLE_ENTITY, err.to_string()),
            ApiError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        (
            status,
            Json(ErrorResponse {
                error: error_message,
            }),
        )
            .into_response()
    }
}

/// Standard error response
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// Health check response
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    request_count: usize,
}

/// Request to create a TDF archive
#[derive(Deserialize)]
struct CreateTdfRequest {
    data: String, // Base64 encoded data
    kas_url: String,
    policy: serde_json::Value,
}

/// Response after creating a TDF archive
#[derive(Serialize)]
struct CreateTdfResponse {
    id: String,
    tdf_data: String, // Base64 encoded TDF archive
}

/// Request to read from a TDF archive
#[derive(Deserialize)]
struct ReadTdfRequest {
    tdf_data: String, // Base64 encoded TDF archive
}

/// Response after reading a TDF archive
#[derive(Serialize)]
struct ReadTdfResponse {
    manifest: serde_json::Value,
    payload: String, // Base64 encoded payload
}

/// Request to encrypt data
#[derive(Deserialize)]
struct EncryptRequest {
    data: String, // Base64 encoded data
}

/// Response after encrypting data
#[derive(Serialize)]
struct EncryptResponse {
    encrypted_data: String,  // Base64 encoded encrypted data
    iv: String,              // Base64 encoded initialization vector
    encrypted_key: String,   // Base64 encoded wrapped key
    policy_key_hash: String, // Hash of the policy key
}

/// Request to decrypt data
#[derive(Deserialize)]
struct DecryptRequest {
    encrypted_data: String,  // Base64 encoded encrypted data
    iv: String,              // Base64 encoded initialization vector
    encrypted_key: String,   // Base64 encoded wrapped key
    policy_key_hash: String, // Hash of the policy key
    policy_key: String,      // Base64 encoded policy key
}

/// Response after decrypting data
#[derive(Serialize)]
struct DecryptResponse {
    data: String, // Base64 encoded decrypted data
}

/// Request to create a policy
#[derive(Deserialize)]
struct CreatePolicyRequest {
    attributes: Vec<String>,
    dissemination: Vec<String>,
    expiry: Option<String>,
}

/// Response after creating a policy
#[derive(Serialize)]
struct CreatePolicyResponse {
    policy: serde_json::Value,
}

/// Request to validate a policy
#[derive(Deserialize)]
struct ValidatePolicyRequest {
    policy: serde_json::Value,
    tdf_data: String, // Base64 encoded TDF archive
}

/// Response after validating a policy
#[derive(Serialize)]
struct ValidatePolicyResponse {
    valid: bool,
    reason: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("opentdf_mcp_server={},tower_http=info", Level::INFO).into()
            }),
        )
        .init();

    info!("Starting OpenTDF MCP Server");

    // Initialize app state
    let state = AppState {
        request_counter: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    };

    // CORS configuration
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    // Define our API routes
    let app = Router::new()
        // Health endpoint
        .route("/mcp/health", get(health_check))
        // TDF operation endpoints
        .route("/mcp/tdf/create", post(create_tdf))
        .route("/mcp/tdf/read", post(read_tdf))
        .route("/mcp/tdf/encrypt", post(encrypt_data))
        .route("/mcp/tdf/decrypt", post(decrypt_data))
        // Policy endpoints
        .route("/mcp/policy/create", post(create_policy))
        .route("/mcp/policy/validate", post(validate_policy))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state);

    // Start the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(&addr).await?;
    info!("OpenTDF MCP Server listening on {}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

/// Health check endpoint
async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    let count = state
        .request_counter
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        request_count: count,
    })
}

/// Create a TDF archive
async fn create_tdf(
    State(state): State<AppState>,
    Json(request): Json<CreateTdfRequest>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .request_counter
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    // Decode the base64 input data
    let data = base64::engine::general_purpose::STANDARD
        .decode(&request.data)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 data: {}", e)))?;

    // Initialize TDF encryption
    let tdf_encryption = TdfEncryption::new()
        .map_err(|e| anyhow::anyhow!("Failed to initialize encryption: {}", e))?;

    // Encrypt the data
    let encrypted_payload = tdf_encryption
        .encrypt(&data)
        .map_err(|e| anyhow::anyhow!("Failed to encrypt data: {}", e))?;

    // Create a manifest
    let mut manifest = TdfManifest::new("0.payload".to_string(), request.kas_url);

    // Update manifest with encryption details
    manifest.encryption_information.method.algorithm = "AES-256-GCM".to_string();
    manifest.encryption_information.method.iv = encrypted_payload.iv.clone();
    manifest.encryption_information.key_access[0].wrapped_key =
        encrypted_payload.encrypted_key.clone();

    // Set policy
    manifest.set_policy(
        &serde_json::to_string(&request.policy)
            .map_err(|e| anyhow::anyhow!("Failed to serialize policy: {}", e))?,
    );

    // Create a temporary file for the TDF archive
    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| anyhow::anyhow!("Failed to create temp file: {}", e))?;
    let temp_path = temp_file.path().to_owned();

    // Create TDF archive
    let mut builder = TdfArchiveBuilder::new(&temp_path)
        .map_err(|e| anyhow::anyhow!("Failed to create TDF archive: {}", e))?;

    // Add encrypted data to the archive
    let encrypted_data = base64::engine::general_purpose::STANDARD
        .decode(&encrypted_payload.ciphertext)
        .map_err(|e| anyhow::anyhow!("Failed to decode ciphertext: {}", e))?;

    builder
        .add_entry(&manifest, &encrypted_data, 0)
        .map_err(|e| anyhow::anyhow!("Failed to add entry to archive: {}", e))?;

    builder
        .finish()
        .map_err(|e| anyhow::anyhow!("Failed to finalize archive: {}", e))?;

    // Read the created TDF file
    let tdf_data =
        std::fs::read(&temp_path).map_err(|e| anyhow::anyhow!("Failed to read TDF file: {}", e))?;

    // Encode the TDF file as base64
    let tdf_base64 = base64::engine::general_purpose::STANDARD.encode(&tdf_data);

    // Generate a unique ID for this operation
    let id = Uuid::new_v4().to_string();

    Ok(Json(CreateTdfResponse {
        id,
        tdf_data: tdf_base64,
    }))
}

/// Read a TDF archive
async fn read_tdf(
    State(state): State<AppState>,
    Json(request): Json<ReadTdfRequest>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .request_counter
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    // Decode the base64 TDF data
    let tdf_data = base64::engine::general_purpose::STANDARD
        .decode(&request.tdf_data)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 TDF data: {}", e)))?;

    // Create a temporary file for the TDF archive
    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| anyhow::anyhow!("Failed to create temp file: {}", e))?;
    let temp_path = temp_file.path().to_owned();

    // Write the TDF data to the temp file
    std::fs::write(&temp_path, &tdf_data)
        .map_err(|e| anyhow::anyhow!("Failed to write TDF data to temp file: {}", e))?;

    // Open the TDF archive
    let mut archive = TdfArchive::open(&temp_path)
        .map_err(|e| anyhow::anyhow!("Failed to open TDF archive: {}", e))?;

    // Read the first entry
    let entry = archive
        .by_index()
        .map_err(|e| anyhow::anyhow!("Failed to read TDF entry: {}", e))?;

    // Convert manifest to JSON
    let manifest_json = serde_json::to_value(&entry.manifest)
        .map_err(|e| anyhow::anyhow!("Failed to serialize manifest: {}", e))?;

    // Encode the payload as base64
    let payload_base64 = base64::engine::general_purpose::STANDARD.encode(&entry.payload);

    Ok(Json(ReadTdfResponse {
        manifest: manifest_json,
        payload: payload_base64,
    }))
}

/// Encrypt data
async fn encrypt_data(
    State(state): State<AppState>,
    Json(request): Json<EncryptRequest>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .request_counter
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    // Decode the base64 input data
    let data = base64::engine::general_purpose::STANDARD
        .decode(&request.data)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 data: {}", e)))?;

    // Initialize TDF encryption
    let tdf_encryption = TdfEncryption::new()
        .map_err(|e| anyhow::anyhow!("Failed to initialize encryption: {}", e))?;

    // Encrypt the data
    let encrypted_payload = tdf_encryption
        .encrypt(&data)
        .map_err(|e| anyhow::anyhow!("Failed to encrypt data: {}", e))?;

    Ok(Json(EncryptResponse {
        encrypted_data: encrypted_payload.ciphertext,
        iv: encrypted_payload.iv,
        encrypted_key: encrypted_payload.encrypted_key,
        policy_key_hash: encrypted_payload.policy_key_hash,
    }))
}

/// Decrypt data
async fn decrypt_data(
    State(state): State<AppState>,
    Json(request): Json<DecryptRequest>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .request_counter
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    // Decode the base64 policy key
    let policy_key = base64::engine::general_purpose::STANDARD
        .decode(&request.policy_key)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 policy key: {}", e)))?;

    // Create encrypted payload
    let encrypted_payload = opentdf::EncryptedPayload {
        ciphertext: request.encrypted_data,
        iv: request.iv,
        encrypted_key: request.encrypted_key,
        policy_key_hash: request.policy_key_hash,
    };

    // Decrypt the data
    let decrypted_data = TdfEncryption::decrypt(&policy_key, &encrypted_payload)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt data: {}", e))?;

    // Encode the decrypted data as base64
    let data_base64 = base64::engine::general_purpose::STANDARD.encode(&decrypted_data);

    Ok(Json(DecryptResponse { data: data_base64 }))
}

/// Create a policy
async fn create_policy(
    State(state): State<AppState>,
    Json(request): Json<CreatePolicyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .request_counter
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    // Generate UUID for policy
    let policy_uuid = Uuid::new_v4().to_string();

    // Construct policy JSON
    let policy = serde_json::json!({
        "uuid": policy_uuid,
        "body": {
            "dataAttributes": request.attributes,
            "dissem": request.dissemination,
            "expiry": request.expiry,
        }
    });

    Ok(Json(CreatePolicyResponse { policy }))
}

/// Validate a policy against a TDF archive
async fn validate_policy(
    State(state): State<AppState>,
    Json(request): Json<ValidatePolicyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .request_counter
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    // Decode the base64 TDF data
    let tdf_data = base64::engine::general_purpose::STANDARD
        .decode(&request.tdf_data)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 TDF data: {}", e)))?;

    // Create a temporary file for the TDF archive
    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| anyhow::anyhow!("Failed to create temp file: {}", e))?;
    let temp_path = temp_file.path().to_owned();

    // Write the TDF data to the temp file
    std::fs::write(&temp_path, &tdf_data)
        .map_err(|e| anyhow::anyhow!("Failed to write TDF data to temp file: {}", e))?;

    // Open the TDF archive
    let mut archive = TdfArchive::open(&temp_path)
        .map_err(|e| anyhow::anyhow!("Failed to open TDF archive: {}", e))?;

    // Read the first entry
    let entry = archive
        .by_index()
        .map_err(|e| anyhow::anyhow!("Failed to read TDF entry: {}", e))?;

    // Get the policy from the manifest
    let policy_str = entry
        .manifest
        .get_policy()
        .map_err(|e| anyhow::anyhow!("Failed to get policy from manifest: {}", e))?;

    // Parse the policy
    let archive_policy: serde_json::Value = serde_json::from_str(&policy_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse policy: {}", e))?;

    // Simple validation: check if policy UUIDs match
    // In a real implementation, this would do more sophisticated validation
    let valid = archive_policy["uuid"] == request.policy["uuid"];

    let reason = if !valid {
        Some("Policy UUIDs do not match".to_string())
    } else {
        None
    };

    Ok(Json(ValidatePolicyResponse { valid, reason }))
}
