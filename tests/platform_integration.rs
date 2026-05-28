//! Integration tests with OpenTDF Platform backend
//!
//! These tests verify interoperability between our Rust implementation
//! and the Go-based OpenTDF platform.
//!
//! Prerequisites:
//! - OpenTDF platform running at http://localhost:8080
//! - Keycloak running at http://localhost:8888
//!
//! Run with: cargo test --package opentdf -- --ignored platform

use std::error::Error;

/// Platform configuration for local development
const PLATFORM_ENDPOINT: &str = "http://localhost:8080";
const TOKEN_ENDPOINT: &str =
    "http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token";
const CLIENT_ID: &str = "opentdf-sdk";
const CLIENT_SECRET: &str = "secret";

/// Helper to get an access token from Keycloak
async fn get_access_token() -> Result<String, Box<dyn Error>> {
    let client = reqwest::Client::new();
    let params = [
        ("grant_type", "client_credentials"),
        ("client_id", CLIENT_ID),
        ("client_secret", CLIENT_SECRET),
    ];

    let response = client.post(TOKEN_ENDPOINT).form(&params).send().await?;

    #[derive(serde::Deserialize)]
    struct TokenResponse {
        access_token: String,
    }

    let token_data: TokenResponse = response.json().await?;
    Ok(token_data.access_token)
}

/// Helper to get KAS public key from platform
async fn get_kas_public_key() -> Result<String, Box<dyn Error>> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/kas/v2/kas_public_key", PLATFORM_ENDPOINT))
        .send()
        .await?;

    #[derive(serde::Deserialize)]
    struct KasKeyResponse {
        #[serde(rename = "publicKey")]
        public_key: String,
    }

    let key_data: KasKeyResponse = response.json().await?;
    Ok(key_data.public_key)
}

#[tokio::test]
#[ignore] // Run explicitly with --ignored flag
async fn test_platform_health() -> Result<(), Box<dyn Error>> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/healthz", PLATFORM_ENDPOINT))
        .send()
        .await?;

    assert!(response.status().is_success());

    #[derive(serde::Deserialize)]
    struct HealthResponse {
        status: String,
    }

    let health: HealthResponse = response.json().await?;
    assert_eq!(health.status, "SERVING");

    println!("✓ Platform health check passed");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_get_access_token() -> Result<(), Box<dyn Error>> {
    let token = get_access_token().await?;

    // JWT tokens have 3 parts separated by dots
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts");

    println!("✓ Successfully obtained access token");
    println!("  Token length: {} chars", token.len());
    println!("  First 20 chars: {}...", &token[..20]);

    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_get_kas_public_key() -> Result<(), Box<dyn Error>> {
    let public_key = get_kas_public_key().await?;

    assert!(public_key.contains("BEGIN PUBLIC KEY"));
    assert!(public_key.contains("END PUBLIC KEY"));

    println!("✓ Successfully retrieved KAS public key");
    println!("  Key preview:\n{}", &public_key[..80]);

    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_encrypt_decrypt_roundtrip() -> Result<(), Box<dyn Error>> {
    // This test will encrypt data with our Rust implementation
    // and verify it can be decrypted, ensuring compatibility
    // with the platform's key management

    // TODO: Once we have the full TDF client implementation:
    // let plaintext = b"Hello from Rust OpenTDF implementation!";
    // let client = create_test_client().await?;
    // let tdf = client.encrypt(plaintext).await?;
    // let decrypted = client.decrypt(&tdf).await?;
    // assert_eq!(plaintext, decrypted.as_slice());

    println!("✓ Encrypt/decrypt roundtrip test (TODO: implement)");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_cross_platform_compatibility() -> Result<(), Box<dyn Error>> {
    // This test will:
    // 1. Create a TDF with Rust implementation
    // 2. Verify it can be read by platform/Go SDK
    // 3. Create a TDF with Go SDK
    // 4. Verify it can be read by our Rust implementation

    println!("✓ Cross-platform compatibility test (TODO: implement)");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_policy_enforcement() -> Result<(), Box<dyn Error>> {
    // Test that policy attributes are correctly enforced
    // by the platform when accessing TDF data

    println!("✓ Policy enforcement test (TODO: implement)");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_kas_rewrap_protocol() -> Result<(), Box<dyn Error>> {
    // Test the complete KAS rewrap protocol:
    // 1. Encrypt payload key with KAS public key
    // 2. Create rewrap request with proper JWT
    // 3. Verify rewrap response
    // 4. Decrypt payload key

    let _kas_public_key = get_kas_public_key().await?;
    println!("✓ Retrieved KAS public key for rewrap test");

    // TODO: Implement full KAS rewrap protocol test
    println!("✓ KAS rewrap protocol test (TODO: implement)");

    Ok(())
}

// ---------------------------------------------------------------------------
// ConnectRPC migration verification (#85)
//
// These tests run against the real Arkavo platform and document the milestone
// state of the Connect transport. They are #[ignore]d by default; opt in with:
//
//   cargo test --test platform_integration --all-features -- --ignored connect
//
// or, if KAS_INTEGRATION_TESTS=1 is set, the user can run them by name.
// ---------------------------------------------------------------------------

const ARKAVO_PLATFORM: &str = "https://platform.arkavo.net";

#[tokio::test]
#[ignore]
async fn connect_well_known_endpoint_returns_kas_config() -> Result<(), Box<dyn Error>> {
    use opentdf::kas_discovery::fetch_well_known;
    let http = reqwest::Client::new();
    let cfg = fetch_well_known(ARKAVO_PLATFORM, &http).await?;
    let kas = cfg.kas.expect("kas block should be present");
    assert!(
        kas.connect_rewrap_url.is_some(),
        "platform should advertise connect_rewrap_url"
    );
    assert!(
        kas.connect_public_key_url.is_some(),
        "platform should advertise connect_public_key_url"
    );
    assert!(
        kas.rewrap_url.is_some(),
        "platform also exposes legacy REST rewrap_url (transitional)"
    );
    println!("✓ well-known reports both Connect and REST URLs");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn connect_public_key_returns_pem() -> Result<(), Box<dyn Error>> {
    use opentdf::kas_discovery::{KasEndpoints, fetch_well_known};
    use opentdf::kas_key::fetch_kas_public_key_connect;

    let http = reqwest::Client::new();
    let cfg = fetch_well_known(ARKAVO_PLATFORM, &http).await?;
    let endpoints = KasEndpoints::from_config(&cfg)?;
    let resp = fetch_kas_public_key_connect(&endpoints.public_key_url, &http).await?;
    assert!(
        resp.public_key.starts_with("-----BEGIN PUBLIC KEY-----"),
        "expected PEM, got: {}",
        resp.public_key
    );
    assert!(!resp.kid.is_empty(), "kid should be populated");
    println!(
        "✓ Connect PublicKey returned kid={} ({} bytes PEM)",
        resp.kid,
        resp.public_key.len()
    );
    Ok(())
}

#[tokio::test]
#[ignore]
async fn connect_rewrap_fails_with_fake_bearer_returns_401() -> Result<(), Box<dyn Error>> {
    use opentdf::TdfManifest;
    use opentdf::kas::KasClient;
    use opentdf::kas_discovery::fetch_well_known;
    use opentdf_protocol::KasError;

    let http = reqwest::Client::new();
    let cfg = fetch_well_known(ARKAVO_PLATFORM, &http).await?;
    // Pass a syntactically-plausible bearer that the platform will reject.
    let client = KasClient::new(&cfg, "eyJhbGciOiJub25lIn0.e30.")?;

    // Build a minimal manifest with a real policy UUID so the client can
    // serialise the rewrap request and actually reach the platform.
    let mut manifest = TdfManifest::new("0.payload".to_string(), ARKAVO_PLATFORM.to_string());
    manifest.set_policy_raw(r#"{"uuid":"00000000-0000-0000-0000-000000000000"}"#);
    let result = client.rewrap_standard_tdf(&manifest).await;

    let err = result.expect_err("rewrap should fail without valid auth");
    match &err {
        KasError::AuthenticationFailed { reason } => {
            // Connect 'unauthenticated' code should surface in the reason string
            // when the platform returns a Connect error envelope.
            println!("✓ Connect rewrap returned AuthenticationFailed: {reason}");
        }
        KasError::AccessDenied { reason, .. } => {
            // Some Connect implementations may return permission_denied (403)
            // when the request is malformed.
            println!("✓ Connect rewrap returned AccessDenied: {reason}");
        }
        KasError::HttpError { status, message } => {
            // A 404 would mean the Connect rewrap path does not exist on the
            // platform — that would NOT prove Connect plumbing, so reject it
            // explicitly. Any other 4xx/5xx means the Connect endpoint received
            // and rejected our (deliberately unauthenticated) request.
            assert_ne!(
                *status, 404,
                "got HTTP 404 — Connect rewrap path missing, plumbing NOT proven: {message}"
            );
            assert!(
                *status >= 400 && *status < 600,
                "expected 4xx/5xx, got {status}"
            );
            println!("✓ Connect rewrap returned HTTP {status}: {message}");
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
    Ok(())
}
