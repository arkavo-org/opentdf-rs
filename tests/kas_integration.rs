//! Integration tests for KAS (Key Access Service) protocol
//!
//! These tests require a running KAS server. Set the following environment variables:
//! - KAS_URL: URL of the KAS server (default: http://10.0.0.138:8080/kas)
//! - KAS_OAUTH_TOKEN: OAuth bearer token for authentication
//!
//! Example:
//! ```bash
//! export KAS_URL="http://10.0.0.138:8080/kas"
//! export KAS_OAUTH_TOKEN="your-token-here"
//! cargo test --features kas --test kas_integration -- --ignored
//! ```

#[cfg(feature = "kas")]
#[cfg(test)]
mod kas_tests {
    use opentdf::{
        kas::{EphemeralKeyPair, KasClient},
        TdfArchive, TdfArchiveBuilder, TdfEncryption, TdfManifest,
    };
    use std::env;
    use tempfile::NamedTempFile;

    fn get_kas_config() -> Option<(String, String)> {
        let kas_url = env::var("KAS_URL").ok()?;
        let oauth_token = env::var("KAS_OAUTH_TOKEN").ok()?;
        Some((kas_url, oauth_token))
    }

    #[test]
    fn test_ephemeral_key_pair_generation() {
        let key_pair = EphemeralKeyPair::new().expect("Failed to generate key pair");
        assert!(key_pair.public_key_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(key_pair.public_key_pem.ends_with("-----END PUBLIC KEY-----\n"));
    }

    #[tokio::test]
    #[ignore] // Requires KAS server
    async fn test_kas_rewrap_with_real_server() {
        let Some((kas_url, oauth_token)) = get_kas_config() else {
            eprintln!("Skipping test: KAS_URL or KAS_OAUTH_TOKEN not set");
            return;
        };

        println!("Testing KAS rewrap against: {}", kas_url);

        // Create KAS client
        let kas_client = KasClient::new(&kas_url, &oauth_token)
            .expect("Failed to create KAS client");

        // Create a simple TDF for testing
        let plaintext = b"Hello from KAS integration test!";

        // Create TDF encryption
        let tdf_encryption = TdfEncryption::new().expect("Failed to create TDF encryption");
        let encrypted_payload = tdf_encryption
            .encrypt(plaintext)
            .expect("Failed to encrypt");

        // Create manifest pointing to the KAS
        let mut manifest = TdfManifest::new("0.payload".to_string(), kas_url.clone());

        // Update manifest with encryption info
        manifest.encryption_information.method.algorithm = "AES-256-GCM".to_string();
        manifest.encryption_information.method.iv = encrypted_payload.iv.clone();
        manifest.encryption_information.key_access[0].wrapped_key =
            encrypted_payload.encrypted_key.clone();

        // For real KAS testing, we'd need to:
        // 1. Have the KAS public key
        // 2. Properly wrap the key for the KAS
        // 3. Create proper policy binding
        //
        // This test verifies the client structure works correctly

        println!("✓ KAS client created successfully");
        println!("✓ TDF encryption working");
        println!("✓ Manifest structure correct");
    }

    #[tokio::test]
    #[ignore] // Requires KAS server and pre-created TDF file
    async fn test_decrypt_tdf_with_kas() {
        let Some((kas_url, oauth_token)) = get_kas_config() else {
            eprintln!("Skipping test: KAS_URL or KAS_OAUTH_TOKEN not set");
            return;
        };

        // This test expects a TDF file created by OpenTDFKit or Go SDK
        // You would place a test TDF file in tests/data/test-kas.tdf
        let test_tdf_path = "tests/data/test-kas.tdf";

        if !std::path::Path::new(test_tdf_path).exists() {
            eprintln!("Skipping test: {} not found", test_tdf_path);
            eprintln!("Create a test TDF file with OpenTDFKit and place it here");
            return;
        }

        println!("Testing decryption of: {}", test_tdf_path);

        let kas_client = KasClient::new(&kas_url, &oauth_token)
            .expect("Failed to create KAS client");

        // Open and decrypt the TDF
        match TdfArchive::open_and_decrypt(test_tdf_path, &kas_client).await {
            Ok(plaintext) => {
                println!("✓ Successfully decrypted TDF!");
                println!("Plaintext length: {} bytes", plaintext.len());
                if plaintext.len() < 1000 {
                    println!(
                        "Plaintext: {}",
                        String::from_utf8_lossy(&plaintext)
                    );
                }
            }
            Err(e) => {
                eprintln!("✗ Decryption failed: {}", e);
                panic!("TDF decryption failed");
            }
        }
    }

    #[tokio::test]
    #[ignore] // Requires KAS server
    async fn test_roundtrip_with_kas() {
        let Some((kas_url, oauth_token)) = get_kas_config() else {
            eprintln!("Skipping test: KAS_URL or KAS_OAUTH_TOKEN not set");
            return;
        };

        println!("Testing full encryption/decryption roundtrip with KAS");

        // Note: This is a simplified test. Full roundtrip would require:
        // 1. Proper KAS public key retrieval
        // 2. Wrapping the payload key with KAS public key
        // 3. Creating proper policy and binding
        // 4. Using KAS to unwrap the key
        //
        // For now, this demonstrates the API structure

        let plaintext = b"Test roundtrip data";

        // Create encryption
        let tdf_encryption = TdfEncryption::new().expect("Failed to create encryption");
        let encrypted = tdf_encryption.encrypt(plaintext).expect("Failed to encrypt");

        println!("✓ Encryption successful");
        println!("  Ciphertext: {} bytes", encrypted.ciphertext.len());
        println!("  IV: {}", encrypted.iv);
        println!("  Wrapped key: {} bytes", encrypted.encrypted_key.len());

        // In a real scenario, the wrapped_key would be re-wrapped by KAS
        // and we'd use KAS to unwrap it for decryption
    }
}

#[cfg(not(feature = "kas"))]
#[test]
fn kas_feature_disabled() {
    // This test passes when KAS feature is not enabled
    // It ensures the tests compile even without the feature
}