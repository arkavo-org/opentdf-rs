//! Create a TDF file using KAS public key wrapping
//!
//! This example demonstrates creating a TDF file that can be decrypted
//! using the KAS rewrap protocol. The payload key is wrapped with the
//! KAS public key using RSA-OAEP, making the TDF compatible with
//! other OpenTDF implementations (Go SDK, Swift, etc.).
//!
//! Usage:
//! ```bash
//! export KAS_URL="http://localhost:8080/kas"
//! cargo run --example create_tdf_with_kas --features kas -- output.tdf
//! ```

use opentdf::{
    fetch_kas_public_key, wrap_key_with_rsa_oaep, TdfArchiveBuilder, TdfEncryption, TdfManifest,
};
use reqwest::Client;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get command line arguments
    let args: Vec<String> = env::args().collect();
    let output_path = if args.len() >= 2 {
        args[1].clone()
    } else {
        "/tmp/test-from-rust.tdf".to_string()
    };

    // Get KAS URL from environment
    let kas_url = env::var("KAS_URL").unwrap_or_else(|_| "http://localhost:8080/kas".to_string());

    println!("=== Creating TDF with KAS Public Key Wrapping ===");
    println!("KAS URL:  {}", kas_url);
    println!("Output:   {}", output_path);
    println!();

    // Step 1: Fetch KAS public key
    println!("1. Fetching KAS public key...");
    let http_client = Client::new();
    let kas_key_response = fetch_kas_public_key(&kas_url, &http_client).await?;
    println!(
        "   ✓ Retrieved KAS public key (kid: {})",
        kas_key_response.kid
    );

    // Step 2: Create test data
    let plaintext =
        b"Hello from Rust opentdf-rs! This TDF can be decrypted by any OpenTDF implementation.";
    println!();
    println!("2. Preparing plaintext...");
    println!(
        "   Plaintext ({} bytes): {}",
        plaintext.len(),
        String::from_utf8_lossy(plaintext)
    );

    // Step 3: Create TDF encryption and encrypt data
    println!();
    println!("3. Encrypting data...");
    let tdf_encryption = TdfEncryption::new()?;
    let encrypted_payload = tdf_encryption.encrypt(plaintext)?;
    println!("   ✓ Data encrypted with AES-256-GCM");
    println!(
        "     - Ciphertext: {} bytes",
        encrypted_payload.ciphertext.len()
    );
    println!("     - IV: {} bytes", encrypted_payload.iv.len());

    // Step 4: Wrap the payload key with KAS public key using RSA-OAEP
    println!();
    println!("4. Wrapping payload key with KAS public key...");
    let wrapped_key =
        wrap_key_with_rsa_oaep(tdf_encryption.payload_key(), &kas_key_response.public_key)?;
    println!("   ✓ Payload key wrapped with RSA-OAEP-SHA1");
    println!("     - Wrapped key: {} bytes (base64)", wrapped_key.len());

    // Step 5: Create manifest with RSA-wrapped key
    println!();
    println!("5. Creating TDF manifest...");
    let mut manifest = TdfManifest::new("0.payload".to_string(), kas_url.clone());

    // Set encryption metadata
    manifest.encryption_information.method.algorithm = "AES-256-GCM".to_string();
    manifest.encryption_information.method.iv = encrypted_payload.iv.clone();

    // Set the RSA-wrapped key
    manifest.encryption_information.key_access[0].wrapped_key = wrapped_key;
    manifest.encryption_information.key_access[0].access_type = "wrapped".to_string();

    // Optionally set the key ID if needed
    if !kas_key_response.kid.is_empty() {
        manifest.encryption_information.key_access[0].kid = Some(kas_key_response.kid.clone());
    }

    // Set policy (you can customize this)
    let policy_json = r#"{"uuid":"policy-1","body":{"dataAttributes":[],"dissem":[]}}"#;
    manifest.encryption_information.policy =
        base64::engine::general_purpose::STANDARD.encode(policy_json);

    // Generate policy binding using the payload key as HMAC key
    manifest.encryption_information.key_access[0]
        .generate_policy_binding_raw(policy_json, tdf_encryption.payload_key())
        .map_err(|e| format!("Failed to generate policy binding: {}", e))?;

    println!("   ✓ Manifest created");
    println!(
        "     - Algorithm: {}",
        manifest.encryption_information.method.algorithm
    );
    println!(
        "     - Key type: {}",
        manifest.encryption_information.key_access[0].access_type
    );
    println!(
        "     - Policy binding: {}",
        manifest.encryption_information.key_access[0]
            .policy_binding
            .hash
    );

    // Step 6: Create TDF archive
    println!();
    println!("6. Building TDF archive...");
    let mut builder = TdfArchiveBuilder::new(&output_path)?;

    // Decode the base64 ciphertext for storage
    use base64::Engine;
    let ciphertext_bytes =
        base64::engine::general_purpose::STANDARD.decode(&encrypted_payload.ciphertext)?;

    builder.add_entry(&manifest, &ciphertext_bytes, 0)?;
    let file_size = builder.finish()?;

    println!("   ✓ TDF archive created");
    println!("     - File size: {} bytes", file_size);
    println!();

    println!("✓ SUCCESS! TDF file created: {}", output_path);
    println!();
    println!("To decrypt with otdfctl:");
    println!(
        "  /Users/paul/Projects/opentdf/otdfctl/otdfctl decrypt {} \\",
        output_path
    );
    println!("    --host http://localhost:8080 \\");
    println!("    --tls-no-verify \\");
    println!("    --with-client-creds opentdf:secret");
    println!();
    println!("To decrypt with Rust:");
    println!("  export KAS_URL='{}'", kas_url);
    println!("  export KAS_OAUTH_TOKEN='your-token-here'");
    println!(
        "  cargo run --example kas_decrypt --features kas -- {}",
        output_path
    );

    Ok(())
}
