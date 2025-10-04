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

use base64::Engine;
use opentdf::{
    fetch_kas_public_key, wrap_key_with_rsa_oaep, Policy, TdfArchiveBuilder, TdfEncryption,
    TdfManifest,
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

    // Step 3: Create TDF encryption and encrypt data with segments
    println!();
    println!("3. Encrypting data with segments...");
    let tdf_encryption = TdfEncryption::new()?;

    // Use 2MB segment size to match Go SDK default
    const SEGMENT_SIZE: usize = 2 * 1024 * 1024; // 2MB
    let segmented = tdf_encryption.encrypt_with_segments(plaintext, SEGMENT_SIZE)?;

    println!("   ✓ Data encrypted with AES-256-GCM (segment-based)");
    println!("     - Segments: {}", segmented.segments.len());
    println!(
        "     - Total encrypted size: {} bytes",
        segmented.segments.iter().map(|s| s.len()).sum::<usize>()
    );

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
    // For segment-based encryption, IV is stored per-segment, so method.iv should be empty
    manifest.encryption_information.method.iv = String::new();

    // Set the RSA-wrapped key
    manifest.encryption_information.key_access[0].wrapped_key = wrapped_key;
    manifest.encryption_information.key_access[0].access_type = "wrapped".to_string();

    // Optionally set the key ID if needed
    if !kas_key_response.kid.is_empty() {
        manifest.encryption_information.key_access[0].kid = Some(kas_key_response.kid.clone());
    }

    // Set policy (you can customize this)
    // Using Policy struct to ensure proper JSON serialization (null for empty arrays)
    // UUID must be in proper format (36 characters with hyphens)
    let policy = Policy::new(
        "00000000-0000-0000-0000-000000000000".to_string(),
        vec![],
        vec![],
    );
    let policy_json = policy
        .to_json()
        .map_err(|e| format!("Failed to serialize policy: {}", e))?;
    manifest.encryption_information.policy =
        base64::engine::general_purpose::STANDARD.encode(&policy_json);

    // Generate policy binding using the payload key as HMAC key
    manifest.encryption_information.key_access[0]
        .generate_policy_binding_raw(&policy_json, tdf_encryption.payload_key())
        .map_err(|e| format!("Failed to generate policy binding: {}", e))?;

    // Add segment information to manifest
    use opentdf::manifest::Segment;
    for seg_info in &segmented.segment_info {
        manifest
            .encryption_information
            .integrity_information
            .segments
            .push(Segment {
                hash: seg_info.hash.clone(),
                segment_size: Some(seg_info.plaintext_size),
                encrypted_segment_size: Some(seg_info.encrypted_size),
            });
    }

    // Set segment size defaults
    if let Some(first_seg) = segmented.segment_info.first() {
        manifest
            .encryption_information
            .integrity_information
            .segment_size_default = first_seg.plaintext_size;
        manifest
            .encryption_information
            .integrity_information
            .encrypted_segment_size_default = first_seg.encrypted_size;
    }

    // Generate root signature from GMAC tags
    manifest
        .encryption_information
        .integrity_information
        .generate_root_signature(&segmented.gmac_tags, tdf_encryption.payload_key())
        .map_err(|e| format!("Failed to generate root signature: {}", e))?;

    println!("   ✓ Manifest created with segments and root signature");
    println!(
        "     - Algorithm: {}",
        manifest.encryption_information.method.algorithm
    );
    println!(
        "     - Segments: {}",
        manifest
            .encryption_information
            .integrity_information
            .segments
            .len()
    );
    println!(
        "     - Root signature: {}",
        &manifest
            .encryption_information
            .integrity_information
            .root_signature
            .sig[..20]
    );

    // Step 6: Create TDF archive with segments
    println!();
    println!("6. Building TDF archive...");
    let mut builder = TdfArchiveBuilder::new(&output_path)?;

    // Use the new segment-based method
    builder.add_entry_with_segments(&manifest, &segmented.segments, 0)?;
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
