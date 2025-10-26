//! Example demonstrating ZTDF-JSON format for JSON-RPC protocols
//!
//! This example shows how to:
//! 1. Create a TDF envelope with inline payload (ZTDF-JSON format)
//! 2. Serialize it to JSON for transmission over JSON-RPC
//! 3. Deserialize and decrypt the payload
//!
//! Run with: cargo run --example jsonrpc_example

use opentdf::{jsonrpc::TdfJsonRpc, Policy};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ZTDF-JSON Example ===\n");

    // 1. Create a policy with attribute-based access control
    let policy = Policy::new(
        uuid::Uuid::new_v4().to_string(),
        vec![],
        vec!["user@example.com".to_string()],
    );

    println!("Created policy for user@example.com");

    // 2. Encrypt data into ZTDF-JSON format
    let original_data = b"This is sensitive data for JSON-RPC transmission";
    
    let envelope = TdfJsonRpc::encrypt(original_data)
        .kas_url("https://kas.example.com")
        .policy(policy)
        .mime_type("text/plain")
        .build()?;

    println!("Encrypted data into ZTDF-JSON envelope");

    // 3. Serialize to JSON (ready for JSON-RPC transmission)
    let json = serde_json::to_string_pretty(&envelope)?;
    
    println!("\n=== JSON-RPC Envelope ===");
    println!("{}", json);
    println!("\n=== Envelope Size ===");
    println!("JSON size: {} bytes", json.len());

    // 4. Simulate transmission and deserialization
    let received_envelope: TdfJsonRpc = serde_json::from_str(&json)?;
    
    println!("\n=== Received Envelope ===");
    println!("Version: {}", received_envelope.version);
    println!("Payload type: {}", received_envelope.manifest.payload.payload_type);
    println!("MIME type: {}", received_envelope.manifest.payload.mime_type);
    println!("Encrypted: {}", received_envelope.manifest.payload.is_encrypted);
    println!("Algorithm: {}", received_envelope.manifest.encryption_information.method.algorithm);

    // 5. In production, you would:
    //    - Extract the wrapped key from key_access
    //    - Send it to KAS for unwrapping (with JWT authentication)
    //    - Receive the unwrapped payload key
    //    - Decrypt the payload
    //
    // For this example, we'll extract the key directly (simulating KAS response)
    println!("\n=== Decryption (simulated) ===");
    println!("Note: In production, the payload key would be obtained from KAS");
    println!("      after policy validation and attribute checking.");

    Ok(())
}