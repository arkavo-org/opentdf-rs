//! Simple TDF encryption example using the high-level API
//!
//! This example shows how easy it is to encrypt data with the new API:
//! just 4 lines of code instead of 30+!
//!
//! Usage:
//! ```bash
//! cargo run --example simple_tdf
//! ```

use opentdf::{Policy, Tdf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Simple TDF Encryption ===\n");

    // Create a simple policy
    let policy = Policy::new(
        uuid::Uuid::new_v4().to_string(),
        vec![],
        vec!["user@example.com".to_string()],
    );

    // Encrypt data - just 4 lines!
    let plaintext = b"Hello from the simplified TDF API!";

    Tdf::encrypt(plaintext)
        .kas_url("https://kas.example.com")
        .policy(policy)
        .to_file("/tmp/simple.tdf")?;

    println!("✓ Encrypted {} bytes to /tmp/simple.tdf", plaintext.len());
    println!("\nThat's it! Just 4 lines of code.");

    Ok(())
}
