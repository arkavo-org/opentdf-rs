# OpenTDF-RS

A Rust implementation of the OpenTDF (Trusted Data Format) specification, providing data-centric security that travels with the data.

## Overview

OpenTDF-RS enables cryptographic binding of access policies directly to data objects, supporting a Zero Trust security model with continuous verification. This library allows secure data sharing across organizations and industries.

## Features

- TDF Archive Creation and Reading
- Cryptographic Operations (AES-256-GCM encryption)
- Policy Binding through HMAC-SHA256
- Streaming Operations for Efficient Data Handling

## MCP Server

The Model Context Protocol (MCP) server provides an HTTP interface to access OpenTDF-RS capabilities. It enables systems to interact with TDF operations through a standardized API.

### MCP Endpoints

| Endpoint                   | Method | Description                                |
|----------------------------|--------|--------------------------------------------|
| `/mcp/tdf/create`          | POST   | Create a new TDF archive                   |
| `/mcp/tdf/read`            | POST   | Read contents from a TDF archive           |
| `/mcp/tdf/encrypt`         | POST   | Encrypt data with TDF encryption           |
| `/mcp/tdf/decrypt`         | POST   | Decrypt TDF-encrypted data                 |
| `/mcp/policy/create`       | POST   | Create a new policy for TDF encryption     |
| `/mcp/policy/validate`     | POST   | Validate a policy against a TDF archive    |
| `/mcp/health`              | GET    | Check server health status                 |

### Running the MCP Server

```bash
cargo run --bin opentdf-mcp-server
```

## Getting Started

### Installation

Add to your Cargo.toml:

```toml
[dependencies]
opentdf = "0.3.0"
```

### Basic Usage

```rust
use opentdf::{TdfArchive, TdfArchiveBuilder, TdfEncryption, TdfManifest};

// Create a new TDF encryption
let tdf_encryption = TdfEncryption::new()?;

// Encrypt data
let data = b"Sensitive data".to_vec();
let encrypted_payload = tdf_encryption.encrypt(&data)?;

// Create manifest
let mut manifest = TdfManifest::new(
    "0.payload".to_string(),
    "http://kas.example.com".to_string(),
);

// Update manifest with encryption details
manifest.encryption_information.method.algorithm = "AES-256-GCM".to_string();
manifest.encryption_information.method.iv = encrypted_payload.iv.clone();
manifest.encryption_information.key_access[0].wrapped_key = 
    encrypted_payload.encrypted_key.clone();

// Create TDF archive
let mut builder = TdfArchiveBuilder::new("example.tdf")?;
builder.add_entry(&manifest, &encrypted_payload.ciphertext.as_bytes(), 0)?;
builder.finish()?;
```

## License

This project is licensed under [LICENSE].