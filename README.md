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

OpenTDF-RS includes an implementation of the Model Context Protocol (MCP) server, allowing AI assistants and other tools to interact with TDF capabilities via a standardized API.

### MCP Server Tools

The MCP server provides the following tools:

| Tool Name        | Description                                       |
|------------------|---------------------------------------------------|
| `tdf_create`     | Creates a new TDF archive with encrypted data     |
| `tdf_read`       | Reads contents from a TDF archive                 |
| `encrypt`        | Encrypts data using TDF encryption methods        |
| `decrypt`        | Decrypts TDF-encrypted data                       |
| `policy_create`  | Creates a new policy for TDF encryption           |
| `policy_validate`| Validates a policy against a TDF archive          |

### Running the MCP Server

To run the MCP server and interact with it via Claude or other MCP-compatible clients:

```bash
cargo run -p opentdf-mcp-server
```

The server listens on stdio for JSON-RPC messages, making it compatible with tools like Claude Code that use the MCP protocol for communication.

### Using with Claude Code

Claude Code can connect to the MCP server to perform TDF operations:

```bash
claude --mcp="cargo run -p opentdf-mcp-server"
```

This starts Claude with the MCP server, allowing you to use TDF capabilities directly within the chat interface.

Example commands:

```
/mcp opentdf tdf_create {"data": "SGVsbG8gV29ybGQh", "kas_url": "https://kas.example.com", "policy": {"uuid": "sample-uuid", "body": {"dataAttributes": ["classification::public"], "dissem": ["user@example.com"]}}}
```

```
/mcp opentdf tdf_read {"tdf_data": "<base64-encoded-tdf-data>"}
```

### Testing the MCP Server

A test script is provided to verify the MCP server functionality:

```bash
node tools/test-mcp.js
```

This script tests:
1. Server initialization 
2. Tool availability
3. Basic tool functionality
4. Error handling

## Development

### MCP Server Development

The MCP server implements the JSON-RPC 2.0 protocol over stdio to provide TDF capabilities to clients. When developing or extending the MCP server:

1. **Tool Definitions**: Define tools with both `schema` and `inputSchema` fields for compatibility
2. **Protocol Version**: Use the latest MCP protocol version (currently "2024-11-05")
3. **Response Format**: Ensure all responses follow the JSON-RPC 2.0 specification
4. **Error Handling**: Use standard JSON-RPC error codes (-32xxx)
5. **Testing**: Use `tools/test-mcp.js` to verify functionality

If adding new tools, remember to:
- Add the tool to both the initialize response and listTools response
- Implement proper parameter validation
- Follow the JSON-RPC request/response flow
- Document the tool in this README

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