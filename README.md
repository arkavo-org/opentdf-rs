# OpenTDF-RS

A Rust implementation of the OpenTDF (Trusted Data Format) specification, providing data-centric security that travels with the data.

## Overview

OpenTDF-RS enables cryptographic binding of access policies directly to data objects, supporting a Zero Trust security model with continuous verification. This library allows secure data sharing across organizations and industries.

## Features

- TDF Archive Creation and Reading
- Cryptographic Operations (AES-256-GCM encryption)
- Policy Binding through HMAC-SHA256
- Streaming Operations for Efficient Data Handling
- **Attribute-Based Access Control (ABAC)**: Fine-grained access control using attributes
- **Hierarchical Attributes**: Support for attributes with inheritance relationships
- **Time-Based Constraints**: Policies with validity periods
- **Logical Operators**: AND, OR, NOT combinations for complex policies
- **Comprehensive Audit Logging**: Detailed records of access attempts and attribute evaluation
- **KAS (Key Access Service) Integration**: Full rewrap protocol support for production deployments
- **MCP Server with KAS Support**: AI agents can decrypt TDF files using KAS

## Attribute-Based Access Control (ABAC)

OpenTDF-RS implements ABAC to provide fine-grained access control that is cryptographically bound to protected data.

![ABAC Flow Diagram](https://mermaid.ink/img/pako:eNp1kU9PwzAMxb_KyU4g0Y-QOFQwOCA0ISHYbodq85pqS5w5CaJM_e44bWFsApeX_PL7PScHZa0FVajWOcFzUK1N8Jm96NaQ9Q18CZsKQ4_5Y5QO9AKVEYUjL2YZzQ-TJ0iJOjB-Cd9bMkc5Sj-JvB6nQXk2UpWIZ8zoD7tD8lEpGfT5FnDdkCefw6dkWQDTgBYzPBHj-OZW-1QY-MXbAPHKDfWOzKBJXtAXUd48S_B9I4R2QbvBjnvQ0O-5d2S0v0l8sKfEYUx7CbFoSLSudUh7k7OSiB3YWwypz7ub2NrJxD9w9LH7gPEf84G-wW1FPvfk47RsH3rMfWdJbUWMb9OG9A62hOUbz7bZyOK5KLGCVBjDYaKXfv4s8WdxOOCGKzRDrrhA5QZ8DQrGSRZHm2PkJdtE0baI16d1uoqLdZ6U-TaJizJZ5vESVTQuoyz6BvZcsks?type=png)

### Core Components

#### AttributeIdentifier

Represents a uniquely identifiable attribute with namespace and name:

```rust
// Create from string in "namespace:name" format
let attr_id = AttributeIdentifier::from_string("gov.example:clearance")?;

// Or create directly
let attr_id = AttributeIdentifier {
    namespace: "gov.example".to_string(),
    name: "clearance".to_string(),
};
```

#### AttributeValue

Supports multiple data types for flexible attribute representation:

```rust
// String value
let value = AttributeValue::String("TOP_SECRET".to_string());

// Numeric value
let value = AttributeValue::Number(42.0);

// Boolean value
let value = AttributeValue::Boolean(true);

// Date/time value
let value = AttributeValue::DateTime(chrono::Utc::now());

// Array values
let value = AttributeValue::StringArray(vec!["ENGINEERING".to_string(), "EXECUTIVE".to_string()]);
let value = AttributeValue::NumberArray(vec![1.0, 2.0, 3.0]);
```

#### Operators

Rich set of comparison operators for attribute evaluation:

| Operator | Description | Example |
|----------|-------------|---------|
| Equals | Exact match | department == "ENGINEERING" |
| NotEquals | Negated match | department != "FINANCE" |
| GreaterThan | Numeric comparison | age > 21 |
| GreaterThanOrEqual | Numeric comparison | priority >= 5 |
| LessThan | Numeric comparison | risk < 3 |
| LessThanOrEqual | Numeric comparison | level <= 4 |
| Contains | String contains | name contains "Admin" |
| In | Value in array | department in ["HR", "LEGAL"] |
| AllOf | All array values present | certifications allof ["ISO", "SOC2"] |
| AnyOf | Any array values present | skills anyof ["Rust", "C++"] |
| NotIn | Value not in array | restricted_country notin ["US", "EU"] |
| MinimumOf | Hierarchical minimum | clearance minimumof "SECRET" |
| MaximumOf | Hierarchical maximum | clearance maximumof "TOP_SECRET" |
| Present | Attribute exists | employee_id present |
| NotPresent | Attribute doesn't exist | terminated notpresent |

#### AttributePolicy

Build complex policy expressions with logical operators:

```rust
// Simple condition
let is_executive = AttributePolicy::condition(
    AttributeIdentifier::from_string("gov.example:role")?,
    Operator::Equals,
    Some("EXECUTIVE".into())
);

// Logical AND
let and_policy = AttributePolicy::and(vec![condition1, condition2, condition3]);

// Logical OR
let or_policy = AttributePolicy::or(vec![condition1, condition2, condition3]);

// Logical NOT (using operator overloading)
let not_policy = !condition1;

// Complex nested policy
let complex_policy = AttributePolicy::or(vec![
    AttributePolicy::and(vec![condition1, condition2]),
    AttributePolicy::and(vec![condition3, !condition4]),
]);
```

#### Policy Structure

Complete policy with time constraints and dissemination:

```rust
// Create policy with attribute conditions and recipients
let policy = Policy {
    uuid: uuid::Uuid::new_v4().to_string(),
    valid_from: Some(chrono::Utc::now()),
    valid_to: Some(chrono::Utc::now() + chrono::Duration::days(30)),
    body: PolicyBody {
        attributes: vec![attribute_policy],
        dissem: vec!["user@example.com".to_string()],
    },
};
```

### ABAC Integration with TDF

```rust
use opentdf::{
    AttributePolicy, AttributeIdentifier, AttributeValue, Operator, 
    Policy, PolicyBody, TdfArchive, TdfArchiveBuilder, TdfEncryption, TdfManifest
};
use std::collections::HashMap;

// 1. Create policy with attribute conditions
let clearance = AttributePolicy::condition(
    AttributeIdentifier::from_string("gov.example:clearance")?,
    Operator::MinimumOf,
    Some("SECRET".into())
);

let department = AttributePolicy::condition(
    AttributeIdentifier::from_string("gov.example:department")?,
    Operator::In,
    Some(AttributeValue::StringArray(vec![
        "ENGINEERING".to_string(), 
        "EXECUTIVE".to_string()
    ]))
);

// Combine with logical AND
let combined_policy = AttributePolicy::and(vec![clearance, department]);

// Create full policy with time constraints
let policy = Policy {
    uuid: uuid::Uuid::new_v4().to_string(),
    valid_from: Some(chrono::Utc::now()),
    valid_to: Some(chrono::Utc::now() + chrono::Duration::days(30)),
    body: PolicyBody {
        attributes: vec![combined_policy],
        dissem: vec!["user@example.com".to_string()],
    },
};

// 2. Encrypt data using TDF
let data = b"Sensitive information".to_vec();
let tdf_encryption = TdfEncryption::new()?;
let encrypted_payload = tdf_encryption.encrypt(&data)?;

// 3. Create manifest with KAS information
let mut manifest = TdfManifest::new(
    "0.payload".to_string(),
    "https://kas.example.com".to_string(),
);

manifest.encryption_information.method.algorithm = "AES-256-GCM".to_string();
manifest.encryption_information.method.iv = encrypted_payload.iv.clone();
manifest.encryption_information.key_access[0].wrapped_key = 
    encrypted_payload.encrypted_key.clone();

// 4. Bind policy to manifest and generate cryptographic binding
manifest.set_policy(&policy)?;
manifest.encryption_information.key_access[0].generate_policy_binding(
    &policy, 
    tdf_encryption.policy_key()
)?;

// 5. Create TDF archive with encrypted payload
let mut builder = TdfArchiveBuilder::new("example.tdf")?;
builder.add_entry(&manifest, &encrypted_payload.ciphertext.as_bytes(), 0)?;
builder.finish()?;

// 6. Later: Evaluate access based on user attributes
let user_attrs = HashMap::from([
    (
        AttributeIdentifier::from_string("gov.example:clearance")?, 
        AttributeValue::String("TOP_SECRET".to_string())
    ),
    (
        AttributeIdentifier::from_string("gov.example:department")?, 
        AttributeValue::String("ENGINEERING".to_string())
    ),
]);

let access_granted = combined_policy.evaluate(&user_attrs)?;
assert!(access_granted, "User should have access based on attributes");
```

### Common Policy Patterns

#### Role-Based Restrictions

```rust
// Require specific role
let role_policy = AttributePolicy::condition(
    AttributeIdentifier::from_string("org:role")?,
    Operator::Equals,
    Some("ADMIN".into())
);
```

#### Multi-Department Access

```rust
// Allow access for multiple departments
let dept_policy = AttributePolicy::condition(
    AttributeIdentifier::from_string("org:department")?,
    Operator::In,
    Some(AttributeValue::StringArray(vec![
        "FINANCE".to_string(), 
        "LEGAL".to_string(), 
        "EXECUTIVE".to_string()
    ]))
);
```

#### Clearance Level with Time Restriction

```rust
// Require minimum clearance and time-bound access
let clearance_policy = AttributePolicy::condition(
    AttributeIdentifier::from_string("gov:clearance")?,
    Operator::MinimumOf,
    Some("SECRET".into())
);

let policy = Policy {
    uuid: uuid::Uuid::new_v4().to_string(),
    // Valid for next 24 hours only
    valid_from: Some(chrono::Utc::now()),
    valid_to: Some(chrono::Utc::now() + chrono::Duration::hours(24)),
    body: PolicyBody {
        attributes: vec![clearance_policy],
        dissem: vec!["user@example.com".to_string()],
    },
};
```

#### Location and Network Restrictions

```rust
// Require specific location AND secure network
let location_policy = AttributePolicy::condition(
    AttributeIdentifier::from_string("env:location")?,
    Operator::Equals,
    Some("HEADQUARTERS".into())
);

let network_policy = AttributePolicy::condition(
    AttributeIdentifier::from_string("env:network_type")?,
    Operator::Equals,
    Some("SECURE".into())
);

let security_policy = AttributePolicy::and(vec![location_policy, network_policy]);
```

#### Exclude Temporary Contractors

```rust
// Employees only (NOT contractors)
let contractor_check = AttributePolicy::condition(
    AttributeIdentifier::from_string("org:employment_type")?,
    Operator::Equals,
    Some("CONTRACTOR".into())
);

let employees_only = !contractor_check;
```

## KAS (Key Access Service) Integration

OpenTDF-RS includes full support for the KAS v2 rewrap protocol, enabling production-ready TDF decryption with centralized key management and access control.

### Overview

The KAS protocol allows:
- **Centralized key management**: KAS securely stores and manages encryption keys
- **Access control enforcement**: KAS validates policies and user attributes before releasing keys
- **Audit logging**: All key access attempts are logged for compliance
- **Zero Trust**: Keys are never stored with encrypted data

### Protocol Flow

```
1. Client generates ephemeral EC key pair (P-256)
2. Client builds rewrap request with TDF manifest
3. Client signs request with JWT (ES256)
4. Client POSTs to KAS /v2/rewrap endpoint
5. KAS validates policy and user attributes
6. KAS returns wrapped key + session public key
7. Client unwraps key: ECDH → HKDF → AES-GCM decrypt
8. Client decrypts TDF payload
```

### Basic Usage

Enable the KAS feature in your `Cargo.toml`:

```toml
[dependencies]
opentdf = { version = "0.3.0", features = ["kas"] }
```

#### Decrypt TDF with KAS

```rust
use opentdf::{TdfArchive, kas::KasClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create KAS client
    let kas_client = KasClient::new(
        "http://kas.example.com/kas",
        "your-oauth-token-here"
    )?;

    // Open and decrypt TDF in one call
    let plaintext = TdfArchive::open_and_decrypt(
        "encrypted-file.tdf",
        &kas_client
    ).await?;

    println!("Decrypted: {}", String::from_utf8_lossy(&plaintext));
    Ok(())
}
```

#### Manual Decryption

For more control over the decryption process:

```rust
use opentdf::{TdfArchive, kas::KasClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create KAS client
    let kas_client = KasClient::new(
        "http://kas.example.com/kas",
        "your-oauth-token-here"
    )?;

    // Open TDF archive
    let mut archive = TdfArchive::open("encrypted-file.tdf")?;
    let entry = archive.by_index()?;

    // Decrypt using KAS
    let plaintext = entry.decrypt_with_kas(&kas_client).await?;

    // Access manifest and policy
    let policy = entry.manifest.get_policy()?;
    println!("Policy: {:?}", policy);

    Ok(())
}
```

### Testing with Real KAS

Integration tests are available that work with a real KAS server:

```bash
# Set environment variables
export KAS_URL="http://10.0.0.138:8080/kas"
export KAS_OAUTH_TOKEN="your-token-here"

# Run KAS integration tests
cargo test --features kas --test kas_integration -- --ignored --nocapture
```

### KAS Error Handling

The KAS client provides detailed error information:

```rust
use opentdf::kas::{KasClient, KasError};

match kas_client.rewrap_standard_tdf(&manifest).await {
    Ok(key) => println!("Successfully unwrapped key"),
    Err(KasError::AccessDenied(reason)) => {
        eprintln!("Access denied: {}", reason);
    }
    Err(KasError::AuthenticationFailed) => {
        eprintln!("Invalid OAuth token");
    }
    Err(KasError::HttpError(msg)) => {
        eprintln!("HTTP error: {}", msg);
    }
    Err(e) => {
        eprintln!("KAS error: {}", e);
    }
}
```

### Interoperability

The Rust KAS client is fully interoperable with:
- **OpenTDFKit** (Swift): iOS/macOS applications
- **platform/sdk** (Go): Backend services
- **OpenTDF Platform**: Production KAS deployments

TDF files created by any SDK can be decrypted by opentdf-rs using KAS, and vice versa.

## MCP Server

OpenTDF-RS includes an implementation of the Model Context Protocol (MCP) server, allowing AI assistants and other tools to interact with TDF capabilities via a standardized API.

### MCP Server Tools

The MCP server provides the following tools:

| Tool Name | Description |
|-----------|-------------|
| `tdf_create` | Creates a new TDF archive with encrypted data |
| `tdf_read` | Reads contents from a TDF archive. Supports optional KAS decryption with `kas_url` and `kas_token` parameters |
| `encrypt` | Encrypts data using TDF encryption methods |
| `decrypt` | Decrypts TDF-encrypted data |
| `policy_create` | Creates a new policy for TDF encryption |
| `policy_validate` | Validates a policy against a TDF archive |
| `attribute_define` | Defines attribute namespaces with optional hierarchies |
| `user_attributes` | Sets user attributes for testing access control |
| `access_evaluate` | Evaluates whether a user with attributes can access protected content with detailed audit records |
| `policy_binding_verify` | Verifies the cryptographic binding of a policy to a TDF |

All access attempts and attribute evaluations are comprehensively logged for compliance and auditing purposes. 
The audit logging system captures detailed information about each operation, including:

- The requesting entity identifiers
- Complete sets of attributes presented
- Attribute sources and verification status
- Detailed evaluation results for each attribute in the policy
- Final access decisions with timestamps
- Policy version information

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
# Create TDF
/mcp opentdf tdf_create {"data": "SGVsbG8gV29ybGQh", "kas_url": "https://kas.example.com", "policy": {"uuid": "sample-uuid", "body": {"attributes": [{"attribute": "gov.example:clearance", "operator": "MinimumOf", "value": "secret"}], "dissem": ["user@example.com"]}}}
```

```
# Read TDF (without decryption)
/mcp opentdf tdf_read {"tdf_data": "<base64-encoded-tdf-data>"}
```

```
# Read and decrypt TDF using KAS
/mcp opentdf tdf_read {"tdf_data": "<base64-encoded-tdf-data>", "kas_url": "http://10.0.0.138:8080/kas", "kas_token": "your-oauth-token"}
```

### ABAC Testing with MCP

The MCP server supports comprehensive ABAC functionality testing:

```bash
# Basic ABAC testing
node tools/test-mcp.js

# Comprehensive attribute access logging test
node tools/audit-logging-test.js
```

These scripts demonstrate:
1. Attribute namespace definition with hierarchies
2. User attribute assignment
3. Policy creation with attribute conditions
4. TDF creation with policy binding
5. Access evaluation based on attributes
6. Policy binding verification
7. Comprehensive audit logging and compliance reporting

The audit logging test generates detailed compliance reports in the `tools/reports` directory. See `tools/audit-guide.md` for more information on the audit logging system.

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

// Set ABAC policy
let policy = Policy::new(
    AttributePolicy::condition(
        AttributeIdentifier::from_string("gov.example:clearance")?,
        Operator::MinimumOf,
        Some("SECRET".into())
    ),
    vec!["user@example.com".to_string()]
);

manifest.set_policy(&policy)?;
manifest.encryption_information.key_access[0].generate_policy_binding(
    &policy, 
    tdf_encryption.policy_key()
)?;

// Create TDF archive
let mut builder = TdfArchiveBuilder::new("example.tdf")?;
builder.add_entry(&manifest, &encrypted_payload.ciphertext.as_bytes(), 0)?;
builder.finish()?;
```

## License

This project is licensed under [LICENSE].