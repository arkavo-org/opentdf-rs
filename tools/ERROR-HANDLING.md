# OpenTDF-RS Error Handling Guide

This document explains the error handling mechanisms in OpenTDF-RS, including error codes, response formats, and best practices for client applications.

## Error Response Format

All API errors follow a consistent JSON structure:

```json
{
  "jsonrpc": "2.0",
  "id": "request-id",
  "error": {
    "code": 101,
    "message": "Invalid data format",
    "data": {
      "error_type": "VALIDATION_ERROR",
      "details": "The provided TDF data is not valid base64: Invalid padding",
      "suggestion": "Ensure your TDF data is properly base64-encoded before sending"
    }
  }
}
```

### Fields Explanation

- **code**: A numeric error code categorized by error type
- **message**: A concise, user-friendly error message
- **data.error_type**: The error category (e.g., VALIDATION_ERROR, CRYPTO_ERROR)
- **data.details**: Technical details about the error for debugging
- **data.suggestion**: Optional guidance on how to fix the error

## Error Categories and Codes

OpenTDF-RS uses a structured error code system where each category has a specific range:

| Category | Code Range | Description |
|----------|------------|-------------|
| Validation | 100-199 | Input validation errors |
| Crypto | 200-299 | Cryptographic operation errors |
| Policy | 300-399 | Policy definition or evaluation errors |
| TDF | 400-499 | TDF structure or format errors |
| IO | 500-599 | File and I/O operation errors |
| Attribute | 600-699 | Attribute-related errors |
| Permission | 700-799 | Access permission errors |
| System | 900-999 | General system errors |

### Common Error Codes

#### Validation Errors (100-199)
- **101**: Invalid base64 encoding
- **102**: Invalid JSON format
- **103**: Missing required field
- **104**: Invalid format
- **105**: Size limit exceeded

#### Cryptographic Errors (200-299)
- **201**: Key error
- **202**: Decryption error
- **203**: Encryption error
- **204**: Signature error
- **205**: IV error

#### Policy Errors (300-399)
- **301**: Invalid policy
- **302**: Policy evaluation error
- **303**: Policy binding error
- **304**: Policy expired
- **305**: Policy not yet valid

#### TDF Errors (400-499)
- **401**: Invalid TDF format
- **402**: Manifest error
- **403**: Payload error
- **404**: TDF corrupted

#### I/O Errors (500-599)
- **501**: File not found
- **502**: File access denied
- **503**: File too large
- **504**: Secure delete error
- **505**: Temporary file error

#### Attribute Errors (600-699)
- **601**: Invalid attribute
- **602**: Attribute not found
- **603**: Attribute value error
- **604**: Attribute namespace error

#### Permission Errors (700-799)
- **701**: Access denied
- **702**: Missing attribute
- **703**: Insufficient clearance
- **704**: Unauthorized source

#### System Errors (900-999)
- **901**: Internal error
- **902**: Service unavailable
- **903**: Rate limit exceeded
- **904**: Configuration error

## Client Error Handling Best Practices

When working with the OpenTDF MCP server, implement these error handling practices:

1. **Check error codes, not just messages**: The error message may change, but codes are stable.

2. **Handle category ranges**: Your application can handle entire categories of errors similarly.

3. **Display suggestions to users**: The `suggestion` field provides user-friendly guidance.

4. **Log details field for debugging**: The `details` field contains technical information useful for debugging.

5. **Implement retries for certain errors**: System errors (900-999) are often transient and good candidates for retries.

## Error Handling Code Examples

### JavaScript

```javascript
async function handleOpenTdfRequest(requestData) {
  try {
    const response = await fetch('/api/opentdf', {
      method: 'POST',
      body: JSON.stringify(requestData),
      headers: { 'Content-Type': 'application/json' }
    });
    
    const result = await response.json();
    
    if (result.error) {
      // Handle based on error category
      const errorCode = result.error.code;
      const category = Math.floor(errorCode / 100) * 100;
      
      switch (category) {
        case 100: // Validation errors
          console.error('Validation error:', result.error.message);
          // Show user the suggestion if available
          if (result.error.data?.suggestion) {
            showUserFriendlyError(result.error.data.suggestion);
          }
          break;
          
        case 500: // IO errors
          console.error('IO error:', result.error.message);
          logForDebugging(result.error.data?.details);
          break;
          
        case 900: // System errors - retry logic
          console.warn('System error, retrying...');
          await new Promise(resolve => setTimeout(resolve, 1000));
          return handleOpenTdfRequest(requestData); // Retry
          
        default:
          console.error('Error:', result.error);
          showUserFriendlyError(result.error.message);
      }
      
      throw new Error(`OpenTDF error: ${result.error.message}`);
    }
    
    return result;
  } catch (error) {
    console.error('Request failed:', error);
    throw error;
  }
}
```

### Rust

```rust
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
enum OpenTdfError {
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    #[error("Policy error: {0}")]
    Policy(String),
    
    #[error("TDF error: {0}")]
    Tdf(String),
    
    #[error("I/O error: {0}")]
    Io(String),
    
    #[error("Attribute error: {0}")]
    Attribute(String),
    
    #[error("Permission error: {0}")]
    Permission(String),
    
    #[error("System error: {0}")]
    System(String),
    
    #[error("Unknown error: {0}")]
    Unknown(String),
}

#[derive(Debug, Deserialize)]
struct ErrorData {
    error_type: String,
    details: String,
    suggestion: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    code: i32,
    message: String,
    data: Option<ErrorData>,
}

#[derive(Debug, Deserialize)]
struct OpenTdfResponse {
    error: Option<ErrorResponse>,
    result: Option<serde_json::Value>,
}

async fn handle_opentdf_request(request_data: &str) -> Result<serde_json::Value, OpenTdfError> {
    let response = reqwest::Client::new()
        .post("http://localhost:8080/api/opentdf")
        .body(request_data.to_string())
        .send()
        .await
        .map_err(|e| OpenTdfError::Unknown(e.to_string()))?;
    
    let result: OpenTdfResponse = response
        .json()
        .await
        .map_err(|e| OpenTdfError::Unknown(e.to_string()))?;
    
    if let Some(error) = result.error {
        // Map error code to appropriate error type
        let category = (error.code / 100) * 100;
        let error_message = if let Some(ref data) = error.data {
            if let Some(ref suggestion) = data.suggestion {
                format!("{}: {}", error.message, suggestion)
            } else {
                error.message
            }
        } else {
            error.message
        };
        
        match category {
            100 => return Err(OpenTdfError::Validation(error_message)),
            200 => return Err(OpenTdfError::Crypto(error_message)),
            300 => return Err(OpenTdfError::Policy(error_message)),
            400 => return Err(OpenTdfError::Tdf(error_message)),
            500 => return Err(OpenTdfError::Io(error_message)),
            600 => return Err(OpenTdfError::Attribute(error_message)),
            700 => return Err(OpenTdfError::Permission(error_message)),
            900 => return Err(OpenTdfError::System(error_message)),
            _ => return Err(OpenTdfError::Unknown(error_message)),
        }
    }
    
    result.result.ok_or_else(|| OpenTdfError::Unknown("No result and no error in response".to_string()))
}
```

## Specific Error Scenarios and Resolution

### Size Limit Exceeded (105)

When uploading or processing files that exceed configured size limits.

**Resolution**: Compress the file or break it into smaller chunks before encrypting.

### Policy Binding Error (303)

Occurs when the cryptographic binding of a policy to a TDF cannot be verified.

**Resolution**: Check that you're using the correct policy key and that the policy hasn't been tampered with.

### TDF Corrupted (404)

The TDF archive is damaged or has been modified in an invalid way.

**Resolution**: Re-download or re-create the TDF file from the original source.

### Rate Limit Exceeded (903)

Too many requests made in a short period.

**Resolution**: Implement exponential backoff in your client application and retry after the specified delay.