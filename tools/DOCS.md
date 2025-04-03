# OpenTDF-RS Documentation

This directory contains documentation for using, configuring, and troubleshooting the OpenTDF-RS server.

## Overview

OpenTDF-RS is a Rust implementation of the Trusted Data Format (TDF) specification, providing attribute-based access control (ABAC) capabilities for secure data sharing. The documentation is organized into several key sections:

## Server Administration

- [**Configuration Guide**](CONFIGURATION.md): Detailed configuration options using environment variables, performance tuning, and security settings.
- [**Error Handling**](ERROR-HANDLING.md): Comprehensive guide to error codes, response formats, and best practices for client applications.
- [**Audit Logging**](audit-guide.md): Information about audit logging capabilities and compliance reporting features.

## MCP Integration

- [**MCP Integration Guide**](README-MCP-INTEGRATION.md): Documentation on how to use OpenTDF-RS with the Model Context Protocol (MCP).
- [**ABAC Examples**](README.md): Examples of using Claude with OpenTDF MCP for ABAC features.

## Testing

- [**Test Scripts**](test-mcp.js): Examples of testing the OpenTDF MCP server functionality.
- [**ABAC Test Scripts**](test-abac-mcp.js): Test scripts specifically for attribute-based access control.
- [**Audit Logging Tests**](audit-logging-test.js): Tests for the audit logging functionality.

## Security

- [**Audit Implementation Guide**](AUDIT_IMPLEMENTATION.md): Details about the audit logging implementation and security considerations.

## API Documentation

The API documentation is available in each script and tool, as well as in the MCP tool schema definition within the server code.

## Health and Monitoring

The OpenTDF-RS server provides a health check endpoint accessible via:

```
/mcp opentdf health
```

Or via JSON-RPC:

```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "health"
}
```

This endpoint returns server health metrics including uptime, request counts, error rates, and memory usage.

## Error Code Reference

See the [Error Handling Guide](ERROR-HANDLING.md) for a complete reference of all error codes and response formats.

## Environment Variables

See the [Configuration Guide](CONFIGURATION.md) for a complete reference of all environment variables and configuration options.

## Metrics and Monitoring

The OpenTDF-RS server provides Prometheus-compatible metrics on port 9091 (by default) that can be used for real-time monitoring and alerting.

Key metrics include:

- `opentdf_secure_delete_duration_ms`: Histogram of secure deletion operation durations
- `opentdf_secure_delete_operations`: Counter of secure deletion operations
- `opentdf_secure_delete_failures`: Counter of secure deletion failures
- `opentdf_errors`: Counter of errors by type
- `opentdf_request_rate`: Rate of incoming requests
- `opentdf_request_duration_ms`: Histogram of request durations

## Recent Improvements

The server has recently added several improvements:

1. **Enhanced Security**: Cryptographically secure file deletion with configurable overwrite passes
2. **Standardized Error Codes**: Structured error codes organized by category
3. **Improved Audit Logging**: Comprehensive security event logging for compliance
4. **Health Checks**: Built-in health check endpoint for monitoring
5. **Metrics**: Prometheus-compatible metrics for operational visibility
6. **Configuration Options**: Extensive configuration via environment variables
7. **Input Validation**: Improved validation and sanitization of inputs
8. **Documentation**: Comprehensive documentation for all aspects of the system