# OpenTDF MCP Integration Guide

This document describes how to integrate OpenTDF with Claude Code and other MCP clients.

## Overview

OpenTDF provides a set of tools for working with Trusted Data Format (TDF) files and attribute-based access control (ABAC). These tools are exposed through an MCP (Model-Calling-Protocol) server that can be used by Claude Code and other MCP clients.

## Self-Documenting Tools

The OpenTDF MCP server has been updated to be fully self-documenting, providing detailed schema information for each tool. When a client connects to the MCP server:

1. The `initialize` response includes detailed schemas for all available tools
2. The `tools/list` endpoint returns a comprehensive list of tools with parameter requirements
3. Each tool provides clear error messages that indicate missing or invalid parameters

This self-documentation makes it easier for clients to understand and use the tools without needing external documentation.

## Available Tools

OpenTDF provides the following MCP tools:

- `opentdf:namespace_list` - Lists all attribute namespaces in the system
- `opentdf:attribute_list` - Lists all attributes in the system
- `opentdf:attribute_define` - Defines a new attribute
- `opentdf:tdf_create` - Creates a TDF with encrypted data
- `opentdf:tdf_read` - Reads a TDF file
- `opentdf:policy_create` - Creates an attribute-based access control policy
- `opentdf:policy_binding_verify` - Verifies the binding of a policy to a TDF
- `opentdf:policy_validate` - Validates a policy against a TDF
- `opentdf:access_evaluate` - Evaluates user access based on attributes

## Registering Tools with Claude Code

To register the OpenTDF tools with Claude Code, use the `register-tools.js` script:

```bash
node tools/register-tools.js
```

This will output a registration command that can be used to register the tools with Claude Code:

```
/mcp register [{"name":"opentdf:tdf_create",...}]
```

Copy and paste this command into Claude Code to register the tools.

## Using Tools in Claude Code

Once registered, you can use the tools in Claude Code like this:

```
opentdf:namespace_list (MCP)(content: [])
```

This will list all attribute namespaces in the system.

To define a new attribute:

```
opentdf:attribute_define (MCP)(content: [{"namespaces": [{"name": "gov", "attributes": ["security", "classification", "clearance"]}]}])
```

## Parameter Format and Schemas

The OpenTDF MCP server now supports multiple parameter formats:

1. **Standard Format**: Direct object parameters (easier for most clients)
   ```json
   {
     "tdf_data": "Base64EncodedData...",
     "policy_key": "Base64EncodedKey..."
   }
   ```

2. **Content-Based Format**: For Claude integration (all parameters wrapped in a `content` array)
   ```json
   {
     "content": [
       {
         "tdf_data": "Base64EncodedData...",
         "policy_key": "Base64EncodedKey..."
       }
     ]
   }
   ```

3. **Namespaces Format**: For defining attribute namespaces
   ```json
   {
     "namespaces": [
       {
         "name": "gov",
         "attributes": ["security", "classification", "clearance"]
       }
     ]
   }
   ```

Each tool provides a detailed schema that specifies:
- Required and optional parameters
- Parameter types and formats
- Parameter descriptions

Example of `tdf_create` tool schema:

```json
{
  "type": "object",
  "properties": {
    "data": {
      "type": "string",
      "description": "Base64 encoded data to encrypt and store in the TDF"
    },
    "kas_url": {
      "type": "string",
      "description": "URL of the Key Access Server"
    },
    "policy": {
      "type": "object",
      "description": "Policy to bind to the TDF archive"
    }
  },
  "required": ["data", "kas_url", "policy"]
}
```

Example usage:

```
opentdf:tdf_create (MCP)(content: [{
  "data": "SGVsbG8gV29ybGQh",  // Base64-encoded data
  "kas_url": "https://kas.example.com",
  "policy": {
    "uuid": "test-policy",
    "body": {
      "attributes": [
        {
          "attribute": "gov.example:clearance",
          "operator": "MinimumOf",
          "value": "secret"
        }
      ],
      "dissem": ["user@example.com"]
    }
  }
}])
```

## MCP Server Implementation

The OpenTDF MCP server is implemented in Rust and is part of the OpenTDF-RS codebase. It handles the following:

1. Providing self-documenting tool schemas during initialization
2. Receiving MCP tool calls in multiple parameter formats (standard, content-based, or namespaces)
3. Extracting parameters from the appropriate format
4. Processing the requests and returning results with appropriate schemas
5. Providing detailed error messages for missing or invalid parameters

## Error Handling

The MCP server provides clear, structured error messages when parameters are missing or invalid. For example:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "Invalid params for tdf_create: missing field `data`"
  }
}
```

These error messages help clients understand exactly what went wrong and how to fix it.

## Troubleshooting

If you encounter errors:

1. **Missing Field Errors**: Check that you're providing all required parameters according to the tool's schema
2. **Format Errors**: Make sure you're using the right parameter format for the tool (standard, content-based, or namespaces)
3. **Parameter Type Errors**: Ensure parameters have the correct type (string, object, array, etc.) as specified in the schema
4. **Parameter Value Errors**: Verify that values meet any format requirements (e.g., Base64 encoding)

## Examples

See the `test-content-format.js` script for examples of how to use each tool.

```bash
node tools/test-content-format.js
```

## Testing the Integration

Several test scripts are available to help you test the OpenTDF MCP integration:

1. **Basic Tests**: `test-content-format.js` - Tests basic functionality with content-based parameter format
   ```bash
   node tools/test-content-format.js
   ```

2. **Claude MCP Tests**: `claude-mcp-test.js` - Tests the integration with Claude Code's exact parameter format
   ```bash
   node tools/claude-mcp-test.js
   ```

3. **Interactive Client**: `claude-mcp-client.js` - An interactive client that lets you manually test tools
   ```bash
   node tools/claude-mcp-client.js
   ```

4. **Attribute Listing Tool**: `list-attributes.js` - A utility to list attributes in the system
   ```bash
   node tools/list-attributes.js
   ```

## How to Verify Claude Code Integration

To verify that the integration works with Claude Code:

1. Start the MCP server:
   ```bash
   cargo run -p opentdf-mcp-server
   ```

2. In Claude Code, register the tools using the output from `register-tools.js`:
   ```
   /mcp register [{"name":"opentdf:namespace_list",...}]
   ```

3. Test the integration with a simple command:
   ```
   opentdf:namespace_list (MCP)(content: [])
   ```
   
   You should receive a list of namespaces from the server.

4. Explore available tools and their schemas:
   ```
   /mcp tools
   ```
   
   This will show all registered tools with their descriptions and parameter schemas.

5. Try using different tools with the parameter formats shown in their schemas.

If you encounter errors, try running the `claude-mcp-test.js` script to ensure the server is working correctly with the content-based parameter format.

## Benefits of Self-Documenting Tools

The self-documenting nature of the MCP server provides several benefits:

1. **Reduced Documentation Needs**: Clients can discover tool capabilities and requirements dynamically
2. **Better Error Messages**: Detailed error messages guide users to correct usage
3. **Easier Integration**: New clients can integrate more easily without extensive documentation
4. **Schema Validation**: Automatic validation of parameters against schemas improves reliability
5. **Flexible Parameter Formats**: Support for multiple parameter formats improves compatibility with different clients

This approach makes the OpenTDF MCP server more robust and easier to use for both human developers and AI assistants.