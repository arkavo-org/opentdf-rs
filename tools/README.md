# Using Claude with OpenTDF MCP - ABAC Examples

This document provides examples of using Claude with the OpenTDF MCP server to test Attribute-Based Access Control functionality.

## Setup

Start Claude with the OpenTDF MCP server:

```bash
claude --mcp="cargo run -p opentdf-mcp-server"
```

## MCP Client

The `mcp_client.js` tool provides a Node.js client for interacting with the OpenTDF MCP server.

### Usage

```bash
# Create a TDF file
node mcp_client.js create <input_file> <output_tdf> [kas_url]

# Read a TDF file
node mcp_client.js read <tdf_file>

# Run ABAC tests
node mcp_client.js test-abac
```

## Test Scripts

The following test scripts demonstrate OpenTDF functionality:

| Script | Description |
|--------|-------------|
| `test-scripts/test-abac-mcp.js` | ABAC policy evaluation testing |
| `test-scripts/http-test-abac.js` | HTTP-based ABAC testing |
| `test-mcp.js` | Basic MCP integration testing |
| `audit-logging-test.js` | Comprehensive audit logging for ABAC access |

To run the ABAC tests:

```bash
# Using the convenience script
./run-abac-test.sh

# Or directly with Node.js
node test-scripts/test-abac-mcp.js
```

The audit logging test generates detailed compliance reports in the `tools/reports` directory.

## ABAC Test Scenarios

The ABAC tests include various scenarios:

1. Valid user with all required attributes (should be granted access)
2. User from legal department (testing OR conditions)
3. User with insufficient clearance (should be denied access)
4. User from unauthorized department (should be denied access) 
5. User from unauthorized region (should be denied access)
6. Context attributes that override user attributes

## Example Tasks

Here are some examples of tasks you can ask Claude to perform using the OpenTDF MCP integration.

### 1. Define Hierarchical Attributes

Ask Claude to define a hierarchical attribute structure for clearance levels:

```
Please define a hierarchical clearance level attribute structure using the OpenTDF MCP server. Create levels for public, confidential, secret, and top-secret, where each level inherits from the previous one.
```

Claude should use the `attribute_define` tool to create this structure.

### 2. Create Users with Different Attributes

Ask Claude to define test users with different attribute sets:

```
Create two users in the OpenTDF system: 
1. Alice with top-secret clearance and executive department
2. Bob with confidential clearance and research department
```

Claude should use the `user_attributes` tool to define these users.

### 3. Create a Policy with Multiple Conditions

Ask Claude to create a complex policy:

```
Create an attribute-based policy that requires:
1. At least secret clearance level
2. Department must be either executive or engineering
3. Valid for the next 24 hours only
```

Claude should use the `policy_create` tool to create this policy with logical operators.

### 4. Create and Protect a TDF with the Policy

Ask Claude to create a TDF with policy protection:

```
Create a TDF file that protects the text "This is sensitive information" using the policy we just created.
```

Claude should use the `tdf_create` tool to create the TDF.

### 5. Test Access Evaluation

Ask Claude to evaluate access for different users:

```
Evaluate whether Alice and Bob would have access to the TDF we just created. Explain why each user is granted or denied access based on the policy.
```

Claude should use the `access_evaluate` tool to check each user's attributes against the policy.

### 6. Verify Policy Binding

Ask Claude to verify the policy binding:

```
Verify that the policy is cryptographically bound to the TDF we created.
```

Claude should use the `policy_binding_verify` tool to check the binding.

## Advanced Examples

### Complex Logical Conditions

```
Create a policy with the following logical structure:
(clearance:secret OR department:security) AND location:headquarters AND NOT temporary_contractor:true
```

### Time-Based Access Control

```
Create a policy that only grants access during business hours (9am-5pm) on weekdays and requires secret clearance.
```

### Testing Policy Updates

```
1. Create a TDF with a simple policy
2. Update the policy with additional restrictions
3. Verify that users who had access under the old policy but don't meet the new requirements are now denied
```

## Troubleshooting

If Claude has trouble with the MCP integration:

1. Make sure the MCP server is running correctly
2. Check the server logs for any JSON-RPC errors
3. Verify that the claude-mcp connection is properly established
4. Try using the explicit tool path: `/mcp opentdf_tool_name` instead of relying on Claude to infer it