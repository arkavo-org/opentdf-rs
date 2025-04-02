#!/usr/bin/env node

/**
 * OpenTDF MCP Tool Registration Script for Claude Code
 * 
 * This script generates the registration command for OpenTDF tools in Claude Code.
 * It creates all tools with correct formats to work with Claude Code MCP.
 */

const tools = [
  {
    name: "opentdf:tdf_create",
    description: "Creates a TDF with encrypted data",
    schema: {
      type: "function",
      parameters: {
        type: "object",
        properties: {
          content: {
            type: "array",
            items: {
              type: "object",
              properties: {
                data: { type: "string", description: "Base64 encoded data" },
                kas_url: { type: "string", description: "KAS URL" },
                policy: { type: "object", description: "Policy object" }
              },
              required: ["data", "kas_url", "policy"]
            }
          }
        },
        required: ["content"]
      }
    }
  },
  {
    name: "opentdf:tdf_read",
    description: "Reads a TDF file",
    schema: {
      type: "function",
      parameters: {
        type: "object",
        properties: {
          content: {
            type: "array",
            items: {
              type: "object",
              properties: {
                tdf_data: { type: "string", description: "Base64 encoded TDF data" }
              },
              required: ["tdf_data"]
            }
          }
        },
        required: ["content"]
      }
    }
  },
  {
    name: "opentdf:attribute_list",
    description: "Lists all attributes in the system",
    schema: {
      type: "function",
      parameters: {
        type: "object",
        properties: {
          content: {
            type: "array",
            items: { type: "string" }
          }
        },
        required: ["content"]
      }
    }
  },
  {
    name: "opentdf:namespace_list",
    description: "Lists all attribute namespaces in the system",
    schema: {
      type: "function",
      parameters: {
        type: "object",
        properties: {
          content: {
            type: "array",
            items: { type: "string" }
          }
        },
        required: ["content"]
      }
    }
  },
  {
    name: "opentdf:attribute_define",
    description: "Defines a new attribute",
    schema: {
      type: "function",
      parameters: {
        type: "object",
        properties: {
          content: {
            type: "array",
            items: {
              type: "object",
              properties: {
                namespaces: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      name: { type: "string" },
                      attributes: { 
                        type: "array",
                        items: { type: "string" }
                      }
                    }
                  }
                }
              }
            }
          }
        },
        required: ["content"]
      }
    }
  },
  {
    name: "opentdf:policy_create",
    description: "Creates an attribute-based access control policy",
    schema: {
      type: "function",
      parameters: {
        type: "object",
        properties: {
          content: {
            type: "array",
            items: {
              type: "object",
              properties: {
                attributes: { 
                  type: "array", 
                  items: { type: "object" },
                  description: "Array of attribute conditions"
                },
                dissemination: {
                  type: "array",
                  items: { type: "string" },
                  description: "Array of recipients"
                }
              },
              required: ["attributes", "dissemination"]
            }
          }
        },
        required: ["content"]
      }
    }
  },
  {
    name: "opentdf:policy_binding_verify",
    description: "Verifies the binding of a policy to a TDF",
    schema: {
      type: "function",
      parameters: {
        type: "object",
        properties: {
          content: {
            type: "array",
            items: {
              type: "object",
              properties: {
                tdf_data: { 
                  type: "string", 
                  description: "Base64 encoded TDF data"
                },
                policy_key: {
                  type: "string",
                  description: "Policy key for verification"
                }
              },
              required: ["tdf_data", "policy_key"]
            }
          }
        },
        required: ["content"]
      }
    }
  },
  {
    name: "opentdf:policy_validate",
    description: "Validates a policy against a TDF",
    schema: {
      type: "function", 
      parameters: {
        type: "object",
        properties: {
          content: {
            type: "array",
            items: {
              type: "object",
              properties: {
                policy: { type: "object", description: "Policy to validate" },
                tdf_data: { type: "string", description: "Base64 encoded TDF data" }
              },
              required: ["policy", "tdf_data"]
            }
          }
        },
        required: ["content"]
      }
    }
  },
  {
    name: "opentdf:access_evaluate",
    description: "Evaluates user access based on attributes",
    schema: {
      type: "function",
      parameters: {
        type: "object",
        properties: {
          content: {
            type: "array",
            items: {
              type: "object",
              properties: {
                policy: { type: "object", description: "Policy to evaluate" },
                user_attributes: { 
                  type: "object", 
                  description: "User attributes to check against policy"
                }
              },
              required: ["policy", "user_attributes"]
            }
          }
        },
        required: ["content"]
      }
    }
  }
];

// Generate the registration command
const registrationCommand = `/mcp register ${JSON.stringify(tools)}`;

// Output the registration command
console.log('Run this command in Claude Code to register the OpenTDF tools:');
console.log('\n' + registrationCommand);
console.log('\n');

// Show example usage for each tool
console.log('Examples of how to use the tools:');
console.log('```');
console.log('opentdf:namespace_list (MCP)(content: [])');
console.log('opentdf:attribute_list (MCP)(content: [])');
console.log('opentdf:attribute_define (MCP)(content: [{"namespaces": [{"name": "gov", "attributes": ["security", "classification", "clearance"]}]}])');
console.log('```');