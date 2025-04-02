#!/usr/bin/env node

/**
 * OpenTDF MCP Tool Registration Script
 * 
 * This script assists in registering the OpenTDF tools with Claude.
 * It provides the command format that you can use with Claude
 * to register the TDF tools in your session.
 */

const tools = [
  {
    name: "opentdf__tdf_create",
    description: "Creates a new TDF archive with encrypted data and policy binding",
    input_schema: {
      type: "object",
      properties: {
        data: {
          type: "string",
          description: "Base64 encoded data to encrypt and store in the TDF"
        },
        kas_url: {
          type: "string",
          description: "URL of the Key Access Server"
        },
        policy: {
          type: "object",
          description: "Policy to bind to the TDF archive"
        }
      },
      required: ["data", "kas_url", "policy"]
    }
  },
  {
    name: "opentdf__tdf_read",
    description: "Reads contents from a TDF archive, returning the manifest and payload",
    input_schema: {
      type: "object",
      properties: {
        tdf_data: {
          type: "string",
          description: "Base64 encoded TDF archive data"
        }
      },
      required: ["tdf_data"]
    }
  },
  {
    name: "opentdf__attribute_define",
    description: "Defines attribute namespaces with optional hierarchies",
    input_schema: {
      type: "object",
      properties: {
        namespace: {
          type: "string",
          description: "Namespace for the attribute (e.g., 'gov.example')"
        },
        name: {
          type: "string",
          description: "Name of the attribute within the namespace"
        },
        values: {
          type: "array",
          items: { type: "string" },
          description: "Possible values for this attribute"
        },
        hierarchy: {
          type: "array",
          items: {
            type: "object",
            properties: {
              value: { type: "string" },
              inherits_from: { type: "string" }
            }
          },
          description: "Optional hierarchy defining inheritance relationships between values"
        }
      },
      required: ["namespace", "name", "values"]
    }
  },
  {
    name: "opentdf__user_attributes",
    description: "Sets user attributes for testing access control",
    input_schema: {
      type: "object",
      properties: {
        user_id: {
          type: "string",
          description: "Identifier for the user"
        },
        attributes: {
          type: "array",
          items: {
            type: "object",
            properties: {
              namespace: { type: "string" },
              name: { type: "string" },
              value: { type: "string" }
            }
          },
          description: "List of attributes to assign to the user"
        }
      },
      required: ["user_id", "attributes"]
    }
  },
  {
    name: "opentdf__policy_create",
    description: "Creates an attribute-based access control policy",
    input_schema: {
      type: "object",
      properties: {
        attributes: {
          type: "array",
          description: "List of attribute conditions for the policy"
        },
        dissemination: {
          type: "array",
          items: { type: "string" },
          description: "List of user identifiers who can access the data"
        },
        valid_from: {
          type: "string",
          description: "Optional start time in ISO 8601 format"
        },
        valid_to: {
          type: "string",
          description: "Optional expiration time in ISO 8601 format"
        }
      },
      required: ["attributes", "dissemination"]
    }
  },
  {
    name: "opentdf__access_evaluate",
    description: "Evaluates whether a user with attributes can access protected content",
    input_schema: {
      type: "object",
      properties: {
        policy: {
          type: "object",
          description: "The policy to evaluate"
        },
        user_attributes: {
          type: "object",
          description: "User attributes to check against the policy"
        },
        context: {
          type: "object",
          description: "Optional environmental context attributes"
        }
      },
      required: ["policy", "user_attributes"]
    }
  },
  {
    name: "opentdf__policy_binding_verify",
    description: "Verifies the cryptographic binding of a policy to a TDF",
    input_schema: {
      type: "object",
      properties: {
        tdf_data: {
          type: "string",
          description: "Base64 encoded TDF archive"
        },
        policy_key: {
          type: "string",
          description: "Policy key for verification"
        }
      },
      required: ["tdf_data", "policy_key"]
    }
  }
];

// Format the tools for Claude's /mcp command
const claudeRegistrationCommand = `/mcp register ${JSON.stringify(tools)}`;

// Display Claude command
console.log('Use the following command with Claude to register the OpenTDF tools:');
console.log('\n' + claudeRegistrationCommand);

// Display individual tool usage examples
console.log('\n\nExample usage for individual tools:');

tools.forEach(tool => {
  const example = {};
  
  // Create a generic example for each required property
  const props = tool.input_schema.properties;
  const required = tool.input_schema.required || [];
  
  for (const prop of required) {
    const propType = props[prop].type;
    if (propType === 'string') {
      example[prop] = 'example';
    } else if (propType === 'array') {
      example[prop] = ['example'];
    } else if (propType === 'object') {
      example[prop] = { key: 'value' };
    }
  }
  
  console.log(`\n/mcp ${tool.name} ${JSON.stringify(example)}`);
});

console.log('\nAfter registering, you can call any of these tools with the appropriate parameters');