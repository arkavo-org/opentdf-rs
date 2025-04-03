// Test script for the access_evaluate endpoint using MCP
// This script uses the Claude MCP client helper to connect to the MCP server

const mcpClient = require('../mcp_client.js');
const uuid = require('uuid');

// Create a policy object for testing
function createTestPolicy() {
  return {
    uuid: `policy-${uuid.v4()}`,
    body: {
      attributes: [
        {
          // Department must be either FINANCE or LEGAL
          type: "OR",
          conditions: [
            {
              attribute: "department:name",
              operator: "equals",
              value: "FINANCE"
            },
            {
              attribute: "department:name",
              operator: "equals",
              value: "LEGAL"
            }
          ]
        },
        {
          // Clearance must be at least CONFIDENTIAL
          attribute: "clearance:level",
          operator: "minimumOf",
          value: "CONFIDENTIAL"
        },
        {
          // Region must be in the allowed list
          attribute: "region:code",
          operator: "in",
          value: ["USA", "CANADA", "UK", "EU"]
        }
      ],
      dissem: ["user@example.com"]
    }
  };
}

// Create different user attribute sets for testing
function createUserAttributes(userId, attributes) {
  const userAttrs = {
    user_id: userId,
    attributes: []
  };
  
  for (const [namespace, name, value] of attributes) {
    userAttrs.attributes.push({
      namespace,
      name,
      value
    });
  }
  
  return userAttrs;
}

async function runTests() {
  try {
    console.log('Starting ABAC access tests using MCP client...');
    
    // Connect to the MCP server
    await mcpClient.initialize();
    
    const policy = createTestPolicy();
    
    // Test case 1: User with valid attributes (should be granted access)
    const validUser = createUserAttributes("alice@example.com", [
      ["department", "name", "FINANCE"],
      ["clearance", "level", "SECRET"],
      ["region", "code", "USA"]
    ]);
    
    // Test case 2: User from LEGAL department (should be granted access)
    const legalUser = createUserAttributes("bob@example.com", [
      ["department", "name", "LEGAL"],
      ["clearance", "level", "TOP_SECRET"],
      ["region", "code", "UK"]
    ]);
    
    // Test case 3: User with insufficient clearance (should be denied access)
    const lowClearanceUser = createUserAttributes("charlie@example.com", [
      ["department", "name", "FINANCE"],
      ["clearance", "level", "PUBLIC"],
      ["region", "code", "USA"]
    ]);
    
    // Test case 4: User from unauthorized department (should be denied access)
    const wrongDeptUser = createUserAttributes("dave@example.com", [
      ["department", "name", "ENGINEERING"],
      ["clearance", "level", "SECRET"],
      ["region", "code", "USA"]
    ]);
    
    // Test case 5: User from unauthorized region (should be denied access)
    const wrongRegionUser = createUserAttributes("eve@example.com", [
      ["department", "name", "FINANCE"],
      ["clearance", "level", "SECRET"],
      ["region", "code", "AUSTRALIA"]
    ]);
    
    // Run the test cases
    console.log('\n--- Running test cases ---\n');
    
    console.log('Test case 1: User with valid attributes (should be granted access)');
    try {
      const response = await mcpClient.callTool('access_evaluate', {
        policy,
        user_attributes: validUser
      });
      console.log(`Result: access_granted = ${response.access_granted}`);
      console.log(`Evaluation time: ${response.evaluation_time}`);
      console.log(`Attributes evaluated: ${response.attributes_evaluated}`);
      console.log('---');
    } catch (error) {
      console.error('Test case 1 failed:', error);
    }
    
    console.log('Test case 2: User from LEGAL department (should be granted access)');
    try {
      const response = await mcpClient.callTool('access_evaluate', {
        policy,
        user_attributes: legalUser
      });
      console.log(`Result: access_granted = ${response.access_granted}`);
      console.log(`Evaluation time: ${response.evaluation_time}`);
      console.log(`Attributes evaluated: ${response.attributes_evaluated}`);
      console.log('---');
    } catch (error) {
      console.error('Test case 2 failed:', error);
    }
    
    console.log('Test case 3: User with insufficient clearance (should be denied access)');
    try {
      const response = await mcpClient.callTool('access_evaluate', {
        policy,
        user_attributes: lowClearanceUser
      });
      console.log(`Result: access_granted = ${response.access_granted}`);
      console.log(`Evaluation time: ${response.evaluation_time}`);
      console.log(`Attributes evaluated: ${response.attributes_evaluated}`);
      console.log('---');
    } catch (error) {
      console.error('Test case 3 failed:', error);
    }
    
    console.log('Test case 4: User from unauthorized department (should be denied access)');
    try {
      const response = await mcpClient.callTool('access_evaluate', {
        policy,
        user_attributes: wrongDeptUser
      });
      console.log(`Result: access_granted = ${response.access_granted}`);
      console.log(`Evaluation time: ${response.evaluation_time}`);
      console.log(`Attributes evaluated: ${response.attributes_evaluated}`);
      console.log('---');
    } catch (error) {
      console.error('Test case 4 failed:', error);
    }
    
    console.log('Test case 5: User from unauthorized region (should be denied access)');
    try {
      const response = await mcpClient.callTool('access_evaluate', {
        policy,
        user_attributes: wrongRegionUser
      });
      console.log(`Result: access_granted = ${response.access_granted}`);
      console.log(`Evaluation time: ${response.evaluation_time}`);
      console.log(`Attributes evaluated: ${response.attributes_evaluated}`);
      console.log('---');
    } catch (error) {
      console.error('Test case 5 failed:', error);
    }
    
    // Test with context attributes override
    console.log('Test case 6: Context attributes override (elevating clearance)');
    try {
      const response = await mcpClient.callTool('access_evaluate', {
        policy,
        user_attributes: lowClearanceUser,
        context: {
          attributes: [
            {
              namespace: "clearance",
              name: "level",
              value: "TOP_SECRET"  // Override the PUBLIC clearance with TOP_SECRET
            }
          ]
        }
      });
      console.log(`Result: access_granted = ${response.access_granted}`);
      console.log(`Evaluation time: ${response.evaluation_time}`);
      console.log(`Attributes evaluated: ${response.attributes_evaluated}`);
      console.log('---');
    } catch (error) {
      console.error('Test case 6 failed:', error);
    }
    
    console.log('\n--- Tests completed ---\n');
    
  } catch (error) {
    console.error('Error running tests:', error);
  } finally {
    // Clean up and exit
    process.exit(0);
  }
}

// Run the tests
runTests();