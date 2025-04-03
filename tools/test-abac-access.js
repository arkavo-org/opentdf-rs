// Test script for the access_evaluate endpoint in the MCP server
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

// Start the MCP server
console.log('Starting MCP server...');
const mcpServer = spawn('cargo', ['run', '--manifest-path', '../crates/mcp-server/Cargo.toml']);

// Set up logging
mcpServer.stdout.on('data', (data) => {
  const dataStr = data.toString();
  console.log(`MCP Server stdout: ${dataStr}`);
  
  // If server is ready, start tests
  if (dataStr.includes('"method":"server/ready"')) {
    console.log('Server is ready, starting tests...');
    setTimeout(runTests, 500);
  }
});

mcpServer.stderr.on('data', (data) => {
  console.error(`MCP Server stderr: ${data.toString()}`);
});

mcpServer.on('close', (code) => {
  console.log(`MCP server process exited with code ${code}`);
});

// Function to send JSON-RPC request to the MCP server
function sendRequest(method, params) {
  return new Promise((resolve, reject) => {
    // Create the JSON-RPC request
    const request = {
      jsonrpc: '2.0',
      id: Date.now().toString(),
      method,
      params
    };
    
    // Stringify the request
    const requestStr = JSON.stringify(request);
    console.log(`Sending request: ${requestStr}`);
    
    // Send the request to the server's stdin
    mcpServer.stdin.write(requestStr + '\n');
    
    // Set up a handler for the server's stdout
    const responseHandler = (data) => {
      const dataStr = data.toString();
      
      // Try to parse the response as JSON
      try {
        // Find JSON in the output - it might contain other log messages
        const jsonStart = dataStr.indexOf('{');
        if (jsonStart >= 0) {
          const jsonStr = dataStr.substring(jsonStart);
          const response = JSON.parse(jsonStr);
          
          // Check if it's the response we're waiting for
          if (response.id === request.id) {
            mcpServer.stdout.removeListener('data', responseHandler);
            console.log(`Received response for request ${request.id}`);
            resolve(response);
          }
        }
      } catch (error) {
        console.warn('Failed to parse response:', error);
      }
    };
    
    // Add the response handler
    mcpServer.stdout.on('data', responseHandler);
    
    // Set up a timeout
    setTimeout(() => {
      mcpServer.stdout.removeListener('data', responseHandler);
      reject(new Error('Request timed out'));
    }, 5000);
  });
}

// Create policy using the policy_create endpoint
async function createTestPolicy() {
  // Define policy attributes in the format expected by policy_create
  const policyParams = {
    attributes: [
      // Department must be FINANCE or LEGAL (OR condition)
      {
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
      // Clearance must be at least CONFIDENTIAL
      {
        attribute: "clearance:level",
        operator: "minimumOf",
        value: "CONFIDENTIAL"
      },
      // Region must be in the allowed list
      {
        attribute: "region:code",
        operator: "in",
        value: ["USA", "CANADA", "UK", "EU"]
      }
    ],
    dissemination: ["user@example.com"],
    valid_from: new Date().toISOString(),
    valid_to: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours from now
  };

  // Call policy_create endpoint
  console.log('Creating policy using policy_create endpoint...');
  const response = await sendRequest('policy_create', policyParams);
  
  if (response.error) {
    throw new Error(`Failed to create policy: ${response.error.message}`);
  }
  
  console.log('Policy created successfully:');
  console.log(JSON.stringify(response.result.policy, null, 2));
  
  return response.result.policy;
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
  console.log('Starting ABAC access tests...');
  
  try {
    // Create a test policy using the policy_create endpoint
    const policy = await createTestPolicy();
    
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
    const response = await sendRequest('access_evaluate', {
      policy,
      user_attributes: validUser
    });
    
    if (response.error) {
      console.error(`Error: ${response.error.message}`);
    } else {
      console.log(`Result: access_granted = ${response.result.access_granted}`);
      console.log(`Evaluation time: ${response.result.evaluation_time}`);
      console.log(`Attributes evaluated: ${response.result.attributes_evaluated}`);
    }
    console.log('---');
    
    console.log('Test case 2: User from LEGAL department (should be granted access)');
    const response2 = await sendRequest('access_evaluate', {
      policy,
      user_attributes: legalUser
    });
    
    if (response2.error) {
      console.error(`Error: ${response2.error.message}`);
    } else {
      console.log(`Result: access_granted = ${response2.result.access_granted}`);
      console.log(`Evaluation time: ${response2.result.evaluation_time}`);
      console.log(`Attributes evaluated: ${response2.result.attributes_evaluated}`);
    }
    console.log('---');
    
    console.log('Test case 3: User with insufficient clearance (should be denied access)');
    const response3 = await sendRequest('access_evaluate', {
      policy,
      user_attributes: lowClearanceUser
    });
    
    if (response3.error) {
      console.error(`Error: ${response3.error.message}`);
    } else {
      console.log(`Result: access_granted = ${response3.result.access_granted}`);
      console.log(`Evaluation time: ${response3.result.evaluation_time}`);
      console.log(`Attributes evaluated: ${response3.result.attributes_evaluated}`);
    }
    console.log('---');
    
    console.log('Test case 4: User from unauthorized department (should be denied access)');
    const response4 = await sendRequest('access_evaluate', {
      policy,
      user_attributes: wrongDeptUser
    });
    
    if (response4.error) {
      console.error(`Error: ${response4.error.message}`);
    } else {
      console.log(`Result: access_granted = ${response4.result.access_granted}`);
      console.log(`Evaluation time: ${response4.result.evaluation_time}`);
      console.log(`Attributes evaluated: ${response4.result.attributes_evaluated}`);
    }
    console.log('---');
    
    console.log('Test case 5: User from unauthorized region (should be denied access)');
    const response5 = await sendRequest('access_evaluate', {
      policy,
      user_attributes: wrongRegionUser
    });
    
    if (response5.error) {
      console.error(`Error: ${response5.error.message}`);
    } else {
      console.log(`Result: access_granted = ${response5.result.access_granted}`);
      console.log(`Evaluation time: ${response5.result.evaluation_time}`);
      console.log(`Attributes evaluated: ${response5.result.attributes_evaluated}`);
    }
    console.log('---');
    
    // Test with context attributes override
    console.log('Test case 6: Context attributes override (elevating clearance)');
    const response6 = await sendRequest('access_evaluate', {
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
    
    if (response6.error) {
      console.error(`Error: ${response6.error.message}`);
    } else {
      console.log(`Result: access_granted = ${response6.result.access_granted}`);
      console.log(`Evaluation time: ${response6.result.evaluation_time}`);
      console.log(`Attributes evaluated: ${response6.result.attributes_evaluated}`);
    }
    console.log('---');
    
    console.log('\n--- Tests completed ---\n');
    
  } catch (error) {
    console.error('Test error:', error);
  } finally {
    // Clean up and exit
    mcpServer.kill();
    process.exit(0);
  }
}