// HTTP-based test script for the access_evaluate endpoint
// This doesn't need to spawn the server - it can connect to an already running one
const http = require('http');

// Function to send JSON-RPC request via HTTP
function sendHttpRequest(method, params) {
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
    
    // HTTP request options
    const options = {
      hostname: 'localhost',
      port: 3000,  // Assumes server is running on port 3000
      path: '/jsonrpc',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(requestStr)
      }
    };
    
    // Send the request
    const req = http.request(options, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          const response = JSON.parse(data);
          resolve(response);
        } catch (error) {
          reject(new Error(`Failed to parse response: ${error.message}`));
        }
      });
    });
    
    req.on('error', (error) => {
      reject(error);
    });
    
    // Write the request body
    req.write(requestStr);
    req.end();
  });
}

// Create a policy object for testing
function createTestPolicy() {
  return {
    uuid: `policy-${Date.now()}`,
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
  console.log('Starting ABAC access tests via HTTP...');
  
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
    const response = await sendHttpRequest('access_evaluate', {
      policy,
      user_attributes: validUser
    });
    console.log(`Result: access_granted = ${response.result.access_granted}`);
    console.log(`Evaluation time: ${response.result.evaluation_time}`);
    console.log(`Attributes evaluated: ${response.result.attributes_evaluated}`);
    console.log('---');
  } catch (error) {
    console.error('Test case 1 failed:', error);
  }
  
  console.log('Test case 2: User from LEGAL department (should be granted access)');
  try {
    const response = await sendHttpRequest('access_evaluate', {
      policy,
      user_attributes: legalUser
    });
    console.log(`Result: access_granted = ${response.result.access_granted}`);
    console.log(`Evaluation time: ${response.result.evaluation_time}`);
    console.log(`Attributes evaluated: ${response.result.attributes_evaluated}`);
    console.log('---');
  } catch (error) {
    console.error('Test case 2 failed:', error);
  }
  
  console.log('Test case 3: User with insufficient clearance (should be denied access)');
  try {
    const response = await sendHttpRequest('access_evaluate', {
      policy,
      user_attributes: lowClearanceUser
    });
    console.log(`Result: access_granted = ${response.result.access_granted}`);
    console.log(`Evaluation time: ${response.result.evaluation_time}`);
    console.log(`Attributes evaluated: ${response.result.attributes_evaluated}`);
    console.log('---');
  } catch (error) {
    console.error('Test case 3 failed:', error);
  }
  
  console.log('Test case 4: User from unauthorized department (should be denied access)');
  try {
    const response = await sendHttpRequest('access_evaluate', {
      policy,
      user_attributes: wrongDeptUser
    });
    console.log(`Result: access_granted = ${response.result.access_granted}`);
    console.log(`Evaluation time: ${response.result.evaluation_time}`);
    console.log(`Attributes evaluated: ${response.result.attributes_evaluated}`);
    console.log('---');
  } catch (error) {
    console.error('Test case 4 failed:', error);
  }
  
  console.log('Test case 5: User from unauthorized region (should be denied access)');
  try {
    const response = await sendHttpRequest('access_evaluate', {
      policy,
      user_attributes: wrongRegionUser
    });
    console.log(`Result: access_granted = ${response.result.access_granted}`);
    console.log(`Evaluation time: ${response.result.evaluation_time}`);
    console.log(`Attributes evaluated: ${response.result.attributes_evaluated}`);
    console.log('---');
  } catch (error) {
    console.error('Test case 5 failed:', error);
  }
  
  // Test with context attributes override
  console.log('Test case 6: Context attributes override (elevating clearance)');
  try {
    const response = await sendHttpRequest('access_evaluate', {
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
    console.log(`Result: access_granted = ${response.result.access_granted}`);
    console.log(`Evaluation time: ${response.result.evaluation_time}`);
    console.log(`Attributes evaluated: ${response.result.attributes_evaluated}`);
    console.log('---');
  } catch (error) {
    console.error('Test case 6 failed:', error);
  }
  
  console.log('\n--- Tests completed ---\n');
}

// Run the tests
runTests().catch(console.error);