#!/usr/bin/env node

const WebSocket = require('ws');
const { spawn } = require('child_process');
const { v4: uuidv4 } = require('uuid');

// Start the MCP server
console.log('Starting MCP server...');
const mcp = spawn('cargo', ['run', '-p', 'opentdf-mcp-server'], { cwd: process.cwd(), stdio: 'pipe' });

// Give the server a moment to start
setTimeout(() => {
  // Create a WebSocket connection to the MCP server
  console.log('Connecting to MCP server...');
  // Use stdio interface instead of WebSocket since that's the default transport
  console.log("Note: Using stdio for MCP communication which isn't implemented in this script.");
  console.log("This is a demonstration of the test flow, not actual execution.");

  ws.on('open', () => {
    console.log('Connected to MCP server');
    
    console.log('\nRunning Basic Attribute Policy Creation test from TESTS.md');
    console.log('------------------------------------------------------------');
    
    // Step 1: Define the clearance attribute
    const attributeDefineRequest = {
      jsonrpc: '2.0',
      id: uuidv4(),
      method: 'attribute_define',
      params: {
        namespace: 'clearance',
        name: 'level',
        values: ['PUBLIC', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'],
        hierarchy: [
          { value: 'PUBLIC', inherits_from: 'none' },
          { value: 'CONFIDENTIAL', inherits_from: 'PUBLIC' },
          { value: 'SECRET', inherits_from: 'CONFIDENTIAL' },
          { value: 'TOP_SECRET', inherits_from: 'SECRET' }
        ]
      }
    };
    
    console.log('Step 1: Define "clearance:level" attribute with hierarchy');
    ws.send(JSON.stringify(attributeDefineRequest));
    
    // Step 2: Create a policy requiring SECRET clearance
    setTimeout(() => {
      const policyCreateRequest = {
        jsonrpc: '2.0',
        id: uuidv4(),
        method: 'policy_create',
        params: {
          attributes: [
            {
              attribute: 'clearance:level',
              operator: 'equals',
              value: 'SECRET'
            }
          ],
          dissemination: ['user@example.com'],
          valid_from: null,
          valid_to: null
        }
      };
      
      console.log('\nStep 2: Create policy requiring "clearance:SECRET" attribute');
      ws.send(JSON.stringify(policyCreateRequest));
    }, 500);
    
    // Step 3: Create a TDF with the policy
    setTimeout(() => {
      const tdfCreateRequest = {
        jsonrpc: '2.0',
        id: uuidv4(),
        method: 'tdf_create',
        params: {
          data: 'VGhpcyBpcyBzZW5zaXRpdmUgZGF0YQ==', // "This is sensitive data"
          kas_url: 'https://kas.example.com',
          policy: {
            uuid: 'test-policy',
            body: {
              attributes: [
                {
                  attribute: 'clearance:level',
                  operator: 'equals',
                  value: 'SECRET'
                }
              ],
              dissem: ['user@example.com']
            }
          }
        }
      };
      
      console.log('\nStep 3: Create TDF with attribute-based policy');
      ws.send(JSON.stringify(tdfCreateRequest));
    }, 1000);
    
    // Step 4: Verify the policy binding
    setTimeout(() => {
      const bindingVerifyRequest = {
        jsonrpc: '2.0',
        id: uuidv4(),
        method: 'policy_binding_verify',
        params: {
          tdf_data: 'base64_encoded_tdf_data', // Would be actual TDF data in real test
          policy_key: 'base64_encoded_policy_key' // Would be actual policy key in real test
        }
      };
      
      console.log('\nStep 4: Verify the policy binding is properly signed');
      ws.send(JSON.stringify(bindingVerifyRequest));
    }, 1500);
    
    // Step 5: Test access evaluation with user attributes
    setTimeout(() => {
      // First, set user attributes
      const userAttributesRequest = {
        jsonrpc: '2.0',
        id: uuidv4(),
        method: 'user_attributes',
        params: {
          user_id: 'user@example.com',
          attributes: [
            {
              namespace: 'clearance',
              name: 'level',
              value: 'SECRET'
            }
          ]
        }
      };
      
      console.log('\nStep 5a: Set user attributes for evaluation');
      ws.send(JSON.stringify(userAttributesRequest));
      
      // Then evaluate access
      setTimeout(() => {
        const accessEvaluateRequest = {
          jsonrpc: '2.0',
          id: uuidv4(),
          method: 'access_evaluate',
          params: {
            policy: {
              uuid: 'test-policy',
              body: {
                attributes: [
                  {
                    attribute: 'clearance:level',
                    operator: 'equals',
                    value: 'SECRET'
                  }
                ],
                dissem: ['user@example.com']
              }
            },
            user_attributes: {
              user_id: 'user@example.com',
              attributes: [
                {
                  attribute: 'clearance:level',
                  value: 'SECRET'
                }
              ]
            }
          }
        };
        
        console.log('\nStep 5b: Evaluate access for user with matching attributes');
        ws.send(JSON.stringify(accessEvaluateRequest));
      }, 500);
    }, 2000);
    
    // Final clean up
    setTimeout(() => {
      console.log('\nTest complete');
      ws.close();
      mcp.kill();
      process.exit(0);
    }, 3500);
  });
  
  ws.on('message', (data) => {
    const response = JSON.parse(data.toString());
    console.log(`Response: ${JSON.stringify(response, null, 2)}`);
  });
  
  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
    mcp.kill();
    process.exit(1);
  });
  
  ws.on('close', () => {
    console.log('WebSocket connection closed');
    mcp.kill();
  });
  
}, 2000);

mcp.stdout.on('data', (data) => {
  console.log(`MCP server: ${data}`);
});

mcp.stderr.on('data', (data) => {
  console.error(`MCP server error: ${data}`);
});

mcp.on('close', (code) => {
  console.log(`MCP server exited with code ${code}`);
});

// Handle process termination
process.on('SIGINT', () => {
  console.log('Received SIGINT, shutting down...');
  if (mcp) mcp.kill();
  process.exit(0);
});