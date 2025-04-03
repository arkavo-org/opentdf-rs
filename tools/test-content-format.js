#!/usr/bin/env node

/**
 * Test script for Claude-style MCP content-based parameters
 */

const { spawn } = require('child_process');
const readline = require('readline');

// Start the MCP server
console.log('Starting MCP server...');
const mcp = spawn('cargo', ['run', '-p', 'opentdf-mcp-server'], { 
  cwd: process.cwd(), 
  stdio: ['pipe', 'pipe', 'inherit'] 
});

// Create readline interface
const rl = readline.createInterface({
  input: mcp.stdout,
  terminal: false
});

// Process server responses
rl.on('line', (line) => {
  if (!line.trim().startsWith('{')) return;
  
  try {
    const response = JSON.parse(line);
    
    if (response.method === 'server/ready') {
      console.log('Server is ready, starting tests...');
      runTests();
    } else {
      console.log(`Received response: ${JSON.stringify(response, null, 2)}`);
    }
  } catch (error) {
    console.log(`Error parsing response: ${error.message}`);
  }
});

// Track message ID
let messageId = 1;

// Send JSON-RPC request
function sendRequest(method, params = {}) {
  const request = {
    jsonrpc: "2.0",
    id: messageId++,
    method,
    params
  };
  
  console.log(`\nSending request: ${JSON.stringify(request, null, 2)}`);
  mcp.stdin.write(JSON.stringify(request) + "\n");
}

// Simulate the MCP tool call exactly as Claude would make it
function sendToolCall(toolName, params = {}) {
  console.log(`\n--- Testing tool: ${toolName} ---`);
  
  const toolParams = {
    name: toolName,
    parameters: params
  };
  
  sendRequest('tools/call', toolParams);
}

// Run the test sequence
async function runTests() {
  // Initialize server
  sendRequest('initialize');
  
  // Wait for server to initialize
  setTimeout(() => {
    // Test namespace_list with content format
    sendToolCall('opentdf:namespace_list', {
      content: []
    });
    
    // Test attribute_list with content format
    setTimeout(() => {
      sendToolCall('opentdf:attribute_list', {
        content: []
      });
      
      // Test attribute_define with namespaces in content format
      setTimeout(() => {
        sendToolCall('opentdf:attribute_define', {
          content: [
            {
              namespaces: [
                {
                  name: "gov",
                  attributes: ["security", "classification", "clearance"]
                }
              ]
            }
          ]
        });
        
        // Test tdf_create with content format
        setTimeout(() => {
          sendToolCall('opentdf:tdf_create', {
            content: [
              {
                data: "SGVsbG8gV29ybGQh", // "Hello World!" base64 encoded
                kas_url: "https://kas.example.com",
                policy: {
                  uuid: "test-policy",
                  body: {
                    attributes: [
                      {
                        attribute: "gov.example:clearance",
                        operator: "MinimumOf",
                        value: "secret"
                      }
                    ],
                    dissem: ["user@example.com"]
                  }
                }
              }
            ]
          });
          
          // Test policy_binding_verify with content format
          setTimeout(() => {
            sendToolCall('opentdf:policy_binding_verify', {
              content: [
                {
                  tdf_data: "UEsDBA==", // Dummy base64 data
                  policy_key: "test-policy-key"
                }
              ]
            });
            
            // Exit after tests are complete
            setTimeout(() => {
              console.log('Tests completed, exiting...');
              mcp.kill();
              process.exit(0);
            }, 1000);
          }, 1000);
        }, 1000);
      }, 1000);
    }, 1000);
  }, 1000);
}

// Handle process termination
process.on('SIGINT', () => {
  console.log('Received SIGINT, shutting down...');
  if (mcp) mcp.kill();
  process.exit(0);
});