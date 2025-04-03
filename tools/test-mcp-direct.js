#!/usr/bin/env node

/**
 * Test script for direct MCP tool calls
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
    // Test namespace_list
    sendToolCall('opentdf:namespace_list', {
      content: []
    });
    
    // Test attribute_list
    setTimeout(() => {
      sendToolCall('opentdf:attribute_list', {
        content: []
      });
      
      // Test attribute_define with namespaces
      setTimeout(() => {
        sendToolCall('opentdf:attribute_define', {
          content: [{
            namespaces: [{
              name: "gov",
              attributes: ["security", "classification", "clearance"]
            }]
          }]
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
}

// Handle process termination
process.on('SIGINT', () => {
  console.log('Received SIGINT, shutting down...');
  if (mcp) mcp.kill();
  process.exit(0);
});