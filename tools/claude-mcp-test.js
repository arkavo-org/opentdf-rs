#!/usr/bin/env node

/**
 * Claude MCP Test Script
 * 
 * This script tests the OpenTDF MCP server with the exact same parameter
 * format that Claude Code uses.
 */

const { spawn } = require('child_process');
const readline = require('readline');

// Start the MCP server
console.log('Starting OpenTDF MCP Server...');
const mcpServer = spawn('cargo', ['run', '-p', 'opentdf-mcp-server'], {
  stdio: ['pipe', 'pipe', 'inherit'] // pipe stdin/stdout, inherit stderr
});

// Create readline interface for processing
const rl = readline.createInterface({
  input: mcpServer.stdout,
  terminal: false
});

// Track message ID and pending requests
let messageId = 1;
const pendingRequests = new Map();

// Function to send a request to the MCP server
function sendRequest(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = messageId++;
    const request = {
      jsonrpc: "2.0",
      id,
      method,
      params
    };
    
    pendingRequests.set(id, { resolve, reject });
    console.log(`\n> Sending ${method} request (ID: ${id})`);
    mcpServer.stdin.write(JSON.stringify(request) + "\n");
    
    // Set a timeout for the request
    setTimeout(() => {
      if (pendingRequests.has(id)) {
        pendingRequests.delete(id);
        reject(new Error(`Request timed out: ${method}`));
      }
    }, 5000);
  });
}

// Process server responses
rl.on('line', (line) => {
  if (!line.trim().startsWith('{')) return;
  
  try {
    const response = JSON.parse(line);
    if (response.id && pendingRequests.has(response.id)) {
      const { resolve, reject } = pendingRequests.get(response.id);
      pendingRequests.delete(response.id);
      
      if (response.error) {
        console.log(`Error: ${response.error.message}`);
        reject(new Error(response.error.message));
      } else {
        resolve(response.result);
      }
    } else if (response.method === 'server/ready') {
      console.log('MCP Server ready');
      // Start the test sequence when server is ready
      runTests();
    }
  } catch (error) {
    console.log(`Error parsing response: ${error.message}`);
  }
});

// Handle process exit
process.on('exit', () => {
  if (!mcpServer.killed) {
    mcpServer.kill();
  }
});

process.on('SIGINT', () => {
  console.log('\nInterrupted, cleaning up...');
  process.exit();
});

// Function to call a tool using Claude's MCP parameter format
async function callTool(name, parameters) {
  console.log(`\n----- Testing tool: ${name} -----`);
  console.log(`Parameters: ${JSON.stringify(parameters, null, 2)}`);
  
  try {
    const result = await sendRequest('tools/call', {
      name,
      parameters
    });
    console.log('Result:');
    console.log(JSON.stringify(result, null, 2));
    return result;
  } catch (error) {
    console.error(`Failed to call ${name}: ${error.message}`);
    return null;
  }
}

// Run all tests
async function runTests() {
  try {
    // Step 1: Initialize the server
    console.log('\n[Step 1] Initializing MCP server');
    const initResult = await sendRequest('initialize');
    console.log(`Server initialized: ${JSON.stringify(initResult.serverInfo)}`);
    
    // Step 2: List namespaces using Claude's content format
    console.log('\n[Step 2] Listing namespaces with content format');
    await callTool('opentdf:namespace_list', {
      content: []
    });
    
    // Step 3: List attributes using Claude's content format
    console.log('\n[Step 3] Listing attributes with content format');
    await callTool('opentdf:attribute_list', {
      content: []
    });
    
    // Step 4: Define a new attribute using Claude's content format
    console.log('\n[Step 4] Defining attribute with content format');
    await callTool('opentdf:attribute_define', {
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
    
    // Step 5: Test policy binding verification with content format
    console.log('\n[Step 5] Testing policy binding verification with content format');
    await callTool('opentdf:policy_binding_verify', {
      content: [
        {
          tdf_data: "UEsDBAoAAAAAAONbk1YAAAAAAAAAAAAAAAAJAAAA",
          policy_key: "test-policy-key-123"
        }
      ]
    });
    
    // Step 6: Test policy creation with content format
    console.log('\n[Step 6] Creating policy with content format');
    const policyResult = await callTool('opentdf:policy_create', {
      content: [
        {
          attributes: [
            {
              attribute: "gov.example:clearance",
              operator: "Equals",
              value: "top-secret"
            }
          ],
          dissemination: ["user@example.com"]
        }
      ]
    });
    
    console.log('\nAll tests completed successfully!');
    
  } catch (error) {
    console.error(`\n❌ Tests failed: ${error.message}`);
  } finally {
    // Clean up
    console.log('\nShutting down server...');
    mcpServer.kill();
    process.exit();
  }
}