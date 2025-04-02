#!/usr/bin/env node

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

// Run the test sequence
async function runTests() {
  try {
    // Step 1: Initialize the server
    console.log('\n[Step 1] Initializing MCP server');
    const initResult = await sendRequest('initialize');
    console.log(`Server initialized: ${initResult.serverInfo.name} v${initResult.serverInfo.version}`);
    
    // Step 2: Define sample attributes
    console.log('\n[Step 2] Defining sample attributes');
    
    // First attribute with hierarchy
    await sendRequest('attribute_define', {
      namespace: 'clearance',
      name: 'level',
      values: ['PUBLIC', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'],
      hierarchy: [
        { value: 'PUBLIC', inherits_from: null },
        { value: 'CONFIDENTIAL', inherits_from: 'PUBLIC' },
        { value: 'SECRET', inherits_from: 'CONFIDENTIAL' },
        { value: 'TOP_SECRET', inherits_from: 'SECRET' }
      ]
    });
    console.log(`Defined clearance levels`);
    
    // Step 3: List all attributes
    console.log('\n[Step 3] Listing all attributes');
    
    const attributeListResult = await sendRequest('attribute_list');
    
    console.log('Attribute List Result:');
    console.log(JSON.stringify(attributeListResult, null, 2));
    
    // Step 4: List all namespaces
    console.log('\n[Step 4] Listing all namespaces');
    
    const namespaceListResult = await sendRequest('namespace_list');
    
    console.log('Namespace List Result:');
    console.log(JSON.stringify(namespaceListResult, null, 2));
    
    // All tests complete
    console.log('\n✅ Test completed successfully!');
    
  } catch (error) {
    console.error(`\n❌ Test failed: ${error.message}`);
  } finally {
    // Clean up
    mcpServer.kill();
    process.exit();
  }
}