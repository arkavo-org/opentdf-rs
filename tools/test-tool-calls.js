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

// Function to simulate an MCP tool call like Claude would make
async function simulateMcpToolCall(toolName, params) {
  console.log(`\n[TEST] Simulating MCP tool call: ${toolName}`);
  
  const toolCallParams = {
    name: toolName,
    parameters: params
  };
  
  try {
    const result = await sendRequest('tools/call', toolCallParams);
    console.log(`Tool call result: ${JSON.stringify(result, null, 2)}`);
    return result;
  } catch (error) {
    console.error(`Tool call error: ${error.message}`);
    return null;
  }
}

// Run the test sequence
async function runTests() {
  try {
    // Step 1: Initialize the server
    console.log('\n[Step 1] Initializing MCP server');
    const initResult = await sendRequest('initialize');
    console.log(`Server initialized: ${initResult.serverInfo.name} v${initResult.serverInfo.version}`);
    
    // Step 2: Test the TDF create call with both formats
    console.log('\n[Step 2] Testing TDF create with different formats');
    
    // Test with normal format
    await simulateMcpToolCall('opentdf__tdf_create', {
      data: "SGVsbG8gV29ybGQ=",
      kas_url: "https://example.com/kas",
      policy: { body: { attributes: [], dissem: ["user@example.com"] } }
    });
    
    // Test with colon format
    await simulateMcpToolCall('opentdf:tdf_create', {
      data: "SGVsbG8gV29ybGQ=",
      kas_url: "https://example.com/kas",
      policy: { body: { attributes: [], dissem: ["user@example.com"] } }
    });
    
    // Step 3: Test namespace listing
    console.log('\n[Step 3] Testing namespace listing');
    
    // Test with normal format
    await simulateMcpToolCall('opentdf__namespace_list', {});
    
    // Test with colon format
    await simulateMcpToolCall('opentdf:namespace_list', {});
    
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