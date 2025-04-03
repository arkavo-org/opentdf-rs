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
    console.log(JSON.stringify(request, null, 2));
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
    
    // Step 2: Test attribute_list with content parameter
    console.log('\n[Step 2] Testing attribute_list with content parameter');
    
    const attrListResult = await sendRequest('attribute_list', {
      content: []
    });
    
    console.log('Attribute List Result:');
    console.log(JSON.stringify(attrListResult, null, 2));
    
    // Step 3: Test namespace_list with content parameter
    console.log('\n[Step 3] Testing namespace_list with content parameter');
    
    const namespaceListResult = await sendRequest('namespace_list', {
      content: []
    });
    
    console.log('Namespace List Result:');
    console.log(JSON.stringify(namespaceListResult, null, 2));
    
    // Step 4: Test attribute_define with content parameter
    console.log('\n[Step 4] Testing attribute_define with content parameter');
    
    const attrDefineResult = await sendRequest('attribute_define', {
      content: [{
        name: "gov",
        attributes: ["security", "classification", "clearance"]
      }]
    });
    
    console.log('Attribute Define Result:');
    console.log(JSON.stringify(attrDefineResult, null, 2));
    
    // Step 5: Test MCP-style tool calls
    console.log('\n[Step 5] Testing MCP-style tool calls');
    
    // Test opentdf:attribute_list
    await simulateMcpToolCall('opentdf:attribute_list', {
      content: []
    });
    
    // Test opentdf:namespace_list
    await simulateMcpToolCall('opentdf:namespace_list', {
      content: []
    });
    
    // Test opentdf:attribute_define
    await simulateMcpToolCall('opentdf:attribute_define', {
      content: [{
        namespaces: [{
          name: "gov",
          attributes: ["security", "classification", "clearance"]
        }]
      }]
    });
    
    // All tests complete
    console.log('\n✅ Content parameter tests completed successfully!');
    
  } catch (error) {
    console.error(`\n❌ Test failed: ${error.message}`);
  } finally {
    // Clean up
    mcpServer.kill();
    process.exit();
  }
}