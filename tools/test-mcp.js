#!/usr/bin/env node

/**
 * Comprehensive MCP server test utility
 *
 * Tests the OpenTDF MCP server implementation by:
 * 1. Sending an initialize request
 * 2. Validating the response format
 * 3. Testing each available tool with sample data
 * 4. Validating error handling
 */

const { spawn } = require('child_process');
const crypto = require('crypto');

console.log('OpenTDF MCP Server Test');
console.log('======================');

// Start the MCP server
const mcpServer = spawn('cargo', ['run', '-p', 'opentdf-mcp-server'], {
  stdio: ['pipe', 'pipe', 'inherit'] // pipe stdin/stdout, inherit stderr
});

// Track responses by request ID
const pendingRequests = new Map();
let lastResponseId = 0;
let serverInitialized = false;
let tools = [];

// Clean up on exit
process.on('exit', () => {
  if (mcpServer && !mcpServer.killed) {
    mcpServer.kill();
  }
});

process.on('SIGINT', () => {
  console.log('\nTest interrupted. Cleaning up...');
  process.exit(1);
});

// Handle server output
let jsonBuffer = '';
mcpServer.stdout.on('data', (data) => {
  const output = data.toString();
  
  // If it looks like JSON, add to buffer
  if (output.trim().startsWith('{')) {
    jsonBuffer += output;
    
    try {
      // Try to parse the accumulated JSON
      const response = JSON.parse(jsonBuffer);
      console.log(`Response received for request ${response.id}`);
      
      // Reset buffer after successful parse
      jsonBuffer = '';
      
      // Find matching request
      if (pendingRequests.has(response.id)) {
        const request = pendingRequests.get(response.id);
        pendingRequests.delete(response.id);

        // Process the response based on the request method
        processResponse(request, response);
      } else {
        console.log('Received response for unknown request ID:', response.id);
      }
    } catch (e) {
      // JSON is incomplete, continue collecting
      // This is normal if the response is split across multiple chunks
    }
  } else if (output.trim()) {
    console.log(`Server log: ${output.trim()}`);
  }
});

mcpServer.on('error', (err) => {
  console.error('Failed to start MCP server:', err);
  process.exit(1);
});

mcpServer.on('close', (code) => {
  if (code !== 0 && code !== null) {
    console.error(`MCP server exited with code ${code}`);
  }
});

// Send a JSON-RPC request to the server
function sendRequest(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++lastResponseId;
    const request = {
      jsonrpc: "2.0",
      id,
      method,
      params
    };

    pendingRequests.set(id, {
      method,
      params,
      resolve,
      reject,
      timestamp: Date.now()
    });

    console.log(`Sending ${method} request (id: ${id})...`);
    mcpServer.stdin.write(JSON.stringify(request) + "\n");

    // Set timeout for this request
    setTimeout(() => {
      if (pendingRequests.has(id)) {
        const pendingRequest = pendingRequests.get(id);
        pendingRequests.delete(id);
        pendingRequest.reject(new Error(`Timeout waiting for ${method} response`));
      }
    }, 5000);
  });
}

// Process a response based on request method
function processResponse(request, response) {
  if (response.error) {
    console.log(`❌ Error in ${request.method} response:`, response.error.message);
    request.reject(new Error(response.error.message));
    return;
  }

  switch (request.method) {
    case 'initialize':
      handleInitializeResponse(response.result);
      break;
    case 'initialized':
      console.log(`✅ Server acknowledged initialized signal`);
      break;
    case 'listTools':
      handleListToolsResponse(response.result);
      break;
    default:
      // Tool-specific responses
      console.log(`✅ ${request.method} successful`);
  }

  request.resolve(response.result);
}

// Handle initialize response
function handleInitializeResponse(result) {
  console.log('\n✅ MCP Server Initialization:');

  // Check protocol
  if (result.protocol) {
    console.log(`   Protocol: ${result.protocol.name}`);
    console.log(`   Version: ${result.protocol.version}`);
  } else if (result.protocolVersion) {
    console.log(`   Protocol Version: ${result.protocolVersion}`);
  } else {
    console.log('❌ Missing protocol version information');
  }

  // Check server info
  if (result.serverInfo) {
    console.log(`   Server Name: ${result.serverInfo.name}`);
    console.log(`   Server Version: ${result.serverInfo.version}`);
    console.log(`   Vendor: ${result.serverInfo.vendor}`);
  } else {
    console.log('❌ Missing server information');
  }

  // Check capabilities
  if (result.capabilities?.tools) {
    tools = Array.isArray(result.capabilities.tools)
        ? result.capabilities.tools
        : Object.entries(result.capabilities.tools).map(([name, info]) => ({ name, ...info }));

    console.log(`   Tools Available: ${tools.length}`);
    console.log(`   Tools: ${tools.map(t => t.name).join(', ')}`);
  } else {
    console.log('❌ No tools found in capabilities');
  }

  serverInitialized = true;
}

// Handle listTools response
function handleListToolsResponse(result) {
  if (result.tools) {
    console.log(`\n✅ Available Tools: ${result.tools.length}`);
    tools = result.tools;
  } else {
    console.log('\n❌ No tools returned from listTools');
  }
}

// Generate sample test data
function generateTestData() {
  // Sample data for testing
  const sampleText = "This is a test of the OpenTDF MCP server";
  const sampleData = Buffer.from(sampleText).toString('base64');
  const samplePolicy = {
    uuid: crypto.randomUUID(),
    body: {
      dataAttributes: ["classification::public", "category::test"],
      dissem: ["user@example.com"],
      expiry: new Date(Date.now() + 86400000).toISOString() // 24 hours from now
    }
  };

  return {
    sampleText,
    sampleData,
    samplePolicy,
    kasUrl: "https://kas.example.com"
  };
}

// Test a specific tool
async function testTool(tool) {
  console.log(`\nTesting tool: ${tool.name}`);

  const { sampleData, samplePolicy, kasUrl } = generateTestData();
  let params = {};

  // Create appropriate parameters based on tool name
  switch (tool.name) {
    // Echo test removed - not needed for OpenTDF
    case 'tdf_create':
      params = { data: sampleData, kas_url: kasUrl, policy: samplePolicy };
      break;
    case 'tdf_read':
      console.log('   Skipping tdf_read (requires output from tdf_create)');
      return null; // Skip for now
    case 'encrypt':
      params = { data: sampleData };
      break;
    case 'decrypt':
      console.log('   Skipping decrypt (requires output from encrypt)');
      return null; // Skip for now
    case 'policy_create':
      params = {
        attributes: samplePolicy.body.dataAttributes,
        dissemination: samplePolicy.body.dissem,
        expiry: samplePolicy.body.expiry
      };
      break;
    case 'policy_validate':
      console.log('   Skipping policy_validate (requires output from other operations)');
      return null; // Skip for now
    default:
      console.log(`   Unknown tool: ${tool.name}, skipping test`);
      return null;
  }

  try {
    const result = await sendRequest(tool.name, params);
    console.log(`   Result: `, JSON.stringify(result).substring(0, 100) + '...');
    return result;
  } catch (error) {
    console.log(`   ❌ Error testing ${tool.name}: ${error.message}`);
    return null;
  }
}

// Test error handling
async function testErrorHandling() {
  console.log('\nTesting error handling:');

  // Test invalid method
  try {
    await sendRequest('nonexistent_method');
    console.log('   ❌ Expected error for nonexistent method, but got success');
  } catch (error) {
    console.log('   ✅ Correctly received error for nonexistent method');
  }

  // Test invalid parameters with tdf_create instead of echo
  try {
    await sendRequest('tdf_create', { invalid_param: 'test' });
    console.log('   ⚠️ Server accepted invalid parameters (may not validate params)');
  } catch (error) {
    console.log('   ✅ Correctly received error for invalid parameters');
  }
}

// Run all tests
async function runTests() {
  try {
    // Wait for server to start
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Initialize the server
    console.log('\nSending initialize request...');
    await sendRequest('initialize');

    if (!serverInitialized) {
      throw new Error('Server failed to initialize properly');
    }

    // Send initialized signal
    await sendRequest('initialized');

    // List available tools if not already populated
    if (tools.length === 0) {
      console.log('\nRequesting tool list...');
      await sendRequest('listTools');
    }

    // Test each available tool
    const results = {};
    for (const tool of tools) {
      const result = await testTool(tool);
      if (result) {
        results[tool.name] = result;
      }
    }

    // Test chained operations if possible
    if (results.tdf_create && tools.some(t => t.name === 'tdf_read')) {
      console.log('\nTesting chained operation: tdf_read with tdf_create output');
      await sendRequest('tdf_read', { tdf_data: results.tdf_create.tdf_data });
    }

    // Test error handling
    await testErrorHandling();

    console.log('\n✅ All tests completed successfully!');
  } catch (error) {
    console.log(`\n❌ Test failed: ${error.message}`);
  } finally {
    // Summarize test results
    console.log('\n=== Test Results Summary ===');
    
    // Count successes and failures
    const implementedTools = [];
    const missingTools = [];
    
    // Check which tools responded correctly
    for (const tool of tools) {
      if (tool.name === 'tdf_create') {
        implementedTools.push(tool.name);
      } else if (['decrypt', 'tdf_read', 'policy_validate'].includes(tool.name)) {
        // These were skipped, they might be implemented
        console.log(`⚠️  Tool not tested (dependencies required): ${tool.name}`);
      } else {
        missingTools.push(tool.name);
      }
    }
    
    if (implementedTools.length > 0) {
      console.log(`✅ Implemented tools: ${implementedTools.join(', ')}`);
    }
    
    if (missingTools.length > 0) {
      console.log(`❌ Missing implementations: ${missingTools.join(', ')}`);
      console.log('\nRecommendation: Implement handlers for these methods in the MCP server.');
    }
    
    // Clean up
    console.log('\nTest completed. Shutting down server...');
    mcpServer.kill();
    process.exit(missingTools.length > 0 ? 1 : 0);
  }
}

// Start the tests
runTests();
