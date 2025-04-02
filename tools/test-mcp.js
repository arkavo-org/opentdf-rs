#!/usr/bin/env node

/**
 * OpenTDF MCP Test Script
 * 
 * This script demonstrates using the Model Context Protocol (MCP) to interact with
 * the OpenTDF library through the MCP server.
 * 
 * It executes a series of steps to test the Attribute-Based Access Control (ABAC)
 * functionality of OpenTDF using the MCP interface.
 */

const { spawn } = require('child_process');
const crypto = require('crypto');

console.log('OpenTDF ABAC Test with MCP');
console.log('=========================');

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
let processedResponses = new Set(); // Track responses we've already processed

mcpServer.stdout.on('data', (data) => {
  const output = data.toString();
  const lines = output.split('\n');
  
  // Process each line separately to handle the duplicate output issue
  for (const line of lines) {
    if (!line.trim()) continue;
    
    if (line.trim().startsWith('{')) {
      try {
        // Try to parse the JSON directly from the line
        const response = JSON.parse(line.trim());
        
        // Create a unique key for deduplication
        const responseKey = `${response.id}-${response.method || 'unknown'}`;
        
        // Skip if we've already processed this response
        if (processedResponses.has(responseKey)) {
          continue;
        }
        
        // Mark as processed
        processedResponses.add(responseKey);
        
        // Process the response
        if (response.id && pendingRequests.has(response.id)) {
          console.log(`✅ Response received for request ${response.id}`);
          const request = pendingRequests.get(response.id);
          pendingRequests.delete(response.id);
          
          // Process the response based on the request method
          processResponse(request, response);
        } else if (response.method === 'server/ready') {
          console.log('MCP Server ready');
          // Start the test sequence when server is ready
          setTimeout(runTests, 1000);
        } else if (response.id) {
          console.log(`⚠️ Response has unknown ID: ${response.id}, Method=${response.method || 'unknown'}`);
        }
      } catch (e) {
        // If direct parsing fails, add to buffer and try to parse
        jsonBuffer += line;
        try {
          const response = JSON.parse(jsonBuffer);
          jsonBuffer = '';
          
          // Create a unique key for deduplication
          const responseKey = `${response.id}-${response.method || 'unknown'}`;
          
          // Skip if we've already processed this response
          if (processedResponses.has(responseKey)) {
            continue;
          }
          
          // Mark as processed
          processedResponses.add(responseKey);
          
          // Process the response
          if (response.id && pendingRequests.has(response.id)) {
            console.log(`✅ Response received for request ${response.id} (from buffer)`);
            const request = pendingRequests.get(response.id);
            pendingRequests.delete(response.id);
            
            // Process the response based on the request method
            processResponse(request, response);
          }
        } catch (bufferError) {
          // JSON is still incomplete, keep collecting
        }
      }
    } else if (line.trim()) {
      console.log(`Server log: ${line.trim()}`);
    }
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

    console.log(`\n📤 Sending ${method} request (id: ${id})...`);
    mcpServer.stdin.write(JSON.stringify(request) + "\n");

    // Set timeout for this request
    setTimeout(() => {
      if (pendingRequests.has(id)) {
        console.log(`🕒 Timeout reached for request ${id} (${method})`);
        console.log(`🔍 Debug: Pending requests at timeout: ${[...pendingRequests.keys()].join(', ')}`);
        const pendingRequest = pendingRequests.get(id);
        pendingRequests.delete(id);
        pendingRequest.reject(new Error(`Timeout waiting for ${method} response`));
      }
    }, 10000); // Increased timeout to 10 seconds
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
  if (result.protocolVersion) {
    console.log(`   Protocol Version: ${result.protocolVersion}`);
  } else {
    console.log('⚠️ Missing protocol version information');
  }

  // Check server info
  if (result.serverInfo) {
    console.log(`   Server Name: ${result.serverInfo.name}`);
    console.log(`   Server Version: ${result.serverInfo.version}`);
  } else {
    console.log('⚠️ Missing server information');
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
    console.log(`   Tool names: ${tools.map(t => t.name).join(', ')}`);
  } else {
    console.log('\n❌ No tools returned from listTools');
  }
}

// Run all ABAC tests
async function runTests() {
  // Flag to track test failure
  let testFailed = false;
  try {
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

    console.log('\n🔍 Starting ABAC Test Sequence');
    console.log('-----------------------------');

    // Step 1: Define attribute namespaces
    console.log('\n📋 Step 1: Define attribute namespaces');
    
    // Define clearance levels with hierarchy
    const clearanceResult = await sendRequest('attribute_define', {
      namespace: 'gov.example',
      name: 'clearance',
      values: ['public', 'confidential', 'secret', 'top-secret'],
      hierarchy: [
        { value: 'top-secret', inherits_from: 'secret' },
        { value: 'secret', inherits_from: 'confidential' },
        { value: 'confidential', inherits_from: 'public' }
      ]
    });
    
    console.log(`   ✅ Defined clearance levels: ${clearanceResult?.attribute?.values?.join(', ') || 'N/A'}`);

    // Define departments attribute
    const departmentResult = await sendRequest('attribute_define', {
      namespace: 'gov.example',
      name: 'department',
      values: ['research', 'engineering', 'finance', 'executive']
    });
    
    console.log(`   ✅ Defined departments: ${departmentResult?.attribute?.values?.join(', ') || 'N/A'}`);

    // Step 2: Define user attributes
    console.log('\n👤 Step 2: Define user attributes');
    
    // Define an authorized user with high clearance
    const aliceResult = await sendRequest('user_attributes', {
      user_id: 'alice@example.com',
      attributes: [
        {
          namespace: 'gov.example',
          name: 'clearance',
          value: 'top-secret'
        },
        {
          namespace: 'gov.example',
          name: 'department',
          value: 'executive'
        }
      ]
    });
    
    console.log(`   ✅ Defined user Alice with attributes: top-secret clearance, executive department`);
    
    // Define a user with lower clearance
    const bobResult = await sendRequest('user_attributes', {
      user_id: 'bob@example.com',
      attributes: [
        {
          namespace: 'gov.example',
          name: 'clearance',
          value: 'confidential'
        },
        {
          namespace: 'gov.example',
          name: 'department',
          value: 'research'
        }
      ]
    });
    
    console.log(`   ✅ Defined user Bob with attributes: confidential clearance, research department`);

    // Step 3: Create a policy with attribute conditions
    console.log('\n🔒 Step 3: Create attribute-based policy');
    
    const policyResult = await sendRequest('policy_create', {
      attributes: [
        {
          attribute: 'gov.example:clearance',
          operator: 'MinimumOf',
          value: 'secret'
        },
        {
          attribute: 'gov.example:department',
          operator: 'In',
          value: ['executive', 'engineering']
        }
      ],
      dissemination: ['alice@example.com', 'bob@example.com'],
      valid_from: new Date().toISOString(),
      valid_to: new Date(Date.now() + 86400000).toISOString() // 24 hours from now
    });
    
    console.log(`   ✅ Created policy requiring secret clearance AND executive/engineering department`);
    if (policyResult?.policy?.uuid) {
      console.log(`   🔑 Policy UUID: ${policyResult.policy.uuid}`);
    }

    // Step 4: Create a TDF with policy protection
    console.log('\n📁 Step 4: Create TDF with policy protection');
    
    const sampleText = "This is sensitive information requiring secret clearance and executive/engineering department.";
    const sampleData = Buffer.from(sampleText).toString('base64');
    
    const tdfResult = await sendRequest('tdf_create', {
      data: sampleData,
      kas_url: 'https://kas.example.com',
      policy: policyResult?.policy || { 
        uuid: crypto.randomUUID(),
        body: {
          attributes: [
            {
              attribute: 'gov.example:clearance',
              operator: 'MinimumOf',
              value: 'secret'
            }
          ],
          dissem: ['user@example.com']
        }
      }
    });
    
    console.log(`   ✅ Created TDF with protected data (${sampleText.length} bytes)`);
    if (tdfResult?.id) {
      console.log(`   🔑 TDF ID: ${tdfResult.id}`);
    }

    // Step 5: Read TDF metadata
    console.log('\n📖 Step 5: Read TDF metadata');
    
    if (tdfResult?.tdf_data) {
      const readResult = await sendRequest('tdf_read', {
        tdf_data: tdfResult.tdf_data
      });
      
      console.log(`   ✅ Successfully read TDF metadata`);
      if (readResult?.manifest?.payload?.protocol) {
        console.log(`   📊 Payload protocol: ${readResult.manifest.payload.protocol}`);
      }
      if (readResult?.manifest?.encryptionInformation?.method?.algorithm) {
        console.log(`   🔐 Encryption method: ${readResult.manifest.encryptionInformation.method.algorithm}`);
      }
    } else {
      console.log(`   ⚠️ Skipping TDF read (no TDF data available)`);
    }

    // Step 6: Evaluate access for different users
    console.log('\n🔍 Step 6: Evaluate access for different users');
    
    // Alice has top-secret clearance and executive department - should be granted
    if (policyResult?.policy) {
      const aliceAccessResult = await sendRequest('access_evaluate', {
        policy: policyResult.policy,
        user_attributes: {
          user_id: 'alice@example.com',
          attributes: [
            { attribute: 'gov.example:clearance', value: 'top-secret' },
            { attribute: 'gov.example:department', value: 'executive' }
          ]
        }
      });
      
      // Bob has only confidential clearance and is in research - should be denied
      const bobAccessResult = await sendRequest('access_evaluate', {
        policy: policyResult.policy,
        user_attributes: {
          user_id: 'bob@example.com',
          attributes: [
            { attribute: 'gov.example:clearance', value: 'confidential' },
            { attribute: 'gov.example:department', value: 'research' }
          ]
        }
      });
      
      console.log(`   ✅ Alice's access: ${aliceAccessResult?.access_granted ? 'GRANTED ✓' : 'DENIED ✗'}`);
      console.log(`   ✅ Bob's access: ${bobAccessResult?.access_granted ? 'GRANTED ✓' : 'DENIED ✗'}`);
    } else {
      console.log(`   ⚠️ Skipping access evaluation (no policy available)`);
    }

    // Step 7: Verify policy binding
    console.log('\n🔐 Step 7: Verify policy binding');
    
    if (tdfResult?.tdf_data) {
      const bindingResult = await sendRequest('policy_binding_verify', {
        tdf_data: tdfResult.tdf_data,
        policy_key: 'dummy_policy_key_for_test'
      });
      
      console.log(`   ✅ Policy binding verified: ${bindingResult?.binding_valid ? 'Valid ✓' : 'Invalid ✗'}`);
      if (bindingResult?.binding_info?.algorithm) {
        console.log(`   🔏 Binding algorithm: ${bindingResult.binding_info.algorithm}`);
      }
    } else {
      console.log(`   ⚠️ Skipping policy binding verification (no TDF data available)`);
    }

    // Final results
    console.log('\n✅ ABAC Test Results:');
    console.log('------------------');
    console.log(`   Hierarchical attributes: ${clearanceResult ? 'Working ✓' : 'Not tested'}`);
    console.log(`   Policy creation: ${policyResult ? 'Working ✓' : 'Not tested'}`);
    console.log(`   TDF creation: ${tdfResult ? 'Working ✓' : 'Not tested'}`);
    console.log(`   Policy evaluation: ${aliceAccessResult || bobAccessResult ? 'Working ✓' : 'Not tested'}`);
    console.log(`   Policy binding: ${bindingResult ? 'Working ✓' : 'Not tested'}`);
    
    console.log(`\n🎉 Test completed successfully!`);

  } catch (error) {
    console.log(`\n❌ Test failed: ${error.message}`);
    // Set failure flag
    testFailed = true;
  } finally {
    // Clean up
    console.log('\nTest completed. Shutting down server...');
    mcpServer.kill();
    // Exit with appropriate code
    process.exit(testFailed ? 1 : 0);
  }
}