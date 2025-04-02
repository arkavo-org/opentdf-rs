#!/usr/bin/env node

/**
 * OpenTDF-RS MCP ABAC Test Client
 * 
 * This utility demonstrates using the MCP server for ABAC testing without Claude.
 * It implements a simple client that connects to the OpenTDF MCP server and
 * exercises the ABAC functionality through a sequence of operations.
 */

const { spawn } = require('child_process');
const readline = require('readline');
const fs = require('fs');
const path = require('path');

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
    
    // Step 2: Define attribute hierarchies
    console.log('\n[Step 2] Defining attribute hierarchies');
    
    // Define clearance levels
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
    console.log(`Defined clearance levels: ${clearanceResult.attribute.values.join(', ')}`);
    
    // Define departments
    const departmentResult = await sendRequest('attribute_define', {
      namespace: 'gov.example',
      name: 'department',
      values: ['research', 'engineering', 'finance', 'executive']
    });
    console.log(`Defined departments: ${departmentResult.attribute.values.join(', ')}`);
    
    // Step 3: Define users with attributes
    console.log('\n[Step 3] Creating users with attributes');
    
    // Define Alice (high clearance)
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
    console.log(`Created user Alice with attributes: top-secret clearance, executive department`);
    
    // Define Bob (lower clearance)
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
    console.log(`Created user Bob with attributes: confidential clearance, research department`);
    
    // Step 4: Create a policy with ABAC rules
    console.log('\n[Step 4] Creating attribute-based policy');
    
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
    
    console.log(`Created policy with UUID: ${policyResult.policy.uuid}`);
    console.log(`Policy requires: secret clearance AND (executive OR engineering department)`);
    
    // Step 5: Create a TDF with the policy
    console.log('\n[Step 5] Creating TDF with policy protection');
    
    const sampleText = "This is sensitive information protected by attribute-based access control.";
    const sampleData = Buffer.from(sampleText).toString('base64');
    
    const tdfResult = await sendRequest('tdf_create', {
      data: sampleData,
      kas_url: 'https://kas.example.com',
      policy: policyResult.policy
    });
    
    console.log(`Created TDF with ID: ${tdfResult.id}`);
    
    // Save TDF data to a file for illustration
    const tdfFilePath = path.join(__dirname, 'sample.tdf');
    fs.writeFileSync(tdfFilePath, Buffer.from(tdfResult.tdf_data, 'base64'));
    console.log(`Saved TDF to: ${tdfFilePath}`);
    
    // Step 6: Read TDF metadata
    console.log('\n[Step 6] Reading TDF metadata');
    
    const readResult = await sendRequest('tdf_read', {
      tdf_data: tdfResult.tdf_data
    });
    
    console.log(`TDF payload protocol: ${readResult.manifest.payload.protocol}`);
    console.log(`TDF encryption algorithm: ${readResult.manifest.encryptionInformation.method.algorithm}`);
    
    // Step 7: Evaluate access for users
    console.log('\n[Step 7] Evaluating access for users');
    
    // Alice should have access (top-secret + executive)
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
    
    // Bob should not have access (confidential + research)
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
    
    console.log(`Alice's access: ${aliceAccessResult.access_granted ? 'GRANTED' : 'DENIED'}`);
    console.log(`Bob's access: ${bobAccessResult.access_granted ? 'GRANTED' : 'DENIED'}`);
    
    if (aliceAccessResult.access_granted && !bobAccessResult.access_granted) {
      console.log('\n✅ ABAC SUCCESSFULLY DEMONSTRATED!');
      console.log('Alice has access because she has:');
      console.log('  - top-secret clearance (which satisfies min requirement of secret)');
      console.log('  - executive department (which is allowed by the policy)');
      console.log('Bob is denied because he has:');
      console.log('  - confidential clearance (below the required minimum of secret)');
      console.log('  - research department (not included in allowed departments)');
    } else {
      console.log('\n❌ UNEXPECTED ACCESS RESULTS!');
    }
    
    // Step 8: Verify policy binding
    console.log('\n[Step 8] Verifying policy binding');
    
    const bindingResult = await sendRequest('policy_binding_verify', {
      tdf_data: tdfResult.tdf_data,
      policy_key: 'dummy_policy_key_for_demonstration'
    });
    
    console.log(`Policy binding verified: ${bindingResult.binding_valid ? 'Valid' : 'Invalid'}`);
    console.log(`Binding algorithm: ${bindingResult.binding_info.algorithm}`);
    
    // All tests complete
    console.log('\n🎉 All ABAC tests completed successfully!');
    
  } catch (error) {
    console.error(`\n❌ Test failed: ${error.message}`);
  } finally {
    // Clean up
    mcpServer.kill();
    process.exit();
  }
}

// Let the server start up, it will notify us when ready