#!/usr/bin/env node

/**
 * OpenTDF-RS Attribute Listing Tool
 * 
 * This utility connects to the OpenTDF MCP server and lists defined attributes.
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
      listAttributes();
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

// List attributes
async function listAttributes() {
  try {
    // Step 1: Initialize the server
    console.log('\n[Step 1] Initializing MCP server');
    const initResult = await sendRequest('initialize');
    console.log(`Server initialized: ${initResult.serverInfo.name} v${initResult.serverInfo.version}`);
    
    // Step 2: Define some attribute hierarchies (optional, as the server already has a few examples)
    console.log('\n[Step 2] Defining some additional attribute hierarchies');
    
    // Define a location attribute
    await sendRequest('attribute_define', {
      namespace: 'gov.example',
      name: 'location',
      values: ['us', 'eu', 'asia', 'global']
    });
    console.log(`Defined location attribute`);
    
    // Step 3: List all attributes
    console.log('\n[Step 3] Listing all defined attributes');
    
    const attributeListResult = await sendRequest('attribute_list');
    
    console.log(`\nFound ${attributeListResult.count} attributes:\n`);
    
    // Display each attribute with proper formatting
    attributeListResult.attributes.forEach((attr, index) => {
      console.log(`ATTRIBUTE #${index+1}: ${attr.namespace}:${attr.name}`);
      console.log(`ID: ${attr.id}`);
      console.log(`Values: ${attr.values.join(', ')}`);
      
      // Handle hierarchy display
      if (attr.hierarchy) {
        console.log('Hierarchy:');
        for (const [value, parent] of Object.entries(attr.hierarchy)) {
          console.log(`  - ${value} inherits from: ${parent || 'none (root level)'}`);
        }
      } else {
        console.log('Hierarchy: None (flat attribute)');
      }
      console.log(''); // Empty line between attributes
    });
    
    console.log('Attribute listing complete');
    
  } catch (error) {
    console.error(`\n❌ Operation failed: ${error.message}`);
  } finally {
    // Clean up
    mcpServer.kill();
    process.exit();
  }
}