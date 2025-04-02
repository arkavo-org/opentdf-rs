#!/usr/bin/env node

/**
 * OpenTDF MCP Client
 * 
 * A simple client that connects to Claude's MCP implementation
 * for creating and reading TDF files through the MCP interface.
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

// Setting up stdin/stdout
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

let messageId = 1;
let pendingRequests = new Map();

// Send JSON-RPC message to Claude
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
    console.error(`Sending request: ${JSON.stringify(request)}`);
    process.stdout.write(JSON.stringify(request) + "\n");
  });
}

// Process incoming JSON-RPC messages
process.stdin.on('data', (chunk) => {
  const data = chunk.toString().trim();
  if (!data) return;
  
  try {
    const response = JSON.parse(data);
    
    if (response.id && pendingRequests.has(response.id)) {
      const { resolve, reject } = pendingRequests.get(response.id);
      pendingRequests.delete(response.id);
      
      if (response.error) {
        reject(new Error(response.error.message));
      } else {
        resolve(response.result);
      }
    } else if (response.method === "log") {
      console.error(`Claude: ${response.params.message}`);
    }
  } catch (err) {
    console.error(`Error parsing response: ${err.message}`);
    console.error(`Raw data: ${data}`);
  }
});

// Initialize client
async function initialize() {
  try {
    console.error('Initializing MCP client...');
    // First request the list of available tools
    const toolsResponse = await sendRequest('listTools');
    if (toolsResponse && toolsResponse.tools) {
      console.error(`Available tools: ${toolsResponse.tools.map(t => t.name).join(', ')}`);
      return true;
    } else {
      console.error('Error: Failed to retrieve tool list');
      return false;
    }
  } catch (error) {
    console.error(`Error initializing client: ${error.message}`);
    return false;
  }
}

// Generic function to call any MCP tool
async function callTool(toolName, params = {}) {
  try {
    // Use mcp__opentdf__ prefix for all tools
    const fullToolName = `mcp__opentdf__${toolName}`;
    console.error(`Calling tool: ${fullToolName}`);
    
    const result = await sendRequest(fullToolName, params);
    return result;
  } catch (error) {
    console.error(`Error calling tool ${toolName}: ${error.message}`);
    throw error;
  }
}

// Main function to create a TDF file
async function createTdf(inputFile, outputFile, kasUrl) {
  try {
    // Read the input file
    const fileData = fs.readFileSync(inputFile);
    const base64Data = fileData.toString('base64');
    
    // Create a simple policy
    const policy = {
      uuid: require('crypto').randomUUID(),
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
    };
    
    // Create TDF using the generic callTool function
    const result = await callTool('tdf_create', {
      data: base64Data,
      kas_url: kasUrl || "https://kas.example.com",
      policy: policy
    });
    
    if (result && result.tdf_data) {
      // Write the TDF file
      const tdfData = Buffer.from(result.tdf_data, 'base64');
      fs.writeFileSync(outputFile, tdfData);
      console.error(`TDF file created: ${outputFile}`);
      console.error(`TDF ID: ${result.id}`);
      return true;
    } else {
      console.error("Error: No TDF data returned");
      return false;
    }
  } catch (error) {
    console.error(`Error creating TDF: ${error.message}`);
    return false;
  }
}

// Function to read a TDF file
async function readTdf(tdfFile) {
  try {
    // Read the TDF file
    const fileData = fs.readFileSync(tdfFile);
    const base64Data = fileData.toString('base64');
    
    // Read TDF using the generic callTool function
    const result = await callTool('tdf_read', {
      tdf_data: base64Data
    });
    
    if (result) {
      console.error(`TDF Manifest:`);
      console.error(JSON.stringify(result.manifest, null, 2));
      
      if (result.payload) {
        const payloadData = Buffer.from(result.payload, 'base64');
        console.error(`TDF Payload (${payloadData.length} bytes):`);
        console.error(payloadData.toString().substring(0, 100) + (payloadData.length > 100 ? '...' : ''));
      }
      
      return true;
    } else {
      console.error("Error: No TDF data returned");
      return false;
    }
  } catch (error) {
    console.error(`Error reading TDF: ${error.message}`);
    return false;
  }
}

// Parse command line arguments
const args = process.argv.slice(2);
const command = args[0];

if (command === 'create') {
  if (args.length < 3) {
    console.error('Usage: node mcp_client.js create <input_file> <output_tdf> [kas_url]');
    process.exit(1);
  }
  
  const inputFile = args[1];
  const outputFile = args[2];
  const kasUrl = args[3];
  
  initialize()
    .then(success => {
      if (success) {
        return createTdf(inputFile, outputFile, kasUrl);
      } else {
        return false;
      }
    })
    .then(success => process.exit(success ? 0 : 1));
} else if (command === 'read') {
  if (args.length < 2) {
    console.error('Usage: node mcp_client.js read <tdf_file>');
    process.exit(1);
  }
  
  const tdfFile = args[1];
  
  initialize()
    .then(success => {
      if (success) {
        return readTdf(tdfFile);
      } else {
        return false;
      }
    })
    .then(success => process.exit(success ? 0 : 1));
} else if (command === 'test-abac') {
  // Load and run the ABAC test script
  require('./test-scripts/test-abac-mcp.js');
} else {
  console.error('Usage: node mcp_client.js <command> [options]');
  console.error('Commands:');
  console.error('  create <input_file> <output_tdf> [kas_url]  Create a TDF file');
  console.error('  read <tdf_file>                             Read a TDF file');
  console.error('  test-abac                                   Run ABAC tests');
  process.exit(1);
}

// Export functions if being used as a module
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    initialize,
    callTool,
    createTdf,
    readTdf
  };
}