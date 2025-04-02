#!/usr/bin/env node

/**
 * Claude-compatible MCP Client for OpenTDF
 * 
 * This script demonstrates how to use the OpenTDF MCP server with Claude.
 * It implements the Claude MCP protocol format for interacting with the tools.
 */

const { spawn } = require('child_process');
const readline = require('readline');
const fs = require('fs');

// Start the MCP server
console.log('Starting OpenTDF MCP Server...');
const mcpServer = spawn('cargo', ['run', '-p', 'opentdf-mcp-server'], {
  stdio: ['pipe', 'pipe', 'inherit'] // pipe stdin/stdout, inherit stderr
});

// Create readline interface for stdin
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// Set up JSON-RPC handling
let messageId = 1;
const pendingRequests = new Map();

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
      
      // Reset buffer after successful parse
      jsonBuffer = '';
      
      // Handle server/ready notification
      if (response.method === 'server/ready') {
        console.log('Server is ready. Initializing...');
        initializeServer();
        return;
      }
      
      // Process response for tracked requests
      if (response.id && pendingRequests.has(response.id)) {
        const { resolve, reject } = pendingRequests.get(response.id);
        pendingRequests.delete(response.id);
        
        if (response.error) {
          reject(new Error(response.error.message));
        } else {
          resolve(response.result);
        }
      }
    } catch (e) {
      // JSON is incomplete, continue collecting
      // This is normal if the response is split across multiple chunks
    }
  }
});

// Send JSON-RPC request
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
    mcpServer.stdin.write(JSON.stringify(request) + "\n");
    
    // Set timeout for request - allow 'initialized' to just time out since it's optional
    setTimeout(() => {
      if (pendingRequests.has(id)) {
        pendingRequests.delete(id);
        if (method === 'initialized') {
          // Just resolve for 'initialized' since we don't really need a response
          resolve({});
        } else {
          reject(new Error(`Request timed out: ${method}`));
        }
      }
    }, 5000);
  });
}

// Initialize the server
async function initializeServer() {
  try {
    // Initialize the server
    const initResult = await sendRequest('initialize');
    console.log('Server initialized successfully');
    
    // Send initialized signal
    await sendRequest('initialized');
    console.log('Server acknowledged initialized signal');
    
    // Start the interactive prompt
    startPrompt();
  } catch (error) {
    console.error(`Failed to initialize server: ${error.message}`);
    process.exit(1);
  }
}

// Call a tool using the Claude MCP format
async function callTool(toolName, parameters) {
  try {
    // Format the request according to Claude's MCP protocol
    const result = await sendRequest('tools/call', {
      name: toolName,
      parameters
    });
    
    console.log(`\nTool Result (${toolName}):`);
    console.log(JSON.stringify(result, null, 2));
    return result;
  } catch (error) {
    console.error(`Error calling tool ${toolName}: ${error.message}`);
    return null;
  }
}

// Start interactive prompt
function startPrompt() {
  console.log('\n=== OpenTDF MCP Client ===');
  console.log('Available commands:');
  console.log('  tdf-create <data> - Create a TDF with sample data');
  console.log('  tdf-read <file-path> - Read a TDF file');
  console.log('  define-attr - Define sample hierarchical attributes');
  console.log('  list-attr - List all defined attributes');
  console.log('  user-attr - Set user attributes');
  console.log('  create-policy - Create a sample policy');
  console.log('  evaluate-access - Test access evaluation');
  console.log('  exit - Exit the client');
  console.log('\nEnter a command:');
  
  rl.on('line', async (line) => {
    const command = line.trim().split(' ')[0];
    
    try {
      switch (command) {
        case 'tdf-create': {
          const data = line.trim().split(' ')[1] || 'SGVsbG8gV29ybGQh'; // Default: "Hello World!"
          console.log(`Creating TDF with data: ${data}`);
          
          // Create a sample policy
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
          
          await callTool('mcp__opentdf__tdf_create', {
            data: data,
            kas_url: "https://kas.example.com",
            policy: policy
          });
          break;
        }
        
        case 'tdf-read': {
          const filePath = line.trim().split(' ')[1];
          if (!filePath) {
            console.log('Please provide a file path: tdf-read <file-path>');
            break;
          }
          
          try {
            const fileData = fs.readFileSync(filePath);
            const base64Data = fileData.toString('base64');
            
            await callTool('mcp__opentdf__tdf_read', {
              tdf_data: base64Data
            });
          } catch (err) {
            console.error(`Error reading file: ${err.message}`);
          }
          break;
        }
        
        case 'define-attr':
          // Define clearance levels with hierarchy
          await callTool('attribute_define', {
            namespace: 'gov.example',
            name: 'clearance',
            values: ['public', 'confidential', 'secret', 'top-secret'],
            hierarchy: [
              { value: 'top-secret', inherits_from: 'secret' },
              { value: 'secret', inherits_from: 'confidential' },
              { value: 'confidential', inherits_from: 'public' }
            ]
          });
          break;

        case 'list-attr':
          // List all defined attributes
          await callTool('mcp__opentdf__attribute_list', {});
          break;
          
        case 'user-attr':
          // Define a user with attributes
          await callTool('user_attributes', {
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
          break;
          
        case 'create-policy':
          // Create a policy
          await callTool('policy_create', {
            attributes: [
              {
                attribute: 'gov.example:clearance',
                operator: 'MinimumOf',
                value: 'secret'
              }
            ],
            dissemination: ['user@example.com'],
            valid_from: new Date().toISOString(),
            valid_to: new Date(Date.now() + 86400000).toISOString() // 24 hours from now
          });
          break;
          
        case 'evaluate-access':
          // Create a policy first
          const policyResult = await callTool('policy_create', {
            attributes: [
              {
                attribute: 'gov.example:clearance',
                operator: 'MinimumOf',
                value: 'secret'
              }
            ],
            dissemination: ['user@example.com'],
            valid_from: new Date().toISOString(),
            valid_to: new Date(Date.now() + 86400000).toISOString()
          });
          
          if (policyResult && policyResult.policy) {
            // Evaluate access for a user with top-secret clearance
            await callTool('access_evaluate', {
              policy: policyResult.policy,
              user_attributes: {
                user_id: 'alice@example.com',
                attributes: [
                  { attribute: 'gov.example:clearance', value: 'top-secret' }
                ]
              }
            });
          }
          break;
          
        case 'exit':
          console.log('Exiting...');
          mcpServer.kill();
          process.exit(0);
          break;
          
        default:
          console.log(`Unknown command: ${command}`);
          break;
      }
    } catch (error) {
      console.error(`Error executing command: ${error.message}`);
    }
    
    console.log('\nEnter a command:');
  });
}

// Handle process exit
process.on('exit', () => {
  if (mcpServer && !mcpServer.killed) {
    mcpServer.kill();
  }
});

process.on('SIGINT', () => {
  console.log('\nInterrupted, cleaning up...');
  mcpServer.kill();
  process.exit();
});

// Wait for server to signal it's ready
// The server will output server/ready notification
console.log('Waiting for server to start...');