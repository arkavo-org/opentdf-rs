#!/bin/bash

# Script to run ABAC evaluation tests against the MCP server

echo "Starting MCP server in the background..."
cargo run --manifest-path=../crates/mcp-server/Cargo.toml > mcp-server.log 2>&1 &
MCP_PID=$!

# Give the server a moment to start
sleep 2

echo "Running ABAC evaluation tests..."
node test-scripts/test-abac-mcp.js

# Kill the MCP server when done
echo "Stopping MCP server (PID: $MCP_PID)..."
kill $MCP_PID

echo "Test complete!"