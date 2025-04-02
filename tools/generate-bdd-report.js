#!/usr/bin/env node

/**
 * Generates a formatted HTML report from Cucumber.js JSON output
 * This enhances the default Cucumber report with additional info about ABAC testing
 */

const fs = require('fs');
const path = require('path');

// Create output directory
const reportDir = path.join(process.cwd(), 'bdd-test-report');
if (!fs.existsSync(reportDir)) {
  fs.mkdirSync(reportDir);
}

// Read the Cucumber JSON report
let rawData;
try {
  rawData = fs.readFileSync('cucumber-report.json', 'utf8');
} catch (e) {
  console.error('Could not read cucumber-report.json:', e.message);
  process.exit(1);
}

// Parse the JSON report
let report;
try {
  report = JSON.parse(rawData);
} catch (e) {
  console.error('Error parsing JSON report:', e.message);
  process.exit(1);
}

// Generate summary statistics
const stats = {
  total: 0,
  passed: 0,
  failed: 0,
  skipped: 0,
  abacFeatures: 0,
  abacScenarios: 0,
  mcpRequests: 0,
};

// Process features
report.forEach(feature => {
  if (feature.name.toLowerCase().includes('abac') || 
      feature.description.toLowerCase().includes('attribute-based access control')) {
    stats.abacFeatures++;
  }
  
  feature.elements.forEach(scenario => {
    stats.total++;
    
    if (scenario.name.toLowerCase().includes('abac') || 
        scenario.description.toLowerCase().includes('attribute')) {
      stats.abacScenarios++;
    }
    
    let scenarioStatus = 'passed';
    
    scenario.steps.forEach(step => {
      if (step.name.toLowerCase().includes('mcp') || 
          step.name.toLowerCase().includes('opentdf')) {
        stats.mcpRequests++;
      }
      
      if (step.result.status === 'failed') {
        scenarioStatus = 'failed';
      } else if (step.result.status === 'skipped' && scenarioStatus !== 'failed') {
        scenarioStatus = 'skipped';
      }
    });
    
    // Increment the appropriate counter based on scenario status
    stats[scenarioStatus]++;
  });
});

// Generate HTML report
const htmlReport = `
<!DOCTYPE html>
<html>
<head>
  <title>OpenTDF ABAC BDD Test Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }
    h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
    .summary { background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
    .stats { display: flex; flex-wrap: wrap; gap: 20px; margin-top: 20px; }
    .stat-box { 
      min-width: 150px; 
      padding: 15px; 
      border-radius: 5px; 
      box-shadow: 0 2px 5px rgba(0,0,0,0.1);
      text-align: center;
    }
    .total { background-color: #3498db; color: white; }
    .passed { background-color: #2ecc71; color: white; }
    .failed { background-color: #e74c3c; color: white; }
    .skipped { background-color: #f39c12; color: white; }
    .info { background-color: #9b59b6; color: white; }
    .number { font-size: 24px; font-weight: bold; margin-bottom: 5px; }
    .label { font-size: 14px; }
    .progress-container { 
      height: 20px; 
      background-color: #ecf0f1; 
      border-radius: 10px; 
      margin: 20px 0; 
    }
    .progress-bar { 
      height: 100%; 
      background-color: #2ecc71; 
      border-radius: 10px; 
      text-align: right; 
      color: white; 
      font-weight: bold; 
      padding-right: 10px; 
    }
    .notes { 
      background-color: #f8f9fa; 
      padding: 15px; 
      border-left: 4px solid #3498db; 
      margin-top: 20px; 
    }
  </style>
</head>
<body>
  <h1>OpenTDF ABAC BDD Test Report</h1>
  
  <div class="summary">
    <h2>Test Summary</h2>
    <div class="progress-container">
      <div class="progress-bar" style="width: ${Math.round((stats.passed / stats.total) * 100)}%; background-color: ${stats.failed > 0 ? '#e74c3c' : '#2ecc71'}">
        ${Math.round((stats.passed / stats.total) * 100)}%
      </div>
    </div>
    
    <div class="stats">
      <div class="stat-box total">
        <div class="number">${stats.total}</div>
        <div class="label">Total Scenarios</div>
      </div>
      <div class="stat-box passed">
        <div class="number">${stats.passed}</div>
        <div class="label">Passed</div>
      </div>
      <div class="stat-box failed">
        <div class="number">${stats.failed}</div>
        <div class="label">Failed</div>
      </div>
      <div class="stat-box skipped">
        <div class="number">${stats.skipped}</div>
        <div class="label">Skipped</div>
      </div>
    </div>
    
    <h2>ABAC Testing Metrics</h2>
    <div class="stats">
      <div class="stat-box info">
        <div class="number">${stats.abacFeatures}</div>
        <div class="label">ABAC Features</div>
      </div>
      <div class="stat-box info">
        <div class="number">${stats.abacScenarios}</div>
        <div class="label">ABAC Scenarios</div>
      </div>
      <div class="stat-box info">
        <div class="number">${stats.mcpRequests}</div>
        <div class="label">MCP Requests</div>
      </div>
    </div>
  </div>
  
  <div class="notes">
    <h3>Notes</h3>
    <p>This report was generated automatically as part of the BDD LLM MCP Test Suite workflow.</p>
    <p>For detailed test results, please refer to the Cucumber HTML report.</p>
    <p>Generated: ${new Date().toISOString()}</p>
  </div>
</body>
</html>
`;

// Write the HTML report
fs.writeFileSync(path.join(reportDir, 'index.html'), htmlReport);

// Create a simple text summary
const textSummary = `
OpenTDF ABAC BDD Test Summary
-----------------------------
Total scenarios: ${stats.total}
Passed: ${stats.passed}
Failed: ${stats.failed}
Skipped: ${stats.skipped}

ABAC features: ${stats.abacFeatures}
ABAC scenarios: ${stats.abacScenarios}
MCP requests: ${stats.mcpRequests}

Pass percentage: ${Math.round((stats.passed / stats.total) * 100)}%
`;

// Write the text summary
fs.writeFileSync(path.join(reportDir, 'summary.txt'), textSummary);

console.log('BDD test report generated successfully');