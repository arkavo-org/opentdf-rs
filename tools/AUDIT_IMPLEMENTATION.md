# Attribute-Based Access Control Audit Logging Implementation

This document details how the comprehensive attribute access logging requirements have been implemented in the OpenTDF-RS project.

## Requirements Implementation Status

| Requirement | Implemented | Location |
|-------------|-------------|----------|
| Entity ID recording | ✅ | `audit-logging-test.js` |
| Complete attribute set logging | ✅ | `audit-logging-test.js` |
| Attribute source and verification status | ✅ | `audit-logging-test.js` |
| Attribute evaluation results | ✅ | `audit-logging-test.js` |
| Access decision with timestamp | ✅ | `audit-logging-test.js` |
| Policy version information | ✅ | `audit-logging-test.js` |
| Compliance reporting | ✅ | `audit-logging-test.js` |

## Implementation Details

### 1. Entity Identifier Recording

Each access attempt is logged with the user ID of the requesting entity:

```json
{
  "userId": "alice@example.com",
  "documentId": "doc-uuid-123",
  "timestamp": "2023-04-01T12:34:56.789Z"
}
```

### 2. Complete Attribute Set Logging

All attributes presented during access attempts are recorded:

```json
{
  "attributes": [
    { "name": "gov.example:clearance", "value": "top-secret" },
    { "name": "gov.example:department", "value": "executive" },
    { "name": "gov.example:region", "value": "usa" },
    { "name": "env.example:network", "value": "classified" }
  ]
}
```

### 3. Attribute Source and Verification Status

The source of each attribute and its verification status are recorded:

```json
{
  "attributes": [
    { 
      "name": "gov.example:clearance", 
      "value": "top-secret", 
      "source": "identity-provider", 
      "verified": true 
    }
  ]
}
```

### 4. Attribute Evaluation Results

Detailed results for each attribute evaluation are logged:

```json
{
  "evaluationResults": [
    { 
      "attribute": "gov.example:clearance", 
      "required": "confidential", 
      "provided": "top-secret",
      "operator": "MinimumOf",
      "satisfied": true,
      "reason": "Hierarchical attribute satisfied via inheritance (top-secret > confidential)"
    },
    // Additional evaluation results...
  ]
}
```

### 5. Access Decision with Timestamp

Final access decisions and timestamps are recorded:

```json
{
  "accessGranted": true,
  "timestamp": "2023-04-01T12:34:56.789Z"
}
```

### 6. Policy Version Information

Policy version information is captured in the audit log:

```json
{
  "policyId": "policy-uuid-456",
  "policyVersion": "1.0"
}
```

### 7. Compliance Reporting

A comprehensive reporting system generates different reports from audit logs:

1. Access Attempts Report
2. Attribute Verification Report
3. Policy Evaluation Report
4. Comprehensive Report

Each report contains detailed information needed for compliance verification.

## Audit Log Record Types

The following record types are implemented:

1. `attributeVerification` - Records when user attributes are verified
2. `accessAttempt` - Records attempts to access protected content
3. `policyEvaluation` - Records the detailed evaluation of policies
4. `policyBindingVerification` - Records verification of policy bindings
5. `documentProtection` - Records when documents are protected with policies

## Testing

The `audit-logging-test.js` script provides comprehensive testing of the audit logging system:

```bash
node tools/audit-logging-test.js
```

This script:
1. Creates test users with different attribute combinations
2. Defines policies with various attribute conditions
3. Creates protected TDF documents
4. Tests access scenarios with different attributes
5. Generates detailed audit logs
6. Creates compliance reports in different formats

Reports are generated in the `tools/reports` directory for review.

## Compliance Reporting

The system supports generating compliance reports in different formats:

```javascript
// Generate access attempt report
const accessReport = await generateComplianceReport('accessAttempts', {
  timeRange: '24h',
  includeSuccessful: true,
  includeDenied: true
});

// Generate attribute verification report
const attributeReport = await generateComplianceReport('attributeVerification', {
  showSources: true
});

// Generate policy evaluation report
const policyReport = await generateComplianceReport('policyEvaluation', {
  documentId: tdf1Result.id,
  showAllConditions: true
});

// Generate comprehensive report
const comprehensiveReport = await generateComplianceReport('comprehensive', {
  fullDetails: true,
  includeMetadata: true
});
```

## Documentation

A comprehensive guide to the audit logging system is provided in `audit-guide.md`.

## Future Work

Potential future enhancements to the audit logging system:

1. Integration with SIEM systems
2. Real-time alerting for suspicious access patterns
3. Enhanced filtering and search capabilities for audit logs
4. Cryptographic proof of log integrity (hash chains)
5. Compliance reporting templates for specific regulations (GDPR, HIPAA, etc.)