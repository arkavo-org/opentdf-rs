use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::ops::Not;
use thiserror::Error;
use time::{Duration, OffsetDateTime};

/// Attribute-Based Access Control Policy Error
/// Validation error with structured information
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub field: String,
    pub error_type: ValidationErrorType,
    pub message: String,
    pub suggestion: Option<String>,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)?;
        if let Some(suggestion) = &self.suggestion {
            write!(f, " (suggestion: {})", suggestion)?;
        }
        Ok(())
    }
}

/// Types of validation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationErrorType {
    Required,
    InvalidFormat,
    OutOfRange,
    FqnParseError,
    NamespaceNotRegistered,
    InvalidUuid,
    EmptyList,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Invalid attribute: {fqn} - {reason}")]
    InvalidAttribute { fqn: String, reason: String },

    #[error("Invalid operator '{operator}' in context: {context}")]
    InvalidOperator { operator: String, context: String },

    #[error("Invalid value type for attribute '{attribute}': expected {expected}, got {actual}")]
    InvalidValueType {
        attribute: String,
        expected: String,
        actual: String,
    },

    #[error("Policy evaluation error: {reason}")]
    EvaluationError {
        reason: String,
        attribute: Option<String>,
    },

    #[error("Policy validation failed with {} error(s)", .0.len())]
    ValidationFailed(Vec<ValidationError>),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("FQN parse error: {0}")]
    FqnError(#[from] FqnError),
}

/// FQN (Fully Qualified Name) parsing and validation errors
#[derive(Debug, Error, Clone)]
pub enum FqnError {
    #[error("Invalid URL scheme: expected '{expected}', found '{found}'")]
    InvalidScheme {
        expected: &'static str,
        found: String,
    },

    #[error("URL must use HTTPS scheme: {url}")]
    NotHttps { url: String },

    #[error("FQN missing required /attr/ structure: {url}")]
    MissingAttrStructure { url: String },

    #[error("Invalid namespace '{namespace}': {reason}")]
    InvalidNamespace { namespace: String, reason: String },

    #[error("Namespace not registered: {namespace}")]
    NamespaceNotRegistered { namespace: String },

    #[error("Malformed URL: {0}")]
    MalformedUrl(String),

    #[error("Missing required component: {component}")]
    MissingComponent { component: &'static str },
}

impl FqnError {
    /// Returns the error kind for programmatic handling
    pub fn kind(&self) -> FqnErrorKind {
        match self {
            FqnError::InvalidScheme { .. } => FqnErrorKind::InvalidScheme,
            FqnError::NotHttps { .. } => FqnErrorKind::NotHttps,
            FqnError::MissingAttrStructure { .. } => FqnErrorKind::MissingAttrStructure,
            FqnError::InvalidNamespace { .. } => FqnErrorKind::InvalidNamespace,
            FqnError::NamespaceNotRegistered { .. } => FqnErrorKind::NamespaceNotRegistered,
            FqnError::MalformedUrl(_) => FqnErrorKind::MalformedUrl,
            FqnError::MissingComponent { .. } => FqnErrorKind::MissingComponent,
        }
    }

    /// Returns a hint for how to fix this error
    pub fn hint(&self) -> &'static str {
        match self {
            FqnError::InvalidScheme { expected, .. } => {
                if *expected == "https" {
                    "Use HTTPS scheme: https://example.com/attr/name/value/val"
                } else {
                    "Use correct URL scheme"
                }
            }
            FqnError::NotHttps { .. } => {
                "FQNs must use HTTPS for security. Example: https://example.com/attr/name/value/val"
            }
            FqnError::MissingAttrStructure { .. } => {
                "FQN must follow format: https://<namespace>/attr/<name>/value/<value>"
            }
            FqnError::InvalidNamespace { .. } => {
                "Namespace must be a valid domain-like identifier (lowercase, no special chars)"
            }
            FqnError::NamespaceNotRegistered { .. } => {
                "Register the namespace using NamespaceRegistry::register() before use"
            }
            FqnError::MalformedUrl(_) => "Ensure URL is properly formatted with scheme://host/path",
            FqnError::MissingComponent { component } => match *component {
                "namespace" => "Provide a namespace: https://namespace.com/...",
                "name" => "Provide an attribute name: .../attr/name/...",
                _ => "Ensure all required FQN components are present",
            },
        }
    }

    /// Returns a stable error code
    pub fn error_code(&self) -> &'static str {
        match self {
            FqnError::InvalidScheme { .. } => "OPENTDF_E_FQN_SCHEME_INVALID",
            FqnError::NotHttps { .. } => "OPENTDF_E_FQN_NOT_HTTPS",
            FqnError::MissingAttrStructure { .. } => "OPENTDF_E_FQN_STRUCTURE",
            FqnError::InvalidNamespace { .. } => "OPENTDF_E_FQN_NAMESPACE_INVALID",
            FqnError::NamespaceNotRegistered { .. } => "OPENTDF_E_FQN_NAMESPACE_UNREGISTERED",
            FqnError::MalformedUrl(_) => "OPENTDF_E_FQN_MALFORMED",
            FqnError::MissingComponent { .. } => "OPENTDF_E_FQN_COMPONENT_MISSING",
        }
    }
}

/// Error kind for programmatic FQN error handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FqnErrorKind {
    InvalidScheme,
    NotHttps,
    MissingAttrStructure,
    InvalidNamespace,
    NamespaceNotRegistered,
    MalformedUrl,
    MissingComponent,
}

impl PolicyError {
    /// Returns true if this error might be resolved by retrying with different input
    pub fn is_retryable(&self) -> bool {
        matches!(self, PolicyError::SerializationError(_))
    }

    /// Returns a suggestion for how to fix this error, if available
    pub fn suggestion(&self) -> Option<&str> {
        match self {
            PolicyError::InvalidAttribute { .. } => {
                Some("Use AttributeFqn::parse() to validate FQN format")
            }
            PolicyError::ValidationFailed(errors) if !errors.is_empty() => {
                errors[0].suggestion.as_deref()
            }
            PolicyError::FqnError(FqnError::NotHttps { .. }) => Some(
                "Use HTTPS URLs for attribute FQNs (e.g., https://example.com/attr/name/value/val)",
            ),
            PolicyError::FqnError(FqnError::MissingAttrStructure { .. }) => {
                Some("FQN must follow format: https://<namespace>/attr/<name>/value/<value>")
            }
            _ => None,
        }
    }

    /// Returns a stable error code for programmatic error handling
    ///
    /// Error codes follow the format: `OPENTDF_E_<CATEGORY>_<SPECIFIC>`
    /// These codes are stable across versions and safe for cross-language bindings.
    pub fn error_code(&self) -> &'static str {
        match self {
            PolicyError::InvalidAttribute { .. } => "OPENTDF_E_POLICY_ATTRIBUTE_INVALID",
            PolicyError::InvalidOperator { .. } => "OPENTDF_E_POLICY_OPERATOR_INVALID",
            PolicyError::InvalidValueType { .. } => "OPENTDF_E_POLICY_VALUE_TYPE",
            PolicyError::EvaluationError { .. } => "OPENTDF_E_POLICY_EVALUATION",
            PolicyError::ValidationFailed(_) => "OPENTDF_E_POLICY_VALIDATION",
            PolicyError::SerializationError(_) => "OPENTDF_E_POLICY_SERIALIZATION",
            PolicyError::FqnError(_) => "OPENTDF_E_FQN",
        }
    }
}

/// Attribute namespace and name
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AttributeIdentifier {
    pub namespace: String,
    pub name: String,
}

impl AttributeIdentifier {
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
        }
    }

    /// Parse an attribute identifier from a string in the format "namespace:name"
    pub fn from_string(s: &str) -> Result<Self, PolicyError> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            return Err(PolicyError::InvalidAttribute {
                fqn: s.to_string(),
                reason: "Attribute must be in format 'namespace:name' with non-empty components"
                    .to_string(),
            });
        }
        Ok(Self::new(parts[0], parts[1]))
    }

    /// Utility function to get the string representation
    pub fn as_string(&self) -> String {
        format!("{}:{}", self.namespace, self.name)
    }
}

impl fmt::Display for AttributeIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.namespace, self.name)
    }
}

/// Supported attribute value types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttributeValue {
    /// String value — declared before `DateTime` so JSON strings (including
    /// ISO-8601 formatted strings) remain `String` for string operators and WASM callers.
    String(String),
    Number(f64),
    Boolean(bool),
    #[serde(with = "time::serde::rfc3339")]
    DateTime(OffsetDateTime),
    StringArray(Vec<String>),
    NumberArray(Vec<f64>),
}

impl AttributeValue {
    pub fn as_string(&self) -> Option<&str> {
        match self {
            AttributeValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_number(&self) -> Option<f64> {
        match self {
            AttributeValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_boolean(&self) -> Option<bool> {
        match self {
            AttributeValue::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_datetime(&self) -> Option<&OffsetDateTime> {
        match self {
            AttributeValue::DateTime(dt) => Some(dt),
            _ => None,
        }
    }

    pub fn as_string_array(&self) -> Option<&[String]> {
        match self {
            AttributeValue::StringArray(arr) => Some(arr),
            _ => None,
        }
    }

    pub fn as_number_array(&self) -> Option<&[f64]> {
        match self {
            AttributeValue::NumberArray(arr) => Some(arr),
            _ => None,
        }
    }
}

/// Comparison operators for attribute values
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Operator {
    Equals,
    NotEquals,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    Contains,
    In,
    AllOf,
    AnyOf,
    NotIn,
    MinimumOf,  // For hierarchical values
    MaximumOf,  // For hierarchical values
    Present,    // Attribute exists
    NotPresent, // Attribute does not exist
}

/// A condition that must be satisfied for access
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttributeCondition {
    pub attribute: AttributeIdentifier,
    pub operator: Operator,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<AttributeValue>,
}

impl AttributeCondition {
    pub fn new(
        attribute: AttributeIdentifier,
        operator: Operator,
        value: Option<AttributeValue>,
    ) -> Self {
        Self {
            attribute,
            operator,
            value,
        }
    }

    /// Create a condition requiring an attribute to be present
    pub fn present(attribute: AttributeIdentifier) -> Self {
        Self::new(attribute, Operator::Present, None)
    }

    /// Create a condition requiring an attribute to be equal to a value
    pub fn equals(attribute: AttributeIdentifier, value: AttributeValue) -> Self {
        Self::new(attribute, Operator::Equals, Some(value))
    }
}

/// Logical operators for combining conditions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE", tag = "type")]
pub enum LogicalOperator {
    AND { conditions: Vec<AttributePolicy> },
    OR { conditions: Vec<AttributePolicy> },
    NOT { condition: Box<AttributePolicy> },
}

/// A policy that can be evaluated against a set of attributes
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttributePolicy {
    Condition(AttributeCondition),
    Logical(LogicalOperator),
}

impl AttributePolicy {
    /// Create a simple condition policy
    pub fn condition(
        attribute: AttributeIdentifier,
        operator: Operator,
        value: AttributeValue,
    ) -> Self {
        AttributePolicy::Condition(AttributeCondition::new(attribute, operator, Some(value)))
    }

    /// Combine multiple policies with AND
    pub fn and(conditions: Vec<AttributePolicy>) -> Self {
        AttributePolicy::Logical(LogicalOperator::AND { conditions })
    }

    /// Combine multiple policies with OR
    pub fn or(conditions: Vec<AttributePolicy>) -> Self {
        AttributePolicy::Logical(LogicalOperator::OR { conditions })
    }

    /// Factory method to create a NOT condition
    pub fn create_not(condition: AttributePolicy) -> Self {
        AttributePolicy::Logical(LogicalOperator::NOT {
            condition: Box::new(condition),
        })
    }
}

impl Not for AttributePolicy {
    type Output = Self;

    fn not(self) -> Self::Output {
        AttributePolicy::Logical(LogicalOperator::NOT {
            condition: Box::new(self),
        })
    }
}

impl AttributePolicy {
    /// Evaluate the policy against a set of attributes
    ///
    /// This implementation provides two evaluation methods:
    /// 1. Recursive: Simple for shallow policies but may cause stack overflow with deep nesting
    /// 2. Iterative: Handles arbitrarily deep policy nesting without stack overflow risk
    pub fn evaluate(
        &self,
        attributes: &HashMap<AttributeIdentifier, AttributeValue>,
    ) -> Result<bool, PolicyError> {
        // For deeply nested policies, use iterative evaluation to avoid stack overflow
        if self.depth() > 50 {
            self.evaluate_iterative(attributes)
        } else {
            self.evaluate_recursive(attributes)
        }
    }

    /// Measure the maximum nesting depth of a policy iteratively (safe for arbitrary depth)
    pub fn depth(&self) -> usize {
        let mut max_depth = 0usize;
        let mut stack = vec![(self, 1usize)];
        while let Some((node, d)) = stack.pop() {
            if d > max_depth {
                max_depth = d;
            }
            if let AttributePolicy::Logical(operator) = node {
                match operator {
                    LogicalOperator::AND { conditions } | LogicalOperator::OR { conditions } => {
                        for child in conditions {
                            stack.push((child, d + 1));
                        }
                    }
                    LogicalOperator::NOT { condition } => {
                        stack.push((condition, d + 1));
                    }
                }
            }
        }
        max_depth
    }

    /// Recursive evaluation method - simple but may cause stack overflow with deep nesting
    fn evaluate_recursive(
        &self,
        attributes: &HashMap<AttributeIdentifier, AttributeValue>,
    ) -> Result<bool, PolicyError> {
        match self {
            AttributePolicy::Condition(condition) => evaluate_condition(condition, attributes),
            AttributePolicy::Logical(operator) => match operator {
                LogicalOperator::AND { conditions } => {
                    for condition in conditions {
                        if !condition.evaluate_recursive(attributes)? {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                }
                LogicalOperator::OR { conditions } => {
                    for condition in conditions {
                        if condition.evaluate_recursive(attributes)? {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                }
                LogicalOperator::NOT { condition } => {
                    Ok(!condition.evaluate_recursive(attributes)?)
                }
            },
        }
    }

    /// Iterative evaluation method - safely handles arbitrarily deep nested policies
    /// using a stack-based approach instead of recursion
    fn evaluate_iterative(
        &self,
        attributes: &HashMap<AttributeIdentifier, AttributeValue>,
    ) -> Result<bool, PolicyError> {
        // Define evaluation task type for stack
        enum EvalTask<'a> {
            Evaluate(&'a AttributePolicy),
            EvaluateAnd(&'a [AttributePolicy], usize), // conditions, next index
            EvaluateOr(&'a [AttributePolicy], usize),  // conditions, next index
            ApplyNot,
        }

        // Result stack and task stack
        let mut results = Vec::new();
        let mut tasks = vec![EvalTask::Evaluate(self)];

        // Process tasks until done
        while let Some(task) = tasks.pop() {
            match task {
                EvalTask::Evaluate(policy) => match policy {
                    AttributePolicy::Condition(condition) => {
                        let result = evaluate_condition(condition, attributes)?;
                        results.push(result);
                    }
                    AttributePolicy::Logical(LogicalOperator::AND { conditions }) => {
                        if conditions.is_empty() {
                            results.push(true); // Empty AND is true (identity)
                        } else {
                            tasks.push(EvalTask::EvaluateAnd(conditions, 0));
                        }
                    }
                    AttributePolicy::Logical(LogicalOperator::OR { conditions }) => {
                        if conditions.is_empty() {
                            results.push(false); // Empty OR is false (identity)
                        } else {
                            tasks.push(EvalTask::EvaluateOr(conditions, 0));
                        }
                    }
                    AttributePolicy::Logical(LogicalOperator::NOT { condition }) => {
                        tasks.push(EvalTask::ApplyNot);
                        tasks.push(EvalTask::Evaluate(condition));
                    }
                },
                EvalTask::EvaluateAnd(conditions, idx) => {
                    if idx == 0 {
                        // First condition - start with true
                        results.push(true);
                    }

                    // Get current accumulated result
                    let current_result = *results.last().unwrap();

                    if !current_result {
                        // Short-circuit: if any previous condition was false, we're done
                        continue;
                    }

                    if idx < conditions.len() {
                        // Push continuation of AND evaluation after this condition
                        tasks.push(EvalTask::EvaluateAnd(conditions, idx + 1));

                        // Push this condition for evaluation
                        tasks.push(EvalTask::Evaluate(&conditions[idx]));

                        // Remove the accumulated result (will be rebuilt with next condition)
                        results.pop();
                    }
                }
                EvalTask::EvaluateOr(conditions, idx) => {
                    if idx == 0 {
                        // First condition - start with false
                        results.push(false);
                    }

                    // Get current accumulated result
                    let current_result = *results.last().unwrap();

                    if current_result {
                        // Short-circuit: if any previous condition was true, we're done
                        continue;
                    }

                    if idx < conditions.len() {
                        // Push continuation of OR evaluation after this condition
                        tasks.push(EvalTask::EvaluateOr(conditions, idx + 1));

                        // Push this condition for evaluation
                        tasks.push(EvalTask::Evaluate(&conditions[idx]));

                        // Remove the accumulated result (will be rebuilt with next condition)
                        results.pop();
                    }
                }
                EvalTask::ApplyNot => {
                    // Get the result to negate
                    let result = results.pop().unwrap();
                    results.push(!result);
                }
            }
        }

        // Final result should be on the stack
        if results.len() != 1 {
            return Err(PolicyError::EvaluationError {
                reason: "Invalid policy evaluation state".to_string(),
                attribute: None,
            });
        }

        Ok(results[0])
    }
}

/// Root policy that includes metadata and effective dates
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    pub uuid: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub valid_from: Option<OffsetDateTime>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub valid_to: Option<OffsetDateTime>,
    pub body: PolicyBody,
}

/// Policy body containing attribute requirements and dissemination list
///
/// Note: To match Go SDK behavior, empty arrays serialize as null instead of []
/// This is critical for policy binding HMAC calculation compatibility
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyBody {
    #[serde(
        rename = "dataAttributes",
        alias = "attributes",
        default,
        serialize_with = "serialize_empty_vec_as_null",
        deserialize_with = "deserialize_null_as_empty_vec"
    )]
    pub attributes: Vec<AttributePolicy>,
    #[serde(
        default,
        serialize_with = "serialize_empty_vec_as_null",
        deserialize_with = "deserialize_null_as_empty_vec"
    )]
    pub dissem: Vec<String>, // Entities authorized to access
}

/// Serialize empty Vec as null to match Go SDK behavior
/// This ensures policy binding HMAC compatibility across implementations
fn serialize_empty_vec_as_null<T, S>(vec: &Vec<T>, serializer: S) -> Result<S::Ok, S::Error>
where
    T: serde::Serialize,
    S: serde::Serializer,
{
    if vec.is_empty() {
        serializer.serialize_none()
    } else {
        vec.serialize(serializer)
    }
}

/// Deserialize null as empty Vec for compatibility with Go SDK
fn deserialize_null_as_empty_vec<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    T: serde::Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    let opt = Option::<Vec<T>>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

impl Policy {
    /// Create a new policy with a UUID and no time constraints
    pub fn new(uuid: String, attributes: Vec<AttributePolicy>, dissem: Vec<String>) -> Self {
        Self {
            uuid,
            valid_from: None,
            valid_to: None,
            body: PolicyBody { attributes, dissem },
        }
    }

    /// Set the validity time window for the policy
    pub fn with_time_window(
        mut self,
        valid_from: Option<OffsetDateTime>,
        valid_to: Option<OffsetDateTime>,
    ) -> Self {
        self.valid_from = valid_from;
        self.valid_to = valid_to;
        self
    }

    /// Convert the policy to a JSON string
    pub fn to_json(&self) -> Result<String, PolicyError> {
        serde_json::to_string(self).map_err(PolicyError::from)
    }

    /// Parse a JSON string into a Policy
    pub fn from_json(json: &str) -> Result<Self, PolicyError> {
        serde_json::from_str(json).map_err(PolicyError::from)
    }

    /// Check if the policy is currently valid based on its time window
    pub fn is_valid_at(&self, time: OffsetDateTime) -> bool {
        let after_start = self.valid_from.is_none_or(|from| time >= from);
        let before_end = self.valid_to.is_none_or(|to| time <= to);
        after_start && before_end
    }

    /// Validate the policy structure and return all errors found
    ///
    /// This performs comprehensive validation including:
    /// - UUID format validation
    /// - Time window consistency (valid_from < valid_to)
    /// - Attribute policy structure validation
    /// - Dissemination list validation
    ///
    /// # Example
    ///
    /// ```rust
    /// use opentdf::prelude::*;
    ///
    /// let policy = PolicyBuilder::new()
    ///     .id_auto()
    ///     .dissemination(["user@example.com"])
    ///     .attribute_fqn("https://example.com/attr/clearance/value/secret")?
    ///     .build()?;
    ///
    /// // Validate the policy
    /// policy.validate()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn validate(&self) -> Result<(), PolicyError> {
        let mut errors = Vec::new();

        // Validate UUID format
        if let Err(e) = uuid::Uuid::parse_str(&self.uuid) {
            errors.push(ValidationError {
                field: "uuid".to_string(),
                error_type: ValidationErrorType::InvalidFormat,
                message: format!("Invalid UUID format: {}", e),
                suggestion: Some(
                    "Use PolicyBuilder::id_auto() to generate a valid UUID".to_string(),
                ),
            });
        }

        // Validate time window
        if let (Some(from), Some(to)) = (self.valid_from, self.valid_to)
            && from >= to
        {
            errors.push(ValidationError {
                field: "time_window".to_string(),
                error_type: ValidationErrorType::OutOfRange,
                message: format!("valid_from ({}) must be before valid_to ({})", from, to),
                suggestion: Some("Ensure valid_from is earlier than valid_to".to_string()),
            });
        }

        // Validate attribute policies
        for (idx, attr_policy) in self.body.attributes.iter().enumerate() {
            if let Err(e) = validate_policy(attr_policy) {
                errors.push(ValidationError {
                    field: format!("attributes[{}]", idx),
                    error_type: ValidationErrorType::InvalidFormat,
                    message: format!("Invalid attribute policy: {}", e),
                    suggestion: None,
                });
            }
        }

        // Validate dissemination list
        if self.body.dissem.is_empty() && !self.body.attributes.is_empty() {
            errors.push(ValidationError {
                field: "dissem".to_string(),
                error_type: ValidationErrorType::EmptyList,
                message: "Dissemination list is empty but attributes are defined".to_string(),
                suggestion: Some(
                    "Add at least one dissemination entity or remove all attributes".to_string(),
                ),
            });
        }

        // Check for duplicate dissemination entities
        let mut seen = std::collections::HashSet::new();
        for (idx, entity) in self.body.dissem.iter().enumerate() {
            if entity.trim().is_empty() {
                errors.push(ValidationError {
                    field: format!("dissem[{}]", idx),
                    error_type: ValidationErrorType::InvalidFormat,
                    message: "Empty dissemination entity".to_string(),
                    suggestion: Some("Remove empty entries from dissemination list".to_string()),
                });
            } else if !seen.insert(entity) {
                errors.push(ValidationError {
                    field: format!("dissem[{}]", idx),
                    error_type: ValidationErrorType::InvalidFormat,
                    message: format!("Duplicate dissemination entity: {}", entity),
                    suggestion: Some(
                        "Remove duplicate entries from dissemination list".to_string(),
                    ),
                });
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(PolicyError::ValidationFailed(errors))
        }
    }

    /// Evaluate the policy against a set of attributes at the current time
    ///
    /// This method first validates the policy structure, then checks time validity,
    /// and finally evaluates each policy condition against the provided attributes.
    pub fn evaluate(
        &self,
        attributes: &HashMap<AttributeIdentifier, AttributeValue>,
    ) -> Result<bool, PolicyError> {
        // Validate all attributes policies first
        for policy in &self.body.attributes {
            validate_policy(policy)?;
        }

        // Check time validity
        if !self.is_valid_at(OffsetDateTime::now_utc()) {
            return Ok(false);
        }

        // If there are no attribute policies, evaluate to true
        if self.body.attributes.is_empty() {
            return Ok(true);
        }

        // Evaluate each attribute policy as an AND condition
        for policy in &self.body.attributes {
            if !policy.evaluate(attributes)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Returns true if the policy contains an attribute condition matching the
    /// given FQN.
    ///
    /// Equivalent to `self.find_attribute(fqn).is_some()`; see
    /// [`Policy::find_attribute`] for the matching rules and their limits.
    ///
    /// # Example
    ///
    /// ```
    /// use opentdf::prelude::*;
    ///
    /// let policy = PolicyBuilder::new()
    ///     .id_auto()
    ///     .dissem("user@example.com")
    ///     .attribute_fqn("https://example.com/attr/storage/value/permanent")?
    ///     .build()?;
    ///
    /// let required = AttributeFqn::parse("https://example.com/attr/storage/value/permanent")?;
    /// assert!(policy.has_attribute(&required));
    ///
    /// let other = AttributeFqn::parse("https://example.com/attr/storage/value/temporary")?;
    /// assert!(!policy.has_attribute(&other));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn has_attribute(&self, fqn: &crate::fqn::AttributeFqn) -> bool {
        self.find_attribute(fqn).is_some()
    }

    /// Finds the first attribute condition matching the given FQN.
    ///
    /// Every condition in `body.attributes` is visited in document order,
    /// including those nested inside `AND`, `OR` and `NOT`. A condition
    /// matches when it agrees with each component the FQN carries:
    ///
    /// - **Namespace** (`https://<namespace>`): compared case-insensitively,
    ///   as [`AttributeFqn`](crate::fqn::AttributeFqn) lowercases it. An FQN
    ///   with only a namespace matches any condition in that namespace.
    /// - **Name** (`/attr/<name>`): compared exactly. An FQN without a value
    ///   matches any condition on that attribute, whatever its operator.
    /// - **Value** (`/value/<value>`): matches only a condition that requires
    ///   exactly that value, i.e. [`Operator::Equals`] with an
    ///   [`AttributeValue::String`] equal to it. This is the condition
    ///   [`PolicyBuilder::attribute_fqn`] builds from the same FQN. Conditions
    ///   that merely mention the value (`NotEquals`, `In`, `AnyOf`,
    ///   `MinimumOf`, ...) are not matched; look them up with the value-less
    ///   FQN and inspect the returned condition.
    ///
    /// The lookup is structural: it reports that a condition is present, not
    /// that the policy as a whole requires it. A condition inside an `OR` or
    /// under a `NOT` is found like any other.
    ///
    /// # Example
    ///
    /// ```
    /// use opentdf::prelude::*;
    ///
    /// let policy = PolicyBuilder::new()
    ///     .id_auto()
    ///     .dissem("user@example.com")
    ///     .attribute_fqn("https://example.com/attr/storage/value/permanent")?
    ///     .build()?;
    ///
    /// // Look the attribute up by name, then inspect what the policy requires.
    /// let storage = AttributeFqn::parse("https://example.com/attr/storage")?;
    /// let condition = policy.find_attribute(&storage).expect("storage condition");
    /// assert_eq!(condition.operator, Operator::Equals);
    /// assert_eq!(
    ///     condition.value,
    ///     Some(AttributeValue::String("permanent".to_string()))
    /// );
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn find_attribute(&self, fqn: &crate::fqn::AttributeFqn) -> Option<&AttributeCondition> {
        // Explicit stack rather than recursion: policies come from untrusted
        // manifests and may nest deeply. Children are pushed in reverse so
        // they pop in document order.
        let mut pending: Vec<&AttributePolicy> = self.body.attributes.iter().rev().collect();

        while let Some(node) = pending.pop() {
            match node {
                AttributePolicy::Condition(condition) => {
                    if condition_matches_fqn(condition, fqn) {
                        return Some(condition);
                    }
                }
                AttributePolicy::Logical(
                    LogicalOperator::AND { conditions } | LogicalOperator::OR { conditions },
                ) => pending.extend(conditions.iter().rev()),
                AttributePolicy::Logical(LogicalOperator::NOT { condition }) => {
                    pending.push(condition);
                }
            }
        }

        None
    }
}

/// Whether `condition` agrees with every component `fqn` carries.
///
/// See [`Policy::find_attribute`] for the rules.
fn condition_matches_fqn(condition: &AttributeCondition, fqn: &crate::fqn::AttributeFqn) -> bool {
    // `AttributeFqn` stores its namespace lowercased; normalize the same way.
    if condition.attribute.namespace.to_lowercase() != fqn.get_namespace() {
        return false;
    }

    let wanted_value = fqn.get_value();

    // Namespace-only FQN: any attribute in the namespace matches.
    if fqn.get_name().is_empty() && wanted_value.is_none() {
        return true;
    }
    if condition.attribute.name != fqn.get_name() {
        return false;
    }

    match wanted_value {
        None => true,
        Some(wanted) => {
            condition.operator == Operator::Equals
                && matches!(&condition.value, Some(AttributeValue::String(value)) if value == wanted)
        }
    }
}

/// Builder for creating Policy instances with ergonomic defaults
///
/// # Example
///
/// ```
/// use opentdf::prelude::*;
///
/// let policy = PolicyBuilder::new()
///     .id_auto()  // Auto-generate UUID
///     .dissem("user@example.com")
///     .attribute_fqn("https://example.com/attr/classification/value/secret")?
///     .valid_for_days(30)
///     .build()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Default)]
pub struct PolicyBuilder {
    uuid: Option<String>,
    valid_from: Option<OffsetDateTime>,
    valid_to: Option<OffsetDateTime>,
    attributes: Vec<AttributePolicy>,
    dissem: Vec<String>,
}

impl PolicyBuilder {
    /// Create a new PolicyBuilder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a specific UUID for the policy
    #[must_use]
    pub fn id(mut self, uuid: impl Into<String>) -> Self {
        self.uuid = Some(uuid.into());
        self
    }

    /// Auto-generate a UUID v4 for the policy
    #[must_use]
    pub fn id_auto(mut self) -> Self {
        self.uuid = Some(uuid::Uuid::new_v4().to_string());
        self
    }

    /// Add an attribute policy condition
    #[must_use]
    pub fn attribute(mut self, policy: AttributePolicy) -> Self {
        self.attributes.push(policy);
        self
    }

    /// Add an attribute from an FQN string (convenience method)
    ///
    /// Creates an equality condition for the attribute value specified in the FQN.
    /// For example: "https://example.com/attr/classification/value/secret"
    /// will require classification == "secret"
    pub fn attribute_fqn(mut self, fqn: impl AsRef<str>) -> Result<Self, PolicyError> {
        use crate::fqn::AttributeFqn;

        let parsed = AttributeFqn::parse(fqn.as_ref())?;
        let identifier = parsed.to_identifier();

        if let Some(value) = parsed.get_value() {
            // Has value - create equality condition
            self.attributes
                .push(AttributePolicy::Condition(AttributeCondition {
                    attribute: identifier,
                    operator: Operator::Equals,
                    value: Some(AttributeValue::String(value.to_string())),
                }));
        } else {
            // No value - just check presence
            self.attributes
                .push(AttributePolicy::Condition(AttributeCondition {
                    attribute: identifier,
                    operator: Operator::Present,
                    value: None,
                }));
        }

        Ok(self)
    }

    /// Add multiple attribute policies
    #[must_use]
    pub fn attributes(mut self, policies: impl IntoIterator<Item = AttributePolicy>) -> Self {
        self.attributes.extend(policies);
        self
    }

    /// Add a dissemination target (entity authorized to access)
    #[must_use]
    pub fn dissem(mut self, target: impl Into<String>) -> Self {
        self.dissem.push(target.into());
        self
    }

    /// Add multiple dissemination targets
    #[must_use]
    pub fn dissemination(mut self, targets: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.dissem.extend(targets.into_iter().map(|t| t.into()));
        self
    }

    /// Set the validity start time
    #[must_use]
    pub fn valid_from(mut self, time: OffsetDateTime) -> Self {
        self.valid_from = Some(time);
        self
    }

    /// Set the validity end time
    #[must_use]
    pub fn valid_to(mut self, time: OffsetDateTime) -> Self {
        self.valid_to = Some(time);
        self
    }

    /// Set validity window (convenience for setting both start and end)
    #[must_use]
    pub fn valid_window(mut self, from: OffsetDateTime, to: OffsetDateTime) -> Self {
        self.valid_from = Some(from);
        self.valid_to = Some(to);
        self
    }

    /// Set validity for a duration from now
    #[must_use]
    pub fn valid_for(mut self, duration: Duration) -> Self {
        let now = OffsetDateTime::now_utc();
        self.valid_from = Some(now);
        self.valid_to = Some(now + duration);
        self
    }

    /// Set validity for a number of days from now (convenience)
    #[must_use]
    pub fn valid_for_days(self, days: i64) -> Self {
        self.valid_for(Duration::days(days))
    }

    /// Build the Policy
    ///
    /// If no UUID was set, one will be auto-generated.
    pub fn build(self) -> Result<Policy, PolicyError> {
        let uuid = self
            .uuid
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        Ok(Policy {
            uuid,
            valid_from: self.valid_from,
            valid_to: self.valid_to,
            body: PolicyBody {
                attributes: self.attributes,
                dissem: self.dissem,
            },
        })
    }
}

/// Define clearance level hierarchies
///
/// This allows for a configurable approach to hierarchical attribute values
/// instead of hard-coding the values in the evaluation function
#[derive(Debug, Clone, PartialEq)]
pub struct ClearanceHierarchy {
    /// Map of level names to their numeric values (higher = more access)
    pub levels: HashMap<String, i32>,
}

impl Default for ClearanceHierarchy {
    fn default() -> Self {
        let mut levels = HashMap::new();
        levels.insert("TOP_SECRET".to_string(), 4);
        levels.insert("SECRET".to_string(), 3);
        levels.insert("CONFIDENTIAL".to_string(), 2);
        levels.insert("PUBLIC".to_string(), 1);
        Self { levels }
    }
}

/// Global instance of clearance hierarchy
pub static CLEARANCE_HIERARCHY: std::sync::OnceLock<ClearanceHierarchy> =
    std::sync::OnceLock::new();

/// Get the clearance hierarchy, initializing it if needed
fn get_clearance_hierarchy() -> &'static ClearanceHierarchy {
    CLEARANCE_HIERARCHY.get_or_init(|| {
        // In a production environment, this could be loaded from configuration
        ClearanceHierarchy::default()
    })
}

/// Validate a policy for correctness before evaluation (iterative, safe for arbitrary depth)
/// Returns error if the policy is invalid, with details about the issue
pub fn validate_policy(policy: &AttributePolicy) -> Result<(), PolicyError> {
    let mut stack = vec![policy];
    while let Some(node) = stack.pop() {
        match node {
            AttributePolicy::Condition(condition) => validate_condition(condition)?,
            AttributePolicy::Logical(operator) => match operator {
                LogicalOperator::AND { conditions } | LogicalOperator::OR { conditions } => {
                    for condition in conditions.iter().rev() {
                        stack.push(condition);
                    }
                }
                LogicalOperator::NOT { condition } => stack.push(condition),
            },
        }
    }
    Ok(())
}

/// Validate a single condition for correctness
fn validate_condition(condition: &AttributeCondition) -> Result<(), PolicyError> {
    // For existence operators, value is not required
    match condition.operator {
        Operator::Present | Operator::NotPresent => return Ok(()),
        _ => {}
    }

    // For other operators, value is required
    if condition.value.is_none() {
        return Err(PolicyError::InvalidValueType {
            attribute: condition.attribute.as_string(),
            expected: "a value".to_string(),
            actual: "None".to_string(),
        });
    }

    // Validate value types based on operator
    if let Some(value) = &condition.value {
        match condition.operator {
            // String array operations
            Operator::AllOf | Operator::AnyOf => {
                if !matches!(value, AttributeValue::StringArray(_)) {
                    return Err(PolicyError::InvalidValueType {
                        attribute: condition.attribute.as_string(),
                        expected: "string array".to_string(),
                        actual: format!("{:?}", value),
                    });
                }
            }

            // Array membership operations
            Operator::In | Operator::NotIn => {
                if !matches!(
                    value,
                    AttributeValue::StringArray(_) | AttributeValue::NumberArray(_)
                ) {
                    return Err(PolicyError::InvalidValueType {
                        attribute: condition.attribute.as_string(),
                        expected: "array (string or number)".to_string(),
                        actual: format!("{:?}", value),
                    });
                }
            }

            // String operations
            Operator::Contains => {
                if !matches!(value, AttributeValue::String(_)) {
                    return Err(PolicyError::InvalidValueType {
                        attribute: condition.attribute.as_string(),
                        expected: "string".to_string(),
                        actual: format!("{:?}", value),
                    });
                }
            }

            // Numeric and datetime comparison operations (also accepts RFC 3339 strings from JSON)
            Operator::GreaterThan
            | Operator::GreaterThanOrEqual
            | Operator::LessThan
            | Operator::LessThanOrEqual => {
                let is_valid = match value {
                    AttributeValue::Number(_) | AttributeValue::DateTime(_) => true,
                    AttributeValue::String(s) => {
                        OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
                            .is_ok()
                    }
                    _ => false,
                };
                if !is_valid {
                    return Err(PolicyError::InvalidValueType {
                        attribute: condition.attribute.as_string(),
                        expected: "number or datetime".to_string(),
                        actual: format!("{:?}", value),
                    });
                }
            }

            // Hierarchical / ordered comparison operations
            Operator::MinimumOf | Operator::MaximumOf => {
                if !matches!(
                    value,
                    AttributeValue::String(_)
                        | AttributeValue::Number(_)
                        | AttributeValue::DateTime(_)
                ) {
                    return Err(PolicyError::InvalidValueType {
                        attribute: condition.attribute.as_string(),
                        expected: "string, number, or datetime".to_string(),
                        actual: format!("{:?}", value),
                    });
                }
            }

            // No type restrictions for these operators
            Operator::Equals | Operator::NotEquals | Operator::Present | Operator::NotPresent => {}
        }
    }

    Ok(())
}

/// Helper function to evaluate a single condition against attributes
fn evaluate_condition(
    condition: &AttributeCondition,
    attributes: &HashMap<AttributeIdentifier, AttributeValue>,
) -> Result<bool, PolicyError> {
    // Validate the condition first
    validate_condition(condition)?;

    // Handle existence checks first
    match condition.operator {
        Operator::Present => return Ok(attributes.contains_key(&condition.attribute)),
        Operator::NotPresent => return Ok(!attributes.contains_key(&condition.attribute)),
        _ => {}
    }

    // For other operators, get the attribute value
    let attr_value = match attributes.get(&condition.attribute) {
        Some(value) => value,
        None => return Ok(false), // Missing attribute means condition fails
    };

    // Get the expected value
    let expected_value = match &condition.value {
        Some(value) => value,
        None => {
            return Err(PolicyError::EvaluationError {
                reason: "Value required for this operator".to_string(),
                attribute: Some(condition.attribute.as_string()),
            });
        }
    };

    // Evaluate based on operator and value types
    let attr_name = condition.attribute.as_string();
    match condition.operator {
        Operator::Equals => {
            if matches!(attr_value, AttributeValue::Number(n) if n.is_nan())
                || matches!(expected_value, AttributeValue::Number(n) if n.is_nan())
            {
                return Err(PolicyError::EvaluationError {
                    reason: "Cannot evaluate Equals on NaN value".to_string(),
                    attribute: Some(attr_name),
                });
            }
            compare_values(attr_value, expected_value, |a, b| a == b)
        }
        Operator::NotEquals => {
            if std::mem::discriminant(attr_value) != std::mem::discriminant(expected_value) {
                return Err(PolicyError::InvalidValueType {
                    attribute: attr_name,
                    expected: format!("{:?}", expected_value),
                    actual: format!("{:?}", attr_value),
                });
            }
            // Reject IEEE-754 NaN with an error so NOT(...) cannot invert it to true
            if matches!(attr_value, AttributeValue::Number(n) if n.is_nan())
                || matches!(expected_value, AttributeValue::Number(n) if n.is_nan())
            {
                return Err(PolicyError::EvaluationError {
                    reason: "Cannot evaluate NotEquals on NaN value".to_string(),
                    attribute: Some(attr_name),
                });
            }
            compare_values(attr_value, expected_value, |a, b| a != b)
        }
        Operator::GreaterThan => compare_ordered(&attr_name, attr_value, expected_value, |o| {
            o == std::cmp::Ordering::Greater
        }),
        Operator::GreaterThanOrEqual => {
            compare_ordered(&attr_name, attr_value, expected_value, |o| {
                o != std::cmp::Ordering::Less
            })
        }
        Operator::LessThan => compare_ordered(&attr_name, attr_value, expected_value, |o| {
            o == std::cmp::Ordering::Less
        }),
        Operator::LessThanOrEqual => compare_ordered(&attr_name, attr_value, expected_value, |o| {
            o != std::cmp::Ordering::Greater
        }),
        Operator::Contains => match (attr_value, expected_value) {
            (AttributeValue::String(haystack), AttributeValue::String(needle)) => {
                Ok(haystack.contains(needle.as_str()))
            }
            _ => Err(PolicyError::InvalidValueType {
                attribute: attr_name,
                expected: "string values".to_string(),
                actual: format!("attr={:?}, value={:?}", attr_value, expected_value),
            }),
        },
        Operator::In => match expected_value {
            AttributeValue::StringArray(values) => match attr_value {
                AttributeValue::String(s) => Ok(values.contains(s)),
                // Empty untagged JSON array deserializes as StringArray([])
                AttributeValue::Number(n) if values.is_empty() => {
                    if n.is_nan() {
                        return Err(PolicyError::EvaluationError {
                            reason: "Cannot evaluate In on NaN value".to_string(),
                            attribute: Some(attr_name),
                        });
                    }
                    Ok(false)
                }
                _ => Err(PolicyError::InvalidValueType {
                    attribute: attr_name,
                    expected: "string".to_string(),
                    actual: format!("{:?}", attr_value),
                }),
            },
            AttributeValue::NumberArray(values) => match attr_value {
                AttributeValue::Number(n) => {
                    if n.is_nan() {
                        return Err(PolicyError::EvaluationError {
                            reason: "Cannot evaluate In on NaN value".to_string(),
                            attribute: Some(attr_name),
                        });
                    }
                    Ok(values.contains(n))
                }
                _ => Err(PolicyError::InvalidValueType {
                    attribute: attr_name,
                    expected: "number".to_string(),
                    actual: format!("{:?}", attr_value),
                }),
            },
            _ => Err(PolicyError::InvalidValueType {
                attribute: attr_name,
                expected: "array value".to_string(),
                actual: format!("{:?}", expected_value),
            }),
        },
        Operator::NotIn => match expected_value {
            AttributeValue::StringArray(values) => match attr_value {
                AttributeValue::String(s) => Ok(!values.contains(s)),
                // Empty untagged JSON array deserializes as StringArray([])
                AttributeValue::Number(n) if values.is_empty() => {
                    if n.is_nan() {
                        return Err(PolicyError::EvaluationError {
                            reason: "Cannot evaluate NotIn on NaN value".to_string(),
                            attribute: Some(attr_name),
                        });
                    }
                    Ok(true)
                }
                _ => Err(PolicyError::InvalidValueType {
                    attribute: attr_name,
                    expected: "string".to_string(),
                    actual: format!("{:?}", attr_value),
                }),
            },
            AttributeValue::NumberArray(values) => match attr_value {
                AttributeValue::Number(n) => {
                    if n.is_nan() {
                        return Err(PolicyError::EvaluationError {
                            reason: "Cannot evaluate NotIn on NaN value".to_string(),
                            attribute: Some(attr_name),
                        });
                    }
                    Ok(!values.contains(n))
                }
                _ => Err(PolicyError::InvalidValueType {
                    attribute: attr_name,
                    expected: "number".to_string(),
                    actual: format!("{:?}", attr_value),
                }),
            },
            _ => Err(PolicyError::InvalidValueType {
                attribute: attr_name,
                expected: "array value".to_string(),
                actual: format!("{:?}", expected_value),
            }),
        },
        Operator::MinimumOf => {
            // Used for hierarchical attributes where higher values include privileges of lower ones
            // Special handling for string values to support hierarchies
            match (attr_value, expected_value) {
                (AttributeValue::String(a), AttributeValue::String(b)) => {
                    // Normalize strings for hierarchy lookup
                    let a_upper = a.to_uppercase();
                    let b_upper = b.to_uppercase();

                    // Use the configurable hierarchy — return Err on unknown levels
                    // so NOT(...) cannot invert an indeterminate comparison into a grant.
                    let hierarchy = get_clearance_hierarchy();
                    let Some(&level_a) = hierarchy.levels.get(&a_upper) else {
                        return Err(PolicyError::EvaluationError {
                            reason: format!("Unknown clearance level: '{a}'"),
                            attribute: Some(attr_name),
                        });
                    };
                    let Some(&level_b) = hierarchy.levels.get(&b_upper) else {
                        return Err(PolicyError::EvaluationError {
                            reason: format!("Unknown clearance level: '{b}'"),
                            attribute: Some(attr_name),
                        });
                    };

                    // User's level must be >= required level
                    Ok(level_a >= level_b)
                }
                _ => compare_ordered(&attr_name, attr_value, expected_value, |o| {
                    o != std::cmp::Ordering::Less
                }),
            }
        }
        Operator::MaximumOf => {
            // Special handling for string values to support hierarchies
            match (attr_value, expected_value) {
                (AttributeValue::String(a), AttributeValue::String(b)) => {
                    // Normalize strings for hierarchy lookup
                    let a_upper = a.to_uppercase();
                    let b_upper = b.to_uppercase();

                    // Use the configurable hierarchy — return Err on unknown levels
                    // so NOT(...) cannot invert an indeterminate comparison into a grant.
                    let hierarchy = get_clearance_hierarchy();
                    let Some(&level_a) = hierarchy.levels.get(&a_upper) else {
                        return Err(PolicyError::EvaluationError {
                            reason: format!("Unknown clearance level: '{a}'"),
                            attribute: Some(attr_name),
                        });
                    };
                    let Some(&level_b) = hierarchy.levels.get(&b_upper) else {
                        return Err(PolicyError::EvaluationError {
                            reason: format!("Unknown clearance level: '{b}'"),
                            attribute: Some(attr_name),
                        });
                    };

                    // User's level must be <= maximum level
                    Ok(level_a <= level_b)
                }
                _ => compare_ordered(&attr_name, attr_value, expected_value, |o| {
                    o != std::cmp::Ordering::Greater
                }),
            }
        }
        Operator::AllOf => match (expected_value, attr_value) {
            (AttributeValue::StringArray(required), AttributeValue::StringArray(actual)) => {
                Ok(required.iter().all(|r| actual.contains(r)))
            }
            _ => Err(PolicyError::InvalidValueType {
                attribute: condition.attribute.as_string(),
                expected: "string arrays".to_string(),
                actual: format!("expected={:?}, actual={:?}", expected_value, attr_value),
            }),
        },
        Operator::AnyOf => match (expected_value, attr_value) {
            (AttributeValue::StringArray(required), AttributeValue::StringArray(actual)) => {
                Ok(required.iter().any(|r| actual.contains(r)))
            }
            _ => Err(PolicyError::InvalidValueType {
                attribute: condition.attribute.as_string(),
                expected: "string arrays".to_string(),
                actual: format!("expected={:?}, actual={:?}", expected_value, attr_value),
            }),
        },
        // These operators are handled above
        Operator::Present | Operator::NotPresent => {
            unreachable!("These operators should be handled earlier")
        }
    }
}

/// Helper function to compare values with a custom comparison function
fn compare_values<F>(
    actual: &AttributeValue,
    expected: &AttributeValue,
    compare: F,
) -> Result<bool, PolicyError>
where
    F: Fn(&AttributeValue, &AttributeValue) -> bool,
{
    // Simple direct comparison of attribute values
    Ok(compare(actual, expected))
}

/// Helper function to compare ordered numeric or datetime values (preserving full sub-second precision).
/// Also supports RFC 3339 datetime strings so JSON-deserialized policies work seamlessly
/// alongside `AttributeValue::DateTime`.
fn compare_ordered<F>(
    attribute: &str,
    actual: &AttributeValue,
    expected: &AttributeValue,
    predicate: F,
) -> Result<bool, PolicyError>
where
    F: Fn(std::cmp::Ordering) -> bool,
{
    match (actual, expected) {
        (AttributeValue::Number(a), AttributeValue::Number(b)) => match a.partial_cmp(b) {
            Some(ord) => Ok(predicate(ord)),
            None => Err(PolicyError::EvaluationError {
                reason: "Cannot compare NaN numeric values".to_string(),
                attribute: Some(attribute.to_string()),
            }),
        },
        (AttributeValue::DateTime(a), AttributeValue::DateTime(b)) => Ok(predicate(a.cmp(b))),
        (AttributeValue::DateTime(a), AttributeValue::String(b_str)) => {
            let b = OffsetDateTime::parse(b_str, &time::format_description::well_known::Rfc3339)
                .map_err(|_| PolicyError::InvalidValueType {
                    attribute: attribute.to_string(),
                    expected: "RFC 3339 datetime".to_string(),
                    actual: format!("actual={:?}, expected={:?}", actual, expected),
                })?;
            Ok(predicate(a.cmp(&b)))
        }
        (AttributeValue::String(a_str), AttributeValue::DateTime(b)) => {
            let a = OffsetDateTime::parse(a_str, &time::format_description::well_known::Rfc3339)
                .map_err(|_| PolicyError::InvalidValueType {
                    attribute: attribute.to_string(),
                    expected: "RFC 3339 datetime".to_string(),
                    actual: format!("actual={:?}, expected={:?}", actual, expected),
                })?;
            Ok(predicate(a.cmp(b)))
        }
        (AttributeValue::String(a_str), AttributeValue::String(b_str)) => {
            let a = OffsetDateTime::parse(a_str, &time::format_description::well_known::Rfc3339)
                .map_err(|_| PolicyError::InvalidValueType {
                    attribute: attribute.to_string(),
                    expected: "number or RFC 3339 datetime".to_string(),
                    actual: format!("actual={:?}, expected={:?}", actual, expected),
                })?;
            let b = OffsetDateTime::parse(b_str, &time::format_description::well_known::Rfc3339)
                .map_err(|_| PolicyError::InvalidValueType {
                    attribute: attribute.to_string(),
                    expected: "number or RFC 3339 datetime".to_string(),
                    actual: format!("actual={:?}, expected={:?}", actual, expected),
                })?;
            Ok(predicate(a.cmp(&b)))
        }
        _ => Err(PolicyError::InvalidValueType {
            attribute: attribute.to_string(),
            expected: "number or datetime".to_string(),
            actual: format!("actual={:?}, expected={:?}", actual, expected),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribute_identifier_parsing() {
        let attr = AttributeIdentifier::from_string("clearance:SECRET").unwrap();
        assert_eq!(attr.namespace, "clearance");
        assert_eq!(attr.name, "SECRET");

        let result = AttributeIdentifier::from_string("invalid_format");
        assert!(result.is_err());
    }

    #[test]
    fn test_simple_equals_condition() {
        let attr_id = AttributeIdentifier::new("clearance", "level");
        let condition = AttributeCondition::equals(
            attr_id.clone(),
            AttributeValue::String("SECRET".to_string()),
        );

        let mut attributes = HashMap::new();
        attributes.insert(
            attr_id.clone(),
            AttributeValue::String("SECRET".to_string()),
        );

        let policy = AttributePolicy::Condition(condition);
        assert!(policy.evaluate(&attributes).unwrap());

        // Test with different value
        attributes.insert(attr_id, AttributeValue::String("CONFIDENTIAL".to_string()));
        assert!(!policy.evaluate(&attributes).unwrap());
    }

    #[test]
    fn test_logical_operators() {
        let dept_attr = AttributeIdentifier::new("department", "name");
        let level_attr = AttributeIdentifier::new("clearance", "level");

        let dept_condition = AttributePolicy::condition(
            dept_attr.clone(),
            Operator::Equals,
            AttributeValue::String("FINANCE".to_string()),
        );

        let level_condition = AttributePolicy::condition(
            level_attr.clone(),
            Operator::MinimumOf,
            AttributeValue::String("CONFIDENTIAL".to_string()),
        );

        let and_policy =
            AttributePolicy::and(vec![dept_condition.clone(), level_condition.clone()]);
        let or_policy = AttributePolicy::or(vec![dept_condition.clone(), level_condition.clone()]);

        let mut attributes = HashMap::new();
        attributes.insert(
            dept_attr.clone(),
            AttributeValue::String("FINANCE".to_string()),
        );
        attributes.insert(
            level_attr.clone(),
            AttributeValue::String("SECRET".to_string()),
        );

        // Both conditions met
        assert!(and_policy.evaluate(&attributes).unwrap());
        assert!(or_policy.evaluate(&attributes).unwrap());

        // Only one condition met
        attributes.insert(
            dept_attr.clone(),
            AttributeValue::String("ENGINEERING".to_string()),
        );
        assert!(!and_policy.evaluate(&attributes).unwrap());
        assert!(or_policy.evaluate(&attributes).unwrap());

        // This is failing because minimumOf is now accepting string values.
        // Let's create different conditions for this test case

        let level_exact_match = AttributePolicy::condition(
            level_attr.clone(),
            Operator::Equals, // Use exact match instead of minimumOf
            AttributeValue::String("CONFIDENTIAL".to_string()),
        );

        let and_policy_exact =
            AttributePolicy::and(vec![dept_condition.clone(), level_exact_match.clone()]);
        let or_policy_exact =
            AttributePolicy::or(vec![dept_condition.clone(), level_exact_match.clone()]);

        attributes.insert(level_attr, AttributeValue::String("PUBLIC".to_string()));
        assert!(!and_policy_exact.evaluate(&attributes).unwrap());
        assert!(!or_policy_exact.evaluate(&attributes).unwrap());

        // Test NOT operator using trait implementation
        let not_policy = !dept_condition.clone();
        assert!(not_policy.evaluate(&attributes).unwrap());

        attributes.insert(dept_attr, AttributeValue::String("FINANCE".to_string()));
        assert!(!not_policy.evaluate(&attributes).unwrap());
    }

    #[test]
    fn test_array_operators() {
        let locations = AttributeIdentifier::new("location", "allowed");
        let in_condition = AttributePolicy::condition(
            locations.clone(),
            Operator::In,
            AttributeValue::StringArray(vec![
                "USA".to_string(),
                "CANADA".to_string(),
                "UK".to_string(),
            ]),
        );

        let mut attributes = HashMap::new();
        attributes.insert(locations.clone(), AttributeValue::String("USA".to_string()));
        assert!(in_condition.evaluate(&attributes).unwrap());

        attributes.insert(
            locations.clone(),
            AttributeValue::String("FRANCE".to_string()),
        );
        assert!(!in_condition.evaluate(&attributes).unwrap());

        // Test NotIn operator
        let not_in_condition = AttributePolicy::condition(
            locations.clone(),
            Operator::NotIn,
            AttributeValue::StringArray(vec!["CHINA".to_string(), "RUSSIA".to_string()]),
        );

        attributes.insert(locations, AttributeValue::String("USA".to_string()));
        assert!(not_in_condition.evaluate(&attributes).unwrap());
    }

    #[test]
    fn test_time_based_policy() {
        let now = OffsetDateTime::now_utc();
        let tomorrow = now + Duration::days(1);
        let yesterday = now - Duration::days(1);

        let mut policy = Policy::new(
            "test-uuid".to_string(),
            vec![],
            vec!["user@example.com".to_string()],
        );

        // Test with no time constraints
        assert!(policy.is_valid_at(now));

        // Test with future valid_from
        policy = policy.with_time_window(Some(tomorrow), None);
        assert!(!policy.is_valid_at(now));

        // Test with past valid_from
        policy = policy.with_time_window(Some(yesterday), None);
        assert!(policy.is_valid_at(now));

        // Test with past valid_from and future valid_to
        policy = policy.with_time_window(Some(yesterday), Some(tomorrow));
        assert!(policy.is_valid_at(now));

        // Test with expired valid_to
        policy = policy.with_time_window(None, Some(yesterday));
        assert!(!policy.is_valid_at(now));
    }

    #[test]
    fn test_policy_serialization() {
        let dept_attr = AttributeIdentifier::new("department", "name");
        let level_attr = AttributeIdentifier::new("clearance", "level");

        let dept_condition = AttributePolicy::condition(
            dept_attr,
            Operator::Equals,
            AttributeValue::String("FINANCE".to_string()),
        );

        let level_condition = AttributePolicy::condition(
            level_attr,
            Operator::MinimumOf,
            AttributeValue::String("CONFIDENTIAL".to_string()),
        );

        let policy = Policy::new(
            "test-uuid".to_string(),
            vec![dept_condition, level_condition],
            vec!["user@example.com".to_string()],
        );

        let json = policy.to_json().unwrap();
        let deserialized = Policy::from_json(&json).unwrap();

        assert_eq!(policy.uuid, deserialized.uuid);
        assert_eq!(policy.body.dissem, deserialized.body.dissem);
        assert_eq!(
            policy.body.attributes.len(),
            deserialized.body.attributes.len()
        );
    }

    #[test]
    fn test_complex_policy_evaluation() {
        // Set up a complex policy: (Finance OR Legal) AND Secret clearance AND not APAC region
        let dept_attr = AttributeIdentifier::new("department", "name");
        let level_attr = AttributeIdentifier::new("clearance", "level");
        let region_attr = AttributeIdentifier::new("region", "code");

        let finance_condition = AttributePolicy::condition(
            dept_attr.clone(),
            Operator::Equals,
            AttributeValue::String("FINANCE".to_string()),
        );

        let legal_condition = AttributePolicy::condition(
            dept_attr.clone(),
            Operator::Equals,
            AttributeValue::String("LEGAL".to_string()),
        );

        let clearance_condition = AttributePolicy::condition(
            level_attr.clone(),
            Operator::Equals,
            AttributeValue::String("SECRET".to_string()),
        );

        let apac_condition = AttributePolicy::condition(
            region_attr.clone(),
            Operator::Equals,
            AttributeValue::String("APAC".to_string()),
        );

        let dept_policy = AttributePolicy::or(vec![finance_condition, legal_condition]);
        let not_apac = AttributePolicy::not(apac_condition);

        let complex_policy = AttributePolicy::and(vec![dept_policy, clearance_condition, not_apac]);

        // Test with finance, secret clearance, and EMEA region
        let mut attributes = HashMap::new();
        attributes.insert(
            dept_attr.clone(),
            AttributeValue::String("FINANCE".to_string()),
        );
        attributes.insert(
            level_attr.clone(),
            AttributeValue::String("SECRET".to_string()),
        );
        attributes.insert(
            region_attr.clone(),
            AttributeValue::String("EMEA".to_string()),
        );

        assert!(complex_policy.evaluate(&attributes).unwrap());

        // Test with legal, secret clearance, and EMEA region
        attributes.insert(
            dept_attr.clone(),
            AttributeValue::String("LEGAL".to_string()),
        );
        assert!(complex_policy.evaluate(&attributes).unwrap());

        // Test with finance, secret clearance, but APAC region (should fail)
        attributes.insert(
            dept_attr.clone(),
            AttributeValue::String("FINANCE".to_string()),
        );
        attributes.insert(
            region_attr.clone(),
            AttributeValue::String("APAC".to_string()),
        );
        assert!(!complex_policy.evaluate(&attributes).unwrap());

        // Test with marketing, secret clearance, and EMEA region (should fail due to department)
        attributes.insert(dept_attr, AttributeValue::String("MARKETING".to_string()));
        attributes.insert(region_attr, AttributeValue::String("EMEA".to_string()));
        assert!(!complex_policy.evaluate(&attributes).unwrap());

        // Test with finance, confidential clearance, and EMEA region (should fail due to clearance)
        attributes.insert(
            level_attr,
            AttributeValue::String("CONFIDENTIAL".to_string()),
        );
        assert!(!complex_policy.evaluate(&attributes).unwrap());
    }

    #[test]
    fn test_datetime_comparison() {
        let time_attr = AttributeIdentifier::new("access", "time");

        // Base time for comparison
        let base_time = OffsetDateTime::parse(
            "2023-04-01T09:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();

        let condition = AttributePolicy::condition(
            time_attr.clone(),
            Operator::GreaterThan,
            AttributeValue::DateTime(base_time),
        );

        let mut attributes = HashMap::new();

        // Test with time after the base
        let later = base_time + Duration::hours(1);
        attributes.insert(time_attr.clone(), AttributeValue::DateTime(later));
        assert!(condition.evaluate(&attributes).unwrap());

        // Test with time before the base
        let earlier = base_time - Duration::hours(1);
        attributes.insert(time_attr, AttributeValue::DateTime(earlier));
        assert!(!condition.evaluate(&attributes).unwrap());
    }
}

#[test]
fn test_empty_policy_serialization_compatibility() {
    // Test that empty policies serialize with null instead of []
    // This is critical for Go SDK compatibility
    let policy = Policy::new("test-uuid".to_string(), vec![], vec![]);
    let json_str = policy.to_json().unwrap();

    println!("Serialized empty policy: {}", json_str);

    // Check for null values
    assert!(
        json_str.contains(r#""dataAttributes":null"#),
        "Empty dataAttributes should serialize as null, got: {}",
        json_str
    );
    assert!(
        json_str.contains(r#""dissem":null"#),
        "Empty dissem should serialize as null, got: {}",
        json_str
    );

    // Deserialize and check
    let parsed = Policy::from_json(&json_str).unwrap();
    assert_eq!(parsed.body.attributes.len(), 0);
    assert_eq!(parsed.body.dissem.len(), 0);
}

#[test]
fn test_policy_validate_valid_policy() {
    // Create a valid policy using the builder
    let policy = PolicyBuilder::new()
        .id_auto()
        .attribute_fqn("https://example.com/attr/clearance/value/secret")
        .unwrap()
        .dissemination(["user@example.com"])
        .build()
        .unwrap();

    // Should pass validation
    assert!(policy.validate().is_ok());
}

#[test]
fn test_policy_validate_invalid_uuid() {
    // Create a policy with invalid UUID
    let policy = Policy::new("not-a-valid-uuid".to_string(), vec![], vec![]);

    let result = policy.validate();
    assert!(result.is_err());

    if let Err(PolicyError::ValidationFailed(errors)) = result {
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field, "uuid");
        assert_eq!(errors[0].error_type, ValidationErrorType::InvalidFormat);
        assert!(errors[0].suggestion.is_some());
    } else {
        panic!("Expected ValidationFailed error");
    }
}

#[test]
fn test_policy_validate_invalid_time_window() {
    let now = OffsetDateTime::now_utc();
    let future = now + Duration::days(7);
    let past = now - Duration::days(7);

    // Create a policy where valid_from is after valid_to
    let mut policy = PolicyBuilder::new()
        .id_auto()
        .dissemination(["user@example.com"])
        .build()
        .unwrap();

    policy.valid_from = Some(future);
    policy.valid_to = Some(past);

    let result = policy.validate();
    assert!(result.is_err());

    if let Err(PolicyError::ValidationFailed(errors)) = result {
        assert!(errors.iter().any(|e| e.field == "time_window"));
        assert!(
            errors
                .iter()
                .any(|e| e.error_type == ValidationErrorType::OutOfRange)
        );
    } else {
        panic!("Expected ValidationFailed error");
    }
}

#[test]
fn test_policy_validate_empty_dissem_with_attributes() {
    // Create a policy with attributes but no dissemination list
    let attr_policy = AttributePolicy::condition(
        AttributeIdentifier::new("example.com", "clearance"),
        Operator::Equals,
        AttributeValue::String("secret".to_string()),
    );

    let policy = Policy::new(uuid::Uuid::new_v4().to_string(), vec![attr_policy], vec![]);

    let result = policy.validate();
    assert!(result.is_err());

    if let Err(PolicyError::ValidationFailed(errors)) = result {
        assert!(errors.iter().any(|e| e.field == "dissem"));
        assert!(
            errors
                .iter()
                .any(|e| e.error_type == ValidationErrorType::EmptyList)
        );
    } else {
        panic!("Expected ValidationFailed error");
    }
}

#[test]
fn test_policy_validate_duplicate_dissem_entities() {
    // Create a policy with duplicate dissemination entities
    let policy = PolicyBuilder::new()
        .id_auto()
        .attribute_fqn("https://example.com/attr/clearance/value/secret")
        .unwrap()
        .dissemination(["user@example.com", "admin@example.com", "user@example.com"])
        .build()
        .unwrap();

    let result = policy.validate();
    assert!(result.is_err());

    if let Err(PolicyError::ValidationFailed(errors)) = result {
        assert!(errors.iter().any(|e| e.field.starts_with("dissem[")));
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("Duplicate dissemination entity"))
        );
    } else {
        panic!("Expected ValidationFailed error");
    }
}

#[test]
fn test_policy_validate_empty_dissem_entry() {
    // Create a policy with empty dissemination entity
    let mut policy = PolicyBuilder::new()
        .id_auto()
        .attribute_fqn("https://example.com/attr/clearance/value/secret")
        .unwrap()
        .dissemination(["user@example.com"])
        .build()
        .unwrap();

    // Manually add empty entry
    policy.body.dissem.push("".to_string());
    policy.body.dissem.push("  ".to_string()); // whitespace only

    let result = policy.validate();
    assert!(result.is_err());

    if let Err(PolicyError::ValidationFailed(errors)) = result {
        assert!(errors.len() >= 2); // At least 2 empty entries
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("Empty dissemination entity"))
        );
    } else {
        panic!("Expected ValidationFailed error");
    }
}

#[test]
fn test_policy_validate_multiple_errors() {
    // Create a policy with multiple validation errors
    let mut policy = Policy::new("invalid-uuid".to_string(), vec![], vec![]);

    // Add invalid time window
    let now = OffsetDateTime::now_utc();
    policy.valid_from = Some(now);
    policy.valid_to = Some(now - Duration::days(1));

    let result = policy.validate();
    assert!(result.is_err());

    if let Err(PolicyError::ValidationFailed(errors)) = result {
        // Should have at least 2 errors (invalid UUID, invalid time window)
        assert!(errors.len() >= 2);
        assert!(errors.iter().any(|e| e.field == "uuid"));
        assert!(errors.iter().any(|e| e.field == "time_window"));
    } else {
        panic!("Expected ValidationFailed error");
    }
}

#[cfg(test)]
mod attribute_lookup_tests {
    use super::*;
    use crate::fqn::AttributeFqn;

    const NS: &str = "example.com";

    fn string(value: &str) -> AttributeValue {
        AttributeValue::String(value.to_string())
    }

    fn equals(name: &str, value: &str) -> AttributeCondition {
        AttributeCondition::equals(AttributeIdentifier::new(NS, name), string(value))
    }

    fn policy(attributes: Vec<AttributePolicy>) -> Policy {
        Policy::new(
            "00000000-0000-0000-0000-000000000000".to_string(),
            attributes,
            vec![],
        )
    }

    fn fqn(url: &str) -> AttributeFqn {
        AttributeFqn::parse(url).unwrap()
    }

    #[test]
    fn finds_condition_built_from_the_same_fqn() {
        let url = "https://example.com/attr/storage/value/permanent";
        let policy = PolicyBuilder::new()
            .id_auto()
            .dissem("user@example.com")
            .attribute_fqn(url)
            .unwrap()
            .build()
            .unwrap();

        assert!(policy.has_attribute(&fqn(url)));
        assert_eq!(
            policy.find_attribute(&fqn(url)),
            Some(&equals("storage", "permanent"))
        );

        // Any differing component is a miss.
        for miss in [
            "https://example.com/attr/storage/value/temporary",
            "https://example.com/attr/retention/value/permanent",
            "https://other.example.com/attr/storage/value/permanent",
            "https://example.com/attr/Storage/value/permanent",
            "https://example.com/attr/storage/value/Permanent",
        ] {
            assert!(!policy.has_attribute(&fqn(miss)), "{miss}");
            assert_eq!(policy.find_attribute(&fqn(miss)), None, "{miss}");
        }
    }

    #[test]
    fn empty_policy_has_no_attributes() {
        let policy = policy(vec![]);
        assert!(!policy.has_attribute(&fqn("https://example.com")));
        assert_eq!(
            policy.find_attribute(&fqn("https://example.com/attr/storage")),
            None
        );
    }

    #[test]
    fn attribute_fqn_without_value_matches_any_operator() {
        let id = AttributeIdentifier::new(NS, "storage");
        let conditions = [
            AttributeCondition::present(id.clone()),
            AttributeCondition::new(id.clone(), Operator::NotPresent, None),
            AttributeCondition::new(id.clone(), Operator::NotEquals, Some(string("permanent"))),
            AttributeCondition::new(
                id.clone(),
                Operator::In,
                Some(AttributeValue::StringArray(vec!["permanent".to_string()])),
            ),
            AttributeCondition::new(id, Operator::GreaterThan, Some(AttributeValue::Number(1.0))),
        ];

        for condition in conditions {
            let policy = policy(vec![AttributePolicy::Condition(condition.clone())]);
            assert_eq!(
                policy.find_attribute(&fqn("https://example.com/attr/storage")),
                Some(&condition),
                "{condition:?}"
            );
            // A different attribute in the same namespace is not a match.
            assert!(!policy.has_attribute(&fqn("https://example.com/attr/retention")));
        }
    }

    #[test]
    fn value_fqn_matches_only_string_equality() {
        let id = AttributeIdentifier::new(NS, "storage");
        let wanted = fqn("https://example.com/attr/storage/value/permanent");
        let mentions_but_does_not_require = [
            AttributeCondition::present(id.clone()),
            AttributeCondition::new(id.clone(), Operator::NotEquals, Some(string("permanent"))),
            AttributeCondition::new(id.clone(), Operator::MinimumOf, Some(string("permanent"))),
            AttributeCondition::new(id.clone(), Operator::Contains, Some(string("permanent"))),
            AttributeCondition::new(
                id.clone(),
                Operator::In,
                Some(AttributeValue::StringArray(vec!["permanent".to_string()])),
            ),
            AttributeCondition::new(
                id.clone(),
                Operator::AnyOf,
                Some(AttributeValue::StringArray(vec!["permanent".to_string()])),
            ),
            // Equals, but not a string value.
            AttributeCondition::new(
                id.clone(),
                Operator::Equals,
                Some(AttributeValue::StringArray(vec!["permanent".to_string()])),
            ),
            AttributeCondition::new(id.clone(), Operator::Equals, None),
        ];

        for condition in mentions_but_does_not_require {
            let policy = policy(vec![AttributePolicy::Condition(condition.clone())]);
            assert!(!policy.has_attribute(&wanted), "{condition:?}");
        }

        // Numbers and booleans are not compared with the FQN's string value.
        let numeric = policy(vec![AttributePolicy::Condition(
            AttributeCondition::equals(id, AttributeValue::Number(5.0)),
        )]);
        assert!(!numeric.has_attribute(&fqn("https://example.com/attr/storage/value/5")));
    }

    #[test]
    fn namespace_fqn_matches_any_attribute_in_the_namespace() {
        let policy = policy(vec![
            AttributePolicy::Condition(equals("storage", "permanent")),
            AttributePolicy::Condition(equals("retention", "7y")),
        ]);

        // First condition in the namespace, in document order.
        assert_eq!(
            policy.find_attribute(&fqn("https://example.com")),
            Some(&equals("storage", "permanent"))
        );
        assert_eq!(
            policy.find_attribute(&AttributeFqn::namespace(NS)),
            Some(&equals("storage", "permanent"))
        );
        assert!(!policy.has_attribute(&fqn("https://other.example.com")));
        // A namespace is matched whole, not as a prefix or substring.
        assert!(!policy.has_attribute(&fqn("https://example.co")));
        assert!(!policy.has_attribute(&fqn("https://sub.example.com")));
        // Only a bare namespace is a wildcard; a value with no name is not.
        assert!(!policy.has_attribute(&AttributeFqn::with_value(NS, "", "permanent")));
    }

    #[test]
    fn namespace_is_compared_case_insensitively() {
        // An identifier built by hand keeps its case; the FQN is lowercased.
        let condition = AttributeCondition::equals(
            AttributeIdentifier::new("Example.COM", "storage"),
            string("permanent"),
        );
        let policy = policy(vec![AttributePolicy::Condition(condition.clone())]);

        for url in [
            "https://example.com",
            "https://EXAMPLE.com/attr/storage",
            "https://example.com/attr/storage/value/permanent",
        ] {
            assert_eq!(policy.find_attribute(&fqn(url)), Some(&condition), "{url}");
        }
    }

    #[test]
    fn finds_conditions_nested_in_logical_operators() {
        let policy = policy(vec![
            AttributePolicy::Condition(equals("top", "1")),
            AttributePolicy::and(vec![
                AttributePolicy::or(vec![
                    AttributePolicy::Condition(equals("in-or", "2")),
                    AttributePolicy::create_not(AttributePolicy::Condition(equals("in-not", "3"))),
                ]),
                AttributePolicy::Condition(equals("in-and", "4")),
            ]),
        ]);

        for (name, value) in [
            ("top", "1"),
            ("in-or", "2"),
            ("in-not", "3"),
            ("in-and", "4"),
        ] {
            let url = format!("https://example.com/attr/{name}/value/{value}");
            assert_eq!(
                policy.find_attribute(&fqn(&url)),
                Some(&equals(name, value)),
                "{url}"
            );
        }
        assert!(!policy.has_attribute(&fqn("https://example.com/attr/absent")));
    }

    #[test]
    fn returns_the_first_match_in_document_order() {
        let policy = policy(vec![
            AttributePolicy::or(vec![
                AttributePolicy::Condition(equals("other", "x")),
                AttributePolicy::and(vec![AttributePolicy::Condition(equals(
                    "storage", "nested",
                ))]),
                AttributePolicy::Condition(equals("storage", "sibling")),
            ]),
            AttributePolicy::Condition(equals("storage", "top-level")),
        ]);

        assert_eq!(
            policy.find_attribute(&fqn("https://example.com/attr/storage")),
            Some(&equals("storage", "nested"))
        );
        // A value FQN skips earlier conditions on the same attribute.
        assert_eq!(
            policy.find_attribute(&fqn("https://example.com/attr/storage/value/top-level")),
            Some(&equals("storage", "top-level"))
        );
    }

    #[test]
    fn finds_attribute_in_policy_parsed_from_manifest_json() {
        let json = r#"{
            "uuid": "00000000-0000-0000-0000-000000000000",
            "body": {
                "dataAttributes": [{
                    "type": "AND",
                    "conditions": [{
                        "attribute": {"namespace": "example.com", "name": "storage"},
                        "operator": "equals",
                        "value": "permanent"
                    }]
                }],
                "dissem": null
            }
        }"#;
        let policy = Policy::from_json(json).unwrap();

        assert!(policy.has_attribute(&fqn("https://example.com/attr/storage/value/permanent")));
        assert!(!policy.has_attribute(&fqn("https://example.com/attr/storage/value/other")));
    }

    #[test]
    fn deeply_nested_policy_is_searched_without_recursion() {
        let mut nested = AttributePolicy::Condition(equals("storage", "permanent"));
        for _ in 0..2_000 {
            nested = AttributePolicy::create_not(nested);
        }
        let policy = policy(vec![nested]);

        assert!(policy.has_attribute(&fqn("https://example.com/attr/storage/value/permanent")));
        assert!(!policy.has_attribute(&fqn("https://example.com/attr/absent")));
    }

    #[test]
    fn test_unknown_clearance_levels_return_err_even_under_not() {
        let attr = AttributeIdentifier::new("clearance", "level");
        let min_policy = AttributePolicy::condition(
            attr.clone(),
            Operator::MinimumOf,
            AttributeValue::String("UNKNOWN_LEVEL".to_string()),
        );
        let mut attrs = HashMap::new();
        attrs.insert(
            attr.clone(),
            AttributeValue::String("UNCLASSIFIED".to_string()),
        );
        // Unknown required level must return Err so NOT(...) cannot invert it into a grant.
        assert!(min_policy.evaluate(&attrs).is_err());
        assert!(
            AttributePolicy::create_not(min_policy)
                .evaluate(&attrs)
                .is_err()
        );

        let max_policy = AttributePolicy::condition(
            attr.clone(),
            Operator::MaximumOf,
            AttributeValue::String("SECRET".to_string()),
        );
        attrs.insert(attr, AttributeValue::String("UNKNOWN_LEVEL".to_string()));
        // Unknown user level must return Err both directly and under NOT(...).
        assert!(max_policy.evaluate(&attrs).is_err());
        assert!(
            AttributePolicy::create_not(max_policy)
                .evaluate(&attrs)
                .is_err()
        );
    }

    #[test]
    fn test_datetime_string_interop_and_subsecond_ordering() {
        let t1 =
            time::OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_100_000_000).unwrap();
        let t2 =
            time::OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_900_000_000).unwrap();

        // ISO-8601 JSON strings deserialize as String so WASM/string equals & contains still work
        let json = serde_json::to_string(&AttributeValue::DateTime(t1)).unwrap();
        let roundtripped: AttributeValue = serde_json::from_str(&json).unwrap();
        assert!(matches!(roundtripped, AttributeValue::String(_)));

        let attr = AttributeIdentifier::new("time", "created");
        // Sub-second ordering works for both DateTime and RFC 3339 String values
        let gt_policy = AttributePolicy::condition(
            attr.clone(),
            Operator::GreaterThan,
            AttributeValue::DateTime(t1),
        );
        let mut attrs = HashMap::new();
        attrs.insert(attr.clone(), AttributeValue::DateTime(t2));
        assert!(gt_policy.evaluate(&attrs).unwrap());

        let gt_from_json =
            AttributePolicy::condition(attr.clone(), Operator::GreaterThan, roundtripped);
        assert!(gt_from_json.evaluate(&attrs).unwrap());
    }

    #[test]
    fn test_not_equals_and_not_in_type_safety_and_nan() {
        let attr = AttributeIdentifier::new("score", "value");
        let ne_num = AttributePolicy::condition(
            attr.clone(),
            Operator::NotEquals,
            AttributeValue::Number(10.0),
        );
        let mut attrs = HashMap::new();
        // Variant mismatch must error, not evaluate to true
        attrs.insert(attr.clone(), AttributeValue::String("10".to_string()));
        assert!(ne_num.evaluate(&attrs).is_err());

        // NaN must return Err for NotEquals, NOT(NotEquals), and NotIn (never flip under NOT)
        attrs.insert(attr.clone(), AttributeValue::Number(f64::NAN));
        assert!(ne_num.evaluate(&attrs).is_err());
        assert!(
            AttributePolicy::create_not(ne_num)
                .evaluate(&attrs)
                .is_err()
        );

        let not_in = AttributePolicy::condition(
            attr,
            Operator::NotIn,
            AttributeValue::NumberArray(vec![1.0, 2.0]),
        );
        assert!(not_in.evaluate(&attrs).is_err());
        assert!(
            AttributePolicy::create_not(not_in)
                .evaluate(&attrs)
                .is_err()
        );
    }

    #[test]
    fn test_policy_body_attributes_alias_and_deep_validation() {
        let json = r#"{
            "uuid": "00000000-0000-0000-0000-000000000000",
            "body": {
                "attributes": [{
                    "attribute": {"namespace": "example.com", "name": "role"},
                    "operator": "equals",
                    "value": "admin"
                }],
                "dissem": []
            }
        }"#;
        let parsed = Policy::from_json(json).unwrap();
        assert_eq!(parsed.body.attributes.len(), 1);

        // Deep nesting must not overflow stack during depth() or validate()
        let mut deep = AttributePolicy::condition(
            AttributeIdentifier::new("ns", "k"),
            Operator::Equals,
            AttributeValue::String("v".to_string()),
        );
        for _ in 0..500 {
            deep = AttributePolicy::create_not(deep);
        }
        assert!(deep.depth() > 500);
        let p = Policy::new(
            "00000000-0000-0000-0000-000000000000".to_string(),
            vec![deep],
            vec![],
        );
        assert!(matches!(
            p.validate(),
            Err(PolicyError::ValidationFailed(_))
        ));

        // Empty namespace or name rejected
        assert!(AttributeIdentifier::from_string(":name").is_err());
        assert!(AttributeIdentifier::from_string("ns:").is_err());
    }
}
