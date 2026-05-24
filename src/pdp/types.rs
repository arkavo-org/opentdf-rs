//! Policy data types used by the Access PDP.
//!
//! These are Rust mirrors of the Go protobuf types the platform's access PDP
//! reads at decision time. The model is intentionally narrow: only the fields
//! needed to answer "may this entity perform this action on this resource?"
//! are included. JSON values from external systems are represented with
//! `serde_json::Value` to avoid a protobuf runtime dependency.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// How an attribute definition's values combine when present on a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum AttributeRule {
    #[default]
    Unspecified,
    AllOf,
    AnyOf,
    Hierarchy,
}

/// Boolean combinator used inside a condition group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ConditionBooleanOperator {
    #[default]
    Unspecified,
    And,
    Or,
}

/// Comparison operator used inside a single subject condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum SubjectMappingOperator {
    #[default]
    Unspecified,
    /// The flattened entity value must equal one of the listed values.
    In,
    /// The flattened entity value must not equal any of the listed values.
    NotIn,
    /// Some flattened entity value must contain one of the listed substrings.
    InContains,
}

/// A namespace reference. Both `id` and `fqn` may be present; the PDP only
/// inspects whichever fields are set when matching action namespaces.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Namespace {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub fqn: String,
}

impl Namespace {
    pub fn is_empty_identity(&self) -> bool {
        self.id.is_empty() && self.fqn.is_empty()
    }
}

/// Named action on a resource (e.g. `read`, `create`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Action {
    #[serde(default)]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub namespace: Option<Namespace>,
}

impl Action {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: String::new(),
            name: name.into(),
            namespace: None,
        }
    }
}

/// A single attribute value, with its FQN and any subject mappings that point at it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Value {
    #[serde(default)]
    pub id: String,
    pub fqn: String,
    pub value: String,
    #[serde(default)]
    pub subject_mappings: Vec<SubjectMapping>,
}

/// An attribute definition. Holds the rule and (optionally) an ordered list of values.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Attribute {
    #[serde(default)]
    pub id: String,
    pub fqn: String,
    pub rule: AttributeRule,
    #[serde(default)]
    pub values: Vec<Value>,
    #[serde(default)]
    pub namespace: Option<Namespace>,
}

/// One subject condition: "the flattened value at `selector` matches `values` under `operator`".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Condition {
    pub subject_external_selector_value: String,
    pub subject_external_values: Vec<String>,
    pub operator: SubjectMappingOperator,
}

/// A group of conditions combined with a boolean operator.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConditionGroup {
    pub boolean_operator: ConditionBooleanOperator,
    pub conditions: Vec<Condition>,
}

/// Condition groups AND-ed together.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubjectSet {
    pub condition_groups: Vec<ConditionGroup>,
}

/// Subject sets AND-ed together.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubjectConditionSet {
    #[serde(default)]
    pub id: String,
    pub subject_sets: Vec<SubjectSet>,
    #[serde(default)]
    pub namespace: Option<Namespace>,
}

/// A subject mapping: "if this subject condition set matches an entity, that
/// entity is entitled to perform `actions` on `attribute_value`".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubjectMapping {
    #[serde(default)]
    pub id: String,
    pub attribute_value: Value,
    pub subject_condition_set: SubjectConditionSet,
    pub actions: Vec<Action>,
    #[serde(default)]
    pub namespace: Option<Namespace>,
}

/// Resolved entity representation. `additional_props` is an array of arbitrary
/// JSON objects (mirroring `[]*structpb.Struct` in Go); the PDP flattens each
/// one and feeds it to the subject mapping engine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntityRepresentation {
    pub original_id: String,
    #[serde(default)]
    pub additional_props: Vec<JsonValue>,
}

impl EntityRepresentation {
    pub fn with_properties(id: impl Into<String>, props: JsonValue) -> Self {
        Self {
            original_id: id.into(),
            additional_props: vec![props],
        }
    }
}

/// A single failure surfaced when a decision is `Deny`: the value FQN that
/// was missing entitlement for the requested action.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EntitlementFailure {
    pub attribute_value_fqn: String,
    pub action_name: String,
}

/// Final ALLOW/DENY result returned by [`crate::pdp::AccessPdp::check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessDecision {
    Allow,
    Deny { failures: Vec<EntitlementFailure> },
}

impl AccessDecision {
    pub fn is_allow(&self) -> bool {
        matches!(self, AccessDecision::Allow)
    }
    pub fn is_deny(&self) -> bool {
        matches!(self, AccessDecision::Deny { .. })
    }
}
