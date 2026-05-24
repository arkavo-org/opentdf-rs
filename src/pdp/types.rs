//! Policy data types used by the Access PDP.
//!
//! The PDP holds **attribute definitions only** (the rules ALL_OF / ANY_OF /
//! HIERARCHY need to know about). It does **not** hold subject mappings —
//! identity-to-attribute resolution is the entitlement service's job and its
//! output (a set of entitled value FQNs + allowed actions) is what the PEP
//! passes to [`crate::pdp::AccessPdp::check`].

use serde::{Deserialize, Serialize};

/// How an attribute definition's values combine when present on a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum AttributeRule {
    #[default]
    Unspecified,
    AllOf,
    AnyOf,
    Hierarchy,
}

/// A namespace reference. Carried on attribute definitions for diagnostics;
/// not used in decision logic now that subject-mapping resolution lives
/// server-side.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Namespace {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub fqn: String,
}

/// Named action on a resource (e.g. `read`, `create`).
///
/// The PDP matches actions by name only (case-insensitive). Action namespace
/// matching belongs in the entitlement service, which has already resolved
/// it by the time entitlements reach the PEP.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Action {
    pub name: String,
}

impl Action {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// A single attribute value (e.g. `https://acme.com/attr/clearance/value/secret`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Value {
    #[serde(default)]
    pub id: String,
    pub fqn: String,
    pub value: String,
}

/// An attribute definition. Holds the rule and (optionally) an ordered list
/// of values. For HIERARCHY rules the order matters — higher-privilege values
/// come first.
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
