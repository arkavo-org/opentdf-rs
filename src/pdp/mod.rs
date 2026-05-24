//! Local Access Policy Decision Point.
//!
//! This module is a Rust port of the OpenTDF platform's internal access PDP
//! (`service/internal/access/v2`), narrowed to a focused **ALLOW / DENY** API.
//! There is no `GetDecision` or `GetEntitlements` surface here — the engine
//! answers a single, scoped question:
//!
//! > *Given this entity, may it perform this action on a resource described by
//! > these attribute value FQNs?*
//!
//! This lets a Policy Enforcement Point evaluate access locally for resources
//! that are tagged with policy attributes but not stored as TDFs.
//!
//! # Example
//!
//! ```
//! use opentdf::pdp::{
//!     AccessPdp, Action, Attribute, AttributeRule, Condition, ConditionBooleanOperator,
//!     ConditionGroup, EntityRepresentation, PdpOptions, SubjectConditionSet, SubjectMapping,
//!     SubjectMappingOperator, SubjectSet, Value,
//! };
//! use serde_json::json;
//!
//! let secret_fqn = "https://demo.com/attr/clearance/value/secret".to_string();
//! let attr = Attribute {
//!     fqn: "https://demo.com/attr/clearance".to_string(),
//!     rule: AttributeRule::Hierarchy,
//!     values: vec![
//!         Value { fqn: "https://demo.com/attr/clearance/value/topsecret".into(), value: "topsecret".into(), ..Default::default() },
//!         Value { fqn: secret_fqn.clone(), value: "secret".into(), ..Default::default() },
//!         Value { fqn: "https://demo.com/attr/clearance/value/public".into(), value: "public".into(), ..Default::default() },
//!     ],
//!     ..Default::default()
//! };
//!
//! let mapping = SubjectMapping {
//!     attribute_value: Value { fqn: secret_fqn.clone(), value: "secret".into(), ..Default::default() },
//!     subject_condition_set: SubjectConditionSet {
//!         subject_sets: vec![SubjectSet {
//!             condition_groups: vec![ConditionGroup {
//!                 boolean_operator: ConditionBooleanOperator::And,
//!                 conditions: vec![Condition {
//!                     subject_external_selector_value: ".properties.clearance".into(),
//!                     subject_external_values: vec!["secret".into()],
//!                     operator: SubjectMappingOperator::In,
//!                 }],
//!             }],
//!         }],
//!         ..Default::default()
//!     },
//!     actions: vec![Action::new("read")],
//!     ..Default::default()
//! };
//!
//! let pdp = AccessPdp::new(vec![attr], vec![mapping], PdpOptions::default()).unwrap();
//!
//! let entity = EntityRepresentation::with_properties(
//!     "alice",
//!     json!({"properties": {"clearance": "secret"}}),
//! );
//!
//! let decision = pdp
//!     .check(&entity, &Action::new("read"), &[secret_fqn])
//!     .unwrap();
//! assert!(decision.is_allow());
//! ```

mod engine;
mod flatten;
mod identifier;
mod subject_mapping;
mod types;
mod validators;

#[cfg(test)]
mod tests;

pub use engine::{AccessPdp, PdpError, PdpOptions};
pub use identifier::{
    FullyQualifiedAttribute, FullyQualifiedRegisteredResourceValue, IdentifierError,
};
pub use types::{
    AccessDecision, Action, Attribute, AttributeRule, Condition, ConditionBooleanOperator,
    ConditionGroup, EntitlementFailure, EntityRepresentation, Namespace, SubjectConditionSet,
    SubjectMapping, SubjectMappingOperator, SubjectSet, Value,
};
