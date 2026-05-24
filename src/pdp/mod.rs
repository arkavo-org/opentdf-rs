//! Local Access Policy Decision Point.
//!
//! Brings the OpenTDF Authorization Service's decision logic in-process so a
//! PEP can answer ALLOW / DENY in microseconds without round-tripping to the
//! Authorization Service on every request.
//!
//! The PDP holds **attribute definitions only**. Identity-to-attribute
//! resolution (subject mappings) belongs on the platform's entitlement
//! service, which is the only component that needs to see those mappings.
//! At request time the PEP extracts entitlements from its access token —
//! typically the `authorization_details` claim returned by the platform's
//! token-exchange endpoint — and passes them to [`AccessPdp::check`] along
//! with the requested action and the resource's attribute tags.
//!
//! The PDP runs the attribute-definition rule locally:
//! [`AttributeRule::AllOf`], [`AttributeRule::AnyOf`], or
//! [`AttributeRule::Hierarchy`].
//!
//! # Example
//!
//! ```
//! use std::collections::HashMap;
//! use opentdf::pdp::{
//!     AccessPdp, Action, Attribute, AttributeRule, PdpOptions, Value,
//! };
//!
//! // Load policy once at startup (e.g. from a periodic refresh of the
//! // platform's attribute service).
//! let classification = Attribute {
//!     fqn: "https://acme.com/attr/classification".into(),
//!     rule: AttributeRule::Hierarchy,
//!     values: vec![
//!         Value { fqn: "https://acme.com/attr/classification/value/topsecret".into(),
//!                 value: "topsecret".into(), ..Default::default() },
//!         Value { fqn: "https://acme.com/attr/classification/value/secret".into(),
//!                 value: "secret".into(), ..Default::default() },
//!         Value { fqn: "https://acme.com/attr/classification/value/public".into(),
//!                 value: "public".into(), ..Default::default() },
//!     ],
//!     ..Default::default()
//! };
//! let pdp = AccessPdp::new(vec![classification], PdpOptions::default()).unwrap();
//!
//! // Per request: build the entitlement map from the verified access token.
//! // Here we hard-code one for the doc; real PEPs extract this from claims.
//! let mut entitlements: HashMap<String, Vec<String>> = HashMap::new();
//! entitlements.insert(
//!     "https://acme.com/attr/classification/value/topsecret".into(),
//!     vec!["read".into()],
//! );
//!
//! // The HIERARCHY rule lets a TOPSECRET entitlement satisfy a SECRET
//! // resource requirement — and the PDP figures that out locally.
//! let decision = pdp.check(
//!     &entitlements,
//!     &Action::new("read"),
//!     &["https://acme.com/attr/classification/value/secret".to_string()],
//! ).unwrap();
//! assert!(decision.is_allow());
//! ```

mod engine;
mod identifier;
mod types;
mod validators;

#[cfg(test)]
mod tests;

pub use engine::{AccessPdp, Entitlements, PdpError, PdpOptions};
pub use identifier::{
    FullyQualifiedAttribute, FullyQualifiedRegisteredResourceValue, IdentifierError,
};
pub use types::{
    AccessDecision, Action, Attribute, AttributeRule, EntitlementFailure, Namespace, Value,
};
