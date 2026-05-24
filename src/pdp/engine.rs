//! The focused ALLOW/DENY Access PDP.
//!
//! The PDP holds attribute definitions and evaluates the
//! attribute-definition rule (ALL_OF / ANY_OF / HIERARCHY) **locally in the
//! SDK** against entitlements the PEP extracts from an access token. There
//! is no subject-mapping resolution and no entity-property handling — both
//! belong on the platform's entitlement service so identity-to-attribute
//! mappings (which carry sensitive selectors) never ship to the PEP.

use std::collections::{HashMap, HashSet};

use thiserror::Error;

use super::types::{AccessDecision, Action, Attribute, AttributeRule, EntitlementFailure};
use super::validators::validate_attribute;

/// Map from attribute value FQN to the action names the entity is entitled
/// to perform on that value. Typically built by the PEP from its
/// access-token claims (e.g. flattening an RFC 9396 `authorization_details`
/// grant set into per-FQN action lists).
pub type Entitlements = HashMap<String, Vec<String>>;

/// Errors returned while building a PDP or evaluating a request.
#[derive(Debug, Error)]
pub enum PdpError {
    #[error("invalid attribute definition: {0}")]
    InvalidAttributeDefinition(String),
    #[error("invalid action: {0}")]
    InvalidAction(String),
    #[error("invalid resource: {0}")]
    InvalidResource(String),
    #[error("attribute rule unspecified: {0}")]
    UnspecifiedRule(String),
}

/// Tunables for the PDP. Reserved for future options; currently empty.
#[derive(Debug, Clone, Copy, Default)]
pub struct PdpOptions {
    #[doc(hidden)]
    pub _reserved: (),
}

/// Indexed in-memory policy. Build once with the attribute definitions the
/// PEP cares about, then call [`check`](Self::check) per request.
#[derive(Debug)]
pub struct AccessPdp {
    /// All attribute definitions, keyed by definition FQN.
    attributes_by_def_fqn: HashMap<String, Attribute>,
    /// Parent-definition FQN for each known value FQN (used to group resource
    /// FQNs and to detect unknown value FQNs at check time).
    parent_def_by_value_fqn: HashMap<String, String>,
}

impl AccessPdp {
    /// Build a PDP from the set of attribute definitions. May be empty
    /// (the resulting PDP denies every request — no known value FQNs).
    pub fn new(attributes: Vec<Attribute>, _opts: PdpOptions) -> Result<Self, PdpError> {
        let mut attributes_by_def_fqn = HashMap::new();
        let mut parent_def_by_value_fqn = HashMap::new();

        for attr in attributes {
            validate_attribute(&attr)?;
            for v in &attr.values {
                parent_def_by_value_fqn.insert(v.fqn.clone(), attr.fqn.clone());
            }
            attributes_by_def_fqn.insert(attr.fqn.clone(), attr);
        }

        Ok(Self {
            attributes_by_def_fqn,
            parent_def_by_value_fqn,
        })
    }

    /// Decide whether the caller — represented by `entitlements` extracted
    /// from their access token — may perform `action` on a resource described
    /// by `resource_attribute_value_fqns`.
    ///
    /// `entitlements` maps each entitled attribute value FQN to the action
    /// names allowed on that value. The map is typically derived from the
    /// access token's `authorization_details` (or equivalent) claim by the
    /// PEP; the PDP performs no token parsing of its own.
    ///
    /// The decision is `Allow` iff every attribute definition referenced by
    /// the resource passes its rule:
    ///
    /// - `AllOf`: the entity holds the action on **every** referenced value.
    /// - `AnyOf`: the entity holds the action on **at least one** referenced value.
    /// - `Hierarchy`: the entity holds the action on the highest referenced
    ///   value or any value above it in the definition's ordered list.
    ///
    /// Unknown value FQNs and unspecified rules both produce a `Deny` /
    /// error respectively. Action and FQN matching are case-insensitive.
    pub fn check(
        &self,
        entitlements: &Entitlements,
        action: &Action,
        resource_attribute_value_fqns: &[String],
    ) -> Result<AccessDecision, PdpError> {
        if action.name.is_empty() {
            return Err(PdpError::InvalidAction("action name required".into()));
        }
        if resource_attribute_value_fqns.is_empty() {
            return Err(PdpError::InvalidResource(
                "at least one attribute value FQN required".into(),
            ));
        }

        // Normalize entitlements to lowercase keys once.
        let normalized_entitlements: HashMap<String, Vec<String>> = entitlements
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
            .collect();

        // Normalize resource FQNs and partition into known / unknown.
        let mut value_fqns: Vec<String> = Vec::with_capacity(resource_attribute_value_fqns.len());
        let mut missing: Vec<String> = Vec::new();
        for raw in resource_attribute_value_fqns {
            let normalized = raw.to_ascii_lowercase();
            if !self.parent_def_by_value_fqn.contains_key(&normalized) {
                missing.push(normalized);
            } else {
                value_fqns.push(normalized);
            }
        }
        if !missing.is_empty() {
            return Ok(AccessDecision::Deny {
                failures: missing
                    .into_iter()
                    .map(|fqn| EntitlementFailure {
                        attribute_value_fqn: fqn,
                        action_name: action.name.clone(),
                    })
                    .collect(),
            });
        }

        // Group resource value FQNs by parent attribute definition.
        let mut by_def: HashMap<String, Vec<String>> = HashMap::new();
        for fqn in &value_fqns {
            let parent_fqn = self
                .parent_def_by_value_fqn
                .get(fqn)
                .expect("checked above")
                .clone();
            by_def.entry(parent_fqn).or_default().push(fqn.clone());
        }

        // Evaluate each definition's rule. The resource passes iff every rule passes.
        let mut all_failures: Vec<EntitlementFailure> = Vec::new();
        for (def_fqn, fqns) in by_def {
            let definition = self
                .attributes_by_def_fqn
                .get(&def_fqn)
                .expect("populated alongside parent_def_by_value_fqn");
            let failures = match definition.rule {
                AttributeRule::AllOf => all_of_rule(&normalized_entitlements, action, &fqns),
                AttributeRule::AnyOf => any_of_rule(&normalized_entitlements, action, &fqns),
                AttributeRule::Hierarchy => {
                    hierarchy_rule(&normalized_entitlements, action, &fqns, definition)
                }
                AttributeRule::Unspecified => {
                    return Err(PdpError::UnspecifiedRule(def_fqn));
                }
            };
            all_failures.extend(failures);
        }

        if all_failures.is_empty() {
            Ok(AccessDecision::Allow)
        } else {
            Ok(AccessDecision::Deny {
                failures: all_failures,
            })
        }
    }
}

fn value_has_action(entitlements: &Entitlements, value_fqn: &str, action: &Action) -> bool {
    entitlements
        .get(value_fqn)
        .map(|acts| acts.iter().any(|a| a.eq_ignore_ascii_case(&action.name)))
        .unwrap_or(false)
}

fn all_of_rule(
    entitlements: &Entitlements,
    action: &Action,
    resource_value_fqns: &[String],
) -> Vec<EntitlementFailure> {
    let mut failures = Vec::new();
    for fqn in resource_value_fqns {
        if !value_has_action(entitlements, fqn, action) {
            failures.push(EntitlementFailure {
                attribute_value_fqn: fqn.clone(),
                action_name: action.name.clone(),
            });
        }
    }
    failures
}

fn any_of_rule(
    entitlements: &Entitlements,
    action: &Action,
    resource_value_fqns: &[String],
) -> Vec<EntitlementFailure> {
    if resource_value_fqns.is_empty() {
        return Vec::new();
    }
    let mut failures = Vec::new();
    let mut any_match = false;
    for fqn in resource_value_fqns {
        if value_has_action(entitlements, fqn, action) {
            any_match = true;
        } else {
            failures.push(EntitlementFailure {
                attribute_value_fqn: fqn.clone(),
                action_name: action.name.clone(),
            });
        }
    }
    if any_match { Vec::new() } else { failures }
}

fn hierarchy_rule(
    entitlements: &Entitlements,
    action: &Action,
    resource_value_fqns: &[String],
    definition: &Attribute,
) -> Vec<EntitlementFailure> {
    if resource_value_fqns.is_empty() {
        return Vec::new();
    }
    let value_index: HashMap<&str, usize> = definition
        .values
        .iter()
        .enumerate()
        .map(|(i, v)| (v.fqn.as_str(), i))
        .collect();

    // Find the lowest-indexed (highest-hierarchy) resource value.
    let mut lowest_idx = definition.values.len();
    for fqn in resource_value_fqns {
        if let Some(&i) = value_index.get(fqn.as_str())
            && i < lowest_idx
        {
            lowest_idx = i;
        }
    }
    // Any entitled FQN at or above that level with the right action satisfies.
    let mut seen: HashSet<&str> = HashSet::new();
    for entitled_fqn in entitlements.keys() {
        if !seen.insert(entitled_fqn.as_str()) {
            continue;
        }
        if let Some(&i) = value_index.get(entitled_fqn.as_str())
            && i <= lowest_idx
            && value_has_action(entitlements, entitled_fqn, action)
        {
            return Vec::new();
        }
    }
    // No satisfying entitlement — report failures for every resource value.
    resource_value_fqns
        .iter()
        .map(|fqn| EntitlementFailure {
            attribute_value_fqn: fqn.clone(),
            action_name: action.name.clone(),
        })
        .collect()
}
