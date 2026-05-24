//! The focused ALLOW/DENY decision engine.
//!
//! Rust port of the inner decision logic from
//! `service/internal/access/v2/pdp.go` and `evaluate.go`. The public surface is
//! deliberately narrow: build an [`AccessPdp`] from attribute definitions and
//! subject mappings, then call [`AccessPdp::check`] for each access request.

use std::collections::HashMap;

use thiserror::Error;

use super::flatten::FlattenError;
use super::identifier::{FullyQualifiedAttribute, IdentifierError};
use super::subject_mapping::{ValueFqnToActions, evaluate_subject_mappings};
use super::types::{
    AccessDecision, Action, Attribute, AttributeRule, EntitlementFailure, EntityRepresentation,
    SubjectMapping,
};
use super::validators::{validate_attribute, validate_subject_mapping};

/// Errors returned while building a PDP or evaluating a request.
#[derive(Debug, Error)]
pub enum PdpError {
    #[error("invalid attribute definition: {0}")]
    InvalidAttributeDefinition(String),
    #[error("invalid subject mapping: {0}")]
    InvalidSubjectMapping(String),
    #[error("invalid action: {0}")]
    InvalidAction(String),
    #[error("invalid resource: {0}")]
    InvalidResource(String),
    #[error("attribute definition not found for FQN: {0}")]
    DefinitionNotFound(String),
    #[error("attribute rule unspecified: {0}")]
    UnspecifiedRule(String),
    #[error("entity flattening failed: {0}")]
    Flatten(#[from] FlattenError),
    #[error("identifier parse error: {0}")]
    Identifier(#[from] IdentifierError),
    #[error("unspecified condition group boolean operator")]
    UnspecifiedBooleanOperator,
    #[error("unspecified subject mapping condition operator")]
    UnspecifiedConditionOperator,
}

/// Tunables for the PDP. Defaults to legacy (non-namespaced) action matching.
#[derive(Debug, Clone, Copy, Default)]
pub struct PdpOptions {
    /// When `true`, action matching enforces that the entitled action's
    /// namespace matches the namespace of the attribute being evaluated. Also
    /// causes subject mappings without a namespace to be skipped at index time.
    pub namespaced_policy: bool,
}

/// Indexed in-memory policy. Build once, then call [`AccessPdp::check`] per request.
#[derive(Debug)]
pub struct AccessPdp {
    /// All attribute definitions, keyed by definition FQN.
    attributes_by_def_fqn: HashMap<String, Attribute>,
    /// Entitleable attribute values, keyed by value FQN. Each entry carries the
    /// parent attribute (cloned) and any subject mappings that point at it.
    entitleable_values: HashMap<String, EntitleableValue>,
    opts: PdpOptions,
}

/// Internal: an attribute value enriched with the subject mappings pointing at it.
#[derive(Debug, Clone)]
struct EntitleableValue {
    parent: Attribute,
    /// Subject mappings whose `attribute_value.fqn` equals this value FQN.
    /// Stored as cloned mappings so the engine owns its policy.
    subject_mappings: Vec<SubjectMapping>,
}

impl AccessPdp {
    /// Build a PDP from the canonical set of attribute definitions and subject
    /// mappings. Both lists may be empty (the resulting PDP simply denies
    /// every request).
    pub fn new(
        attributes: Vec<Attribute>,
        subject_mappings: Vec<SubjectMapping>,
        opts: PdpOptions,
    ) -> Result<Self, PdpError> {
        let mut attributes_by_def_fqn = HashMap::new();
        let mut entitleable_values: HashMap<String, EntitleableValue> = HashMap::new();

        for attr in attributes {
            validate_attribute(&attr)?;
            // Seed lookup for every declared value FQN.
            for v in &attr.values {
                entitleable_values.insert(
                    v.fqn.clone(),
                    EntitleableValue {
                        parent: attr.clone(),
                        subject_mappings: v.subject_mappings.clone(),
                    },
                );
            }
            attributes_by_def_fqn.insert(attr.fqn.clone(), attr);
        }

        for sm in subject_mappings {
            validate_subject_mapping(&sm)?;
            if opts.namespaced_policy {
                let has_ns = sm
                    .namespace
                    .as_ref()
                    .map(|ns| !ns.id.is_empty() || !ns.fqn.is_empty())
                    .unwrap_or(false);
                if !has_ns {
                    // Strict namespaced mode skips unnamespaced subject mappings.
                    continue;
                }
            }
            let value_fqn = sm.attribute_value.fqn.clone();
            if let Some(entry) = entitleable_values.get_mut(&value_fqn) {
                entry.subject_mappings.push(sm);
            } else {
                // Subject mapping points at a value whose definition we haven't
                // seen; resolve the parent from the FQN.
                let parent_fqn = parent_def_fqn(&value_fqn)?;
                let parent = attributes_by_def_fqn
                    .get(&parent_fqn)
                    .ok_or_else(|| PdpError::DefinitionNotFound(parent_fqn.clone()))?
                    .clone();
                entitleable_values.insert(
                    value_fqn,
                    EntitleableValue {
                        parent,
                        subject_mappings: vec![sm],
                    },
                );
            }
        }

        Ok(Self {
            attributes_by_def_fqn,
            entitleable_values,
            opts,
        })
    }

    /// Decide whether `entity` may perform `action` on a resource described by
    /// `resource_attribute_value_fqns`. The decision is `Allow` iff every
    /// attribute definition referenced by the resource passes its rule:
    ///
    /// - `AllOf`: the entity has the action on **every** referenced value.
    /// - `AnyOf`: the entity has the action on **at least one** referenced value.
    /// - `Hierarchy`: the entity has the action on the highest referenced value
    ///   or any value above it in the definition's ordered list.
    ///
    /// Unknown value FQNs and missing definitions both cause a `Deny`.
    pub fn check(
        &self,
        entity: &EntityRepresentation,
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

        // Normalize and validate resource FQNs (lowercase, all known).
        let mut value_fqns = Vec::with_capacity(resource_attribute_value_fqns.len());
        let mut missing: Vec<String> = Vec::new();
        for raw in resource_attribute_value_fqns {
            let normalized = raw.to_ascii_lowercase();
            if !self.entitleable_values.contains_key(&normalized) {
                missing.push(normalized);
            } else {
                value_fqns.push(normalized);
            }
        }
        if !missing.is_empty() {
            // Match Go behavior: any unknown FQN denies the whole resource.
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

        // Compute the relevant decisionable-attributes set, expanded with
        // hierarchically-higher values so the entity can satisfy a HIERARCHY
        // rule by being entitled to a higher value than the resource carries.
        let decisionable = self.build_decisionable(&value_fqns);

        // Resolve the entity's entitlements against just those values.
        let mappings_to_eval: Vec<(&str, &SubjectMapping)> = decisionable
            .iter()
            .flat_map(|fqn| {
                self.entitleable_values
                    .get(fqn)
                    .into_iter()
                    .flat_map(move |ev| {
                        ev.subject_mappings.iter().map(move |sm| (fqn.as_str(), sm))
                    })
            })
            .collect();
        let entitlements = evaluate_subject_mappings(&mappings_to_eval, entity)?;

        // Group resource value FQNs by their parent attribute definition.
        let mut by_def: HashMap<String, Vec<String>> = HashMap::new();
        for fqn in &value_fqns {
            let parent_fqn = self
                .entitleable_values
                .get(fqn)
                .map(|ev| ev.parent.fqn.clone())
                .ok_or_else(|| PdpError::DefinitionNotFound(fqn.clone()))?;
            by_def.entry(parent_fqn).or_default().push(fqn.clone());
        }

        // Evaluate each definition's rule. The resource passes iff every rule passes.
        let mut all_failures: Vec<EntitlementFailure> = Vec::new();
        for (def_fqn, fqns) in by_def {
            let definition = self
                .attributes_by_def_fqn
                .get(&def_fqn)
                .ok_or_else(|| PdpError::DefinitionNotFound(def_fqn.clone()))?;
            let namespace_fqn = definition
                .namespace
                .as_ref()
                .map(|ns| ns.fqn.clone())
                .unwrap_or_default();
            let failures = match definition.rule {
                AttributeRule::AllOf => {
                    self.all_of_rule(&entitlements, action, &fqns, &namespace_fqn)
                }
                AttributeRule::AnyOf => {
                    self.any_of_rule(&entitlements, action, &fqns, &namespace_fqn)
                }
                AttributeRule::Hierarchy => {
                    self.hierarchy_rule(&entitlements, action, &fqns, definition, &namespace_fqn)
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

    /// Expand the resource's value FQNs with hierarchically-higher siblings so
    /// the entity's entitlement to a higher value satisfies a HIERARCHY rule.
    fn build_decisionable(&self, resource_value_fqns: &[String]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for fqn in resource_value_fqns {
            if seen.insert(fqn.clone()) {
                out.push(fqn.clone());
            }
            let Some(ev) = self.entitleable_values.get(fqn) else {
                continue;
            };
            if !matches!(ev.parent.rule, AttributeRule::Hierarchy) {
                continue;
            }
            // Add every value strictly above this one in the definition's order.
            for v in ev.parent.values.iter() {
                if v.fqn == *fqn {
                    break;
                }
                if seen.insert(v.fqn.clone()) {
                    out.push(v.fqn.clone());
                }
            }
        }
        out
    }

    fn all_of_rule(
        &self,
        entitlements: &ValueFqnToActions,
        action: &Action,
        resource_value_fqns: &[String],
        required_namespace_fqn: &str,
    ) -> Vec<EntitlementFailure> {
        let mut failures = Vec::new();
        for value_fqn in resource_value_fqns {
            if !self.value_has_action(entitlements, value_fqn, action, required_namespace_fqn) {
                failures.push(EntitlementFailure {
                    attribute_value_fqn: value_fqn.clone(),
                    action_name: action.name.clone(),
                });
            }
        }
        failures
    }

    fn any_of_rule(
        &self,
        entitlements: &ValueFqnToActions,
        action: &Action,
        resource_value_fqns: &[String],
        required_namespace_fqn: &str,
    ) -> Vec<EntitlementFailure> {
        if resource_value_fqns.is_empty() {
            return Vec::new();
        }
        let mut failures = Vec::new();
        let mut any_match = false;
        for value_fqn in resource_value_fqns {
            if self.value_has_action(entitlements, value_fqn, action, required_namespace_fqn) {
                any_match = true;
            } else {
                failures.push(EntitlementFailure {
                    attribute_value_fqn: value_fqn.clone(),
                    action_name: action.name.clone(),
                });
            }
        }
        if any_match { Vec::new() } else { failures }
    }

    fn hierarchy_rule(
        &self,
        entitlements: &ValueFqnToActions,
        action: &Action,
        resource_value_fqns: &[String],
        definition: &Attribute,
        required_namespace_fqn: &str,
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
        for (entitled_fqn, actions) in entitlements {
            if let Some(&i) = value_index.get(entitled_fqn.as_str())
                && i <= lowest_idx
                && actions.iter().any(|a| {
                    is_requested_action_match(
                        action,
                        required_namespace_fqn,
                        a,
                        self.opts.namespaced_policy,
                    )
                })
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

    fn value_has_action(
        &self,
        entitlements: &ValueFqnToActions,
        value_fqn: &str,
        action: &Action,
        required_namespace_fqn: &str,
    ) -> bool {
        let Some(actions) = entitlements.get(value_fqn) else {
            return false;
        };
        actions.iter().any(|a| {
            is_requested_action_match(
                action,
                required_namespace_fqn,
                a,
                self.opts.namespaced_policy,
            )
        })
    }
}

/// Action identity matching — Rust port of `isRequestedActionMatch` in `evaluate.go`.
///
/// 1. If the request carries an action `id`, it is authoritative; otherwise
///    names are matched case-insensitively.
/// 2. If the request carries an explicit `namespace`, the entitled action's
///    namespace must match (by id, otherwise by fqn case-insensitively).
/// 3. Under strict `namespaced_policy`, the entitled action's namespace must
///    additionally match the namespace FQN of the resource's attribute
///    definition.
fn is_requested_action_match(
    requested: &Action,
    required_namespace_fqn: &str,
    entitled: &Action,
    namespaced_policy: bool,
) -> bool {
    if !requested.id.is_empty() {
        if requested.id != entitled.id {
            return false;
        }
    } else {
        if requested.name.is_empty() || !requested.name.eq_ignore_ascii_case(&entitled.name) {
            return false;
        }
    }

    if let Some(req_ns) = requested.namespace.as_ref()
        && !req_ns.is_empty_identity()
    {
        let entitled_ns = match entitled.namespace.as_ref() {
            Some(ns) => ns,
            None => return false,
        };
        if !req_ns.id.is_empty() {
            if entitled_ns.id != req_ns.id {
                return false;
            }
        } else if !req_ns.fqn.is_empty() && !entitled_ns.fqn.eq_ignore_ascii_case(&req_ns.fqn) {
            return false;
        }
    }

    if !namespaced_policy {
        return true;
    }

    if required_namespace_fqn.is_empty() {
        return false;
    }
    let entitled_ns = match entitled.namespace.as_ref() {
        Some(ns) => ns,
        None => return false,
    };
    if entitled_ns.id.is_empty() {
        return false;
    }
    entitled_ns.fqn == required_namespace_fqn
}

fn parent_def_fqn(value_fqn: &str) -> Result<String, PdpError> {
    let parsed = FullyQualifiedAttribute::parse(value_fqn)?;
    let def = FullyQualifiedAttribute {
        namespace: parsed.namespace,
        name: parsed.name,
        value: String::new(),
    };
    Ok(def.fqn())
}
