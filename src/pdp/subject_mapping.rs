//! Subject mapping evaluator.
//!
//! Rust port of `service/internal/subjectmappingbuiltin/subject_mapping_builtin.go`
//! and `subject_mapping_builtin_actions.go`. Given the in-memory subject mappings
//! attached to attribute values and a single entity representation, this
//! resolves the set of attribute value FQNs the entity is entitled to and the
//! actions allowed on each.

use std::collections::HashMap;

use serde_json::Value as JsonValue;

use super::PdpError;
use super::flatten::{Flattened, flatten, get_from_flattened};
use super::types::{
    Action, Condition, ConditionBooleanOperator, ConditionGroup, EntityRepresentation,
    SubjectMapping, SubjectMappingOperator, SubjectSet,
};

/// Map from attribute value FQN to the list of entitled actions on that value
/// for a single entity. Mirrors `AttributeValueFQNsToActions` in Go.
pub type ValueFqnToActions = HashMap<String, Vec<Action>>;

/// Evaluate every supplied subject mapping against the entity and return the
/// resulting entitlement map keyed by attribute value FQN.
///
/// `subject_mappings_by_value_fqn` is a slice of `(value_fqn, mapping)` pairs
/// rather than a map so callers can include multiple mappings per value.
pub(crate) fn evaluate_subject_mappings(
    mappings_by_value_fqn: &[(&str, &SubjectMapping)],
    entity: &EntityRepresentation,
) -> Result<ValueFqnToActions, PdpError> {
    let mut entitlements: ValueFqnToActions = HashMap::new();

    for prop_obj in entity.additional_props.iter() {
        let flattened = flatten(prop_obj).map_err(PdpError::Flatten)?;

        for (value_fqn, mapping) in mappings_by_value_fqn {
            let mut all_subject_sets_matched = true;
            for ss in mapping.subject_condition_set.subject_sets.iter() {
                if !evaluate_subject_set(ss, &flattened)? {
                    all_subject_sets_matched = false;
                    break;
                }
            }
            if !all_subject_sets_matched {
                continue;
            }
            // Mapping matched: merge in its actions (dedup by lowercase name).
            let actions = dedupe_actions(&mapping.actions);
            let entry = entitlements.entry((*value_fqn).to_string()).or_default();
            for action in actions {
                if !entry
                    .iter()
                    .any(|existing| eq_ignore_ascii_case(&existing.name, &action.name))
                {
                    entry.push(action);
                }
            }
        }
    }

    Ok(entitlements)
}

fn evaluate_subject_set(ss: &SubjectSet, entity: &Flattened) -> Result<bool, PdpError> {
    for cg in ss.condition_groups.iter() {
        if !evaluate_condition_group(cg, entity)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn evaluate_condition_group(cg: &ConditionGroup, entity: &Flattened) -> Result<bool, PdpError> {
    match cg.boolean_operator {
        ConditionBooleanOperator::And => {
            for c in cg.conditions.iter() {
                if !evaluate_condition(c, entity)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        ConditionBooleanOperator::Or => {
            for c in cg.conditions.iter() {
                if evaluate_condition(c, entity)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        ConditionBooleanOperator::Unspecified => Err(PdpError::UnspecifiedBooleanOperator),
    }
}

fn evaluate_condition(c: &Condition, entity: &Flattened) -> Result<bool, PdpError> {
    let mapped = get_from_flattened(entity, &c.subject_external_selector_value);
    match c.operator {
        SubjectMappingOperator::In => {
            for expected in c.subject_external_values.iter() {
                for actual in mapped.iter() {
                    if json_eq_string(actual, expected) {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        SubjectMappingOperator::NotIn => {
            for expected in c.subject_external_values.iter() {
                for actual in mapped.iter() {
                    if json_eq_string(actual, expected) {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        }
        SubjectMappingOperator::InContains => {
            for expected in c.subject_external_values.iter() {
                for actual in mapped.iter() {
                    if json_string_view(actual)
                        .map(|s| s.contains(expected.as_str()))
                        .unwrap_or(false)
                    {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        SubjectMappingOperator::Unspecified => Err(PdpError::UnspecifiedConditionOperator),
    }
}

fn json_eq_string(value: &JsonValue, expected: &str) -> bool {
    match value {
        JsonValue::String(s) => s == expected,
        JsonValue::Number(n) => n.to_string() == expected,
        JsonValue::Bool(b) => match expected {
            "true" => *b,
            "false" => !*b,
            _ => false,
        },
        _ => false,
    }
}

fn json_string_view(value: &JsonValue) -> Option<String> {
    match value {
        JsonValue::String(s) => Some(s.clone()),
        JsonValue::Number(n) => Some(n.to_string()),
        JsonValue::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Dedupe a list of actions by lowercased name (matches Go `dedupeSubjectMappingActions`).
fn dedupe_actions(actions: &[Action]) -> Vec<Action> {
    let mut seen: HashMap<String, Action> = HashMap::new();
    for a in actions {
        seen.entry(a.name.to_ascii_lowercase())
            .or_insert_with(|| a.clone());
    }
    seen.into_values().collect()
}

fn eq_ignore_ascii_case(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(test)]
mod tests {
    use super::super::types::*;
    use super::*;
    use serde_json::json;

    fn entity(props: serde_json::Value) -> EntityRepresentation {
        EntityRepresentation::with_properties("ent", json!({"properties": props}))
    }

    fn mapping(
        value_fqn: &str,
        sel: &str,
        vals: &[&str],
        op: SubjectMappingOperator,
    ) -> SubjectMapping {
        SubjectMapping {
            id: String::new(),
            attribute_value: Value {
                id: String::new(),
                fqn: value_fqn.to_string(),
                value: String::new(),
                subject_mappings: vec![],
            },
            subject_condition_set: SubjectConditionSet {
                id: String::new(),
                subject_sets: vec![SubjectSet {
                    condition_groups: vec![ConditionGroup {
                        boolean_operator: ConditionBooleanOperator::And,
                        conditions: vec![Condition {
                            subject_external_selector_value: sel.to_string(),
                            subject_external_values: vals.iter().map(|s| s.to_string()).collect(),
                            operator: op,
                        }],
                    }],
                }],
                namespace: None,
            },
            actions: vec![Action::new("read")],
            namespace: None,
        }
    }

    #[test]
    fn in_matches_string() {
        let sm = mapping(
            "v1",
            ".properties.clearance",
            &["secret"],
            SubjectMappingOperator::In,
        );
        let ent = entity(json!({"clearance": "secret"}));
        let res = evaluate_subject_mappings(&[("v1", &sm)], &ent).unwrap();
        assert!(res.contains_key("v1"));
    }

    #[test]
    fn in_does_not_match_when_wrong_value() {
        let sm = mapping(
            "v1",
            ".properties.clearance",
            &["secret"],
            SubjectMappingOperator::In,
        );
        let ent = entity(json!({"clearance": "public"}));
        let res = evaluate_subject_mappings(&[("v1", &sm)], &ent).unwrap();
        assert!(!res.contains_key("v1"));
    }

    #[test]
    fn in_matches_array_via_bracketless_selector() {
        let sm = mapping(
            "v1",
            ".properties.country[]",
            &["uk"],
            SubjectMappingOperator::In,
        );
        let ent = entity(json!({"country": ["us", "uk"]}));
        let res = evaluate_subject_mappings(&[("v1", &sm)], &ent).unwrap();
        assert!(res.contains_key("v1"));
    }

    #[test]
    fn not_in_matches_when_value_absent() {
        let sm = mapping(
            "v1",
            ".properties.clearance",
            &["topsecret"],
            SubjectMappingOperator::NotIn,
        );
        let ent = entity(json!({"clearance": "secret"}));
        let res = evaluate_subject_mappings(&[("v1", &sm)], &ent).unwrap();
        assert!(res.contains_key("v1"));
    }

    #[test]
    fn in_contains_matches_substring() {
        let sm = mapping(
            "v1",
            ".properties.email",
            &["@example.com"],
            SubjectMappingOperator::InContains,
        );
        let ent = entity(json!({"email": "alice@example.com"}));
        let res = evaluate_subject_mappings(&[("v1", &sm)], &ent).unwrap();
        assert!(res.contains_key("v1"));
    }
}
