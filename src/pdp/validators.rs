//! Validation helpers used when indexing the in-memory policy.

use super::PdpError;
use super::types::{Attribute, AttributeRule};

pub(crate) fn validate_attribute(attr: &Attribute) -> Result<(), PdpError> {
    if attr.fqn.is_empty() {
        return Err(PdpError::InvalidAttributeDefinition(
            "attribute FQN is empty".into(),
        ));
    }
    // A value FQN must be a child of the definition FQN under `/value/`.
    // `starts_with(attr.fqn)` alone is insufficient because it would accept
    // sibling names that share a prefix — e.g. attr `https://x/attr/foo`
    // would otherwise admit value `https://x/attr/foobar/value/x`.
    let expected_prefix = format!("{}/value/", attr.fqn);
    let mut seen_values = std::collections::HashSet::with_capacity(attr.values.len());
    for v in &attr.values {
        let Some(value_part) = v.fqn.strip_prefix(&expected_prefix) else {
            return Err(PdpError::InvalidAttributeDefinition(format!(
                "value FQN {} must be a child of definition FQN {} (expected prefix {})",
                v.fqn, attr.fqn, expected_prefix
            )));
        };
        if value_part.is_empty() || value_part.contains("/value/") {
            return Err(PdpError::InvalidAttributeDefinition(format!(
                "value FQN {} has empty or nested value component",
                v.fqn
            )));
        }
        if !seen_values.insert(v.fqn.as_str()) {
            return Err(PdpError::InvalidAttributeDefinition(format!(
                "duplicate value FQN {} in attribute {}",
                v.fqn, attr.fqn
            )));
        }
    }
    if matches!(attr.rule, AttributeRule::Unspecified) {
        return Err(PdpError::InvalidAttributeDefinition(format!(
            "attribute rule is unspecified for {}",
            attr.fqn
        )));
    }
    Ok(())
}
