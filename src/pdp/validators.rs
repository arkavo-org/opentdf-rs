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
    for v in &attr.values {
        if !v.fqn.starts_with(&expected_prefix) {
            return Err(PdpError::InvalidAttributeDefinition(format!(
                "value FQN {} must be a child of definition FQN {} (expected prefix {})",
                v.fqn, attr.fqn, expected_prefix
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
