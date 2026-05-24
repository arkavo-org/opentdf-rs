//! Validation helpers used when indexing the in-memory policy and at check time.
//!
//! Mirrors `service/internal/access/v2/validators.go`, trimmed to the subset
//! used by the focused ALLOW/DENY API.

use super::PdpError;
use super::types::{Attribute, AttributeRule, SubjectMapping};

pub(crate) fn validate_attribute(attr: &Attribute) -> Result<(), PdpError> {
    if attr.fqn.is_empty() {
        return Err(PdpError::InvalidAttributeDefinition(
            "attribute FQN is empty".into(),
        ));
    }
    for v in &attr.values {
        if !v.fqn.starts_with(&attr.fqn) {
            return Err(PdpError::InvalidAttributeDefinition(format!(
                "value FQN {} must be of definition FQN {}",
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

pub(crate) fn validate_subject_mapping(sm: &SubjectMapping) -> Result<(), PdpError> {
    if sm.attribute_value.fqn.is_empty() {
        return Err(PdpError::InvalidSubjectMapping(
            "subject mapping's attribute value FQN is empty".into(),
        ));
    }
    Ok(())
}
