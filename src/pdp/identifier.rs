//! Platform-style fully-qualified identifiers for attributes and registered resource values.
//!
//! Rust port of `lib/identifier/attribute.go` and `lib/identifier/registered_resource_value.go`
//! from the OpenTDF platform repo. Kept separate from the legacy `crate::fqn` module so the
//! two FQN flavors do not collide.

use std::fmt;

use thiserror::Error;

/// Errors produced while parsing a Platform-style FQN.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdentifierError {
    /// The string did not match any recognized FQN form.
    #[error(
        "invalid FQN format: must be https://<namespace>, https://<namespace>/attr/<name>, https://<namespace>/attr/<name>/value/<value>, or https://[<namespace>/]resm/<name>/value/<value>"
    )]
    InvalidFormat,
    /// Found a namespace, name, or value that is malformed.
    #[error("invalid FQN component: {0}")]
    InvalidComponent(String),
}

fn is_valid_namespace_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }
    let bytes = label.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    label
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn is_valid_namespace(ns: &str) -> bool {
    !ns.is_empty() && ns.split('.').all(is_valid_namespace_label)
}

fn is_valid_object_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A fully-qualified attribute identifier. FQNs are normalized to lowercase to
/// match the Go implementation, which lowercases the joined URL.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct FullyQualifiedAttribute {
    pub namespace: String,
    pub name: String,
    pub value: String,
}

impl FullyQualifiedAttribute {
    pub fn new(
        namespace: impl Into<String>,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
            value: value.into(),
        }
    }

    /// Canonical lowercased FQN string.
    pub fn fqn(&self) -> String {
        let mut s =
            String::with_capacity(self.namespace.len() + self.name.len() + self.value.len() + 32);
        s.push_str("https://");
        s.push_str(&self.namespace);
        if !self.name.is_empty() {
            s.push_str("/attr/");
            s.push_str(&self.name);
            if !self.value.is_empty() {
                s.push_str("/value/");
                s.push_str(&self.value);
            }
        }
        s.to_lowercase()
    }

    /// Parse an attribute FQN in any of the three accepted forms.
    pub fn parse(fqn: &str) -> Result<Self, IdentifierError> {
        let rest = fqn
            .strip_prefix("https://")
            .ok_or(IdentifierError::InvalidFormat)?;

        // namespace-only
        if !rest.contains('/') {
            let ns = rest.to_lowercase();
            if !is_valid_namespace(&ns) {
                return Err(IdentifierError::InvalidComponent(format!("namespace {ns}")));
            }
            return Ok(Self {
                namespace: ns,
                name: String::new(),
                value: String::new(),
            });
        }

        let (ns, after_ns) = rest.split_once('/').ok_or(IdentifierError::InvalidFormat)?;
        let attr_tail = after_ns
            .strip_prefix("attr/")
            .ok_or(IdentifierError::InvalidFormat)?;

        let ns = ns.to_lowercase();
        if !is_valid_namespace(&ns) {
            return Err(IdentifierError::InvalidComponent(format!("namespace {ns}")));
        }

        match attr_tail.split_once("/value/") {
            Some((name, value)) => {
                if name.is_empty() || name.contains('/') || value.contains('/') {
                    return Err(IdentifierError::InvalidFormat);
                }
                let name = name.to_lowercase();
                let value = value.to_lowercase();
                if !is_valid_object_name(&name) || !is_valid_object_name(&value) {
                    return Err(IdentifierError::InvalidComponent(format!(
                        "name {name}, value {value}"
                    )));
                }
                Ok(Self {
                    namespace: ns,
                    name,
                    value,
                })
            }
            None => {
                if attr_tail.is_empty() || attr_tail.contains('/') {
                    return Err(IdentifierError::InvalidFormat);
                }
                let name = attr_tail.to_lowercase();
                if !is_valid_object_name(&name) {
                    return Err(IdentifierError::InvalidComponent(format!("name {name}")));
                }
                Ok(Self {
                    namespace: ns,
                    name,
                    value: String::new(),
                })
            }
        }
    }
}

impl fmt::Display for FullyQualifiedAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.fqn())
    }
}

/// A fully-qualified registered resource value identifier. Namespace is optional
/// for backward compatibility with the legacy non-namespaced mode.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct FullyQualifiedRegisteredResourceValue {
    pub namespace: String,
    pub name: String,
    pub value: String,
}

impl FullyQualifiedRegisteredResourceValue {
    pub fn new(
        namespace: impl Into<String>,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
            value: value.into(),
        }
    }

    pub fn fqn(&self) -> String {
        let mut s = String::from("https://");
        if !self.namespace.is_empty() {
            s.push_str(&self.namespace);
            s.push('/');
        }
        s.push_str("resm/");
        s.push_str(&self.name);
        s.push_str("/value/");
        s.push_str(&self.value);
        s.to_lowercase()
    }

    pub fn parse(fqn: &str) -> Result<Self, IdentifierError> {
        let rest = fqn
            .strip_prefix("https://")
            .ok_or(IdentifierError::InvalidFormat)?;

        // Split into optional namespace and the resm tail.
        let (ns, after) = match rest.split_once("/resm/") {
            Some(("", _)) => return Err(IdentifierError::InvalidFormat),
            Some((maybe_ns, after)) => {
                if maybe_ns == "resm" {
                    // The string was actually "resm/..." with no leading namespace; fall through.
                    return Self::parse_no_namespace_tail(after);
                }
                (maybe_ns.to_lowercase(), after)
            }
            None => return Self::parse_no_namespace_form(rest),
        };

        let (name, value) = split_name_value(after)?;
        let ns_owned = ns;
        if !is_valid_namespace(&ns_owned) {
            return Err(IdentifierError::InvalidComponent(format!(
                "namespace {ns_owned}"
            )));
        }
        if !is_valid_object_name(&name) || !is_valid_object_name(&value) {
            return Err(IdentifierError::InvalidComponent(format!(
                "name {name}, value {value}"
            )));
        }
        Ok(Self {
            namespace: ns_owned,
            name,
            value,
        })
    }

    fn parse_no_namespace_form(rest: &str) -> Result<Self, IdentifierError> {
        let after = rest
            .strip_prefix("resm/")
            .ok_or(IdentifierError::InvalidFormat)?;
        Self::parse_no_namespace_tail(after)
    }

    fn parse_no_namespace_tail(after: &str) -> Result<Self, IdentifierError> {
        let (name, value) = split_name_value(after)?;
        if !is_valid_object_name(&name) || !is_valid_object_name(&value) {
            return Err(IdentifierError::InvalidComponent(format!(
                "name {name}, value {value}"
            )));
        }
        Ok(Self {
            namespace: String::new(),
            name,
            value,
        })
    }
}

fn split_name_value(after: &str) -> Result<(String, String), IdentifierError> {
    let (name, value) = after
        .split_once("/value/")
        .ok_or(IdentifierError::InvalidFormat)?;
    if name.is_empty() || name.contains('/') || value.contains('/') {
        return Err(IdentifierError::InvalidFormat);
    }
    Ok((name.to_lowercase(), value.to_lowercase()))
}

impl fmt::Display for FullyQualifiedRegisteredResourceValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.fqn())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_attr_value() {
        let parsed =
            FullyQualifiedAttribute::parse("https://demo.com/attr/classification/value/secret")
                .unwrap();
        assert_eq!(parsed.namespace, "demo.com");
        assert_eq!(parsed.name, "classification");
        assert_eq!(parsed.value, "secret");
        assert_eq!(
            parsed.fqn(),
            "https://demo.com/attr/classification/value/secret"
        );
    }

    #[test]
    fn parse_attr_def() {
        let parsed =
            FullyQualifiedAttribute::parse("https://demo.com/attr/classification").unwrap();
        assert_eq!(parsed.namespace, "demo.com");
        assert_eq!(parsed.name, "classification");
        assert_eq!(parsed.value, "");
    }

    #[test]
    fn parse_ns_only() {
        let parsed = FullyQualifiedAttribute::parse("https://demo.com").unwrap();
        assert_eq!(parsed.namespace, "demo.com");
        assert!(parsed.name.is_empty());
    }

    #[test]
    fn parse_case_insensitive() {
        let a = FullyQualifiedAttribute::parse("https://DEMO.COM/attr/Foo/value/BAR").unwrap();
        assert_eq!(a.namespace, "demo.com");
        assert_eq!(a.name, "foo");
        assert_eq!(a.value, "bar");
    }

    #[test]
    fn parse_invalid_no_scheme() {
        assert!(matches!(
            FullyQualifiedAttribute::parse("not a url"),
            Err(IdentifierError::InvalidFormat)
        ));
    }

    #[test]
    fn parse_invalid_namespace() {
        assert!(FullyQualifiedAttribute::parse("https://-bad.com/attr/foo").is_err());
    }

    #[test]
    fn round_trip_fqn_lowercases() {
        let a = FullyQualifiedAttribute::new("Demo.com", "Foo", "Bar");
        assert_eq!(a.fqn(), "https://demo.com/attr/foo/value/bar");
    }

    #[test]
    fn reg_res_with_namespace() {
        let v = FullyQualifiedRegisteredResourceValue::parse(
            "https://demo.com/resm/network/value/private",
        )
        .unwrap();
        assert_eq!(v.namespace, "demo.com");
        assert_eq!(v.name, "network");
        assert_eq!(v.value, "private");
    }

    #[test]
    fn reg_res_legacy_no_namespace() {
        let v = FullyQualifiedRegisteredResourceValue::parse("https://resm/network/value/private")
            .unwrap();
        assert!(v.namespace.is_empty());
        assert_eq!(v.name, "network");
        assert_eq!(v.value, "private");
    }

    #[test]
    fn reg_res_round_trip() {
        let v = FullyQualifiedRegisteredResourceValue::new("", "network", "private");
        assert_eq!(v.fqn(), "https://resm/network/value/private");

        let v2 = FullyQualifiedRegisteredResourceValue::new("demo.com", "network", "private");
        assert_eq!(v2.fqn(), "https://demo.com/resm/network/value/private");
    }

    #[test]
    fn reg_res_rejects_garbage() {
        assert!(FullyQualifiedRegisteredResourceValue::parse("nope").is_err());
        assert!(
            FullyQualifiedRegisteredResourceValue::parse("https://demo.com/notresm/foo/value/x")
                .is_err()
        );
    }
}
