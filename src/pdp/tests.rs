//! Integration tests for the entitlement-driven Access PDP.
//!
//! Each test constructs an attribute-definition catalog plus a per-request
//! entitlement map (the shape a PEP extracts from a verified access token)
//! and asserts the rule engine returns the expected ALLOW / DENY.

use super::*;

const NS_BASE: &str = "test.example.com";
const NS_SECONDARY: &str = "secondary.example.org";

fn def_fqn(ns: &str, name: &str) -> String {
    FullyQualifiedAttribute::new(ns, name, "").fqn()
}
fn val_fqn(ns: &str, name: &str, value: &str) -> String {
    FullyQualifiedAttribute::new(ns, name, value).fqn()
}

fn val(fqn: &str, v: &str) -> Value {
    Value {
        id: String::new(),
        fqn: fqn.to_string(),
        value: v.to_string(),
    }
}

fn classification_attr() -> Attribute {
    Attribute {
        fqn: def_fqn(NS_BASE, "classification"),
        rule: AttributeRule::Hierarchy,
        values: vec![
            val(
                &val_fqn(NS_BASE, "classification", "topsecret"),
                "topsecret",
            ),
            val(&val_fqn(NS_BASE, "classification", "secret"), "secret"),
            val(
                &val_fqn(NS_BASE, "classification", "confidential"),
                "confidential",
            ),
            val(&val_fqn(NS_BASE, "classification", "public"), "public"),
        ],
        ..Default::default()
    }
}

fn department_attr() -> Attribute {
    Attribute {
        fqn: def_fqn(NS_BASE, "department"),
        rule: AttributeRule::AnyOf,
        values: vec![
            val(
                &val_fqn(NS_BASE, "department", "engineering"),
                "engineering",
            ),
            val(&val_fqn(NS_BASE, "department", "finance"), "finance"),
            val(&val_fqn(NS_BASE, "department", "sales"), "sales"),
        ],
        ..Default::default()
    }
}

fn country_attr() -> Attribute {
    Attribute {
        fqn: def_fqn(NS_BASE, "country"),
        rule: AttributeRule::AllOf,
        values: vec![
            val(&val_fqn(NS_BASE, "country", "usa"), "usa"),
            val(&val_fqn(NS_BASE, "country", "uk"), "uk"),
        ],
        ..Default::default()
    }
}

fn project_attr() -> Attribute {
    Attribute {
        fqn: def_fqn(NS_SECONDARY, "project"),
        rule: AttributeRule::AnyOf,
        values: vec![
            val(&val_fqn(NS_SECONDARY, "project", "alpha"), "alpha"),
            val(&val_fqn(NS_SECONDARY, "project", "beta"), "beta"),
        ],
        ..Default::default()
    }
}

fn ents(pairs: &[(&str, &[&str])]) -> Entitlements {
    pairs
        .iter()
        .map(|(fqn, actions)| {
            (
                (*fqn).to_string(),
                actions.iter().map(|s| (*s).to_string()).collect(),
            )
        })
        .collect()
}

fn read() -> Action {
    Action::new("read")
}
fn create() -> Action {
    Action::new("create")
}
fn update() -> Action {
    Action::new("update")
}
fn delete() -> Action {
    Action::new("delete")
}

// -------------------- TESTS --------------------

// --- Construction / input validation ---

#[test]
fn rejects_construction_with_unspecified_rule() {
    let bad = Attribute {
        fqn: def_fqn(NS_BASE, "broken"),
        rule: AttributeRule::Unspecified,
        ..Default::default()
    };
    assert!(matches!(
        AccessPdp::new(vec![bad], PdpOptions::default()),
        Err(PdpError::InvalidAttributeDefinition(_))
    ));
}

#[test]
fn check_requires_action_name() {
    let pdp = AccessPdp::new(vec![classification_attr()], PdpOptions::default()).unwrap();
    let e = ents(&[(&val_fqn(NS_BASE, "classification", "secret"), &["read"])]);
    let err = pdp
        .check(
            &e,
            &Action::new(""),
            &[val_fqn(NS_BASE, "classification", "secret")],
        )
        .unwrap_err();
    assert!(matches!(err, PdpError::InvalidAction(_)));
}

#[test]
fn check_requires_resource_fqn() {
    let pdp = AccessPdp::new(vec![classification_attr()], PdpOptions::default()).unwrap();
    let e = ents(&[(&val_fqn(NS_BASE, "classification", "secret"), &["read"])]);
    let err = pdp.check(&e, &read(), &[]).unwrap_err();
    assert!(matches!(err, PdpError::InvalidResource(_)));
}

#[test]
fn unknown_attribute_value_denies() {
    let pdp = AccessPdp::new(vec![classification_attr()], PdpOptions::default()).unwrap();
    let e = ents(&[(&val_fqn(NS_BASE, "classification", "secret"), &["read"])]);
    let res = pdp
        .check(
            &e,
            &read(),
            &["https://test.example.com/attr/classification/value/cosmic".to_string()],
        )
        .unwrap();
    assert!(res.is_deny());
}

#[test]
fn empty_policy_denies_everything() {
    let pdp = AccessPdp::new(vec![], PdpOptions::default()).unwrap();
    let e = ents(&[]);
    let res = pdp.check(&e, &read(), &[val_fqn(NS_BASE, "classification", "secret")]);
    assert!(matches!(res, Ok(AccessDecision::Deny { .. })));
}

#[test]
fn empty_entitlements_denies() {
    let pdp = AccessPdp::new(vec![classification_attr()], PdpOptions::default()).unwrap();
    let e = ents(&[]);
    let res = pdp
        .check(&e, &read(), &[val_fqn(NS_BASE, "classification", "secret")])
        .unwrap();
    assert!(res.is_deny());
}

// --- HIERARCHY rule ---

#[test]
fn hierarchy_grants_when_entitled_to_higher_value() {
    let pdp = AccessPdp::new(vec![classification_attr()], PdpOptions::default()).unwrap();
    // Entitled to TOPSECRET; resource only demands SECRET.
    let e = ents(&[(&val_fqn(NS_BASE, "classification", "topsecret"), &["read"])]);
    let decision = pdp
        .check(&e, &read(), &[val_fqn(NS_BASE, "classification", "secret")])
        .unwrap();
    assert_eq!(decision, AccessDecision::Allow);
}

#[test]
fn hierarchy_grants_for_exact_match() {
    let pdp = AccessPdp::new(vec![classification_attr()], PdpOptions::default()).unwrap();
    let e = ents(&[(&val_fqn(NS_BASE, "classification", "secret"), &["read"])]);
    let decision = pdp
        .check(&e, &read(), &[val_fqn(NS_BASE, "classification", "secret")])
        .unwrap();
    assert_eq!(decision, AccessDecision::Allow);
}

#[test]
fn hierarchy_denies_when_entitled_to_lower_value() {
    let pdp = AccessPdp::new(vec![classification_attr()], PdpOptions::default()).unwrap();
    let e = ents(&[(
        &val_fqn(NS_BASE, "classification", "confidential"),
        &["read"],
    )]);
    let decision = pdp
        .check(&e, &read(), &[val_fqn(NS_BASE, "classification", "secret")])
        .unwrap();
    assert!(decision.is_deny());
}

#[test]
fn hierarchy_with_multiple_resource_values_uses_highest() {
    let pdp = AccessPdp::new(vec![classification_attr()], PdpOptions::default()).unwrap();
    // Resource carries SECRET and CONFIDENTIAL; entity is entitled to SECRET.
    // The highest resource value is SECRET, and the entity satisfies it.
    let e = ents(&[(&val_fqn(NS_BASE, "classification", "secret"), &["read"])]);
    let res = pdp
        .check(
            &e,
            &read(),
            &[
                val_fqn(NS_BASE, "classification", "secret"),
                val_fqn(NS_BASE, "classification", "confidential"),
            ],
        )
        .unwrap();
    assert_eq!(res, AccessDecision::Allow);

    // Entity only entitled to CONFIDENTIAL cannot satisfy a SECRET requirement.
    let e2 = ents(&[(
        &val_fqn(NS_BASE, "classification", "confidential"),
        &["read"],
    )]);
    let res2 = pdp
        .check(
            &e2,
            &read(),
            &[
                val_fqn(NS_BASE, "classification", "secret"),
                val_fqn(NS_BASE, "classification", "confidential"),
            ],
        )
        .unwrap();
    assert!(res2.is_deny());
}

// --- ALL_OF rule ---

#[test]
fn all_of_requires_every_value() {
    let pdp = AccessPdp::new(vec![country_attr()], PdpOptions::default()).unwrap();

    let e_both = ents(&[
        (&val_fqn(NS_BASE, "country", "usa"), &["read"]),
        (&val_fqn(NS_BASE, "country", "uk"), &["read"]),
    ]);
    let res = pdp
        .check(
            &e_both,
            &read(),
            &[
                val_fqn(NS_BASE, "country", "usa"),
                val_fqn(NS_BASE, "country", "uk"),
            ],
        )
        .unwrap();
    assert_eq!(res, AccessDecision::Allow);

    let e_one = ents(&[(&val_fqn(NS_BASE, "country", "usa"), &["read"])]);
    let res2 = pdp
        .check(
            &e_one,
            &read(),
            &[
                val_fqn(NS_BASE, "country", "usa"),
                val_fqn(NS_BASE, "country", "uk"),
            ],
        )
        .unwrap();
    match res2 {
        AccessDecision::Deny { failures } => {
            assert_eq!(failures.len(), 1);
            assert_eq!(
                failures[0].attribute_value_fqn,
                val_fqn(NS_BASE, "country", "uk")
            );
        }
        AccessDecision::Allow => panic!("expected deny"),
    }
}

// --- ANY_OF rule ---

#[test]
fn any_of_requires_at_least_one() {
    let pdp = AccessPdp::new(vec![department_attr()], PdpOptions::default()).unwrap();

    // Entitled to engineering only; resource accepts engineering OR finance.
    let e = ents(&[(&val_fqn(NS_BASE, "department", "engineering"), &["read"])]);
    let res = pdp
        .check(
            &e,
            &read(),
            &[
                val_fqn(NS_BASE, "department", "engineering"),
                val_fqn(NS_BASE, "department", "finance"),
            ],
        )
        .unwrap();
    assert_eq!(res, AccessDecision::Allow);

    // Entitled to neither -> deny.
    let e_none = ents(&[]);
    let res2 = pdp
        .check(
            &e_none,
            &read(),
            &[
                val_fqn(NS_BASE, "department", "engineering"),
                val_fqn(NS_BASE, "department", "finance"),
            ],
        )
        .unwrap();
    assert!(res2.is_deny());
}

// --- Action matching ---

#[test]
fn missing_action_denies() {
    let pdp = AccessPdp::new(vec![department_attr()], PdpOptions::default()).unwrap();
    // Entitled to read on engineering; resource asks for delete.
    let e = ents(&[(&val_fqn(NS_BASE, "department", "engineering"), &["read"])]);
    let res = pdp
        .check(
            &e,
            &delete(),
            &[val_fqn(NS_BASE, "department", "engineering")],
        )
        .unwrap();
    assert!(res.is_deny());
}

#[test]
fn action_match_is_case_insensitive() {
    let pdp = AccessPdp::new(vec![department_attr()], PdpOptions::default()).unwrap();
    let e = ents(&[(&val_fqn(NS_BASE, "department", "engineering"), &["READ"])]);
    let res = pdp
        .check(
            &e,
            &Action::new("read"),
            &[val_fqn(NS_BASE, "department", "engineering")],
        )
        .unwrap();
    assert_eq!(res, AccessDecision::Allow);
}

#[test]
fn fqn_match_is_case_insensitive() {
    let pdp = AccessPdp::new(vec![department_attr()], PdpOptions::default()).unwrap();
    let e = ents(&[(&val_fqn(NS_BASE, "department", "engineering"), &["read"])]);
    let uppercased = val_fqn(NS_BASE, "department", "engineering").to_uppercase();
    let res = pdp.check(&e, &read(), &[uppercased]).unwrap();
    assert_eq!(res, AccessDecision::Allow);
}

// --- Combined rules across attributes ---

#[test]
fn combined_rules_all_must_pass() {
    let pdp = AccessPdp::new(
        vec![classification_attr(), department_attr(), country_attr()],
        PdpOptions::default(),
    )
    .unwrap();

    let e = ents(&[
        (&val_fqn(NS_BASE, "classification", "secret"), &["read"]),
        (&val_fqn(NS_BASE, "department", "engineering"), &["read"]),
        (&val_fqn(NS_BASE, "country", "usa"), &["read"]),
    ]);
    let res = pdp
        .check(
            &e,
            &read(),
            &[
                val_fqn(NS_BASE, "classification", "secret"),
                val_fqn(NS_BASE, "department", "engineering"),
                val_fqn(NS_BASE, "country", "usa"),
            ],
        )
        .unwrap();
    assert_eq!(res, AccessDecision::Allow);

    // Drop the country entitlement — ALL_OF on country now fails.
    let e2 = ents(&[
        (&val_fqn(NS_BASE, "classification", "secret"), &["read"]),
        (&val_fqn(NS_BASE, "department", "engineering"), &["read"]),
    ]);
    let res2 = pdp
        .check(
            &e2,
            &read(),
            &[
                val_fqn(NS_BASE, "classification", "secret"),
                val_fqn(NS_BASE, "department", "engineering"),
                val_fqn(NS_BASE, "country", "usa"),
            ],
        )
        .unwrap();
    assert!(res2.is_deny());
}

// --- Cross-namespace ---

#[test]
fn cross_namespace_resources_evaluate_independently() {
    let pdp = AccessPdp::new(
        vec![classification_attr(), project_attr()],
        PdpOptions::default(),
    )
    .unwrap();

    let e = ents(&[
        (&val_fqn(NS_BASE, "classification", "secret"), &["read"]),
        (
            &val_fqn(NS_SECONDARY, "project", "alpha"),
            &["read", "create"],
        ),
    ]);

    // Create is allowed on project/alpha but not on classification/secret -> deny.
    let res = pdp
        .check(
            &e,
            &create(),
            &[
                val_fqn(NS_BASE, "classification", "secret"),
                val_fqn(NS_SECONDARY, "project", "alpha"),
            ],
        )
        .unwrap();
    assert!(res.is_deny());

    // Read works on both.
    let res2 = pdp
        .check(
            &e,
            &read(),
            &[
                val_fqn(NS_BASE, "classification", "secret"),
                val_fqn(NS_SECONDARY, "project", "alpha"),
            ],
        )
        .unwrap();
    assert_eq!(res2, AccessDecision::Allow);
}

// --- Failure payload ---

#[test]
fn deny_surfaces_failures_for_each_unsatisfied_value() {
    let pdp = AccessPdp::new(
        vec![classification_attr(), department_attr()],
        PdpOptions::default(),
    )
    .unwrap();

    // No entitlements at all.
    let e = ents(&[]);
    let res = pdp
        .check(
            &e,
            &update(),
            &[
                val_fqn(NS_BASE, "classification", "secret"),
                val_fqn(NS_BASE, "department", "engineering"),
            ],
        )
        .unwrap();
    match res {
        AccessDecision::Deny { failures } => {
            // Classification HIERARCHY emits one failure per resource value, so 1.
            // Department ANY_OF emits one failure per resource value (1).
            // We don't care about ordering, only count and content.
            assert_eq!(failures.len(), 2);
            let names: Vec<&str> = failures.iter().map(|f| f.action_name.as_str()).collect();
            assert!(names.iter().all(|n| *n == "update"));
        }
        AccessDecision::Allow => panic!("expected deny"),
    }
}
