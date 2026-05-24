//! Integration tests for the focused ALLOW/DENY access PDP.
//!
//! Scenarios are ported (and trimmed to the narrowed surface) from
//! `service/internal/access/v2/pdp_test.go` and `evaluate_test.go`.

use serde_json::{Value as JsonValue, json};

use super::*;

// -- FQN constants matching the Go test fixtures --

const TEST_NS_BASE: &str = "test.example.com";
const TEST_NS_SECONDARY: &str = "secondary.example.org";

fn def_fqn(ns: &str, name: &str) -> String {
    FullyQualifiedAttribute::new(ns, name, "").fqn()
}
fn val_fqn(ns: &str, name: &str, value: &str) -> String {
    FullyQualifiedAttribute::new(ns, name, value).fqn()
}

// -- Builders --

fn val(fqn: &str, v: &str) -> Value {
    Value {
        id: String::new(),
        fqn: fqn.to_string(),
        value: v.to_string(),
        subject_mappings: vec![],
    }
}

fn action(name: &str) -> Action {
    Action::new(name)
}

fn ns_with_id(id: &str, fqn: &str) -> Namespace {
    Namespace {
        id: id.to_string(),
        name: String::new(),
        fqn: fqn.to_string(),
    }
}

fn classification_attr() -> Attribute {
    Attribute {
        fqn: def_fqn(TEST_NS_BASE, "classification"),
        rule: AttributeRule::Hierarchy,
        values: vec![
            val(
                &val_fqn(TEST_NS_BASE, "classification", "topsecret"),
                "topsecret",
            ),
            val(&val_fqn(TEST_NS_BASE, "classification", "secret"), "secret"),
            val(
                &val_fqn(TEST_NS_BASE, "classification", "confidential"),
                "confidential",
            ),
            val(&val_fqn(TEST_NS_BASE, "classification", "public"), "public"),
        ],
        ..Default::default()
    }
}

fn department_attr() -> Attribute {
    Attribute {
        fqn: def_fqn(TEST_NS_BASE, "department"),
        rule: AttributeRule::AnyOf,
        values: vec![
            val(&val_fqn(TEST_NS_BASE, "department", "rnd"), "rnd"),
            val(
                &val_fqn(TEST_NS_BASE, "department", "engineering"),
                "engineering",
            ),
            val(&val_fqn(TEST_NS_BASE, "department", "sales"), "sales"),
            val(&val_fqn(TEST_NS_BASE, "department", "finance"), "finance"),
        ],
        ..Default::default()
    }
}

fn country_attr() -> Attribute {
    Attribute {
        fqn: def_fqn(TEST_NS_BASE, "country"),
        rule: AttributeRule::AllOf,
        values: vec![
            val(&val_fqn(TEST_NS_BASE, "country", "usa"), "usa"),
            val(&val_fqn(TEST_NS_BASE, "country", "uk"), "uk"),
        ],
        ..Default::default()
    }
}

fn project_attr() -> Attribute {
    Attribute {
        fqn: def_fqn(TEST_NS_SECONDARY, "project"),
        rule: AttributeRule::AnyOf,
        values: vec![
            val(&val_fqn(TEST_NS_SECONDARY, "project", "alpha"), "alpha"),
            val(&val_fqn(TEST_NS_SECONDARY, "project", "beta"), "beta"),
        ],
        ..Default::default()
    }
}

fn simple_mapping(
    attr_value_fqn: &str,
    attr_value: &str,
    actions: Vec<Action>,
    selector: &str,
    expected: Vec<&str>,
    namespace: Option<Namespace>,
) -> SubjectMapping {
    let condition = Condition {
        subject_external_selector_value: selector.to_string(),
        subject_external_values: expected.into_iter().map(|s| s.to_string()).collect(),
        operator: SubjectMappingOperator::In,
    };
    let cg = ConditionGroup {
        boolean_operator: ConditionBooleanOperator::And,
        conditions: vec![condition],
    };
    SubjectMapping {
        id: String::new(),
        attribute_value: val(attr_value_fqn, attr_value),
        subject_condition_set: SubjectConditionSet {
            id: String::new(),
            subject_sets: vec![SubjectSet {
                condition_groups: vec![cg],
            }],
            namespace: namespace.clone(),
        },
        actions,
        namespace,
    }
}

fn entity_with_props(id: &str, props: JsonValue) -> EntityRepresentation {
    EntityRepresentation::with_properties(id, json!({"properties": props}))
}

// -------------------- TESTS --------------------

#[test]
fn rejects_construction_with_unspecified_rule() {
    let bad = Attribute {
        fqn: def_fqn(TEST_NS_BASE, "broken"),
        rule: AttributeRule::Unspecified,
        ..Default::default()
    };
    assert!(matches!(
        AccessPdp::new(vec![bad], vec![], PdpOptions::default()),
        Err(PdpError::InvalidAttributeDefinition(_))
    ));
}

#[test]
fn check_requires_action_name() {
    let pdp = AccessPdp::new(vec![classification_attr()], vec![], PdpOptions::default()).unwrap();
    let ent = entity_with_props("u", json!({"clearance": "secret"}));
    let err = pdp
        .check(
            &ent,
            &Action::new(""),
            &[val_fqn(TEST_NS_BASE, "classification", "secret")],
        )
        .unwrap_err();
    assert!(matches!(err, PdpError::InvalidAction(_)));
}

#[test]
fn check_requires_resource_fqn() {
    let pdp = AccessPdp::new(vec![classification_attr()], vec![], PdpOptions::default()).unwrap();
    let ent = entity_with_props("u", json!({"clearance": "secret"}));
    let err = pdp.check(&ent, &action("read"), &[]).unwrap_err();
    assert!(matches!(err, PdpError::InvalidResource(_)));
}

#[test]
fn unknown_attribute_value_denies() {
    let pdp = AccessPdp::new(vec![classification_attr()], vec![], PdpOptions::default()).unwrap();
    let ent = entity_with_props("u", json!({"clearance": "secret"}));
    let res = pdp
        .check(
            &ent,
            &action("read"),
            &["https://test.example.com/attr/classification/value/cosmic".to_string()],
        )
        .unwrap();
    assert!(res.is_deny());
}

// --- Hierarchy rule ---

#[test]
fn hierarchy_grants_when_entity_is_higher() {
    let topsecret_map = simple_mapping(
        &val_fqn(TEST_NS_BASE, "classification", "topsecret"),
        "topsecret",
        vec![action("read")],
        ".properties.clearance",
        vec!["ts"],
        None,
    );
    let pdp = AccessPdp::new(
        vec![classification_attr()],
        vec![topsecret_map],
        PdpOptions::default(),
    )
    .unwrap();

    // Entity has topsecret entitlement; resource only needs secret (lower).
    let ent = entity_with_props("u", json!({"clearance": "ts"}));
    let decision = pdp
        .check(
            &ent,
            &action("read"),
            &[val_fqn(TEST_NS_BASE, "classification", "secret")],
        )
        .unwrap();
    assert_eq!(decision, AccessDecision::Allow);
}

#[test]
fn hierarchy_denies_when_entity_is_lower() {
    let confidential_map = simple_mapping(
        &val_fqn(TEST_NS_BASE, "classification", "confidential"),
        "confidential",
        vec![action("read")],
        ".properties.clearance",
        vec!["confidential"],
        None,
    );
    let pdp = AccessPdp::new(
        vec![classification_attr()],
        vec![confidential_map],
        PdpOptions::default(),
    )
    .unwrap();

    let ent = entity_with_props("u", json!({"clearance": "confidential"}));
    let decision = pdp
        .check(
            &ent,
            &action("read"),
            &[val_fqn(TEST_NS_BASE, "classification", "secret")], // needs SECRET, only has CONF
        )
        .unwrap();
    assert!(decision.is_deny());
}

#[test]
fn hierarchy_with_multiple_values_uses_highest() {
    let secret_map = simple_mapping(
        &val_fqn(TEST_NS_BASE, "classification", "secret"),
        "secret",
        vec![action("read")],
        ".properties.clearance",
        vec!["secret"],
        None,
    );
    let pdp = AccessPdp::new(
        vec![classification_attr()],
        vec![secret_map],
        PdpOptions::default(),
    )
    .unwrap();
    let ent = entity_with_props("u", json!({"clearance": "secret"}));
    let res = pdp
        .check(
            &ent,
            &action("read"),
            &[
                val_fqn(TEST_NS_BASE, "classification", "secret"),
                val_fqn(TEST_NS_BASE, "classification", "confidential"),
            ],
        )
        .unwrap();
    assert_eq!(res, AccessDecision::Allow);

    let confidential_map = simple_mapping(
        &val_fqn(TEST_NS_BASE, "classification", "confidential"),
        "confidential",
        vec![action("read")],
        ".properties.clearance",
        vec!["confidential"],
        None,
    );
    let pdp2 = AccessPdp::new(
        vec![classification_attr()],
        vec![confidential_map],
        PdpOptions::default(),
    )
    .unwrap();
    let ent2 = entity_with_props("u2", json!({"clearance": "confidential"}));
    let res2 = pdp2
        .check(
            &ent2,
            &action("read"),
            &[
                val_fqn(TEST_NS_BASE, "classification", "secret"),
                val_fqn(TEST_NS_BASE, "classification", "confidential"),
            ],
        )
        .unwrap();
    assert!(res2.is_deny());
}

// --- AllOf rule ---

#[test]
fn all_of_requires_every_value() {
    let usa_map = simple_mapping(
        &val_fqn(TEST_NS_BASE, "country", "usa"),
        "usa",
        vec![action("read")],
        ".properties.country[]",
        vec!["us"],
        None,
    );
    let uk_map = simple_mapping(
        &val_fqn(TEST_NS_BASE, "country", "uk"),
        "uk",
        vec![action("read")],
        ".properties.country[]",
        vec!["uk"],
        None,
    );
    let pdp = AccessPdp::new(
        vec![country_attr()],
        vec![usa_map, uk_map],
        PdpOptions::default(),
    )
    .unwrap();

    let ent_both = entity_with_props("u", json!({"country": ["us", "uk"]}));
    let res = pdp
        .check(
            &ent_both,
            &action("read"),
            &[
                val_fqn(TEST_NS_BASE, "country", "usa"),
                val_fqn(TEST_NS_BASE, "country", "uk"),
            ],
        )
        .unwrap();
    assert_eq!(res, AccessDecision::Allow);

    let ent_one = entity_with_props("u", json!({"country": ["us"]}));
    let res2 = pdp
        .check(
            &ent_one,
            &action("read"),
            &[
                val_fqn(TEST_NS_BASE, "country", "usa"),
                val_fqn(TEST_NS_BASE, "country", "uk"),
            ],
        )
        .unwrap();
    match res2 {
        AccessDecision::Deny { failures } => {
            assert_eq!(failures.len(), 1);
            assert_eq!(
                failures[0].attribute_value_fqn,
                val_fqn(TEST_NS_BASE, "country", "uk")
            );
        }
        AccessDecision::Allow => panic!("expected deny"),
    }
}

// --- AnyOf rule ---

#[test]
fn any_of_requires_at_least_one() {
    let eng_map = simple_mapping(
        &val_fqn(TEST_NS_BASE, "department", "engineering"),
        "engineering",
        vec![action("read"), action("create")],
        ".properties.department",
        vec!["engineering"],
        None,
    );
    let fin_map = simple_mapping(
        &val_fqn(TEST_NS_BASE, "department", "finance"),
        "finance",
        vec![action("read"), action("update")],
        ".properties.department",
        vec!["finance"],
        None,
    );
    let pdp = AccessPdp::new(
        vec![department_attr()],
        vec![eng_map, fin_map],
        PdpOptions::default(),
    )
    .unwrap();

    let ent = entity_with_props("u", json!({"department": "engineering"}));
    let res = pdp
        .check(
            &ent,
            &action("read"),
            &[
                val_fqn(TEST_NS_BASE, "department", "engineering"),
                val_fqn(TEST_NS_BASE, "department", "finance"),
            ],
        )
        .unwrap();
    assert_eq!(res, AccessDecision::Allow);

    let ent_sales = entity_with_props("u", json!({"department": "sales"}));
    let res2 = pdp
        .check(
            &ent_sales,
            &action("read"),
            &[
                val_fqn(TEST_NS_BASE, "department", "engineering"),
                val_fqn(TEST_NS_BASE, "department", "finance"),
            ],
        )
        .unwrap();
    assert!(res2.is_deny());
}

#[test]
fn missing_action_denies() {
    let map = simple_mapping(
        &val_fqn(TEST_NS_BASE, "department", "engineering"),
        "engineering",
        vec![action("read")],
        ".properties.department",
        vec!["engineering"],
        None,
    );
    let pdp = AccessPdp::new(vec![department_attr()], vec![map], PdpOptions::default()).unwrap();
    let ent = entity_with_props("u", json!({"department": "engineering"}));
    let res = pdp
        .check(
            &ent,
            &action("delete"),
            &[val_fqn(TEST_NS_BASE, "department", "engineering")],
        )
        .unwrap();
    assert!(res.is_deny());
}

#[test]
fn fqn_case_normalization() {
    let map = simple_mapping(
        &val_fqn(TEST_NS_BASE, "department", "engineering"),
        "engineering",
        vec![action("read")],
        ".properties.department",
        vec!["engineering"],
        None,
    );
    let pdp = AccessPdp::new(vec![department_attr()], vec![map], PdpOptions::default()).unwrap();
    let ent = entity_with_props("u", json!({"department": "engineering"}));
    let uppercased = val_fqn(TEST_NS_BASE, "department", "engineering").to_uppercase();
    let res = pdp.check(&ent, &action("read"), &[uppercased]).unwrap();
    assert_eq!(res, AccessDecision::Allow);
}

// --- Combined rules on one resource ---

#[test]
fn combined_rules_all_must_pass() {
    let class_map = simple_mapping(
        &val_fqn(TEST_NS_BASE, "classification", "secret"),
        "secret",
        vec![action("read")],
        ".properties.clearance",
        vec!["secret"],
        None,
    );
    let dept_map = simple_mapping(
        &val_fqn(TEST_NS_BASE, "department", "engineering"),
        "engineering",
        vec![action("read")],
        ".properties.department",
        vec!["engineering"],
        None,
    );
    let usa_map = simple_mapping(
        &val_fqn(TEST_NS_BASE, "country", "usa"),
        "usa",
        vec![action("read")],
        ".properties.country[]",
        vec!["us"],
        None,
    );
    let pdp = AccessPdp::new(
        vec![classification_attr(), department_attr(), country_attr()],
        vec![class_map, dept_map, usa_map],
        PdpOptions::default(),
    )
    .unwrap();

    let ent = entity_with_props(
        "u",
        json!({"clearance": "secret", "department": "engineering", "country": ["us"]}),
    );
    let res = pdp
        .check(
            &ent,
            &action("read"),
            &[
                val_fqn(TEST_NS_BASE, "classification", "secret"),
                val_fqn(TEST_NS_BASE, "department", "engineering"),
                val_fqn(TEST_NS_BASE, "country", "usa"),
            ],
        )
        .unwrap();
    assert_eq!(res, AccessDecision::Allow);

    let ent2 = entity_with_props(
        "u",
        json!({"clearance": "secret", "department": "engineering", "country": []}),
    );
    let res2 = pdp
        .check(
            &ent2,
            &action("read"),
            &[
                val_fqn(TEST_NS_BASE, "classification", "secret"),
                val_fqn(TEST_NS_BASE, "department", "engineering"),
                val_fqn(TEST_NS_BASE, "country", "usa"),
            ],
        )
        .unwrap();
    assert!(res2.is_deny());
}

// --- Cross-namespace ---

#[test]
fn cross_namespace_resources_can_pass_or_fail_independently() {
    let class_map = simple_mapping(
        &val_fqn(TEST_NS_BASE, "classification", "secret"),
        "secret",
        vec![action("read")],
        ".properties.clearance",
        vec!["secret"],
        None,
    );
    let alpha_map = simple_mapping(
        &val_fqn(TEST_NS_SECONDARY, "project", "alpha"),
        "alpha",
        vec![action("read"), action("create")],
        ".properties.project",
        vec!["alpha"],
        None,
    );
    let pdp = AccessPdp::new(
        vec![classification_attr(), project_attr()],
        vec![class_map, alpha_map],
        PdpOptions::default(),
    )
    .unwrap();

    let ent = entity_with_props("u", json!({"clearance": "secret", "project": "alpha"}));

    let res = pdp
        .check(
            &ent,
            &action("create"),
            &[
                val_fqn(TEST_NS_BASE, "classification", "secret"),
                val_fqn(TEST_NS_SECONDARY, "project", "alpha"),
            ],
        )
        .unwrap();
    assert!(res.is_deny());

    let res2 = pdp
        .check(
            &ent,
            &action("read"),
            &[
                val_fqn(TEST_NS_BASE, "classification", "secret"),
                val_fqn(TEST_NS_SECONDARY, "project", "alpha"),
            ],
        )
        .unwrap();
    assert_eq!(res2, AccessDecision::Allow);
}

// --- Strict namespaced-policy mode ---

#[test]
fn strict_mode_skips_unnamespaced_subject_mappings() {
    let base_ns = ns_with_id(
        "11111111-1111-1111-1111-111111111111",
        &format!("https://{TEST_NS_BASE}"),
    );
    let mut attr = classification_attr();
    attr.namespace = Some(base_ns.clone());

    let unnamespaced = simple_mapping(
        &val_fqn(TEST_NS_BASE, "classification", "secret"),
        "secret",
        vec![Action {
            id: String::new(),
            name: "read".into(),
            namespace: Some(base_ns.clone()),
        }],
        ".properties.clearance",
        vec!["secret"],
        None,
    );

    let pdp = AccessPdp::new(
        vec![attr],
        vec![unnamespaced],
        PdpOptions {
            namespaced_policy: true,
        },
    )
    .unwrap();

    let ent = entity_with_props("u", json!({"clearance": "secret"}));
    let res = pdp
        .check(
            &ent,
            &action("read"),
            &[val_fqn(TEST_NS_BASE, "classification", "secret")],
        )
        .unwrap();
    assert!(res.is_deny());
}

#[test]
fn strict_mode_denies_cross_namespace_action_match() {
    let base_ns = ns_with_id("aaaa", &format!("https://{TEST_NS_BASE}"));
    let secondary_ns = ns_with_id("bbbb", &format!("https://{TEST_NS_SECONDARY}"));

    let mut class_attr = classification_attr();
    class_attr.namespace = Some(base_ns.clone());
    let mut proj_attr = project_attr();
    proj_attr.namespace = Some(secondary_ns.clone());

    let secret_map = simple_mapping(
        &val_fqn(TEST_NS_BASE, "classification", "secret"),
        "secret",
        vec![Action {
            id: String::new(),
            name: "read".into(),
            namespace: Some(base_ns.clone()),
        }],
        ".properties.clearance",
        vec!["secret"],
        Some(base_ns.clone()),
    );
    let project_alpha_wrong_ns = simple_mapping(
        &val_fqn(TEST_NS_SECONDARY, "project", "alpha"),
        "alpha",
        vec![Action {
            id: String::new(),
            name: "read".into(),
            namespace: Some(base_ns.clone()),
        }],
        ".properties.project",
        vec!["alpha"],
        Some(secondary_ns.clone()),
    );

    let pdp = AccessPdp::new(
        vec![class_attr, proj_attr],
        vec![secret_map, project_alpha_wrong_ns],
        PdpOptions {
            namespaced_policy: true,
        },
    )
    .unwrap();

    let ent = entity_with_props("u", json!({"clearance": "secret", "project": "alpha"}));

    let res = pdp
        .check(
            &ent,
            &action("read"),
            &[
                val_fqn(TEST_NS_BASE, "classification", "secret"),
                val_fqn(TEST_NS_SECONDARY, "project", "alpha"),
            ],
        )
        .unwrap();
    assert!(
        res.is_deny(),
        "strict mode should deny cross-namespace action match"
    );
}

#[test]
fn legacy_mode_allows_cross_namespace_action_match() {
    let base_ns = ns_with_id("aaaa", &format!("https://{TEST_NS_BASE}"));
    let secondary_ns = ns_with_id("bbbb", &format!("https://{TEST_NS_SECONDARY}"));

    let mut class_attr = classification_attr();
    class_attr.namespace = Some(base_ns.clone());
    let mut proj_attr = project_attr();
    proj_attr.namespace = Some(secondary_ns.clone());

    let secret_map = simple_mapping(
        &val_fqn(TEST_NS_BASE, "classification", "secret"),
        "secret",
        vec![Action {
            id: String::new(),
            name: "read".into(),
            namespace: Some(base_ns.clone()),
        }],
        ".properties.clearance",
        vec!["secret"],
        Some(base_ns.clone()),
    );
    let project_alpha_wrong_ns = simple_mapping(
        &val_fqn(TEST_NS_SECONDARY, "project", "alpha"),
        "alpha",
        vec![Action {
            id: String::new(),
            name: "read".into(),
            namespace: Some(base_ns.clone()),
        }],
        ".properties.project",
        vec!["alpha"],
        Some(secondary_ns.clone()),
    );

    let pdp = AccessPdp::new(
        vec![class_attr, proj_attr],
        vec![secret_map, project_alpha_wrong_ns],
        PdpOptions::default(),
    )
    .unwrap();

    let ent = entity_with_props("u", json!({"clearance": "secret", "project": "alpha"}));
    let res = pdp
        .check(
            &ent,
            &action("read"),
            &[
                val_fqn(TEST_NS_BASE, "classification", "secret"),
                val_fqn(TEST_NS_SECONDARY, "project", "alpha"),
            ],
        )
        .unwrap();
    assert_eq!(res, AccessDecision::Allow);
}

#[test]
fn explicit_request_namespace_must_match_entitled() {
    let base_ns = ns_with_id("aaaa", &format!("https://{TEST_NS_BASE}"));
    let other_ns = ns_with_id("bbbb", &format!("https://{TEST_NS_SECONDARY}"));

    let mut attr = classification_attr();
    attr.namespace = Some(base_ns.clone());

    let map = simple_mapping(
        &val_fqn(TEST_NS_BASE, "classification", "secret"),
        "secret",
        vec![Action {
            id: String::new(),
            name: "read".into(),
            namespace: Some(base_ns.clone()),
        }],
        ".properties.clearance",
        vec!["secret"],
        Some(base_ns.clone()),
    );

    let pdp = AccessPdp::new(vec![attr], vec![map], PdpOptions::default()).unwrap();
    let ent = entity_with_props("u", json!({"clearance": "secret"}));

    let res_match = pdp
        .check(
            &ent,
            &Action {
                id: String::new(),
                name: "read".into(),
                namespace: Some(base_ns.clone()),
            },
            &[val_fqn(TEST_NS_BASE, "classification", "secret")],
        )
        .unwrap();
    assert_eq!(res_match, AccessDecision::Allow);

    let res_mismatch = pdp
        .check(
            &ent,
            &Action {
                id: String::new(),
                name: "read".into(),
                namespace: Some(other_ns),
            },
            &[val_fqn(TEST_NS_BASE, "classification", "secret")],
        )
        .unwrap();
    assert!(res_mismatch.is_deny());
}

#[test]
fn empty_policy_denies_everything() {
    let pdp = AccessPdp::new(vec![], vec![], PdpOptions::default()).unwrap();
    let ent = entity_with_props("u", json!({"clearance": "secret"}));
    let res = pdp.check(
        &ent,
        &action("read"),
        &[val_fqn(TEST_NS_BASE, "classification", "secret")],
    );
    assert!(matches!(res, Ok(AccessDecision::Deny { .. })));
}
