//! Benchmarks for the Access PDP's hot path.
//!
//! Measures `AccessPdp::check` under realistic and worst-case shapes:
//! - single-attribute single-rule decisions (the trivial case)
//! - each rule kind in isolation (ALL_OF / ANY_OF / HIERARCHY)
//! - combined-rules resources (mixed rule kinds on one resource)
//! - the unknown-FQN deny path
//! - scaling along entitlement-set size and policy-catalog size

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use opentdf::pdp::{
    AccessPdp, Action, Attribute, AttributeRule, Entitlements, FullyQualifiedAttribute, PdpOptions,
    Value,
};

const NS: &str = "bench.example.com";

fn def_fqn(name: &str) -> String {
    FullyQualifiedAttribute::new(NS, name, "").fqn()
}
fn val_fqn(name: &str, value: &str) -> String {
    FullyQualifiedAttribute::new(NS, name, value).fqn()
}

fn val(fqn: &str, v: &str) -> Value {
    Value {
        id: String::new(),
        fqn: fqn.to_string(),
        value: v.to_string(),
    }
}

fn hierarchy_attr(name: &str, levels: &[&str]) -> Attribute {
    Attribute {
        fqn: def_fqn(name),
        rule: AttributeRule::Hierarchy,
        values: levels.iter().map(|v| val(&val_fqn(name, v), v)).collect(),
        ..Default::default()
    }
}

fn any_of_attr(name: &str, values: &[&str]) -> Attribute {
    Attribute {
        fqn: def_fqn(name),
        rule: AttributeRule::AnyOf,
        values: values.iter().map(|v| val(&val_fqn(name, v), v)).collect(),
        ..Default::default()
    }
}

fn all_of_attr(name: &str, values: &[&str]) -> Attribute {
    Attribute {
        fqn: def_fqn(name),
        rule: AttributeRule::AllOf,
        values: values.iter().map(|v| val(&val_fqn(name, v), v)).collect(),
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

// --- Trivial single-rule single-attribute checks ---

fn bench_single_rule(c: &mut Criterion) {
    let mut group = c.benchmark_group("check_single_rule");

    let hierarchy = hierarchy_attr(
        "classification",
        &["topsecret", "secret", "confidential", "public"],
    );
    let any_of = any_of_attr("department", &["engineering", "finance", "sales", "rnd"]);
    let all_of = all_of_attr("country", &["usa", "uk", "ca", "au"]);

    let hierarchy_pdp = AccessPdp::new(vec![hierarchy.clone()], PdpOptions::default()).unwrap();
    let any_of_pdp = AccessPdp::new(vec![any_of.clone()], PdpOptions::default()).unwrap();
    let all_of_pdp = AccessPdp::new(vec![all_of.clone()], PdpOptions::default()).unwrap();

    let action = Action::new("read");

    // HIERARCHY: entitled to TS, resource demands SECRET (lower).
    let hierarchy_ents = ents(&[(&val_fqn("classification", "topsecret"), &["read"])]);
    let hierarchy_resource = vec![val_fqn("classification", "secret")];
    group.bench_function("hierarchy_allow", |b| {
        b.iter(|| {
            black_box(
                hierarchy_pdp
                    .check(
                        black_box(&hierarchy_ents),
                        black_box(&action),
                        black_box(&hierarchy_resource),
                    )
                    .unwrap(),
            )
        });
    });

    // ANY_OF: entitled to engineering, resource accepts engineering OR finance.
    let any_of_ents = ents(&[(&val_fqn("department", "engineering"), &["read"])]);
    let any_of_resource = vec![
        val_fqn("department", "engineering"),
        val_fqn("department", "finance"),
    ];
    group.bench_function("any_of_allow", |b| {
        b.iter(|| {
            black_box(
                any_of_pdp
                    .check(
                        black_box(&any_of_ents),
                        black_box(&action),
                        black_box(&any_of_resource),
                    )
                    .unwrap(),
            )
        });
    });

    // ALL_OF: entitled to all four, resource demands all four.
    let all_of_ents = ents(&[
        (&val_fqn("country", "usa"), &["read"]),
        (&val_fqn("country", "uk"), &["read"]),
        (&val_fqn("country", "ca"), &["read"]),
        (&val_fqn("country", "au"), &["read"]),
    ]);
    let all_of_resource = vec![
        val_fqn("country", "usa"),
        val_fqn("country", "uk"),
        val_fqn("country", "ca"),
        val_fqn("country", "au"),
    ];
    group.bench_function("all_of_allow", |b| {
        b.iter(|| {
            black_box(
                all_of_pdp
                    .check(
                        black_box(&all_of_ents),
                        black_box(&action),
                        black_box(&all_of_resource),
                    )
                    .unwrap(),
            )
        });
    });

    group.finish();
}

// --- Combined rules on one resource (realistic shape) ---

fn bench_combined_rules(c: &mut Criterion) {
    let mut group = c.benchmark_group("check_combined_rules");

    // Resource carries: classification (HIERARCHY), department (ANY_OF), country (ALL_OF).
    let pdp = AccessPdp::new(
        vec![
            hierarchy_attr(
                "classification",
                &["topsecret", "secret", "confidential", "public"],
            ),
            any_of_attr("department", &["engineering", "finance", "sales", "rnd"]),
            all_of_attr("country", &["usa", "uk"]),
        ],
        PdpOptions::default(),
    )
    .unwrap();

    let action = Action::new("read");
    let resource = vec![
        val_fqn("classification", "secret"),
        val_fqn("department", "engineering"),
        val_fqn("country", "usa"),
        val_fqn("country", "uk"),
    ];

    let allow_ents = ents(&[
        (&val_fqn("classification", "topsecret"), &["read"]),
        (&val_fqn("department", "engineering"), &["read"]),
        (&val_fqn("country", "usa"), &["read"]),
        (&val_fqn("country", "uk"), &["read"]),
    ]);
    group.bench_function("3_rules_allow", |b| {
        b.iter(|| {
            black_box(
                pdp.check(
                    black_box(&allow_ents),
                    black_box(&action),
                    black_box(&resource),
                )
                .unwrap(),
            )
        });
    });

    // Same resource, missing the UK entitlement -> ALL_OF fails.
    let deny_ents = ents(&[
        (&val_fqn("classification", "topsecret"), &["read"]),
        (&val_fqn("department", "engineering"), &["read"]),
        (&val_fqn("country", "usa"), &["read"]),
    ]);
    group.bench_function("3_rules_deny_on_all_of", |b| {
        b.iter(|| {
            black_box(
                pdp.check(
                    black_box(&deny_ents),
                    black_box(&action),
                    black_box(&resource),
                )
                .unwrap(),
            )
        });
    });

    group.finish();
}

// --- Early-exit deny path: resource carries an unknown FQN ---

fn bench_unknown_fqn_deny(c: &mut Criterion) {
    let pdp = AccessPdp::new(
        vec![hierarchy_attr(
            "classification",
            &["topsecret", "secret", "confidential", "public"],
        )],
        PdpOptions::default(),
    )
    .unwrap();
    let action = Action::new("read");
    let entitlements = ents(&[(&val_fqn("classification", "topsecret"), &["read"])]);
    let resource = vec![
        val_fqn("classification", "secret"),
        // Unknown FQN forces immediate deny.
        "https://bench.example.com/attr/classification/value/cosmic".to_string(),
    ];
    c.bench_function("check_unknown_fqn_early_deny", |b| {
        b.iter(|| {
            black_box(
                pdp.check(
                    black_box(&entitlements),
                    black_box(&action),
                    black_box(&resource),
                )
                .unwrap(),
            )
        });
    });
}

// --- Scaling: entitlement-set size ---

fn bench_entitlement_set_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("check_entitlement_set_size");

    // Single ANY_OF attribute with 50 values; resource demands one of them.
    let values: Vec<String> = (0..50).map(|i| format!("v{i}")).collect();
    let value_refs: Vec<&str> = values.iter().map(String::as_str).collect();
    let attr = any_of_attr("bucket", &value_refs);
    let pdp = AccessPdp::new(vec![attr], PdpOptions::default()).unwrap();
    let action = Action::new("read");
    let resource = vec![val_fqn("bucket", "v25")];

    for size in [1, 10, 50].iter() {
        let pairs: Vec<(String, Vec<String>)> = (0..*size)
            .map(|i| {
                (
                    val_fqn("bucket", &format!("v{i}")),
                    vec!["read".to_string()],
                )
            })
            .collect();
        let entitlements: Entitlements = pairs.into_iter().collect();

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(
                    pdp.check(
                        black_box(&entitlements),
                        black_box(&action),
                        black_box(&resource),
                    )
                    .unwrap(),
                )
            });
        });
    }
    group.finish();
}

// --- Scaling: policy catalog size (many attribute definitions loaded) ---

fn bench_policy_catalog_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("check_policy_catalog_size");

    for n_attrs in [10, 100, 1000].iter() {
        let attrs: Vec<Attribute> = (0..*n_attrs)
            .map(|i| any_of_attr(&format!("attr{i}"), &["a", "b", "c"]))
            .collect();
        let pdp = AccessPdp::new(attrs, PdpOptions::default()).unwrap();
        let action = Action::new("read");
        // The check is always against one specific attribute regardless of catalog size.
        let resource = vec![val_fqn(&format!("attr{}", n_attrs / 2), "a")];
        let entitlements = ents(&[(&val_fqn(&format!("attr{}", n_attrs / 2), "a"), &["read"])]);

        group.bench_with_input(BenchmarkId::from_parameter(n_attrs), n_attrs, |b, _| {
            b.iter(|| {
                black_box(
                    pdp.check(
                        black_box(&entitlements),
                        black_box(&action),
                        black_box(&resource),
                    )
                    .unwrap(),
                )
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_single_rule,
    bench_combined_rules,
    bench_unknown_fqn_deny,
    bench_entitlement_set_size,
    bench_policy_catalog_size,
);
criterion_main!(benches);
