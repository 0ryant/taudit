//! Criterion benches for the custom invariant DSL.
//!
//! Measures both YAML loading cost and per-graph evaluation cost as the
//! number of loaded invariants grows (1, 10, 100). Covers the v0.9 DSL
//! additions: `graph_metadata:`, `standalone:` (node-shape-only), and the
//! `not:` negation predicate.
#![allow(clippy::all)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::HashMap;
use taudit_core::custom_rules::{evaluate_custom_rules, parse_rules_multi_doc};
use taudit_core::graph::{
    AuthorityGraph, EdgeKind, NodeKind, PipelineSource, TrustZone, META_TRIGGER,
};
use taudit_core::propagation::{propagation_analysis, DEFAULT_MAX_HOPS};

/// Single propagation invariant — back-compat shape.
const RULE_PROPAGATION: &str = r#"
id: bench_propagation_to_untrusted
name: Secret reaches untrusted
severity: critical
category: authority_propagation
match:
  source:
    node_type: secret
  sink:
    trust_zone: untrusted
  path:
    crosses_to: [untrusted]
"#;

/// Standalone (node-shape-only) invariant — v0.9 addition.
const RULE_STANDALONE: &str = r#"
id: bench_standalone_floating_image
name: Standalone floating image
severity: high
category: floating_image
match:
  standalone:
    node_type: image
    not:
      metadata:
        digest:
          equals: pinned
"#;

/// Graph-metadata-gated invariant with negation — v0.9 addition.
const RULE_GRAPH_METADATA: &str = r#"
id: bench_graph_metadata_pr_target
name: PR-target trigger with secret access
severity: critical
category: trigger_context_mismatch
match:
  graph_metadata:
    trigger:
      contains: pull_request_target
  source:
    node_type: secret
  sink:
    trust_zone: [third_party, untrusted]
"#;

/// Build a YAML multi-doc string with `n` invariants by cycling through the
/// three DSL shapes. Each invariant gets a unique `id:` so the loader doesn't
/// dedupe / collide.
fn make_invariants_yaml(n: usize) -> String {
    let templates = [RULE_PROPAGATION, RULE_STANDALONE, RULE_GRAPH_METADATA];
    let mut out = String::new();
    for i in 0..n {
        let raw = templates[i % templates.len()];
        // Rewrite `id:` so each rule is distinct (otherwise the loader treats
        // them as duplicates of the same logical rule, which is uninteresting
        // for a perf bench).
        let renamed = raw.replacen("id: ", &format!("id: bench_rule_{i}_"), 1);
        if i > 0 {
            out.push_str("\n---\n");
        }
        out.push_str(renamed.trim_start());
    }
    out
}

/// Fixture graph with the shape needed to exercise all three rule types:
/// a Secret reaching an Untrusted Step, a floating Image, and a
/// `pull_request_target` graph-level trigger.
fn make_fixture_graph() -> AuthorityGraph {
    let mut g = AuthorityGraph::new(PipelineSource {
        file: "custom-rules-fixture.yml".into(),
        repo: None,
        git_ref: None,
        commit_sha: None,
    });
    g.metadata.insert(
        META_TRIGGER.to_string(),
        "pull_request_target,push".to_string(),
    );

    let secret = g.add_node(NodeKind::Secret, "DEPLOY_KEY", TrustZone::FirstParty);
    let step = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
    let artifact = g.add_node(NodeKind::Artifact, "dist.tar.gz", TrustZone::FirstParty);
    let untrusted_step = g.add_node(NodeKind::Step, "third_party_publish", TrustZone::Untrusted);
    // Floating image (no `digest=pinned` metadata) — exercises standalone+not.
    let _floating = g.add_node_with_metadata(
        NodeKind::Image,
        "untrusted/img@main",
        TrustZone::Untrusted,
        HashMap::new(),
    );

    g.add_edge(step, secret, EdgeKind::HasAccessTo);
    g.add_edge(step, artifact, EdgeKind::Produces);
    g.add_edge(artifact, untrusted_step, EdgeKind::Consumes);

    g
}

fn bench_load_invariants(c: &mut Criterion) {
    let mut group = c.benchmark_group("custom_rules_load");
    for &n in &[1usize, 10, 100] {
        let yaml = make_invariants_yaml(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &yaml, |b, y| {
            b.iter(|| parse_rules_multi_doc(y).expect("invariant YAML must parse"));
        });
    }
    group.finish();
}

fn bench_evaluate_invariants(c: &mut Criterion) {
    let mut group = c.benchmark_group("custom_rules_evaluate");
    let graph = make_fixture_graph();
    let paths = propagation_analysis(&graph, DEFAULT_MAX_HOPS);

    for &n in &[1usize, 10, 100] {
        let yaml = make_invariants_yaml(n);
        let rules = parse_rules_multi_doc(&yaml).expect("invariant YAML must parse");
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &rules, |b, r| {
            b.iter(|| evaluate_custom_rules(&graph, &paths, r));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_load_invariants, bench_evaluate_invariants);
criterion_main!(benches);
