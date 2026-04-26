//! Criterion benches for individual analysis rules + the full `run_all_rules`
//! aggregation.
//!
//! Goal: surface rules whose cost grows non-linearly with graph size. Each
//! bench evaluates one rule (or the full set) against three graph sizes so
//! the per-call µs trend over (10, 100, 1000) nodes is visible.
#![allow(clippy::all)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::HashMap;
use taudit_core::graph::{
    AuthorityGraph, EdgeKind, NodeKind, PipelineSource, TrustZone, META_TRIGGER,
};
use taudit_core::propagation::DEFAULT_MAX_HOPS;
use taudit_core::rules::{
    authority_propagation, over_privileged_identity, run_all_rules, unpinned_action,
    untrusted_with_authority,
};

/// Build a graph with a realistic mix of node shapes that exercises many
/// rules at once: identities, secrets, unpinned action images, third-party
/// steps, and a `pull_request_target` graph metadata trigger.
fn make_fixture_graph(n_steps: usize) -> AuthorityGraph {
    let mut g = AuthorityGraph::new(PipelineSource {
        file: format!("rules-fixture-{n_steps}.yml"),
        repo: None,
        git_ref: None,
        commit_sha: None,
    });
    g.metadata
        .insert(META_TRIGGER.to_string(), "pull_request_target".to_string());

    // One broad identity (over_privileged_identity, etc.)
    let mut perms_meta = HashMap::new();
    perms_meta.insert("permissions".to_string(), "write-all".to_string());
    perms_meta.insert("identity_scope".to_string(), "broad".to_string());
    let identity = g.add_node_with_metadata(
        NodeKind::Identity,
        "GITHUB_TOKEN",
        TrustZone::FirstParty,
        perms_meta,
    );

    // One secret, one floating image (unpinned), one untrusted step.
    let secret = g.add_node(NodeKind::Secret, "DEPLOY_KEY", TrustZone::FirstParty);
    let unpinned = g.add_node(
        NodeKind::Image,
        "some-org/deploy-action@main",
        TrustZone::Untrusted,
    );
    let untrusted_step = g.add_node(NodeKind::Step, "third_party_publish", TrustZone::Untrusted);

    // n_steps first-party steps producing/consuming artifacts.
    let mut prev_artifact: Option<usize> = None;
    for i in 0..n_steps {
        let step = g.add_node(NodeKind::Step, format!("step_{i}"), TrustZone::FirstParty);
        if i == 0 {
            g.add_edge(step, secret, EdgeKind::HasAccessTo);
            g.add_edge(step, identity, EdgeKind::HasAccessTo);
        }
        if let Some(prev) = prev_artifact {
            g.add_edge(prev, step, EdgeKind::Consumes);
        }
        let artifact = g.add_node(
            NodeKind::Artifact,
            format!("artifact_{i}"),
            TrustZone::FirstParty,
        );
        g.add_edge(step, artifact, EdgeKind::Produces);
        prev_artifact = Some(artifact);
    }

    // Connect the chain into the untrusted step + unpinned image.
    if let Some(last) = prev_artifact {
        g.add_edge(last, untrusted_step, EdgeKind::Consumes);
    }
    g.add_edge(untrusted_step, unpinned, EdgeKind::UsesImage);

    g
}

fn bench_individual_rules(c: &mut Criterion) {
    let mut group = c.benchmark_group("rules_individual");
    for &n in &[10usize, 100, 1000] {
        let graph = make_fixture_graph(n);
        group.throughput(Throughput::Elements(graph.nodes.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("authority_propagation", n),
            &graph,
            |b, g| {
                b.iter(|| authority_propagation(g, DEFAULT_MAX_HOPS));
            },
        );
        group.bench_with_input(BenchmarkId::new("unpinned_action", n), &graph, |b, g| {
            b.iter(|| unpinned_action(g));
        });
        group.bench_with_input(
            BenchmarkId::new("untrusted_with_authority", n),
            &graph,
            |b, g| {
                b.iter(|| untrusted_with_authority(g));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("over_privileged_identity", n),
            &graph,
            |b, g| {
                b.iter(|| over_privileged_identity(g));
            },
        );
    }
    group.finish();
}

fn bench_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("rules_run_all");
    for &n in &[10usize, 100, 1000] {
        let graph = make_fixture_graph(n);
        group.throughput(Throughput::Elements(graph.nodes.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &graph, |b, g| {
            b.iter(|| run_all_rules(g, DEFAULT_MAX_HOPS));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_individual_rules, bench_full_pipeline);
criterion_main!(benches);
