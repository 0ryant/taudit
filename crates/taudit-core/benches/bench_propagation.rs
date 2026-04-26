//! Criterion benches for the BFS propagation engine.
//!
//! Measures `propagation_analysis` against synthetic graphs of varying size
//! and edge density. Used as the v0.9 perf baseline for the engine — the
//! propagation walk is the hot path on every `taudit` invocation.
#![allow(clippy::all)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use taudit_core::graph::{AuthorityGraph, EdgeKind, NodeKind, PipelineSource, TrustZone};
use taudit_core::propagation::{propagation_analysis, DEFAULT_MAX_HOPS};

/// Build a synthetic graph with `n_nodes` nodes and roughly
/// `n_nodes * edge_factor` edges.
///
/// Layout: every 4th node is a Secret in the FirstParty zone (authority
/// source). The remaining nodes alternate Step/Artifact roles. Steps in the
/// last 25% of the graph live in the Untrusted zone so the BFS produces
/// real boundary-crossing paths (otherwise the engine short-circuits and
/// the bench measures nothing useful).
///
/// Edge wiring is deterministic, in-degree-bounded, and forms a forward DAG
/// modulo cross-links — close enough to a real workflow's authority shape
/// without depending on a YAML parser.
fn make_graph(n_nodes: usize, edge_factor: f64) -> AuthorityGraph {
    let mut g = AuthorityGraph::new(PipelineSource {
        file: format!("synthetic-{n_nodes}.yml"),
        repo: None,
        git_ref: None,
        commit_sha: None,
    });

    let untrusted_threshold = (n_nodes * 3) / 4;

    // Pre-seed nodes so we have stable IDs to wire edges between.
    let mut node_ids = Vec::with_capacity(n_nodes);
    for i in 0..n_nodes {
        let zone = if i >= untrusted_threshold {
            TrustZone::Untrusted
        } else if i % 8 == 7 {
            TrustZone::ThirdParty
        } else {
            TrustZone::FirstParty
        };
        let (kind, name) = if i % 4 == 0 {
            (NodeKind::Secret, format!("SECRET_{i}"))
        } else if i % 4 == 2 {
            (NodeKind::Artifact, format!("artifact_{i}"))
        } else {
            (NodeKind::Step, format!("step_{i}"))
        };
        node_ids.push(g.add_node(kind, name, zone));
    }

    // Wire edges. Each Step gets `edge_factor` outgoing edges to deterministic
    // downstream targets so propagation has a non-trivial frontier.
    let n_edges = ((n_nodes as f64) * edge_factor) as usize;
    for e in 0..n_edges {
        let from = node_ids[e % n_nodes];
        // Skip Secret/Artifact-as-from for HasAccessTo wiring; we put HasAccessTo
        // edges in a dedicated pass below.
        let from_kind = g.nodes[from].kind;
        if matches!(from_kind, NodeKind::Secret | NodeKind::Identity) {
            continue;
        }
        // Deterministic forward target with a small backward-jump probability so
        // the graph isn't strictly layered.
        let offset = 1 + (e * 7) % 11;
        let to = node_ids[(from + offset) % n_nodes];
        if from == to {
            continue;
        }

        // Pick an edge kind that's structurally compatible with the from/to
        // node kinds. The propagation engine only cares about reachability,
        // but using realistic kinds keeps the bench honest if rules ever
        // start filtering on them.
        let kind = match (g.nodes[from].kind, g.nodes[to].kind) {
            (NodeKind::Step, NodeKind::Artifact) => EdgeKind::Produces,
            (NodeKind::Artifact, NodeKind::Step) => EdgeKind::Consumes,
            (NodeKind::Step, NodeKind::Image) => EdgeKind::UsesImage,
            (NodeKind::Step, NodeKind::Step) => EdgeKind::DelegatesTo,
            _ => EdgeKind::DelegatesTo,
        };
        g.add_edge(from, to, kind);
    }

    // Wire one HasAccessTo edge per Secret -> nearest Step so every authority
    // source has a real entry point into the BFS frontier.
    let secret_ids: Vec<_> = g
        .nodes
        .iter()
        .filter(|n| n.kind == NodeKind::Secret)
        .map(|n| n.id)
        .collect();
    for sid in secret_ids {
        // Find the next Step after this secret.
        let next_step = (sid + 1..n_nodes)
            .find(|i| g.nodes[*i].kind == NodeKind::Step)
            .or_else(|| (0..sid).find(|i| g.nodes[*i].kind == NodeKind::Step));
        if let Some(step) = next_step {
            g.add_edge(step, sid, EdgeKind::HasAccessTo);
        }
    }

    g
}

fn bench_propagation_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("propagation_scaling");
    // Throughput in nodes — gives elements/sec which makes scaling visible
    // across input sizes (linear engine should hold elements/sec ~constant).
    for &n in &[10usize, 100, 1000, 10_000] {
        for &density in &[("sparse_1.5x", 1.5_f64), ("dense_5x", 5.0_f64)] {
            let (label, factor) = density;
            let graph = make_graph(n, factor);
            group.throughput(Throughput::Elements((n + graph.edges.len()) as u64));
            group.bench_with_input(BenchmarkId::new(label, n), &graph, |b, g| {
                b.iter(|| propagation_analysis(g, DEFAULT_MAX_HOPS));
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_propagation_scaling);
criterion_main!(benches);
