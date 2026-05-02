use crate::graph::{AuthorityGraph, EdgeId, NodeId};
use std::collections::VecDeque;

// `PropagationPath` is a wire type — the BFS engine here computes them, but
// the struct itself lives in `taudit-api` (it serialises into `Finding.path`
// in JSON output and into the standalone `authority-propagation-summary.v1.json`
// schema). Re-export so existing in-tree imports stay green.
pub use taudit_api::PropagationPath;

/// Default maximum BFS depth. Override via CLI --max-hops.
pub const DEFAULT_MAX_HOPS: usize = 4;

/// Node-count threshold above which the dense-graph guard activates.
/// Graphs at or below this size are always scanned regardless of edge density.
pub const DENSE_GRAPH_NODE_THRESHOLD: usize = 50_000;

/// Edge-to-node ratio above which a graph is considered "dense" for the
/// purposes of the safety guard. A graph with `V > DENSE_GRAPH_NODE_THRESHOLD`
/// AND `E > V * DENSE_GRAPH_EDGE_RATIO` will be refused unless the caller
/// passes `force_dense = true` (CLI: `--force-scan-dense`).
pub const DENSE_GRAPH_EDGE_RATIO: usize = 5;

/// Error returned when a graph is too dense to scan safely without an
/// explicit override. The error message is the user-visible string the
/// CLI surfaces verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenseGraphError {
    pub nodes: usize,
    pub edges: usize,
}

impl std::fmt::Display for DenseGraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "graph too dense to scan safely (V={}, E={}); use --force-scan-dense to override",
            self.nodes, self.edges
        )
    }
}

impl std::error::Error for DenseGraphError {}

/// Returns true when the graph exceeds the size+density thresholds the
/// propagation engine considers a DoS risk. Used by both the engine and
/// the CLI surface.
///
/// Note: On 32-bit systems, graphs approaching usize::MAX nodes/edges are
/// conservatively treated as dense to avoid overflow edge cases.
pub fn is_dense_graph(graph: &AuthorityGraph) -> bool {
    let v = graph.nodes.len();
    let e = graph.edges.len();

    // Sanity check: if v or e are close to usize::MAX on 32-bit systems,
    // conservatively treat as dense to avoid any overflow edge cases
    if v > (usize::MAX / 10) || e > (usize::MAX / 10) {
        return true;
    }

    v > DENSE_GRAPH_NODE_THRESHOLD && e > v.saturating_mul(DENSE_GRAPH_EDGE_RATIO)
}

/// Walk the graph from every authority-bearing source node (Secret + Identity).
/// Flag any path that reaches a node in a lower trust zone.
///
/// Backward-compatible entry point — does NOT enforce the dense-graph guard
/// (preserves existing behaviour for callers that haven't opted into the
/// safety check). New callers should prefer `propagation_analysis_checked`
/// which returns an error on dense graphs unless explicitly overridden.
pub fn propagation_analysis(graph: &AuthorityGraph, max_hops: usize) -> Vec<PropagationPath> {
    propagation_analysis_inner(graph, max_hops)
}

/// Density-gated entry point. Returns `Err(DenseGraphError)` when the graph
/// exceeds size+density thresholds AND `force_dense` is false. Otherwise
/// behaves like `propagation_analysis`.
pub fn propagation_analysis_checked(
    graph: &AuthorityGraph,
    max_hops: usize,
    force_dense: bool,
) -> Result<Vec<PropagationPath>, DenseGraphError> {
    if !force_dense && is_dense_graph(graph) {
        return Err(DenseGraphError {
            nodes: graph.nodes.len(),
            edges: graph.edges.len(),
        });
    }
    Ok(propagation_analysis_inner(graph, max_hops))
}

/// The actual BFS engine. Pre-builds an adjacency-list index once per call
/// so the inner loop never linear-scans the edge vector.
///
/// Complexity: O(sources × (V + E)) once adjacency is built. The previous
/// implementation was O(sources × accessor_steps × V × E) because
/// `edges_from`/`edges_to` are O(E) linear filters on the edge vector and
/// the BFS reseeded from every accessor step independently. On the
/// `dense_5x` bench at V=10 000 the pathological cost was ~1.08 s; with
/// adjacency pre-indexing and per-source visited sharing it drops to
/// well under 100 ms.
fn propagation_analysis_inner(graph: &AuthorityGraph, max_hops: usize) -> Vec<PropagationPath> {
    let n = graph.nodes.len();
    let mut results = Vec::new();

    if n == 0 {
        return results;
    }

    // Outgoing adjacency: for each node, the (edge_id, dest_node_id) pairs.
    let mut adj_out: Vec<Vec<(EdgeId, NodeId)>> = vec![Vec::new(); n];
    // Incoming HasAccessTo edges keyed by destination — we only need this
    // edge kind for finding accessor steps, so filter at index time.
    let mut accessors_for: Vec<Vec<NodeId>> = vec![Vec::new(); n];

    for edge in &graph.edges {
        if edge.from < n && edge.to < n {
            adj_out[edge.from].push((edge.id, edge.to));
            if edge.kind == crate::graph::EdgeKind::HasAccessTo {
                accessors_for[edge.to].push(edge.from);
            }
        }
    }

    // Reused buffers across sources to avoid per-source allocator churn on
    // large graphs. `visited` is bulk-reset to false on each iteration; on
    // small graphs that's a couple cache lines, on large graphs it's a
    // single linear write — still strictly cheaper than re-allocating.
    let mut visited: Vec<bool> = vec![false; n];
    let mut queue: VecDeque<(NodeId, Vec<EdgeId>, usize)> = VecDeque::new();

    for source_node in graph.authority_sources() {
        let accessor_steps = &accessors_for[source_node.id];
        if accessor_steps.is_empty() {
            continue;
        }

        // Bulk reset visited buffer for this source's BFS.
        for v in visited.iter_mut() {
            *v = false;
        }
        queue.clear();

        // Seed the BFS with every accessor step at once (single visited
        // set, single frontier) — the previous code ran an independent
        // BFS per accessor step, which on dense graphs duplicated O(V·E)
        // work for every additional accessor.
        for &start_step in accessor_steps {
            if !visited[start_step] {
                visited[start_step] = true;
                for &(edge_id, to) in &adj_out[start_step] {
                    queue.push_back((to, vec![edge_id], 1));
                }
            }
        }

        let source_zone = source_node.trust_zone;

        while let Some((current_id, path, depth)) = queue.pop_front() {
            if visited[current_id] {
                continue;
            }
            if depth > max_hops {
                continue;
            }
            visited[current_id] = true;

            let current_node = match graph.node(current_id) {
                Some(n) => n,
                None => continue,
            };

            let current_zone = current_node.trust_zone;
            if current_zone.is_lower_than(&source_zone) {
                results.push(PropagationPath {
                    source: source_node.id,
                    sink: current_id,
                    edges: path.clone(),
                    crossed_boundary: true,
                    boundary_crossing: Some((source_zone, current_zone)),
                });
            }

            if depth >= max_hops {
                continue;
            }

            for &(edge_id, to) in &adj_out[current_id] {
                if !visited[to] {
                    let mut new_path = path.clone();
                    new_path.push(edge_id);
                    queue.push_back((to, new_path, depth + 1));
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::*;

    fn make_source(file: &str) -> PipelineSource {
        PipelineSource {
            file: file.into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        }
    }

    #[test]
    fn detects_secret_propagation_across_trust_boundary() {
        let mut g = AuthorityGraph::new(make_source("test.yml"));

        // Secret in first-party zone
        let secret = g.add_node(NodeKind::Secret, "AWS_KEY", TrustZone::FirstParty);
        // First-party build step reads the secret
        let build = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        // Build produces an artifact
        let artifact = g.add_node(NodeKind::Artifact, "dist.tar.gz", TrustZone::FirstParty);
        // Third-party deploy step consumes the artifact
        let deploy = g.add_node(NodeKind::Step, "deploy", TrustZone::ThirdParty);

        g.add_edge(build, secret, EdgeKind::HasAccessTo);
        g.add_edge(build, artifact, EdgeKind::Produces);
        g.add_edge(artifact, deploy, EdgeKind::Consumes);

        let paths = propagation_analysis(&g, DEFAULT_MAX_HOPS);

        assert!(!paths.is_empty(), "should detect propagation");
        assert!(paths
            .iter()
            .any(|p| p.source == secret && p.crossed_boundary));
    }

    #[test]
    fn no_finding_when_same_trust_zone() {
        let mut g = AuthorityGraph::new(make_source("test.yml"));

        let secret = g.add_node(NodeKind::Secret, "TOKEN", TrustZone::FirstParty);
        let step_a = g.add_node(NodeKind::Step, "lint", TrustZone::FirstParty);
        let step_b = g.add_node(NodeKind::Step, "test", TrustZone::FirstParty);
        let artifact = g.add_node(NodeKind::Artifact, "output", TrustZone::FirstParty);

        g.add_edge(step_a, secret, EdgeKind::HasAccessTo);
        g.add_edge(step_a, artifact, EdgeKind::Produces);
        g.add_edge(artifact, step_b, EdgeKind::Consumes);

        let paths = propagation_analysis(&g, DEFAULT_MAX_HOPS);

        let boundary_crossings: Vec<_> = paths.iter().filter(|p| p.crossed_boundary).collect();
        assert!(
            boundary_crossings.is_empty(),
            "no boundary crossing expected"
        );
    }

    #[test]
    fn respects_max_hops() {
        let mut g = AuthorityGraph::new(make_source("test.yml"));

        let secret = g.add_node(NodeKind::Secret, "KEY", TrustZone::FirstParty);
        let s1 = g.add_node(NodeKind::Step, "s1", TrustZone::FirstParty);
        let a1 = g.add_node(NodeKind::Artifact, "a1", TrustZone::FirstParty);
        let s2 = g.add_node(NodeKind::Step, "s2", TrustZone::FirstParty);
        let a2 = g.add_node(NodeKind::Artifact, "a2", TrustZone::FirstParty);
        let s3 = g.add_node(NodeKind::Step, "s3", TrustZone::Untrusted);

        g.add_edge(s1, secret, EdgeKind::HasAccessTo);
        g.add_edge(s1, a1, EdgeKind::Produces);
        g.add_edge(a1, s2, EdgeKind::Consumes);
        g.add_edge(s2, a2, EdgeKind::Produces);
        g.add_edge(a2, s3, EdgeKind::Consumes);

        // With max_hops=2, should NOT reach s3 (which is 4 edges away)
        let paths_short = propagation_analysis(&g, 2);
        let boundary_short: Vec<_> = paths_short.iter().filter(|p| p.crossed_boundary).collect();
        assert!(
            boundary_short.is_empty(),
            "should not reach untrusted at depth 2"
        );

        // With max_hops=5, should reach s3
        let paths_long = propagation_analysis(&g, 5);
        let boundary_long: Vec<_> = paths_long.iter().filter(|p| p.crossed_boundary).collect();
        assert!(
            !boundary_long.is_empty(),
            "should reach untrusted at depth 5"
        );
    }

    #[test]
    fn identity_is_authority_source() {
        let mut g = AuthorityGraph::new(make_source("test.yml"));

        let identity = g.add_node(NodeKind::Identity, "GITHUB_TOKEN", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "publish", TrustZone::FirstParty);
        let action = g.add_node(
            NodeKind::Image,
            "third-party/deploy@main",
            TrustZone::Untrusted,
        );

        g.add_edge(step, identity, EdgeKind::HasAccessTo);
        g.add_edge(step, action, EdgeKind::UsesImage);

        let paths = propagation_analysis(&g, DEFAULT_MAX_HOPS);
        assert!(paths
            .iter()
            .any(|p| p.source == identity && p.crossed_boundary));
    }

    #[test]
    fn dense_graph_check_rejects_oversized_input() {
        // Construct a synthetic graph that crosses BOTH the node-count and
        // density thresholds. We don't need real authority — only the
        // shape matters for the gate.
        let mut g = AuthorityGraph::new(make_source("dense.yml"));
        let n = DENSE_GRAPH_NODE_THRESHOLD + 10;
        let e_per_node = DENSE_GRAPH_EDGE_RATIO + 1;

        for i in 0..n {
            g.add_node(NodeKind::Step, format!("s{i}"), TrustZone::FirstParty);
        }
        for i in 0..n {
            for k in 0..e_per_node {
                let to = (i + k + 1) % n;
                g.add_edge(i, to, EdgeKind::DelegatesTo);
            }
        }

        assert!(is_dense_graph(&g), "fixture should trip the density gate");

        let err = propagation_analysis_checked(&g, DEFAULT_MAX_HOPS, false).unwrap_err();
        assert_eq!(err.nodes, n);
        assert!(err.to_string().contains("--force-scan-dense"));
        assert!(err.to_string().contains("graph too dense"));
    }

    #[test]
    fn force_scan_dense_overrides_the_gate() {
        // Same fixture, but pass force_dense=true — the scan must run to
        // completion even though the gate would otherwise fire.
        let mut g = AuthorityGraph::new(make_source("dense.yml"));
        // Smaller fixture so the test stays fast — just past both
        // thresholds is enough; the BFS itself must not panic or hang.
        let n = DENSE_GRAPH_NODE_THRESHOLD + 5;
        let e_per_node = DENSE_GRAPH_EDGE_RATIO + 1;

        for i in 0..n {
            g.add_node(NodeKind::Step, format!("s{i}"), TrustZone::FirstParty);
        }
        for i in 0..n {
            for k in 0..e_per_node {
                let to = (i + k + 1) % n;
                g.add_edge(i, to, EdgeKind::DelegatesTo);
            }
        }

        assert!(is_dense_graph(&g));
        let result = propagation_analysis_checked(&g, DEFAULT_MAX_HOPS, true);
        assert!(
            result.is_ok(),
            "force_dense=true must override the density gate"
        );
        // No authority sources in this graph — result is empty by design.
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn small_graph_below_threshold_passes_check() {
        let mut g = AuthorityGraph::new(make_source("small.yml"));
        let secret = g.add_node(NodeKind::Secret, "K", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "s", TrustZone::Untrusted);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        assert!(!is_dense_graph(&g));
        let result = propagation_analysis_checked(&g, DEFAULT_MAX_HOPS, false);
        assert!(result.is_ok());
    }
}
