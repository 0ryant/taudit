use crate::graph::{AuthorityGraph, EdgeId, NodeId, TrustZone};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// A path that authority took through the graph.
/// The path is the product — it's what makes findings persuasive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationPath {
    /// The authority origin (Secret or Identity).
    pub source: NodeId,
    /// Where authority ended up.
    pub sink: NodeId,
    /// The full edge path from source to sink.
    pub edges: Vec<EdgeId>,
    /// Did this path cross a trust zone boundary?
    pub crossed_boundary: bool,
    /// If crossed, from which zone to which zone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boundary_crossing: Option<(TrustZone, TrustZone)>,
}

/// Default maximum BFS depth. Override via CLI --max-hops.
pub const DEFAULT_MAX_HOPS: usize = 4;

/// Walk the graph from every authority-bearing source node (Secret + Identity).
/// Flag any path that reaches a node in a lower trust zone.
///
/// Propagation continues unless an explicit isolation boundary breaks it.
/// Generic traversal with a configurable depth cap — no theory around hop count.
pub fn propagation_analysis(graph: &AuthorityGraph, max_hops: usize) -> Vec<PropagationPath> {
    let mut results = Vec::new();

    for source_node in graph.authority_sources() {
        // Find all steps that have access to this authority source.
        // The edges point from step -> source (HasAccessTo), so we look at edges_to.
        let accessor_steps: Vec<NodeId> = graph
            .edges_to(source_node.id)
            .filter(|e| e.kind == crate::graph::EdgeKind::HasAccessTo)
            .map(|e| e.from)
            .collect();

        for start_step in accessor_steps {
            // BFS from the step that holds this authority
            let mut queue: VecDeque<(NodeId, Vec<EdgeId>, usize)> = VecDeque::new();
            let mut visited = vec![false; graph.nodes.len()];

            // Seed: the step that directly accesses the authority source
            visited[start_step] = true;

            // Add all outgoing edges from the start step
            for edge in graph.edges_from(start_step) {
                queue.push_back((edge.to, vec![edge.id], 1));
            }

            while let Some((current_id, path, depth)) = queue.pop_front() {
                if depth > max_hops || visited[current_id] {
                    continue;
                }
                visited[current_id] = true;

                let current_node = match graph.node(current_id) {
                    Some(n) => n,
                    None => continue,
                };

                let source_zone = source_node.trust_zone;
                let current_zone = current_node.trust_zone;
                let crossed = current_zone.is_lower_than(&source_zone);

                if crossed {
                    results.push(PropagationPath {
                        source: source_node.id,
                        sink: current_id,
                        edges: path.clone(),
                        crossed_boundary: true,
                        boundary_crossing: Some((source_zone, current_zone)),
                    });
                }

                // Continue BFS through outgoing edges
                for edge in graph.edges_from(current_id) {
                    if !visited[edge.to] {
                        let mut new_path = path.clone();
                        new_path.push(edge.id);
                        queue.push_back((edge.to, new_path, depth + 1));
                    }
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
}
