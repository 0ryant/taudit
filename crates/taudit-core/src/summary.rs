//! Deterministic propagation aggregates for triage (ADR 0002 Phase 3).
//!
//! Summaries are **read-only projections** over the same BFS the rule engine
//! uses for boundary crossings — they **inform** analysis; [`crate::rules`]
//! and **`verify`** remain the policy surfaces.

use crate::graph::{AuthorityCompleteness, AuthorityGraph, NodeId, NodeKind, TrustZone};
use crate::propagation::{propagation_analysis_checked, DenseGraphError, PropagationPath};
use serde::Serialize;
use std::collections::HashMap;

/// Semver for [`AuthorityPropagationSummaryDocument`] JSON.
pub const AUTHORITY_PROPAGATION_SUMMARY_SCHEMA_VERSION: &str = "1.0.0";

/// JSON Schema `$id` for the propagation summary document.
pub const AUTHORITY_PROPAGATION_SUMMARY_SCHEMA_URI: &str =
    "https://taudit.dev/schemas/authority-propagation-summary.v1.json";

/// Max rows in each ranked list for bounded output size.
pub const PROPAGATION_SUMMARY_TOP_N: usize = 32;

/// One row in a ranked list of nodes by path count.
#[derive(Debug, Clone, Serialize)]
pub struct PropagationNodeAgg {
    pub node_id: NodeId,
    pub kind: NodeKind,
    pub name: String,
    pub trust_zone: TrustZone,
    pub path_count: usize,
}

/// Rollup counts over all boundary-crossing propagation paths.
#[derive(Debug, Clone, Serialize)]
pub struct PropagationSummaryTotals {
    /// Paths where authority reaches a strictly lower trust zone than its source.
    pub boundary_path_count: usize,
    pub distinct_authority_sources: usize,
    pub distinct_sinks: usize,
}

/// Standalone JSON document for `taudit graph --format summary`.
#[derive(Debug, Clone, Serialize)]
pub struct AuthorityPropagationSummaryDocument {
    pub schema_version: &'static str,
    pub schema_uri: &'static str,
    pub source_file: String,
    pub graph_completeness: AuthorityCompleteness,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub completeness_gaps: Vec<String>,
    pub max_hops: usize,
    pub method: &'static str,
    pub totals: PropagationSummaryTotals,
    pub top_sinks_by_path_count: Vec<PropagationNodeAgg>,
    pub top_sources_by_path_count: Vec<PropagationNodeAgg>,
}

fn rank_node_aggs(
    counts: HashMap<NodeId, usize>,
    graph: &AuthorityGraph,
    top_n: usize,
) -> Vec<PropagationNodeAgg> {
    let mut pairs: Vec<(NodeId, usize)> = counts.into_iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    pairs
        .into_iter()
        .take(top_n)
        .filter_map(|(id, path_count)| {
            let n = graph.node(id)?;
            Some(PropagationNodeAgg {
                node_id: id,
                kind: n.kind,
                name: n.name.clone(),
                trust_zone: n.trust_zone,
                path_count,
            })
        })
        .collect()
}

/// Build a bounded propagation summary from `graph`, using the same density gate
/// as [`crate::propagation::propagation_analysis_checked`].
pub fn build_authority_propagation_summary(
    graph: &AuthorityGraph,
    max_hops: usize,
    force_dense: bool,
) -> Result<AuthorityPropagationSummaryDocument, DenseGraphError> {
    let paths: Vec<PropagationPath> = propagation_analysis_checked(graph, max_hops, force_dense)?;

    let mut sink_count: HashMap<NodeId, usize> = HashMap::new();
    let mut source_count: HashMap<NodeId, usize> = HashMap::new();
    for p in &paths {
        *sink_count.entry(p.sink).or_insert(0) += 1;
        *source_count.entry(p.source).or_insert(0) += 1;
    }

    Ok(AuthorityPropagationSummaryDocument {
        schema_version: AUTHORITY_PROPAGATION_SUMMARY_SCHEMA_VERSION,
        schema_uri: AUTHORITY_PROPAGATION_SUMMARY_SCHEMA_URI,
        source_file: graph.source.file.clone(),
        graph_completeness: graph.completeness,
        completeness_gaps: graph.completeness_gaps.clone(),
        max_hops,
        method: "bfs_lower_trust_zone_sinks",
        totals: PropagationSummaryTotals {
            boundary_path_count: paths.len(),
            distinct_authority_sources: source_count.len(),
            distinct_sinks: sink_count.len(),
        },
        top_sinks_by_path_count: rank_node_aggs(sink_count, graph, PROPAGATION_SUMMARY_TOP_N),
        top_sources_by_path_count: rank_node_aggs(source_count, graph, PROPAGATION_SUMMARY_TOP_N),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{EdgeKind, PipelineSource};

    fn src(file: &str) -> PipelineSource {
        PipelineSource {
            file: file.into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        }
    }

    #[test]
    fn summary_counts_crossing_paths() {
        let mut g = AuthorityGraph::new(src("t.yml"));
        let secret = g.add_node(NodeKind::Secret, "K", TrustZone::FirstParty);
        let build = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        let art = g.add_node(NodeKind::Artifact, "a", TrustZone::FirstParty);
        let deploy = g.add_node(NodeKind::Step, "deploy", TrustZone::Untrusted);
        g.add_edge(build, secret, EdgeKind::HasAccessTo);
        g.add_edge(build, art, EdgeKind::Produces);
        g.add_edge(art, deploy, EdgeKind::Consumes);

        let doc =
            build_authority_propagation_summary(&g, crate::propagation::DEFAULT_MAX_HOPS, true)
                .unwrap();
        assert_eq!(doc.totals.boundary_path_count, 1);
        assert_eq!(doc.totals.distinct_authority_sources, 1);
        assert_eq!(doc.totals.distinct_sinks, 1);
        assert_eq!(doc.top_sinks_by_path_count.len(), 1);
        assert_eq!(doc.top_sinks_by_path_count[0].node_id, deploy);
        assert_eq!(doc.top_sources_by_path_count[0].node_id, secret);
    }

    #[test]
    fn summary_empty_when_no_crossing() {
        let mut g = AuthorityGraph::new(src("t.yml"));
        let secret = g.add_node(NodeKind::Secret, "T", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "s", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let doc =
            build_authority_propagation_summary(&g, crate::propagation::DEFAULT_MAX_HOPS, true)
                .unwrap();
        assert_eq!(doc.totals.boundary_path_count, 0);
        assert!(doc.top_sinks_by_path_count.is_empty());
    }
}
