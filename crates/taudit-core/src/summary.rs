//! Deterministic propagation aggregates for triage (ADR 0002 Phase 3).
//!
//! Summaries are **read-only projections** over the same BFS the rule engine
//! uses for boundary crossings — they **inform** analysis; [`crate::rules`]
//! and **`verify`** remain the policy surfaces.

use crate::graph::{AuthorityCompleteness, AuthorityGraph, GapKind, NodeId, NodeKind, TrustZone};
use crate::propagation::{propagation_analysis_checked, DenseGraphError, PropagationPath};
use serde::Serialize;
use std::collections::HashMap;

/// Semver for [`AuthorityPropagationSummaryDocument`] JSON.
///
/// 1.1.0: additive — surfaces `completeness_gap_kinds` and `worst_gap_kind`
/// alongside the existing free-text `completeness_gaps`. Older consumers that
/// validate the schema as written keep working because the schema's
/// `schema_version` const was loosened to a `^1\.\d+\.\d+$` pattern; older
/// consumers that key on field presence ignore unknown fields by default.
pub const AUTHORITY_PROPAGATION_SUMMARY_SCHEMA_VERSION: &str = "1.1.0";

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
    /// Typed gap-kind classifications matching `completeness_gaps` by index.
    /// Parallel array — same length, same order as `completeness_gaps`.
    /// Added in v1.1.0-beta.3 (schema 1.1.0). Older consumers ignore unknown fields.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub completeness_gap_kinds: Vec<GapKind>,
    /// The most severe `GapKind` present in the graph, or `None` if the graph
    /// is `Complete` / `Unknown` or carries no typed gaps. Severity ordering is
    /// canonical to [`GapKind`]: `Opaque > Structural > Expression`.
    /// Added in schema 1.1.0; omitted when absent so older payloads remain valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worst_gap_kind: Option<GapKind>,
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
        completeness_gap_kinds: graph.completeness_gap_kinds.clone(),
        worst_gap_kind: graph.worst_gap_kind(),
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
    fn summary_carries_gap_kinds_from_graph() {
        // Regression: prior to schema 1.1.0 the summary cloned only the
        // free-text `completeness_gaps`, silently dropping the typed
        // `completeness_gap_kinds` taxonomy and `worst_gap_kind`.
        let mut g = AuthorityGraph::new(src("partial.yml"));
        g.mark_partial(GapKind::Structural, "composite action not resolved");
        g.mark_partial(GapKind::Expression, "matrix expansion hides paths");
        g.mark_partial(GapKind::Opaque, "platform unknown");

        let doc =
            build_authority_propagation_summary(&g, crate::propagation::DEFAULT_MAX_HOPS, true)
                .unwrap();

        assert_eq!(doc.graph_completeness, AuthorityCompleteness::Partial);
        assert_eq!(doc.completeness_gaps.len(), 3);
        assert_eq!(
            doc.completeness_gap_kinds,
            vec![GapKind::Structural, GapKind::Expression, GapKind::Opaque,]
        );
        // Parallel-array invariant: same length as the free-text gaps.
        assert_eq!(
            doc.completeness_gap_kinds.len(),
            doc.completeness_gaps.len(),
            "completeness_gap_kinds must be a parallel array of completeness_gaps"
        );
        // Canonical severity ordering on `AuthorityGraph::worst_gap_kind`:
        // Opaque (2) > Structural (1) > Expression (0).
        assert_eq!(doc.worst_gap_kind, Some(GapKind::Opaque));
    }

    #[test]
    fn summary_omits_gap_kinds_when_complete() {
        // schema_version 1.1.0 is additive: a Complete graph emits the doc
        // without `completeness_gap_kinds` or `worst_gap_kind`, keeping the
        // wire-format minimal for the common case.
        let g = AuthorityGraph::new(src("clean.yml"));

        let doc =
            build_authority_propagation_summary(&g, crate::propagation::DEFAULT_MAX_HOPS, true)
                .unwrap();
        assert!(doc.completeness_gap_kinds.is_empty());
        assert_eq!(doc.worst_gap_kind, None);

        let v = serde_json::to_value(&doc).expect("summary doc serialises");
        assert!(
            v.get("completeness_gap_kinds").is_none(),
            "empty completeness_gap_kinds must be skipped on the wire"
        );
        assert!(
            v.get("worst_gap_kind").is_none(),
            "absent worst_gap_kind must be skipped on the wire"
        );
        assert_eq!(
            v.get("schema_version").and_then(|x| x.as_str()),
            Some("1.1.0"),
            "schema_version must reflect the additive 1.1.0 bump"
        );
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
