use taudit_core::error::TauditError;
use taudit_core::finding::{compute_finding_group_id, compute_fingerprint, rule_id_for, Finding};
use taudit_core::graph::{
    is_docker_digest_pinned, is_pin_semantically_valid, AuthorityCompleteness, AuthorityGraph,
    EdgeKind, GapKind, NodeKind, META_CONTAINER, META_OIDC, META_SERVICE_CONNECTION,
    META_SERVICE_CONNECTION_NAME, META_VARIABLE_GROUP,
};
use taudit_core::ports::ReportSink;

use serde::Serialize;

const JSON_REPORT_SCHEMA_VERSION: &str = "1.0.0";
const JSON_REPORT_SCHEMA_URI: &str = "https://taudit.dev/schemas/taudit-report.schema.json";

/// Schema version of the standalone authority-graph export
/// (`taudit graph --format json`). Semver-stable: 1.x.y additions are
/// non-breaking; 2.0.0 means breaking changes.
pub const AUTHORITY_GRAPH_SCHEMA_VERSION: &str = "1.0.0";

/// Canonical URI of the authority-graph JSON Schema.
pub const AUTHORITY_GRAPH_SCHEMA_URI: &str = "https://taudit.dev/schemas/authority-graph.v1.json";

/// JSON report containing the full authority graph and all findings.
#[derive(Serialize)]
pub struct JsonReport<'a> {
    pub schema_version: &'static str,
    /// Canonical URI of the JSON Schema this report conforms to.
    /// Non-breaking addition (1.x consumers ignore unknown fields).
    pub schema_uri: &'static str,
    pub graph: &'a AuthorityGraph,
    pub findings: Vec<FindingWithFingerprint>,
    pub summary: Summary,
}

/// Per-finding wrapper that flattens the upstream `Finding` fields and
/// appends a stable `fingerprint`. The fingerprint matches the value
/// surfaced by SARIF `partialFingerprints[primaryLocationLineHash]` and
/// CloudEvents extension attribute `tauditfindingfingerprint`, so a SIEM
/// keying on any of the three sees the same identifier per finding.
/// See `docs/finding-fingerprint.md` for the contract.
///
/// The `rule_id` field carries the snake_case rule identifier (custom-rule
/// id when the finding came from a YAML rule with a `[id] …` message
/// prefix, otherwise the snake_case form of the category enum). This is
/// the same id surfaced in SARIF `result.ruleId` and CloudEvents
/// `taudit.rule_id`, so JSON consumers can filter/group by rule without
/// re-deriving it from the category serialization.
///
/// The wrapper owns its `Finding` so the JSON sink can populate
/// `extras.finding_group_id` from the fingerprint without mutating the
/// caller's finding list. See `docs/finding-output-enhancements.md`.
#[derive(Serialize)]
pub struct FindingWithFingerprint {
    pub rule_id: String,
    #[serde(flatten)]
    pub finding: Finding,
    pub fingerprint: String,
}

/// Standalone authority-graph export — the document emitted by
/// `taudit graph --format json`. Versioned independently from the scan
/// report because downstream tools (tsign, axiom, runtime cells)
/// consume the graph without caring about findings.
#[derive(Serialize)]
pub struct GraphExport<'a> {
    /// Semver of the authority-graph schema. See `AUTHORITY_GRAPH_SCHEMA_VERSION`.
    pub schema_version: &'static str,
    /// Canonical URI of the schema this document conforms to.
    pub schema_uri: &'static str,
    /// The authority graph itself.
    pub graph: &'a AuthorityGraph,
}

impl<'a> GraphExport<'a> {
    /// Wrap a graph reference in a versioned export envelope.
    pub fn new(graph: &'a AuthorityGraph) -> Self {
        Self {
            schema_version: AUTHORITY_GRAPH_SCHEMA_VERSION,
            schema_uri: AUTHORITY_GRAPH_SCHEMA_URI,
            graph,
        }
    }

    /// Serialize to pretty-printed JSON.
    pub fn to_json_pretty(&self) -> Result<String, TauditError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| TauditError::Report(format!("graph JSON serialization error: {e}")))
    }
}

/// Structured representation of a single graph completeness gap as it
/// appears in `summary.completeness_gaps`. Each entry pairs the typed
/// `GapKind` (so SIEMs can filter by class of imprecision) with the
/// human-readable `reason` (so analysts can read it).
#[derive(Serialize)]
pub struct CompletenessGap {
    pub kind: GapKind,
    pub reason: String,
}

#[derive(Serialize)]
pub struct Summary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total_nodes: usize,
    pub total_edges: usize,
    pub completeness: AuthorityCompleteness,
    /// Structured `{kind, reason}` entries describing why the graph is
    /// partial. Built by zipping `AuthorityGraph.completeness_gap_kinds`
    /// with `AuthorityGraph.completeness_gaps`. Omitted when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub completeness_gaps: Vec<CompletenessGap>,
    /// Compact graph-density rollup for report authors and triage systems.
    /// This is not a finding; it describes how much authority-bearing surface
    /// the graph exposed so large workflows can be discussed without relying
    /// on raw finding count alone.
    #[serde(skip_serializing_if = "GraphRiskSummary::is_empty")]
    pub graph_risk_summary: GraphRiskSummary,
}

/// High-signal graph-density metrics used by reports and dashboards.
#[derive(Serialize, Default)]
pub struct GraphRiskSummary {
    pub authority_roots: usize,
    pub untrusted_sinks: usize,
    pub mutable_refs: usize,
    pub publication_adjacent_sinks: usize,
    pub delegation_hops: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub protected_resource_categories: Vec<String>,
}

impl GraphRiskSummary {
    fn is_empty(&self) -> bool {
        self.authority_roots == 0
            && self.untrusted_sinks == 0
            && self.mutable_refs == 0
            && self.publication_adjacent_sinks == 0
            && self.delegation_hops == 0
            && self.protected_resource_categories.is_empty()
    }
}

fn graph_risk_summary(graph: &AuthorityGraph) -> GraphRiskSummary {
    let mut protected = std::collections::BTreeSet::<String>::new();
    let mut summary = GraphRiskSummary::default();

    for node in &graph.nodes {
        match node.kind {
            NodeKind::Secret | NodeKind::Identity => {
                summary.authority_roots += 1;
            }
            _ => {}
        }

        if node.trust_zone == taudit_core::graph::TrustZone::Untrusted {
            summary.untrusted_sinks += 1;
        }

        if node.kind == NodeKind::Image
            && !node
                .metadata
                .get(META_CONTAINER)
                .map(|v| v == "true")
                .unwrap_or(false)
            && !is_pin_semantically_valid(&node.name)
            && !is_docker_digest_pinned(&node.name)
        {
            summary.mutable_refs += 1;
        }

        let lower = node.name.to_ascii_lowercase();
        if node.kind == NodeKind::Step
            && ["publish", "release", "deploy", "push", "upload"]
                .iter()
                .any(|needle| lower.contains(needle))
        {
            summary.publication_adjacent_sinks += 1;
        }

        if node.metadata.contains_key(META_VARIABLE_GROUP) {
            protected.insert("variable_group".into());
        }
        if node.metadata.contains_key(META_SERVICE_CONNECTION)
            || node.metadata.contains_key(META_SERVICE_CONNECTION_NAME)
        {
            protected.insert("service_connection".into());
        }
        if node.metadata.contains_key(META_OIDC) {
            protected.insert("oidc_identity".into());
        }
        if node.kind == NodeKind::Secret {
            protected.insert("secret".into());
        }
        if node.kind == NodeKind::Identity {
            protected.insert("identity".into());
        }
    }

    summary.delegation_hops = graph
        .edges
        .iter()
        .filter(|edge| edge.kind == EdgeKind::DelegatesTo)
        .count();
    summary.protected_resource_categories = protected.into_iter().collect();
    summary
}

pub struct JsonReportSink;

impl<W: std::io::Write> ReportSink<W> for JsonReportSink {
    fn emit(
        &self,
        w: &mut W,
        graph: &AuthorityGraph,
        findings: &[Finding],
    ) -> Result<(), TauditError> {
        use taudit_core::finding::Severity;

        // For each finding compute the fingerprint and derive the
        // group id from it. We populate `extras.finding_group_id` on a
        // cloned `Finding` so callers' lists stay untouched. If a rule
        // already populated the group id, we respect that value.
        let findings_with_fp: Vec<FindingWithFingerprint> = findings
            .iter()
            .map(|f| {
                let fingerprint = compute_fingerprint(f, graph);
                let rule_id = rule_id_for(f);
                let mut owned = f.clone();
                if owned.extras.finding_group_id.is_none() {
                    owned.extras.finding_group_id = Some(compute_finding_group_id(&fingerprint));
                }
                FindingWithFingerprint {
                    rule_id,
                    finding: owned,
                    fingerprint,
                }
            })
            .collect();

        let report = JsonReport {
            schema_version: JSON_REPORT_SCHEMA_VERSION,
            schema_uri: JSON_REPORT_SCHEMA_URI,
            graph,
            findings: findings_with_fp,
            summary: Summary {
                total_findings: findings.len(),
                critical: findings
                    .iter()
                    .filter(|f| f.severity == Severity::Critical)
                    .count(),
                high: findings
                    .iter()
                    .filter(|f| f.severity == Severity::High)
                    .count(),
                medium: findings
                    .iter()
                    .filter(|f| f.severity == Severity::Medium)
                    .count(),
                low: findings
                    .iter()
                    .filter(|f| f.severity == Severity::Low)
                    .count(),
                info: findings
                    .iter()
                    .filter(|f| f.severity == Severity::Info)
                    .count(),
                total_nodes: graph.nodes.len(),
                total_edges: graph.edges.len(),
                completeness: graph.completeness,
                // Zip kinds with reasons. `zip` stops at the shorter
                // iterator, so if `completeness_gap_kinds` is somehow
                // shorter than `completeness_gaps` (shouldn't happen —
                // mark_partial pushes both — but be safe), we silently
                // drop the unkinded extras rather than emit a malformed
                // gap.
                completeness_gaps: graph
                    .completeness_gap_kinds
                    .iter()
                    .zip(graph.completeness_gaps.iter())
                    .map(|(kind, reason)| CompletenessGap {
                        kind: *kind,
                        reason: reason.clone(),
                    })
                    .collect(),
                graph_risk_summary: graph_risk_summary(graph),
            },
        };

        serde_json::to_writer_pretty(w, &report)
            .map_err(|e| TauditError::Report(format!("JSON serialization error: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::JsonReportSink;
    use std::{fs, path::PathBuf};
    use taudit_core::finding::{Finding, FindingExtras, Recommendation, Severity};
    use taudit_core::graph::PipelineSource;
    use taudit_core::ports::ReportSink;

    fn workspace_file(relative: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
    }

    fn read_json(relative: &str) -> serde_json::Value {
        let path = workspace_file(relative);
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        serde_json::from_str(&text)
            .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
    }

    fn assert_schema_validates_instance(schema_relative: &str, instance_relative: &str) {
        let schema = read_json(schema_relative);
        let instance = read_json(instance_relative);
        let validator = jsonschema::validator_for(&schema)
            .unwrap_or_else(|err| panic!("invalid schema {schema_relative}: {err}"));
        let errors: Vec<String> = validator
            .iter_errors(&instance)
            .map(|err| err.to_string())
            .collect();
        assert!(
            errors.is_empty(),
            "{instance_relative} does not match {schema_relative}:\n{}",
            errors.join("\n")
        );
    }

    #[test]
    fn emitted_report_includes_schema_version_and_matches_schema() {
        let graph = taudit_core::graph::AuthorityGraph::new(PipelineSource {
            file: ".github/workflows/ci.yml".into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        });
        let findings = vec![Finding {
            severity: Severity::Medium,
            category: taudit_core::finding::FindingCategory::UnpinnedAction,
            path: None,
            nodes_involved: vec![],
            message: "test finding".into(),
            recommendation: Recommendation::Manual {
                action: "pin the action".into(),
            },
            source: taudit_core::finding::FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        }];

        let mut buf = Vec::new();
        JsonReportSink.emit(&mut buf, &graph, &findings).unwrap();

        let report: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(report["schema_version"], "1.0.0");

        let schema = read_json("contracts/schemas/taudit-report.schema.json");
        let validator = jsonschema::validator_for(&schema).expect("report schema should compile");
        let errors: Vec<String> = validator
            .iter_errors(&report)
            .map(|err| err.to_string())
            .collect();

        assert!(
            errors.is_empty(),
            "emitted report does not match report schema:\n{}",
            errors.join("\n")
        );
    }

    #[test]
    fn clean_report_example_matches_schema() {
        assert_schema_validates_instance(
            "contracts/schemas/taudit-report.schema.json",
            "contracts/examples/clean-report.json",
        );
    }

    #[test]
    fn over_privileged_report_example_matches_schema() {
        assert_schema_validates_instance(
            "contracts/schemas/taudit-report.schema.json",
            "contracts/examples/over-privileged-report.json",
        );
    }

    /// End-to-end: build a graph that exercises every NodeKind, every
    /// TrustZone, and every EdgeKind, emit it through the standalone
    /// GraphExport envelope, then validate the JSON against the
    /// authority-graph v1 schema. Catches drift between the Rust types
    /// and the published schema before downstream consumers do.
    #[test]
    fn authority_graph_export_matches_v1_schema() {
        use taudit_core::graph::{
            AuthorityGraph, EdgeKind, GapKind, NodeKind, PipelineSource, TrustZone,
        };

        let mut graph = AuthorityGraph::new(PipelineSource {
            file: "tests/fixtures/over-privileged.yml".into(),
            repo: Some("0ryant/taudit".into()),
            git_ref: Some("main".into()),
            commit_sha: None,
        });
        graph.mark_partial(
            GapKind::Expression,
            "inline shell scripts not fully resolved",
        );

        let secret = graph.add_node(NodeKind::Secret, "AWS_KEY", TrustZone::FirstParty);
        let identity = graph.add_node(NodeKind::Identity, "GITHUB_TOKEN", TrustZone::FirstParty);
        let image = graph.add_node(NodeKind::Image, "ubuntu-latest", TrustZone::ThirdParty);
        let step_build = graph.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        let artifact = graph.add_node(NodeKind::Artifact, "dist.tar.gz", TrustZone::FirstParty);
        let step_deploy = graph.add_node(NodeKind::Step, "deploy", TrustZone::Untrusted);

        graph.add_edge(step_build, secret, EdgeKind::HasAccessTo);
        graph.add_edge(step_build, identity, EdgeKind::HasAccessTo);
        graph.add_edge(step_build, image, EdgeKind::UsesImage);
        graph.add_edge(step_build, artifact, EdgeKind::Produces);
        graph.add_edge(artifact, step_deploy, EdgeKind::Consumes);
        graph.add_edge(step_build, step_deploy, EdgeKind::DelegatesTo);
        graph.add_edge(step_build, secret, EdgeKind::PersistsTo);

        graph.stamp_edge_authority_summaries();

        let export = crate::GraphExport::new(&graph);
        let json = export.to_json_pretty().expect("export serializes");
        let value: serde_json::Value =
            serde_json::from_str(&json).expect("export round-trips through serde_json");

        assert_eq!(
            value["schema_version"],
            crate::AUTHORITY_GRAPH_SCHEMA_VERSION
        );
        assert_eq!(value["schema_uri"], crate::AUTHORITY_GRAPH_SCHEMA_URI);

        // The standalone graph export keeps `completeness_gaps` and
        // `completeness_gap_kinds` as parallel arrays (this is the
        // authority-graph v1 schema contract). Confirm the Expression
        // gap we marked is round-tripped under both keys.
        assert_eq!(
            value["graph"]["completeness_gaps"][0],
            "inline shell scripts not fully resolved"
        );
        assert_eq!(value["graph"]["completeness_gap_kinds"][0], "expression");

        let schema = read_json("schemas/authority-graph.v1.json");
        let validator =
            jsonschema::validator_for(&schema).expect("authority-graph schema should compile");
        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|err| err.to_string())
            .collect();

        assert!(
            errors.is_empty(),
            "graph export does not match authority-graph.v1.json:\n{}",
            errors.join("\n")
        );
    }

    /// Regression for the post-v0.9.1 fuzz-report B1 (HIGH): scanning the
    /// same fixture nine times in a row must produce nine byte-identical
    /// JSON outputs. Before the fix, HashMap iteration order leaked into
    /// node IDs, edge `from`/`to`, and `metadata` key ordering — so each
    /// run differed and any cache / SIEM keying on the JSON saw false
    /// changes. The fix sorts parser HashMap iteration and serializes
    /// graph metadata maps in sorted-key order.
    #[test]
    fn json_output_is_byte_deterministic_across_runs() {
        use std::collections::HashMap;
        use taudit_core::graph::{AuthorityGraph, EdgeKind, NodeKind, PipelineSource, TrustZone};

        // Build a graph with rich metadata across multiple keys — exercises
        // the HashMap-key-order code path that was previously the source of
        // non-determinism. We then serialise it twice in sequence (mimics
        // back-to-back runs of the same scan).
        fn build_graph() -> (AuthorityGraph, Vec<Finding>) {
            let mut graph = AuthorityGraph::new(PipelineSource {
                file: "ci.yml".into(),
                repo: None,
                git_ref: None,
                commit_sha: None,
            });
            let secret_a = graph.add_node(NodeKind::Secret, "AWS_KEY", TrustZone::FirstParty);
            let secret_b = graph.add_node(NodeKind::Secret, "DEPLOY_TOKEN", TrustZone::FirstParty);
            let step = graph.add_node(NodeKind::Step, "deploy", TrustZone::FirstParty);
            graph.add_edge(step, secret_a, EdgeKind::HasAccessTo);
            graph.add_edge(step, secret_b, EdgeKind::HasAccessTo);
            // Stamp many metadata keys on the step so HashMap ordering matters.
            if let Some(node) = graph.nodes.get_mut(step) {
                let mut meta: HashMap<String, String> = HashMap::new();
                meta.insert("z_field".into(), "z".into());
                meta.insert("a_field".into(), "a".into());
                meta.insert("m_field".into(), "m".into());
                meta.insert("k_field".into(), "k".into());
                meta.insert("c_field".into(), "c".into());
                node.metadata = meta;
            }
            graph
                .metadata
                .insert("trigger".into(), "pull_request".into());
            graph.metadata.insert("platform".into(), "github".into());
            let findings = vec![Finding {
                severity: Severity::High,
                category: taudit_core::finding::FindingCategory::AuthorityPropagation,
                path: None,
                nodes_involved: vec![secret_a, step],
                message: "AWS_KEY reaches deploy".into(),
                recommendation: Recommendation::Manual {
                    action: "scope it".into(),
                },
                source: taudit_core::finding::FindingSource::BuiltIn,
                extras: taudit_core::finding::FindingExtras::default(),
            }];
            (graph, findings)
        }

        let mut runs: Vec<Vec<u8>> = Vec::with_capacity(9);
        for _ in 0..9 {
            let (g, f) = build_graph();
            let mut buf = Vec::new();
            JsonReportSink.emit(&mut buf, &g, &f).unwrap();
            runs.push(buf);
        }

        let first = &runs[0];
        for (i, run) in runs.iter().enumerate().skip(1) {
            assert_eq!(
                first, run,
                "run 0 and run {i} produced byte-different JSON output (non-determinism regression)"
            );
        }
    }

    /// Regression for the post-v0.9.1 self-hosting-scan finding: every
    /// `findings[].rule_id` was `null` in the JSON sink output, even though
    /// SARIF and the text formatter surfaced rule names correctly. JSON
    /// consumers (SIEMs, suppression DBs, dashboards) couldn't filter by
    /// rule. Each finding must now carry a non-null `rule_id` string equal
    /// to the snake_case form of the category — and a custom-rule message
    /// prefix `[id]` must override the category id.
    #[test]
    fn each_finding_has_non_null_snake_case_rule_id() {
        let graph = taudit_core::graph::AuthorityGraph::new(PipelineSource {
            file: ".github/workflows/ci.yml".into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        });
        let findings = vec![
            Finding {
                severity: Severity::High,
                category: taudit_core::finding::FindingCategory::AuthorityPropagation,
                path: None,
                nodes_involved: vec![],
                message: "GITHUB_TOKEN propagated".into(),
                recommendation: Recommendation::Manual {
                    action: "scope it".into(),
                },
                source: taudit_core::finding::FindingSource::BuiltIn,
                extras: taudit_core::finding::FindingExtras::default(),
            },
            Finding {
                severity: Severity::Medium,
                category: taudit_core::finding::FindingCategory::UnpinnedAction,
                path: None,
                nodes_involved: vec![],
                message: "[my_custom_rule] custom rule fired".into(),
                recommendation: Recommendation::Manual {
                    action: "pin it".into(),
                },
                source: taudit_core::finding::FindingSource::BuiltIn,
                extras: taudit_core::finding::FindingExtras::default(),
            },
        ];

        let mut buf = Vec::new();
        JsonReportSink.emit(&mut buf, &graph, &findings).unwrap();
        let report: serde_json::Value = serde_json::from_slice(&buf).unwrap();

        let findings_arr = report["findings"].as_array().expect("findings is an array");
        assert_eq!(findings_arr.len(), 2);

        // Each finding has a non-null rule_id string.
        for f in findings_arr {
            let id = f["rule_id"].as_str();
            assert!(
                id.is_some(),
                "every finding must have a string rule_id, got: {:?}",
                f["rule_id"]
            );
            assert!(
                !id.unwrap().is_empty(),
                "rule_id must be non-empty, got: {:?}",
                f["rule_id"]
            );
        }

        // Category-derived id: snake_case form of FindingCategory.
        assert_eq!(findings_arr[0]["rule_id"], "authority_propagation");
        // Custom-rule prefix wins over the category id.
        assert_eq!(findings_arr[1]["rule_id"], "my_custom_rule");
    }

    /// Lane 1F contract: `summary.completeness_gaps` is an array of
    /// `{kind, reason}` objects, not plain strings. Each entry carries
    /// the typed `GapKind` (snake_case: `expression` | `structural` |
    /// `opaque`) so downstream consumers can filter / group gaps by
    /// class without re-parsing the human-readable reason. Exercise
    /// every variant in one report and assert both shape and values.
    #[test]
    fn summary_completeness_gaps_serialize_as_kind_reason_objects() {
        use taudit_core::graph::GapKind;

        let mut graph = taudit_core::graph::AuthorityGraph::new(PipelineSource {
            file: ".github/workflows/ci.yml".into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        });
        graph.mark_partial(GapKind::Structural, "composite action not found: ./action");
        graph.mark_partial(
            GapKind::Expression,
            "matrix strategy hides some authority paths",
        );
        graph.mark_partial(GapKind::Opaque, "platform unknown; zero steps produced");

        let mut buf = Vec::new();
        JsonReportSink.emit(&mut buf, &graph, &[]).unwrap();
        let report: serde_json::Value = serde_json::from_slice(&buf).unwrap();

        let gaps = report["summary"]["completeness_gaps"]
            .as_array()
            .expect("summary.completeness_gaps must be an array");
        assert_eq!(gaps.len(), 3, "all three gaps round-trip");

        // Index 0: Structural
        assert_eq!(gaps[0]["kind"], "structural");
        assert_eq!(gaps[0]["reason"], "composite action not found: ./action");
        // Index 1: Expression
        assert_eq!(gaps[1]["kind"], "expression");
        assert_eq!(
            gaps[1]["reason"],
            "matrix strategy hides some authority paths"
        );
        // Index 2: Opaque
        assert_eq!(gaps[2]["kind"], "opaque");
        assert_eq!(gaps[2]["reason"], "platform unknown; zero steps produced");

        // Every entry must be an object with exactly the two contract
        // keys — guards against a regression that drops the structured
        // shape and falls back to bare strings.
        for (i, gap) in gaps.iter().enumerate() {
            assert!(gap.is_object(), "gap[{i}] must be an object, got: {gap:?}");
            assert!(
                gap.get("kind").and_then(|v| v.as_str()).is_some(),
                "gap[{i}].kind must be a string"
            );
            assert!(
                gap.get("reason").and_then(|v| v.as_str()).is_some(),
                "gap[{i}].reason must be a string"
            );
        }

        // The emitted report (with structured gaps) must still validate
        // against the published JSON Schema — catches drift between the
        // Rust types and `contracts/schemas/taudit-report.schema.json`.
        let schema = read_json("contracts/schemas/taudit-report.schema.json");
        let validator = jsonschema::validator_for(&schema).expect("report schema should compile");
        let errors: Vec<String> = validator
            .iter_errors(&report)
            .map(|err| err.to_string())
            .collect();
        assert!(
            errors.is_empty(),
            "partial-graph report does not match report schema:\n{}",
            errors.join("\n")
        );
    }

    /// Regression for the P0 schema-drift class (Agent-10 Findings 2 + 3
    /// of the v1.1.0-beta.2 deep-audit synthesis). The published
    /// `taudit-report.schema.json` previously listed only 10 of the 63
    /// `FindingCategory` variants in `Finding/properties/category/enum`.
    /// With `additionalProperties: false`, a finding emitted by 53 of 63
    /// rules was byte-valid but schema-invalid against the contract the
    /// README publishes — strict-validating consumers rejected the output.
    /// CI was blind because every prior schema test fired
    /// `UnpinnedAction` or `AuthorityPropagation`, both inside the
    /// stale 10-item subset.
    ///
    /// This test enumerates every variant — including the two reserved
    /// ones, which are valid in OUTPUT — emits each through the JSON
    /// sink, and validates the resulting report against the published
    /// schema. Adding a new `FindingCategory` variant without updating
    /// the schema generator (`scripts/generate-authority-invariant-schema.py`)
    /// trips this test in addition to the CI `--check` step.
    ///
    /// Variants are hand-listed (no `strum`) — the workspace deliberately
    /// avoids that dependency for one test. Removing a variant fails to
    /// compile, which is a stronger signal than a missing-from-list bug.
    #[test]
    fn every_finding_category_variant_validates_against_report_schema() {
        use taudit_core::finding::FindingCategory as C;

        // Hand-listed enumeration of every FindingCategory variant. If a
        // variant is added/removed in `crates/taudit-core/src/finding.rs`,
        // this list MUST be updated in lock-step with the schema
        // generator. The schema `--check` CI gate catches the schema half;
        // this test catches the test-coverage half.
        let all: Vec<C> = vec![
            C::AuthorityPropagation,
            C::OverPrivilegedIdentity,
            C::UnpinnedAction,
            C::UntrustedWithAuthority,
            C::ArtifactBoundaryCrossing,
            C::FloatingImage,
            C::LongLivedCredential,
            C::PersistedCredential,
            C::TriggerContextMismatch,
            C::CrossWorkflowAuthorityChain,
            C::AuthorityCycle,
            C::UpliftWithoutAttestation,
            C::SelfMutatingPipeline,
            C::CheckoutSelfPrExposure,
            C::VariableGroupInPrJob,
            C::SelfHostedPoolPrHijack,
            C::SharedSelfHostedPoolNoIsolation,
            C::ServiceConnectionScopeMismatch,
            C::TemplateExtendsUnpinnedBranch,
            C::TemplateRepoRefIsFeatureBranch,
            C::VmRemoteExecViaPipelineSecret,
            C::ShortLivedSasInCommandLine,
            C::SecretToInlineScriptEnvExport,
            C::SecretMaterialisedToWorkspaceFile,
            C::KeyVaultSecretToPlaintext,
            C::TerraformAutoApproveInProd,
            C::AddSpnWithInlineScript,
            C::ParameterInterpolationIntoShell,
            C::RuntimeScriptFetchedFromFloatingUrl,
            C::PrTriggerWithFloatingActionRef,
            C::UntrustedApiResponseToEnvSink,
            C::PrBuildPushesImageWithFloatingCredentials,
            C::SecretViaEnvGateToUntrustedConsumer,
            C::NoWorkflowLevelPermissionsBlock,
            C::ProdDeployJobNoEnvironmentGate,
            C::LongLivedSecretWithoutOidcRecommendation,
            C::PullRequestWorkflowInconsistentForkCheck,
            C::GitlabDeployJobMissingProtectedBranchOnly,
            C::TerraformOutputViaSetvariableShellExpansion,
            C::RiskyTriggerWithAuthority,
            C::SensitiveValueInJobOutput,
            C::ManualDispatchInputToUrlOrCommand,
            C::SecretsInheritOverscopedPassthrough,
            C::UnsafePrArtifactInWorkflowRunConsumer,
            C::ScriptInjectionViaUntrustedContext,
            C::InteractiveDebugActionInAuthorityWorkflow,
            C::PrSpecificCacheKeyInDefaultBranchConsumer,
            C::GhCliWithDefaultTokenEscalating,
            C::GhaScriptInjectionToPrivilegedShell,
            C::GhaWorkflowRunArtifactPoisoningToPrivilegedConsumer,
            C::GhaRemoteScriptInAuthorityJob,
            C::GhaPatRemoteUrlWrite,
            C::GhaIssueCommentCommandToWriteToken,
            C::GhaPrBuildPushesPublishableImage,
            C::GhaManualDispatchRefToPrivilegedCheckout,
            C::CiJobTokenToExternalApi,
            C::IdTokenAudienceOverscoped,
            C::UntrustedCiVarInShellInterpolation,
            C::UnpinnedIncludeRemoteOrBranchRef,
            C::DindServiceGrantsHostAuthority,
            C::SecurityJobSilentlySkipped,
            C::ChildPipelineTriggerInheritsAuthority,
            C::CacheKeyCrossesTrustBoundary,
            C::PatEmbeddedInGitRemoteUrl,
            C::CiTokenTriggersDownstreamWithVariablePassthrough,
            C::DotenvArtifactFlowsToPrivilegedDeployment,
            C::SetvariableIssecretFalse,
            C::HomoglyphInActionRef,
            C::GhaHelperPathSensitiveArgv,
            C::GhaHelperPathSensitiveStdin,
            C::GhaHelperPathSensitiveEnv,
            C::GhaPostAmbientEnvCleanupPath,
            C::GhaActionMintedSecretToHelper,
            C::GhaHelperUntrustedPathResolution,
            C::GhaSecretOutputAfterHelperLogin,
            C::LaterSecretMaterializedAfterPathMutation,
            C::GhaSetupNodeCacheHelperPathHandoff,
            C::GhaSetupPythonCacheHelperPathHandoff,
            C::GhaSetupPythonPipInstallAuthorityEnv,
            C::GhaSetupGoCacheHelperPathHandoff,
            C::GhaDockerSetupQemuPrivilegedDockerHelper,
            C::GhaToolInstallerThenShellHelperAuthority,
            C::GhaWorkflowShellAuthorityConcentration,
            C::GhaActionTokenEnvBeforeBareDownloadHelper,
            C::GhaPostActionInputRetargetToCacheSave,
            C::GhaTerraformWrapperSensitiveOutput,
            C::GhaCompositeBareHelperAfterPathInstallWithSecretEnv,
            C::GhaPulumiPathResolvedCliWithAuthority,
            C::GhaPypiPublishOidcAfterPathMutation,
            C::GhaChangesetsPublishCommandWithAuthority,
            C::GhaRubygemsReleaseGitTokenAndOidcHelper,
            C::GhaCompositeEntrypointPathShadowWithSecretEnv,
            C::GhaDockerBuildxAuthorityPathHandoff,
            C::GhaGoogleDeployGcloudCredentialPath,
            C::GhaDatadogTestVisibilityInstallerAuthority,
            C::GhaKubernetesHelperKubeconfigAuthority,
            C::GhaAzureCompanionHelperAuthority,
            C::GhaCreatePrGitTokenPathHandoff,
            C::GhaImportGpgPrivateKeyHelperPath,
            C::GhaSshAgentPrivateKeyToPathHelper,
            C::GhaMacosCodesignCertSecurityPath,
            C::GhaPagesDeployTokenUrlToGitHelper,
            C::GhaToolcacheAbsolutePathDowngrade,
            // Reserved categories — valid in OUTPUT (the Rust enum can
            // construct them); rejected in custom-rule YAML INPUT via
            // `#[serde(skip_deserializing)]`.
            C::EgressBlindspot,
            C::MissingAuditTrail,
        ];

        // Sanity guard: 93 is the wire-contract count the schema
        // generator emits. A drift between this list and the enum is the
        // exact failure class this test exists to catch.
        assert_eq!(
            all.len(),
            105,
            "FindingCategory enumeration is out of sync with the schema generator (expected 105, got {})",
            all.len()
        );

        let schema = read_json("contracts/schemas/taudit-report.schema.json");
        let validator = jsonschema::validator_for(&schema).expect("report schema should compile");

        for category in all {
            let graph = taudit_core::graph::AuthorityGraph::new(PipelineSource {
                file: ".github/workflows/ci.yml".into(),
                repo: None,
                git_ref: None,
                commit_sha: None,
            });
            let findings = vec![Finding {
                severity: Severity::Medium,
                category,
                path: None,
                nodes_involved: vec![],
                message: "category coverage probe".into(),
                recommendation: Recommendation::Manual {
                    action: "noop".into(),
                },
                source: taudit_core::finding::FindingSource::BuiltIn,
                extras: FindingExtras::default(),
            }];

            let mut buf = Vec::new();
            JsonReportSink
                .emit(&mut buf, &graph, &findings)
                .expect("sink emits");
            let report: serde_json::Value =
                serde_json::from_slice(&buf).expect("output is valid JSON");
            let errors: Vec<String> = validator
                .iter_errors(&report)
                .map(|err| err.to_string())
                .collect();
            assert!(
                errors.is_empty(),
                "category {category:?} produced a report that fails the published schema:\n{}",
                errors.join("\n")
            );
        }
    }
}
