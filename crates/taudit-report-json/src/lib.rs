use taudit_core::error::TauditError;
use taudit_core::finding::{compute_fingerprint, rule_id_for, Finding};
use taudit_core::graph::{AuthorityCompleteness, AuthorityGraph};
use taudit_core::ports::ReportSink;

use serde::Serialize;

const JSON_REPORT_SCHEMA_VERSION: &str = "v1";
const JSON_REPORT_SCHEMA_URI: &str = "https://taudit.dev/schemas/taudit-report.schema.json";

/// Schema version of the standalone authority-graph export
/// (`taudit graph --format json`). Semver-stable: 1.x.y additions are
/// non-breaking; 2.0.0 means breaking changes.
pub const AUTHORITY_GRAPH_SCHEMA_VERSION: &str = "1.0.0";

/// Canonical URI of the authority-graph JSON Schema.
pub const AUTHORITY_GRAPH_SCHEMA_URI: &str =
    "https://github.com/0ryant/taudit/schemas/authority-graph.v1.json";

/// JSON report containing the full authority graph and all findings.
#[derive(Serialize)]
pub struct JsonReport<'a> {
    pub schema_version: &'static str,
    /// Canonical URI of the JSON Schema this report conforms to.
    /// Non-breaking addition (1.x consumers ignore unknown fields).
    pub schema_uri: &'static str,
    pub graph: &'a AuthorityGraph,
    pub findings: Vec<FindingWithFingerprint<'a>>,
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
#[derive(Serialize)]
pub struct FindingWithFingerprint<'a> {
    pub rule_id: String,
    #[serde(flatten)]
    pub finding: &'a Finding,
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub completeness_gaps: Vec<String>,
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

        let findings_with_fp: Vec<FindingWithFingerprint<'_>> = findings
            .iter()
            .map(|f| FindingWithFingerprint {
                rule_id: rule_id_for(f),
                finding: f,
                fingerprint: compute_fingerprint(f, graph),
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
                completeness_gaps: graph.completeness_gaps.clone(),
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
    use taudit_core::finding::{Finding, Recommendation, Severity};
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
        }];

        let mut buf = Vec::new();
        JsonReportSink.emit(&mut buf, &graph, &findings).unwrap();

        let report: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(report["schema_version"], "v1");

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
        use taudit_core::graph::{AuthorityGraph, EdgeKind, NodeKind, PipelineSource, TrustZone};

        let mut graph = AuthorityGraph::new(PipelineSource {
            file: "tests/fixtures/over-privileged.yml".into(),
            repo: Some("0ryant/taudit".into()),
            git_ref: Some("main".into()),
            commit_sha: None,
        });
        graph.mark_partial("inline shell scripts not fully resolved");

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

        let export = crate::GraphExport::new(&graph);
        let json = export.to_json_pretty().expect("export serializes");
        let value: serde_json::Value =
            serde_json::from_str(&json).expect("export round-trips through serde_json");

        assert_eq!(
            value["schema_version"],
            crate::AUTHORITY_GRAPH_SCHEMA_VERSION
        );
        assert_eq!(value["schema_uri"], crate::AUTHORITY_GRAPH_SCHEMA_URI);

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
}
