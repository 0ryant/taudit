use taudit_core::error::TauditError;
use taudit_core::finding::{compute_fingerprint, Finding};
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
#[derive(Serialize)]
pub struct FindingWithFingerprint<'a> {
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
}
