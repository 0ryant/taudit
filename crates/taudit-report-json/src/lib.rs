use taudit_core::error::TauditError;
use taudit_core::finding::Finding;
use taudit_core::graph::{AuthorityCompleteness, AuthorityGraph};
use taudit_core::ports::ReportSink;

use serde::Serialize;

const JSON_REPORT_SCHEMA_VERSION: &str = "v1";

/// JSON report containing the full authority graph and all findings.
#[derive(Serialize)]
pub struct JsonReport<'a> {
    pub schema_version: &'static str,
    pub graph: &'a AuthorityGraph,
    pub findings: &'a [Finding],
    pub summary: Summary,
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

        let report = JsonReport {
            schema_version: JSON_REPORT_SCHEMA_VERSION,
            graph,
            findings,
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
}
