use taudit_core::error::TauditError;
use taudit_core::finding::Finding;
use taudit_core::graph::{AuthorityCompleteness, AuthorityGraph};
use taudit_core::ports::ReportSink;

use serde::Serialize;

/// JSON report containing the full authority graph and all findings.
#[derive(Serialize)]
pub struct JsonReport<'a> {
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
