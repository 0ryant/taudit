use serde::Serialize;
use taudit_core::error::TauditError;
use taudit_core::finding::{Finding, FindingCategory};
use taudit_core::graph::AuthorityGraph;
use taudit_core::ports::ReportSink;

// ---------------------------------------------------------------------------
// CloudEvents 1.0 envelope — hand-rolled, matches CellOS pattern.
// No dependency on cloudevents-sdk (0.9.x, pre-1.0, unstable API).
// ---------------------------------------------------------------------------

/// Minimal CloudEvents 1.0 JSON envelope.
#[derive(Debug, Clone, Serialize)]
pub struct CloudEventV1 {
    pub specversion: String,
    pub id: String,
    pub source: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datacontenttype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    // Extension attributes — CloudEvents 1.0 allows arbitrary top-level keys.
    /// Authority graph completeness: "complete", "partial", or "unknown".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tauditcompleteness: Option<String>,
}

/// Event source identifier for taudit.
const EVENT_SOURCE: &str = "taudit";

/// Map a FindingCategory to a CloudEvents type string.
fn event_type(category: FindingCategory) -> String {
    let suffix = match category {
        FindingCategory::AuthorityPropagation => "authority_propagation",
        FindingCategory::OverPrivilegedIdentity => "over_privileged_identity",
        FindingCategory::UnpinnedAction => "unpinned_action",
        FindingCategory::UntrustedWithAuthority => "untrusted_with_authority",
        FindingCategory::ArtifactBoundaryCrossing => "artifact_boundary_crossing",
        FindingCategory::EgressBlindspot => "egress_blindspot",
        FindingCategory::MissingAuditTrail => "missing_audit_trail",
        FindingCategory::FloatingImage => "floating_image",
        FindingCategory::LongLivedCredential => "long_lived_credential",
    };
    format!("io.taudit.finding.{suffix}")
}

/// Build a CloudEvents 1.0 envelope for a single finding.
fn finding_to_event(finding: &Finding, graph: &AuthorityGraph) -> CloudEventV1 {
    let data = serde_json::to_value(finding)
        .unwrap_or_else(|_| serde_json::Value::String(finding.message.clone()));

    let completeness_str = match graph.completeness {
        taudit_core::graph::AuthorityCompleteness::Complete => "complete",
        taudit_core::graph::AuthorityCompleteness::Partial => "partial",
        taudit_core::graph::AuthorityCompleteness::Unknown => "unknown",
    };

    CloudEventV1 {
        specversion: "1.0".into(),
        id: uuid::Uuid::new_v4().to_string(),
        source: EVENT_SOURCE.into(),
        ty: event_type(finding.category),
        subject: Some(graph.source.file.clone()),
        datacontenttype: Some("application/json".into()),
        time: Some(chrono::Utc::now().to_rfc3339()),
        data: Some(data),
        tauditcompleteness: Some(completeness_str.into()),
    }
}

// ---------------------------------------------------------------------------
// ReportSink implementation — one JSONL line per finding.
// ---------------------------------------------------------------------------

pub struct CloudEventsJsonlSink;

impl<W: std::io::Write> ReportSink<W> for CloudEventsJsonlSink {
    fn emit(
        &self,
        w: &mut W,
        graph: &AuthorityGraph,
        findings: &[Finding],
    ) -> Result<(), TauditError> {
        for finding in findings {
            let event = finding_to_event(finding, graph);
            serde_json::to_writer(&mut *w, &event)
                .map_err(|e| TauditError::Report(format!("CloudEvents serialization: {e}")))?;
            writeln!(w).map_err(|e| TauditError::Report(e.to_string()))?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use taudit_core::finding::{Recommendation, Severity};
    use taudit_core::graph::PipelineSource;

    fn test_source() -> PipelineSource {
        PipelineSource {
            file: ".github/workflows/ci.yml".into(),
            repo: None,
            git_ref: None,
        }
    }

    fn test_finding(category: FindingCategory, severity: Severity) -> Finding {
        Finding {
            severity,
            category,
            path: None,
            nodes_involved: vec![0, 1],
            message: "test finding".into(),
            recommendation: Recommendation::Manual {
                action: "fix it".into(),
            },
        }
    }

    #[test]
    fn emits_one_jsonl_line_per_finding() {
        let graph = AuthorityGraph::new(test_source());
        let findings = vec![
            test_finding(FindingCategory::UnpinnedAction, Severity::Medium),
            test_finding(FindingCategory::AuthorityPropagation, Severity::Critical),
        ];

        let mut buf = Vec::new();
        CloudEventsJsonlSink
            .emit(&mut buf, &graph, &findings)
            .unwrap();

        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2, "one JSONL line per finding");
    }

    #[test]
    fn each_line_is_valid_cloudevent() {
        let graph = AuthorityGraph::new(test_source());
        let findings = vec![test_finding(
            FindingCategory::OverPrivilegedIdentity,
            Severity::High,
        )];

        let mut buf = Vec::new();
        CloudEventsJsonlSink
            .emit(&mut buf, &graph, &findings)
            .unwrap();

        let output = String::from_utf8(buf).unwrap();
        let event: serde_json::Value =
            serde_json::from_str(output.lines().next().unwrap()).unwrap();

        assert_eq!(event["specversion"], "1.0");
        assert_eq!(event["source"], "taudit");
        assert_eq!(event["type"], "io.taudit.finding.over_privileged_identity");
        assert_eq!(event["subject"], ".github/workflows/ci.yml");
        assert_eq!(event["datacontenttype"], "application/json");
        assert!(event["id"].is_string());
        assert!(event["time"].is_string());
        assert!(event["data"].is_object());
        assert_eq!(event["tauditcompleteness"], "complete");
    }

    #[test]
    fn partial_graph_sets_completeness_extension() {
        let mut graph = AuthorityGraph::new(test_source());
        graph.mark_partial("inferred secret in run: block");
        let findings = vec![test_finding(
            FindingCategory::AuthorityPropagation,
            Severity::Critical,
        )];

        let mut buf = Vec::new();
        CloudEventsJsonlSink
            .emit(&mut buf, &graph, &findings)
            .unwrap();

        let output = String::from_utf8(buf).unwrap();
        let event: serde_json::Value =
            serde_json::from_str(output.lines().next().unwrap()).unwrap();

        assert_eq!(event["tauditcompleteness"], "partial");
    }

    #[test]
    fn data_payload_contains_finding_fields() {
        let graph = AuthorityGraph::new(test_source());
        let findings = vec![test_finding(
            FindingCategory::LongLivedCredential,
            Severity::Low,
        )];

        let mut buf = Vec::new();
        CloudEventsJsonlSink
            .emit(&mut buf, &graph, &findings)
            .unwrap();

        let output = String::from_utf8(buf).unwrap();
        let event: serde_json::Value =
            serde_json::from_str(output.lines().next().unwrap()).unwrap();
        let data = &event["data"];

        assert_eq!(data["severity"], "low");
        assert_eq!(data["category"], "long_lived_credential");
        assert_eq!(data["message"], "test finding");
        assert!(data["recommendation"].is_object());
    }

    #[test]
    fn event_type_maps_all_categories() {
        let categories = vec![
            (
                FindingCategory::AuthorityPropagation,
                "io.taudit.finding.authority_propagation",
            ),
            (
                FindingCategory::OverPrivilegedIdentity,
                "io.taudit.finding.over_privileged_identity",
            ),
            (
                FindingCategory::UnpinnedAction,
                "io.taudit.finding.unpinned_action",
            ),
            (
                FindingCategory::UntrustedWithAuthority,
                "io.taudit.finding.untrusted_with_authority",
            ),
            (
                FindingCategory::ArtifactBoundaryCrossing,
                "io.taudit.finding.artifact_boundary_crossing",
            ),
            (
                FindingCategory::EgressBlindspot,
                "io.taudit.finding.egress_blindspot",
            ),
            (
                FindingCategory::MissingAuditTrail,
                "io.taudit.finding.missing_audit_trail",
            ),
            (
                FindingCategory::FloatingImage,
                "io.taudit.finding.floating_image",
            ),
            (
                FindingCategory::LongLivedCredential,
                "io.taudit.finding.long_lived_credential",
            ),
        ];

        for (cat, expected) in categories {
            assert_eq!(event_type(cat), expected);
        }
    }

    #[test]
    fn empty_findings_produces_empty_output() {
        let graph = AuthorityGraph::new(test_source());

        let mut buf = Vec::new();
        CloudEventsJsonlSink.emit(&mut buf, &graph, &[]).unwrap();

        assert!(buf.is_empty(), "no findings = no output");
    }

    #[test]
    fn unique_ids_per_event() {
        let graph = AuthorityGraph::new(test_source());
        let findings = vec![
            test_finding(FindingCategory::UnpinnedAction, Severity::Medium),
            test_finding(FindingCategory::UnpinnedAction, Severity::Medium),
        ];

        let mut buf = Vec::new();
        CloudEventsJsonlSink
            .emit(&mut buf, &graph, &findings)
            .unwrap();

        let output = String::from_utf8(buf).unwrap();
        let ids: Vec<String> = output
            .lines()
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                v["id"].as_str().unwrap().to_string()
            })
            .collect();

        assert_ne!(ids[0], ids[1], "each event must have a unique ID");
    }
}
