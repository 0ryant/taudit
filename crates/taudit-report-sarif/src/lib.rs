use serde::Serialize;
use taudit_core::error::TauditError;
use taudit_core::finding::{Finding, FindingCategory, Severity};
use taudit_core::graph::AuthorityGraph;
use taudit_core::ports::ReportSink;

const SARIF_SCHEMA: &str =
    "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const TOOL_NAME: &str = "taudit";
const TOOL_URI: &str = "https://github.com/0ryant/taudit";
const RULES_BASE_URI: &str = "https://github.com/0ryant/taudit/blob/main/docs/rules";

// ── Static rule catalogue ───────────────────────────────

struct RuleDef {
    id: &'static str,
    name: &'static str,
    description: &'static str,
}

const RULE_DEFS: &[RuleDef] = &[
    RuleDef {
        id: "authority_propagation",
        name: "AuthorityPropagation",
        description: "A secret or identity propagates to a step in a lower trust zone.",
    },
    RuleDef {
        id: "over_privileged_identity",
        name: "OverPrivilegedIdentity",
        description: "A GITHUB_TOKEN or service identity has broader permissions than needed.",
    },
    RuleDef {
        id: "unpinned_action",
        name: "UnpinnedAction",
        description: "A third-party action is referenced by mutable tag instead of SHA digest.",
    },
    RuleDef {
        id: "untrusted_with_authority",
        name: "UntrustedWithAuthority",
        description: "An untrusted or unpinned step has direct access to a secret or identity.",
    },
    RuleDef {
        id: "artifact_boundary_crossing",
        name: "ArtifactBoundaryCrossing",
        description:
            "An artifact produced by a privileged step is consumed across a trust boundary.",
    },
    RuleDef {
        id: "egress_blindspot",
        name: "EgressBlindspot",
        description: "A step with access to secrets has network access and no egress constraint.",
    },
    RuleDef {
        id: "missing_audit_trail",
        name: "MissingAuditTrail",
        description: "An authority-bearing step has no logging or audit trail.",
    },
    RuleDef {
        id: "floating_image",
        name: "FloatingImage",
        description: "A container image is referenced without a digest pin.",
    },
    RuleDef {
        id: "long_lived_credential",
        name: "LongLivedCredential",
        description:
            "A secret name matches static credential patterns (API keys, passwords, tokens).",
    },
];

// ── SARIF 2.1.0 schema structs ──────────────────────────

#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: &'static str,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: &'static str,
    name: &'static str,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    #[serde(rename = "helpUri")]
    help_uri: String,
}

#[derive(Serialize, Clone)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
    #[serde(rename = "uriBaseId")]
    uri_base_id: &'static str,
}

// ── Adapter ─────────────────────────────────────────────

pub struct SarifReportSink;

impl<W: std::io::Write> ReportSink<W> for SarifReportSink {
    fn emit(
        &self,
        w: &mut W,
        graph: &AuthorityGraph,
        findings: &[Finding],
    ) -> Result<(), TauditError> {
        let rules = build_rules();
        let results = findings
            .iter()
            .map(|f| finding_to_result(f, &graph.source.file))
            .collect();

        let log = SarifLog {
            schema: SARIF_SCHEMA,
            version: SARIF_VERSION,
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: TOOL_NAME,
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: TOOL_URI,
                        rules,
                    },
                },
                results,
            }],
        };

        serde_json::to_writer_pretty(w, &log)
            .map_err(|e| TauditError::Report(format!("SARIF serialization error: {e}")))?;

        Ok(())
    }
}

fn build_rules() -> Vec<SarifRule> {
    RULE_DEFS
        .iter()
        .map(|r| SarifRule {
            id: r.id,
            name: r.name,
            short_description: SarifMessage {
                text: r.description.to_string(),
            },
            help_uri: format!("{RULES_BASE_URI}/{}", r.id),
        })
        .collect()
}

/// Map a `Finding` to a SARIF `result` object.
fn finding_to_result(finding: &Finding, source_file: &str) -> SarifResult {
    let rule_id = category_to_rule_id(&finding.category);
    let level = severity_to_level(&finding.severity);

    SarifResult {
        rule_id,
        level,
        message: SarifMessage {
            text: finding.message.clone(),
        },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: source_file.to_string(),
                    uri_base_id: "%SRCROOT%",
                },
            },
        }],
    }
}

fn category_to_rule_id(category: &FindingCategory) -> String {
    // Delegate to serde to stay in sync with the serialized form (snake_case).
    serde_json::to_value(category)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn severity_to_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

// ── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use taudit_core::finding::{Recommendation, Severity};
    use taudit_core::graph::{AuthorityGraph, PipelineSource};
    use taudit_core::ports::ReportSink;

    fn source() -> PipelineSource {
        PipelineSource {
            file: ".github/workflows/ci.yml".into(),
            repo: None,
            git_ref: None,
        }
    }

    fn empty_graph() -> AuthorityGraph {
        AuthorityGraph::new(source())
    }

    fn make_finding(severity: Severity, category: FindingCategory, msg: &str) -> Finding {
        Finding {
            severity,
            category,
            path: None,
            nodes_involved: vec![],
            message: msg.to_string(),
            recommendation: Recommendation::Manual {
                action: "review".to_string(),
            },
        }
    }

    fn emit_to_string(graph: &AuthorityGraph, findings: &[Finding]) -> serde_json::Value {
        let mut buf = Vec::new();
        SarifReportSink.emit(&mut buf, graph, findings).unwrap();
        serde_json::from_slice(&buf).unwrap()
    }

    #[test]
    fn empty_findings_produces_valid_sarif() {
        let graph = empty_graph();
        let sarif = emit_to_string(&graph, &[]);

        assert_eq!(sarif["version"], "2.1.0");
        assert!(sarif["$schema"].as_str().unwrap().contains("sarif-2.1.0"));
        let results = &sarif["runs"][0]["results"];
        assert_eq!(results.as_array().unwrap().len(), 0);
    }

    #[test]
    fn driver_name_and_rules_present() {
        let graph = empty_graph();
        let sarif = emit_to_string(&graph, &[]);

        let driver = &sarif["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "taudit");

        let rules = driver["rules"].as_array().unwrap();
        assert_eq!(rules.len(), RULE_DEFS.len());

        // Every rule has the required fields
        for rule in rules {
            assert!(rule["id"].is_string());
            assert!(rule["name"].is_string());
            assert!(rule["shortDescription"]["text"].is_string());
            assert!(rule["helpUri"].is_string());
        }
    }

    #[test]
    fn severity_maps_to_correct_sarif_level() {
        let graph = empty_graph();
        let findings = vec![
            make_finding(
                Severity::Critical,
                FindingCategory::UnpinnedAction,
                "critical",
            ),
            make_finding(
                Severity::High,
                FindingCategory::OverPrivilegedIdentity,
                "high",
            ),
            make_finding(
                Severity::Medium,
                FindingCategory::AuthorityPropagation,
                "medium",
            ),
            make_finding(Severity::Low, FindingCategory::LongLivedCredential, "low"),
            make_finding(Severity::Info, FindingCategory::FloatingImage, "info"),
        ];

        let sarif = emit_to_string(&graph, &findings);
        let results = sarif["runs"][0]["results"].as_array().unwrap();

        assert_eq!(results[0]["level"], "error");   // Critical
        assert_eq!(results[1]["level"], "error");   // High
        assert_eq!(results[2]["level"], "warning"); // Medium
        assert_eq!(results[3]["level"], "note");    // Low
        assert_eq!(results[4]["level"], "note");    // Info
    }

    #[test]
    fn result_has_rule_id_message_and_location() {
        let graph = empty_graph();
        let findings = vec![make_finding(
            Severity::High,
            FindingCategory::UnpinnedAction,
            "Unpinned actions/checkout@v4",
        )];

        let sarif = emit_to_string(&graph, &findings);
        let r = &sarif["runs"][0]["results"][0];

        assert_eq!(r["ruleId"], "unpinned_action");
        assert_eq!(r["message"]["text"], "Unpinned actions/checkout@v4");

        let uri = &r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"];
        assert_eq!(uri, ".github/workflows/ci.yml");

        let base = &r["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"];
        assert_eq!(base, "%SRCROOT%");
    }
}
