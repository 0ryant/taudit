//! L5-09 hostile rendering corpus.
//!
//! This file is intentionally separate from `output_injection_corpus.rs`: that
//! earlier corpus pins ANSI/Markdown basics, while this one adds CRLF/path
//! separator injection, SARIF-shaped text, and long attacker-controlled fields.

use std::collections::HashMap;
use std::path::PathBuf;

use taudit_core::custom_rules::{CustomRule, MatchSpec};
use taudit_core::finding::{
    Finding, FindingCategory, FindingExtras, FindingSource, Recommendation, Severity,
};
use taudit_core::graph::{AuthorityGraph, EdgeKind, NodeKind, PipelineSource, TrustZone};
use taudit_core::ports::ReportSink;
use taudit_report_json::JsonReportSink;
use taudit_report_sarif::SarifReportSink;
use taudit_report_terminal::TerminalReport;
use taudit_sink_cloudevents::CloudEventsJsonlSink;

const CUSTOM_RULE_ID: &str = "hostile_custom_rule";
const FORGED_LINE: &str = "TAUDIT_FORGED_CLEAN_LINE";

#[derive(Debug, Clone, PartialEq, Eq)]
struct SinkIdentity {
    rule_id: String,
    fingerprint: String,
    suppression_key: String,
    finding_group_id: String,
}

struct HostileCase {
    graph: AuthorityGraph,
    findings: Vec<Finding>,
    custom_rules: Vec<CustomRule>,
    raw_message: String,
    raw_source_file: String,
}

fn hostile_text(label: &str) -> String {
    let long_tail = "L".repeat(6_144);
    format!(
        "{label} \x1b[2J\x1b[H\x07\u{202e}\u{200d} \
         [review](https://attacker.example/triage?token=1) \
         <script>alert(1)</script> \
         SARIF-text {{\"runs\":[{{\"results\":[{{\"ruleId\":\"forged.clean\",\"message\":{{\"text\":\"no findings\"}}}}]}}]}} \
         ..\\..\\release/../../workflow.yml\r\n{FORGED_LINE} {long_tail}"
    )
}

fn build_hostile_case() -> HostileCase {
    let raw_source_file = format!(".github\\workflows\\release/../../hostile\r\n{FORGED_LINE}.yml");
    let mut graph = AuthorityGraph::new(PipelineSource {
        file: raw_source_file.clone(),
        repo: Some("0ryant/taudit".into()),
        git_ref: Some("refs/pull/9/head".into()),
        commit_sha: None,
    });
    graph.metadata.insert("platform".into(), "gha".into());

    let secret_name = hostile_text("AWS_PROD_KEY");
    let step_name = hostile_text("deploy-step");
    let secret = graph.add_node(NodeKind::Secret, secret_name, TrustZone::FirstParty);
    let step = graph.add_node(NodeKind::Step, step_name, TrustZone::Untrusted);
    graph.add_edge(step, secret, EdgeKind::HasAccessTo);

    if let Some(node) = graph.nodes.get_mut(step) {
        let mut metadata = HashMap::new();
        metadata.insert("permissions".into(), hostile_text("contents:write"));
        metadata.insert("identity_scope".into(), hostile_text("prod/subscription"));
        node.metadata = metadata;
    }

    let raw_message = format!("[{CUSTOM_RULE_ID}] {}", hostile_text("finding-message"));
    let finding = Finding {
        severity: Severity::High,
        category: FindingCategory::AuthorityPropagation,
        path: None,
        nodes_involved: vec![secret, step],
        message: raw_message.clone(),
        recommendation: Recommendation::Manual {
            action: hostile_text("recommendation"),
        },
        source: FindingSource::Custom {
            source_file: PathBuf::from(format!("rules\\hostile\r\n{FORGED_LINE}.yaml")),
        },
        extras: FindingExtras::default(),
    };

    let custom_rules = vec![CustomRule {
        id: CUSTOM_RULE_ID.into(),
        name: hostile_text("custom-rule-name"),
        description: hostile_text("custom-rule-description"),
        severity: Severity::High,
        category: FindingCategory::AuthorityPropagation,
        match_spec: MatchSpec::default(),
        source_file: Some(PathBuf::from("rules/hostile.yaml")),
    }];

    HostileCase {
        graph,
        findings: vec![finding],
        custom_rules,
        raw_message,
        raw_source_file,
    }
}

fn json_report(graph: &AuthorityGraph, findings: &[Finding]) -> serde_json::Value {
    let mut buf = Vec::new();
    JsonReportSink.emit(&mut buf, graph, findings).unwrap();
    serde_json::from_slice(&buf).unwrap()
}

fn sarif_report(
    graph: &AuthorityGraph,
    findings: &[Finding],
    custom_rules: &[CustomRule],
) -> serde_json::Value {
    let mut buf = Vec::new();
    SarifReportSink
        .emit_multi_with_custom_rules(&mut buf, &[(graph, findings)], custom_rules)
        .unwrap();
    serde_json::from_slice(&buf).unwrap()
}

fn cloudevent(graph: &AuthorityGraph, findings: &[Finding]) -> serde_json::Value {
    let mut buf = Vec::new();
    CloudEventsJsonlSink::with_ids(Some("hostile-rendering".into()), Some("scan-1".into()))
        .emit(&mut buf, graph, findings)
        .unwrap();
    let line = std::str::from_utf8(&buf).unwrap().lines().next().unwrap();
    serde_json::from_str(line).unwrap()
}

fn json_identity(report: &serde_json::Value) -> SinkIdentity {
    let finding = &report["findings"][0];
    SinkIdentity {
        rule_id: finding["rule_id"].as_str().unwrap().into(),
        fingerprint: finding["fingerprint"].as_str().unwrap().into(),
        suppression_key: finding["suppression_key"].as_str().unwrap().into(),
        finding_group_id: finding["finding_group_id"].as_str().unwrap().into(),
    }
}

fn sarif_identity(report: &serde_json::Value) -> SinkIdentity {
    let result = &report["runs"][0]["results"][0];
    SinkIdentity {
        rule_id: result["ruleId"].as_str().unwrap().into(),
        fingerprint: result["partialFingerprints"]["primaryLocationLineHash"]
            .as_str()
            .unwrap()
            .into(),
        suppression_key: result["properties"]["suppressionKey"]
            .as_str()
            .unwrap()
            .into(),
        finding_group_id: result["properties"]["findingGroupId"]
            .as_str()
            .unwrap()
            .into(),
    }
}

fn cloudevent_identity(event: &serde_json::Value) -> SinkIdentity {
    SinkIdentity {
        rule_id: event["tauditruleid"].as_str().unwrap().into(),
        fingerprint: event["tauditfindingfingerprint"].as_str().unwrap().into(),
        suppression_key: event["tauditsuppressionkey"].as_str().unwrap().into(),
        finding_group_id: event["tauditfindinggroup"].as_str().unwrap().into(),
    }
}

fn assert_no_interpretable_control_bytes(bytes: &[u8]) {
    for &byte in bytes {
        if byte < 0x20 && !matches!(byte, b'\n' | b'\t') {
            panic!("terminal output contains forbidden C0 byte 0x{byte:02x}");
        }
        if byte == 0x7f {
            panic!("terminal output contains DEL byte");
        }
    }
    let rendered = std::str::from_utf8(bytes).unwrap();
    for c in rendered.chars() {
        let cp = c as u32;
        if (0x80..=0x9f).contains(&cp) {
            panic!("terminal output contains C1 control U+{cp:04X}");
        }
        if matches!(
            c,
            '\u{200b}'
                | '\u{200c}'
                | '\u{200d}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'
                | '\u{202b}'
                | '\u{202c}'
                | '\u{202d}'
                | '\u{202e}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
                | '\u{feff}'
        ) {
            panic!("terminal output contains Unicode steering codepoint U+{cp:04X}");
        }
    }
}

#[test]
fn terminal_rendering_neutralizes_control_bytes_and_crlf_path_injection() {
    let case = build_hostile_case();

    colored::control::set_override(false);
    let mut buf = Vec::new();
    TerminalReport { verbose: true }
        .emit(&mut buf, &case.graph, &case.findings)
        .unwrap();

    assert_no_interpretable_control_bytes(&buf);

    let rendered = std::str::from_utf8(&buf).unwrap();
    assert!(
        !rendered.lines().any(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with(FORGED_LINE)
        }),
        "CRLF from attacker-controlled paths/messages must not mint a forged standalone line:\n{rendered}"
    );
}

#[test]
fn json_sarif_and_cloudevents_keep_identity_stable_under_hostile_fields() {
    let case = build_hostile_case();

    let json = json_report(&case.graph, &case.findings);
    let sarif = sarif_report(&case.graph, &case.findings, &case.custom_rules);
    let ce = cloudevent(&case.graph, &case.findings);

    let json_identity = json_identity(&json);
    let sarif_identity = sarif_identity(&sarif);
    let ce_identity = cloudevent_identity(&ce);

    assert_eq!(json_identity, sarif_identity);
    assert_eq!(sarif_identity, ce_identity);
    assert_eq!(json_identity.rule_id, CUSTOM_RULE_ID);
}

#[test]
fn machine_outputs_preserve_raw_payloads_while_sarif_rendering_defangs_markdown() {
    let case = build_hostile_case();

    let json = json_report(&case.graph, &case.findings);
    let sarif = sarif_report(&case.graph, &case.findings, &case.custom_rules);
    let ce = cloudevent(&case.graph, &case.findings);

    assert_eq!(json["findings"][0]["message"], case.raw_message);
    assert_eq!(json["graph"]["source"]["file"], case.raw_source_file);
    assert_eq!(ce["data"]["message"], case.raw_message);
    assert_eq!(ce["subject"], case.raw_source_file);

    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert_eq!(
        results.len(),
        1,
        "SARIF-shaped text inside message must not create forged results"
    );
    assert_eq!(results[0]["ruleId"], CUSTOM_RULE_ID);

    let message = results[0]["message"]["text"].as_str().unwrap();
    assert!(
        !message.contains("[review]("),
        "raw Markdown link was not escaped"
    );
    assert!(
        !message.contains("<script>"),
        "raw HTML tag was not escaped"
    );
    assert!(
        message.contains("https://attacker.example/triage?token=1"),
        "URL text should remain visible after Markdown defanging"
    );

    let custom_rule = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["id"] == CUSTOM_RULE_ID)
        .expect("custom rule descriptor present");
    let rule_name = custom_rule["name"].as_str().unwrap();
    let rule_description = custom_rule["shortDescription"]["text"].as_str().unwrap();
    assert!(
        !rule_name.contains("[review](") && !rule_description.contains("[review]("),
        "custom SARIF rule descriptor Markdown was not escaped"
    );
    assert!(
        !rule_name.contains("<script>") && !rule_description.contains("<script>"),
        "custom SARIF rule descriptor HTML was not escaped"
    );
}
