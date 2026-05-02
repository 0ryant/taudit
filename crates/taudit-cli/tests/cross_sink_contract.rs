//! Cross-sink contract: every finding's `fingerprint` and `rule_id` must be
//! byte-identical across the three production sinks (JSON, SARIF, CloudEvents).
//!
//! The contract is documented in `docs/finding-fingerprint.md`; this test
//! pins it. Without it, a regression in any single sink — say, a SARIF
//! refactor that re-derives the fingerprint with a slightly different input
//! recipe, or a CloudEvents change that re-computes the rule id from a
//! different field — silently breaks SIEM dedup keyed on the fingerprint.
//!
//! Two finding shapes are exercised:
//!   1. A built-in finding (`AuthorityPropagation`). `rule_id` MUST be the
//!      snake_case category across all three sinks.
//!   2. A custom-rule finding whose message starts with a `[my_rule]`
//!      bracketed prefix. `rule_id` MUST be `my_rule` across all three sinks
//!      — the custom-rule prefix wins per `taudit_core::finding::rule_id_for`.

use std::collections::HashMap;

use taudit_core::custom_rules::{CustomRule, MatchSpec};
use taudit_core::finding::{
    Finding, FindingCategory, FindingExtras, FindingSource, Recommendation, Severity,
};
use taudit_core::graph::{AuthorityGraph, EdgeKind, NodeKind, PipelineSource, TrustZone};
use taudit_core::ports::ReportSink;
use taudit_report_json::JsonReportSink;
use taudit_report_sarif::SarifReportSink;
use taudit_sink_cloudevents::CloudEventsJsonlSink;

/// Build one rich-metadata graph plus two findings (built-in + custom-rule)
/// so each sink invocation operates on an identical input. The metadata
/// shape mirrors the JSON byte-determinism test's `build_graph` helper —
/// multiple secrets, varied permissions, varied metadata keys — so every
/// HashMap-iteration code path that could leak non-determinism into the
/// fingerprint inputs is exercised on the same graph all three sinks see.
fn build_graph_with_findings() -> (AuthorityGraph, Vec<Finding>) {
    let mut graph = AuthorityGraph::new(PipelineSource {
        file: ".github/workflows/ci.yml".into(),
        repo: None,
        git_ref: None,
        commit_sha: None,
    });

    let secret_a = graph.add_node(NodeKind::Secret, "AWS_KEY", TrustZone::FirstParty);
    let secret_b = graph.add_node(NodeKind::Secret, "DEPLOY_TOKEN", TrustZone::FirstParty);
    let step = graph.add_node(NodeKind::Step, "deploy", TrustZone::FirstParty);
    graph.add_edge(step, secret_a, EdgeKind::HasAccessTo);
    graph.add_edge(step, secret_b, EdgeKind::HasAccessTo);

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
    graph.metadata.insert("platform".into(), "gha".into());

    let builtin = Finding {
        severity: Severity::High,
        category: FindingCategory::AuthorityPropagation,
        path: None,
        nodes_involved: vec![secret_a, step],
        message: "AWS_KEY reaches deploy across trust boundary".into(),
        recommendation: Recommendation::Manual {
            action: "scope it".into(),
        },
        source: FindingSource::BuiltIn,
        extras: FindingExtras::default(),
    };

    let custom = Finding {
        severity: Severity::Medium,
        category: FindingCategory::UnpinnedAction,
        path: None,
        nodes_involved: vec![step],
        message: "[my_custom_rule] this is a user-defined invariant violation".into(),
        recommendation: Recommendation::Manual {
            action: "tighten the policy".into(),
        },
        source: FindingSource::Custom {
            source_file: std::path::PathBuf::from("rules/my_custom_rule.yaml"),
        },
        extras: FindingExtras::default(),
    };

    (graph, vec![builtin, custom])
}

/// Stub `CustomRule` matching the `[my_custom_rule]` finding message prefix
/// so the SARIF sink injects it into the SARIF `rules[]` array. Without this
/// the SARIF result would use the *category* rule id instead of `my_custom_rule`,
/// because SARIF only honours the bracketed prefix for known custom ids
/// (`finding_to_result` filters on `custom_ids.contains(...)`).
fn custom_rules_for_test() -> Vec<CustomRule> {
    vec![CustomRule {
        id: "my_custom_rule".to_string(),
        name: "My Custom Rule".to_string(),
        description: "test custom rule".to_string(),
        severity: Severity::Medium,
        category: FindingCategory::UnpinnedAction,
        match_spec: MatchSpec::default(),
        source_file: None,
    }]
}

/// Pull `(rule_id, fingerprint)` pairs in input order from a JSON report.
fn json_pairs(graph: &AuthorityGraph, findings: &[Finding]) -> Vec<(String, String)> {
    let mut buf = Vec::new();
    JsonReportSink.emit(&mut buf, graph, findings).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["rule_id"].as_str().unwrap().to_string(),
                f["fingerprint"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

/// Pull `(rule_id, fingerprint)` pairs in input order from a SARIF report.
/// Uses `emit_multi_with_custom_rules` so the custom rule actually surfaces
/// as `result.ruleId = "my_custom_rule"` rather than the category fallback.
fn sarif_pairs(
    graph: &AuthorityGraph,
    findings: &[Finding],
    custom_rules: &[CustomRule],
) -> Vec<(String, String)> {
    let mut buf = Vec::new();
    SarifReportSink
        .emit_multi_with_custom_rules(&mut buf, &[(graph, findings)], custom_rules)
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    v["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["ruleId"].as_str().unwrap().to_string(),
                r["partialFingerprints"]["primaryLocationLineHash"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
        })
        .collect()
}

/// Pull `(tauditruleid, tauditfindingfingerprint)` pairs in input order from
/// the CloudEvents JSONL stream.
fn cloudevents_pairs(graph: &AuthorityGraph, findings: &[Finding]) -> Vec<(String, String)> {
    let mut buf = Vec::new();
    // Pin the correlation id so the test never mints a UUID that could leak
    // into other assertions in this file (pure cleanliness — none of our
    // assertions touch `correlationid`, but it keeps grep output tidy).
    let sink = CloudEventsJsonlSink::with_correlation_id(Some("cross-sink-test".into()));
    sink.emit(&mut buf, graph, findings).unwrap();
    std::str::from_utf8(&buf)
        .unwrap()
        .lines()
        .map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            (
                v["tauditruleid"].as_str().unwrap().to_string(),
                v["tauditfindingfingerprint"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn fingerprints_match_across_all_three_sinks() {
    let (graph, findings) = build_graph_with_findings();
    let custom_rules = custom_rules_for_test();

    let json = json_pairs(&graph, &findings);
    let sarif = sarif_pairs(&graph, &findings, &custom_rules);
    let ce = cloudevents_pairs(&graph, &findings);

    assert_eq!(json.len(), 2, "json sink emitted wrong finding count");
    assert_eq!(sarif.len(), 2, "sarif sink emitted wrong finding count");
    assert_eq!(ce.len(), 2, "cloudevents sink emitted wrong finding count");

    for i in 0..2 {
        let (_, fp_json) = &json[i];
        let (_, fp_sarif) = &sarif[i];
        let (_, fp_ce) = &ce[i];
        assert_eq!(
            fp_json, fp_sarif,
            "finding[{i}]: JSON fingerprint {fp_json} != SARIF partialFingerprints {fp_sarif}"
        );
        assert_eq!(
            fp_sarif, fp_ce,
            "finding[{i}]: SARIF partialFingerprints {fp_sarif} != CloudEvents tauditfindingfingerprint {fp_ce}"
        );
    }
}

#[test]
fn rule_ids_match_across_all_three_sinks() {
    let (graph, findings) = build_graph_with_findings();
    let custom_rules = custom_rules_for_test();

    let json = json_pairs(&graph, &findings);
    let sarif = sarif_pairs(&graph, &findings, &custom_rules);
    let ce = cloudevents_pairs(&graph, &findings);

    for i in 0..2 {
        let (rid_json, _) = &json[i];
        let (rid_sarif, _) = &sarif[i];
        let (rid_ce, _) = &ce[i];
        assert_eq!(
            rid_json, rid_sarif,
            "finding[{i}]: JSON rule_id {rid_json} != SARIF ruleId {rid_sarif}"
        );
        assert_eq!(
            rid_sarif, rid_ce,
            "finding[{i}]: SARIF ruleId {rid_sarif} != CloudEvents tauditruleid {rid_ce}"
        );
    }
}

#[test]
fn builtin_finding_uses_snake_case_category_rule_id() {
    let (graph, findings) = build_graph_with_findings();
    let custom_rules = custom_rules_for_test();

    let json = json_pairs(&graph, &findings);
    let sarif = sarif_pairs(&graph, &findings, &custom_rules);
    let ce = cloudevents_pairs(&graph, &findings);

    // findings[0] is the built-in `AuthorityPropagation`.
    assert_eq!(json[0].0, "authority_propagation");
    assert_eq!(sarif[0].0, "authority_propagation");
    assert_eq!(ce[0].0, "authority_propagation");
}

#[test]
fn custom_rule_finding_surfaces_bracketed_id_in_all_three_sinks() {
    let (graph, findings) = build_graph_with_findings();
    let custom_rules = custom_rules_for_test();

    let json = json_pairs(&graph, &findings);
    let sarif = sarif_pairs(&graph, &findings, &custom_rules);
    let ce = cloudevents_pairs(&graph, &findings);

    // findings[1] message starts with `[my_custom_rule] …`. The custom-rule
    // id MUST win across every sink, not the `UnpinnedAction` category that
    // happens to be on the Finding struct.
    assert_eq!(json[1].0, "my_custom_rule");
    assert_eq!(sarif[1].0, "my_custom_rule");
    assert_eq!(ce[1].0, "my_custom_rule");
}
