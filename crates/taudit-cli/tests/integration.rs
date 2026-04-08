use std::path::PathBuf;

use taudit_core::finding::{FindingCategory, Severity};
use taudit_core::graph::{NodeKind, PipelineSource, TrustZone};
use taudit_core::ignore::IgnoreConfig;
use taudit_core::ports::PipelineParser;
use taudit_core::propagation::DEFAULT_MAX_HOPS;
use taudit_core::rules;
use taudit_parse_gha::GhaParser;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn parse(yaml: &str) -> taudit_core::graph::AuthorityGraph {
    let parser = GhaParser;
    let source = PipelineSource {
        file: "test.yml".into(),
        repo: None,
        git_ref: None,
    };
    parser.parse(yaml, &source).unwrap()
}

#[test]
fn clean_workflow_minimal_findings() {
    let yaml = std::fs::read_to_string(fixture("clean.yml")).unwrap();
    let graph = parse(&yaml);
    let findings = rules::run_all_rules(&graph, DEFAULT_MAX_HOPS);

    // Clean workflow: SHA-pinned action, contents:read
    // Only finding: GITHUB_TOKEN propagation to third-party (graduated to High)
    assert!(findings.iter().all(|f| f.severity != Severity::Critical));
}

#[test]
fn over_privileged_has_critical_findings() {
    let yaml = std::fs::read_to_string(fixture("over-privileged.yml")).unwrap();
    let graph = parse(&yaml);
    let findings = rules::run_all_rules(&graph, DEFAULT_MAX_HOPS);

    // Should have critical findings (untrusted with authority, propagation)
    assert!(findings.iter().any(|f| f.severity == Severity::Critical));

    // Should detect over-privileged identity
    assert!(findings
        .iter()
        .any(|f| f.category == FindingCategory::OverPrivilegedIdentity));

    // Should detect unpinned actions
    assert!(findings
        .iter()
        .any(|f| f.category == FindingCategory::UnpinnedAction));

    // Should detect long-lived credentials (AWS keys)
    assert!(findings
        .iter()
        .any(|f| f.category == FindingCategory::LongLivedCredential));
}

#[test]
fn propagation_leaky_detects_boundary_crossings() {
    let yaml = std::fs::read_to_string(fixture("propagation-leaky.yml")).unwrap();
    let graph = parse(&yaml);
    let findings = rules::run_all_rules(&graph, DEFAULT_MAX_HOPS);

    // Should detect authority propagation
    assert!(findings
        .iter()
        .any(|f| f.category == FindingCategory::AuthorityPropagation));

    // Should detect untrusted step with authority
    assert!(findings
        .iter()
        .any(|f| f.category == FindingCategory::UntrustedWithAuthority));

    // All propagation findings should have path evidence
    for f in findings
        .iter()
        .filter(|f| f.category == FindingCategory::AuthorityPropagation)
    {
        assert!(
            f.path.is_some(),
            "propagation finding missing path evidence"
        );
    }
}

#[test]
fn authority_map_correct_for_fixture() {
    let yaml = std::fs::read_to_string(fixture("over-privileged.yml")).unwrap();
    let graph = parse(&yaml);
    let map = taudit_core::map::authority_map(&graph);

    // Should have authority sources (GITHUB_TOKEN + secrets)
    assert!(!map.authorities.is_empty());

    // Should have step rows
    assert!(!map.rows.is_empty());

    // At least one step should have access to something
    assert!(map.rows.iter().any(|r| r.access.iter().any(|&a| a)));
}

#[test]
fn json_output_round_trips() {
    let yaml = std::fs::read_to_string(fixture("clean.yml")).unwrap();
    let graph = parse(&yaml);
    let findings = rules::run_all_rules(&graph, DEFAULT_MAX_HOPS);

    // Serialize to JSON
    let mut buf = Vec::new();
    use taudit_core::ports::ReportSink;
    taudit_report_json::JsonReportSink
        .emit(&mut buf, &graph, &findings)
        .unwrap();

    // Should be valid JSON
    let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    assert!(json.get("graph").is_some());
    assert!(json.get("findings").is_some());
    assert!(json.get("summary").is_some());
}

#[test]
fn pull_request_target_detected() {
    let yaml = r#"
on: pull_request_target
permissions: write-all
jobs:
  check:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "processing PR"
        env:
          TITLE: "${{ github.event.pull_request.title }}"
"#;
    let graph = parse(yaml);

    // Steps in a pull_request_target workflow should be flagged
    // The checkout step uses an untrusted action and has GITHUB_TOKEN
    let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
    assert!(steps.len() >= 2);

    // GITHUB_TOKEN with write-all should be flagged
    let findings = rules::run_all_rules(&graph, DEFAULT_MAX_HOPS);
    assert!(findings
        .iter()
        .any(|f| f.category == FindingCategory::OverPrivilegedIdentity));
}

#[test]
fn sha_pinned_action_gets_third_party_zone() {
    let yaml = r#"
jobs:
  ci:
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - uses: actions/checkout@v4
      - uses: ./.github/actions/local
"#;
    let graph = parse(yaml);
    let images: Vec<_> = graph.nodes_of_kind(NodeKind::Image).collect();

    assert_eq!(images.len(), 3);

    // SHA-pinned -> ThirdParty
    let pinned = images.iter().find(|n| n.name.contains("a5ac7e5")).unwrap();
    assert_eq!(pinned.trust_zone, TrustZone::ThirdParty);

    // Tag-pinned -> Untrusted
    let tagged = images.iter().find(|n| n.name.contains("@v4")).unwrap();
    assert_eq!(tagged.trust_zone, TrustZone::Untrusted);

    // Local -> FirstParty
    let local = images.iter().find(|n| n.name.contains("local")).unwrap();
    assert_eq!(local.trust_zone, TrustZone::FirstParty);
}

// ── Severity threshold tests ──────────────────────────

#[test]
fn severity_threshold_filters_exit_code_logic() {
    let yaml = std::fs::read_to_string(fixture("over-privileged.yml")).unwrap();
    let graph = parse(&yaml);
    let findings = rules::run_all_rules(&graph, DEFAULT_MAX_HOPS);

    // Without threshold: has Critical findings -> would exit 1
    assert!(findings.iter().any(|f| f.severity == Severity::Critical));

    // With threshold=Critical: only Critical findings trigger exit 1
    let has_critical = findings.iter().any(|f| f.severity <= Severity::Critical);
    assert!(has_critical, "Critical findings should trigger exit");

    // With threshold=Info (most permissive): any finding triggers exit
    let has_any = findings.iter().any(|f| f.severity <= Severity::Info);
    assert!(has_any);

    // All findings still present regardless of threshold
    assert!(findings.len() > 0, "threshold doesn't remove findings from report");
}

#[test]
fn threshold_high_skips_medium_and_low() {
    let yaml = std::fs::read_to_string(fixture("clean.yml")).unwrap();
    let graph = parse(&yaml);
    let findings = rules::run_all_rules(&graph, DEFAULT_MAX_HOPS);

    // Clean workflow should have no Critical findings
    assert!(!findings.iter().any(|f| f.severity == Severity::Critical));

    // With threshold=Critical: only critical matters -> no trigger
    let would_exit = findings.iter().any(|f| f.severity <= Severity::Critical);
    assert!(!would_exit, "no critical findings -> exit 0 with critical threshold");
}

// ── Ignore file tests ─────────────────────────────────

#[test]
fn ignore_file_suppresses_expected_findings() {
    let yaml = std::fs::read_to_string(fixture("over-privileged.yml")).unwrap();
    let graph = parse(&yaml);
    let findings = rules::run_all_rules(&graph, DEFAULT_MAX_HOPS);

    // Count unpinned action findings before ignore
    let unpinned_before = findings
        .iter()
        .filter(|f| f.category == FindingCategory::UnpinnedAction)
        .count();
    assert!(unpinned_before > 0, "should have unpinned action findings");

    // Create ignore config that suppresses UnpinnedAction
    let ignore_yaml = r#"
ignore:
  - category: unpinned_action
    reason: "Accepted for this test"
"#;
    let config: IgnoreConfig = serde_yaml::from_str(ignore_yaml).unwrap();
    let result = config.apply(findings, &graph.source.file);

    // Unpinned actions should be suppressed
    let unpinned_after = result
        .findings
        .iter()
        .filter(|f| f.category == FindingCategory::UnpinnedAction)
        .count();
    assert_eq!(unpinned_after, 0, "unpinned action findings should be suppressed");
    assert!(result.suppressed_count > 0, "should have suppressed findings");

    // Other findings should still be present
    assert!(!result.findings.is_empty(), "non-matching findings should survive");
}

#[test]
fn ignore_file_with_path_only_matches_specific_file() {
    let yaml = std::fs::read_to_string(fixture("over-privileged.yml")).unwrap();
    let graph = parse(&yaml);
    let findings = rules::run_all_rules(&graph, DEFAULT_MAX_HOPS);
    let total = findings.len();

    // Ignore UnpinnedAction but only for a different file
    let ignore_yaml = r#"
ignore:
  - category: unpinned_action
    path: ".github/workflows/other.yml"
"#;
    let config: IgnoreConfig = serde_yaml::from_str(ignore_yaml).unwrap();
    let result = config.apply(findings, &graph.source.file);

    // Nothing should be suppressed — path doesn't match
    assert_eq!(result.findings.len(), total);
    assert_eq!(result.suppressed_count, 0);
}
