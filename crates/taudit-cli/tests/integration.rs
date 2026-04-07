use std::path::PathBuf;

use taudit_core::finding::{FindingCategory, Severity};
use taudit_core::graph::{NodeKind, PipelineSource, TrustZone};
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
        assert!(f.path.is_some(), "propagation finding missing path evidence");
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
