mod common;

use insta::assert_yaml_snapshot;
use taudit_core::graph::PipelineSource;
use taudit_core::ports::{PipelineParser, ReportSink};
use taudit_core::propagation::DEFAULT_MAX_HOPS;
use taudit_core::rules;
use taudit_parse_gha::GhaParser;

use common::{fixture, sorted_findings};

fn strip_ansi(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&ch) = chars.peek() {
                    chars.next();
                    if ch.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

fn parse_gha(yaml: &str) -> taudit_core::graph::AuthorityGraph {
    let source = PipelineSource {
        file: "test.yml".into(),
        repo: None,
        git_ref: None,
        commit_sha: None,
    };
    GhaParser.parse(yaml, &source).unwrap()
}

// ── GHA over-privileged.yml ──────────────────────────────────────────────────

#[test]
fn snap_gha_over_privileged_all_findings() {
    let yaml = std::fs::read_to_string(fixture("over-privileged.yml")).unwrap();
    let graph = parse_gha(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    assert_yaml_snapshot!("gha_over_privileged_all_findings", findings);
}

#[test]
fn snap_gha_over_privileged_per_finding() {
    let yaml = std::fs::read_to_string(fixture("over-privileged.yml")).unwrap();
    let graph = parse_gha(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    for (i, finding) in findings.iter().enumerate() {
        assert_yaml_snapshot!(format!("gha_over_privileged_finding_{i}"), finding);
    }
}

#[test]
fn snap_gha_over_privileged_json() {
    let yaml = std::fs::read_to_string(fixture("over-privileged.yml")).unwrap();
    let graph = parse_gha(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    let mut buf = Vec::new();
    taudit_report_json::JsonReportSink
        .emit(&mut buf, &graph, &findings)
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    assert_yaml_snapshot!("gha_over_privileged_json_report", json);
}

#[test]
fn snap_gha_over_privileged_sarif_results() {
    let yaml = std::fs::read_to_string(fixture("over-privileged.yml")).unwrap();
    let graph = parse_gha(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    let mut buf = Vec::new();
    taudit_report_sarif::SarifReportSink
        .emit(&mut buf, &graph, &findings)
        .unwrap();
    let sarif: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    let results = sarif["runs"][0]["results"].clone();
    assert_yaml_snapshot!("gha_over_privileged_sarif_results", results);
}

#[test]
fn snap_gha_over_privileged_terminal() {
    let yaml = std::fs::read_to_string(fixture("over-privileged.yml")).unwrap();
    let graph = parse_gha(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    let mut buf = Vec::new();
    let sink = taudit_report_terminal::TerminalReport::default();
    sink.emit(&mut buf, &graph, &findings).unwrap();
    let raw = String::from_utf8(buf).unwrap();
    assert_yaml_snapshot!("gha_over_privileged_terminal", strip_ansi(&raw));
}

// ── GHA clean.yml ────────────────────────────────────────────────────────────

#[test]
fn snap_gha_clean_all_findings() {
    let yaml = std::fs::read_to_string(fixture("clean.yml")).unwrap();
    let graph = parse_gha(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    assert_yaml_snapshot!("gha_clean_all_findings", findings);
}

#[test]
fn snap_gha_clean_per_finding() {
    let yaml = std::fs::read_to_string(fixture("clean.yml")).unwrap();
    let graph = parse_gha(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    for (i, finding) in findings.iter().enumerate() {
        assert_yaml_snapshot!(format!("gha_clean_finding_{i}"), finding);
    }
}

#[test]
fn snap_gha_clean_json() {
    let yaml = std::fs::read_to_string(fixture("clean.yml")).unwrap();
    let graph = parse_gha(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    let mut buf = Vec::new();
    taudit_report_json::JsonReportSink
        .emit(&mut buf, &graph, &findings)
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    assert_yaml_snapshot!("gha_clean_json_report", json);
}

#[test]
fn snap_gha_clean_sarif_results() {
    let yaml = std::fs::read_to_string(fixture("clean.yml")).unwrap();
    let graph = parse_gha(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    let mut buf = Vec::new();
    taudit_report_sarif::SarifReportSink
        .emit(&mut buf, &graph, &findings)
        .unwrap();
    let sarif: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    let results = sarif["runs"][0]["results"].clone();
    assert_yaml_snapshot!("gha_clean_sarif_results", results);
}

// ── GHA propagation-leaky.yml ────────────────────────────────────────────────

#[test]
fn snap_gha_propagation_all_findings() {
    let yaml = std::fs::read_to_string(fixture("propagation-leaky.yml")).unwrap();
    let graph = parse_gha(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    assert_yaml_snapshot!("gha_propagation_all_findings", findings);
}

#[test]
fn snap_gha_propagation_per_finding() {
    let yaml = std::fs::read_to_string(fixture("propagation-leaky.yml")).unwrap();
    let graph = parse_gha(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    for (i, finding) in findings.iter().enumerate() {
        assert_yaml_snapshot!(format!("gha_propagation_finding_{i}"), finding);
    }
}

#[test]
fn snap_gha_propagation_json() {
    let yaml = std::fs::read_to_string(fixture("propagation-leaky.yml")).unwrap();
    let graph = parse_gha(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    let mut buf = Vec::new();
    taudit_report_json::JsonReportSink
        .emit(&mut buf, &graph, &findings)
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    assert_yaml_snapshot!("gha_propagation_json_report", json);
}

#[test]
fn snap_gha_propagation_sarif_results() {
    let yaml = std::fs::read_to_string(fixture("propagation-leaky.yml")).unwrap();
    let graph = parse_gha(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    let mut buf = Vec::new();
    taudit_report_sarif::SarifReportSink
        .emit(&mut buf, &graph, &findings)
        .unwrap();
    let sarif: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    let results = sarif["runs"][0]["results"].clone();
    assert_yaml_snapshot!("gha_propagation_sarif_results", results);
}

// ── GHA inline scenarios ─────────────────────────────────────────────────────

const PRT_YAML: &str = r#"
on: pull_request_target
permissions: write-all
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.pull_request.title }}"
"#;

#[test]
fn snap_gha_pull_request_target_findings() {
    let graph = parse_gha(PRT_YAML);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    assert_yaml_snapshot!("gha_prt_all_findings", findings);
}

#[test]
fn snap_gha_pull_request_target_per_finding() {
    let graph = parse_gha(PRT_YAML);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    for (i, finding) in findings.iter().enumerate() {
        assert_yaml_snapshot!(format!("gha_prt_finding_{i}"), finding);
    }
}

#[test]
fn snap_gha_write_all_with_secrets_findings() {
    let yaml = r#"
on: push
permissions: write-all
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - run: deploy.sh
        env:
          AWS_KEY: ${{ secrets.AWS_ACCESS_KEY_ID }}
          DB_PASS: ${{ secrets.DB_PASSWORD }}
"#;
    let graph = parse_gha(yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    assert_yaml_snapshot!("gha_write_all_secrets_findings", findings);
}
