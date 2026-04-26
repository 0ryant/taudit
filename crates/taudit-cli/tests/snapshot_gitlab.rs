use std::path::PathBuf;

use insta::assert_yaml_snapshot;
use taudit_core::finding::Finding;
use taudit_core::graph::PipelineSource;
use taudit_core::ports::{PipelineParser, ReportSink};
use taudit_core::propagation::DEFAULT_MAX_HOPS;
use taudit_core::rules;
use taudit_parse_gitlab::GitlabParser;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn parse_gitlab(yaml: &str) -> taudit_core::graph::AuthorityGraph {
    let source = PipelineSource {
        file: ".gitlab-ci.yml".into(),
        repo: None,
        git_ref: None,
        commit_sha: None,
    };
    GitlabParser.parse(yaml, &source).unwrap()
}

fn sorted_findings(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| {
        let ka = (
            format!("{:?}", a.category),
            a.message.clone(),
            a.nodes_involved.clone(),
        );
        let kb = (
            format!("{:?}", b.category),
            b.message.clone(),
            b.nodes_involved.clone(),
        );
        ka.cmp(&kb)
    });
    findings
}

// ── GitLab credential-in-variable fixture ────────────────────────────────────

#[test]
fn snap_gitlab_creds_all_findings() {
    let yaml = std::fs::read_to_string(fixture("gitlab-creds.yml")).unwrap();
    let graph = parse_gitlab(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    assert_yaml_snapshot!("gitlab_creds_all_findings", findings);
}

#[test]
fn snap_gitlab_creds_per_finding() {
    let yaml = std::fs::read_to_string(fixture("gitlab-creds.yml")).unwrap();
    let graph = parse_gitlab(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    for (i, finding) in findings.iter().enumerate() {
        assert_yaml_snapshot!(format!("gitlab_creds_finding_{i}"), finding);
    }
}

#[test]
fn snap_gitlab_creds_json() {
    let yaml = std::fs::read_to_string(fixture("gitlab-creds.yml")).unwrap();
    let graph = parse_gitlab(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    let mut buf = Vec::new();
    taudit_report_json::JsonReportSink
        .emit(&mut buf, &graph, &findings)
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    assert_yaml_snapshot!("gitlab_creds_json_report", json);
}

#[test]
fn snap_gitlab_creds_sarif_results() {
    let yaml = std::fs::read_to_string(fixture("gitlab-creds.yml")).unwrap();
    let graph = parse_gitlab(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    let mut buf = Vec::new();
    taudit_report_sarif::SarifReportSink
        .emit(&mut buf, &graph, &findings)
        .unwrap();
    let sarif: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    let results = sarif["runs"][0]["results"].clone();
    assert_yaml_snapshot!("gitlab_creds_sarif_results", results);
}

// ── GitLab inline scenarios ───────────────────────────────────────────────────

#[test]
fn snap_gitlab_mr_trigger_with_secrets_findings() {
    let yaml = r#"
stages:
  - test

variables:
  DEPLOY_TOKEN: "hard-coded-token"

.mr_rules:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'

test:
  extends: .mr_rules
  stage: test
  image: node:18
  script:
    - npm test
  secrets:
    VAULT_SECRET:
      vault: secret/myapp/token@ops
"#;
    let graph = parse_gitlab(yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    assert_yaml_snapshot!("gitlab_mr_trigger_secrets_findings", findings);
}

#[test]
fn snap_gitlab_docker_floating_image_findings() {
    let yaml = r#"
stages:
  - build

build:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t myapp:latest .
    - docker push myapp:latest
  variables:
    REGISTRY_TOKEN: "my-registry-password"
"#;
    let graph = parse_gitlab(yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    assert_yaml_snapshot!("gitlab_docker_floating_findings", findings);
}
