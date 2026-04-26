mod common;

use insta::assert_yaml_snapshot;
use taudit_core::graph::PipelineSource;
use taudit_core::ports::{PipelineParser, ReportSink};
use taudit_core::propagation::DEFAULT_MAX_HOPS;
use taudit_core::rules;
use taudit_parse_ado::AdoParser;

use common::{fixture, sorted_findings};

fn parse_ado(yaml: &str) -> taudit_core::graph::AuthorityGraph {
    let source = PipelineSource {
        file: "azure-pipelines.yml".into(),
        repo: None,
        git_ref: None,
        commit_sha: None,
    };
    AdoParser.parse(yaml, &source).unwrap()
}

// ── ADO setvariable fixture ──────────────────────────────────────────────────

#[test]
fn snap_ado_setvariable_all_findings() {
    let yaml = std::fs::read_to_string(fixture("ado-setvariable.yml")).unwrap();
    let graph = parse_ado(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    assert_yaml_snapshot!("ado_setvariable_all_findings", findings);
}

#[test]
fn snap_ado_setvariable_per_finding() {
    let yaml = std::fs::read_to_string(fixture("ado-setvariable.yml")).unwrap();
    let graph = parse_ado(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    for (i, finding) in findings.iter().enumerate() {
        assert_yaml_snapshot!(format!("ado_setvariable_finding_{i}"), finding);
    }
}

#[test]
fn snap_ado_setvariable_json() {
    let yaml = std::fs::read_to_string(fixture("ado-setvariable.yml")).unwrap();
    let graph = parse_ado(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    let mut buf = Vec::new();
    taudit_report_json::JsonReportSink
        .emit(&mut buf, &graph, &findings)
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    assert_yaml_snapshot!("ado_setvariable_json_report", json);
}

#[test]
fn snap_ado_setvariable_sarif_results() {
    let yaml = std::fs::read_to_string(fixture("ado-setvariable.yml")).unwrap();
    let graph = parse_ado(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    let mut buf = Vec::new();
    taudit_report_sarif::SarifReportSink
        .emit(&mut buf, &graph, &findings)
        .unwrap();
    let sarif: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    let results = sarif["runs"][0]["results"].clone();
    assert_yaml_snapshot!("ado_setvariable_sarif_results", results);
}

// ── ADO shared pool fixture ──────────────────────────────────────────────────

#[test]
fn snap_ado_shared_pool_all_findings() {
    let yaml = std::fs::read_to_string(fixture("ado-shared-pool.yml")).unwrap();
    let graph = parse_ado(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    assert_yaml_snapshot!("ado_shared_pool_all_findings", findings);
}

#[test]
fn snap_ado_shared_pool_per_finding() {
    let yaml = std::fs::read_to_string(fixture("ado-shared-pool.yml")).unwrap();
    let graph = parse_ado(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    for (i, finding) in findings.iter().enumerate() {
        assert_yaml_snapshot!(format!("ado_shared_pool_finding_{i}"), finding);
    }
}

#[test]
fn snap_ado_shared_pool_json() {
    let yaml = std::fs::read_to_string(fixture("ado-shared-pool.yml")).unwrap();
    let graph = parse_ado(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    let mut buf = Vec::new();
    taudit_report_json::JsonReportSink
        .emit(&mut buf, &graph, &findings)
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    assert_yaml_snapshot!("ado_shared_pool_json_report", json);
}

#[test]
fn snap_ado_shared_pool_sarif_results() {
    let yaml = std::fs::read_to_string(fixture("ado-shared-pool.yml")).unwrap();
    let graph = parse_ado(&yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    let mut buf = Vec::new();
    taudit_report_sarif::SarifReportSink
        .emit(&mut buf, &graph, &findings)
        .unwrap();
    let sarif: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    let results = sarif["runs"][0]["results"].clone();
    assert_yaml_snapshot!("ado_shared_pool_sarif_results", results);
}

// ── ADO inline scenarios ─────────────────────────────────────────────────────

#[test]
fn snap_ado_terraform_autoapprove_findings() {
    let yaml = r#"
trigger:
  - main

pool:
  vmImage: ubuntu-latest

steps:
  - script: |
      terraform init
      terraform apply -auto-approve
    displayName: Terraform deploy
    env:
      ARM_CLIENT_SECRET: $(ARM_CLIENT_SECRET)
"#;
    let graph = parse_ado(yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    assert_yaml_snapshot!("ado_terraform_autoapprove_findings", findings);
}

#[test]
fn snap_ado_keyvault_plaintext_findings() {
    let yaml = r#"
trigger:
  - main

pool:
  vmImage: ubuntu-latest

variables:
  - group: ProductionSecrets

steps:
  - script: |
      echo "Deploying with key: $(DEPLOY_KEY)"
      curl -H "Authorization: $(API_TOKEN)" https://api.example.com
    displayName: Deploy
"#;
    let graph = parse_ado(yaml);
    let findings = sorted_findings(rules::run_all_rules(&graph, DEFAULT_MAX_HOPS));
    assert_yaml_snapshot!("ado_keyvault_plaintext_findings", findings);
}
