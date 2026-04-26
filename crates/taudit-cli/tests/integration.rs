use std::path::PathBuf;

use taudit_core::finding::{FindingCategory, Severity};
use taudit_core::graph::{AuthorityCompleteness, NodeKind, PipelineSource, TrustZone};
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
        commit_sha: None,
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
fn partial_graph_caps_findings_below_critical() {
    let yaml = r#"
on: pull_request_target
permissions: write-all
jobs:
    test:
        strategy:
            matrix:
                os: [ubuntu-latest, windows-latest]
        steps:
            - run: echo "checking PR"
"#;
    let graph = parse(yaml);
    assert_eq!(graph.completeness, AuthorityCompleteness::Partial);

    let findings = rules::run_all_rules(&graph, DEFAULT_MAX_HOPS);
    assert!(!findings.is_empty());
    assert!(!findings.iter().any(|f| f.severity == Severity::Critical));
    assert!(findings.iter().any(|f| f.severity == Severity::High));
    assert!(findings
        .iter()
        .any(|f| f.category == FindingCategory::UntrustedWithAuthority));
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
fn pull_request_target_run_steps_are_untrusted_with_authority() {
    // Minimal PRT workflow: run: step with GITHUB_TOKEN access but no write-all
    // (so no OverPrivilegedIdentity). The UntrustedWithAuthority finding should
    // fire because trigger-based classification marks run: steps as Untrusted.
    let yaml = r#"
on: pull_request_target
permissions:
  contents: read
jobs:
  check:
    steps:
      - run: echo "PR title is ${{ github.event.pull_request.title }}"
"#;
    let graph = parse(yaml);

    // run: step should be Untrusted (trigger-based classification)
    let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
    assert_eq!(steps.len(), 1);
    assert_eq!(
        steps[0].trust_zone,
        taudit_core::graph::TrustZone::Untrusted,
        "run: step in pull_request_target workflow must be Untrusted"
    );

    // UntrustedWithAuthority should fire because the Untrusted step has GITHUB_TOKEN access
    let findings = rules::run_all_rules(&graph, DEFAULT_MAX_HOPS);
    assert!(
        findings
            .iter()
            .any(|f| f.category == FindingCategory::UntrustedWithAuthority),
        "should detect UntrustedWithAuthority for run: step in pull_request_target workflow"
    );
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
fn severity_threshold_filters_findings() {
    // v0.7+: scan is informational and always exits 0 unless a structural
    // error occurs. --severity-threshold is now a *display filter*; the
    // logic below verifies which findings would survive the filter (and
    // would historically have triggered the v0.6 migration warning).
    let yaml = std::fs::read_to_string(fixture("over-privileged.yml")).unwrap();
    let graph = parse(&yaml);
    let findings = rules::run_all_rules(&graph, DEFAULT_MAX_HOPS);

    // Without threshold: has Critical findings -> warning would fire
    assert!(findings.iter().any(|f| f.severity == Severity::Critical));

    // With threshold=Critical: at least one finding survives the filter
    let has_critical = findings.iter().any(|f| f.severity <= Severity::Critical);
    assert!(has_critical, "Critical findings survive critical threshold");

    // With threshold=Info (most permissive): any finding survives
    let has_any = findings.iter().any(|f| f.severity <= Severity::Info);
    assert!(has_any);

    // All findings still present in the rule output regardless of threshold
    assert!(
        !findings.is_empty(),
        "threshold doesn't remove findings from rule output"
    );
}

#[test]
fn threshold_critical_excludes_lower_severities() {
    // v0.7+: see comment on severity_threshold_filters_findings above.
    // This test verifies the display filter excludes findings below the
    // chosen threshold — and that no critical findings exist on a clean
    // workflow, so the v0.7 migration warning would NOT fire here.
    let yaml = std::fs::read_to_string(fixture("clean.yml")).unwrap();
    let graph = parse(&yaml);
    let findings = rules::run_all_rules(&graph, DEFAULT_MAX_HOPS);

    // Clean workflow should have no Critical findings
    assert!(!findings.iter().any(|f| f.severity == Severity::Critical));

    // With threshold=Critical: nothing survives -> no warning would fire
    let exceeds_threshold = findings.iter().any(|f| f.severity <= Severity::Critical);
    assert!(
        !exceeds_threshold,
        "no critical findings -> threshold not exceeded -> no v0.7 warning"
    );
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
    assert_eq!(
        unpinned_after, 0,
        "unpinned action findings should be suppressed"
    );
    assert!(
        result.suppressed_count > 0,
        "should have suppressed findings"
    );

    // Other findings should still be present
    assert!(
        !result.findings.is_empty(),
        "non-matching findings should survive"
    );
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

// ── --exclude flag tests ──────────────────────────────

#[test]
fn glob_match_excludes_matching_paths() {
    use taudit_core::ignore::glob_match;

    // Basic wildcard
    assert!(glob_match("*.yml", "workflow.yml"));
    assert!(!glob_match("*.yml", "workflow.yaml"));
    assert!(glob_match("generated/*.yml", "generated/ci.yml"));
    assert!(!glob_match("generated/*.yml", "src/ci.yml"));

    // Double-star (path traversal)
    assert!(glob_match(".github/**/*.yml", ".github/workflows/ci.yml"));
    assert!(glob_match(
        ".github/**/*.yml",
        ".github/workflows/sub/ci.yml"
    ));
    assert!(!glob_match(".github/**/*.yml", "src/workflows/ci.yml"));
}

#[test]
fn exclude_patterns_filter_resolved_paths() {
    // Simulate the filter applied in cmd_scan over a list of paths
    use std::path::PathBuf;
    use taudit_core::ignore::glob_match;

    let paths = [
        PathBuf::from(".github/workflows/ci.yml"),
        PathBuf::from(".github/workflows/release.yml"),
        PathBuf::from("vendor/workflows/ci.yml"),
    ];

    let exclude = ["vendor/**".to_string()];

    let filtered: Vec<_> = paths
        .iter()
        .filter(|p| {
            let s = p.display().to_string();
            !exclude.iter().any(|pat| glob_match(pat, &s))
        })
        .collect();

    assert_eq!(filtered.len(), 2);
    assert!(filtered
        .iter()
        .all(|p| !p.display().to_string().contains("vendor")));
}

// ── --baseline suppression tests ─────────────────────

#[test]
fn baseline_suppresses_matching_findings() {
    let yaml = std::fs::read_to_string(fixture("over-privileged.yml")).unwrap();
    let graph = parse(&yaml);
    let findings = rules::run_all_rules(&graph, DEFAULT_MAX_HOPS);
    let total = findings.len();
    assert!(total > 0);

    // Build a baseline JSON that contains the first finding
    let first = &findings[0];
    let category_str = serde_json::to_value(first.category)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let message = first.message.clone();

    let baseline_json = serde_json::json!({
        "findings": [
            {
                "category": category_str,
                "message": message
            }
        ]
    });

    // Write to a temp file and reload via load_baseline indirectly by constructing
    // the set manually (same logic as load_baseline)
    let mut baseline_set = std::collections::HashSet::new();
    baseline_set.insert((category_str.clone(), message.clone()));

    // Filter findings using the same logic as apply_baseline
    let (kept, suppressed) = {
        let mut kept = Vec::new();
        let mut sup = 0usize;
        for f in findings.clone() {
            let key = (
                serde_json::to_value(f.category)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default(),
                f.message.clone(),
            );
            if baseline_set.contains(&key) {
                sup += 1;
            } else {
                kept.push(f);
            }
        }
        (kept, sup)
    };

    assert_eq!(
        suppressed, 1,
        "baseline should suppress exactly the matching finding"
    );
    assert_eq!(kept.len(), total - 1);
    // Baseline drop should not affect findings with different messages
    assert!(!kept.iter().any(|f| f.message == message && {
        let k = serde_json::to_value(f.category)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        k == category_str
    }));

    // Suppress unused variable warning
    let _ = baseline_json;
}

#[test]
fn baseline_empty_suppresses_nothing() {
    let yaml = std::fs::read_to_string(fixture("over-privileged.yml")).unwrap();
    let graph = parse(&yaml);
    let findings = rules::run_all_rules(&graph, DEFAULT_MAX_HOPS);
    let total = findings.len();

    let baseline_set: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();

    let (kept, suppressed) = {
        let mut kept = Vec::new();
        let mut sup = 0usize;
        for f in findings {
            let key = (
                serde_json::to_value(f.category)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default(),
                f.message.clone(),
            );
            if baseline_set.contains(&key) {
                sup += 1;
            } else {
                kept.push(f);
            }
        }
        (kept, sup)
    };

    assert_eq!(suppressed, 0);
    assert_eq!(kept.len(), total);
}
