//! Per-rule firing benchmark over the committed public-shape corpus.
//!
//! The sibling `corpus_cli_suite.rs` is a *smoke* pass: it asserts every YAML
//! scans to exit-0 + valid JSON. It deliberately never asserts that any rule
//! actually *fires*. That leaves a fail-OPEN gap: a regression could silently
//! stop a detector from ever flagging anything and the smoke suite would stay
//! green (valid JSON, zero findings is still "valid"). The effectiveness
//! ablation (council level-up 2026-06-12) called this out — the published proof
//! was a single N=1 consumer smoke, never per-rule firing or false-positive
//! posture.
//!
//! This benchmark closes that gap, fail-CLOSED, in three layers:
//!
//!   1. **Known-positive firing.** For each rule in [`KNOWN_POSITIVE`], assert
//!      the rule fires at least once on its pinned positive fixture. If a
//!      detector regresses to silence, this test fails — the rule can no longer
//!      silently rot.
//!
//!   2. **Known-negative silence.** For each rule in [`KNOWN_NEGATIVE_SILENT`],
//!      assert the clean fixture does NOT fire it. This pins false-positive
//!      posture: a rule that starts flagging hardened, SHA-pinned,
//!      least-privilege workflows fails the build.
//!
//!   3. **Coverage floor.** Assert the committed corpus collectively fires at
//!      least the pinned set [`COVERAGE_FLOOR`] of distinct rule ids. Coverage
//!      can grow freely; it cannot silently shrink.
//!
//! A machine-readable benchmark report (per-rule fire histogram + coverage) is
//! emitted to `$TAUDIT_BENCH_REPORT` when set, so a release/CI lane can attach
//! it as evidence. The assertions are the gate; the report is the artifact.
//!
//! Ground truth was captured by running `target/debug/taudit.exe scan` over
//! every fixture under `tests/fixtures/` and recording the distinct `rule_id`
//! set each emits (see the histogram printed on failure). All fixtures are
//! committed, license-clean, synthetic, and SHA-stable — no network, no fetch.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

use common::workspace_root;

fn taudit() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_taudit"));
    c.env("TAUDIT_NO_UPDATE_CHECK", "1");
    c
}

fn fixture(name: &str) -> PathBuf {
    workspace_root().join("tests/fixtures").join(name)
}

/// Run `taudit scan <fixture> --format json` and return the distinct set of
/// `rule_id`s emitted. Panics (fails the test) on any non-zero exit, non-UTF-8
/// stdout, or unparseable JSON — a scan that cannot even run is a benchmark
/// failure, not a silent skip.
fn rule_ids_for_fixture(name: &str) -> BTreeSet<String> {
    let path = fixture(name);
    let p = path.to_string_lossy().to_string();
    let out = taudit()
        .args([
            "scan", &p, "--platform", "auto", "--quiet", "--format", "json", "--no-color",
        ])
        .output()
        .unwrap_or_else(|e| panic!("scan spawn {name}: {e}"));
    assert!(
        out.status.success(),
        "scan failed for benchmark fixture {name} (code {:?})\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let s = std::str::from_utf8(&out.stdout)
        .unwrap_or_else(|e| panic!("scan {name}: stdout not utf-8: {e}"));
    let v: serde_json::Value = serde_json::from_str(s.trim())
        .unwrap_or_else(|e| panic!("scan {name}: invalid JSON: {e}\n---\n{s}\n---"));
    let findings = v
        .get("findings")
        .and_then(|f| f.as_array())
        .unwrap_or_else(|| panic!("scan {name}: report has no findings array"));
    let mut ids = BTreeSet::new();
    for f in findings {
        let id = f
            .get("rule_id")
            .and_then(|x| x.as_str())
            .unwrap_or_else(|| panic!("scan {name}: finding without string rule_id: {f}"));
        assert!(
            !id.is_empty(),
            "scan {name}: finding has empty rule_id (rule_id must be a stable snake_case id)"
        );
        ids.insert(id.to_string());
    }
    ids
}

/// Every committed fixture under `tests/fixtures/`, sorted for determinism.
fn all_fixture_names() -> Vec<String> {
    let dir = workspace_root().join("tests/fixtures");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read fixtures dir {}: {e}", dir.display()))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            matches!(
                p.extension().and_then(|x| x.to_str()),
                Some("yml") | Some("yaml")
            )
        })
        .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(String::from))
        .collect();
    names.sort();
    names
}

/// Per-rule known-positive corpus: `(rule_id, fixture)` — scanning `fixture`
/// MUST fire `rule_id`. Captured from real `taudit scan` runs over the
/// committed fixtures. A rule that stops firing here has regressed to silence.
///
/// One representative positive per rule keeps the benchmark legible; the
/// coverage-floor test below still enforces the full distinct-rule set.
const KNOWN_POSITIVE: &[(&str, &str)] = &[
    ("action_major_version_pin_without_sha", "over-privileged.yml"),
    ("authority_propagation", "over-privileged.yml"),
    ("checkout_self_pr_exposure", "ado-shared-pool.yml"),
    ("cross_workflow_authority_chain", "partial-structural.yml"),
    ("floating_image", "gha-service-containers-and-credentials.yml"),
    (
        "gha_tool_installer_then_shell_helper_authority",
        "algol-authority-confusion-fixture.yml",
    ),
    (
        "gitlab_deploy_job_missing_protected_branch_only",
        "gitlab-generic-artifacts.yml",
    ),
    ("long_lived_credential", "gitlab-creds.yml"),
    ("no_workflow_level_permissions_block", "partial-structural.yml"),
    ("over_privileged_identity", "over-privileged.yml"),
    ("self_hosted_pool_pr_hijack", "ado-shared-pool.yml"),
    ("self_mutating_pipeline", "ado-setvariable.yml"),
    ("setvariable_issecret_false", "ado-setvariable.yml"),
    (
        "shared_self_hosted_pool_no_isolation",
        "ado-shared-pool.yml",
    ),
    (
        "template_extends_unpinned_branch",
        "ado-resources-containers-pipelines.yml",
    ),
    ("trigger_context_mismatch", "ado-shared-pool.yml"),
    ("unpinned_action", "over-privileged.yml"),
    ("untrusted_with_authority", "over-privileged.yml"),
    ("uplift_without_attestation", "over-privileged.yml"),
];

/// Rules that MUST stay silent on the hardened `clean.yml` fixture
/// (SHA-pinned action, `contents: read`, no secrets, no untrusted trigger).
/// This pins false-positive posture: any of these firing on a clean,
/// least-privilege workflow is a regression. `authority_propagation` is
/// intentionally excluded — it is an informational graph-structure finding
/// that legitimately emits even on benign graphs.
const KNOWN_NEGATIVE_SILENT: &[&str] = &[
    "action_major_version_pin_without_sha",
    "checkout_self_pr_exposure",
    "cross_workflow_authority_chain",
    "floating_image",
    "gha_tool_installer_then_shell_helper_authority",
    "gitlab_deploy_job_missing_protected_branch_only",
    "long_lived_credential",
    "no_workflow_level_permissions_block",
    "over_privileged_identity",
    "self_hosted_pool_pr_hijack",
    "self_mutating_pipeline",
    "setvariable_issecret_false",
    "shared_self_hosted_pool_no_isolation",
    "template_extends_unpinned_branch",
    "trigger_context_mismatch",
    "unpinned_action",
    "untrusted_with_authority",
    "uplift_without_attestation",
];

/// The committed corpus must collectively fire at least these distinct rule
/// ids. Captured from the real firing sweep. Coverage may grow; this floor
/// fails closed if it shrinks (a detector silently lost or a fixture dropped).
const COVERAGE_FLOOR: &[&str] = &[
    "action_major_version_pin_without_sha",
    "authority_propagation",
    "checkout_self_pr_exposure",
    "cross_workflow_authority_chain",
    "floating_image",
    "gha_tool_installer_then_shell_helper_authority",
    "gitlab_deploy_job_missing_protected_branch_only",
    "long_lived_credential",
    "no_workflow_level_permissions_block",
    "over_privileged_identity",
    "self_hosted_pool_pr_hijack",
    "self_mutating_pipeline",
    "setvariable_issecret_false",
    "shared_self_hosted_pool_no_isolation",
    "template_extends_unpinned_branch",
    "trigger_context_mismatch",
    "unpinned_action",
    "untrusted_with_authority",
    "uplift_without_attestation",
];

/// Layer 1 — every benchmarked rule fires on its pinned known-positive fixture.
#[test]
fn every_benchmarked_rule_fires_on_known_positive() {
    // Cache scans per fixture so we do not re-spawn the binary per rule.
    let mut cache: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut missing: Vec<String> = Vec::new();
    for (rule, fixture_name) in KNOWN_POSITIVE {
        let ids = cache
            .entry((*fixture_name).to_string())
            .or_insert_with(|| rule_ids_for_fixture(fixture_name));
        if !ids.contains(*rule) {
            missing.push(format!(
                "rule `{rule}` did NOT fire on its known-positive `{fixture_name}` (fired: [{}])",
                ids.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "per-rule firing benchmark FAILED — {} rule(s) regressed to silence:\n  {}",
        missing.len(),
        missing.join("\n  ")
    );
}

/// Layer 2 — none of the exploit rules fire on the hardened clean fixture.
#[test]
fn exploit_rules_stay_silent_on_clean_fixture() {
    let fired = rule_ids_for_fixture("clean.yml");
    let mut false_positives: Vec<String> = Vec::new();
    for rule in KNOWN_NEGATIVE_SILENT {
        if fired.contains(*rule) {
            false_positives.push((*rule).to_string());
        }
    }
    assert!(
        false_positives.is_empty(),
        "false-positive posture REGRESSED — {} exploit rule(s) fired on the hardened clean.yml: [{}]\n\
         clean.yml is SHA-pinned, contents: read, no secrets — none of these should fire.",
        false_positives.len(),
        false_positives.join(", ")
    );
}

/// Layer 3 — the committed corpus collectively fires at least the pinned floor
/// of distinct rule ids. Also emits the full fire histogram as an artifact when
/// `TAUDIT_BENCH_REPORT` points at a writable path.
#[test]
fn corpus_meets_distinct_rule_coverage_floor() {
    // rule_id -> number of fixtures it fired on.
    let mut histogram: BTreeMap<String, u32> = BTreeMap::new();
    // rule_id -> sorted list of fixtures that fired it (for the artifact).
    let mut by_rule_fixtures: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut fixtures_scanned = 0u32;

    for name in all_fixture_names() {
        fixtures_scanned += 1;
        for id in rule_ids_for_fixture(&name) {
            *histogram.entry(id.clone()).or_insert(0) += 1;
            by_rule_fixtures.entry(id).or_default().push(name.clone());
        }
    }

    let distinct: BTreeSet<&str> = histogram.keys().map(|s| s.as_str()).collect();

    // Emit the machine-readable benchmark report if requested. This is the
    // release-evidence artifact; the assertions below are the gate.
    if let Some(dest) = std::env::var_os("TAUDIT_BENCH_REPORT") {
        let report = serde_json::json!({
            "report_kind": "taudit.rule-firing-benchmark",
            "contract": "taudit-rule-firing-benchmark.v1",
            "claim_ceiling": "per-rule-firing-on-committed-corpus",
            "network_mode": "offline",
            "fixtures_scanned": fixtures_scanned,
            "distinct_rules_fired": distinct.len(),
            "coverage_floor": COVERAGE_FLOOR.len(),
            "histogram": histogram,
            "fixtures_by_rule": by_rule_fixtures,
        });
        let pretty = serde_json::to_string_pretty(&report).expect("serialize bench report");
        std::fs::write(&dest, pretty).unwrap_or_else(|e| {
            panic!(
                "write benchmark report to {}: {e}",
                PathBuf::from(&dest).display()
            )
        });
    }

    let mut below_floor: Vec<&str> = COVERAGE_FLOOR
        .iter()
        .copied()
        .filter(|r| !distinct.contains(r))
        .collect();
    below_floor.sort_unstable();

    assert!(
        below_floor.is_empty(),
        "corpus rule-coverage REGRESSED below the pinned floor — {} rule(s) no longer fire on \
         ANY committed fixture: [{}]\n\
         fired this run ({}): [{}]",
        below_floor.len(),
        below_floor.join(", "),
        distinct.len(),
        distinct.iter().copied().collect::<Vec<_>>().join(", "),
    );
}

/// Guard the benchmark tables themselves: every rule named in the
/// known-positive / known-negative / coverage tables must be a real id in the
/// SARIF rule registry (`taudit_report_sarif::all_rules`). This catches typos
/// and stale ids the moment a rule is renamed — the benchmark cannot drift away
/// from the canonical registry and keep passing.
#[test]
fn benchmark_rule_ids_exist_in_registry() {
    let registry: BTreeSet<&str> = taudit_report_sarif::all_rules()
        .iter()
        .map(|r| r.id)
        .collect();
    let mut unknown: BTreeSet<&str> = BTreeSet::new();
    for (rule, _) in KNOWN_POSITIVE {
        if !registry.contains(rule) {
            unknown.insert(rule);
        }
    }
    for rule in KNOWN_NEGATIVE_SILENT {
        if !registry.contains(rule) {
            unknown.insert(rule);
        }
    }
    for rule in COVERAGE_FLOOR {
        if !registry.contains(rule) {
            unknown.insert(rule);
        }
    }
    assert!(
        unknown.is_empty(),
        "benchmark references rule id(s) absent from the SARIF registry (typo or rename?): [{}]",
        unknown.iter().copied().collect::<Vec<_>>().join(", ")
    );
}
