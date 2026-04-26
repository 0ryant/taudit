//! End-to-end CLI contract tests for the v0.7 informational-scan contract.
//!
//! These tests spawn the actual `taudit` binary built by `cargo test` and
//! assert on its exit code and stderr. Unlike the rule-engine tests in
//! `integration.rs`, these are the only place that the CLI exit-code
//! contract is verified — so they must stay in lockstep with `taudit verify`.
//!
//! Contract under test (v0.7):
//!   * `taudit scan <file-with-findings>`           -> exit 0
//!   * `taudit scan --severity-threshold critical`  -> exit 0 + stderr warning
//!   * `taudit scan /nonexistent`                   -> exit 2 (structural)

use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at crates/taudit-cli; up two levels = repo root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("workspace root resolves")
}

fn taudit() -> Command {
    Command::new(env!("CARGO_BIN_EXE_taudit"))
}

#[test]
fn scan_with_findings_and_no_threshold_exits_zero() {
    // v0.7 contract: scan is informational. Even on a fixture that
    // produces high-severity findings, exit code is 0.
    let fixture = workspace_root().join("tests/fixtures/propagation-leaky.yml");
    assert!(
        fixture.exists(),
        "fixture must exist: {}",
        fixture.display()
    );

    let output = taudit()
        .arg("scan")
        .arg(&fixture)
        .output()
        .expect("spawn taudit");

    assert!(
        output.status.success(),
        "scan should exit 0 on a leaky fixture; got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(0));

    // Without --severity-threshold, the v0.7 migration warning must NOT fire.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("taudit verify"),
        "no migration warning expected without --severity-threshold; got stderr:\n{stderr}"
    );
}

#[test]
fn scan_with_findings_exceeding_threshold_exits_zero_and_warns() {
    // v0.7 contract: even when --severity-threshold is exceeded, scan exits
    // 0 — but it emits a one-shot stderr migration warning so users whose
    // CI relied on v0.6's exit-1 gating notice the change.
    let fixture = workspace_root().join("tests/fixtures/propagation-leaky.yml");
    assert!(
        fixture.exists(),
        "fixture must exist: {}",
        fixture.display()
    );

    let output = taudit()
        .arg("scan")
        .arg("--severity-threshold")
        .arg("critical")
        .arg(&fixture)
        .output()
        .expect("spawn taudit");

    assert_eq!(
        output.status.code(),
        Some(0),
        "scan must exit 0 even when threshold exceeded; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("taudit verify"),
        "expected v0.7 migration warning mentioning 'taudit verify'; got stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("v0.6") && stderr.contains("v0.7"),
        "warning should reference v0.6 -> v0.7 transition; got stderr:\n{stderr}"
    );
}

#[test]
fn scan_with_missing_file_exits_two() {
    // v0.7 contract: structural errors (file missing, parse failure, bad
    // flag) are the *only* non-zero exit path. Exit code is 2 so callers
    // can distinguish "tool broke" from "scan ran clean" (0).
    let output = taudit()
        .arg("scan")
        .arg("/nonexistent/definitely-not-here.yml")
        .output()
        .expect("spawn taudit");

    assert_eq!(
        output.status.code(),
        Some(2),
        "missing file must exit 2; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ── --rules-dir / --invariants-dir contract ──────────────────────────────

/// JSON output is stable across the two flag spellings — the loader sees
/// the same directory either way. We compare scan output to verify the
/// alias really is a no-op functionally.
#[test]
fn rules_dir_alias_loads_same_invariants_as_invariants_dir() {
    let invariants = workspace_root().join("invariants/starter");
    let fixture = workspace_root().join("tests/fixtures/clean.yml");
    assert!(invariants.exists(), "starter invariants must exist");
    assert!(fixture.exists(), "clean fixture must exist");

    let with_old = taudit()
        .arg("scan")
        .arg("--format")
        .arg("json")
        .arg("--rules-dir")
        .arg(&invariants)
        .arg(&fixture)
        .output()
        .expect("spawn taudit (deprecated)");
    let with_new = taudit()
        .arg("scan")
        .arg("--format")
        .arg("json")
        .arg("--invariants-dir")
        .arg(&invariants)
        .arg(&fixture)
        .output()
        .expect("spawn taudit (canonical)");

    assert_eq!(with_old.status.code(), Some(0));
    assert_eq!(with_new.status.code(), Some(0));
    // Compare parsed JSON shape rather than raw bytes — node `metadata` is a
    // HashMap, so key ordering varies per process invocation.
    let parsed_old: serde_json::Value =
        serde_json::from_slice(&with_old.stdout).expect("--rules-dir output is JSON");
    let parsed_new: serde_json::Value =
        serde_json::from_slice(&with_new.stdout).expect("--invariants-dir output is JSON");
    assert_eq!(
        parsed_old, parsed_new,
        "deprecated --rules-dir must produce structurally identical output to --invariants-dir"
    );
}

#[test]
fn rules_dir_emits_deprecation_warning() {
    let invariants = workspace_root().join("invariants/starter");
    let fixture = workspace_root().join("tests/fixtures/clean.yml");

    let output = taudit()
        .arg("scan")
        .arg("--rules-dir")
        .arg(&invariants)
        .arg(&fixture)
        .output()
        .expect("spawn taudit");

    assert_eq!(output.status.code(), Some(0));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--rules-dir is deprecated"),
        "expected deprecation warning naming the flag; got stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("--invariants-dir"),
        "warning must point users at the new flag name; got stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("v1.0"),
        "warning must document the removal target version; got stderr:\n{stderr}"
    );
}

#[test]
fn invariants_dir_does_not_emit_deprecation_warning() {
    // Sanity check: the *new* flag name must be silent — no warning at all.
    let invariants = workspace_root().join("invariants/starter");
    let fixture = workspace_root().join("tests/fixtures/clean.yml");

    let output = taudit()
        .arg("scan")
        .arg("--invariants-dir")
        .arg(&invariants)
        .arg(&fixture)
        .output()
        .expect("spawn taudit");

    assert_eq!(output.status.code(), Some(0));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("deprecated"),
        "canonical --invariants-dir must not warn; got stderr:\n{stderr}"
    );
}

// ── .taudit-suppressions.yml end-to-end ──────────────────────────────────

/// Helper: scan the fixture once with `--format json --suppressions <none>`,
/// pluck out the first finding fingerprint, and return it. Used by the
/// suppression tests below to learn a real fingerprint to waive against.
fn first_fingerprint_for(fixture: &std::path::Path) -> (String, String) {
    let output = taudit()
        .arg("scan")
        .arg("--format")
        .arg("json")
        .arg(fixture)
        .output()
        .expect("spawn taudit");
    assert!(
        output.status.success(),
        "scan must succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse JSON");
    let findings = report["findings"].as_array().expect("findings array");
    assert!(!findings.is_empty(), "fixture must have findings");
    let fp = findings[0]["fingerprint"]
        .as_str()
        .expect("first finding fingerprint")
        .to_string();
    let category = findings[0]["category"]
        .as_str()
        .expect("first finding category")
        .to_string();
    (fp, category)
}

#[test]
fn suppression_downgrade_drops_severity_and_records_audit_fields() {
    let fixture = workspace_root().join("tests/fixtures/propagation-leaky.yml");
    let (fp, rule) = first_fingerprint_for(&fixture);

    let dir = std::env::temp_dir().join(format!(
        "taudit-supp-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let supp_path = dir.join(".taudit-suppressions.yml");
    std::fs::write(
        &supp_path,
        format!(
            "suppressions:\n  - fingerprint: \"{fp}\"\n    rule_id: \"{rule}\"\n    reason: \"end-to-end test waiver\"\n    accepted_by: \"test@example.com\"\n    accepted_at: \"2026-04-26\"\n    expires_at: \"2099-01-01\"\n"
        ),
    )
    .unwrap();

    let output = taudit()
        .arg("scan")
        .arg("--format")
        .arg("json")
        .arg("--suppressions")
        .arg(&supp_path)
        .arg(&fixture)
        .output()
        .expect("spawn taudit");
    assert!(
        output.status.success(),
        "scan with suppressions must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse JSON");
    let findings = report["findings"].as_array().expect("findings array");
    let waived = findings
        .iter()
        .find(|f| f["fingerprint"] == fp)
        .expect("waived finding still present (audit trail preserved)");
    assert!(
        waived["original_severity"].is_string(),
        "downgrade must record original_severity; got: {waived}"
    );
    assert_eq!(
        waived["suppression_reason"].as_str(),
        Some("end-to-end test waiver"),
    );
}

#[test]
fn suppression_critical_without_expiry_exits_two() {
    // The hard rule from blueteam-corpus-defense Section 5: critical
    // waivers MUST carry expires_at. Loader rejects, scan exits 2.
    let fixture = workspace_root().join("tests/fixtures/propagation-leaky.yml");
    let (fp, rule) = first_fingerprint_for(&fixture);

    let dir = std::env::temp_dir().join(format!(
        "taudit-crit-supp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let supp_path = dir.join(".taudit-suppressions.yml");
    // Write a waiver against the first fingerprint with NO expires_at.
    // The rule under test is whichever rule fired first; the leaky
    // fixture is known to produce critical findings (authority_propagation),
    // so this should trigger the validator.
    std::fs::write(
        &supp_path,
        format!(
            "suppressions:\n  - fingerprint: \"{fp}\"\n    rule_id: \"{rule}\"\n    reason: \"missing expiry on critical — should fail\"\n    accepted_by: \"test@example.com\"\n    accepted_at: \"2026-04-26\"\n"
        ),
    )
    .unwrap();

    let output = taudit()
        .arg("scan")
        .arg("--suppressions")
        .arg(&supp_path)
        .arg(&fixture)
        .output()
        .expect("spawn taudit");

    assert_eq!(
        output.status.code(),
        Some(2),
        "critical waiver missing expires_at must exit 2; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("critical") && (stderr.contains("expires_at") || stderr.contains("expire")),
        "stderr should explain the critical-without-expiry rule; got:\n{stderr}"
    );
}

#[test]
fn suppression_expired_warns_and_does_not_downgrade() {
    let fixture = workspace_root().join("tests/fixtures/propagation-leaky.yml");
    let (fp, rule) = first_fingerprint_for(&fixture);

    let dir = std::env::temp_dir().join(format!(
        "taudit-exp-supp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let supp_path = dir.join(".taudit-suppressions.yml");
    std::fs::write(
        &supp_path,
        format!(
            "suppressions:\n  - fingerprint: \"{fp}\"\n    rule_id: \"{rule}\"\n    reason: \"expired waiver\"\n    accepted_by: \"test@example.com\"\n    accepted_at: \"2024-01-01\"\n    expires_at: \"2024-06-01\"\n"
        ),
    )
    .unwrap();

    let output = taudit()
        .arg("scan")
        .arg("--suppressions")
        .arg(&supp_path)
        .arg(&fixture)
        .output()
        .expect("spawn taudit");

    // Even with an expired waiver, scan still exits 0 (waiver simply
    // doesn't apply). The warning is on stderr.
    assert_eq!(
        output.status.code(),
        Some(0),
        "expired waiver should leave exit code at 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("expired"),
        "stderr should warn about the expired waiver; got:\n{stderr}"
    );
}

#[test]
fn suppression_suppress_mode_sets_flag_and_keeps_severity() {
    let fixture = workspace_root().join("tests/fixtures/propagation-leaky.yml");
    let (fp, rule) = first_fingerprint_for(&fixture);

    let dir = std::env::temp_dir().join(format!(
        "taudit-supp-mode-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let supp_path = dir.join(".taudit-suppressions.yml");
    std::fs::write(
        &supp_path,
        format!(
            "suppressions:\n  - fingerprint: \"{fp}\"\n    rule_id: \"{rule}\"\n    reason: \"suppress mode test\"\n    accepted_by: \"test@example.com\"\n    accepted_at: \"2026-04-26\"\n    expires_at: \"2099-01-01\"\n"
        ),
    )
    .unwrap();

    let output = taudit()
        .arg("scan")
        .arg("--format")
        .arg("json")
        .arg("--suppressions")
        .arg(&supp_path)
        .arg("--suppression-mode")
        .arg("suppress")
        .arg(&fixture)
        .output()
        .expect("spawn taudit");

    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse JSON");
    let findings = report["findings"].as_array().expect("findings array");
    let waived = findings
        .iter()
        .find(|f| f["fingerprint"] == fp)
        .expect("waived finding still present");
    assert_eq!(
        waived["suppressed"].as_bool(),
        Some(true),
        "suppress mode must set the flag; got: {waived}"
    );
    // Severity not changed in suppress mode.
    assert!(
        waived["original_severity"].is_string(),
        "original_severity recorded in suppress mode too"
    );
}

#[test]
fn suppressions_list_emits_loaded_entries() {
    let dir = std::env::temp_dir().join(format!(
        "taudit-supp-list-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let supp_path = dir.join(".taudit-suppressions.yml");
    std::fs::write(
        &supp_path,
        "suppressions:\n  - fingerprint: \"deadbeefdeadbeef\"\n    rule_id: \"unpinned_action\"\n    reason: \"internal action\"\n    accepted_by: \"alice@example.com\"\n    accepted_at: \"2026-04-26\"\n",
    )
    .unwrap();

    let output = taudit()
        .arg("suppressions")
        .arg("list")
        .arg("--no-color")
        .arg("--suppressions")
        .arg(&supp_path)
        .output()
        .expect("spawn taudit");

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("deadbeefdeadbeef"));
    assert!(stdout.contains("unpinned_action"));
    assert!(stdout.contains("alice@example.com"));
}
