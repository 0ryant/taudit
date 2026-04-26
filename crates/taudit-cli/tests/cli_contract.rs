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

// ── --dedupe-against tests ───────────────────────────
//
// These cover the SI-2 "incremental SIEM ingest" path: a CI run scans a
// PR, dedupes against the previous PR's CloudEvents output, and only
// emits NEW findings as events. End-to-end through the binary so the
// flag wiring and JSONL parsing both live in the contract.

#[test]
fn dedupe_against_drops_repeats_keeps_news() {
    use std::io::Write;

    let fixture = workspace_root().join("tests/fixtures/propagation-leaky.yml");
    assert!(fixture.exists());

    // First run: capture all CloudEvents fingerprints from the leaky fixture.
    let first = taudit()
        .arg("scan")
        .arg("--format")
        .arg("cloudevents")
        .arg(&fixture)
        .output()
        .expect("spawn taudit");
    assert_eq!(first.status.code(), Some(0));
    let first_jsonl = String::from_utf8(first.stdout).unwrap();
    let first_count = first_jsonl.lines().filter(|l| !l.is_empty()).count();
    assert!(
        first_count > 0,
        "leaky fixture must produce at least one CloudEvent on its own"
    );

    // Write the prior file to a temp path and re-run with --dedupe-against.
    // Every fingerprint should be in the prior set, so the second run
    // emits zero events.
    let tmp_dir = std::env::temp_dir();
    let prior_path = tmp_dir.join(format!("taudit-dedupe-prior-{}.jsonl", std::process::id()));
    {
        let mut f = std::fs::File::create(&prior_path).unwrap();
        f.write_all(first_jsonl.as_bytes()).unwrap();
    }

    let second = taudit()
        .arg("scan")
        .arg("--format")
        .arg("cloudevents")
        .arg("--dedupe-against")
        .arg(&prior_path)
        .arg(&fixture)
        .output()
        .expect("spawn taudit");
    assert_eq!(second.status.code(), Some(0));
    let second_jsonl = String::from_utf8(second.stdout).unwrap();
    let second_count = second_jsonl.lines().filter(|l| !l.is_empty()).count();
    assert_eq!(
        second_count, 0,
        "every finding's fingerprint was in the prior file; expected zero NEW events, got {second_count}\n\n{second_jsonl}"
    );

    // Now write a prior file with ONLY the first fingerprint. The second
    // run should drop every finding that shares that fingerprint (per-hop
    // collapse is intentional — see docs/finding-fingerprint.md) and emit
    // the rest. So we assert by FINGERPRINT count, not raw event count.
    let only_first_line = first_jsonl.lines().next().unwrap();
    let only_first_fp: String = serde_json::from_str::<serde_json::Value>(only_first_line).unwrap()
        ["tauditfindingfingerprint"]
        .as_str()
        .unwrap()
        .to_string();
    let partial_path = tmp_dir.join(format!(
        "taudit-dedupe-partial-{}.jsonl",
        std::process::id()
    ));
    std::fs::write(&partial_path, format!("{only_first_line}\n")).unwrap();

    let third = taudit()
        .arg("scan")
        .arg("--format")
        .arg("cloudevents")
        .arg("--dedupe-against")
        .arg(&partial_path)
        .arg(&fixture)
        .output()
        .expect("spawn taudit");
    assert_eq!(third.status.code(), Some(0));
    let third_jsonl = String::from_utf8(third.stdout).unwrap();
    let third_fps: std::collections::HashSet<String> = third_jsonl
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["tauditfindingfingerprint"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert!(
        !third_fps.contains(&only_first_fp),
        "the suppressed fingerprint must not appear in third-run output"
    );
    let first_fps: std::collections::HashSet<String> = first_jsonl
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["tauditfindingfingerprint"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    let expected_remaining_fps: std::collections::HashSet<String> = first_fps
        .iter()
        .filter(|fp| **fp != only_first_fp)
        .cloned()
        .collect();
    assert_eq!(
        third_fps, expected_remaining_fps,
        "third-run fingerprints must equal (first-run fingerprints) − {{suppressed}}"
    );

    let _ = std::fs::remove_file(&prior_path);
    let _ = std::fs::remove_file(&partial_path);
}

#[test]
fn dedupe_against_missing_file_is_noop_not_error() {
    // First-time CI runs hit "no prior file yet". The flag must not
    // hard-fail in that case — otherwise the very first scan that
    // adopts dedupe will break the pipeline.
    let fixture = workspace_root().join("tests/fixtures/propagation-leaky.yml");
    let missing = workspace_root().join("tests/fixtures/_does_not_exist.jsonl");
    assert!(
        !missing.exists(),
        "test setup requires the path NOT to exist"
    );

    let output = taudit()
        .arg("scan")
        .arg("--format")
        .arg("cloudevents")
        .arg("--dedupe-against")
        .arg(&missing)
        .arg(&fixture)
        .output()
        .expect("spawn taudit");

    assert_eq!(
        output.status.code(),
        Some(0),
        "missing prior file must be a no-op, not an error; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.lines().any(|l| !l.is_empty()),
        "with no prior file, every finding should pass through"
    );
}

#[test]
fn dedupe_against_empty_file_is_noop() {
    // An empty prior file (no fingerprints) should also pass everything
    // through unchanged.
    let fixture = workspace_root().join("tests/fixtures/propagation-leaky.yml");
    let tmp =
        std::env::temp_dir().join(format!("taudit-dedupe-empty-{}.jsonl", std::process::id()));
    std::fs::write(&tmp, "").unwrap();

    let output = taudit()
        .arg("scan")
        .arg("--format")
        .arg("cloudevents")
        .arg("--dedupe-against")
        .arg(&tmp)
        .arg(&fixture)
        .output()
        .expect("spawn taudit");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.lines().any(|l| !l.is_empty()),
        "empty prior file must not suppress any findings"
    );

    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn dedupe_against_warns_when_used_with_non_cloudevents_format() {
    // The flag has no effect on JSON/SARIF/terminal output. Surface a
    // warning so users don't silently miss the no-op.
    let fixture = workspace_root().join("tests/fixtures/propagation-leaky.yml");
    let tmp = std::env::temp_dir().join(format!("taudit-dedupe-noop-{}.jsonl", std::process::id()));
    std::fs::write(&tmp, "").unwrap();

    let output = taudit()
        .arg("scan")
        .arg("--format")
        .arg("json")
        .arg("--dedupe-against")
        .arg(&tmp)
        .arg(&fixture)
        .output()
        .expect("spawn taudit");

    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--dedupe-against") && stderr.contains("cloudevents"),
        "expected a warning about format mismatch; got stderr:\n{stderr}"
    );

    let _ = std::fs::remove_file(&tmp);
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
