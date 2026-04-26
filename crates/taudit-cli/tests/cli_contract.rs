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
