//! ADR 0002 Phase 4: `taudit graph --collapse-by` / `--risk-only` (DOT job collapse + stderr notices).

use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("workspace root resolves")
}

fn clean_fixture() -> PathBuf {
    workspace_root().join("tests/fixtures/clean.yml")
}

fn taudit() -> Command {
    Command::new(env!("CARGO_BIN_EXE_taudit"))
}

#[test]
fn graph_collapse_by_job_json_stderr_explains_dot_only() {
    let fixture = clean_fixture();
    let out = taudit()
        .args([
            "graph",
            "--format",
            "json",
            "--platform",
            "github-actions",
            "--collapse-by",
            "job",
            fixture.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("spawn taudit graph");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("job collapse is DOT-only"),
        "expected DOT-only notice, got: {err}"
    );
    assert!(
        !err.contains("not implemented"),
        "JSON export should not claim Phase 4 collapse is unimplemented: {err}"
    );
}

#[test]
fn graph_collapse_by_job_dot_emits_collapsed_clusters_silently() {
    let fixture = clean_fixture();
    let out = taudit()
        .args([
            "graph",
            "--format",
            "dot",
            "--platform",
            "github-actions",
            "--collapse-by",
            "job",
            fixture.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("spawn taudit graph");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.trim().is_empty(),
        "expected no Phase 4 stderr for implemented DOT job collapse, got: {err}"
    );
    let dot = String::from_utf8_lossy(&out.stdout);
    assert!(
        dot.contains("subgraph cluster_job_") && dot.contains("\"jb0\""),
        "expected job cluster + synthetic job node, got: {dot}"
    );
    assert!(
        dot.contains("label=\"job: test\""),
        "expected cluster title from job_name, got: {dot}"
    );
}

#[test]
fn graph_risk_only_emits_notice_and_succeeds() {
    let fixture = clean_fixture();
    let out = taudit()
        .args([
            "graph",
            "--format",
            "json",
            "--platform",
            "github-actions",
            "--risk-only",
            fixture.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("spawn taudit graph");

    assert!(out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--risk-only"), "got: {err}");
}

#[test]
fn graph_collapse_by_trust_zone_notice() {
    let fixture = clean_fixture();
    let out = taudit()
        .args([
            "graph",
            "--format",
            "json",
            "--platform",
            "github-actions",
            "--collapse-by",
            "trust-zone",
            "--risk-only",
            fixture.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("spawn taudit graph");

    assert!(out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--collapse-by=trust-zone") && err.contains("--risk-only"),
        "got: {err}"
    );
}

#[test]
fn graph_unknown_collapse_by_errors() {
    let fixture = clean_fixture();
    let out = taudit()
        .args([
            "graph",
            "--format",
            "json",
            "--collapse-by",
            "nope",
            fixture.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("spawn taudit graph");

    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("collapse") || err.contains("invalid"),
        "expected clap value error, got: {err}"
    );
}
