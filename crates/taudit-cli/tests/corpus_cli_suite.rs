//! Exhaustive CLI smoke: `taudit scan`, `taudit graph` (json + summary), on every committed
//! YAML corpus (fixtures, fuzz seeds, `.github/workflows`). Optional root
//! `corpus/` is included when present (gitignored mirrors — see
//! `docs/corpus-research.md`).

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::workspace_root;

fn taudit() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_taudit"));
    // Deterministic stderr (no background crates.io version nudge).
    c.env("TAUDIT_NO_UPDATE_CHECK", "1");
    c
}

/// Directories (relative to workspace root) scanned recursively for `.yml` / `.yaml`.
///
/// Root `corpus/` (see `docs/corpus-research.md`) is **not** included by default: mirrors
/// may contain invalid or non-GHA upstream YAML. Set `TAUDIT_TEST_LOCAL_CORPUS=1` to
/// include it (expect some files to fail parse / scan — this is a stress pass only).
fn corpus_directory_roots() -> Vec<PathBuf> {
    let root = workspace_root();
    let mut v = vec![
        root.join("tests/fixtures"),
        root.join("crates/taudit-parse-gha/fuzz/corpus"),
        root.join("crates/taudit-parse-ado/fuzz/corpus"),
        root.join("crates/taudit-parse-gitlab/fuzz/corpus"),
        root.join(".github/workflows"),
    ];
    if std::env::var_os("TAUDIT_TEST_LOCAL_CORPUS").is_some() {
        let opt = root.join("corpus");
        if opt.is_dir() {
            v.push(opt);
        }
    }
    v
}

fn is_yaml(p: &Path) -> bool {
    matches!(
        p.extension().and_then(|e| e.to_str()),
        Some("yml") | Some("yaml")
    )
}

fn walk_yaml_files(root: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if !root.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_yaml_files(&path, out)?;
        } else if path.is_file() && is_yaml(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn all_corpus_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    for dir in corpus_directory_roots() {
        walk_yaml_files(&dir, &mut files).unwrap_or_else(|e| {
            panic!("read corpus dir {}: {e}", dir.display());
        });
    }
    files.sort();
    files.dedup();
    assert!(
        !files.is_empty(),
        "expected at least one YAML under tests/fixtures/ or fuzz/corpus/"
    );
    files
}

fn assert_json_object(stdout: &[u8], ctx: &str) -> serde_json::Value {
    let s = std::str::from_utf8(stdout).unwrap_or_else(|e| {
        panic!("{ctx}: stdout not utf-8: {e}");
    });
    let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap_or_else(|e| {
        panic!("{ctx}: invalid JSON: {e}\n---\n{s}\n---");
    });
    assert!(v.is_object(), "{ctx}: expected JSON object");
    v
}

fn assert_scan_report(v: &serde_json::Value, ctx: &str) {
    assert_eq!(
        v.get("schema_version").and_then(|x| x.as_str()),
        Some("v1"),
        "{ctx}: scan report schema_version"
    );
    assert!(
        v.get("graph").is_some(),
        "{ctx}: scan report must contain graph"
    );
    assert!(
        v.get("findings").is_some(),
        "{ctx}: scan report must contain findings"
    );
}

fn assert_graph_export(v: &serde_json::Value, ctx: &str) {
    assert_eq!(
        v.get("schema_version").and_then(|x| x.as_str()),
        Some("1.0.0"),
        "{ctx}: graph export schema_version"
    );
    assert!(
        v.get("graph").is_some(),
        "{ctx}: graph export must contain graph"
    );
}

fn assert_propagation_summary(v: &serde_json::Value, ctx: &str) {
    assert_eq!(
        v.get("schema_version").and_then(|x| x.as_str()),
        Some("1.0.0"),
        "{ctx}: summary schema_version"
    );
    assert_eq!(
        v.get("method").and_then(|x| x.as_str()),
        Some("bfs_lower_trust_zone_sinks"),
        "{ctx}: summary method"
    );
    let totals = v
        .get("totals")
        .and_then(|t| t.as_object())
        .unwrap_or_else(|| panic!("{ctx}: summary.totals object"));
    assert!(
        totals.contains_key("boundary_path_count"),
        "{ctx}: summary.totals"
    );
}

/// Every YAML under fixtures, fuzz seeds, and CI workflows: `scan` and `graph` exit 0
/// and emit parseable JSON with required keys.
#[test]
fn scan_and_graph_json_all_corpus_files() {
    for path in all_corpus_files() {
        let p = path.to_string_lossy().to_string();
        let label = p.clone();

        let out_scan = taudit()
            .args([
                "scan",
                &p,
                "--platform",
                "auto",
                "--quiet",
                "--format",
                "json",
                "--no-color",
            ])
            .output()
            .unwrap_or_else(|e| panic!("scan spawn {label}: {e}"));
        assert!(
            out_scan.status.success(),
            "scan failed for {label} (code {:?})\nstderr:\n{}",
            out_scan.status.code(),
            String::from_utf8_lossy(&out_scan.stderr)
        );
        let scan_json = assert_json_object(&out_scan.stdout, &format!("scan {label}"));
        assert_scan_report(&scan_json, &format!("scan {label}"));

        let out_graph = taudit()
            .args(["graph", &p, "--platform", "auto", "--format", "json"])
            .output()
            .unwrap_or_else(|e| panic!("graph spawn {label}: {e}"));
        assert!(
            out_graph.status.success(),
            "graph failed for {label} (code {:?})\nstderr:\n{}",
            out_graph.status.code(),
            String::from_utf8_lossy(&out_graph.stderr)
        );
        let graph_json = assert_json_object(&out_graph.stdout, &format!("graph {label}"));
        assert_graph_export(&graph_json, &format!("graph {label}"));

        let out_summary = taudit()
            .args(["graph", &p, "--platform", "auto", "--format", "summary"])
            .output()
            .unwrap_or_else(|e| panic!("graph summary spawn {label}: {e}"));
        assert!(
            out_summary.status.success(),
            "graph --format summary failed for {label} (code {:?})\nstderr:\n{}",
            out_summary.status.code(),
            String::from_utf8_lossy(&out_summary.stderr)
        );
        let sum_json = assert_json_object(&out_summary.stdout, &format!("graph summary {label}"));
        assert_propagation_summary(&sum_json, &format!("graph summary {label}"));
    }
}

/// `taudit diff` on two identical files: exit 0, valid terminal output header.
#[test]
fn diff_identical_fixtures_exits_zero() {
    let root = workspace_root();
    let a = root.join("tests/fixtures/clean.yml");
    let b = a.clone();
    let out = taudit()
        .args([
            "diff",
            a.to_str().expect("path utf-8"),
            b.to_str().expect("path utf-8"),
            "--platform",
            "github-actions",
        ])
        .output()
        .expect("spawn diff");
    assert!(
        out.status.success(),
        "diff identical: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("taudit diff"),
        "expected diff banner: {stdout}"
    );
}

/// `taudit explain` without args lists every rule id (smoke: binary + registry).
#[test]
fn explain_lists_rules_smoke() {
    let out = taudit().arg("explain").output().expect("spawn explain");
    assert!(
        out.status.success(),
        "explain: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("authority_propagation") || stdout.len() > 500);
}

/// One graph diagram format (Mermaid) on a fixture — catches escaping / stdout path.
#[test]
fn graph_mermaid_smoke() {
    let root = workspace_root();
    let p = root.join("tests/fixtures/clean.yml");
    let out = taudit()
        .args([
            "graph",
            p.to_str().expect("path"),
            "--format",
            "mermaid",
            "--platform",
            "github-actions",
        ])
        .output()
        .expect("spawn graph mermaid");
    assert!(
        out.status.success(),
        "graph mermaid: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("flowchart") || s.contains("graph"),
        "mermaid: {s}"
    );
}

/// `completions` subcommand does not panic.
#[test]
fn completions_bash_smoke() {
    let out = taudit()
        .args(["completions", "bash"])
        .output()
        .expect("spawn completions");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("taudit") || stdout.contains("_taudit"));
}
