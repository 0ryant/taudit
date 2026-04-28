//! `taudit graph --format summary` output validates against
//! `schemas/authority-propagation-summary.v1.json`.

mod common;

use std::process::Command;

use common::{fixture, workspace_root};

fn taudit() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_taudit"));
    c.current_dir(workspace_root());
    c
}

fn propagation_summary_schema() -> serde_json::Value {
    let p = workspace_root().join("schemas/authority-propagation-summary.v1.json");
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    serde_json::from_str(&text).expect("authority-propagation-summary.v1.json must parse")
}

fn graph_summary_json(fixture_name: &str) -> serde_json::Value {
    let path = fixture(fixture_name);
    let out = taudit()
        .args([
            "graph",
            path.to_str().expect("fixture path utf-8"),
            "--platform",
            "auto",
            "--format",
            "summary",
        ])
        .output()
        .unwrap_or_else(|e| panic!("spawn taudit graph --format summary: {e}"));
    assert!(
        out.status.success(),
        "graph --format summary failed for {fixture_name} (code {:?})\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(s.trim())
        .unwrap_or_else(|e| panic!("invalid JSON for {fixture_name}: {e}\n---\n{s}\n---"))
}

#[test]
fn clean_fixture_summary_matches_schema() {
    let schema = propagation_summary_schema();
    let validator =
        jsonschema::validator_for(&schema).expect("authority-propagation-summary schema compiles");
    let v = graph_summary_json("clean.yml");
    let errors: Vec<String> = validator.iter_errors(&v).map(|e| e.to_string()).collect();
    assert!(
        errors.is_empty(),
        "schema errors:\n  {}\nvalue:\n{}",
        errors.join("\n  "),
        serde_json::to_string_pretty(&v).unwrap()
    );
}

#[test]
fn graph_summary_with_job_is_rejected() {
    let path = fixture("clean.yml");
    let out = taudit()
        .args([
            "graph",
            path.to_str().expect("fixture path utf-8"),
            "--platform",
            "github-actions",
            "--format",
            "summary",
            "--job",
            "test",
        ])
        .output()
        .expect("spawn taudit graph summary --job");

    assert!(
        !out.status.success(),
        "expected failure when --job is combined with --format summary"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("summary") && err.contains("job"),
        "expected job/summary error, got: {err}"
    );
}

#[test]
fn propagation_leaky_fixture_summary_matches_schema() {
    let schema = propagation_summary_schema();
    let validator =
        jsonschema::validator_for(&schema).expect("authority-propagation-summary schema compiles");
    let v = graph_summary_json("propagation-leaky.yml");
    let errors: Vec<String> = validator.iter_errors(&v).map(|e| e.to_string()).collect();
    assert!(
        errors.is_empty(),
        "schema errors:\n  {}\nvalue:\n{}",
        errors.join("\n  "),
        serde_json::to_string_pretty(&v).unwrap()
    );
    assert!(
        v["totals"]["boundary_path_count"].as_u64().unwrap_or(0) > 0,
        "fixture should emit at least one boundary path for regression signal"
    );
}
