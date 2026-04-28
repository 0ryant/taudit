//! CLI tests for `--rich-labels` on diagram exports (ADR 0002 Phase 1),
//! `authority_summary` on graph JSON (ADR 0002 Phase 2), and rejection of
//! `--rich-labels` with `--format summary` (ADR 0002 Phase 3).

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

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
fn graph_mermaid_compact_omits_rich_zone_tokens() {
    let fixture = clean_fixture();
    assert!(fixture.exists(), "fixture: {}", fixture.display());

    let out = taudit()
        .args([
            "graph",
            "--format",
            "mermaid",
            "--platform",
            "github-actions",
            fixture.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("spawn taudit graph");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("zone: FirstParty"),
        "default labels must stay compact: {s}"
    );
}

#[test]
fn graph_mermaid_rich_includes_zone_and_permission_hints() {
    let fixture = clean_fixture();
    let out = taudit()
        .args([
            "graph",
            "--format",
            "mermaid",
            "--rich-labels",
            "--platform",
            "github-actions",
            fixture.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("spawn taudit graph");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("zone: FirstParty"),
        "rich mermaid should surface trust zone: {s}"
    );
    assert!(
        s.contains("perm:") || s.contains("scope:"),
        "rich mermaid should surface metadata when present: {s}"
    );
}

#[test]
fn graph_dot_rich_includes_zone_line() {
    let fixture = clean_fixture();
    let out = taudit()
        .args([
            "graph",
            "--format",
            "dot",
            "--rich-labels",
            "--platform",
            "github-actions",
            fixture.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("spawn taudit graph");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("zone: FirstParty") || s.contains("zone: ThirdParty"),
        "rich dot should include a zone: line: {s}"
    );
}

#[test]
fn graph_rich_labels_with_json_errors() {
    let fixture = clean_fixture();
    let out = taudit()
        .args([
            "graph",
            "--format",
            "json",
            "--rich-labels",
            "--platform",
            "github-actions",
            fixture.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("spawn taudit graph");

    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("rich-labels") || err.contains("JSON"),
        "expected validation message, got: {err}"
    );
}

#[test]
fn graph_rich_labels_with_summary_errors() {
    let fixture = clean_fixture();
    let out = taudit()
        .args([
            "graph",
            "--format",
            "summary",
            "--rich-labels",
            "--platform",
            "github-actions",
            fixture.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("spawn taudit graph");

    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("rich-labels"),
        "expected validation message, got: {err}"
    );
}

#[test]
fn map_mermaid_matches_graph_semantics() {
    let fixture = clean_fixture();
    let out = taudit()
        .args([
            "map",
            "--format",
            "mermaid",
            "--rich-labels",
            "--platform",
            "github-actions",
            fixture.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("spawn taudit map");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("flowchart LR"),
        "expected mermaid flowchart: {s}"
    );
    assert!(s.contains("zone: FirstParty"), "rich map mermaid: {s}");
}

#[test]
fn graph_json_has_authority_summary_on_has_access_to_identity() {
    let fixture = clean_fixture();
    let out = taudit()
        .args([
            "graph",
            "--format",
            "json",
            "--platform",
            "github-actions",
            fixture.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("spawn taudit graph");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).expect("graph json");
    let edges = v["graph"]["edges"].as_array().expect("graph.edges");
    let token_edge = edges.iter().find(|e| {
        e["kind"] == "has_access_to"
            && e.get("authority_summary").is_some()
            && e["authority_summary"]["trust_zone"] == "first_party"
    });
    assert!(
        token_edge.is_some(),
        "expected has_access_to identity edge with authority_summary: {edges:?}"
    );
}

#[test]
fn map_rich_labels_with_text_errors() {
    let fixture = clean_fixture();
    let out = taudit()
        .args([
            "map",
            "--format",
            "text",
            "--rich-labels",
            "--platform",
            "github-actions",
            fixture.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("spawn taudit map");

    assert!(!out.status.success());
}
