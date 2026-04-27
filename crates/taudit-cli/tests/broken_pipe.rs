//! Pipelines that close stdout early (EPIPE) must not panic or return failure.
//! Unix-only: relies on `sh` and `head`.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("workspace root resolves")
}

fn taudit_exe() -> &'static str {
    env!("CARGO_BIN_EXE_taudit")
}

fn clean_fixture() -> PathBuf {
    let f = workspace_root().join("tests/fixtures/clean.yml");
    assert!(f.exists(), "fixture missing: {}", f.display());
    f
}

fn sh_pipe_taudit_status(args: &str) -> std::process::ExitStatus {
    let exe = taudit_exe();
    let f = clean_fixture();
    let script = format!(r#""{}" {args} "{}" | head -c 1"#, exe, f.display());
    Command::new("sh")
        .arg("-c")
        .arg(&script)
        .status()
        .expect("spawn sh -c")
}

#[test]
fn map_dot_pipe_exits_zero() {
    assert!(sh_pipe_taudit_status("map --format dot").success());
}

#[test]
fn map_text_pipe_exits_zero() {
    assert!(sh_pipe_taudit_status("map --format text").success());
}

#[test]
fn scan_json_pipe_exits_zero() {
    assert!(sh_pipe_taudit_status("scan --format json").success());
}

#[test]
fn graph_mermaid_pipe_exits_zero() {
    assert!(sh_pipe_taudit_status("graph --format mermaid").success());
}

#[test]
fn version_pipe_exits_zero() {
    let script = format!(r#""{}" --version | head -c 1"#, taudit_exe());
    let st = Command::new("sh")
        .arg("-c")
        .arg(&script)
        .status()
        .expect("spawn sh");
    assert!(st.success());
}
