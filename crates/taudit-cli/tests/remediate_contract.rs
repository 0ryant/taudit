use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn unique_tmp_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "taudit-remediate-contract-{}-{nanos}-{label}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    dir
}

fn taudit_in(dir: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_taudit"));
    cmd.current_dir(dir);
    cmd.args(args);
    cmd.output().expect("spawn taudit")
}

fn write_fixture_workflow(base: &Path) -> PathBuf {
    let wf = base.join("ci.yml");
    std::fs::write(
        &wf,
        "name: ci\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
    )
    .expect("write workflow");
    wf
}

fn write_policy(base: &Path) -> PathBuf {
    let policy = base.join("policy.yml");
    std::fs::write(
        &policy,
        "id: never_match\nname: Never match\ndescription: Test policy\nseverity: high\ncategory: authority_propagation\nmatch:\n  source:\n    metadata:\n      impossible_key: impossible_value\n",
    )
    .expect("write policy");
    policy
}

#[test]
fn suggest_is_read_only() {
    let dir = unique_tmp_dir("suggest-read-only");
    let wf = write_fixture_workflow(&dir);
    let before = std::fs::read_to_string(&wf).expect("read before");

    let out = taudit_in(&dir, &["remediate", "suggest", wf.to_str().expect("path")]);
    assert_eq!(out.status.code(), Some(0));

    let after = std::fs::read_to_string(&wf).expect("read after");
    assert_eq!(before, after, "suggest must not mutate files");
}

#[test]
fn diff_is_read_only() {
    let dir = unique_tmp_dir("diff-read-only");
    let wf = write_fixture_workflow(&dir);
    let before = std::fs::read_to_string(&wf).expect("read before");

    let out = taudit_in(&dir, &["remediate", "diff", wf.to_str().expect("path")]);
    assert_eq!(out.status.code(), Some(0));

    let after = std::fs::read_to_string(&wf).expect("read after");
    assert_eq!(before, after, "diff must not mutate files");
}

#[test]
fn apply_creates_backup_and_writes_index() {
    let dir = unique_tmp_dir("apply-backup");
    let wf = write_fixture_workflow(&dir);
    let policy = write_policy(&dir);

    let out = taudit_in(
        &dir,
        &[
            "remediate",
            "--unstable",
            "apply",
            wf.to_str().expect("path"),
            "--policy",
            policy.to_str().expect("path"),
            "--format",
            "json",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let payload: Value =
        serde_json::from_slice(&out.stdout).expect("parse apply json output for backup id");
    let backup_id = payload
        .get("backup_id")
        .and_then(|v| v.as_str())
        .expect("backup id present");

    let manifest = dir
        .join(".taudit")
        .join("backups")
        .join(backup_id)
        .join("manifest.json");
    assert!(
        manifest.exists(),
        "manifest should exist: {}",
        manifest.display()
    );

    let index = dir.join(".taudit").join("backups").join("index.json");
    assert!(index.exists(), "index should exist: {}", index.display());
}

#[test]
fn apply_validation_failure_auto_restores() {
    let dir = unique_tmp_dir("apply-restore");
    let wf = write_fixture_workflow(&dir);
    let before = std::fs::read_to_string(&wf).expect("read before");

    let out = taudit_in(
        &dir,
        &[
            "remediate",
            "--unstable",
            "apply",
            wf.to_str().expect("path"),
            "--policy",
            "does-not-exist.yml",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected validation failure exit 1; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let after = std::fs::read_to_string(&wf).expect("read after");
    assert_eq!(
        before, after,
        "apply validation failure must restore original content"
    );
}

#[test]
fn rollback_restores_original_content() {
    let dir = unique_tmp_dir("rollback");
    let wf = write_fixture_workflow(&dir);
    let policy = write_policy(&dir);
    let original = std::fs::read_to_string(&wf).expect("read original");

    let apply = taudit_in(
        &dir,
        &[
            "remediate",
            "--unstable",
            "apply",
            wf.to_str().expect("path"),
            "--policy",
            policy.to_str().expect("path"),
            "--format",
            "json",
        ],
    );
    assert_eq!(
        apply.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&apply.stderr)
    );

    let payload: Value = serde_json::from_slice(&apply.stdout).expect("parse apply json");
    let backup_id = payload
        .get("backup_id")
        .and_then(|v| v.as_str())
        .expect("backup id present");

    let rollback = taudit_in(
        &dir,
        &[
            "remediate",
            "--unstable",
            "rollback",
            "--backup-id",
            backup_id,
        ],
    );
    assert_eq!(
        rollback.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&rollback.stderr)
    );

    let restored = std::fs::read_to_string(&wf).expect("read restored");
    assert_eq!(
        restored, original,
        "rollback should restore original content"
    );
}
