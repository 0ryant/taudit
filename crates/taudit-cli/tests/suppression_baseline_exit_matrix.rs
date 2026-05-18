//! L5-07 CLI matrix for suppression, baseline, threshold, waiver, and exit
//! semantics. This is black-box coverage: spawn the real `taudit` binary and
//! keep all mutable state in per-test temp directories.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const RULE_ID: &str = "wave7a_untrusted_sink";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root from CARGO_MANIFEST_DIR")
}

fn fixture(name: &str) -> PathBuf {
    workspace_root().join("tests/fixtures").join(name)
}

fn unique_tmp_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "taudit-wave7a-{}-{nanos}-{label}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn taudit(cwd: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_taudit"));
    cmd.current_dir(cwd)
        .env("TAUDIT_NO_UPDATE_CHECK", "1")
        .env("NO_COLOR", "1");
    cmd
}

fn run(mut cmd: Command) -> Output {
    cmd.output().expect("spawn taudit")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn assert_code(output: &Output, expected: i32, label: &str) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "{label}: expected exit {expected}, got {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout(output),
        stderr(output)
    );
}

fn write_policy(dir: &Path, severity: &str) -> PathBuf {
    std::fs::create_dir_all(dir).expect("create policy dir");
    let policy = dir.join(format!("policy-{severity}.yml"));
    std::fs::write(
        &policy,
        format!(
            "id: {RULE_ID}\n\
             name: Wave 7A untrusted sink\n\
             description: CLI matrix fixture policy\n\
             severity: {severity}\n\
             category: authority_propagation\n\
             match:\n\
               sink:\n\
                 trust_zone: untrusted\n"
        ),
    )
    .expect("write policy");
    policy
}

fn scan_json(cwd: &Path, policy_dir: &Path, pipeline: &Path) -> serde_json::Value {
    let output = run({
        let mut cmd = taudit(cwd);
        cmd.arg("scan")
            .arg("--format")
            .arg("json")
            .arg("--platform")
            .arg("github-actions")
            .arg("--invariants-dir")
            .arg(policy_dir)
            .arg(pipeline);
        cmd
    });
    assert_code(&output, 0, "scan json");
    serde_json::from_slice(&output.stdout).expect("scan emits JSON")
}

fn custom_suppression_keys(report: &serde_json::Value) -> Vec<String> {
    let findings = report["findings"].as_array().expect("scan findings array");
    let mut keys: Vec<String> = findings
        .iter()
        .filter(|f| f["rule_id"].as_str() == Some(RULE_ID))
        .map(|f| {
            f["suppression_key"]
                .as_str()
                .expect("custom finding has suppression_key")
                .to_string()
        })
        .collect();
    keys.sort();
    keys.dedup();
    assert!(
        !keys.is_empty(),
        "fixture and policy must produce at least one custom finding: {report:#}"
    );
    keys
}

fn write_suppressions(path: &Path, keys: &[String], expires_at: Option<&str>) {
    let mut body = String::from("suppressions:\n");
    for key in keys {
        body.push_str(&format!(
            "  - suppression_key: \"{key}\"\n    rule_id: \"{RULE_ID}\"\n    reason: \"Wave 7A matrix waiver for exit semantics\"\n    accepted_by: \"wave7a@example.com\"\n    accepted_at: \"2026-05-18\"\n"
        ));
        if let Some(expires_at) = expires_at {
            body.push_str(&format!("    expires_at: \"{expires_at}\"\n"));
        }
    }
    std::fs::write(path, body).expect("write suppressions file");
}

#[test]
fn scan_threshold_and_legacy_baseline_matrix() {
    let tmp = unique_tmp_dir("scan");
    let policy_dir = tmp.join("policy-high");
    write_policy(&policy_dir, "high");
    let pipeline = fixture("propagation-leaky.yml");
    assert!(pipeline.exists(), "fixture exists: {}", pipeline.display());

    let baseline_report = scan_json(&tmp, &policy_dir, &pipeline);
    let legacy_baseline = tmp.join("legacy-baseline.json");
    std::fs::write(
        &legacy_baseline,
        serde_json::to_vec_pretty(&baseline_report).expect("serialize baseline report"),
    )
    .expect("write legacy baseline");

    struct ScanCase<'a> {
        name: &'a str,
        args: Vec<String>,
        expected_code: i32,
        stderr_contains: Option<&'a str>,
        json_findings_len: Option<usize>,
    }

    let cases = vec![
        ScanCase {
            name: "threshold is informational and warns",
            args: vec![
                "scan".into(),
                "--platform".into(),
                "github-actions".into(),
                "--invariants-dir".into(),
                policy_dir.display().to_string(),
                "--severity-threshold".into(),
                "high".into(),
                pipeline.display().to_string(),
            ],
            expected_code: 0,
            stderr_contains: Some("taudit verify"),
            json_findings_len: None,
        },
        ScanCase {
            name: "legacy baseline report filters scan JSON",
            args: vec![
                "scan".into(),
                "--format".into(),
                "json".into(),
                "--platform".into(),
                "github-actions".into(),
                "--invariants-dir".into(),
                policy_dir.display().to_string(),
                "--baseline".into(),
                legacy_baseline.display().to_string(),
                pipeline.display().to_string(),
            ],
            expected_code: 0,
            stderr_contains: None,
            json_findings_len: Some(0),
        },
    ];

    for case in cases {
        let output = run({
            let mut cmd = taudit(&tmp);
            cmd.args(&case.args);
            cmd
        });
        assert_code(&output, case.expected_code, case.name);
        if let Some(needle) = case.stderr_contains {
            let err = stderr(&output);
            assert!(
                err.contains(needle),
                "{}: expected stderr to contain {needle:?}, got:\n{err}",
                case.name
            );
        }
        if let Some(expected_len) = case.json_findings_len {
            let json: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("case emits JSON");
            let len = json["findings"].as_array().expect("findings array").len();
            assert_eq!(len, expected_len, "{}: JSON findings length", case.name);
        }
    }
}

#[test]
fn verify_suppression_threshold_and_waiver_matrix() {
    let tmp = unique_tmp_dir("verify-suppression");
    let pipeline = fixture("propagation-leaky.yml");

    let high_policy_dir = tmp.join("policy-high");
    let high_policy = write_policy(&high_policy_dir, "high");
    let high_keys = custom_suppression_keys(&scan_json(&tmp, &high_policy_dir, &pipeline));
    let high_suppressions = tmp.join("high-suppressions.yml");
    write_suppressions(&high_suppressions, &high_keys, None);

    let critical_policy_dir = tmp.join("policy-critical");
    let critical_policy = write_policy(&critical_policy_dir, "critical");
    let critical_keys = custom_suppression_keys(&scan_json(&tmp, &critical_policy_dir, &pipeline));
    let invalid_critical_suppressions = tmp.join("critical-no-expiry.yml");
    write_suppressions(&invalid_critical_suppressions, &critical_keys, None);

    struct VerifyCase<'a> {
        name: &'a str,
        policy: &'a Path,
        suppressions: Option<&'a Path>,
        suppression_mode: Option<&'a str>,
        threshold: Option<&'a str>,
        expected_code: i32,
        stdout_contains: Option<&'a str>,
        stderr_contains: Option<&'a str>,
    }

    let cases = vec![
        VerifyCase {
            name: "unsuppressed high finding gates verify",
            policy: &high_policy,
            suppressions: None,
            suppression_mode: None,
            threshold: Some("high"),
            expected_code: 1,
            stdout_contains: Some("verify:"),
            stderr_contains: None,
        },
        VerifyCase {
            name: "downgrade waiver falls below high threshold",
            policy: &high_policy,
            suppressions: Some(&high_suppressions),
            suppression_mode: None,
            threshold: Some("high"),
            expected_code: 0,
            stdout_contains: Some("verify: 0 violations"),
            stderr_contains: Some("loaded"),
        },
        VerifyCase {
            name: "tag-only waiver stays gateable at high threshold",
            policy: &high_policy,
            suppressions: Some(&high_suppressions),
            suppression_mode: Some("tag-only"),
            threshold: Some("high"),
            expected_code: 1,
            stdout_contains: Some("verify:"),
            stderr_contains: Some("tag-only is metadata-only"),
        },
        VerifyCase {
            name: "critical waiver without expiry is misconfiguration",
            policy: &critical_policy,
            suppressions: Some(&invalid_critical_suppressions),
            suppression_mode: None,
            threshold: None,
            expected_code: 2,
            stdout_contains: None,
            stderr_contains: Some("critical waivers must expire"),
        },
    ];

    for case in cases {
        let output = run({
            let mut cmd = taudit(&tmp);
            cmd.arg("verify")
                .arg("--policy")
                .arg(case.policy)
                .arg("--platform")
                .arg("github-actions");
            if let Some(threshold) = case.threshold {
                cmd.arg("--severity-threshold").arg(threshold);
            }
            if let Some(path) = case.suppressions {
                cmd.arg("--suppressions").arg(path);
            }
            if let Some(mode) = case.suppression_mode {
                cmd.arg("--suppression-mode").arg(mode);
            }
            cmd.arg(&pipeline);
            cmd
        });
        assert_code(&output, case.expected_code, case.name);
        if let Some(needle) = case.stdout_contains {
            let out = stdout(&output);
            assert!(
                out.contains(needle),
                "{}: expected stdout to contain {needle:?}, got:\n{out}",
                case.name
            );
        }
        if let Some(needle) = case.stderr_contains {
            let err = stderr(&output);
            assert!(
                err.contains(needle),
                "{}: expected stderr to contain {needle:?}, got:\n{err}",
                case.name
            );
        }
    }
}

#[test]
fn per_pipeline_baseline_exit_matrix() {
    let tmp = unique_tmp_dir("baseline");
    let baseline_root = tmp.join("baseline-root");
    std::fs::create_dir_all(&baseline_root).expect("create baseline root");
    let policy_dir = tmp.join("policy-high");
    let policy = write_policy(&policy_dir, "high");
    let pipeline = fixture("propagation-leaky.yml");

    let init = run({
        let mut cmd = taudit(&tmp);
        cmd.arg("baseline")
            .arg("init")
            .arg("--root")
            .arg(&baseline_root)
            .arg("--captured-by")
            .arg("wave7a@example.com")
            .arg("--platform")
            .arg("github-actions")
            .arg("--invariants-dir")
            .arg(&policy_dir)
            .arg(&pipeline);
        cmd
    });
    assert_code(&init, 0, "baseline init");
    assert!(
        stdout(&init).contains("baseline") && stdout(&init).contains("written"),
        "baseline init should report written baseline, got:\n{}",
        stdout(&init)
    );

    struct BaselineCase<'a> {
        name: &'a str,
        args: Vec<String>,
        expected_code: i32,
        stdout_contains: Option<&'a str>,
        stderr_contains: Option<&'a str>,
    }

    let cases = vec![
        BaselineCase {
            name: "verify without baseline root gates",
            args: vec![
                "verify".into(),
                "--policy".into(),
                policy.display().to_string(),
                "--platform".into(),
                "github-actions".into(),
                pipeline.display().to_string(),
            ],
            expected_code: 1,
            stdout_contains: Some("verify:"),
            stderr_contains: None,
        },
        BaselineCase {
            name: "verify with baseline suppresses pre-existing finding",
            args: vec![
                "verify".into(),
                "--policy".into(),
                policy.display().to_string(),
                "--platform".into(),
                "github-actions".into(),
                "--baseline-root".into(),
                baseline_root.display().to_string(),
                pipeline.display().to_string(),
            ],
            expected_code: 0,
            stdout_contains: Some("verify: 0 violations"),
            stderr_contains: Some("baseline-aware verify"),
        },
        BaselineCase {
            name: "gate-on-all bypasses baseline suppression",
            args: vec![
                "verify".into(),
                "--policy".into(),
                policy.display().to_string(),
                "--platform".into(),
                "github-actions".into(),
                "--baseline-root".into(),
                baseline_root.display().to_string(),
                "--gate-on-all".into(),
                pipeline.display().to_string(),
            ],
            expected_code: 1,
            stdout_contains: Some("verify:"),
            stderr_contains: None,
        },
        BaselineCase {
            name: "baseline diff reports pre-existing findings",
            args: vec![
                "baseline".into(),
                "diff".into(),
                "--root".into(),
                baseline_root.display().to_string(),
                "--platform".into(),
                "github-actions".into(),
                "--invariants-dir".into(),
                policy_dir.display().to_string(),
                pipeline.display().to_string(),
            ],
            expected_code: 0,
            stdout_contains: Some("0 NEW"),
            stderr_contains: None,
        },
    ];

    for case in cases {
        let output = run({
            let mut cmd = taudit(&tmp);
            cmd.args(&case.args);
            cmd
        });
        assert_code(&output, case.expected_code, case.name);
        if let Some(needle) = case.stdout_contains {
            let out = stdout(&output);
            assert!(
                out.contains(needle),
                "{}: expected stdout to contain {needle:?}, got:\n{out}",
                case.name
            );
        }
        if let Some(needle) = case.stderr_contains {
            let err = stderr(&output);
            assert!(
                err.contains(needle),
                "{}: expected stderr to contain {needle:?}, got:\n{err}",
                case.name
            );
        }
    }
}
