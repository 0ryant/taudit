use crate::error_hints::{
    BACKUP_READ_ONLY, MIN_CONFIDENCE, REMEDIATE_PATH, REMEDIATE_UNCOMMITTED, ROLLBACK_BACKUP_ID,
    ROLLBACK_NOT_FOUND,
};
use crate::stdio_epipe::try_write_stdout;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

const MAX_INPUT_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixSuggestion {
    pub transform_id: String,
    pub title: String,
    pub description: String,
    pub confidence: f32,
    pub risk: RiskClass,
    pub safe_default: bool,
    pub reason_if_skipped: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSuggestion {
    pub path: String,
    pub suggestions: Vec<FixSuggestion>,
}

#[derive(Debug, Clone)]
pub struct SuggestOpts {
    pub paths: Vec<PathBuf>,
    pub format: OutputFormat,
}

#[derive(Debug, Clone)]
pub struct DiffOpts {
    pub paths: Vec<PathBuf>,
    pub format: OutputFormat,
}

#[derive(Debug, Clone)]
pub struct ApplyOpts {
    pub paths: Vec<PathBuf>,
    pub format: OutputFormat,
    pub policy: PathBuf,
    pub allow_risky: bool,
    pub min_confidence: f32,
    pub force: bool,
    pub backup_root: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct RollbackOpts {
    pub backup_id: String,
    pub backup_root: Option<PathBuf>,
    pub force: bool,
}

#[derive(Debug, Clone)]
pub struct ListBackupsOpts {
    pub backup_root: Option<PathBuf>,
    pub format: OutputFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupIndex {
    schema_version: String,
    entries: Vec<BackupIndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupIndexEntry {
    backup_id: String,
    created_at: String,
    pipeline_paths: Vec<String>,
    manifest_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupManifest {
    schema_version: String,
    backup_id: String,
    created_at: String,
    taudit_version: String,
    transform_ids: Vec<String>,
    files: Vec<FileBackupRecord>,
    validation: ValidationRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileBackupRecord {
    path: String,
    pre_apply_hash: String,
    post_apply_hash: String,
    original_snapshot: String,
    rewritten_snapshot: String,
    forward_patch: String,
    reverse_patch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ValidationRecord {
    parse_ok: bool,
    verify_exit_code: i32,
    verify_stdout: String,
    verify_stderr: String,
    restored_on_failure: bool,
}

#[derive(Debug, Clone)]
struct PlannedEdit {
    path: PathBuf,
    before: String,
    after: String,
    suggestions: Vec<FixSuggestion>,
    transform_ids: Vec<String>,
}

#[derive(Debug, Clone)]
struct VerifyRun {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

struct IndexLock {
    path: PathBuf,
}

impl Drop for IndexLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn cmd_suggest(opts: SuggestOpts) -> Result<()> {
    let files = collect_pipeline_files(&opts.paths)?;
    let suggestions = build_suggestions(&files)?;

    match opts.format {
        OutputFormat::Text => {
            if suggestions.is_empty() {
                try_write_stdout(
                    b"taudit remediate suggest: no candidate low-risk remediations found\n",
                )?;
            } else {
                try_write_stdout(
                    format!("taudit remediate suggest: {} file(s)\n", suggestions.len()).as_bytes(),
                )?;
                for file in &suggestions {
                    try_write_stdout(format!("{}\n", file.path).as_bytes())?;
                    for s in &file.suggestions {
                        try_write_stdout(
                            format!(
                                "  - {} [{:?}] conf={:.2}: {}\n",
                                s.transform_id, s.risk, s.confidence, s.title
                            )
                            .as_bytes(),
                        )?;
                    }
                }
            }
        }
        OutputFormat::Json => {
            let out = serde_json::json!({
                "schema_version": "taudit.remediate.suggest.v1",
                "files": suggestions,
            });
            try_write_stdout(format!("{}\n", serde_json::to_string_pretty(&out)?).as_bytes())?;
        }
    }

    std::process::exit(0)
}

pub fn cmd_diff(opts: DiffOpts) -> Result<()> {
    let files = collect_pipeline_files(&opts.paths)?;
    let plan = build_plan(&files)?;

    match opts.format {
        OutputFormat::Text => {
            if plan.is_empty() {
                try_write_stdout(b"taudit remediate diff: no patches to generate\n")?;
            } else {
                for item in &plan {
                    try_write_stdout(format!("diff -- {}\n", item.path.display()).as_bytes())?;
                    try_write_stdout(
                        format!(
                            "{}\n",
                            render_unified_patch(
                                &item.path.display().to_string(),
                                &item.before,
                                &item.after
                            )
                        )
                        .as_bytes(),
                    )?;
                }
            }
        }
        OutputFormat::Json => {
            let files_json: Vec<_> = plan
                .iter()
                .map(|item| {
                    serde_json::json!({
                        "path": item.path.display().to_string(),
                        "transform_ids": item.transform_ids,
                        "patch": render_unified_patch(&item.path.display().to_string(), &item.before, &item.after),
                    })
                })
                .collect();
            let out = serde_json::json!({
                "schema_version": "taudit.remediate.diff.v1",
                "files": files_json,
            });
            try_write_stdout(format!("{}\n", serde_json::to_string_pretty(&out)?).as_bytes())?;
        }
    }

    std::process::exit(0)
}

pub fn cmd_apply(opts: ApplyOpts) -> Result<()> {
    if !(0.0..=1.0).contains(&opts.min_confidence) {
        eprintln!("error: --min-confidence must be between 0.0 and 1.0");
        eprintln!("{MIN_CONFIDENCE}");
        std::process::exit(2);
    }

    let files = collect_pipeline_files(&opts.paths)?;
    let mut plan = build_plan(&files)?;
    if plan.is_empty() {
        eprintln!("note: no eligible remediation patches found");
        std::process::exit(0);
    }

    for item in &mut plan {
        let mut kept = Vec::new();
        for s in &item.suggestions {
            let risky = matches!(s.risk, RiskClass::Medium | RiskClass::High);
            if risky && !opts.allow_risky {
                continue;
            }
            if s.confidence < opts.min_confidence {
                continue;
            }
            kept.push(s.clone());
        }
        item.suggestions = kept;
        item.transform_ids = item
            .suggestions
            .iter()
            .map(|s| s.transform_id.clone())
            .collect();
    }
    plan.retain(|p| !p.suggestions.is_empty());
    if plan.is_empty() {
        eprintln!("note: no remediations passed risk/confidence filters");
        std::process::exit(0);
    }

    if !opts.force {
        ensure_no_uncommitted_edits(&plan)?;
    }

    let backup_root = resolve_backup_root(opts.backup_root);
    let backups_dir = backup_root.join("backups");
    fs::create_dir_all(&backups_dir)
        .with_context(|| format!("failed to create {}", backups_dir.display()))?;

    // Race-safe backup-id commit: candidates are proposed and the
    // binding commit is `fs::create_dir`, which returns `AlreadyExists`
    // atomically if another process won the race. Retries up to
    // `MAX_BACKUP_ID_ATTEMPTS` times to absorb extreme contention.
    let (backup_id, operation_dir) = commit_backup_id(&backups_dir)?;

    let original_dir = operation_dir.join("original");
    let rewritten_dir = operation_dir.join("rewritten");
    let patches_dir = operation_dir.join("patches");
    fs::create_dir_all(&original_dir)?;
    fs::create_dir_all(&rewritten_dir)?;
    fs::create_dir_all(&patches_dir)?;

    let mut records = Vec::new();
    for item in &plan {
        let storage_rel = storage_rel_path(&item.path);
        let original_snapshot_path = original_dir.join(&storage_rel);
        let rewritten_snapshot_path = rewritten_dir.join(&storage_rel);

        write_text(&original_snapshot_path, &item.before)?;
        write_text(&rewritten_snapshot_path, &item.after)?;

        let patch_name = safe_patch_name(&item.path);
        let forward_patch_path = patches_dir.join(format!("{patch_name}.patch"));
        let reverse_patch_path = patches_dir.join(format!("{patch_name}.reverse.patch"));
        let forward_patch =
            render_unified_patch(&item.path.display().to_string(), &item.before, &item.after);
        let reverse_patch =
            render_unified_patch(&item.path.display().to_string(), &item.after, &item.before);

        write_text(&forward_patch_path, &forward_patch)?;
        write_text(&reverse_patch_path, &reverse_patch)?;
        write_text(&item.path, &item.after)?;

        records.push(FileBackupRecord {
            path: item.path.display().to_string(),
            pre_apply_hash: sha256_hex(&item.before),
            post_apply_hash: sha256_hex(&item.after),
            original_snapshot: relative_from(&backup_root, &original_snapshot_path),
            rewritten_snapshot: relative_from(&backup_root, &rewritten_snapshot_path),
            forward_patch: relative_from(&backup_root, &forward_patch_path),
            reverse_patch: relative_from(&backup_root, &reverse_patch_path),
        });
    }

    let parse_ok = plan
        .iter()
        .all(|p| serde_yaml::from_str::<serde_yaml::Value>(&p.after).is_ok());

    let verify = run_verify_subprocess(&opts.policy, &plan)?;
    let validation_ok = parse_ok && verify.exit_code == 0;

    if !validation_ok {
        for item in &plan {
            write_text(&item.path, &item.before)?;
        }

        let manifest = BackupManifest {
            schema_version: "taudit.remediate.backup.v1".to_string(),
            backup_id: backup_id.clone(),
            created_at: now_rfc3339(),
            taudit_version: env!("CARGO_PKG_VERSION").to_string(),
            transform_ids: plan.iter().flat_map(|p| p.transform_ids.clone()).collect(),
            files: records,
            validation: ValidationRecord {
                parse_ok,
                verify_exit_code: verify.exit_code,
                verify_stdout: verify.stdout,
                verify_stderr: verify.stderr,
                restored_on_failure: true,
            },
        };
        save_manifest_and_index(&backup_root, &backup_id, &manifest)?;

        eprintln!(
            "error: remediation validation failed; changes were rolled back (backup_id={backup_id})"
        );
        std::process::exit(1);
    }

    let manifest = BackupManifest {
        schema_version: "taudit.remediate.backup.v1".to_string(),
        backup_id: backup_id.clone(),
        created_at: now_rfc3339(),
        taudit_version: env!("CARGO_PKG_VERSION").to_string(),
        transform_ids: plan.iter().flat_map(|p| p.transform_ids.clone()).collect(),
        files: records,
        validation: ValidationRecord {
            parse_ok,
            verify_exit_code: verify.exit_code,
            verify_stdout: verify.stdout,
            verify_stderr: verify.stderr,
            restored_on_failure: false,
        },
    };
    save_manifest_and_index(&backup_root, &backup_id, &manifest)?;

    match opts.format {
        OutputFormat::Text => {
            try_write_stdout(
                format!(
                    "taudit remediate apply: applied {} file(s), backup_id={}\n",
                    plan.len(),
                    backup_id
                )
                .as_bytes(),
            )?;
        }
        OutputFormat::Json => {
            let out = serde_json::json!({
                "schema_version": "taudit.remediate.apply.v1",
                "backup_id": backup_id,
                "files_changed": plan.iter().map(|p| p.path.display().to_string()).collect::<Vec<_>>(),
            });
            try_write_stdout(format!("{}\n", serde_json::to_string_pretty(&out)?).as_bytes())?;
        }
    }

    std::process::exit(0)
}

/// Restore files from a previous `apply` operation in two passes.
///
/// **Pass 1** reads every file referenced by the manifest and verifies
/// its SHA-256 matches `post_apply_hash`. ALL hashes are checked before
/// any write happens, and ALL mismatches are reported together; the
/// rollback aborts before touching any file unless `--force` is set.
///
/// **Pass 2** writes the original content of each file via the atomic
/// tempfile-rename pattern (see [`write_text`]). Per-file atomicity
/// is guaranteed by POSIX `rename(2)` — a concurrent reader sees either
/// the post-apply content or the fully-restored original, never a
/// partial write.
///
/// **Cross-file atomicity is best-effort.** If pass 2 fails partway
/// through (disk full, permission revoked, etc.), files already
/// restored stay restored, and files not yet visited stay at their
/// post-apply state. There is intentionally no journal — re-running
/// `rollback` on the same backup id is idempotent and will resume.
pub fn cmd_rollback(opts: RollbackOpts) -> Result<()> {
    if !is_valid_backup_id(&opts.backup_id) {
        eprintln!("error: invalid backup_id format (expected YYYYMMDDTHHMMSSZ-<pid>-<suffix>)");
        eprintln!("{ROLLBACK_BACKUP_ID}");
        std::process::exit(2);
    }

    let backup_root = resolve_backup_root(opts.backup_root);
    let manifest_path = backup_root
        .join("backups")
        .join(&opts.backup_id)
        .join("manifest.json");

    if !manifest_path.exists() {
        eprintln!(
            "error: backup id '{}' not found under {}",
            opts.backup_id,
            backup_root.join("backups").display()
        );
        eprintln!("{ROLLBACK_NOT_FOUND}");
        std::process::exit(2);
    }

    let manifest_text = read_text_file_capped(&manifest_path)
        .with_context(|| format!("failed to read {}", manifest_path.display()))?;
    let manifest: BackupManifest = serde_json::from_str(&manifest_text)
        .with_context(|| format!("failed to parse {}", manifest_path.display()))?;

    let workspace_root = env::current_dir().context("failed to resolve current directory")?;
    let workspace_root = fs::canonicalize(&workspace_root)
        .with_context(|| format!("failed to resolve {}", workspace_root.display()))?;
    let operation_dir = manifest_path
        .parent()
        .context("backup manifest path has no parent directory")?;
    let operation_dir = fs::canonicalize(operation_dir)
        .with_context(|| format!("failed to resolve {}", operation_dir.display()))?;

    // Pass 1 — verify every record's hash and accumulate mismatches.
    // Reading files here is fine: reads do not mutate state, so the
    // worst-case outcome of pass 1 is "no changes were made".
    struct ResolvedRecord<'a> {
        record: &'a FileBackupRecord,
        target: PathBuf,
        original: String,
        original_hash: String,
        current_hash: String,
    }
    let mut resolved: Vec<ResolvedRecord<'_>> = Vec::with_capacity(manifest.files.len());
    let mut mismatches: Vec<String> = Vec::new();
    for record in &manifest.files {
        let target = resolve_manifest_target(&record.path, &workspace_root)?;
        let original_path = resolve_manifest_snapshot(
            &backup_root,
            &operation_dir,
            "original",
            &record.original_snapshot,
        )?;
        let original = read_text_file_capped(&original_path)
            .with_context(|| format!("failed to read {}", original_path.display()))?;
        let current = read_text_file_capped(&target)
            .with_context(|| format!("failed to read current file {}", target.display()))?;

        let current_hash = sha256_hex(&current);
        let original_hash = sha256_hex(&original);

        if current_hash != record.post_apply_hash {
            mismatches.push(format!(
                "  {} (expected post-apply {}, found {})",
                record.path, record.post_apply_hash, current_hash
            ));
        }

        resolved.push(ResolvedRecord {
            record,
            target,
            original,
            original_hash,
            current_hash,
        });
    }

    // If any hash mismatched and `--force` is not set, abort BEFORE any
    // write. Print every offending file so the operator can inspect
    // them in one pass instead of fixing-and-rerunning serially.
    if !mismatches.is_empty() && !opts.force {
        eprintln!(
            "error: rollback aborted — {} file(s) have unexpected hashes:",
            mismatches.len()
        );
        for line in &mismatches {
            eprintln!("{line}");
        }
        eprintln!("re-run with --force to override (will restore originals regardless)");
        std::process::exit(2);
    }

    // Pass 2 — write each file via tempfile-rename. Per-file atomic;
    // see this function's doc-comment for the cross-file contract.
    for r in &resolved {
        if r.current_hash == r.original_hash {
            continue;
        }
        write_text(&r.target, &r.original).with_context(|| {
            format!(
                "failed to restore {} from backup {}",
                r.record.path, opts.backup_id
            )
        })?;
    }

    try_write_stdout(
        format!(
            "taudit remediate rollback: restored backup_id={} ({})\n",
            manifest.backup_id, manifest.created_at
        )
        .as_bytes(),
    )?;
    std::process::exit(0)
}

pub fn cmd_list_backups(opts: ListBackupsOpts) -> Result<()> {
    let backup_root = resolve_backup_root(opts.backup_root);
    let index_path = backup_root.join("backups").join("index.json");
    let index = load_backup_index(&index_path)?;

    match opts.format {
        OutputFormat::Text => {
            if index.entries.is_empty() {
                try_write_stdout(b"taudit remediate list-backups: no backups found\n")?;
            } else {
                for entry in &index.entries {
                    try_write_stdout(
                        format!(
                            "{} {} {}\n",
                            entry.backup_id,
                            entry.created_at,
                            entry.pipeline_paths.join(", ")
                        )
                        .as_bytes(),
                    )?;
                }
            }
        }
        OutputFormat::Json => {
            try_write_stdout(format!("{}\n", serde_json::to_string_pretty(&index)?).as_bytes())?;
        }
    }

    std::process::exit(0)
}

fn collect_pipeline_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for p in paths {
        let meta = fs::symlink_metadata(p)
            .with_context(|| format!("failed to read metadata {}", p.display()))?;
        if meta.file_type().is_symlink() {
            anyhow::bail!("refusing to follow symlink {}", p.display());
        }
        if meta.is_dir() {
            collect_yaml_recursively(p, &mut out)?;
        } else if meta.is_file() {
            out.push(p.clone());
        } else {
            return Err(anyhow::anyhow!(
                "path not found: {}\n{REMEDIATE_PATH}",
                p.display()
            ));
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn collect_yaml_recursively(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut visited_dirs = HashSet::new();
    if let Ok(root) = fs::canonicalize(dir) {
        visited_dirs.insert(root);
    }
    collect_yaml_recursively_inner(dir, out, &mut visited_dirs)
}

fn collect_yaml_recursively_inner(
    dir: &Path,
    out: &mut Vec<PathBuf>,
    visited_dirs: &mut HashSet<PathBuf>,
) -> Result<()> {
    let mut entries = fs::read_dir(dir)
        .with_context(|| format!("failed to read directory {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read entry under {}", dir.display()))?;
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to read metadata {}", path.display()))?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            let canonical = fs::canonicalize(&path)
                .with_context(|| format!("failed to resolve directory {}", path.display()))?;
            if visited_dirs.insert(canonical) {
                collect_yaml_recursively_inner(&path, out, visited_dirs)?;
            }
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("yml") || e.eq_ignore_ascii_case("yaml"))
            .unwrap_or(false)
        {
            out.push(path);
        }
    }
    Ok(())
}

fn build_suggestions(files: &[PathBuf]) -> Result<Vec<FileSuggestion>> {
    let mut out = Vec::new();
    for path in files {
        let before = read_text_file_capped(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let suggestions = detect_suggestions(path, &before)?;
        if !suggestions.is_empty() {
            out.push(FileSuggestion {
                path: path.display().to_string(),
                suggestions,
            });
        }
    }
    Ok(out)
}

fn build_plan(files: &[PathBuf]) -> Result<Vec<PlannedEdit>> {
    let mut out = Vec::new();
    for path in files {
        let before = read_text_file_capped(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let suggestions = detect_suggestions(path, &before)?;
        if suggestions.is_empty() {
            continue;
        }

        let mut after = before.clone();
        for s in &suggestions {
            after = apply_transform(&after, &s.transform_id).with_context(|| {
                format!("failed applying {} to {}", s.transform_id, path.display())
            })?;
        }

        if after == before {
            continue;
        }

        let transform_ids = suggestions.iter().map(|s| s.transform_id.clone()).collect();
        out.push(PlannedEdit {
            path: path.clone(),
            before,
            after,
            suggestions,
            transform_ids,
        });
    }
    Ok(out)
}

fn detect_suggestions(path: &Path, content: &str) -> Result<Vec<FixSuggestion>> {
    let mut out = Vec::new();
    let doc: serde_yaml::Value = match serde_yaml::from_str(content) {
        Ok(v) => v,
        Err(_) => return Ok(out),
    };

    let Some(root) = doc.as_mapping() else {
        return Ok(out);
    };

    let has_on = root.contains_key(serde_yaml::Value::String("on".to_string()));
    let has_permissions = root.contains_key(serde_yaml::Value::String("permissions".to_string()));

    if has_on && !has_permissions {
        out.push(FixSuggestion {
            transform_id: "gha_add_workflow_permissions_readonly".to_string(),
            title: "Add workflow-level least-privilege permissions".to_string(),
            description: format!(
                "{} is missing a top-level permissions block; add `permissions: {{ contents: read }}`",
                path.display()
            ),
            confidence: 0.95,
            risk: RiskClass::Low,
            safe_default: true,
            reason_if_skipped: None,
        });
    }

    Ok(out)
}

fn apply_transform(content: &str, transform_id: &str) -> Result<String> {
    match transform_id {
        "gha_add_workflow_permissions_readonly" => Ok(insert_workflow_permissions(content)),
        _ => Err(anyhow::anyhow!("unknown transform id: {transform_id}")),
    }
}

fn insert_workflow_permissions(content: &str) -> String {
    // Keep edit surface small by inserting a top-level block instead of
    // serializing the entire YAML document.
    let insertion = "permissions:\n  contents: read\n\n";
    if let Some(rest) = content.strip_prefix("---\n") {
        return format!("---\n{insertion}{rest}");
    }
    format!("{insertion}{content}")
}

fn render_unified_patch(path: &str, before: &str, after: &str) -> String {
    let before_lines: Vec<&str> = before.lines().collect();
    let after_lines: Vec<&str> = after.lines().collect();

    let mut out = String::new();
    out.push_str(&format!("--- a/{path}\n"));
    out.push_str(&format!("+++ b/{path}\n"));
    let before_n = before_lines.len();
    let after_n = after_lines.len();
    out.push_str(&format!("@@ -1,{before_n} +1,{after_n} @@\n"));

    for line in &before_lines {
        out.push('-');
        out.push_str(line);
        out.push('\n');
    }
    for line in &after_lines {
        out.push('+');
        out.push_str(line);
        out.push('\n');
    }

    out
}

fn ensure_no_uncommitted_edits(plan: &[PlannedEdit]) -> Result<()> {
    if !in_git_repo()? {
        return Ok(());
    }

    for item in plan {
        let output = std::process::Command::new("git")
            .arg("status")
            .arg("--porcelain")
            .arg("--")
            .arg(&item.path)
            .output()
            .with_context(|| "failed to run git status")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "git status failed for {}",
                item.path.display()
            ));
        }

        if !String::from_utf8_lossy(&output.stdout).trim().is_empty() {
            return Err(anyhow::anyhow!(
                "refusing to apply remediation: {} has uncommitted edits (use --force to override)\n{REMEDIATE_UNCOMMITTED}",
                item.path.display()
            ));
        }
    }

    Ok(())
}

fn in_git_repo() -> Result<bool> {
    let output = std::process::Command::new("git")
        .arg("rev-parse")
        .arg("--is-inside-work-tree")
        .output()
        .with_context(|| "failed to run git rev-parse")?;

    if !output.status.success() {
        return Ok(false);
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim() == "true")
}

fn run_verify_subprocess(policy: &Path, plan: &[PlannedEdit]) -> Result<VerifyRun> {
    let exe = std::env::current_exe().with_context(|| "failed to resolve current executable")?;

    let mut cmd = std::process::Command::new(exe);
    cmd.arg("verify").arg("--policy").arg(policy);
    for item in plan {
        cmd.arg(&item.path);
    }

    let out = cmd
        .output()
        .with_context(|| "failed to run taudit verify subprocess")?;

    Ok(VerifyRun {
        exit_code: out.status.code().unwrap_or(2),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

fn resolve_backup_root(override_root: Option<PathBuf>) -> PathBuf {
    override_root.unwrap_or_else(|| PathBuf::from(".taudit"))
}

/// Maximum attempts to commit a unique backup id when racing with other
/// `apply` invocations. Each attempt does an atomic `fs::create_dir`
/// which fails with `AlreadyExists` if the candidate is taken.
const MAX_BACKUP_ID_ATTEMPTS: u32 = 100;

/// Race-safe commit of a fresh backup id. Replaces the old "check
/// `exists()` then create later" TOCTOU dance: the directory creation
/// itself is the atomic commit step. Returns `(backup_id, operation_dir)`.
fn commit_backup_id(backups_dir: &Path) -> Result<(String, PathBuf)> {
    // Verify backup directory is writable before attempting allocation.
    let metadata = std::fs::metadata(backups_dir)
        .with_context(|| format!("failed to check {}", backups_dir.display()))?;
    if metadata.permissions().readonly() {
        return Err(anyhow::anyhow!(
            "backup directory is read-only\n{BACKUP_READ_ONLY}"
        ));
    }

    for _ in 0..MAX_BACKUP_ID_ATTEMPTS {
        let id = candidate_backup_id();
        let dir = backups_dir.join(&id);
        match fs::create_dir(&dir) {
            Ok(()) => return Ok((id, dir)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Another process won the race; try a fresh id.
                continue;
            }
            Err(e) => {
                return Err(anyhow::Error::new(e).context(format!(
                    "failed to create backup operation directory {}",
                    dir.display()
                )));
            }
        }
    }
    Err(anyhow::anyhow!(
        "failed to allocate unique backup id after {} attempts (possible DoS or disk full)",
        MAX_BACKUP_ID_ATTEMPTS
    ))
}

fn candidate_backup_id() -> String {
    format!(
        "{}-{:x}-{}",
        chrono::Utc::now().format("%Y%m%dT%H%M%SZ"),
        std::process::id(),
        rand_suffix()
    )
}

fn rand_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}", nanos & 0xfffff)
}

fn unique_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Persist the per-operation manifest and append a reference to the
/// shared `index.json`. The index update is serialised across
/// concurrent `apply` invocations by holding an exclusive lockfile for
/// the read-modify-write window, and the final `index.json` write goes
/// through [`write_text`].
fn save_manifest_and_index(
    backup_root: &Path,
    backup_id: &str,
    manifest: &BackupManifest,
) -> Result<()> {
    let manifest_path = backup_root
        .join("backups")
        .join(backup_id)
        .join("manifest.json");
    let manifest_json = serde_json::to_string_pretty(manifest).context("serialize manifest")?;
    write_text(&manifest_path, &manifest_json)?;

    let index_path = backup_root.join("backups").join("index.json");
    let _lock = lock_index(&index_path)?;

    // Reload inside the critical section so we observe any update made
    // by a process that held the lock just before us.
    let mut index = load_backup_index(&index_path)?;
    index.entries.push(BackupIndexEntry {
        backup_id: backup_id.to_string(),
        created_at: manifest.created_at.clone(),
        pipeline_paths: manifest.files.iter().map(|f| f.path.clone()).collect(),
        manifest_path: relative_from(backup_root, &manifest_path),
    });
    index
        .entries
        .sort_by(|a, b| b.created_at.cmp(&a.created_at));

    let index_json = serde_json::to_string_pretty(&index).context("serialize index")?;
    write_text(&index_path, &index_json)?;
    Ok(())
}

fn load_backup_index(index_path: &Path) -> Result<BackupIndex> {
    if !index_path.exists() {
        return Ok(BackupIndex {
            schema_version: "taudit.remediate.backup.index.v1".to_string(),
            entries: Vec::new(),
        });
    }

    let txt = read_text_file_capped(index_path)
        .with_context(|| format!("failed reading {}", index_path.display()))?;
    let index: BackupIndex = serde_json::from_str(&txt)
        .with_context(|| format!("failed parsing {}", index_path.display()))?;
    Ok(index)
}

fn write_text(path: &Path, content: &str) -> Result<()> {
    atomic_write(path, content.as_bytes())
        .with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

fn read_text_file_capped(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to read metadata for {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to read symlink {}", path.display());
    }
    if metadata.len() > MAX_INPUT_BYTES {
        anyhow::bail!(
            "input file {} exceeds {} byte limit ({} bytes)",
            path.display(),
            MAX_INPUT_BYTES,
            metadata.len()
        );
    }

    let file =
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut content = String::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_string(&mut content)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if content.len() as u64 > MAX_INPUT_BYTES {
        anyhow::bail!(
            "input file {} exceeds {} byte limit ({} bytes)",
            path.display(),
            MAX_INPUT_BYTES,
            content.len()
        );
    }
    Ok(content)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("file");
    let tmp_path = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        unique_nanos()
    ));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .with_context(|| format!("failed creating temporary file {}", tmp_path.display()))?;
    if let Err(err) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err)
            .with_context(|| format!("failed writing temporary file {}", tmp_path.display()));
    }
    drop(file);

    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err).with_context(|| {
            format!(
                "failed atomically replacing {} with {}",
                path.display(),
                tmp_path.display()
            )
        });
    }
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn resolve_manifest_target(record_path: &str, workspace_root: &Path) -> Result<PathBuf> {
    let raw = Path::new(record_path);
    ensure_no_parent_components(raw, "manifest target path")?;
    let target = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        workspace_root.join(raw)
    };
    let meta = fs::symlink_metadata(&target)
        .with_context(|| format!("failed to read metadata {}", target.display()))?;
    if meta.file_type().is_symlink() {
        anyhow::bail!("refusing to rollback through symlink {}", target.display());
    }
    if !meta.is_file() {
        anyhow::bail!("rollback target is not a file: {}", target.display());
    }
    let canonical = fs::canonicalize(&target)
        .with_context(|| format!("failed to resolve rollback target {}", target.display()))?;
    if !canonical.starts_with(workspace_root) {
        anyhow::bail!(
            "rollback target {} escapes workspace {}",
            canonical.display(),
            workspace_root.display()
        );
    }
    Ok(target)
}

fn resolve_manifest_snapshot(
    backup_root: &Path,
    operation_dir: &Path,
    expected_subdir: &str,
    manifest_path: &str,
) -> Result<PathBuf> {
    let rel = Path::new(manifest_path);
    ensure_safe_relative_manifest_path(rel, "manifest snapshot path")?;
    let path = backup_root.join(rel);
    let canonical =
        fs::canonicalize(&path).with_context(|| format!("failed to resolve {}", path.display()))?;
    let expected_root = operation_dir.join(expected_subdir);
    let expected_root = fs::canonicalize(&expected_root)
        .with_context(|| format!("failed to resolve {}", expected_root.display()))?;
    if !canonical.starts_with(&expected_root) {
        anyhow::bail!(
            "manifest snapshot {} escapes expected backup directory {}",
            canonical.display(),
            expected_root.display()
        );
    }
    Ok(path)
}

fn ensure_safe_relative_manifest_path(path: &Path, label: &str) -> Result<()> {
    if path.is_absolute() {
        anyhow::bail!("{label} must be relative: {}", path.display());
    }
    ensure_no_parent_components(path, label)?;
    if path
        .components()
        .any(|c| matches!(c, Component::Prefix(_) | Component::RootDir))
    {
        anyhow::bail!("{label} contains a root component: {}", path.display());
    }
    Ok(())
}

fn ensure_no_parent_components(path: &Path, label: &str) -> Result<()> {
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        anyhow::bail!("{label} contains '..': {}", path.display());
    }
    Ok(())
}

fn lock_index(index_path: &Path) -> Result<IndexLock> {
    let lock_path = index_path.with_file_name("index.json.lock");
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .with_context(|| {
            format!(
                "failed to acquire backup index lock {}",
                lock_path.display()
            )
        })?;
    Ok(IndexLock { path: lock_path })
}

fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn safe_patch_name(path: &Path) -> String {
    path.display().to_string().replace(['/', '\\'], "__")
}

fn storage_rel_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::from("abs");
    for c in path.components() {
        match c {
            Component::RootDir | Component::Prefix(_) => continue,
            Component::ParentDir => continue, // strip .. to prevent path traversal
            Component::CurDir => continue,    // strip .
            Component::Normal(part) => {
                out.push(part);
            }
        }
    }
    out
}

fn relative_from(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Validate backup_id format to prevent path traversal attacks.
/// Expected format: YYYYMMDDTHHMMSSZ-<pid>-<suffix>
fn is_valid_backup_id(id: &str) -> bool {
    // Backup IDs should only contain alphanumeric chars, dash, and underscore
    // Reject any path traversal sequences
    if id.contains("..") || id.contains('/') || id.contains('\\') {
        return false;
    }
    if id.starts_with('-') || id.ends_with('-') {
        return false;
    }
    if id.is_empty() || id.len() > 128 {
        // reasonable upper bound
        return false;
    }
    // Allow only safe characters
    id.chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_tmp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "taudit-remediate-unit-{}-{nanos}-{label}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create tmp dir");
        dir
    }

    #[test]
    fn insert_permissions_is_deterministic() {
        let src = "name: ci\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n";
        let once = insert_workflow_permissions(src);
        let twice = insert_workflow_permissions(src);
        assert_eq!(once, twice);
        assert!(once.starts_with("permissions:\n  contents: read\n\n"));
    }

    #[test]
    fn render_patch_has_expected_headers() {
        let patch = render_unified_patch(".github/workflows/ci.yml", "a\n", "b\n");
        assert!(patch.contains("--- a/.github/workflows/ci.yml"));
        assert!(patch.contains("+++ b/.github/workflows/ci.yml"));
    }

    #[test]
    fn backup_id_generation_is_unique_enough() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..32 {
            seen.insert(format!(
                "{}-{}",
                chrono::Utc::now().format("%Y%m%dT%H%M%SZ"),
                rand_suffix()
            ));
        }
        assert!(seen.len() > 1);
    }

    #[test]
    fn risk_filter_behavior_default_safe_only() {
        let safe = FixSuggestion {
            transform_id: "safe".into(),
            title: "safe".into(),
            description: "safe".into(),
            confidence: 0.95,
            risk: RiskClass::Low,
            safe_default: true,
            reason_if_skipped: None,
        };
        let risky = FixSuggestion {
            transform_id: "risky".into(),
            title: "risky".into(),
            description: "risky".into(),
            confidence: 0.95,
            risk: RiskClass::High,
            safe_default: false,
            reason_if_skipped: None,
        };

        let kept: Vec<_> = [safe.clone(), risky]
            .into_iter()
            .filter(|s| !matches!(s.risk, RiskClass::Medium | RiskClass::High))
            .collect();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].transform_id, safe.transform_id);
    }

    #[test]
    fn manifest_round_trip_schema_stable() {
        let manifest = BackupManifest {
            schema_version: "taudit.remediate.backup.v1".into(),
            backup_id: "id".into(),
            created_at: "2026-04-26T18:00:00Z".into(),
            taudit_version: "0.9.3".into(),
            transform_ids: vec!["gha_add_workflow_permissions_readonly".into()],
            files: vec![FileBackupRecord {
                path: ".github/workflows/ci.yml".into(),
                pre_apply_hash: "a".into(),
                post_apply_hash: "b".into(),
                original_snapshot: "backups/id/original/.github/workflows/ci.yml".into(),
                rewritten_snapshot: "backups/id/rewritten/.github/workflows/ci.yml".into(),
                forward_patch: "backups/id/patches/ci.patch".into(),
                reverse_patch: "backups/id/patches/ci.reverse.patch".into(),
            }],
            validation: ValidationRecord {
                parse_ok: true,
                verify_exit_code: 0,
                verify_stdout: String::new(),
                verify_stderr: String::new(),
                restored_on_failure: false,
            },
        };

        let json = serde_json::to_string(&manifest).expect("serialize");
        let parsed: BackupManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.schema_version, "taudit.remediate.backup.v1");
        assert_eq!(parsed.transform_ids.len(), 1);
    }

    #[test]
    fn hash_mismatch_detection_works() {
        assert_ne!(sha256_hex("one"), sha256_hex("two"));
    }

    #[test]
    fn capped_read_rejects_oversized_remediation_input() {
        let dir = unique_tmp_dir("oversized");
        let path = dir.join("big.yml");
        std::fs::write(&path, vec![b'a'; (MAX_INPUT_BYTES + 1) as usize]).expect("write big file");

        let err = read_text_file_capped(&path).expect_err("oversized file rejected");
        assert!(
            err.to_string().contains("exceeds"),
            "unexpected error: {err:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn collect_pipeline_files_refuses_explicit_symlink() {
        let dir = unique_tmp_dir("explicit-symlink");
        let real = dir.join("real.yml");
        let link = dir.join("link.yml");
        std::fs::write(&real, "name: ci\n").expect("write real");
        std::os::unix::fs::symlink(&real, &link).expect("create symlink");

        let err = collect_pipeline_files(&[link]).expect_err("explicit symlink refused");
        assert!(
            err.to_string().contains("symlink"),
            "unexpected error: {err:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn collect_pipeline_files_skips_discovered_symlinks() {
        let dir = unique_tmp_dir("discovered-symlink");
        let real = dir.join("real.yml");
        let outside = unique_tmp_dir("outside").join("outside.yml");
        let link = dir.join("link.yml");
        std::fs::write(&real, "name: ci\n").expect("write real");
        std::fs::write(&outside, "name: outside\n").expect("write outside");
        std::os::unix::fs::symlink(&outside, &link).expect("create symlink");

        let files = collect_pipeline_files(std::slice::from_ref(&dir)).expect("collect files");
        assert_eq!(files, vec![real]);
    }

    #[test]
    fn manifest_snapshot_paths_must_stay_under_operation_original_dir() {
        let dir = unique_tmp_dir("snapshot-escape");
        let backup_root = dir.join(".taudit");
        let operation_dir = backup_root.join("backups").join("id");
        let original_dir = operation_dir.join("original");
        let escaped_dir = backup_root.join("backups").join("other").join("original");
        std::fs::create_dir_all(&original_dir).expect("create original");
        std::fs::create_dir_all(&escaped_dir).expect("create escaped");
        std::fs::write(escaped_dir.join("ci.yml"), "payload").expect("write escaped");

        let operation_dir = std::fs::canonicalize(operation_dir).expect("canonical op");
        let err = resolve_manifest_snapshot(
            &backup_root,
            &operation_dir,
            "original",
            "backups/other/original/ci.yml",
        )
        .expect_err("snapshot from another backup id rejected");
        assert!(
            err.to_string()
                .contains("escapes expected backup directory"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn manifest_target_paths_must_stay_under_workspace() {
        let workspace = unique_tmp_dir("workspace");
        let outside = unique_tmp_dir("outside-target").join("ci.yml");
        std::fs::write(&outside, "name: ci\n").expect("write outside");
        let workspace = std::fs::canonicalize(workspace).expect("canonical workspace");

        let err = resolve_manifest_target(outside.to_str().expect("utf8 path"), &workspace)
            .expect_err("outside rollback target rejected");
        assert!(
            err.to_string().contains("escapes workspace"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn reverse_patch_references_swapped_content() {
        let before = "a\nb\n";
        let after = insert_workflow_permissions(before);
        let reverse = render_unified_patch("x.yml", &after, before);
        assert!(reverse.contains("--- a/x.yml"));
        assert!(reverse.contains("+++ b/x.yml"));
    }
}
