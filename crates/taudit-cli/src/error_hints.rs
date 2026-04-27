//! Short, actionable hint lines for common CLI failure modes.
//! Keep pointers relative to the repo / install (docs ship in the crate).

/// Policy path for `taudit verify` / `taudit remediate apply --policy`.
pub const VERIFY_POLICY_PATH: &str = "hint: --policy must be an existing YAML file or directory of invariant rules (e.g. .taudit/policy/); see docs/verify.md";

/// Policy path exists but loads zero custom invariants while built-ins are disabled.
pub const VERIFY_EMPTY_POLICY: &str =
    "hint: add invariant YAML under --policy, or pass --include-builtin; see docs/verify.md";

/// User passed a file or directory that does not exist.
pub const PATH_NOT_FOUND: &str =
    "hint: check the path exists, or use `-` to read a pipeline from stdin; see USERGUIDE.md";

/// No `.yml` / `.yaml` under given paths (empty directory, wrong extension, or all excluded).
pub const NO_PIPELINE_FILES: &str = "hint: pass a workflow file, a directory tree containing *.yml or *.yaml, or `-` for stdin; with `--exclude` ensure matches remain";

/// Writing `--output` / `-o` failed.
pub const OUTPUT_FILE: &str =
    "hint: ensure the parent directory exists and is writable; use `-o` with a path you can create";

/// Explicit `--suppressions` path missing.
pub const SUPPRESSIONS_FILE: &str = "hint: use an existing .taudit-suppressions.yml, or omit --suppressions to auto-discover; see docs/suppressions.md";

/// Critical finding waiver without `expires_at`.
pub const CRITICAL_WAIVER_EXPIRY: &str =
    "hint: critical suppressions must include `expires_at` (audit field); see docs/suppressions.md";

/// Explicit `--ignore-file` missing or unreadable.
pub const IGNORE_FILE: &str =
    "hint: --ignore-file must exist and be YAML with an `ignore:` list; see `taudit scan --help`";

/// `--baseline` JSON report.
pub const BASELINE_JSON: &str =
    "hint: use a prior `taudit scan --format json` report, or omit --baseline; see USERGUIDE.md";

/// Graph too dense for BFS.
pub const DENSE_GRAPH: &str =
    "hint: inspect input size; if intentional, pass --force-scan-dense (see `taudit scan --help`)";

/// Custom invariants directory load failed.
pub const INVARIANTS_DIR: &str = "hint: --invariants-dir should contain valid Authority Invariant YAML; see docs/authority-invariants.md";

/// `--job` did not match any file.
pub const JOB_NAME_NOT_FOUND: &str = "hint: list job names with `taudit map` on the same paths, or inspect `taudit graph --format json` for job metadata";

/// Unknown built-in rule id.
pub const EXPLAIN_RULE: &str = "hint: run `taudit explain` (no args) to list all rule ids";

/// `taudit diff` (two files) read/parse.
pub const DIFF_FILES: &str = "hint: `taudit diff <before.yml> <after.yml>` — both must exist and be valid pipeline YAML; see `taudit diff --help`";

/// `--dedupe-against` read error (file exists but unreadable).
pub const DEDUPE_FILE: &str = "hint: use JSONL from a prior `taudit scan --format cloudevents` run; missing file is treated as empty";

/// Remediation: path argument.
pub const REMEDIATE_PATH: &str =
    "hint: pass existing workflow files or directories of *.yml / *.yaml; see docs/remediation.md";

/// Remediation: `--min-confidence` range.
pub const MIN_CONFIDENCE: &str = "hint: pass a value in [0.0, 1.0], e.g. --min-confidence 0.8";

/// Remediation: backup root not writable.
pub const BACKUP_READ_ONLY: &str = "hint: ensure `.taudit/backups` (or your --backup-root) is writable, or pass a different --backup-root";

/// Interactive `prompt_or_value` empty stdin.
pub const PROMPT_EMPTY: &str =
    "hint: pass the value via the corresponding flag for non-interactive use";

/// `taudit remediate rollback --backup-id` format.
pub const ROLLBACK_BACKUP_ID: &str =
    "hint: use `taudit remediate list-backups` to copy a valid backup id (format: YYYYMMDDTHHMMSSZ-<pid>-<suffix>)";

/// No manifest for a rollback id.
pub const ROLLBACK_NOT_FOUND: &str =
    "hint: list backups with `taudit remediate list-backups` (or pass --backup-root)";

/// `apply` refuses when git reports dirty tracked files.
pub const REMEDIATE_UNCOMMITTED: &str =
    "hint: commit or stash changes first, or pass --force to apply over a dirty file";

/// Per-pipeline baseline load failure in scan/verify.
pub const PIPELINE_BASELINE_LOAD: &str = "hint: re-run `taudit baseline init` for this repository if the file is corrupt; see USERGUIDE.md (baseline section)";

/// Could not read a pipeline file in `verify`.
pub const VERIFY_READ_PIPELINE: &str = "hint: each argument must be a readable workflow file or a directory of *.yml / *.yaml; see docs/verify.md";
