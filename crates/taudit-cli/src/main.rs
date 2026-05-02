use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use taudit_core::finding::{FindingExtras, Severity};
use taudit_core::graph::{AuthorityCompleteness, GapKind, PipelineSource};
use taudit_core::ignore::{glob_match, IgnoreConfig};
use taudit_core::map;
use taudit_core::ports::ReportSink;
use taudit_core::propagation::DEFAULT_MAX_HOPS;
use taudit_core::rules;
use taudit_core::summary;
use taudit_parse_ado::AdoParser;
use taudit_parse_gha::GhaParser;
use taudit_parse_gitlab::GitlabParser;
use taudit_report_json::JsonReportSink;
use taudit_report_sarif::SarifReportSink;
use taudit_report_terminal::TerminalReport;
use taudit_sink_cloudevents::CloudEventsJsonlSink;

mod error_hints;
mod remediate;
pub mod stdio_epipe;

use stdio_epipe::{try_write_stdout, SilenceBrokenPipe};

use error_hints::{
    BASELINE_JSON, CRITICAL_WAIVER_EXPIRY, DEDUPE_FILE, DENSE_GRAPH, DIFF_FILES, EXPLAIN_RULE,
    IGNORE_FILE, INVARIANTS_DIR, JOB_NAME_NOT_FOUND, NO_PIPELINE_FILES, OUTPUT_FILE,
    PATH_NOT_FOUND, PIPELINE_BASELINE_LOAD, PROMPT_EMPTY, SUPPRESSIONS_FILE, VERIFY_EMPTY_POLICY,
    VERIFY_POLICY_PATH, VERIFY_READ_PIPELINE,
};

/// Like `println!` but never panics on a closed stdout pipe (EPIPE).
macro_rules! try_println {
    ($($arg:tt)*) => {{
        let mut s = format!($($arg)*);
        s.push('\n');
        try_write_stdout(s.as_bytes())
    }};
}

#[derive(Parser)]
#[command(
    name = "taudit",
    about = "Pipeline authority scanner — models how authority propagates through CI/CD pipelines",
    long_about = "CI/CD is an untyped authority system. taudit makes it explicit, inspectable, and enforceable.\n\n\
                  The CLI contract, graph schema, and invariant DSL are stable as of v1.0.0.\n\n\
                  Start with `taudit verify --help` for policy enforcement, `taudit graph --help` for exports, \
                  `taudit explain` for built-in rules, or see docs/positioning.md.",
    after_long_help = include_str!("../static/after-long-help.txt"),
    version
)]
enum Cli {
    /// Scan pipeline file(s) for authority findings
    #[command(long_about = "Scan pipeline file(s) for authority findings.\n\n\
                            As of v0.7 `scan` is informational and always exits 0 unless a structural \
                            error occurs — use `taudit verify` to gate CI.\n\n\
                            Partial graphs are annotated with their gap kind:\n  \
                            [expression] — a template or matrix expression hides a value\n  \
                            [structural] — an unresolvable component (composite action, reusable\n                 \
                            workflow, extends, include) breaks the authority chain\n  \
                            [opaque]     — the graph cannot be built at all\n\n\
                            Verbosity and [partial] tags:\n\n  \
                            By default, per-finding [partial] tags are suppressed; the per-file header\n  \
                            and run summary always show completeness. Opaque gaps (total graph failure)\n  \
                            always emit [partial:opaque] inline regardless of verbosity.\n\n  \
                            Use --verbose / -v to show [partial] inline on every finding from a\n  \
                            partial graph.")]
    Scan {
        /// Path to pipeline YAML file(s) or directory.
        /// Use `-` to read from stdin (e.g. `cat ci.yml | taudit scan -`).
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Output format
        #[arg(long, default_value = "terminal")]
        format: OutputFormat,

        /// Maximum propagation depth for BFS analysis
        #[arg(long, default_value_t = DEFAULT_MAX_HOPS)]
        max_hops: usize,

        /// Filter findings shown in output to this severity or higher.
        /// As of v0.7, `scan` is informational and always exits 0 unless a
        /// structural error occurs — use `taudit verify` to gate CI.
        /// When this flag is passed and findings still exceed the threshold,
        /// scan prints a one-time stderr migration warning.
        #[arg(long)]
        severity_threshold: Option<SeverityLevel>,

        /// Path to ignore file (default: .tauditignore in working directory).
        /// File must be YAML with an `ignore:` list. Each entry requires a `category:`
        /// field (snake_case rule id) and accepts optional `path:` (glob) and `reason:` fields.
        /// Example: `ignore:\n  - category: unpinned_action\n    path: "*.yml"\n    reason: "legacy"`
        #[arg(long)]
        ignore_file: Option<PathBuf>,

        /// Disable ANSI color codes in terminal output.
        /// Also honored via the NO_COLOR environment variable (any value disables color).
        /// Color is on by default — CI log viewers (GitHub Actions, Azure DevOps) render ANSI.
        #[arg(long, default_value_t = false)]
        no_color: bool,

        /// Glob pattern(s) to exclude from scanning.
        /// Applied to file paths resolved from the given paths.
        /// Can be specified multiple times, e.g. --exclude '*.generated.yml'
        #[arg(long)]
        exclude: Vec<String>,

        /// Summary-only output: print finding counts per file and a grand
        /// total instead of full per-finding details. Useful in CI logs.
        #[arg(long, default_value_t = false)]
        quiet: bool,

        /// Show [partial] tags inline on every finding (default: header-only).
        /// In default mode, only Opaque gaps emit an inline [partial:opaque] tag.
        /// Use --verbose to always show inline tags (useful for local investigation).
        #[arg(short = 'v', long, default_value_t = false)]
        verbose: bool,

        /// In `--quiet` terminal mode, suppress the per-file line for files
        /// with zero findings. No effect on non-quiet mode or other formats.
        #[arg(long, default_value_t = false)]
        omit_empty: bool,

        /// Collapse multiple findings sharing the same category and root
        /// authority node (first Secret/Identity in `nodes_involved`) into a
        /// single summary finding per file. Useful when a templated pipeline
        /// produces N near-duplicate findings — keeps the highest severity,
        /// the first finding's location, and a count-prefixed message.
        #[arg(long, default_value_t = false)]
        collapse_template_instances: bool,

        /// Path to a JSON report from a prior scan. Findings whose
        /// (category, message) pair appears in the baseline are suppressed.
        /// Use this to surface only new findings since the last known-good scan.
        #[arg(long)]
        baseline: Option<PathBuf>,

        /// Path to a CloudEvents JSONL file from a prior scan. Findings whose
        /// `tauditfindingfingerprint` matches an event in the prior file are
        /// dropped from the emitted output. Useful for incremental SIEM
        /// ingest: scan a PR, dedupe against the previous PR's CloudEvents
        /// stream, only emit NEW findings as events.
        ///
        /// Only takes effect with `--format cloudevents`. Ignored for other
        /// formats (terminal/JSON/SARIF) since those have their own dedup
        /// channels (baseline / SARIF `partialFingerprints` suppressions).
        ///
        /// Missing or empty prior files are treated as "no fingerprints to
        /// dedup against" — the flag becomes a no-op rather than an error,
        /// so first-time CI runs don't fail the pipeline.
        #[arg(long)]
        dedupe_against: Option<PathBuf>,
        /// Override the baseline-aware diff-shaped default and emit every
        /// finding (the v0.9.x absolute behaviour). Has no effect when the
        /// pipeline has no `.taudit/baselines/<hash>.json` entry.
        #[arg(long, default_value_t = false)]
        show_all: bool,

        /// Repository root under which `.taudit/baselines/` lives. Defaults
        /// to the current working directory; baselines are looked up by
        /// SHA-256 of the scanned file's bytes.
        #[arg(long)]
        baseline_root: Option<PathBuf>,

        /// Directory to write telemetry events (JSONL).
        /// Default: $TAUDIT_TELEMETRY_DIR or
        /// $XDG_STATE_HOME/taudit/telemetry or $HOME/.local/state/taudit/telemetry
        #[arg(long)]
        telemetry_dir: Option<PathBuf>,

        /// Directory to write scan receipts (JSON).
        /// Default: $TAUDIT_RECEIPT_DIR or
        /// $XDG_DATA_HOME/taudit/receipts or $HOME/.local/share/taudit/receipts
        #[arg(long)]
        receipt_dir: Option<PathBuf>,

        /// Directory to write taudit logs.
        /// Default: $TAUDIT_LOG_DIR or
        /// $XDG_STATE_HOME/taudit/logs or $HOME/.local/state/taudit/logs
        #[arg(long)]
        log_dir: Option<PathBuf>,

        /// CI/CD platform. Default: auto (detects from YAML content)
        #[arg(long, default_value = "auto")]
        platform: Platform,

        /// Write the report to this file instead of stdout.
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,

        /// Directory containing Authority Invariant YAML files (`*.yml`,
        /// `*.yaml`). Each file defines a single invariant that fires on
        /// propagation paths matching its source/sink/path predicates.
        ///
        /// Accepts the deprecated alias `--rules-dir` for backwards
        /// compatibility (slated for removal in v1.0). Using the alias
        /// emits a one-shot stderr deprecation warning.
        #[arg(long, alias = "rules-dir")]
        invariants_dir: Option<PathBuf>,

        /// Allow `--invariants-dir` to follow symlinks that point OUTSIDE
        /// the directory tree. Off by default — taudit refuses such links to
        /// prevent symlink-traversal escapes when the invariants directory is
        /// shared / writable / extracted from a CI artifact. Turn this on
        /// only when the symlinks are deliberate and the target paths are
        /// trusted.
        #[arg(long, default_value_t = false)]
        invariants_allow_external_symlinks: bool,

        /// Override the dense-graph safety guard. By default `taudit scan`
        /// refuses graphs with more than 50 000 nodes AND an edge-to-node
        /// ratio above 5x — at that scale the BFS propagation engine has
        /// pathological worst-case behaviour and a crafted input can stall
        /// the scan. Pass `--force-scan-dense` only if you've inspected
        /// the input and are willing to accept the wall-clock cost.
        #[arg(long, default_value_t = false)]
        force_scan_dense: bool,
        /// Path to `.taudit-suppressions.yml`. When omitted, taudit looks for
        /// `.taudit-suppressions.yml` in CWD then `.taudit/suppressions.yml`.
        /// See `docs/suppressions.md`.
        #[arg(long)]
        suppressions: Option<PathBuf>,

        /// How to apply matched suppressions. `downgrade` (default) drops
        /// severity by one tier; `suppress` sets `extras.suppressed = true`
        /// and leaves severity unchanged. The full finding always appears.
        #[arg(long, default_value = "downgrade")]
        suppression_mode: SuppressionModeArg,
    },

    /// Show authority map — which steps access which secrets/identities
    Map {
        /// Path to pipeline YAML file(s) or directory
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// CI/CD platform. Default: auto (detects from YAML content)
        #[arg(long, default_value = "auto")]
        platform: Platform,

        /// Disable ANSI color output
        #[arg(long, default_value_t = false)]
        no_color: bool,

        /// Output format: `text` (default) step×authority table, `dot` (same graph
        /// as `taudit graph --format dot`), or `mermaid` (same as `taudit graph --format mermaid`).
        #[arg(long, default_value = "text")]
        format: MapFormat,

        /// Restrict the output to the subgraph reachable from a single job.
        /// Most useful with `--format dot` or `--format mermaid`; for `--format text` the table is
        /// filtered to steps belonging to the named job.
        #[arg(long)]
        job: Option<String>,

        /// Include trust zone and key node metadata in diagram labels (DOT / Mermaid only).
        #[arg(long, default_value_t = false)]
        rich_labels: bool,
    },

    /// Emit the canonical authority graph (JSON, DOT, or Mermaid).
    ///
    /// Unlike `taudit map` (human-readable table), this command emits the full
    /// `AuthorityGraph`: by default as JSON (`schemas/authority-graph.v1.json`)
    /// for downstream tools, or as Graphviz DOT / Mermaid for documentation.
    ///
    /// Formats:
    ///   json (default) — schema-validated; canonical machine interchange.
    ///   dot — Graphviz; pipe to `dot -Tsvg` (install Graphviz separately).
    ///   mermaid — `flowchart LR` text for GitHub/GitLab Markdown (no Graphviz).
    ///   summary — bounded propagation rollup JSON (trust-boundary paths only); see
    ///   `schemas/authority-propagation-summary.v1.json`. Uses `--max-hops` and the
    ///   dense-graph guard like `taudit scan` (`--force-scan-dense` to override).
    ///
    /// Use `--job` with dot/mermaid to restrict to one job's reachable subgraph.
    /// JSON and summary use the full parsed graph (`--job` does not apply). See docs/authority-graph.md.
    ///
    /// **Output:** all formats write to **stdout** only. There is no `-o` /
    /// `--output` flag on `graph` — use shell redirection (`> file.json`).
    /// For file output flags, use `taudit scan` or `taudit verify`.
    Graph {
        /// Path to pipeline YAML file(s) or directory.
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// CI/CD platform. Default: auto (detects from YAML content)
        #[arg(long, default_value = "auto")]
        platform: Platform,

        /// Output format: `json` (default, schema-validated), `dot` (Graphviz DOT),
        /// `mermaid` (GitHub-flavored Markdown `flowchart`), or `summary` (propagation rollup JSON).
        #[arg(long, default_value = "json")]
        format: GraphFormat,

        /// Maximum propagation depth for `--format summary` (same meaning as `taudit scan`).
        #[arg(long, default_value_t = DEFAULT_MAX_HOPS)]
        max_hops: usize,

        /// Override the dense-graph safety guard for `--format summary` (same as `taudit scan`).
        #[arg(long, default_value_t = false)]
        force_scan_dense: bool,

        /// Restrict the output to the subgraph reachable from a single job.
        /// For `--format json` and `--format summary` the graph is unfiltered; the flag only
        /// affects `--format dot` and `--format mermaid` (matching `taudit map --job` semantics).
        #[arg(long)]
        job: Option<String>,

        /// Directory containing custom rule YAML files (`*.yml`, `*.yaml`).
        /// Accepted for symmetry with `taudit scan`; rules do not currently
        /// alter the emitted graph but the flag is reserved for future use.
        #[arg(long)]
        rules_dir: Option<PathBuf>,

        /// Include trust zone and key node metadata in diagram labels (DOT / Mermaid only).
        #[arg(long, default_value_t = false)]
        rich_labels: bool,

        /// Collapse nodes for large-pipeline views: `job` or `trust-zone` (ADR 0002 Phase 4).
        ///
        /// **Not yet implemented.** The flag is accepted and documented for CLI stability;
        /// taudit prints a one-time notice to stderr and emits the same graph as without it.
        #[arg(long, value_name = "DIMENSION")]
        collapse_by: Option<GraphCollapseBy>,

        /// Restrict diagram output to risk-relevant subgraph (ADR 0002 Phase 4).
        ///
        /// **Not yet implemented.** Accepted for forward compatibility; stderr notice only.
        #[arg(long, default_value_t = false)]
        risk_only: bool,
    },

    /// Generate shell completions and print them to stdout.
    /// Source or eval the output in your shell config to enable tab completion.
    ///
    /// Example (bash): eval "$(taudit completions bash)"
    /// Example (zsh):  eval "$(taudit completions zsh)"
    /// Example (fish): taudit completions fish | source
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },

    /// Print taudit product version.
    Version,

    /// Check for a newer taudit release and print upgrade instructions.
    ///
    /// Queries crates.io for the latest published version. Exits 0 whether
    /// or not an upgrade is available. Set TAUDIT_NO_UPDATE_CHECK=1 to
    /// disable the background check that also runs after `scan` and `verify`.
    Update,

    /// Emit a CellOS execution-cell spec that runs taudit scan.
    EmitSpec {
        /// Pipeline path to scan inside the cell (file or directory)
        #[arg(required = true)]
        target: PathBuf,

        /// Execution cell id in the generated spec
        #[arg(long, default_value = "taudit-cellos-scan")]
        id: String,

        /// Cell lifetime in seconds
        #[arg(long, default_value_t = 300)]
        ttl_seconds: u64,

        /// Minimum severity to fail the scan in-cell
        #[arg(long)]
        severity_threshold: Option<SeverityLevel>,

        /// Use summary-only scan output in-cell
        #[arg(long, default_value_t = false)]
        quiet: bool,

        /// Path for writing the generated spec (stdout if omitted)
        #[arg(long)]
        output: Option<PathBuf>,

        /// CI/CD platform. Default: auto (detects from YAML content)
        #[arg(long, default_value = "auto")]
        platform: Platform,
    },

    /// List built-in rule IDs, or print one rule's full description and remediation.
    ///
    /// Examples:
    ///   taudit explain              — tabular list (id, severity, short text).
    ///   taudit explain unpinned_action — long text, tags, link to docs/rules/<id>.md.
    ///
    /// Does not cover custom YAML invariants from `--invariants-dir`; use
    /// `taudit invariants list` for those.
    Explain {
        /// Rule id to explain (e.g. `unpinned_action`). Omit to list all rules.
        rule: Option<String>,

        /// Disable ANSI color codes in output. Also honored via the NO_COLOR env var.
        #[arg(long, default_value_t = false)]
        no_color: bool,
    },

    /// Diff findings between two pipeline versions
    Diff {
        /// Path to the "before" pipeline YAML file
        #[arg(required = true)]
        before: PathBuf,

        /// Path to the "after" pipeline YAML file
        #[arg(required = true)]
        after: PathBuf,

        /// Output format
        #[arg(long, default_value = "terminal")]
        format: DiffOutputFormat,

        /// Maximum propagation depth for BFS analysis
        #[arg(long, default_value_t = DEFAULT_MAX_HOPS)]
        max_hops: usize,

        /// CI/CD platform. Default: auto (detects from YAML content)
        #[arg(long, default_value = "auto")]
        platform: Platform,
    },

    /// Inspect, add, or review per-finding waivers from `.taudit-suppressions.yml`.
    ///
    /// Suppressions waive specific findings by their stable fingerprint. They
    /// preserve the audit trail (operator, reason, expiry) and survive across
    /// re-runs. See `docs/suppressions.md`.
    Suppressions {
        #[command(subcommand)]
        action: SuppressionsAction,

        /// Path to `.taudit-suppressions.yml` (default: `.taudit-suppressions.yml`
        /// in the current directory, then `.taudit/suppressions.yml`).
        #[arg(long, global = true)]
        suppressions: Option<PathBuf>,
    },

    /// Inspect or list authority invariants (built-in and custom).
    ///
    /// Authority invariants are declarative properties that the pipeline
    /// authority graph must satisfy. taudit ships 61 built-in invariants and
    /// loads any custom invariants from `--invariants-dir`.
    Invariants {
        #[command(subcommand)]
        action: InvariantsAction,
    },

    /// Enforce policy invariants — exit non-zero on any violation.
    ///
    /// `verify` is the policy-driven enforcement entrypoint for CI required
    /// checks and merge gates. Unlike `scan` (which always runs the 61
    /// built-in rules), `verify` runs ONLY the user-supplied invariants in
    /// `--policy` unless `--include-builtin` is set.
    ///
    /// Exit codes are deterministic:
    ///   0 — no policy violations
    ///   1 — at least one policy violation
    ///   2 — usage error / file not found / parse error
    #[command(
        long_about = "Enforce policy invariants — exit non-zero on any violation.\n\n\
                            `verify` is the policy-driven enforcement entrypoint for CI required \
                            checks and merge gates. Unlike `scan` (which always runs the 61 built-in \
                            rules), `verify` runs ONLY the user-supplied invariants in `--policy` \
                            unless `--include-builtin` is set.\n\n\
                            Exit codes are deterministic:\n  \
                            0 — no policy violations\n  \
                            1 — at least one policy violation\n  \
                            2 — usage error / file not found / parse error\n\n\
                            Partial graphs are annotated with their gap kind:\n  \
                            [expression] — a template or matrix expression hides a value\n  \
                            [structural] — an unresolvable component (composite action, reusable\n                 \
                            workflow, extends, include) breaks the authority chain\n  \
                            [opaque]     — the graph cannot be built at all"
    )]
    Verify {
        /// Path to pipeline YAML file(s) or directory.
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Policy source. Either a single `.yml`/`.yaml` invariant file or a
        /// directory containing one or more invariant files. Required.
        #[arg(long, required = true)]
        policy: PathBuf,

        /// Output format for violations.
        #[arg(long, default_value = "text")]
        format: VerifyFormat,

        /// CI/CD platform. Default: auto (detects from YAML content)
        #[arg(long, default_value = "auto")]
        platform: Platform,

        /// Maximum propagation depth for BFS analysis.
        #[arg(long, default_value_t = DEFAULT_MAX_HOPS)]
        max_hops: usize,

        /// Also run the 61 built-in rules. Their findings count toward
        /// violations alongside the `--policy` invariants. Default: false
        /// (verify is policy-only).
        #[arg(long, default_value_t = false)]
        include_builtin: bool,

        /// Only count violations at or above this severity. When omitted,
        /// every violation counts regardless of severity.
        #[arg(long)]
        severity_threshold: Option<SeverityLevel>,

        /// Disable ANSI color codes in text output. Also honored via NO_COLOR.
        #[arg(long, default_value_t = false)]
        no_color: bool,

        /// Write the report to this file instead of stdout.
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,

        /// Path to `.taudit-suppressions.yml`. See `docs/suppressions.md`.
        #[arg(long)]
        suppressions: Option<PathBuf>,

        /// How to apply matched suppressions. See `taudit scan --help`.
        #[arg(long, default_value = "downgrade")]
        suppression_mode: SuppressionModeArg,

        /// Force every violation to count toward exit 1, ignoring any
        /// `.taudit/baselines/<hash>.json` entries. Useful for org-wide
        /// enforcement runs that intentionally bypass per-team waivers.
        /// CRITICAL findings without a valid waiver always count toward
        /// exit 1 regardless of this flag.
        #[arg(long, default_value_t = false)]
        gate_on_all: bool,

        /// Strict verify mode. When scanning a directory, read/parse errors
        /// in discovered files are fatal (exit 2) instead of warn-and-skip.
        #[arg(long, default_value_t = false)]
        strict: bool,

        /// Repository root under which `.taudit/baselines/` lives. Defaults
        /// to the current working directory.
        #[arg(long)]
        baseline_root: Option<PathBuf>,

        /// Suppress all findings produced by partial-graph reasoning
        /// (unresolvable variable groups, opaque templates). Enables CI gating
        /// on pipelines that use ADO variable groups without API access.
        #[arg(long, default_value_t = false)]
        ignore_partial: bool,
    },

    /// Manage per-pipeline baselines under `.taudit/baselines/`.
    ///
    /// Baselines snapshot the findings present on a pipeline at adoption time
    /// so subsequent scans diff against them, surfacing only NEW findings.
    /// Pre-existing findings are reported but do not fail `verify` exit-1
    /// — UNLESS they are critical and have not been explicitly waived with
    /// `severity_override: critical` + `reason` + `expires_at` <= 90 days.
    ///
    /// See docs/baselines.md for the full workflow and security guarantees.
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },

    /// Suggest, diff, apply, and roll back conservative pipeline remediations.
    ///
    /// v1 is intentionally conservative: only low-risk, high-confidence
    /// transforms run by default. `apply` writes backups to
    /// `.taudit/backups/<backup-id>/` and auto-restores on validation failure.
    ///
    /// Write-path subcommands (`apply`, `rollback`) require `--unstable` because
    /// the remediation engine is still maturing. Read-only subcommands (`suggest`,
    /// `diff`, `list-backups`) are stable and never require the flag.
    Remediate {
        /// Opt in to write-path operations (`apply`, `rollback`).
        ///
        /// These subcommands modify files on disk and are gated behind this flag
        /// because the remediation engine may change its transform set or backup
        /// schema in a future minor release. Once the engine stabilises the flag
        /// will be removed and the subcommands will become unconditionally stable.
        #[arg(long, global = false, default_value_t = false)]
        unstable: bool,

        #[command(subcommand)]
        action: RemediateAction,
    },
}

#[derive(clap::Subcommand)]
enum RemediateAction {
    /// Show candidate remediations without modifying files.
    Suggest {
        /// Pipeline file(s) or directories to analyze.
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Output format.
        #[arg(long, default_value = "text")]
        format: RemediateFormat,
    },
    /// Show patch previews for candidate remediations without modifying files.
    Diff {
        /// Pipeline file(s) or directories to analyze.
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Output format.
        #[arg(long, default_value = "text")]
        format: RemediateFormat,
    },
    /// Apply low-risk remediations with backup + validation + auto-restore.
    Apply {
        /// Pipeline file(s) or directories to modify.
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Output format.
        #[arg(long, default_value = "text")]
        format: RemediateFormat,

        /// Policy path passed to `taudit verify` after rewrite.
        #[arg(long, required = true)]
        policy: PathBuf,

        /// Allow medium/high-risk transforms (off by default).
        #[arg(long, default_value_t = false)]
        allow_risky: bool,

        /// Minimum confidence required for any transform to run.
        #[arg(long, default_value_t = 0.90)]
        min_confidence: f32,

        /// Override dirty-worktree and hash-mismatch guardrails.
        #[arg(long, default_value_t = false)]
        force: bool,

        /// Override backup root (default: `.taudit`).
        #[arg(long)]
        backup_root: Option<PathBuf>,
    },
    /// Restore files from a prior remediation backup.
    Rollback {
        /// Backup id from `taudit remediate apply` output.
        #[arg(long)]
        backup_id: String,

        /// Override backup root (default: `.taudit`).
        #[arg(long)]
        backup_root: Option<PathBuf>,

        /// Override hash mismatch protection during restore.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// List known remediation backups.
    ListBackups {
        /// Override backup root (default: `.taudit`).
        #[arg(long)]
        backup_root: Option<PathBuf>,

        /// Output format.
        #[arg(long, default_value = "text")]
        format: RemediateFormat,
    },
}

/// CLI surface for `SuppressionMode`. Mirrors the core enum but lives
/// in the CLI crate so we can derive `clap::ValueEnum` without having
/// taudit-core depend on clap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, clap::ValueEnum)]
enum SuppressionModeArg {
    /// Default — drop severity one tier (Critical -> High -> ... -> Info).
    #[default]
    Downgrade,
    /// Set `extras.suppressed = true`; leave severity unchanged.
    Suppress,
}

impl SuppressionModeArg {
    fn to_core(self) -> taudit_core::suppressions::SuppressionMode {
        match self {
            SuppressionModeArg::Downgrade => taudit_core::suppressions::SuppressionMode::Downgrade,
            SuppressionModeArg::Suppress => taudit_core::suppressions::SuppressionMode::Suppress,
        }
    }
}

#[derive(clap::Subcommand)]
enum SuppressionsAction {
    /// Print all loaded suppressions with status (active / expiring-soon /
    /// expired / stale-for-review).
    List {
        /// Disable ANSI color codes. Also honored via the NO_COLOR env var.
        #[arg(long, default_value_t = false)]
        no_color: bool,
    },
    /// Append a new suppression entry. Either pass all fields via flags
    /// (non-interactive, scriptable) or run with no flags to be prompted.
    Add {
        /// 16-char hex fingerprint to waive.
        #[arg(long)]
        fingerprint: Option<String>,
        /// Snake-case rule id (or custom rule id) being waived.
        #[arg(long)]
        rule_id: Option<String>,
        /// Operator-supplied justification.
        #[arg(long)]
        reason: Option<String>,
        /// Identity of the person accepting the risk.
        #[arg(long)]
        accepted_by: Option<String>,
        /// Date the waiver was created (YYYY-MM-DD). Defaults to today.
        #[arg(long)]
        accepted_at: Option<String>,
        /// Optional expiry date (YYYY-MM-DD). Required for critical waivers.
        #[arg(long)]
        expires_at: Option<String>,
    },
    /// List all loaded suppressions sorted by `accepted_at`. Flags any
    /// older than 90 days for human re-review and any with `expires_at`
    /// in the past as expired.
    Review {
        /// Disable ANSI color codes. Also honored via the NO_COLOR env var.
        #[arg(long, default_value_t = false)]
        no_color: bool,
    },
}

#[derive(clap::Subcommand)]
enum BaselineAction {
    /// Snapshot CURRENT findings on the given pipelines into
    /// `.taudit/baselines/<pipeline-content-hash>.json`. One file per
    /// pipeline. Idempotent: re-running on an unchanged pipeline rewrites
    /// the same file with a refreshed `captured_at` timestamp. Exits 0.
    Init {
        /// Pipeline path(s). Files or directories.
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Repository root under which `.taudit/baselines/` is created.
        /// Defaults to the current working directory.
        #[arg(long)]
        root: Option<PathBuf>,

        /// Identity recorded in the baseline's `captured_by` field. Defaults
        /// to `$USER@$HOSTNAME` when both are set, else `$USER`, else
        /// `unknown@local`.
        #[arg(long)]
        captured_by: Option<String>,

        /// CI/CD platform. Default: auto (detects from YAML content).
        #[arg(long, default_value = "auto")]
        platform: Platform,

        /// Maximum propagation depth for BFS analysis.
        #[arg(long, default_value_t = DEFAULT_MAX_HOPS)]
        max_hops: usize,

        /// Directory containing Authority Invariant YAML files (`*.yml`,
        /// `*.yaml`). Same semantics as `taudit scan --invariants-dir`.
        #[arg(long)]
        invariants_dir: Option<PathBuf>,
    },

    /// Append a single finding to a baseline as a waiver. Requires a
    /// `--reason` (>=10 chars) of justification. To waive a critical
    /// finding, also pass `--severity-override critical` and
    /// `--expires-at <ISO-8601>` (must be <=90 days away).
    Accept {
        /// Pipeline path the finding belongs to. The baseline file is
        /// resolved by hashing this file's current content.
        #[arg(long)]
        pipeline: PathBuf,

        /// 16-hex finding fingerprint to waive.
        #[arg(long)]
        fingerprint: String,

        /// Snake-case rule id (recorded for human review).
        #[arg(long)]
        rule_id: String,

        /// Severity at the time of acceptance.
        #[arg(long)]
        severity: SeverityLevel,

        /// Free-form justification (>=10 chars). Empty / `wip` / `todo` /
        /// `fix later` strings are rejected.
        #[arg(long)]
        reason: String,

        /// Acknowledge a critical-severity bypass. Required when waiving an
        /// originally-critical finding; otherwise the critical falls
        /// through to exit 1 even with the entry in the baseline.
        #[arg(long)]
        severity_override: Option<SeverityLevel>,

        /// ISO-8601 expiry timestamp. Mandatory when
        /// `--severity-override critical`; must be <=90 days from now.
        #[arg(long)]
        expires_at: Option<String>,

        /// Repository root under which `.taudit/baselines/` lives.
        /// Defaults to the current working directory.
        #[arg(long)]
        root: Option<PathBuf>,
    },

    /// Scan the given pipelines, compare to their baselines, and print a
    /// per-pipeline summary: `<pipeline>: N NEW, M FIXED, K PRE-EXISTING
    /// (W waived, U unwaived)`. Exits 0; use `taudit verify` to gate CI.
    Diff {
        /// Pipeline path(s). Files or directories.
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Repository root under which `.taudit/baselines/` lives.
        /// Defaults to the current working directory.
        #[arg(long)]
        root: Option<PathBuf>,

        /// CI/CD platform. Default: auto (detects from YAML content).
        #[arg(long, default_value = "auto")]
        platform: Platform,

        /// Maximum propagation depth for BFS analysis.
        #[arg(long, default_value_t = DEFAULT_MAX_HOPS)]
        max_hops: usize,

        /// Directory containing Authority Invariant YAML files.
        #[arg(long)]
        invariants_dir: Option<PathBuf>,
    },

    /// List all waivers across every baseline under `.taudit/baselines/`,
    /// sorted by `expires_at` ASC (expiring/expired first). Flags critical
    /// waivers that have no `expires_at` (config error — they are not
    /// protecting anything).
    Review {
        /// Repository root under which `.taudit/baselines/` lives.
        /// Defaults to the current working directory.
        #[arg(long)]
        root: Option<PathBuf>,
    },
}

#[derive(clap::Subcommand)]
enum InvariantsAction {
    /// List every loaded invariant (built-in plus any custom).
    ///
    /// Prints a plain-text table of `id`, `severity`, and `source` (either
    /// `built-in` or the YAML file path). Useful for verifying which
    /// invariants are active in a given configuration.
    List {
        /// Directory containing custom invariant YAML files. Same semantics
        /// as `taudit scan --invariants-dir`. `--rules-dir` is accepted as
        /// an alias for backward compatibility.
        #[arg(long = "invariants-dir", alias = "rules-dir")]
        invariants_dir: Option<PathBuf>,

        /// Disable ANSI color codes. Also honored via the NO_COLOR env var.
        #[arg(long, default_value_t = false)]
        no_color: bool,
    },
}

#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    Terminal,
    Json,
    Sarif,
    Cloudevents,
}

impl OutputFormat {
    fn as_str(&self) -> &'static str {
        match self {
            OutputFormat::Terminal => "terminal",
            OutputFormat::Json => "json",
            OutputFormat::Sarif => "sarif",
            OutputFormat::Cloudevents => "cloudevents",
        }
    }
}

#[derive(Clone, clap::ValueEnum)]
enum DiffOutputFormat {
    Terminal,
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum VerifyFormat {
    /// Human-readable list: `path: invariant_id: message [severity]`
    Text,
    /// Structured JSON: `{schema_version, violations, summary}`
    Json,
    /// SARIF 2.1.0
    Sarif,
}

#[derive(Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
enum MapFormat {
    Text,
    Dot,
    Mermaid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum GraphFormat {
    Json,
    Dot,
    Mermaid,
    Summary,
}

/// Dimension for org-scale collapsed graph views (ADR 0002 Phase 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum GraphCollapseBy {
    /// One synthetic node per job (pipeline step grouping).
    #[value(name = "job")]
    Job,
    /// One synthetic node per trust zone.
    #[value(name = "trust-zone")]
    TrustZone,
}

impl GraphCollapseBy {
    const fn as_cli_value(self) -> &'static str {
        match self {
            GraphCollapseBy::Job => "job",
            GraphCollapseBy::TrustZone => "trust-zone",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum RemediateFormat {
    Text,
    Json,
}

impl RemediateFormat {
    fn to_module(self) -> remediate::OutputFormat {
        match self {
            RemediateFormat::Text => remediate::OutputFormat::Text,
            RemediateFormat::Json => remediate::OutputFormat::Json,
        }
    }
}

#[derive(Clone, clap::ValueEnum, Default, PartialEq, Eq, Debug)]
enum Platform {
    /// Auto-detect platform per file by sniffing top-level YAML keys.
    #[default]
    #[value(name = "auto")]
    Auto,
    #[value(name = "github-actions")]
    GithubActions,
    #[value(name = "azure-devops")]
    AzureDevOps,
    #[value(name = "gitlab")]
    GitLab,
}

impl Platform {
    fn as_str(&self) -> &'static str {
        match self {
            Platform::Auto => "auto",
            Platform::GithubActions => "github-actions",
            Platform::AzureDevOps => "azure-devops",
            Platform::GitLab => "gitlab-ci",
        }
    }

    /// Canonical short token stamped into `graph.metadata["platform"]` and
    /// surfaced as the CloudEvents `tauditplatform` extension attribute.
    /// Returns `None` for the abstract `Auto` variant — callers must always
    /// resolve to a concrete platform first.
    fn metadata_token(&self) -> Option<&'static str> {
        match self {
            Platform::Auto => None,
            Platform::GithubActions => Some("gha"),
            Platform::AzureDevOps => Some("ado"),
            Platform::GitLab => Some("gitlab"),
        }
    }
}

/// Path-based platform hint. Returns `Some(platform)` when the file path
/// strongly indicates a specific CI platform; `None` when the path is
/// uninformative.
///
/// Hints (case-sensitive against forward-slash-normalised path):
/// - `.gitlab-ci.yml`, `*-gitlab-ci.yml`, `gitlab-ci.yml` → GitLab
/// - `azure-pipelines*.yml`, `*.azure-pipelines.yml`, files under
///   `.azuredevops/` or `.pipelines/` → ADO
/// - Files under `.github/workflows/` → GHA
fn platform_from_path(path: &Path) -> Option<Platform> {
    // Normalize separators so the substring checks below work on Windows too.
    let path_str = path.to_string_lossy().replace('\\', "/");
    let lower = path_str.to_ascii_lowercase();

    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    // GitLab — most distinctive name pattern. Match the bare filename so we
    // don't trip on a directory called "gitlab-ci.yml".
    if file_name == ".gitlab-ci.yml"
        || file_name == "gitlab-ci.yml"
        || file_name.ends_with("-gitlab-ci.yml")
        || file_name.ends_with(".gitlab-ci.yml")
    {
        return Some(Platform::GitLab);
    }

    // ADO — `azure-pipelines.yml`, `azure-pipelines-prod.yml`, `release.azure-pipelines.yml`,
    // or any file under `.azuredevops/` / `.pipelines/`.
    if file_name.starts_with("azure-pipelines") && file_name.ends_with(".yml")
        || file_name.ends_with(".azure-pipelines.yml")
        || lower.contains("/.azuredevops/")
        || lower.starts_with(".azuredevops/")
        || lower.contains("/.pipelines/")
        || lower.starts_with(".pipelines/")
    {
        return Some(Platform::AzureDevOps);
    }

    // GHA — anything under `.github/workflows/`.
    if lower.contains("/.github/workflows/") || lower.starts_with(".github/workflows/") {
        return Some(Platform::GithubActions);
    }

    None
}

/// Detect platform from YAML content alone (no path hint).
///
/// Caller should usually use [`detect_platform`] instead, which combines a
/// path hint with the content sniff. This function is exposed for tests and
/// for the stdin path where no filename is available.
fn detect_platform_from_content(content: &str) -> Platform {
    let parsed: Result<serde_yaml::Value, _> = serde_yaml::from_str(content);
    let Ok(value) = parsed else {
        return Platform::GithubActions;
    };
    let Some(map) = value.as_mapping() else {
        return Platform::GithubActions;
    };

    let has_key = |k: &str| map.contains_key(serde_yaml::Value::String(k.to_string()));

    if has_key("on") {
        return Platform::GithubActions;
    }

    // `stages:` disambiguation: GitLab uses a flat string list, ADO uses a list of objects.
    if has_key("stages") {
        let stages_val = map.get(serde_yaml::Value::String("stages".to_string()));
        if let Some(serde_yaml::Value::Sequence(seq)) = stages_val {
            if seq.first().is_some_and(|v| v.is_string()) {
                return Platform::GitLab;
            }
            if seq.first().is_some_and(|v| v.is_mapping()) {
                return Platform::AzureDevOps;
            }
        }
        // Ambiguous or empty stages: fall through to other keys
    }

    if has_key("trigger") || has_key("pr") || has_key("jobs") {
        return Platform::AzureDevOps;
    }

    // GitLab CI: look for image: or workflow: at top level alongside jobs as plain keys
    if has_key("image") || has_key("workflow") {
        return Platform::GitLab;
    }

    Platform::GithubActions
}

/// Detect platform from YAML content, optionally biased by the source file
/// path. The filename is treated as a strong hint and **wins** over
/// content-based detection for unambiguous patterns (e.g. `.gitlab-ci.yml`
/// containing a stray top-level `on:`). When the two disagree, a stderr
/// warning is emitted so the user can pass `--platform` explicitly if the
/// filename is misleading. Pass `None` for stdin / inputs without a path.
///
/// Fuzz B2 reproducer: `.gitlab-ci.yml` containing `on:` previously parsed
/// as GHA and silently dropped GitLab `test:` jobs from the graph.
fn detect_platform(content: &str, path: Option<&Path>) -> Platform {
    let content_guess = detect_platform_from_content(content);

    let Some(path) = path else {
        return content_guess;
    };

    let Some(path_guess) = platform_from_path(path) else {
        return content_guess;
    };

    if path_guess != content_guess {
        let path_str = path.display();
        // Surface the GHA `on:` mismatch case explicitly because that's the
        // documented attacker primitive (single stray top-level key flips the
        // analyser). Other mismatch shapes get the generic message.
        let parsed_top: Result<serde_yaml::Value, _> = serde_yaml::from_str(content);
        let has_on = parsed_top
            .ok()
            .and_then(|v| v.as_mapping().cloned())
            .map(|m| m.contains_key(serde_yaml::Value::String("on".into())))
            .unwrap_or(false);

        let kind_label = match path_guess {
            Platform::GitLab => "GitLab CI",
            Platform::AzureDevOps => "Azure DevOps",
            Platform::GithubActions => "GitHub Actions",
            Platform::Auto => "auto",
        };
        let cli_value = match path_guess {
            Platform::GitLab => "gitlab",
            Platform::AzureDevOps => "azure-devops",
            Platform::GithubActions => "github-actions",
            Platform::Auto => "auto",
        };

        if path_guess == Platform::GitLab && has_on {
            eprintln!(
                "WARNING: {path_str} looks like {kind_label} by name but contains GHA-only syntax (on:); parsing as {kind_label}. If this is wrong, use --platform <X> explicitly."
            );
        } else {
            eprintln!(
                "WARNING: {path_str} looks like {kind_label} by name but content suggests another platform; parsing as {kind_label}. If this is wrong, use --platform {cli_value} (or another value) explicitly."
            );
        }
    }

    path_guess
}

/// Severity levels for the threshold flag.
#[derive(Clone, clap::ValueEnum)]
enum SeverityLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl SeverityLevel {
    fn to_severity(&self) -> Severity {
        match self {
            SeverityLevel::Critical => Severity::Critical,
            SeverityLevel::High => Severity::High,
            SeverityLevel::Medium => Severity::Medium,
            SeverityLevel::Low => Severity::Low,
            SeverityLevel::Info => Severity::Info,
        }
    }

    fn to_arg(&self) -> &'static str {
        match self {
            SeverityLevel::Critical => "critical",
            SeverityLevel::High => "high",
            SeverityLevel::Medium => "medium",
            SeverityLevel::Low => "low",
            SeverityLevel::Info => "info",
        }
    }
}

struct ScanOpts {
    paths: Vec<PathBuf>,
    format: OutputFormat,
    max_hops: usize,
    severity_threshold: Option<SeverityLevel>,
    ignore_file: Option<PathBuf>,
    exclude: Vec<String>,
    quiet: bool,
    verbose: bool,
    omit_empty: bool,
    collapse_template_instances: bool,
    baseline: Option<PathBuf>,
    dedupe_against: Option<PathBuf>,
    show_all: bool,
    baseline_root: Option<PathBuf>,
    telemetry_dir: Option<PathBuf>,
    receipt_dir: Option<PathBuf>,
    log_dir: Option<PathBuf>,
    platform: Platform,
    output: Option<PathBuf>,
    invariants_dir: Option<PathBuf>,
    invariants_allow_external_symlinks: bool,
    force_scan_dense: bool,
    suppressions: Option<PathBuf>,
    suppression_mode: SuppressionModeArg,
}

#[derive(Clone)]
struct RuntimeArtifactPaths {
    telemetry_dir: Option<PathBuf>,
    receipt_dir: Option<PathBuf>,
    log_dir: Option<PathBuf>,
}

fn main() {
    let result = run();
    match result {
        Ok(()) => {}
        Err(err) => {
            // Structural error path. v0.7 contract: exit 2 for structural
            // errors (file missing, parse failure, etc.) so callers can
            // distinguish "tool broke" from "scan ran clean" (0). Note:
            // clap surfaces invalid-flag failures with its own exit code (2)
            // before we get here, which already matches this contract.
            eprintln!("error: {err:#}");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // Spawn a background version check for the substantive commands so it
    // doesn't block startup. The handle is joined after the command finishes.
    // The check is skipped entirely when TAUDIT_NO_UPDATE_CHECK is set, when
    // CI=true (most CI systems set this), or for quick/read-only commands.
    let version_check_handle = match &cli {
        Cli::Scan { .. } | Cli::Verify { .. } | Cli::Version => {
            if std::env::var_os("TAUDIT_NO_UPDATE_CHECK").is_none()
                && std::env::var_os("CI").is_none()
            {
                Some(std::thread::spawn(check_latest_version))
            } else {
                None
            }
        }
        _ => None,
    };

    let result = match cli {
        Cli::Scan {
            paths,
            format,
            max_hops,
            severity_threshold,
            ignore_file,
            no_color,
            exclude,
            quiet,
            verbose,
            omit_empty,
            collapse_template_instances,
            baseline,
            dedupe_against,
            show_all,
            baseline_root,
            telemetry_dir,
            receipt_dir,
            log_dir,
            platform,
            output,
            invariants_dir,
            invariants_allow_external_symlinks,
            force_scan_dense,
            suppressions,
            suppression_mode,
        } => {
            // Color is on by default — CI log viewers (GHA, ADO) render ANSI from piped stdout.
            // Disable only when --no-color is passed or the NO_COLOR env var is set (no-color.org).
            // The log file sink writes plain text independently; this setting only affects stdout.
            if no_color || std::env::var_os("NO_COLOR").is_some() {
                colored::control::set_override(false);
            } else {
                colored::control::set_override(true);
            }
            cmd_scan(ScanOpts {
                paths,
                format,
                max_hops,
                severity_threshold,
                ignore_file,
                exclude,
                quiet,
                verbose,
                omit_empty,
                collapse_template_instances,
                baseline,
                dedupe_against,
                show_all,
                baseline_root,
                telemetry_dir,
                receipt_dir,
                log_dir,
                platform,
                output,
                invariants_dir,
                invariants_allow_external_symlinks,
                force_scan_dense,
                suppressions,
                suppression_mode,
            })
        }
        Cli::Completions { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
            Ok(())
        }
        Cli::Version => cmd_version(),
        Cli::Update => cmd_update(),
        Cli::EmitSpec {
            target,
            id,
            ttl_seconds,
            severity_threshold,
            quiet,
            output,
            platform,
        } => cmd_emit_spec(
            target,
            id,
            ttl_seconds,
            severity_threshold,
            quiet,
            output,
            platform,
        ),
        Cli::Map {
            paths,
            platform,
            no_color,
            format,
            job,
            rich_labels,
        } => cmd_map(paths, platform, no_color, format, job, rich_labels),
        Cli::Graph {
            paths,
            platform,
            format,
            max_hops,
            force_scan_dense,
            job,
            rules_dir,
            rich_labels,
            collapse_by,
            risk_only,
        } => cmd_graph(
            paths,
            platform,
            format,
            max_hops,
            force_scan_dense,
            job,
            rules_dir,
            rich_labels,
            collapse_by,
            risk_only,
        ),
        Cli::Diff {
            before,
            after,
            format,
            max_hops,
            platform,
        } => cmd_diff(before, after, format, max_hops, platform),
        Cli::Explain { rule, no_color } => {
            if no_color || std::env::var_os("NO_COLOR").is_some() {
                colored::control::set_override(false);
            } else {
                colored::control::set_override(true);
            }
            cmd_explain(rule)
        }
        Cli::Invariants { action } => match action {
            InvariantsAction::List {
                invariants_dir,
                no_color,
            } => {
                if no_color || std::env::var_os("NO_COLOR").is_some() {
                    colored::control::set_override(false);
                } else {
                    colored::control::set_override(true);
                }
                cmd_invariants_list(invariants_dir)
            }
        },
        Cli::Verify {
            paths,
            policy,
            format,
            platform,
            max_hops,
            include_builtin,
            severity_threshold,
            no_color,
            output,
            suppressions,
            suppression_mode,
            gate_on_all,
            strict,
            baseline_root,
            ignore_partial,
        } => {
            if no_color || std::env::var_os("NO_COLOR").is_some() {
                colored::control::set_override(false);
            } else {
                colored::control::set_override(true);
            }
            cmd_verify(VerifyOpts {
                paths,
                policy,
                format,
                platform,
                max_hops,
                include_builtin,
                severity_threshold,
                output,
                suppressions,
                suppression_mode,
                gate_on_all,
                strict,
                baseline_root,
                ignore_partial,
            })
        }
        Cli::Suppressions {
            action,
            suppressions,
        } => match action {
            SuppressionsAction::List { no_color } => {
                if no_color || std::env::var_os("NO_COLOR").is_some() {
                    colored::control::set_override(false);
                } else {
                    colored::control::set_override(true);
                }
                cmd_suppressions_list(suppressions)
            }
            SuppressionsAction::Add {
                fingerprint,
                rule_id,
                reason,
                accepted_by,
                accepted_at,
                expires_at,
            } => cmd_suppressions_add(SuppressionsAddOpts {
                suppressions_path: suppressions,
                fingerprint,
                rule_id,
                reason,
                accepted_by,
                accepted_at,
                expires_at,
            }),
            SuppressionsAction::Review { no_color } => {
                if no_color || std::env::var_os("NO_COLOR").is_some() {
                    colored::control::set_override(false);
                } else {
                    colored::control::set_override(true);
                }
                cmd_suppressions_review(suppressions)
            }
        },
        Cli::Baseline { action } => cmd_baseline(action),
        Cli::Remediate { unstable, action } => match action {
            RemediateAction::Suggest { paths, format } => {
                remediate::cmd_suggest(remediate::SuggestOpts {
                    paths,
                    format: format.to_module(),
                })
            }
            RemediateAction::Diff { paths, format } => remediate::cmd_diff(remediate::DiffOpts {
                paths,
                format: format.to_module(),
            }),
            RemediateAction::Apply {
                paths,
                format,
                policy,
                allow_risky,
                min_confidence,
                force,
                backup_root,
            } => {
                if !unstable {
                    eprintln!(
                        "error: `taudit remediate apply` is an unstable write-path operation.\n\
                         Pass --unstable to confirm you accept that the remediation engine\n\
                         may change its transform set or backup schema in a future release.\n\n\
                         Example: taudit remediate --unstable apply --policy <policy> <paths>"
                    );
                    std::process::exit(2);
                }
                remediate::cmd_apply(remediate::ApplyOpts {
                    paths,
                    format: format.to_module(),
                    policy,
                    allow_risky,
                    min_confidence,
                    force,
                    backup_root,
                })
            }
            RemediateAction::Rollback {
                backup_id,
                backup_root,
                force,
            } => {
                if !unstable {
                    eprintln!(
                        "error: `taudit remediate rollback` is an unstable write-path operation.\n\
                         Pass --unstable to confirm you accept that the backup schema\n\
                         may change in a future release.\n\n\
                         Example: taudit remediate --unstable rollback --backup-id <id>"
                    );
                    std::process::exit(2);
                }
                remediate::cmd_rollback(remediate::RollbackOpts {
                    backup_id,
                    backup_root,
                    force,
                })
            }
            RemediateAction::ListBackups {
                backup_root,
                format,
            } => remediate::cmd_list_backups(remediate::ListBackupsOpts {
                backup_root,
                format: format.to_module(),
            }),
        },
    };

    // After the command finishes, collect the background version check and
    // print a one-line nudge if a newer release is available.
    if let Some(handle) = version_check_handle {
        if let Ok(Some(latest)) = handle.join() {
            let current = env!("CARGO_PKG_VERSION");
            eprintln!(
                "\n  taudit {latest} is available (you have {current}). \
                 Run: cargo install taudit --version {latest} --locked"
            );
        }
    }

    result
}

fn cmd_diff(
    before: PathBuf,
    after: PathBuf,
    format: DiffOutputFormat,
    max_hops: usize,
    platform: Platform,
) -> Result<()> {
    let parser_box = make_parser(&platform);
    let parser = parser_box.as_ref();
    let stdout = std::io::stdout();
    let mut out = SilenceBrokenPipe {
        inner: stdout.lock(),
    };

    // For `--platform auto`, detect each file independently. Otherwise reuse the
    // pre-built parser to avoid extra allocations.
    let parse_one = |path: &PathBuf| -> Result<taudit_core::graph::AuthorityGraph> {
        if platform == Platform::Auto {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read {}\n{DIFF_FILES}", path.display()))?;
            let resolved_platform = resolve_platform(&platform, &content, Some(path.as_path()));
            let per_file_parser = make_parser(&resolved_platform);
            parse_content(
                per_file_parser.as_ref(),
                content,
                path.display().to_string(),
            )
        } else {
            parse_file(parser, path)
        }
    };

    let before_graph = parse_one(&before)?;
    let after_graph = parse_one(&after)?;

    let before_findings = rules::run_all_rules(&before_graph, max_hops);
    let after_findings = rules::run_all_rules(&after_graph, max_hops);

    let (mut added, mut removed) = diff_findings(&before_findings, &after_findings);
    sort_findings(&mut added);
    sort_findings(&mut removed);

    match format {
        DiffOutputFormat::Terminal => {
            use std::io::Write;
            writeln!(out, "taudit diff")?;
            writeln!(out, "  before: {}", before.display())?;
            writeln!(out, "  after:  {}", after.display())?;
            writeln!(out)?;
            writeln!(
                out,
                "graph: nodes {} -> {} ({:+}), edges {} -> {} ({:+})",
                before_graph.nodes.len(),
                after_graph.nodes.len(),
                after_graph.nodes.len() as isize - before_graph.nodes.len() as isize,
                before_graph.edges.len(),
                after_graph.edges.len(),
                after_graph.edges.len() as isize - before_graph.edges.len() as isize,
            )?;
            writeln!(
                out,
                "findings: {} -> {} ({:+})",
                before_findings.len(),
                after_findings.len(),
                after_findings.len() as isize - before_findings.len() as isize,
            )?;

            writeln!(out)?;
            writeln!(out, "added findings: {}", added.len())?;
            for finding in &added {
                let category = finding_category(&finding.category);
                writeln!(
                    out,
                    "  + [{:?}] {}: {}",
                    finding.severity, category, finding.message
                )?;
            }

            writeln!(out)?;
            writeln!(out, "removed findings: {}", removed.len())?;
            for finding in &removed {
                let category = finding_category(&finding.category);
                writeln!(
                    out,
                    "  - [{:?}] {}: {}",
                    finding.severity, category, finding.message
                )?;
            }
        }
        DiffOutputFormat::Json => {
            let json = serde_json::json!({
                "before": {
                    "file": before_graph.source.file,
                    "nodes": before_graph.nodes.len(),
                    "edges": before_graph.edges.len(),
                    "findings": before_findings.len(),
                },
                "after": {
                    "file": after_graph.source.file,
                    "nodes": after_graph.nodes.len(),
                    "edges": after_graph.edges.len(),
                    "findings": after_findings.len(),
                },
                "delta": {
                    "nodes": after_graph.nodes.len() as isize - before_graph.nodes.len() as isize,
                    "edges": after_graph.edges.len() as isize - before_graph.edges.len() as isize,
                    "findings": after_findings.len() as isize - before_findings.len() as isize,
                },
                "added": added,
                "removed": removed,
            });
            serde_json::to_writer_pretty(&mut out, &json)
                .with_context(|| "Failed to write JSON diff")?;
        }
    }

    Ok(())
}

fn cmd_scan(opts: ScanOpts) -> Result<()> {
    let ScanOpts {
        paths,
        format,
        max_hops,
        severity_threshold,
        ignore_file,
        exclude,
        quiet,
        verbose,
        omit_empty,
        collapse_template_instances: collapse_templates,
        baseline,
        dedupe_against,
        show_all,
        baseline_root,
        telemetry_dir,
        receipt_dir,
        log_dir,
        platform,
        output,
        invariants_dir,
        invariants_allow_external_symlinks,
        force_scan_dense,
        suppressions: suppressions_path,
        suppression_mode,
    } = opts;

    // Deprecation warning: --rules-dir was renamed to --invariants-dir as
    // part of the v0.7 Authority Invariants rebrand. The old form is kept
    // as a clap alias and will be removed in v1.0. Detect which spelling
    // the user typed by scanning argv directly — clap's derive parser
    // doesn't expose that info on a derived enum field.
    if invariants_dir.is_some()
        && std::env::args().any(|a| a == "--rules-dir" || a.starts_with("--rules-dir="))
    {
        eprintln!(
            "WARNING: --rules-dir is deprecated and will be removed in a future release (target: v1.0). Use --invariants-dir instead. See docs/authority-invariants.md."
        );
    }

    // Load custom invariants up front so a bad --invariants-dir fails
    // before we touch any pipeline files. Errors are written to stderr in
    // full and the process exits non-zero — never panic, and never silently
    // ignore.
    let custom_rules = match invariants_dir.as_ref() {
        Some(dir) => match taudit_core::custom_rules::load_rules_dir_with_opts(
            dir,
            invariants_allow_external_symlinks,
        ) {
            Ok(rules) => rules,
            Err(errors) => {
                for err in &errors {
                    eprintln!("error: {err}");
                }
                eprintln!("{INVARIANTS_DIR}");
                std::process::exit(2);
            }
        },
        None => Vec::new(),
    };

    // Pre-build a parser for the explicit-platform case. When `--platform auto` is
    // used, parsers are built per-file inside the loop after detecting from content.
    let parser_box = make_parser(&platform);
    let parser = parser_box.as_ref();
    let stdout_handle = std::io::stdout();
    let mut writer: Box<dyn std::io::Write> = match output.as_ref() {
        Some(path) => Box::new(std::io::BufWriter::new(
            std::fs::File::create(path).with_context(|| {
                format!(
                    "Failed to open output file {}\n{OUTPUT_FILE}",
                    path.display()
                )
            })?,
        )),
        None => Box::new(SilenceBrokenPipe {
            inner: stdout_handle.lock(),
        }),
    };
    // As of v0.7, `scan` is informational: it always exits 0 unless a
    // structural error (file missing, parse failure, bad flag) occurs.
    // Gating moved to `taudit verify`. We retain `exit_code` only as a
    // value reported to telemetry/receipts.
    let exit_code = 0;

    // Track whether any file produced findings at or above the user's
    // requested severity threshold. Used solely to drive the one-shot
    // migration-warning printed at end-of-run when --severity-threshold
    // is passed (preserves the v0.6 contract semantics for one release).
    let mut threshold_exceeded_anywhere = false;

    // Load ignore config
    let ignore_config = load_ignore_config(ignore_file)?;

    // Load baseline fingerprints (category + message pairs to suppress)
    let baseline_fingerprints = load_baseline(baseline)?;

    // Load --dedupe-against fingerprints. Only applies to the cloudevents
    // emit path; we still load it for any format so a misuse warning can
    // fire. Missing/empty file => empty set (intentional: first-run CI).
    let dedupe_fingerprints: HashSet<String> = match dedupe_against.as_ref() {
        Some(path) => load_dedupe_fingerprints(path)?,
        None => HashSet::new(),
    };
    if dedupe_against.is_some() && !matches!(format, OutputFormat::Cloudevents) {
        eprintln!(
            "warning: --dedupe-against only takes effect with --format cloudevents (current format: {}); flag will be ignored",
            format.as_str()
        );
    }
    // Load .taudit-suppressions.yml. Empty config when no file present.
    // The applicator runs after .tauditignore + baseline so a waiver only
    // takes effect on findings that are still in scope.
    let suppression_config = load_suppression_config(suppressions_path.clone())?;
    let suppression_mode_core = suppression_mode.to_core();
    let suppression_today = today_local();

    let threshold = severity_threshold.map(|s| s.to_severity());
    let runtime_paths = resolve_runtime_artifact_paths(telemetry_dir, receipt_dir, log_dir);

    // Resolve and filter paths. `-` (stdin) bypasses the glob exclude filter.
    let all_paths = resolve_paths_tagged(&paths)?;
    let resolved: Vec<ResolvedPath> = all_paths
        .into_iter()
        .filter(|p| {
            if p.path().as_os_str() == "-" {
                return true; // never exclude stdin
            }
            let path_str = p.path().display().to_string();
            !exclude.iter().any(|pattern| glob_match(pattern, &path_str))
        })
        .collect();

    if resolved.is_empty() {
        anyhow::bail!("no matching pipeline files (.yml / .yaml)\n{NO_PIPELINE_FILES}");
    }

    // Terminal mode: print run banner before the loop
    if !quiet && matches!(format, OutputFormat::Terminal) {
        taudit_report_terminal::print_banner(&mut writer, resolved.len()).ok();
    }

    let mut quiet_total = SeverityCounts::default();
    let mut findings_total = 0usize;
    let mut suppressed_total = 0usize;
    // Terminal summary accumulators
    let mut terminal_clean = 0usize;
    let mut terminal_files_with_findings = 0usize;
    let mut terminal_partial_files = 0usize;
    let mut terminal_totals = SeverityCounts::default();
    // SARIF accumulates all (graph, findings) pairs and emits one document after the loop.
    let mut sarif_buffer: Vec<(
        taudit_core::graph::AuthorityGraph,
        Vec<taudit_core::finding::Finding>,
    )> = Vec::new();
    let mut skipped_total = 0usize;

    for tagged_path in &resolved {
        let path = tagged_path.path();
        // Resolved (concrete) platform for THIS file. Threaded back from the
        // per-file branches so we can stamp `graph.metadata["platform"]`
        // regardless of whether `--platform auto` was used.
        let mut resolved_for_file: Platform = platform.clone();
        // We retain `pipeline_content` so the per-pipeline baseline lookup
        // can hash it without a second filesystem read. Stdin pipelines
        // never have a baseline (no stable filename), so `pipeline_content`
        // stays `None` for them and the lookup is skipped.
        let mut pipeline_content: Option<String> = None;
        let graph = if path.as_os_str() == "-" {
            let mut content = String::new();
            use std::io::Read;
            std::io::stdin()
                .read_to_string(&mut content)
                .with_context(|| "Failed to read from stdin")?;
            // Resolve `Auto` against the stdin content; otherwise reuse the
            // pre-built parser without re-allocating. No path hint for stdin.
            if platform == Platform::Auto {
                let resolved_platform = resolve_platform(&platform, &content, None);
                let per_file_parser = make_parser(&resolved_platform);
                resolved_for_file = resolved_platform;
                parse_content(per_file_parser.as_ref(), content, "<stdin>".to_string())?
            } else {
                parse_content(parser, content, "<stdin>".to_string())?
            }
        } else {
            // Read the file once. When auto-detecting, sniff the content to pick
            // the parser; otherwise reuse the pre-built one. We then call
            // `parse_content` directly to avoid a redundant filesystem read.
            let content = match std::fs::read_to_string(path) {
                Ok(c) => normalise_line_endings(c),
                Err(err) => match tagged_path {
                    ResolvedPath::Discovered(_) => {
                        eprintln!("warning: skipping {}: {err:#}", path.display());
                        skipped_total += 1;
                        continue;
                    }
                    ResolvedPath::Explicit(_) => {
                        return Err(anyhow::Error::new(err)
                            .context(format!("Failed to read {}", path.display())));
                    }
                },
            };
            // Stash for the per-pipeline baseline lookup later in this
            // iteration. Cloned because parse_content takes ownership.
            pipeline_content = Some(content.clone());
            let parse_result = if platform == Platform::Auto {
                let resolved_platform = resolve_platform(&platform, &content, Some(path.as_path()));
                let per_file_parser = make_parser(&resolved_platform);
                resolved_for_file = resolved_platform;
                parse_content(
                    per_file_parser.as_ref(),
                    content,
                    path.display().to_string(),
                )
            } else {
                parse_content(parser, content, path.display().to_string())
            };
            match parse_result {
                Ok(g) => g,
                Err(err) => match tagged_path {
                    ResolvedPath::Discovered(_) => {
                        eprintln!("warning: skipping {}: {err:#}", path.display());
                        skipped_total += 1;
                        continue;
                    }
                    ResolvedPath::Explicit(_) => {
                        return Err(err);
                    }
                },
            }
        };

        // Stamp the resolved CI/CD platform into graph metadata so downstream
        // sinks (CloudEvents) can route by platform without re-parsing the
        // file path. Use the canonical short token: "ado", "gha", "gitlab".
        // Skip when `Auto` somehow survived (no content to detect against).
        let mut graph = graph;
        if let Some(token) = resolved_for_file.metadata_token() {
            graph
                .metadata
                .entry("platform".to_string())
                .or_insert_with(|| token.to_string());
        }

        if graph.completeness == taudit_core::graph::AuthorityCompleteness::Partial
            || graph.completeness == taudit_core::graph::AuthorityCompleteness::Unknown
        {
            terminal_partial_files += 1;
        }

        // Dense-graph safety guard: refuse to run BFS on graphs whose size
        // and edge density combine to push the propagation engine into the
        // O(V·E) corner. The override flag (`--force-scan-dense`) is the
        // escape hatch for callers who have inspected the input.
        if !force_scan_dense && taudit_core::propagation::is_dense_graph(&graph) {
            let err = taudit_core::propagation::DenseGraphError {
                nodes: graph.nodes.len(),
                edges: graph.edges.len(),
            };
            return Err(anyhow::anyhow!(
                "{}\n(source: {})\n{}",
                err,
                graph.source.file,
                DENSE_GRAPH
            ));
        }

        let mut all_findings = rules::run_all_rules(&graph, max_hops);

        if !custom_rules.is_empty() {
            let paths = taudit_core::propagation::propagation_analysis(&graph, max_hops);
            all_findings.extend(taudit_core::custom_rules::evaluate_custom_rules(
                &graph,
                &paths,
                &custom_rules,
            ));
        }

        // Apply .tauditignore
        let ignore_result = ignore_config.apply(all_findings, &graph.source.file);
        let after_ignore = ignore_result.findings;
        let suppressed_ignore = ignore_result.suppressed_count;

        // Apply baseline suppression (legacy --baseline JSON-report flag)
        let (findings, suppressed_baseline) = apply_baseline(after_ignore, &baseline_fingerprints);

        // Apply .taudit-suppressions.yml waivers. Critical waivers without
        // expires_at are rejected up-front (validate against the current
        // file's critical fingerprints). Then apply per the configured mode.
        let findings = {
            let fingerprints: Vec<String> = findings
                .iter()
                .map(|f| taudit_core::finding::compute_fingerprint(f, &graph))
                .collect();
            let critical_fps: Vec<&str> = findings
                .iter()
                .zip(fingerprints.iter())
                .filter(|(f, _)| f.severity == taudit_core::finding::Severity::Critical)
                .map(|(_, fp)| fp.as_str())
                .collect();
            if let Err(errors) =
                suppression_config.validate_critical_waivers(critical_fps.iter().copied())
            {
                for err in errors {
                    eprintln!("error: {err}");
                }
                eprintln!("{CRITICAL_WAIVER_EXPIRY}");
                std::process::exit(2);
            }
            let (waived, warnings) = suppression_config.apply(
                findings,
                suppression_mode_core,
                &fingerprints,
                suppression_today,
            );
            for w in warnings {
                eprintln!("{w}");
            }
            waived
        };
        // Apply per-pipeline baseline (`.taudit/baselines/<hash>.json`).
        // Default behaviour: if a baseline exists for this pipeline, switch
        // to diff-shaped output — only NEW findings (plus any CRITICAL
        // pre-existing findings without a valid waiver) are surfaced.
        // `--show-all` opts back into the legacy absolute view.
        let (findings, suppressed_pipeline_baseline, pipeline_baseline_banner) = if show_all
            || pipeline_content.is_none()
        {
            (findings, 0usize, None)
        } else {
            let outcome = apply_pipeline_baseline(
                findings,
                &graph,
                pipeline_content.as_deref().unwrap_or(""),
                baseline_root.as_deref(),
                /* gate_on_all */ false,
            )?;
            let banner = if outcome.baseline_present {
                Some(format!(
                        "baseline-aware: {} pre-existing suppressed, {} fixed (use --show-all to see everything)",
                        outcome.preexisting_suppressed, outcome.fixed,
                    ))
            } else {
                None
            };
            (outcome.kept, outcome.preexisting_suppressed, banner)
        };
        // Surface the banner once per pipeline on stderr so it doesn't
        // pollute machine-readable output formats.
        if let Some(banner) = pipeline_baseline_banner.as_deref() {
            eprintln!("{}: {banner}", path.display());
        }

        // v0.7: scan no longer gates on findings. We still observe whether
        // the user-supplied threshold would have triggered the legacy v0.6
        // exit-1 contract — but only to drive the one-shot stderr migration
        // warning printed at end-of-run. The exit code itself stays 0.
        if let Some(ref thresh) = threshold {
            if findings.iter().any(|f| f.severity <= *thresh) {
                threshold_exceeded_anywhere = true;
            }
        }

        // Display filter: only show findings at or above the threshold.
        let (findings, suppressed_threshold) = match threshold {
            Some(ref thresh) => {
                let before_len = findings.len();
                let kept: Vec<_> = findings
                    .into_iter()
                    .filter(|f| f.severity <= *thresh)
                    .collect();
                let dropped = before_len - kept.len();
                (kept, dropped)
            }
            None => (findings, 0usize),
        };

        // Collapse near-duplicate findings produced by templated pipelines into
        // one summary finding per (category, root authority) group. Applied
        // after threshold filtering so the collapsed view matches what the
        // formatters would otherwise emit.
        let findings = if collapse_templates {
            collapse_template_instance_findings(findings, &graph)
        } else {
            findings
        };

        findings_total += findings.len();
        suppressed_total += suppressed_ignore
            + suppressed_baseline
            + suppressed_pipeline_baseline
            + suppressed_threshold;

        match format {
            OutputFormat::Terminal => {
                if quiet {
                    let counts = SeverityCounts::from_findings(&findings);
                    quiet_total.add(&counts);
                    let total = findings.len();
                    if !(omit_empty && total == 0) {
                        let suppressed = suppressed_ignore + suppressed_baseline;
                        let sup_note = if suppressed > 0 {
                            format!(" ({suppressed} suppressed)")
                        } else {
                            String::new()
                        };
                        use std::io::Write;
                        writeln!(
                            &mut writer,
                            "{}: {} finding{}{} — {} critical / {} high / {} medium / {} low",
                            path.display(),
                            total,
                            if total == 1 { "" } else { "s" },
                            sup_note,
                            counts.critical,
                            counts.high,
                            counts.medium,
                            counts.low,
                        )
                        .ok();
                    }
                } else if findings.is_empty() {
                    terminal_clean += 1;
                } else {
                    terminal_files_with_findings += 1;
                    let counts = SeverityCounts::from_findings(&findings);
                    terminal_totals.add(&counts);
                    TerminalReport { verbose }
                        .emit(&mut writer, &graph, &findings)
                        .with_context(|| "Failed to write terminal report")?;
                    if suppressed_ignore > 0 || suppressed_baseline > 0 || suppressed_threshold > 0
                    {
                        use std::io::Write;
                        let mut notes = Vec::new();
                        if suppressed_ignore > 0 {
                            notes.push(format!("{suppressed_ignore} suppressed by .tauditignore"));
                        }
                        if suppressed_baseline > 0 {
                            notes.push(format!("{suppressed_baseline} suppressed by baseline"));
                        }
                        if suppressed_threshold > 0 {
                            notes
                                .push(format!("{suppressed_threshold} below --severity-threshold"));
                        }
                        writeln!(&mut writer, "  ({})", notes.join(", ")).ok();
                    }
                }
            }
            OutputFormat::Json => {
                JsonReportSink
                    .emit(&mut writer, &graph, &findings)
                    .with_context(|| "Failed to write JSON report")?;
            }
            OutputFormat::Sarif => {
                sarif_buffer.push((graph, findings));
            }
            OutputFormat::Cloudevents => {
                // --dedupe-against: drop findings whose fingerprint already
                // appears in the prior CloudEvents JSONL. Empty set =>
                // pass-through (first run / no prior file).
                let to_emit: Vec<taudit_core::finding::Finding> = if dedupe_fingerprints.is_empty()
                {
                    findings
                } else {
                    findings
                        .into_iter()
                        .filter(|f| {
                            let fp = taudit_core::finding::compute_fingerprint(f, &graph);
                            !dedupe_fingerprints.contains(&fp)
                        })
                        .collect()
                };
                CloudEventsJsonlSink::default()
                    .emit(&mut writer, &graph, &to_emit)
                    .with_context(|| "Failed to write CloudEvents JSONL")?;
            }
        }
    }

    // Emit the single aggregated SARIF document now that all files have been scanned.
    if !sarif_buffer.is_empty() && matches!(format, OutputFormat::Sarif) {
        let items: Vec<_> = sarif_buffer
            .iter()
            .map(|(g, f)| (g, f.as_slice()))
            .collect();
        SarifReportSink
            .emit_multi_with_custom_rules(&mut writer, &items, &custom_rules)
            .with_context(|| "Failed to write SARIF report")?;
    }

    if quiet && matches!(format, OutputFormat::Terminal) && resolved.len() > 1 {
        use std::io::Write;
        writeln!(
            &mut writer,
            "TOTAL: {} findings — {} critical / {} high / {} medium / {} low",
            quiet_total.total(),
            quiet_total.critical,
            quiet_total.high,
            quiet_total.medium,
            quiet_total.low,
        )
        .ok();
    }

    // Terminal mode: print run summary after the loop
    if !quiet && matches!(format, OutputFormat::Terminal) {
        taudit_report_terminal::print_summary(
            &mut writer,
            &taudit_report_terminal::RunSummary {
                total_files: resolved.len(),
                files_with_findings: terminal_files_with_findings,
                clean_files: terminal_clean,
                partial_files: terminal_partial_files,
                critical: terminal_totals.critical,
                high: terminal_totals.high,
                medium: terminal_totals.medium,
                low: terminal_totals.low,
            },
        )
        .ok();
    }

    if skipped_total > 0 {
        eprintln!(
            "note: {skipped_total} file{} skipped (parse error — check --platform)",
            if skipped_total == 1 { "" } else { "s" }
        );
    }

    // v0.7 migration warning: when --severity-threshold was passed AND
    // findings still exceed it, alert users whose CI relied on v0.6's
    // exit-1 gating that the contract has changed. Targeted for removal
    // once the transition window closes.
    if threshold.is_some() && threshold_exceeded_anywhere {
        eprintln!(
            "WARNING: in v0.6 and earlier, taudit scan exited 1 when severity threshold was exceeded. As of v0.7, scan is informational; use 'taudit verify' to gate CI. See https://github.com/0ryant/taudit/blob/main/CHANGELOG.md for migration."
        );
    }

    let resolved_paths: Vec<PathBuf> = resolved.iter().map(|p| p.path().clone()).collect();

    let now_secs = now_unix_seconds();
    if let Err(err) = write_runtime_artifacts(
        &runtime_paths,
        now_secs,
        &resolved_paths,
        &ScanStats {
            format: &format,
            max_hops,
            findings_total,
            suppressed_total,
            exit_code,
        },
    ) {
        eprintln!("warning: failed to write runtime artifacts: {err}");
    }

    use std::io::Write;
    let _ = writer.flush();
    drop(writer);

    std::process::exit(exit_code);
}

/// Options for `taudit verify`. Mirrors the `Verify` CLI variant fields.
struct VerifyOpts {
    paths: Vec<PathBuf>,
    policy: PathBuf,
    format: VerifyFormat,
    platform: Platform,
    max_hops: usize,
    include_builtin: bool,
    severity_threshold: Option<SeverityLevel>,
    output: Option<PathBuf>,
    suppressions: Option<PathBuf>,
    suppression_mode: SuppressionModeArg,
    /// Force every violation to drive exit 1, ignoring per-pipeline
    /// `.taudit/baselines/<hash>.json` waivers. Critical findings without a
    /// valid waiver always count toward exit 1 regardless of this flag.
    gate_on_all: bool,
    /// Fail fast on discovered-file read/parse errors in directory scans.
    strict: bool,
    /// Optional override of `.taudit/` location. Defaults to CWD.
    baseline_root: Option<PathBuf>,
    /// BUG-6: suppress findings that originate from partial-graph reasoning
    /// (unresolvable variable groups, template references). Lets CI gate on
    /// NEW findings while ignoring known-partial noise from groups that
    /// taudit can't resolve without ADO API access.
    ignore_partial: bool,
}

/// One policy violation surfaced by `verify`. Carries enough detail for the
/// three output formats to render without re-running rule evaluation.
#[derive(Debug, Clone)]
struct Violation {
    path: String,
    invariant_id: String,
    severity: Severity,
    category: String,
    message: String,
}

/// Per-pipeline authority-graph completeness for `verify` text/JSON output
/// (ADR 0003 Phase 2 — gate-adjacent surfacing).
///
/// `gap_kinds` parallels `completeness_gaps` (one entry per gap, same index)
/// so renderers can prefix each reason with its severity label
/// (`[expression]` / `[structural]` / `[opaque]`). Lengths must match.
#[derive(Debug, Clone)]
struct VerifyPipelineModeling {
    path: String,
    completeness: AuthorityCompleteness,
    completeness_gaps: Vec<String>,
    gap_kinds: Vec<GapKind>,
}

/// `taudit verify` entrypoint. Computes the exit code via `run_verify_io`
/// (which is `cfg(test)`-friendly) then `process::exit`s with it.
///
/// Exit codes are part of the contract:
///   0 — no policy violations
///   1 — at least one policy violation
///   2 — usage / file-not-found / parse error
fn cmd_verify(opts: VerifyOpts) -> Result<()> {
    let stdout_handle = std::io::stdout();
    let mut writer: Box<dyn std::io::Write> = match opts.output.as_ref() {
        Some(path) => Box::new(std::io::BufWriter::new(
            std::fs::File::create(path).with_context(|| {
                format!(
                    "Failed to open output file {}\n{OUTPUT_FILE}",
                    path.display()
                )
            })?,
        )),
        None => Box::new(SilenceBrokenPipe {
            inner: stdout_handle.lock(),
        }),
    };

    let exit_code = run_verify_io(&opts, &mut writer);

    use std::io::Write;
    let _ = writer.flush();
    drop(writer);

    std::process::exit(exit_code);
}

/// Run `verify` against `opts`, writing the report into `writer`. Returns the
/// process exit code (0 / 1 / 2). Never panics — every error path is mapped
/// to exit 2 with a stderr line. This is the testable entrypoint.
fn run_verify_io<W: std::io::Write>(opts: &VerifyOpts, writer: &mut W) -> i32 {
    // Step 1: load custom rules. Bad path / parse error => exit 2 (usage).
    // BUG-5: if --include-builtin is set and the policy path simply doesn't
    // exist, treat it as zero custom rules rather than a hard error — the
    // caller wants built-in coverage and the directory hasn't been created
    // yet (common in fresh repos using `taudit verify --include-builtin`).
    let custom_rules = match load_policy(&opts.policy) {
        Ok(rules) => rules,
        Err(errors) => {
            let path_not_found = errors.iter().any(|e| e.contains("policy path not found"));
            if path_not_found && opts.include_builtin {
                Vec::new()
            } else {
                for err in &errors {
                    eprintln!("error: {err}");
                }
                return 2;
            }
        }
    };

    // An empty policy file/dir is almost certainly a misconfiguration in CI —
    // surface it loudly rather than silently exiting 0 on every input.
    if custom_rules.is_empty() && !opts.include_builtin {
        eprintln!("error: no invariants loaded from {}", opts.policy.display());
        eprintln!("{VERIFY_EMPTY_POLICY}");
        return 2;
    }

    // Step 2: resolve pipeline paths. Missing path => exit 2.
    let resolved = match resolve_paths_tagged(&opts.paths) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("error: {err:#}");
            return 2;
        }
    };
    if resolved.is_empty() {
        eprintln!("error: no matching pipeline files (.yml / .yaml)");
        eprintln!("{NO_PIPELINE_FILES}");
        return 2;
    }

    let parser_box = make_parser(&opts.platform);
    let parser = parser_box.as_ref();
    let threshold = opts.severity_threshold.as_ref().map(|s| s.to_severity());

    // Load .taudit-suppressions.yml — verify honors the same waiver file
    // as scan so policy-gated CI runs see consistent severity levels.
    let suppression_config = match load_suppression_config(opts.suppressions.clone()) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("error: {err:#}");
            return 2;
        }
    };
    let suppression_mode_core = opts.suppression_mode.to_core();
    let suppression_today = today_local();

    let mut violations: Vec<Violation> = Vec::new();
    let mut sarif_buffer: Vec<(
        taudit_core::graph::AuthorityGraph,
        Vec<taudit_core::finding::Finding>,
    )> = Vec::new();
    let mut pipeline_modeling: Vec<VerifyPipelineModeling> = Vec::new();

    // Step 3: parse each pipeline file and evaluate the loaded invariants.
    // For explicitly-named files a parse error is fatal (exit 2). For files
    // discovered via directory walk we warn-and-skip (matches `scan`) unless
    // strict mode is enabled.
    for tagged_path in &resolved {
        let path = tagged_path.path();
        let content = match std::fs::read_to_string(path) {
            Ok(c) => normalise_line_endings(c),
            Err(err) => match tagged_path {
                ResolvedPath::Explicit(_) => {
                    eprintln!("error: failed to read {}: {err}", path.display());
                    eprintln!("{VERIFY_READ_PIPELINE}");
                    return 2;
                }
                ResolvedPath::Discovered(_) => {
                    if opts.strict {
                        eprintln!("error: failed to read {}: {err}", path.display());
                        eprintln!("{VERIFY_READ_PIPELINE}");
                        return 2;
                    }
                    eprintln!("warning: skipping {}: {err}", path.display());
                    continue;
                }
            },
        };

        // Retain the content for the per-pipeline baseline lookup below.
        let content_for_baseline = content.clone();
        let parse_result = if opts.platform == Platform::Auto {
            let resolved_platform =
                resolve_platform(&opts.platform, &content, Some(path.as_path()));
            let per_file_parser = make_parser(&resolved_platform);
            parse_content(
                per_file_parser.as_ref(),
                content,
                path.display().to_string(),
            )
        } else {
            parse_content(parser, content, path.display().to_string())
        };

        let graph = match parse_result {
            Ok(g) => g,
            Err(err) => match tagged_path {
                ResolvedPath::Explicit(_) => {
                    eprintln!("error: {err:#}");
                    return 2;
                }
                ResolvedPath::Discovered(_) => {
                    if opts.strict {
                        eprintln!("error: {}: {err:#}", path.display());
                        return 2;
                    }
                    eprintln!("warning: skipping {}: {err:#}", path.display());
                    continue;
                }
            },
        };

        pipeline_modeling.push(VerifyPipelineModeling {
            path: graph.source.file.clone(),
            completeness: graph.completeness,
            completeness_gaps: graph.completeness_gaps.clone(),
            gap_kinds: graph.completeness_gap_kinds.clone(),
        });

        let propagation_paths =
            taudit_core::propagation::propagation_analysis(&graph, opts.max_hops);

        // Custom (policy) findings.
        let mut findings = taudit_core::custom_rules::evaluate_custom_rules(
            &graph,
            &propagation_paths,
            &custom_rules,
        );

        // Optionally fold in the 61 built-in rules.
        if opts.include_builtin {
            findings.extend(rules::run_all_rules(&graph, opts.max_hops));
        }

        // BUG-6: --ignore-partial suppresses findings whose nodes_involved
        // include a variable-group Secret (unresolvable without ADO API).
        // Only active when the graph is non-Complete AND --ignore-partial set.
        if opts.ignore_partial
            && graph.completeness != taudit_core::graph::AuthorityCompleteness::Complete
        {
            findings.retain(|f| {
                !f.nodes_involved.iter().any(|&nid| {
                    graph
                        .node(nid)
                        .and_then(|n| n.metadata.get(taudit_core::graph::META_VARIABLE_GROUP))
                        .map(|v| v == "true")
                        .unwrap_or(false)
                })
            });
        }

        // Apply .taudit-suppressions.yml before the threshold filter so a
        // downgraded waiver can fall below the severity floor and stop
        // gating CI. Critical-without-expiry is a hard error.
        let fingerprints: Vec<String> = findings
            .iter()
            .map(|f| taudit_core::finding::compute_fingerprint(f, &graph))
            .collect();
        let critical_fps: Vec<&str> = findings
            .iter()
            .zip(fingerprints.iter())
            .filter(|(f, _)| f.severity == taudit_core::finding::Severity::Critical)
            .map(|(_, fp)| fp.as_str())
            .collect();
        if let Err(errors) =
            suppression_config.validate_critical_waivers(critical_fps.iter().copied())
        {
            for err in errors {
                eprintln!("error: {err}");
            }
            eprintln!("{CRITICAL_WAIVER_EXPIRY}");
            return 2;
        }
        let (waived, warnings) = suppression_config.apply(
            findings,
            suppression_mode_core,
            &fingerprints,
            suppression_today,
        );
        for w in warnings {
            eprintln!("{w}");
        }
        let mut findings = waived;

        // Apply the severity threshold (Severity orders Critical < Info).
        if let Some(ref t) = threshold {
            findings.retain(|f| f.severity <= *t);
        }

        // Apply the per-pipeline baseline. Default behaviour: keep only
        // NEW findings + CRITICAL pre-existing findings without a valid
        // waiver (council's load-bearing constraint). `--gate-on-all`
        // bypasses suppression but critical-without-valid-waiver still
        // counts. Errors here are non-fatal — log and fall through to the
        // unfiltered behaviour so a corrupt baseline doesn't break verify.
        let findings = match apply_pipeline_baseline(
            findings,
            &graph,
            &content_for_baseline,
            opts.baseline_root.as_deref(),
            opts.gate_on_all,
        ) {
            Ok(outcome) => {
                if outcome.baseline_present && !opts.gate_on_all {
                    eprintln!(
                        "{}: baseline-aware verify ({} pre-existing suppressed, {} fixed)",
                        path.display(),
                        outcome.preexisting_suppressed,
                        outcome.fixed,
                    );
                }
                outcome.kept
            }
            Err(err) => {
                eprintln!(
                    "warning: failed to apply baseline for {}: {err}",
                    path.display()
                );
                // Fall through to no-baseline behaviour. We re-derive the
                // unfiltered list by re-running the rules — but `findings`
                // was moved into apply_pipeline_baseline. Since this branch
                // is only reachable on a corrupt baseline file (very rare),
                // we re-run the inexpensive rule pass to recover.
                let mut rebuilt = taudit_core::custom_rules::evaluate_custom_rules(
                    &graph,
                    &propagation_paths,
                    &custom_rules,
                );
                if opts.include_builtin {
                    rebuilt.extend(rules::run_all_rules(&graph, opts.max_hops));
                }
                if let Some(ref t) = threshold {
                    rebuilt.retain(|f| f.severity <= *t);
                }
                rebuilt
            }
        };

        // Project Findings into Violations and stash for SARIF emission.
        for f in &findings {
            violations.push(Violation {
                path: graph.source.file.clone(),
                invariant_id: extract_invariant_id(&f.message),
                severity: f.severity,
                category: finding_category(&f.category),
                message: f.message.clone(),
            });
        }
        sarif_buffer.push((graph, findings));
    }

    // Step 4: emit the report in the requested format.
    let render_result = match opts.format {
        VerifyFormat::Text => render_verify_text(writer, &violations, &pipeline_modeling),
        VerifyFormat::Json => render_verify_json(writer, &violations, &pipeline_modeling),
        VerifyFormat::Sarif => {
            let items: Vec<_> = sarif_buffer
                .iter()
                .map(|(g, f)| (g, f.as_slice()))
                .collect();
            SarifReportSink
                .emit_multi_with_custom_rules(writer, &items, &custom_rules)
                .map_err(|e| anyhow::anyhow!("Failed to write SARIF report: {e}"))
        }
    };
    if let Err(err) = render_result {
        eprintln!("error: {err:#}");
        return 2;
    }

    if violations.is_empty() {
        0
    } else {
        1
    }
}

/// Load policy invariants from a file or directory. Returns rules on success,
/// a list of errors otherwise. Errors map to exit 2 in `run_verify_io`.
fn load_policy(
    policy: &std::path::Path,
) -> Result<Vec<taudit_core::custom_rules::CustomRule>, Vec<String>> {
    if !policy.exists() {
        return Err(vec![format!(
            "policy path not found: {}\n{}",
            policy.display(),
            VERIFY_POLICY_PATH
        )]);
    }

    if policy.is_dir() {
        match taudit_core::custom_rules::load_rules_dir(policy) {
            Ok(rules) => Ok(rules),
            Err(errors) => Err(errors.iter().map(|e| e.to_string()).collect()),
        }
    } else {
        // Single file. Supports multi-doc YAML: a file may contain one or more
        // `CustomRule` documents separated by `---`.
        let content = std::fs::read_to_string(policy)
            .map_err(|err| vec![format!("failed to read policy {}: {err}", policy.display())])?;
        taudit_core::custom_rules::parse_rules_multi_doc(&content).map_err(|err| {
            vec![format!(
                "failed to parse policy {}: {err}",
                policy.display()
            )]
        })
    }
}

/// Custom-rule findings are formatted as `[<id>] <name>: <src> -> <sink>` by
/// `evaluate_custom_rules`. Pull the id out of the leading `[...]` so it can
/// surface in text/JSON output without re-evaluating the rules.
fn extract_invariant_id(message: &str) -> String {
    if let Some(rest) = message.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_string();
        }
    }
    // Built-in rule findings (when --include-builtin is set) don't carry a
    // leading [id] prefix; fall back to "builtin" so downstream consumers
    // always see a non-empty invariant id.
    "builtin".to_string()
}

/// Render the human-readable text format. One line per violation:
/// `path: invariant_id: message [severity]`. Includes a final summary line
/// even when there are zero violations so CI logs always show the verdict.
fn render_verify_text<W: std::io::Write>(
    w: &mut W,
    violations: &[Violation],
    pipeline_modeling: &[VerifyPipelineModeling],
) -> Result<()> {
    for v in violations {
        writeln!(
            w,
            "{}: {}: {} [{:?}]",
            v.path, v.invariant_id, v.message, v.severity
        )?;
    }
    write_verify_authority_modeling_text(w, pipeline_modeling)?;
    let summary = severity_summary(violations);
    writeln!(
        w,
        "verify: {} violation{} ({} critical / {} high / {} medium / {} low / {} info)",
        violations.len(),
        if violations.len() == 1 { "" } else { "s" },
        summary.critical,
        summary.high,
        summary.medium,
        summary.low,
        summary.info,
    )?;
    Ok(())
}

fn completeness_snake(c: AuthorityCompleteness) -> &'static str {
    match c {
        AuthorityCompleteness::Complete => "complete",
        AuthorityCompleteness::Partial => "partial",
        AuthorityCompleteness::Unknown => "unknown",
    }
}

/// Snake-case label for a `GapKind`. Matches the JSON `kind` field and the
/// `[expression]` / `[structural]` / `[opaque]` text-output prefixes.
fn gap_kind_snake(k: GapKind) -> &'static str {
    match k {
        GapKind::Expression => "expression",
        GapKind::Structural => "structural",
        GapKind::Opaque => "opaque",
    }
}

/// One rollup line plus per-pipeline detail when not `complete` (ADR 0003).
fn write_verify_authority_modeling_text<W: std::io::Write>(
    w: &mut W,
    pipelines: &[VerifyPipelineModeling],
) -> Result<()> {
    if pipelines.is_empty() {
        return Ok(());
    }
    let n = pipelines.len();
    let mut n_complete: u32 = 0;
    let mut n_partial: u32 = 0;
    let mut n_unknown: u32 = 0;
    for p in pipelines {
        match p.completeness {
            AuthorityCompleteness::Complete => n_complete += 1,
            AuthorityCompleteness::Partial => n_partial += 1,
            AuthorityCompleteness::Unknown => n_unknown += 1,
        }
    }
    writeln!(
        w,
        "verify: authority graph modeling: {n} pipeline(s) — complete: {n_complete}, partial: {n_partial}, unknown: {n_unknown}"
    )?;
    for p in pipelines {
        if p.completeness == AuthorityCompleteness::Complete {
            continue;
        }
        if p.completeness_gaps.is_empty() {
            writeln!(
                w,
                "verify:   {} — {} — (no gap strings recorded)",
                p.path,
                completeness_snake(p.completeness),
            )?;
            continue;
        }
        // Header line for the pipeline; one indented line per gap follows,
        // each prefixed with its `[kind]` label. The struct invariant
        // (gap_kinds parallels completeness_gaps) lets us zip safely; if a
        // future producer breaks that invariant we fall back to a neutral
        // `[partial]` label so output stays useful instead of panicking.
        writeln!(
            w,
            "verify:   {} — {}",
            p.path,
            completeness_snake(p.completeness),
        )?;
        let n = p.completeness_gaps.len();
        for (i, reason) in p.completeness_gaps.iter().enumerate() {
            let kind_label = p
                .gap_kinds
                .get(i)
                .copied()
                .map(gap_kind_snake)
                .unwrap_or("partial");
            let line = format!("[{kind_label}] {reason}");
            let line = truncate_for_verify_line(&line, 400);
            let connector = if i + 1 == n { "└──" } else { "├──" };
            writeln!(w, "verify:     {connector} {line}")?;
        }
    }
    Ok(())
}

fn truncate_for_verify_line(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i + 1 >= max_chars {
            out.push('…');
            break;
        }
        out.push(ch);
    }
    out
}

/// Render the structured JSON format with stable field names and a versioned
/// schema marker. `summary.by_severity` is a fixed-key object so consumers
/// can index without checking for missing keys.
fn render_verify_json<W: std::io::Write>(
    w: &mut W,
    violations: &[Violation],
    pipeline_modeling: &[VerifyPipelineModeling],
) -> Result<()> {
    let summary = severity_summary(violations);
    let json = serde_json::json!({
        "schema_version": "taudit.verify.v1",
        "violations": violations.iter().map(|v| serde_json::json!({
            "path": v.path,
            "invariant_id": v.invariant_id,
            "severity": format!("{:?}", v.severity).to_lowercase(),
            "category": v.category,
            "message": v.message,
        })).collect::<Vec<_>>(),
        "summary": {
            "total": violations.len(),
            "by_severity": {
                "critical": summary.critical,
                "high": summary.high,
                "medium": summary.medium,
                "low": summary.low,
                "info": summary.info,
            }
        },
        "pipelines": pipeline_modeling.iter().map(|p| {
            // Each gap becomes a {kind, reason} object so consumers can
            // filter on severity (expression < structural < opaque) without
            // string-parsing. If gap_kinds is shorter than completeness_gaps
            // (struct invariant violation) we emit a neutral "partial" kind
            // for the trailing entries rather than panic.
            let gaps: Vec<serde_json::Value> = p
                .completeness_gaps
                .iter()
                .enumerate()
                .map(|(i, reason)| {
                    let kind = p
                        .gap_kinds
                        .get(i)
                        .copied()
                        .map(gap_kind_snake)
                        .unwrap_or("partial");
                    serde_json::json!({"kind": kind, "reason": reason})
                })
                .collect();
            serde_json::json!({
                "path": p.path,
                "completeness": completeness_snake(p.completeness),
                "completeness_gaps": gaps,
            })
        }).collect::<Vec<_>>(),
    });
    serde_json::to_writer_pretty(w, &json).with_context(|| "Failed to write verify JSON report")?;
    Ok(())
}

fn severity_summary(violations: &[Violation]) -> SeverityCounts {
    let mut c = SeverityCounts::default();
    for v in violations {
        match v.severity {
            Severity::Critical => c.critical += 1,
            Severity::High => c.high += 1,
            Severity::Medium => c.medium += 1,
            Severity::Low => c.low += 1,
            Severity::Info => c.info += 1,
        }
    }
    c
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}

fn xdg_data_home() -> Option<PathBuf> {
    env_path("XDG_DATA_HOME").or_else(|| env_path("HOME").map(|h| h.join(".local/share")))
}

fn xdg_state_home() -> Option<PathBuf> {
    env_path("XDG_STATE_HOME").or_else(|| env_path("HOME").map(|h| h.join(".local/state")))
}

/// Resolve runtime artifact paths. Each path is independently optional — if a path cannot
/// be resolved (no CLI flag, no env var, no HOME/XDG), that artifact is silently skipped.
/// This ensures CI containers without HOME set don't fail before scanning anything.
fn resolve_runtime_artifact_paths(
    telemetry_dir: Option<PathBuf>,
    receipt_dir: Option<PathBuf>,
    log_dir: Option<PathBuf>,
) -> RuntimeArtifactPaths {
    let telemetry_dir = telemetry_dir
        .or_else(|| env_path("TAUDIT_TELEMETRY_DIR"))
        .or_else(|| xdg_state_home().map(|p| p.join("taudit/telemetry")));

    let receipt_dir = receipt_dir
        .or_else(|| env_path("TAUDIT_RECEIPT_DIR"))
        .or_else(|| xdg_data_home().map(|p| p.join("taudit/receipts")));

    let log_dir = log_dir
        .or_else(|| env_path("TAUDIT_LOG_DIR"))
        .or_else(|| xdg_state_home().map(|p| p.join("taudit/logs")));

    RuntimeArtifactPaths {
        telemetry_dir,
        receipt_dir,
        log_dir,
    }
}

fn ensure_dir(path: &PathBuf) -> Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("failed to create directory {}", path.display()))
}

struct ScanStats<'a> {
    format: &'a OutputFormat,
    max_hops: usize,
    findings_total: usize,
    suppressed_total: usize,
    exit_code: i32,
}

fn write_runtime_artifacts(
    paths: &RuntimeArtifactPaths,
    now_secs: u64,
    resolved_paths: &[PathBuf],
    stats: &ScanStats<'_>,
) -> Result<()> {
    let ScanStats {
        format,
        max_hops,
        findings_total,
        suppressed_total,
        exit_code,
    } = stats;
    if let Some(ref telemetry_dir) = paths.telemetry_dir {
        ensure_dir(telemetry_dir)?;
        let telemetry_file = telemetry_dir.join("events.jsonl");
        let telemetry_event = serde_json::json!({
            "event": "scan_completed",
            "ts_unix": now_secs,
            "paths_scanned": resolved_paths.len(),
            "findings_total": findings_total,
            "suppressed_total": suppressed_total,
            "exit_code": exit_code,
        });
        append_line(&telemetry_file, &telemetry_event.to_string())?;
    }

    if let Some(ref receipt_dir) = paths.receipt_dir {
        ensure_dir(receipt_dir)?;
        let receipt_file = receipt_dir.join(format!("receipt-{now_secs}.json"));
        let path_strings: Vec<String> = resolved_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let receipt = serde_json::json!({
            "kind": "taudit.scan.receipt",
            "ts_unix": now_secs,
            "format": format.as_str(),
            "max_hops": max_hops,
            "paths": path_strings,
            "findings_total": findings_total,
            "suppressed_total": suppressed_total,
            "exit_code": exit_code,
        });
        let receipt_text = serde_json::to_string_pretty(&receipt)
            .with_context(|| "failed to serialize scan receipt")?;
        std::fs::write(&receipt_file, receipt_text)
            .with_context(|| format!("failed to write receipt {}", receipt_file.display()))?;
    }

    if let Some(ref log_dir) = paths.log_dir {
        ensure_dir(log_dir)?;
        let log_file = log_dir.join("taudit.log");
        let log_line = format!(
            "ts_unix={} event=scan_completed format={} paths={} findings={} suppressed={} exit_code={}",
            now_secs,
            format.as_str(),
            resolved_paths.len(),
            findings_total,
            suppressed_total,
            exit_code
        );
        append_line(&log_file, &log_line)?;
    }

    Ok(())
}

fn append_line(path: &PathBuf, line: &str) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    writeln!(file, "{line}").with_context(|| format!("failed to append to {}", path.display()))?;
    Ok(())
}

/// Load `.taudit-suppressions.yml`. Resolution order:
///   1. Explicit `--suppressions <path>` flag (must exist).
///   2. `.taudit-suppressions.yml` in CWD.
///   3. `.taudit/suppressions.yml` in CWD.
///   4. Empty config.
fn load_suppression_config(
    explicit_path: Option<PathBuf>,
) -> Result<taudit_core::suppressions::SuppressionConfig> {
    let path = if let Some(p) = explicit_path {
        // Operator named a path explicitly — fail if missing rather than
        // silently fall through to a different file.
        if !p.exists() {
            return Err(anyhow::anyhow!(
                "suppression file not found: {}\n{SUPPRESSIONS_FILE}",
                p.display()
            ));
        }
        Some(p)
    } else {
        let cwd = std::env::current_dir().with_context(|| "failed to resolve CWD")?;
        taudit_core::suppressions::SuppressionConfig::discover(&cwd)
    };

    match path {
        Some(p) => taudit_core::suppressions::SuppressionConfig::load_from_path(&p)
            .map_err(|e| anyhow::anyhow!(e.to_string())),
        None => Ok(taudit_core::suppressions::SuppressionConfig::default()),
    }
}

/// Today's date in the local timezone. Used by the suppression
/// applicator to determine expiry. The date-only granularity matches
/// the YAML schema (`expires_at: YYYY-MM-DD`).
fn today_local() -> chrono::NaiveDate {
    chrono::Local::now().date_naive()
}

/// Load ignore config from file. Tries `--ignore-file` path first,
/// then `.tauditignore` in CWD. Returns empty config if neither exists.
fn load_ignore_config(explicit_path: Option<PathBuf>) -> Result<IgnoreConfig> {
    let path = if let Some(p) = explicit_path {
        // Explicit path must exist — fail immediately, don't fall through to default
        if !p.exists() {
            anyhow::bail!("ignore file not found: {}\n{IGNORE_FILE}", p.display());
        }
        Some(p)
    } else {
        let default = PathBuf::from(".tauditignore");
        if default.exists() {
            Some(default)
        } else {
            None
        }
    };

    match path {
        Some(p) => {
            let content = std::fs::read_to_string(&p)
                .with_context(|| format!("Failed to read ignore file: {}", p.display()))?;
            let config: IgnoreConfig = serde_yaml::from_str(&content).with_context(|| {
                format!(
                    "Failed to parse ignore file: {}\n\n\
                     Expected YAML format:\n\
                     \n\
                     ignore:\n\
                     \x20 - category: unpinned_action\n\
                     \x20   path: \".github/workflows/legacy.yml\"  # optional glob\n\
                     \x20   reason: \"Accepted — migrating to pinned actions\"  # optional\n\
                     \n\
                     Valid category values: run `taudit explain` for the full list.",
                    p.display()
                )
            })?;
            Ok(config)
        }
        None => Ok(IgnoreConfig::default()),
    }
}

/// A fingerprint (category, message) that identifies a finding in a baseline.
type BaselineSet = HashSet<(String, String)>;

/// Load a JSON report from `path` and extract fingerprints.
/// Returns an empty set if `path` is None.
fn load_baseline(path: Option<PathBuf>) -> Result<BaselineSet> {
    let Some(p) = path else {
        return Ok(HashSet::new());
    };

    let content = std::fs::read_to_string(&p).with_context(|| {
        format!(
            "Failed to read baseline file: {}\n{BASELINE_JSON}",
            p.display()
        )
    })?;

    let json: serde_json::Value = serde_json::from_str(&content).with_context(|| {
        format!(
            "Failed to parse baseline JSON: {}\n{BASELINE_JSON}",
            p.display()
        )
    })?;

    let mut set = HashSet::new();

    // Support both a single report object and an array of reports
    let reports = if json.is_array() {
        json.as_array().cloned().unwrap_or_default()
    } else {
        vec![json]
    };

    for report in reports {
        if let Some(findings) = report.get("findings").and_then(|f| f.as_array()) {
            for f in findings {
                let category = f
                    .get("category")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let message = f
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if !category.is_empty() && !message.is_empty() {
                    set.insert((category, message));
                }
            }
        }
    }

    Ok(set)
}

/// Load `tauditfindingfingerprint` values from a CloudEvents JSONL file
/// emitted by a prior `taudit scan --format cloudevents` run. Used by
/// `--dedupe-against` to drop already-seen findings before re-emitting.
///
/// Liberal in what it accepts:
///   * Missing file → empty set (first-run CI shouldn't fail).
///   * Empty file → empty set.
///   * Lines that don't parse as JSON or lack the fingerprint field are
///     silently skipped (so a partial / truncated prior file doesn't
///     break the current scan). A diagnostic is printed to stderr only
///     if zero fingerprints could be loaded from a non-empty file —
///     that's the case worth surfacing.
fn load_dedupe_fingerprints(path: &PathBuf) -> Result<HashSet<String>> {
    let mut out = HashSet::new();

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // Treat missing prior file as "no fingerprints" rather than an
            // error. First-time CI runs hit this path and should succeed.
            return Ok(out);
        }
        Err(err) => {
            return Err(anyhow::Error::new(err).context(format!(
                "Failed to read --dedupe-against file: {}\n{DEDUPE_FILE}",
                path.display()
            )));
        }
    };

    if content.trim().is_empty() {
        return Ok(out);
    }

    let mut malformed = 0usize;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let event: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                malformed += 1;
                continue;
            }
        };
        if let Some(fp) = event
            .get("tauditfindingfingerprint")
            .and_then(|v| v.as_str())
        {
            // Accept only the documented shape (32 lowercase hex chars,
            // v3 algorithm). Anything else is silently ignored to avoid
            // a malformed prior file polluting the current run.
            if fp.len() == 32 && fp.chars().all(|c| c.is_ascii_hexdigit()) {
                out.insert(fp.to_string());
            }
        }
    }

    if out.is_empty() && malformed > 0 {
        eprintln!(
            "warning: --dedupe-against file {} had {malformed} malformed line{} and 0 usable fingerprints; treating as empty",
            path.display(),
            if malformed == 1 { "" } else { "s" }
        );
    }

    Ok(out)
}

/// Remove findings whose (category, message) is present in `baseline`.
/// Returns `(kept_findings, suppressed_count)`.
fn apply_baseline(
    findings: Vec<taudit_core::finding::Finding>,
    baseline: &BaselineSet,
) -> (Vec<taudit_core::finding::Finding>, usize) {
    if baseline.is_empty() {
        return (findings, 0);
    }

    let mut kept = Vec::new();
    let mut suppressed = 0;

    for f in findings {
        let key = (
            serde_json::to_value(f.category)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default(),
            f.message.clone(),
        );
        if baseline.contains(&key) {
            suppressed += 1;
        } else {
            kept.push(f);
        }
    }

    (kept, suppressed)
}

/// Outcome of applying a per-pipeline `.taudit/baselines/<hash>.json` to a
/// fresh finding set. Drives both `scan`'s diff-shaped default output and
/// `verify`'s "exit-1 only on NEW (or critical-without-valid-waiver)"
/// contract.
struct PipelineBaselineOutcome {
    /// Findings to surface to the user / counted toward exit 1. This is the
    /// union of (NEW findings) + (CRITICAL pre-existing findings whose
    /// baseline entry does not carry a valid waiver).
    pub kept: Vec<taudit_core::finding::Finding>,
    /// How many findings were summarised away as pre-existing (no longer
    /// shown / no longer driving exit 1). Surfaced in the banner.
    pub preexisting_suppressed: usize,
    /// How many baseline entries no longer match a current finding —
    /// the underlying issue was fixed. Surfaced in the banner.
    pub fixed: usize,
    /// True iff a baseline file was actually loaded for this pipeline.
    /// When false, the caller should fall through to existing behaviour.
    pub baseline_present: bool,
}

/// Apply the per-pipeline baseline (if one exists at
/// `<root>/.taudit/baselines/<sha256>.json`) to `findings`. When
/// `gate_on_all` is true, the baseline is loaded only to compute the
/// fixed/preexisting counts for the banner — `kept` retains every finding.
/// Critical findings without a valid waiver are ALWAYS retained in `kept`
/// regardless of `gate_on_all` (council's load-bearing constraint).
fn apply_pipeline_baseline(
    findings: Vec<taudit_core::finding::Finding>,
    graph: &taudit_core::graph::AuthorityGraph,
    content: &str,
    baseline_root: Option<&std::path::Path>,
    gate_on_all: bool,
) -> Result<PipelineBaselineOutcome> {
    let root = match baseline_root {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir().with_context(|| "Failed to resolve current directory")?,
    };
    let hash = taudit_core::baselines::compute_pipeline_hash(content);
    let target = taudit_core::baselines::baseline_path_for(&root, &hash);
    let baseline = match taudit_core::baselines::Baseline::load(&target).map_err(|e| {
        anyhow::anyhow!(
            "Failed to load baseline {}: {e}\n{PIPELINE_BASELINE_LOAD}",
            target.display()
        )
    })? {
        Some(b) => b,
        None => {
            return Ok(PipelineBaselineOutcome {
                kept: findings,
                preexisting_suppressed: 0,
                fixed: 0,
                baseline_present: false,
            })
        }
    };
    if !baseline.identity_material_matches(graph) {
        eprintln!(
            "warning: baseline {} identity material mismatch; skipping suppression (re-run `taudit baseline init`)",
            target.display()
        );
        return Ok(PipelineBaselineOutcome {
            kept: findings,
            preexisting_suppressed: 0,
            fixed: 0,
            baseline_present: false,
        });
    }
    let now = chrono::Utc::now();
    let diff = taudit_core::baselines::diff(&findings, &baseline, graph);
    if gate_on_all {
        return Ok(PipelineBaselineOutcome {
            kept: findings,
            preexisting_suppressed: 0,
            fixed: diff.fixed.len(),
            baseline_present: true,
        });
    }
    let blockers = diff.critical_without_valid_waiver(&baseline, graph, now);
    // Union NEW + (preexisting critical without valid waiver). Preserve
    // input order: walk `findings` once, keep iff in NEW or in blockers.
    let new_set: std::collections::HashSet<String> = diff
        .new
        .iter()
        .map(|f| taudit_core::baselines::compute_finding_fingerprint(f, graph))
        .collect();
    let blocker_set: std::collections::HashSet<String> = blockers
        .iter()
        .map(|f| taudit_core::baselines::compute_finding_fingerprint(f, graph))
        .collect();
    let mut kept = Vec::new();
    let mut suppressed = 0usize;
    for f in findings {
        let fp = taudit_core::baselines::compute_finding_fingerprint(&f, graph);
        if new_set.contains(&fp) || blocker_set.contains(&fp) {
            kept.push(f);
        } else {
            suppressed += 1;
        }
    }
    Ok(PipelineBaselineOutcome {
        kept,
        preexisting_suppressed: suppressed,
        fixed: diff.fixed.len(),
        baseline_present: true,
    })
}

fn finding_category(category: &taudit_core::finding::FindingCategory) -> String {
    serde_json::to_value(category)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn finding_fingerprint(finding: &taudit_core::finding::Finding) -> (String, String, String) {
    (
        format!("{:?}", finding.severity),
        finding_category(&finding.category),
        finding.message.clone(),
    )
}

fn diff_findings(
    before: &[taudit_core::finding::Finding],
    after: &[taudit_core::finding::Finding],
) -> (
    Vec<taudit_core::finding::Finding>,
    Vec<taudit_core::finding::Finding>,
) {
    let before_set: HashSet<_> = before.iter().map(finding_fingerprint).collect();
    let after_set: HashSet<_> = after.iter().map(finding_fingerprint).collect();

    let added = after
        .iter()
        .filter(|f| !before_set.contains(&finding_fingerprint(f)))
        .cloned()
        .collect();

    let removed = before
        .iter()
        .filter(|f| !after_set.contains(&finding_fingerprint(f)))
        .cloned()
        .collect();

    (added, removed)
}

fn sort_findings(findings: &mut [taudit_core::finding::Finding]) {
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| finding_category(&a.category).cmp(&finding_category(&b.category)))
            .then_with(|| a.message.cmp(&b.message))
    });
}

/// Collapse near-duplicate findings produced by templated pipeline expansions.
///
/// Groups findings by `(category, root_authority_node_name)` where the root is
/// the first `Secret` or `Identity` node in `nodes_involved`. When a group has
/// more than one finding it is replaced by a single summary finding that keeps
/// the highest severity, the first finding's location/category/nodes_involved/
/// recommendation, and rewrites the message as
/// `"N occurrences of <category>: [node1, node2, ...]"`.
///
/// Findings with no Secret/Identity in `nodes_involved` are keyed by their
/// message (effectively never collapsed) so unrelated findings never merge.
/// Group order is preserved by first-appearance to keep output deterministic.
fn collapse_template_instance_findings(
    findings: Vec<taudit_core::finding::Finding>,
    graph: &taudit_core::graph::AuthorityGraph,
) -> Vec<taudit_core::finding::Finding> {
    use taudit_core::graph::NodeKind;

    /// Cap on how many distinct node names to inline in the collapsed message.
    const MAX_NODE_NAMES_IN_MESSAGE: usize = 8;

    #[derive(PartialEq, Eq, Hash, Clone)]
    enum GroupKey {
        /// Collapsible: same category + same root authority node name.
        Authority(taudit_core::finding::FindingCategory, String),
        /// Non-collapsible: no authority root — keyed on the full message so
        /// each finding lands in its own singleton group.
        Unique(String),
    }

    fn root_authority_name(
        f: &taudit_core::finding::Finding,
        graph: &taudit_core::graph::AuthorityGraph,
    ) -> Option<String> {
        f.nodes_involved.iter().find_map(|id| {
            graph.node(*id).and_then(|n| {
                if matches!(n.kind, NodeKind::Secret | NodeKind::Identity) {
                    Some(n.name.clone())
                } else {
                    None
                }
            })
        })
    }

    // Preserve first-appearance order: track group keys in a Vec, indices in a
    // parallel HashMap, and accumulate finding indices per group.
    let mut group_order: Vec<GroupKey> = Vec::new();
    let mut group_index: std::collections::HashMap<GroupKey, usize> =
        std::collections::HashMap::new();
    let mut groups: Vec<Vec<usize>> = Vec::new();

    for (idx, f) in findings.iter().enumerate() {
        let key = match root_authority_name(f, graph) {
            Some(name) => GroupKey::Authority(f.category, name),
            None => GroupKey::Unique(f.message.clone()),
        };
        match group_index.get(&key) {
            Some(&gi) => groups[gi].push(idx),
            None => {
                let gi = groups.len();
                group_index.insert(key.clone(), gi);
                group_order.push(key);
                groups.push(vec![idx]);
            }
        }
    }

    let mut out: Vec<taudit_core::finding::Finding> = Vec::with_capacity(group_order.len());
    for indices in groups {
        if indices.len() == 1 {
            out.push(findings[indices[0]].clone());
            continue;
        }

        // Highest severity wins (Severity::Critical < Severity::Info via rank).
        let max_sev = indices
            .iter()
            .map(|&i| findings[i].severity)
            .min()
            .expect("group is non-empty");

        // Collect unique node names from `nodes_involved` across all members,
        // preserving first-seen order, capped for readability.
        let mut seen: HashSet<String> = HashSet::new();
        let mut names: Vec<String> = Vec::new();
        for &i in &indices {
            for nid in &findings[i].nodes_involved {
                if let Some(node) = graph.node(*nid) {
                    if seen.insert(node.name.clone()) {
                        names.push(node.name.clone());
                    }
                }
            }
        }
        let displayed_names: Vec<String> = if names.len() > MAX_NODE_NAMES_IN_MESSAGE {
            let mut head: Vec<String> = names
                .iter()
                .take(MAX_NODE_NAMES_IN_MESSAGE)
                .cloned()
                .collect();
            head.push(format!(
                "... +{} more",
                names.len() - MAX_NODE_NAMES_IN_MESSAGE
            ));
            head
        } else {
            names
        };

        let first = &findings[indices[0]];
        let category_label = finding_category(&first.category);
        let message = format!(
            "{} occurrences of {}: [{}]",
            indices.len(),
            category_label,
            displayed_names.join(", "),
        );

        out.push(taudit_core::finding::Finding {
            severity: max_sev,
            category: first.category,
            path: first.path.clone(),
            nodes_involved: first.nodes_involved.clone(),
            message,
            recommendation: first.recommendation.clone(),
            // Preserve provenance from the representative finding so the
            // collapsed entry still attributes back to the correct source
            // (built-in vs custom YAML). Collapsing only groups findings
            // already sharing rule + category + nodes, so all members of
            // the group share a source.
            source: first.source.clone(),
            extras: FindingExtras::default(),
        });
    }

    out
}

/// Per-severity finding counts.
#[derive(Default)]
struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

impl SeverityCounts {
    fn from_findings(findings: &[taudit_core::finding::Finding]) -> Self {
        let mut c = SeverityCounts::default();
        for f in findings {
            match f.severity {
                Severity::Critical => c.critical += 1,
                Severity::High => c.high += 1,
                Severity::Medium => c.medium += 1,
                Severity::Low => c.low += 1,
                Severity::Info => c.info += 1,
            }
        }
        c
    }

    fn add(&mut self, other: &SeverityCounts) {
        self.critical += other.critical;
        self.high += other.high;
        self.medium += other.medium;
        self.low += other.low;
        self.info += other.info;
    }

    fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

fn cmd_map(
    paths: Vec<PathBuf>,
    platform: Platform,
    no_color: bool,
    format: MapFormat,
    job: Option<String>,
    rich_labels: bool,
) -> Result<()> {
    if rich_labels && matches!(format, MapFormat::Text) {
        anyhow::bail!(
            "`--rich-labels` applies only to `--format dot` and `--format mermaid` (not `text`)"
        );
    }

    if no_color || std::env::var_os("NO_COLOR").is_some() {
        colored::control::set_override(false);
    }

    let parser_box = make_parser(&platform);
    let parser = parser_box.as_ref();

    // Track whether --job matched any file so we can give a useful error at the end.
    let mut job_matched_any = false;

    let tagged_paths = resolve_paths_tagged(&paths)?;
    if tagged_paths.is_empty() {
        anyhow::bail!("no matching pipeline files (.yml / .yaml)\n{NO_PIPELINE_FILES}");
    }
    for tagged_path in tagged_paths {
        let path = tagged_path.path().clone();
        let graph = if platform == Platform::Auto {
            // Read once, sniff platform, parse with the right parser.
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(err) => match &tagged_path {
                    ResolvedPath::Discovered(_) => {
                        eprintln!("warning: skipping {}: {err:#}", path.display());
                        continue;
                    }
                    ResolvedPath::Explicit(_) => {
                        return Err(anyhow::Error::new(err)
                            .context(format!("Failed to read {}", path.display())));
                    }
                },
            };
            let resolved_platform = resolve_platform(&platform, &content, Some(path.as_path()));
            let per_file_parser = make_parser(&resolved_platform);
            match parse_content(
                per_file_parser.as_ref(),
                content,
                path.display().to_string(),
            ) {
                Ok(g) => g,
                Err(err) => match &tagged_path {
                    ResolvedPath::Discovered(_) => {
                        eprintln!("warning: skipping {}: {err:#}", path.display());
                        continue;
                    }
                    ResolvedPath::Explicit(_) => return Err(err),
                },
            }
        } else {
            match parse_file(parser, &path) {
                Ok(g) => g,
                Err(err) => match &tagged_path {
                    ResolvedPath::Discovered(_) => {
                        eprintln!("warning: skipping {}: {err:#}", path.display());
                        continue;
                    }
                    ResolvedPath::Explicit(_) => return Err(err),
                },
            }
        };
        // When --job is specified, skip files that don't contain the job. This makes
        // directory scans work correctly: each file is checked independently, and
        // only files that have the named job produce output. Error at the end if
        // no file in the set contained the job.
        if let Some(ref name) = job {
            if !map::job_names(&graph).iter().any(|n| n == name) {
                continue;
            }
            job_matched_any = true;
        }

        let diagram_label_detail = if rich_labels {
            map::DiagramLabelDetail::Rich
        } else {
            map::DiagramLabelDetail::Compact
        };

        match format {
            MapFormat::Text => {
                let authority_map = map::authority_map(&graph);
                let mut buf = String::new();
                buf.push_str(&format!("Authority Map: {}\n\n", path.display()));
                buf.push_str(&map::render_map(&authority_map, term_width()));
                buf.push('\n');
                try_write_stdout(buf.as_bytes())?;
            }
            MapFormat::Dot => {
                let mut s = map::render_dot(
                    &graph,
                    job.as_deref(),
                    diagram_label_detail,
                    map::DotJobCollapse::Off,
                );
                s.push('\n');
                try_write_stdout(s.as_bytes())?;
            }
            MapFormat::Mermaid => {
                let mut s = map::render_mermaid(&graph, job.as_deref(), diagram_label_detail);
                s.push('\n');
                try_write_stdout(s.as_bytes())?;
            }
        }
    }

    if let Some(ref name) = job {
        if !job_matched_any {
            eprintln!("error: no job named '{name}' found in any scanned file");
            eprintln!("{JOB_NAME_NOT_FOUND}");
            std::process::exit(2);
        }
    }

    Ok(())
}

/// `taudit graph` — emit the canonical authority graph as a versioned,
/// machine-readable export. Mirrors `cmd_map`'s file-resolution and
/// per-file platform sniffing, but produces the graph itself rather than
/// the human-readable map. Default format is JSON conforming to
/// `schemas/authority-graph.v1.json`; `--format summary` emits propagation rollup JSON;
/// `--format dot` and `--format mermaid` reuse the same renderers as `taudit map --format dot|mermaid`
/// (job filter applies to diagram output only, not JSON or summary).
fn warn_graph_phase4_flags(
    collapse_by: Option<GraphCollapseBy>,
    risk_only: bool,
    format: GraphFormat,
) {
    if collapse_by.is_none() && !risk_only {
        return;
    }

    let job_collapse_dot = matches!(
        (collapse_by, format),
        (Some(GraphCollapseBy::Job), GraphFormat::Dot)
    );

    if job_collapse_dot && !risk_only {
        return;
    }

    let mut parts = Vec::<String>::new();
    if let Some(by) = collapse_by {
        match (by, format) {
            (GraphCollapseBy::Job, GraphFormat::Dot) => {}
            (GraphCollapseBy::Job, _) => {
                parts.push(
                    "--collapse-by=job (ignored for this export format; job collapse is DOT-only)"
                        .to_string(),
                );
            }
            (GraphCollapseBy::TrustZone, _) => {
                parts.push(format!("--collapse-by={}", by.as_cli_value()));
            }
        }
    }
    if risk_only {
        parts.push("--risk-only".to_owned());
    }
    if parts.is_empty() {
        return;
    }
    let joined = parts.join(", ");
    let dot_only_job_notice = parts.len() == 1 && joined.contains("job collapse is DOT-only");
    if dot_only_job_notice {
        eprintln!("taudit: notice: {joined}.");
        return;
    }
    eprintln!(
        "taudit: notice: {joined} — ADR 0002 Phase 4 (scale / composite policy) is not implemented yet; output unchanged."
    );
}

// Many flags mirror `taudit scan` / clap surface; bundling would churn call sites.
#[allow(clippy::too_many_arguments)]
fn cmd_graph(
    paths: Vec<PathBuf>,
    platform: Platform,
    format: GraphFormat,
    max_hops: usize,
    force_scan_dense: bool,
    job: Option<String>,
    rules_dir: Option<PathBuf>,
    rich_labels: bool,
    collapse_by: Option<GraphCollapseBy>,
    risk_only: bool,
) -> Result<()> {
    warn_graph_phase4_flags(collapse_by, risk_only, format);

    if rich_labels && matches!(format, GraphFormat::Json | GraphFormat::Summary) {
        anyhow::bail!("`--rich-labels` applies only to `--format dot` and `--format mermaid`");
    }

    if matches!(format, GraphFormat::Summary) && job.is_some() {
        anyhow::bail!(
            "`--job` does not apply to `--format summary` (summary is always computed on the full parsed graph)"
        );
    }

    // Validate `--rules-dir` early so a bad directory fails fast, even
    // though custom rules don't currently affect the emitted graph
    // (kept for symmetry with `taudit scan`).
    if let Some(dir) = rules_dir.as_ref() {
        if let Err(errors) = taudit_core::custom_rules::load_rules_dir(dir) {
            for err in &errors {
                eprintln!("error: {err}");
            }
            eprintln!("{INVARIANTS_DIR}");
            std::process::exit(2);
        }
    }

    let parser_box = make_parser(&platform);
    let parser = parser_box.as_ref();

    let mut job_matched_any = false;

    let tagged_paths = resolve_paths_tagged(&paths)?;
    if tagged_paths.is_empty() {
        anyhow::bail!("no matching pipeline files (.yml / .yaml)\n{NO_PIPELINE_FILES}");
    }
    for tagged_path in tagged_paths {
        let path = tagged_path.path().clone();
        let graph = if platform == Platform::Auto {
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(err) => match &tagged_path {
                    ResolvedPath::Discovered(_) => {
                        eprintln!("warning: skipping {}: {err:#}", path.display());
                        continue;
                    }
                    ResolvedPath::Explicit(_) => {
                        return Err(anyhow::Error::new(err)
                            .context(format!("Failed to read {}", path.display())));
                    }
                },
            };
            let resolved_platform = resolve_platform(&platform, &content, Some(path.as_path()));
            let per_file_parser = make_parser(&resolved_platform);
            match parse_content(
                per_file_parser.as_ref(),
                content,
                path.display().to_string(),
            ) {
                Ok(g) => g,
                Err(err) => match &tagged_path {
                    ResolvedPath::Discovered(_) => {
                        eprintln!("warning: skipping {}: {err:#}", path.display());
                        continue;
                    }
                    ResolvedPath::Explicit(_) => return Err(err),
                },
            }
        } else {
            match parse_file(parser, &path) {
                Ok(g) => g,
                Err(err) => match &tagged_path {
                    ResolvedPath::Discovered(_) => {
                        eprintln!("warning: skipping {}: {err:#}", path.display());
                        continue;
                    }
                    ResolvedPath::Explicit(_) => return Err(err),
                },
            }
        };

        // For `--job` filtering: skip files that don't contain the named job.
        // Same semantics as `taudit map --job`. (Summary format rejects `--job` up-front.)
        if let Some(ref name) = job {
            if !map::job_names(&graph).iter().any(|n| n == name) {
                continue;
            }
            job_matched_any = true;
        }

        let diagram_label_detail = if rich_labels {
            map::DiagramLabelDetail::Rich
        } else {
            map::DiagramLabelDetail::Compact
        };

        match format {
            GraphFormat::Summary => {
                let doc = summary::build_authority_propagation_summary(
                    &graph,
                    max_hops,
                    force_scan_dense,
                )
                .map_err(|e| {
                    anyhow::anyhow!("{e}\n(source: {})\n{DENSE_GRAPH}", graph.source.file)
                })?;
                let mut json = serde_json::to_string_pretty(&doc)
                    .map_err(|e| anyhow::anyhow!("summary JSON error: {e}"))?
                    .into_bytes();
                json.push(b'\n');
                try_write_stdout(&json)?;
            }
            GraphFormat::Json => {
                // Note: --job only filters diagram output (DOT / Mermaid); the
                // JSON export emits the full graph for every matched file. This
                // matches user expectation that the schema-validated JSON
                // is a faithful, lossless dump.
                let export = taudit_report_json::GraphExport::new(&graph);
                let mut json = export
                    .to_json_pretty()
                    .map_err(|e| anyhow::anyhow!("{e}"))?
                    .into_bytes();
                json.push(b'\n');
                try_write_stdout(&json)?;
            }
            GraphFormat::Dot => {
                let job_collapse = if collapse_by == Some(GraphCollapseBy::Job) {
                    map::DotJobCollapse::On
                } else {
                    map::DotJobCollapse::Off
                };
                let mut dot =
                    map::render_dot(&graph, job.as_deref(), diagram_label_detail, job_collapse)
                        .into_bytes();
                dot.push(b'\n');
                try_write_stdout(&dot)?;
            }
            GraphFormat::Mermaid => {
                let mut mer =
                    map::render_mermaid(&graph, job.as_deref(), diagram_label_detail).into_bytes();
                mer.push(b'\n');
                try_write_stdout(&mer)?;
            }
        }
    }

    if let Some(ref name) = job {
        if !job_matched_any {
            eprintln!("error: no job named '{name}' found in any scanned file");
            eprintln!("{JOB_NAME_NOT_FOUND}");
            std::process::exit(2);
        }
    }

    Ok(())
}

/// Detect terminal width for table layout.  Reads `$COLUMNS` (set by most
/// interactive shells); falls back to 120 when unset or non-numeric.
fn term_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(120)
}

fn version_report() -> String {
    format!("taudit {}", env!("CARGO_PKG_VERSION"))
}

fn cmd_version() -> Result<()> {
    try_write_stdout(format!("{}\n", version_report()).as_bytes())
}

/// Query crates.io for the latest published version of taudit.
/// Returns `Some(version_string)` only when a **newer** version exists.
/// Returns `None` on any error (network unavailable, timeout, parse failure).
/// Designed to be called from a background thread — never panics.
fn check_latest_version() -> Option<String> {
    let current = env!("CARGO_PKG_VERSION");
    let resp = ureq::get("https://crates.io/api/v1/crates/taudit")
        .timeout(std::time::Duration::from_secs(3))
        .set(
            "User-Agent",
            &format!("taudit/{current} (version-check; https://github.com/0ryant/taudit)"),
        )
        .call()
        .ok()?;
    let json: serde_json::Value = resp.into_json().ok()?;
    let latest = json["crate"]["newest_version"].as_str()?.to_string();
    if latest != current {
        Some(latest)
    } else {
        None
    }
}

fn cmd_update() -> Result<()> {
    use std::io::Write;

    let current = env!("CARGO_PKG_VERSION");
    let stdout = std::io::stdout();
    let mut out = SilenceBrokenPipe {
        inner: stdout.lock(),
    };
    write!(out, "Checking crates.io for updates… ")?;
    match check_latest_version() {
        Some(latest) => {
            writeln!(out, "update available!")?;
            writeln!(out, "  Current : {current}")?;
            writeln!(out, "  Latest  : {latest}")?;
            writeln!(out)?;
            writeln!(
                out,
                "  Run: cargo install taudit --version {latest} --locked"
            )?;
        }
        None => {
            if std::env::var_os("TAUDIT_NO_UPDATE_CHECK").is_some() {
                writeln!(out, "skipped (TAUDIT_NO_UPDATE_CHECK is set)")?;
            } else {
                writeln!(out, "you are up to date ({current})")?;
            }
        }
    }
    Ok(())
}

/// Map a rule's static `security_severity` (CVSS-style numeric string) to a
/// human-friendly severity label for terminal display. Used only by `cmd_explain`.
/// Falls back to "info" for unparseable values rather than panicking.
fn severity_label_for_rule(security_severity: &str) -> &'static str {
    let n: f32 = security_severity.parse().unwrap_or(0.0);
    if n >= 9.0 {
        "critical"
    } else if n >= 7.0 {
        "high"
    } else if n >= 5.0 {
        "medium"
    } else if n >= 1.0 {
        "low"
    } else {
        "info"
    }
}

fn cmd_explain(rule: Option<String>) -> Result<()> {
    use colored::Colorize;
    use std::io::Write;

    let rules = taudit_report_sarif::all_rules();
    let stdout = std::io::stdout();
    let mut out = SilenceBrokenPipe {
        inner: stdout.lock(),
    };

    match rule {
        None => {
            writeln!(out, "{} — {} rules\n", "taudit".bold(), rules.len())?;
            // Two-column layout: left column is widest rule id + padding, then severity, then desc.
            let id_width = rules.iter().map(|r| r.id.len()).max().unwrap_or(0);
            for r in rules {
                let sev = severity_label_for_rule(r.security_severity);
                let sev_colored = match sev {
                    "critical" => sev.red().bold(),
                    "high" => sev.red(),
                    "medium" => sev.yellow(),
                    "low" => sev.cyan(),
                    _ => sev.dimmed(),
                };
                writeln!(
                    out,
                    "  {:<id_width$}  {:<10}  {}",
                    r.id.bold(),
                    sev_colored,
                    r.short_description,
                    id_width = id_width,
                )?;
            }
            writeln!(out)?;
            writeln!(
                out,
                "Use '{}' for full description and remediation guidance.",
                "taudit explain <rule>".bold()
            )?;
            Ok(())
        }
        Some(id) => {
            let Some(r) = rules.iter().find(|r| r.id == id) else {
                eprintln!("error: unknown rule '{id}'");
                eprintln!("{EXPLAIN_RULE}");
                eprintln!();
                eprintln!("valid rule ids:");
                for r in rules {
                    eprintln!("  {}", r.id);
                }
                std::process::exit(2);
            };

            let sev = severity_label_for_rule(r.security_severity);
            let sev_colored = match sev {
                "critical" => sev.red().bold(),
                "high" => sev.red(),
                "medium" => sev.yellow(),
                "low" => sev.cyan(),
                _ => sev.dimmed(),
            };

            writeln!(out, "{} ({})  {}\n", r.id.bold(), r.name, sev_colored,)?;
            writeln!(out, "  {}\n", r.short_description)?;
            // Wrap the full description at ~76 cols with a 2-space indent.
            for line in wrap_paragraph(r.full_description, 76) {
                writeln!(out, "  {line}")?;
            }
            writeln!(out)?;
            writeln!(out, "  Tags: {}", r.tags.join(", "))?;
            writeln!(
                out,
                "\n  See: https://github.com/0ryant/taudit/blob/main/docs/rules/{}.md",
                r.id
            )?;
            Ok(())
        }
    }
}

/// List every loaded authority invariant — built-in plus any custom YAML files
/// from `--invariants-dir`. Prints a plain-text three-column table:
/// `id | severity | source`. Source is `built-in` for the bundled invariants
/// and the YAML file path for custom invariants. Used to verify which
/// invariants will actually run for a given `taudit scan` invocation.
fn cmd_invariants_list(invariants_dir: Option<PathBuf>) -> Result<()> {
    use colored::Colorize;
    use std::io::Write;

    // Built-in invariants come from the SARIF rule registry — same source the
    // `taudit explain` command uses. Severity is derived from the static
    // `security_severity` (CVSS-style) the same way `cmd_explain` does it.
    let built_in = taudit_report_sarif::all_rules();

    // Custom invariants: walk the directory ourselves so we can pair each
    // parsed rule with its source file path. We deliberately do not call
    // `load_rules_dir` here because that helper drops file paths.
    let mut custom: Vec<(PathBuf, taudit_core::custom_rules::CustomRule)> = Vec::new();
    if let Some(dir) = invariants_dir.as_ref() {
        let read_dir = std::fs::read_dir(dir).with_context(|| {
            format!(
                "Failed to read invariants directory {}\n{INVARIANTS_DIR}",
                dir.display()
            )
        })?;
        let mut paths: Vec<PathBuf> = read_dir
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .filter(|p| {
                matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some("yml") | Some("yaml")
                )
            })
            .collect();
        paths.sort();
        for path in paths {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            // Use the multi-doc parser so bundle files (multiple `---`-separated
            // invariants in one file) list every invariant, matching the engine's
            // load path. Single-doc files behave identically.
            let rules = taudit_core::custom_rules::parse_rules_multi_doc(&content)
                .with_context(|| format!("Failed to parse {}", path.display()))?;
            for rule in rules {
                custom.push((path.clone(), rule));
            }
        }
    }

    let stdout = std::io::stdout();
    let mut out = SilenceBrokenPipe {
        inner: stdout.lock(),
    };

    let total = built_in.len() + custom.len();
    writeln!(
        out,
        "{} — {} invariants ({} built-in, {} custom)\n",
        "taudit invariants".bold(),
        total,
        built_in.len(),
        custom.len(),
    )?;

    // Compute column widths from all rows so the table is aligned.
    let id_width = built_in
        .iter()
        .map(|r| r.id.len())
        .chain(custom.iter().map(|(_, r)| r.id.len()))
        .max()
        .unwrap_or(2)
        .max("id".len());
    let sev_width = "severity".len().max("critical".len());

    writeln!(
        out,
        "  {:<id_width$}  {:<sev_width$}  {}",
        "id".bold(),
        "severity".bold(),
        "source".bold(),
        id_width = id_width,
        sev_width = sev_width,
    )?;
    writeln!(
        out,
        "  {:-<id_width$}  {:-<sev_width$}  {:-<20}",
        "",
        "",
        "",
        id_width = id_width,
        sev_width = sev_width,
    )?;

    for r in built_in {
        let sev = severity_label_for_rule(r.security_severity);
        let sev_colored = match sev {
            "critical" => sev.red().bold(),
            "high" => sev.red(),
            "medium" => sev.yellow(),
            "low" => sev.cyan(),
            _ => sev.dimmed(),
        };
        writeln!(
            out,
            "  {:<id_width$}  {:<sev_width$}  {}",
            r.id.bold(),
            sev_colored,
            "built-in".dimmed(),
            id_width = id_width,
            // colored strings inflate the byte count; pad on the visible label width
            sev_width = sev_width + (sev_colored.to_string().len() - sev.len()),
        )?;
    }

    for (path, rule) in &custom {
        let sev = severity_label_for_custom(&rule.severity);
        let sev_colored = match sev {
            "critical" => sev.red().bold(),
            "high" => sev.red(),
            "medium" => sev.yellow(),
            "low" => sev.cyan(),
            _ => sev.dimmed(),
        };
        writeln!(
            out,
            "  {:<id_width$}  {:<sev_width$}  {}",
            rule.id.bold(),
            sev_colored,
            path.display(),
            id_width = id_width,
            sev_width = sev_width + (sev_colored.to_string().len() - sev.len()),
        )?;
    }

    Ok(())
}

// ── `taudit suppressions` subcommand handlers ────────────────────────

struct SuppressionsAddOpts {
    suppressions_path: Option<PathBuf>,
    fingerprint: Option<String>,
    rule_id: Option<String>,
    reason: Option<String>,
    accepted_by: Option<String>,
    accepted_at: Option<String>,
    expires_at: Option<String>,
}

/// `taudit suppressions list` — print every loaded entry with its
/// runtime status (active / expiring-soon / expired / stale-for-review).
fn cmd_suppressions_list(suppressions_path: Option<PathBuf>) -> Result<()> {
    use colored::Colorize;
    use std::io::Write;

    let cfg = load_suppression_config(suppressions_path)?;
    let stdout = std::io::stdout();
    let mut out = SilenceBrokenPipe {
        inner: stdout.lock(),
    };

    if cfg.suppressions.is_empty() {
        writeln!(
            out,
            "no suppressions loaded (.taudit-suppressions.yml absent or empty)"
        )?;
        return Ok(());
    }

    writeln!(
        out,
        "{} — {} suppression{}\n",
        "taudit suppressions".bold(),
        cfg.suppressions.len(),
        if cfg.suppressions.len() == 1 { "" } else { "s" },
    )?;

    let today = today_local();
    let fp_width = cfg
        .suppressions
        .iter()
        .map(|s| s.fingerprint.len())
        .max()
        .unwrap_or(16);
    let rule_width = cfg
        .suppressions
        .iter()
        .map(|s| s.rule_id.len())
        .max()
        .unwrap_or(8);

    for entry in &cfg.suppressions {
        let status = taudit_core::suppressions::SuppressionConfig::status_of(entry, today);
        let label = status.label();
        let labeled = match status {
            taudit_core::suppressions::SuppressionStatus::Active => label.green(),
            taudit_core::suppressions::SuppressionStatus::ExpiringSoon => label.yellow(),
            taudit_core::suppressions::SuppressionStatus::Expired => label.red(),
            taudit_core::suppressions::SuppressionStatus::StaleForReview => label.cyan(),
        };
        let expiry = entry.expires_at.as_deref().unwrap_or("(no expiry)");
        writeln!(
            out,
            "  {:<fp_width$}  {:<rule_width$}  {:<16}  expires={:<12}  by={}",
            entry.fingerprint,
            entry.rule_id,
            labeled,
            expiry,
            entry.accepted_by,
            fp_width = fp_width,
            rule_width = rule_width,
        )?;
        writeln!(out, "    reason: {}", entry.reason)?;
    }
    Ok(())
}

/// `taudit suppressions add` — append a new entry to the suppressions
/// file. All fields can be supplied via flags (scriptable) or prompted
/// interactively when omitted.
fn cmd_suppressions_add(opts: SuppressionsAddOpts) -> Result<()> {
    use std::io::Write;

    // Resolve target file: explicit `--suppressions` or default to
    // `.taudit-suppressions.yml` in CWD.
    let target = opts.suppressions_path.clone().unwrap_or_else(|| {
        std::env::current_dir()
            .ok()
            .map(|p| p.join(".taudit-suppressions.yml"))
            .unwrap_or_else(|| PathBuf::from(".taudit-suppressions.yml"))
    });

    let fingerprint = prompt_or_value(opts.fingerprint, "fingerprint (16 hex chars)")?;
    let rule_id = prompt_or_value(opts.rule_id, "rule_id (snake_case)")?;
    let reason = prompt_or_value(opts.reason, "reason (one-line justification)")?;
    let accepted_by = prompt_or_value(opts.accepted_by, "accepted_by (email or handle)")?;
    let accepted_at = match opts.accepted_at {
        Some(s) => s,
        None => today_local().format("%Y-%m-%d").to_string(),
    };
    let expires_at = opts.expires_at.filter(|s| !s.is_empty());

    let entry = taudit_core::suppressions::Suppression {
        fingerprint,
        rule_id,
        reason,
        accepted_by,
        accepted_at,
        expires_at,
    };

    let body = taudit_core::suppressions::render_entry_yaml(&entry);

    if target.exists() {
        // Append to the existing `suppressions:` list. We do a simple text
        // append so operator-authored comments survive.
        let existing = std::fs::read_to_string(&target)
            .with_context(|| format!("failed to read {}", target.display()))?;
        let mut next = existing;
        if !next.ends_with('\n') {
            next.push('\n');
        }
        next.push_str(&body);
        std::fs::write(&target, next)
            .with_context(|| format!("failed to write {}", target.display()))?;
    } else {
        // Create a fresh file with a header comment.
        let header = "# .taudit-suppressions.yml — see docs/suppressions.md\nsuppressions:\n";
        let mut full = String::from(header);
        full.push_str(&body);
        std::fs::write(&target, full)
            .with_context(|| format!("failed to write {}", target.display()))?;
    }

    let stdout = std::io::stdout();
    let mut out = SilenceBrokenPipe {
        inner: stdout.lock(),
    };
    writeln!(out, "appended suppression to {}", target.display())?;
    Ok(())
}

/// Prompt for `name` on stdin if the operator omitted the flag.
/// Empty input is rejected to avoid silently writing a useless waiver.
fn prompt_or_value(supplied: Option<String>, name: &str) -> Result<String> {
    if let Some(v) = supplied.filter(|s| !s.is_empty()) {
        return Ok(v);
    }
    use std::io::{BufRead, Write};
    let stdout = std::io::stdout();
    let mut out = SilenceBrokenPipe {
        inner: stdout.lock(),
    };
    write!(out, "{name}: ")?;
    out.flush().ok();
    let mut buf = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut buf)
        .with_context(|| format!("failed to read {name} from stdin"))?;
    let trimmed = buf.trim().to_string();
    if trimmed.is_empty() {
        return Err(anyhow::anyhow!(
            "{name} is required (no value supplied)\n{PROMPT_EMPTY}"
        ));
    }
    Ok(trimmed)
}

/// `taudit suppressions review` — list suppressions sorted by
/// `accepted_at`, flagging any older than 90 days for re-review or
/// any with `expires_at` in the past as expired.
fn cmd_suppressions_review(suppressions_path: Option<PathBuf>) -> Result<()> {
    use colored::Colorize;
    use std::io::Write;

    let cfg = load_suppression_config(suppressions_path)?;
    let stdout = std::io::stdout();
    let mut out = SilenceBrokenPipe {
        inner: stdout.lock(),
    };

    if cfg.suppressions.is_empty() {
        writeln!(out, "no suppressions to review")?;
        return Ok(());
    }

    let today = today_local();
    // Sort by accepted_at ascending (oldest first) so reviewers see the
    // staleness gradient at a glance.
    let mut entries: Vec<&taudit_core::suppressions::Suppression> =
        cfg.suppressions.iter().collect();
    entries.sort_by(|a, b| a.accepted_at.cmp(&b.accepted_at));

    let mut needs_review = 0;
    writeln!(
        out,
        "{} — review {} suppression{}\n",
        "taudit suppressions review".bold(),
        entries.len(),
        if entries.len() == 1 { "" } else { "s" },
    )?;

    for entry in entries {
        let status = taudit_core::suppressions::SuppressionConfig::status_of(entry, today);
        let label = status.label();
        let attention = matches!(
            status,
            taudit_core::suppressions::SuppressionStatus::Expired
                | taudit_core::suppressions::SuppressionStatus::StaleForReview
                | taudit_core::suppressions::SuppressionStatus::ExpiringSoon
        );
        if attention {
            needs_review += 1;
        }
        let labeled = match status {
            taudit_core::suppressions::SuppressionStatus::Active => label.green(),
            taudit_core::suppressions::SuppressionStatus::ExpiringSoon => label.yellow(),
            taudit_core::suppressions::SuppressionStatus::Expired => label.red(),
            taudit_core::suppressions::SuppressionStatus::StaleForReview => label.cyan(),
        };
        writeln!(
            out,
            "  {}  rule={}  status={}  accepted_at={}  by={}",
            entry.fingerprint, entry.rule_id, labeled, entry.accepted_at, entry.accepted_by
        )?;
        if let Some(ref expiry) = entry.expires_at {
            writeln!(out, "    expires_at: {expiry}")?;
        }
        writeln!(out, "    reason: {}", entry.reason)?;
    }

    writeln!(out)?;
    if needs_review == 0 {
        writeln!(out, "{}", "all suppressions look healthy".green())?;
    } else {
        writeln!(
            out,
            "{} entr{} need{} review",
            needs_review,
            if needs_review == 1 { "y" } else { "ies" },
            if needs_review == 1 { "s" } else { "" },
        )?;
    }
    Ok(())
}

/// Map a `Severity` enum value to the same lowercase label used by
/// `severity_label_for_rule` so the invariants list table is consistent
/// regardless of whether a row originated from a built-in (CVSS-derived)
/// or a custom YAML invariant (enum-typed).
fn severity_label_for_custom(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

/// Tiny word-wrap for `cmd_explain`'s full description block. Avoids pulling in
/// a dep just for this one display path. Splits on ASCII whitespace and packs
/// words greedily into lines no longer than `width`. A single word longer than
/// `width` is emitted on its own line uncut.
fn wrap_paragraph(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn cmd_emit_spec(
    target: PathBuf,
    id: String,
    ttl_seconds: u64,
    severity_threshold: Option<SeverityLevel>,
    quiet: bool,
    output: Option<PathBuf>,
    platform: Platform,
) -> Result<()> {
    let working_dir = std::env::current_dir().context("Failed to resolve current directory")?;
    let spec = build_cellos_spec(
        &id,
        ttl_seconds,
        working_dir.to_string_lossy().as_ref(),
        target.to_string_lossy().as_ref(),
        severity_threshold.as_ref(),
        quiet,
        &platform,
    );
    let rendered = serde_json::to_string_pretty(&spec).context("Failed to render spec JSON")?;

    if let Some(path) = output {
        std::fs::write(&path, rendered).with_context(|| {
            format!("Failed to write spec to {}\n{OUTPUT_FILE}", path.display())
        })?;
        eprintln!("Wrote CellOS spec to {}", path.display());
    } else {
        try_println!("{rendered}")?;
    }

    Ok(())
}

fn build_cellos_spec(
    id: &str,
    ttl_seconds: u64,
    working_directory: &str,
    target: &str,
    severity_threshold: Option<&SeverityLevel>,
    quiet: bool,
    platform: &Platform,
) -> serde_json::Value {
    let mut argv = vec![
        "taudit".to_string(),
        "scan".to_string(),
        target.to_string(),
        "--format".to_string(),
        "json".to_string(),
        "--no-color".to_string(),
        "--platform".to_string(),
        platform.as_str().to_string(),
    ];

    if let Some(level) = severity_threshold {
        argv.push("--severity-threshold".to_string());
        argv.push(level.to_arg().to_string());
    }
    if quiet {
        argv.push("--quiet".to_string());
    }

    serde_json::json!({
      "apiVersion": "cellos.io/v1",
      "kind": "ExecutionCell",
      "spec": {
        "id": id,
        "authority": {
          "secretRefs": [],
          "egressRules": []
        },
        "lifetime": { "ttlSeconds": ttl_seconds },
        "run": {
          "argv": argv,
          "workingDirectory": working_directory
        }
      }
    })
}

fn make_parser(platform: &Platform) -> Box<dyn taudit_core::ports::PipelineParser> {
    match platform {
        // `Auto` should be resolved to a concrete platform per-file before reaching
        // this function. If it slips through (e.g. an empty path list never triggers
        // detection), fall back to the GHA parser to preserve historical behavior.
        Platform::Auto | Platform::GithubActions => Box::new(GhaParser),
        Platform::AzureDevOps => Box::new(AdoParser),
        Platform::GitLab => Box::new(GitlabParser),
    }
}

/// Resolve `Platform::Auto` against a YAML body. Returns the platform unchanged
/// when it's already concrete. The optional `path` is used as a strong filename
/// hint when present (see [`detect_platform`]).
fn resolve_platform(platform: &Platform, content: &str, path: Option<&Path>) -> Platform {
    match platform {
        Platform::Auto => detect_platform(content, path),
        Platform::GithubActions => Platform::GithubActions,
        Platform::AzureDevOps => Platform::AzureDevOps,
        Platform::GitLab => Platform::GitLab,
    }
}

/// Normalise CRLF → LF so every downstream consumer (parser, hash, baseline)
/// sees identical content regardless of `git core.autocrlf` or platform.
/// Called immediately after every `read_to_string` on a pipeline file.
#[inline]
fn normalise_line_endings(s: String) -> String {
    if s.contains('\r') {
        s.replace("\r\n", "\n")
    } else {
        s
    }
}

fn parse_content(
    parser: &dyn taudit_core::ports::PipelineParser,
    content: String,
    source_file: String,
) -> Result<taudit_core::graph::AuthorityGraph> {
    let source = PipelineSource {
        file: source_file.clone(),
        repo: None,
        git_ref: None,
        commit_sha: None,
    };
    // Normalise at the parse boundary so parser, hash and baseline all see LF.
    let content = normalise_line_endings(content);
    parser.parse(&content, &source).with_context(|| {
        format!(
            "Failed to parse {source_file}\n\
             hint: confirm the file is valid CI YAML for the selected --platform (use `auto` to detect); see `taudit scan --help`"
        )
    })
}

fn parse_file(
    parser: &dyn taudit_core::ports::PipelineParser,
    path: &PathBuf,
) -> Result<taudit_core::graph::AuthorityGraph> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}\n{PATH_NOT_FOUND}", path.display()))?;
    parse_content(parser, content, path.display().to_string())
}

enum ResolvedPath {
    Explicit(PathBuf),
    Discovered(PathBuf),
}

impl ResolvedPath {
    fn path(&self) -> &PathBuf {
        match self {
            ResolvedPath::Explicit(p) | ResolvedPath::Discovered(p) => p,
        }
    }
}

/// Like `resolve_paths`, but tags each result so callers can distinguish
/// explicitly-named paths (hard-fail on parse error) from directory-walked
/// paths (soft-fail with a warning, e.g. wrong-platform YAML in a tree).
fn resolve_paths_tagged(paths: &[PathBuf]) -> Result<Vec<ResolvedPath>> {
    let mut result = Vec::new();
    for path in paths {
        if path.as_os_str() == "-" {
            result.push(ResolvedPath::Explicit(path.clone()));
        } else if path.is_dir() {
            for entry in walkdir(path)? {
                if let Some(ext) = entry.extension() {
                    if ext == "yml" || ext == "yaml" {
                        result.push(ResolvedPath::Discovered(entry));
                    }
                }
            }
        } else if path.is_file() {
            result.push(ResolvedPath::Explicit(path.clone()));
        } else {
            anyhow::bail!("Path not found: {}\n{}", path.display(), PATH_NOT_FOUND);
        }
    }
    Ok(result)
}

/// Resolve paths: if a directory, find all .yml/.yaml files recursively.
/// If a file, use it directly. `-` is passed through as the stdin sentinel.
///
/// Retained for callers that want a flat path list without tagged hard/soft-fail
/// semantics (see `resolve_paths_tagged` for the directory-walk soft-fail variant).
#[allow(dead_code)]
fn resolve_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();

    for path in paths {
        if path.as_os_str() == "-" {
            result.push(path.clone());
        } else if path.is_dir() {
            for entry in walkdir(path)? {
                if let Some(ext) = entry.extension() {
                    if ext == "yml" || ext == "yaml" {
                        result.push(entry);
                    }
                }
            }
        } else if path.is_file() {
            result.push(path.clone());
        } else {
            anyhow::bail!("Path not found: {}\n{}", path.display(), PATH_NOT_FOUND);
        }
    }

    Ok(result)
}

/// Simple recursive directory walker (no extra deps).
fn walkdir(dir: &PathBuf) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            files.extend(walkdir(&path)?);
        } else {
            files.push(path);
        }
    }
    Ok(files)
}

// ── Baseline subcommand ─────────────────────────────────────
//
// Per-pipeline state lives at `<root>/.taudit/baselines/<hash>.json` (one
// file per pipeline, keyed by SHA-256 of the pipeline content). The
// fingerprint algorithm is shared with SARIF/JSON/CloudEvents — see
// `taudit_core::baselines` for the load-bearing decisions.

fn cmd_baseline(action: BaselineAction) -> Result<()> {
    match action {
        BaselineAction::Init {
            paths,
            root,
            captured_by,
            platform,
            max_hops,
            invariants_dir,
        } => cmd_baseline_init(paths, root, captured_by, platform, max_hops, invariants_dir),
        BaselineAction::Accept {
            pipeline,
            fingerprint,
            rule_id,
            severity,
            reason,
            severity_override,
            expires_at,
            root,
        } => cmd_baseline_accept(
            pipeline,
            fingerprint,
            rule_id,
            severity,
            reason,
            severity_override,
            expires_at,
            root,
        ),
        BaselineAction::Diff {
            paths,
            root,
            platform,
            max_hops,
            invariants_dir,
        } => cmd_baseline_diff(paths, root, platform, max_hops, invariants_dir),
        BaselineAction::Review { root } => cmd_baseline_review(root),
    }
}

/// Resolve the repository root for baseline storage. Defaults to CWD when
/// the user did not pass `--root`.
fn baseline_root(root: Option<PathBuf>) -> Result<PathBuf> {
    match root {
        Some(p) => Ok(p),
        None => std::env::current_dir().with_context(|| "Failed to resolve current directory"),
    }
}

/// Pick a sensible `captured_by` identity: `--captured-by` wins, then
/// `$USER@$HOSTNAME`, then `$USER`, else `unknown@local`.
fn resolve_captured_by(supplied: Option<String>) -> String {
    if let Some(s) = supplied {
        return s;
    }
    let user = std::env::var("USER").ok();
    let host = std::env::var("HOSTNAME").ok();
    match (user, host) {
        (Some(u), Some(h)) if !u.is_empty() && !h.is_empty() => format!("{u}@{h}"),
        (Some(u), _) if !u.is_empty() => u,
        _ => "unknown@local".to_string(),
    }
}

/// Free-form description of the loaded rule set, recorded in
/// `captured_with.rules_version`. Built-ins are counted from the explain
/// table; custom rules are counted from the loaded set.
fn rules_version_label(custom_count: usize) -> String {
    // Built-in rule count — kept in sync with `taudit_report_sarif::all_rules().len()`.
    // Update whenever a rule is added to or removed from the SARIF registry.
    const BUILTIN_COUNT: usize = 61;
    if custom_count == 0 {
        format!("{BUILTIN_COUNT}-builtin")
    } else {
        format!("{BUILTIN_COUNT}-builtin+{custom_count}-custom")
    }
}

/// Run the loaded rules over a parsed graph, returning the full finding set
/// (built-ins plus custom). Mirrors what `cmd_scan` does internally so the
/// baseline captures the same fingerprints `scan` would emit.
fn run_all_findings(
    graph: &taudit_core::graph::AuthorityGraph,
    custom_rules: &[taudit_core::custom_rules::CustomRule],
    max_hops: usize,
) -> Vec<taudit_core::finding::Finding> {
    let mut findings = rules::run_all_rules(graph, max_hops);
    if !custom_rules.is_empty() {
        let paths = taudit_core::propagation::propagation_analysis(graph, max_hops);
        findings.extend(taudit_core::custom_rules::evaluate_custom_rules(
            graph,
            paths.as_slice(),
            custom_rules,
        ));
    }
    findings
}

/// Load custom invariants from `--invariants-dir` or return an empty Vec.
/// Errors are bubbled as exit-2 the same way `scan` and `verify` do.
fn load_custom_rules(
    invariants_dir: Option<&PathBuf>,
) -> Result<Vec<taudit_core::custom_rules::CustomRule>> {
    match invariants_dir {
        Some(dir) => taudit_core::custom_rules::load_rules_dir(dir).map_err(|errs| {
            let joined = errs
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            anyhow::anyhow!("failed to load invariants from {}: {joined}", dir.display())
        }),
        None => Ok(Vec::new()),
    }
}

fn cmd_baseline_init(
    paths: Vec<PathBuf>,
    root: Option<PathBuf>,
    captured_by: Option<String>,
    platform: Platform,
    max_hops: usize,
    invariants_dir: Option<PathBuf>,
) -> Result<()> {
    let root = baseline_root(root)?;
    let captured_by = resolve_captured_by(captured_by);
    let custom_rules = load_custom_rules(invariants_dir.as_ref())?;
    let rules_label = rules_version_label(custom_rules.len());
    let now = chrono::Utc::now();
    let resolved = resolve_paths_tagged(&paths)?;

    let mut written = 0usize;
    let mut skipped = 0usize;

    for tagged in &resolved {
        let path = tagged.path();
        let content = match std::fs::read_to_string(path) {
            Ok(c) => normalise_line_endings(c),
            Err(err) => match tagged {
                ResolvedPath::Discovered(_) => {
                    eprintln!("warning: skipping {}: {err}", path.display());
                    skipped += 1;
                    continue;
                }
                ResolvedPath::Explicit(_) => {
                    return Err(anyhow::Error::new(err)
                        .context(format!("Failed to read {}", path.display())));
                }
            },
        };

        let resolved_platform = resolve_platform(&platform, &content, Some(path));
        let parser = make_parser(&resolved_platform);
        let graph =
            match parse_content(parser.as_ref(), content.clone(), path.display().to_string()) {
                Ok(g) => g,
                Err(err) => match tagged {
                    ResolvedPath::Discovered(_) => {
                        eprintln!("warning: skipping {}: {err:#}", path.display());
                        skipped += 1;
                        continue;
                    }
                    ResolvedPath::Explicit(_) => return Err(err),
                },
            };

        let findings = run_all_findings(&graph, &custom_rules, max_hops);

        let baseline = taudit_core::baselines::Baseline::from_findings(
            &path.display().to_string(),
            &content,
            &graph,
            &findings,
            &captured_by,
            env!("CARGO_PKG_VERSION"),
            &rules_label,
            now,
        );
        let target =
            taudit_core::baselines::baseline_path_for(&root, &baseline.pipeline_content_hash);
        baseline
            .save(&target)
            .with_context(|| format!("Failed to write baseline {}", target.display()))?;
        try_println!(
            "wrote {} ({} finding{})",
            target.display(),
            baseline.baseline_findings.len(),
            if baseline.baseline_findings.len() == 1 {
                ""
            } else {
                "s"
            }
        )?;
        written += 1;
    }

    try_println!(
        "{written} baseline{} written{}",
        if written == 1 { "" } else { "s" },
        if skipped > 0 {
            format!(", {skipped} skipped")
        } else {
            String::new()
        }
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_baseline_accept(
    pipeline: PathBuf,
    fingerprint: String,
    rule_id: String,
    severity: SeverityLevel,
    reason: String,
    severity_override: Option<SeverityLevel>,
    expires_at: Option<String>,
    root: Option<PathBuf>,
) -> Result<()> {
    let root = baseline_root(root)?;
    let content = std::fs::read_to_string(&pipeline)
        .with_context(|| format!("Failed to read pipeline {}", pipeline.display()))?;
    let hash = taudit_core::baselines::compute_pipeline_hash(&content);
    let target = taudit_core::baselines::baseline_path_for(&root, &hash);

    let mut baseline = match taudit_core::baselines::Baseline::load(&target)? {
        Some(b) => b,
        None => anyhow::bail!(
            "no baseline at {} — run `taudit baseline init {}` first",
            target.display(),
            pipeline.display()
        ),
    };

    let expires_dt: Option<chrono::DateTime<chrono::Utc>> = match expires_at {
        Some(s) => Some(parse_iso8601(&s)?),
        None => None,
    };
    let now = chrono::Utc::now();

    baseline
        .accept(
            &fingerprint,
            &rule_id,
            severity.to_severity(),
            &reason,
            severity_override.as_ref().map(|s| s.to_severity()),
            expires_dt,
            now,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    baseline.save(&target)?;
    try_println!("accepted {fingerprint} into {}", target.display())?;
    Ok(())
}

fn cmd_baseline_diff(
    paths: Vec<PathBuf>,
    root: Option<PathBuf>,
    platform: Platform,
    max_hops: usize,
    invariants_dir: Option<PathBuf>,
) -> Result<()> {
    let root = baseline_root(root)?;
    let custom_rules = load_custom_rules(invariants_dir.as_ref())?;
    let resolved = resolve_paths_tagged(&paths)?;
    let now = chrono::Utc::now();

    for tagged in &resolved {
        let path = tagged.path();
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(err) => match tagged {
                ResolvedPath::Discovered(_) => {
                    eprintln!("warning: skipping {}: {err}", path.display());
                    continue;
                }
                ResolvedPath::Explicit(_) => {
                    return Err(anyhow::Error::new(err)
                        .context(format!("Failed to read {}", path.display())));
                }
            },
        };
        let resolved_platform = resolve_platform(&platform, &content, Some(path));
        let parser = make_parser(&resolved_platform);
        let graph = parse_content(parser.as_ref(), content.clone(), path.display().to_string())?;
        let findings = run_all_findings(&graph, &custom_rules, max_hops);

        let hash = taudit_core::baselines::compute_pipeline_hash(&content);
        let target = taudit_core::baselines::baseline_path_for(&root, &hash);
        match taudit_core::baselines::Baseline::load(&target)? {
            Some(baseline) => {
                if !baseline.identity_material_matches(&graph) {
                    try_println!(
                        "{}: baseline identity material mismatch at {} (re-run `taudit baseline init {}`)",
                        path.display(),
                        target.display(),
                        path.display()
                    )?;
                    continue;
                }
                let diff = taudit_core::baselines::diff(&findings, &baseline, &graph);
                let unwaived = diff.preexisting.len() - diff.waived_count;
                let blockers = diff.critical_without_valid_waiver(&baseline, &graph, now);
                try_println!(
                    "{}: {} NEW, {} FIXED, {} PRE-EXISTING ({} waived, {} unwaived){}",
                    path.display(),
                    diff.new.len(),
                    diff.fixed.len(),
                    diff.preexisting.len(),
                    diff.waived_count,
                    unwaived,
                    if blockers.is_empty() {
                        String::new()
                    } else {
                        format!(" — {} CRITICAL without valid waiver", blockers.len())
                    },
                )?;
            }
            None => {
                try_println!(
                    "{}: no baseline at {} (run `taudit baseline init {}`)",
                    path.display(),
                    target.display(),
                    path.display()
                )?;
            }
        }
    }
    try_println!("Use 'taudit baseline review' to see waivers.")?;
    Ok(())
}

fn cmd_baseline_review(root: Option<PathBuf>) -> Result<()> {
    let root = baseline_root(root)?;
    let dir = taudit_core::baselines::baselines_dir(&root);
    if !dir.exists() {
        try_println!("no baselines at {} (nothing to review)", dir.display())?;
        return Ok(());
    }
    let mut waivers: Vec<(String, taudit_core::baselines::BaselineFinding)> = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .with_context(|| format!("Failed to read baselines dir {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let baseline = match taudit_core::baselines::Baseline::load(&path)? {
            Some(b) => b,
            None => continue,
        };
        for f in &baseline.baseline_findings {
            if f.reason_waived.is_some() {
                waivers.push((baseline.pipeline_path.clone(), f.clone()));
            }
        }
    }

    if waivers.is_empty() {
        try_println!("no waivers across {} baselines", count_baselines(&dir)?)?;
        return Ok(());
    }

    // Sort: expired first, then expiring soonest. Entries without expires_at
    // sort to the end, but critical-without-expires_at is flagged inline.
    waivers.sort_by(|a, b| match (a.1.expires_at, b.1.expires_at) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });

    let now = chrono::Utc::now();
    let mut errors = 0usize;
    try_println!("waiver review ({} entries)", waivers.len())?;
    for (pipeline, w) in &waivers {
        let expiry = match w.expires_at {
            Some(t) => {
                if t <= now {
                    format!("EXPIRED {}", t.to_rfc3339())
                } else {
                    format!("expires {}", t.to_rfc3339())
                }
            }
            None => "no expires_at".to_string(),
        };
        let critical_without_expiry =
            w.severity_override == Some(Severity::Critical) && w.expires_at.is_none();
        let flag = if critical_without_expiry {
            errors += 1;
            " [ERROR: critical waiver without expires_at]"
        } else {
            ""
        };
        try_println!(
            "  {} :: {} :: {} :: {} :: {}{}",
            pipeline,
            w.fingerprint,
            w.rule_id,
            expiry,
            w.reason_waived.as_deref().unwrap_or(""),
            flag
        )?;
    }
    if errors > 0 {
        anyhow::bail!("{errors} critical waiver(s) without expires_at — fix before merge");
    }
    Ok(())
}

fn count_baselines(dir: &std::path::Path) -> Result<usize> {
    let mut n = 0usize;
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read baselines dir {}", dir.display()))?
    {
        let entry = entry?;
        if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
            n += 1;
        }
    }
    Ok(n)
}

fn parse_iso8601(s: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&chrono::Utc))
        .with_context(|| format!("--expires-at must be RFC3339 / ISO-8601 (got {s:?})"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use taudit_core::finding::{
        Finding, FindingCategory, FindingExtras, FindingSource, Recommendation, Severity,
    };

    fn finding(severity: Severity, category: FindingCategory, msg: &str) -> Finding {
        Finding {
            severity,
            category,
            path: None,
            nodes_involved: vec![],
            message: msg.to_string(),
            recommendation: Recommendation::Manual {
                action: "review".to_string(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        }
    }

    #[test]
    fn diff_findings_detects_added_and_removed() {
        let before = vec![
            finding(
                Severity::High,
                FindingCategory::UnpinnedAction,
                "unpinned checkout",
            ),
            finding(
                Severity::Medium,
                FindingCategory::OverPrivilegedIdentity,
                "write-all token",
            ),
        ];

        let after = vec![
            finding(
                Severity::High,
                FindingCategory::UnpinnedAction,
                "unpinned checkout",
            ),
            finding(
                Severity::Critical,
                FindingCategory::AuthorityPropagation,
                "secret reaches untrusted step",
            ),
        ];

        let (added, removed) = diff_findings(&before, &after);
        assert_eq!(added.len(), 1);
        assert_eq!(removed.len(), 1);
        assert_eq!(added[0].category, FindingCategory::AuthorityPropagation);
        assert_eq!(removed[0].category, FindingCategory::OverPrivilegedIdentity);
    }

    #[test]
    fn diff_findings_treats_severity_change_as_delta() {
        let before = vec![finding(
            Severity::Medium,
            FindingCategory::AuthorityPropagation,
            "same message",
        )];
        let after = vec![finding(
            Severity::High,
            FindingCategory::AuthorityPropagation,
            "same message",
        )];

        let (added, removed) = diff_findings(&before, &after);
        assert_eq!(added.len(), 1);
        assert_eq!(removed.len(), 1);
        assert_eq!(added[0].severity, Severity::High);
        assert_eq!(removed[0].severity, Severity::Medium);
    }

    #[test]
    fn version_report_includes_package_version() {
        let report = version_report();
        assert!(report.starts_with("taudit "));
        assert!(report.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn build_cellos_spec_contains_required_shape() {
        let spec = build_cellos_spec(
            "taudit-cellos-scan",
            120,
            "/workspace",
            "tests/fixtures/clean.yml",
            Some(&SeverityLevel::Critical),
            true,
            &Platform::GithubActions,
        );

        assert_eq!(spec["apiVersion"], "cellos.io/v1");
        assert_eq!(spec["kind"], "ExecutionCell");
        assert_eq!(spec["spec"]["id"], "taudit-cellos-scan");
        assert_eq!(spec["spec"]["lifetime"]["ttlSeconds"], 120);
        assert_eq!(spec["spec"]["run"]["workingDirectory"], "/workspace");

        let argv = spec["spec"]["run"]["argv"].as_array().unwrap();
        assert!(argv.iter().any(|v| v == "taudit"));
        assert!(argv.iter().any(|v| v == "scan"));
        assert!(argv.iter().any(|v| v == "--severity-threshold"));
        assert!(argv.iter().any(|v| v == "critical"));
        assert!(argv.iter().any(|v| v == "--quiet"));
        assert!(argv.iter().any(|v| v == "--no-color"));
        assert!(argv.iter().any(|v| v == "--platform"));
        assert!(argv.iter().any(|v| v == "github-actions"));
    }

    #[test]
    fn resolve_runtime_artifact_paths_prefers_explicit_values() {
        let telemetry = PathBuf::from("/tmp/telemetry-explicit");
        let receipt = PathBuf::from("/tmp/receipt-explicit");
        let log = PathBuf::from("/tmp/log-explicit");

        let resolved = resolve_runtime_artifact_paths(
            Some(telemetry.clone()),
            Some(receipt.clone()),
            Some(log.clone()),
        );

        assert_eq!(resolved.telemetry_dir, Some(telemetry));
        assert_eq!(resolved.receipt_dir, Some(receipt));
        assert_eq!(resolved.log_dir, Some(log));
    }

    #[test]
    fn output_format_as_str_matches_cli_values() {
        assert_eq!(OutputFormat::Terminal.as_str(), "terminal");
        assert_eq!(OutputFormat::Json.as_str(), "json");
        assert_eq!(OutputFormat::Sarif.as_str(), "sarif");
        assert_eq!(OutputFormat::Cloudevents.as_str(), "cloudevents");
    }

    #[test]
    fn auto_detects_github_actions() {
        // Top-level `on:` is the GHA-only trigger key.
        let yaml = "name: ci\non:\n  push:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
        assert_eq!(detect_platform_from_content(yaml), Platform::GithubActions);
    }

    #[test]
    fn auto_detects_azure_devops() {
        // ADO uses `trigger:` / `pr:` / `stages:` / `jobs:` without `on:`.
        let yaml = "trigger:\n  branches:\n    include: [main]\nstages:\n  - stage: build\n    jobs:\n      - job: compile\n        steps:\n          - script: echo hi\n";
        assert_eq!(detect_platform_from_content(yaml), Platform::AzureDevOps);
    }

    #[test]
    fn auto_falls_back_to_github_actions_when_yaml_unparseable() {
        let yaml = "::: this is not yaml :::\n  - and: [oops";
        assert_eq!(detect_platform_from_content(yaml), Platform::GithubActions);
    }

    #[test]
    fn auto_falls_back_to_github_actions_when_no_markers() {
        let yaml = "name: hello\nversion: 1\n";
        assert_eq!(detect_platform_from_content(yaml), Platform::GithubActions);
    }

    #[test]
    fn auto_detects_gitlab_ci_by_stages_string_list() {
        let yaml = "stages:\n  - build\n  - test\n  - deploy\n\nbuild-job:\n  stage: build\n  script:\n    - make\n";
        assert_eq!(detect_platform_from_content(yaml), Platform::GitLab);
    }

    #[test]
    fn stages_object_list_still_detects_ado_not_gitlab() {
        // ADO stages: is a list of objects, not strings
        let yaml = "trigger:\n  - main\nstages:\n  - stage: build\n    jobs:\n      - job: compile\n        steps:\n          - script: echo hi\n";
        assert_eq!(detect_platform_from_content(yaml), Platform::AzureDevOps);
    }

    #[test]
    fn auto_detects_gitlab_ci_by_image_key() {
        // GitLab CI with image: at top level but no stages:
        let yaml = "image: alpine:latest\n\nbuild:\n  script:\n    - make\n";
        assert_eq!(detect_platform_from_content(yaml), Platform::GitLab);
    }

    // -------- path-based detection (fuzz B2 regression) --------

    #[test]
    fn path_hint_gitlab_overrides_gha_content() {
        // Fuzz B2 reproducer: a `.gitlab-ci.yml` file containing a stray
        // top-level `on:` previously routed through the GHA parser and
        // dropped the gitlab `test:` job. Filename now wins.
        let yaml =
            "on:\n  push:\nstages:\n  - test\n\ntest:\n  stage: test\n  script:\n    - make test\n";
        let path = Path::new(".gitlab-ci.yml");
        assert_eq!(detect_platform(yaml, Some(path)), Platform::GitLab);
    }

    #[test]
    fn path_hint_gitlab_suffix_variant() {
        let yaml = "stages:\n  - build\nbuild:\n  script:\n    - make\n";
        let path = Path::new("backend/release-gitlab-ci.yml");
        assert_eq!(detect_platform(yaml, Some(path)), Platform::GitLab);
    }

    #[test]
    fn path_hint_ado_filename() {
        let yaml = "trigger:\n  - main\nstages:\n  - stage: build\n    jobs:\n      - job: c\n        steps:\n          - script: echo\n";
        let path = Path::new("azure-pipelines.yml");
        assert_eq!(detect_platform(yaml, Some(path)), Platform::AzureDevOps);
    }

    #[test]
    fn path_hint_ado_pipelines_dir() {
        let yaml = "trigger:\n  - main\nstages:\n  - stage: build\n    jobs:\n      - job: c\n        steps:\n          - script: echo\n";
        let path = Path::new(".pipelines/build.yml");
        assert_eq!(detect_platform(yaml, Some(path)), Platform::AzureDevOps);
    }

    #[test]
    fn path_hint_gha_workflows_dir() {
        let yaml = "name: ci\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n";
        let path = Path::new(".github/workflows/ci.yml");
        assert_eq!(detect_platform(yaml, Some(path)), Platform::GithubActions);
    }

    #[test]
    fn path_hint_no_filename_falls_back_to_content() {
        // No path → pure content sniff (GHA via `on:`).
        let yaml = "name: ci\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n";
        assert_eq!(detect_platform(yaml, None), Platform::GithubActions);
    }

    #[test]
    fn path_hint_uninformative_path_falls_back_to_content() {
        // `pipeline.yml` in the repo root is not a recognised pattern.
        let yaml = "name: ci\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n";
        let path = Path::new("pipeline.yml");
        assert_eq!(detect_platform(yaml, Some(path)), Platform::GithubActions);
    }

    #[test]
    fn path_from_path_helper_unambiguous_cases() {
        assert_eq!(
            platform_from_path(Path::new(".gitlab-ci.yml")),
            Some(Platform::GitLab)
        );
        assert_eq!(
            platform_from_path(Path::new("a/b/.gitlab-ci.yml")),
            Some(Platform::GitLab)
        );
        assert_eq!(
            platform_from_path(Path::new("azure-pipelines-prod.yml")),
            Some(Platform::AzureDevOps)
        );
        assert_eq!(
            platform_from_path(Path::new(".azuredevops/build.yml")),
            Some(Platform::AzureDevOps)
        );
        assert_eq!(
            platform_from_path(Path::new("repo/.github/workflows/x.yml")),
            Some(Platform::GithubActions)
        );
        assert_eq!(platform_from_path(Path::new("misc.yml")), None);
    }

    // -------- verify command tests --------
    //
    // The three tests below pin the exit-code contract for `taudit verify`:
    //
    //   exit 0 — no policy violations
    //   exit 1 — at least one policy violation
    //   exit 2 — usage / file-not-found / parse error
    //
    // They drive `run_verify_io` directly (not via subprocess) so the assertions
    // are deterministic and don't depend on a built binary.

    fn write_tmp(name: &str, content: &str) -> PathBuf {
        // PID + nanos-since-epoch keeps fixtures unique even when tests run
        // in parallel inside the same temp dir.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "taudit-verify-{}-{nanos}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("tmp dir create");
        let path = dir.join(name);
        std::fs::write(&path, content).expect("tmp write");
        path
    }

    /// A pipeline with no propagation — no invariant should fire.
    fn clean_pipeline_yaml() -> &'static str {
        "name: ci\non: push\npermissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29\n      - run: cargo test\n"
    }

    /// A pipeline that puts a secret on a step and delegates to an untrusted
    /// third-party action — guaranteed to produce an authority propagation
    /// path that any "secret -> untrusted" invariant will catch.
    fn leaky_pipeline_yaml() -> &'static str {
        "name: release\non:\n  push:\n    tags: ['v*']\npermissions: write-all\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29\n      - uses: untrusted-org/publish-action@main\n        with:\n          api-key: \"${{ secrets.PUBLISH_API_KEY }}\"\n"
    }

    /// "Any first-party authority that crosses into an untrusted zone."
    /// The clean fixture has no untrusted sinks (no third-party `@main`
    /// actions, no untrusted steps), so this never fires there. The leaky
    /// fixture delegates to `untrusted-org/publish-action@main` which lands
    /// in the Untrusted trust zone — this invariant catches it.
    fn untrusted_sink_invariant_yaml() -> &'static str {
        "id: any_to_untrusted\nname: Authority reaches untrusted sink\ndescription: catch-all for untrusted propagation\nseverity: high\ncategory: authority_propagation\nmatch:\n  sink:\n    trust_zone: untrusted\n"
    }

    #[test]
    fn verify_clean_fixture_exits_zero() {
        let pipeline = write_tmp("clean.yml", clean_pipeline_yaml());
        let policy = write_tmp("policy.yml", untrusted_sink_invariant_yaml());

        let opts = VerifyOpts {
            paths: vec![pipeline],
            policy,
            format: VerifyFormat::Text,
            platform: Platform::GithubActions,
            max_hops: DEFAULT_MAX_HOPS,
            include_builtin: false,
            severity_threshold: None,
            output: None,
            suppressions: None,
            suppression_mode: SuppressionModeArg::Downgrade,
            gate_on_all: false,
            strict: false,
            baseline_root: None,
            ignore_partial: false,
        };

        let mut buf = Vec::new();
        let code = run_verify_io(&opts, &mut buf);
        let output = String::from_utf8_lossy(&buf);
        assert_eq!(
            code, 0,
            "expected clean fixture to exit 0, output: {output}"
        );
        assert!(
            output.contains("verify: 0 violations"),
            "missing summary: {output}"
        );
        assert!(
            output.contains("verify: authority graph modeling:"),
            "expected completeness rollup in verify text: {output}"
        );
    }

    #[test]
    fn verify_violating_fixture_exits_one() {
        let pipeline = write_tmp("leaky.yml", leaky_pipeline_yaml());
        let policy = write_tmp("policy.yml", untrusted_sink_invariant_yaml());

        let opts = VerifyOpts {
            paths: vec![pipeline],
            policy,
            format: VerifyFormat::Text,
            platform: Platform::GithubActions,
            max_hops: DEFAULT_MAX_HOPS,
            include_builtin: false,
            severity_threshold: None,
            output: None,
            suppressions: None,
            suppression_mode: SuppressionModeArg::Downgrade,
            gate_on_all: false,
            strict: false,
            baseline_root: None,
            ignore_partial: false,
        };

        let mut buf = Vec::new();
        let code = run_verify_io(&opts, &mut buf);
        let output = String::from_utf8_lossy(&buf);
        assert_eq!(
            code, 1,
            "expected leaky fixture to exit 1, output: {output}"
        );
        assert!(
            output.contains("any_to_untrusted"),
            "expected invariant id in output: {output}"
        );
    }

    #[test]
    fn verify_missing_policy_exits_two() {
        let pipeline = write_tmp("any.yml", clean_pipeline_yaml());
        let opts = VerifyOpts {
            paths: vec![pipeline],
            policy: PathBuf::from("/nonexistent/path/policy.yml"),
            format: VerifyFormat::Text,
            platform: Platform::GithubActions,
            max_hops: DEFAULT_MAX_HOPS,
            include_builtin: false,
            severity_threshold: None,
            output: None,
            suppressions: None,
            suppression_mode: SuppressionModeArg::Downgrade,
            gate_on_all: false,
            strict: false,
            baseline_root: None,
            ignore_partial: false,
        };

        let mut buf = Vec::new();
        let code = run_verify_io(&opts, &mut buf);
        assert_eq!(code, 2, "expected missing policy to exit 2");
    }

    #[test]
    fn verify_json_format_emits_schema_and_summary() {
        let pipeline = write_tmp("leaky.yml", leaky_pipeline_yaml());
        let policy = write_tmp("policy.yml", untrusted_sink_invariant_yaml());

        let opts = VerifyOpts {
            paths: vec![pipeline],
            policy,
            format: VerifyFormat::Json,
            platform: Platform::GithubActions,
            max_hops: DEFAULT_MAX_HOPS,
            include_builtin: false,
            severity_threshold: None,
            output: None,
            suppressions: None,
            suppression_mode: SuppressionModeArg::Downgrade,
            gate_on_all: false,
            strict: false,
            baseline_root: None,
            ignore_partial: false,
        };

        let mut buf = Vec::new();
        let code = run_verify_io(&opts, &mut buf);
        assert_eq!(code, 1);
        let parsed: serde_json::Value =
            serde_json::from_slice(&buf).expect("verify json must be valid");
        assert_eq!(parsed["schema_version"], "taudit.verify.v1");
        assert!(parsed["summary"]["total"].as_u64().unwrap() >= 1);
        assert!(parsed["summary"]["by_severity"].is_object());
        let pipelines = parsed["pipelines"].as_array().expect("pipelines array");
        assert_eq!(pipelines.len(), 1);
        assert_eq!(pipelines[0]["completeness"], "complete");
    }

    #[test]
    fn verify_severity_threshold_filters_low_violations() {
        // Wildcard invariant emits at `info` — the lowest severity. With a
        // `--severity-threshold critical` only Critical-or-higher counts, so
        // an info-severity violation is filtered out and the verdict is 0.
        let info_invariant = "id: info_only\nname: info-only invariant\nseverity: info\ncategory: authority_propagation\n";
        let pipeline = write_tmp("leaky.yml", leaky_pipeline_yaml());
        let policy = write_tmp("policy.yml", info_invariant);

        let opts = VerifyOpts {
            paths: vec![pipeline],
            policy,
            format: VerifyFormat::Text,
            platform: Platform::GithubActions,
            max_hops: DEFAULT_MAX_HOPS,
            include_builtin: false,
            severity_threshold: Some(SeverityLevel::Critical),
            output: None,
            suppressions: None,
            suppression_mode: SuppressionModeArg::Downgrade,
            gate_on_all: false,
            strict: false,
            baseline_root: None,
            ignore_partial: false,
        };

        let mut buf = Vec::new();
        let code = run_verify_io(&opts, &mut buf);
        assert_eq!(code, 0, "info-severity violation should be filtered out");
    }

    // ── Per-pipeline baseline contract tests ────────────────
    //
    // Council's load-bearing constraints:
    //   1. No `.taudit/` directory ⇒ behave exactly as today (OSS default).
    //   2. With baseline ⇒ pre-existing findings no longer drive exit 1.
    //   3. Critical-without-valid-waiver ALWAYS drives exit 1 anyway.
    //   4. `--gate-on-all` overrides (1)+(2); (3) still applies.

    fn baseline_test_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "taudit-baseline-cli-{}-{nanos}-{label}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("tmp dir create");
        dir
    }

    #[test]
    fn verify_with_no_baseline_dir_behaves_exactly_as_today() {
        // OSS-friendly default: absent `.taudit/` ⇒ baseline machinery is a
        // no-op. This is the council's #4 load-bearing constraint.
        let dir = baseline_test_dir("no-baseline");
        let pipeline = dir.join("leaky.yml");
        std::fs::write(&pipeline, leaky_pipeline_yaml()).unwrap();
        let policy = dir.join("policy.yml");
        std::fs::write(&policy, untrusted_sink_invariant_yaml()).unwrap();

        let opts = VerifyOpts {
            paths: vec![pipeline],
            policy,
            format: VerifyFormat::Text,
            platform: Platform::GithubActions,
            max_hops: DEFAULT_MAX_HOPS,
            include_builtin: false,
            severity_threshold: None,
            output: None,
            suppressions: None,
            suppression_mode: SuppressionModeArg::Downgrade,
            gate_on_all: false,
            strict: false,
            baseline_root: Some(dir.clone()),
            ignore_partial: false,
        };

        let mut buf = Vec::new();
        let code = run_verify_io(&opts, &mut buf);
        // No `.taudit/baselines/` directory under `dir` ⇒ verify falls
        // through to today's behaviour and the leaky fixture fails 1.
        assert_eq!(code, 1, "absent baseline must not change exit code");
    }

    #[test]
    fn verify_with_baseline_suppresses_preexisting_high_findings() {
        let dir = baseline_test_dir("with-baseline");
        let pipeline = dir.join("leaky.yml");
        std::fs::write(&pipeline, leaky_pipeline_yaml()).unwrap();
        let policy = dir.join("policy.yml");
        std::fs::write(&policy, untrusted_sink_invariant_yaml()).unwrap();

        // Capture the baseline (rule fires at high severity, no critical).
        cmd_baseline_init(
            vec![pipeline.clone()],
            Some(dir.clone()),
            Some("test@local".to_string()),
            Platform::GithubActions,
            DEFAULT_MAX_HOPS,
            None, /* invariants_dir */
        )
        .expect("init");
        // Custom policy is high-severity (`untrusted_sink_invariant_yaml`),
        // so baseline init via built-ins is a near-empty diff. To exercise
        // the suppression path we directly capture the policy findings into
        // a baseline. Easier: just re-run verify; the leaky fixture's
        // built-in `authority_propagation` is critical and would not be
        // waived. The custom-policy invariant is the only thing verify sees
        // because include_builtin=false.

        // Capture custom-policy findings into the baseline. We call init
        // again with the same invariants_dir (custom invariant lives in a
        // dir, so write it to one).
        let policy_dir = dir.join("invariants");
        std::fs::create_dir_all(&policy_dir).unwrap();
        std::fs::write(policy_dir.join("any.yml"), untrusted_sink_invariant_yaml()).unwrap();
        cmd_baseline_init(
            vec![pipeline.clone()],
            Some(dir.clone()),
            Some("test@local".to_string()),
            Platform::GithubActions,
            DEFAULT_MAX_HOPS,
            Some(policy_dir.clone()),
        )
        .expect("init w/ custom rules");

        let opts = VerifyOpts {
            paths: vec![pipeline],
            policy,
            format: VerifyFormat::Text,
            platform: Platform::GithubActions,
            max_hops: DEFAULT_MAX_HOPS,
            include_builtin: false,
            severity_threshold: None,
            output: None,
            suppressions: None,
            suppression_mode: SuppressionModeArg::Downgrade,
            gate_on_all: false,
            strict: false,
            baseline_root: Some(dir),
            ignore_partial: false,
        };

        let mut buf = Vec::new();
        let code = run_verify_io(&opts, &mut buf);
        // The high-severity finding now lives in the baseline ⇒ no NEW
        // violations ⇒ exit 0. (The built-in critical isn't on the verify
        // path because include_builtin=false.)
        assert_eq!(
            code,
            0,
            "preexisting high finding must be suppressed by baseline (output: {})",
            String::from_utf8_lossy(&buf)
        );
    }

    #[test]
    fn verify_with_identity_material_mismatch_skips_suppression() {
        let dir = baseline_test_dir("identity-material-mismatch");
        let pipeline = dir.join("leaky.yml");
        std::fs::write(&pipeline, leaky_pipeline_yaml()).unwrap();
        let policy = dir.join("policy.yml");
        std::fs::write(&policy, untrusted_sink_invariant_yaml()).unwrap();

        let policy_dir = dir.join("invariants");
        std::fs::create_dir_all(&policy_dir).unwrap();
        std::fs::write(policy_dir.join("any.yml"), untrusted_sink_invariant_yaml()).unwrap();

        cmd_baseline_init(
            vec![pipeline.clone()],
            Some(dir.clone()),
            Some("test@local".to_string()),
            Platform::GithubActions,
            DEFAULT_MAX_HOPS,
            Some(policy_dir),
        )
        .expect("init");

        // Corrupt only the additive identity material field to simulate
        // include/template/dependency drift while preserving legacy content
        // hash lookup and backward-compatible file loading.
        let content = std::fs::read_to_string(&pipeline).unwrap();
        let hash = taudit_core::baselines::compute_pipeline_hash(&content);
        let target = taudit_core::baselines::baseline_path_for(&dir, &hash);
        let mut baseline = taudit_core::baselines::Baseline::load(&target)
            .unwrap()
            .expect("baseline present");
        baseline.pipeline_identity_material_hash =
            Some("sha256:0000000000000000000000000000000000000000000000000000000000000000".into());
        baseline.save(&target).unwrap();

        let opts = VerifyOpts {
            paths: vec![pipeline],
            policy,
            format: VerifyFormat::Text,
            platform: Platform::GithubActions,
            max_hops: DEFAULT_MAX_HOPS,
            include_builtin: false,
            severity_threshold: None,
            output: None,
            suppressions: None,
            suppression_mode: SuppressionModeArg::Downgrade,
            gate_on_all: false,
            strict: false,
            baseline_root: Some(dir),
            ignore_partial: false,
        };

        let mut buf = Vec::new();
        let code = run_verify_io(&opts, &mut buf);
        assert_eq!(
            code, 1,
            "identity-material mismatch must skip suppression and keep violation blocking"
        );
    }

    #[test]
    fn verify_gate_on_all_overrides_baseline_suppression() {
        let dir = baseline_test_dir("gate-on-all");
        let pipeline = dir.join("leaky.yml");
        std::fs::write(&pipeline, leaky_pipeline_yaml()).unwrap();
        let policy = dir.join("policy.yml");
        std::fs::write(&policy, untrusted_sink_invariant_yaml()).unwrap();
        let policy_dir = dir.join("invariants");
        std::fs::create_dir_all(&policy_dir).unwrap();
        std::fs::write(policy_dir.join("any.yml"), untrusted_sink_invariant_yaml()).unwrap();
        cmd_baseline_init(
            vec![pipeline.clone()],
            Some(dir.clone()),
            Some("test@local".to_string()),
            Platform::GithubActions,
            DEFAULT_MAX_HOPS,
            Some(policy_dir),
        )
        .expect("init");

        let opts = VerifyOpts {
            paths: vec![pipeline],
            policy,
            format: VerifyFormat::Text,
            platform: Platform::GithubActions,
            max_hops: DEFAULT_MAX_HOPS,
            include_builtin: false,
            severity_threshold: None,
            output: None,
            suppressions: None,
            suppression_mode: SuppressionModeArg::Downgrade,
            gate_on_all: true, // bypass baseline suppression
            strict: false,
            baseline_root: Some(dir),
            ignore_partial: false,
        };

        let mut buf = Vec::new();
        let code = run_verify_io(&opts, &mut buf);
        // `--gate-on-all` ignores the baseline ⇒ pre-existing high finding
        // counts again ⇒ exit 1.
        assert_eq!(
            code,
            1,
            "--gate-on-all must override baseline suppression (output: {})",
            String::from_utf8_lossy(&buf)
        );
    }

    #[test]
    fn baseline_init_writes_one_file_per_pipeline() {
        let dir = baseline_test_dir("init-writes");
        let p1 = dir.join("a.yml");
        let p2 = dir.join("b.yml");
        std::fs::write(&p1, leaky_pipeline_yaml()).unwrap();
        // `b.yml` differs by a single comment so the content hash changes.
        std::fs::write(&p2, format!("# variant\n{}", leaky_pipeline_yaml())).unwrap();

        cmd_baseline_init(
            vec![p1.clone(), p2.clone()],
            Some(dir.clone()),
            Some("test@local".to_string()),
            Platform::GithubActions,
            DEFAULT_MAX_HOPS,
            None,
        )
        .expect("init");

        let baselines = dir.join(".taudit").join("baselines");
        let entries: Vec<_> = std::fs::read_dir(&baselines)
            .expect("baselines dir")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(
            entries.len(),
            2,
            "expected one baseline per pipeline, got {}",
            entries.len()
        );
    }

    #[test]
    fn verify_discovered_parse_error_warns_and_skips_by_default() {
        let dir = baseline_test_dir("verify-discovered-default");
        let pipeline_dir = dir.join("pipelines");
        std::fs::create_dir_all(&pipeline_dir).unwrap();

        let good = pipeline_dir.join("good.yml");
        std::fs::write(&good, clean_pipeline_yaml()).unwrap();
        let bad = pipeline_dir.join("bad.yml");
        std::fs::write(&bad, "name: [\n").unwrap();

        let policy = dir.join("policy.yml");
        std::fs::write(&policy, untrusted_sink_invariant_yaml()).unwrap();

        let opts = VerifyOpts {
            paths: vec![pipeline_dir],
            policy,
            format: VerifyFormat::Text,
            platform: Platform::Auto,
            max_hops: DEFAULT_MAX_HOPS,
            include_builtin: false,
            severity_threshold: None,
            output: None,
            suppressions: None,
            suppression_mode: SuppressionModeArg::Downgrade,
            gate_on_all: false,
            strict: false,
            baseline_root: None,
            ignore_partial: false,
        };

        let mut buf = Vec::new();
        let code = run_verify_io(&opts, &mut buf);
        assert_eq!(
            code, 0,
            "default verify should warn-and-skip discovered parse errors"
        );
    }

    #[test]
    fn verify_discovered_parse_error_is_fatal_in_strict_mode() {
        let dir = baseline_test_dir("verify-discovered-strict");
        let pipeline_dir = dir.join("pipelines");
        std::fs::create_dir_all(&pipeline_dir).unwrap();

        let good = pipeline_dir.join("good.yml");
        std::fs::write(&good, clean_pipeline_yaml()).unwrap();
        let bad = pipeline_dir.join("bad.yml");
        std::fs::write(&bad, "name: [\n").unwrap();

        let policy = dir.join("policy.yml");
        std::fs::write(&policy, untrusted_sink_invariant_yaml()).unwrap();

        let opts = VerifyOpts {
            paths: vec![pipeline_dir],
            policy,
            format: VerifyFormat::Text,
            platform: Platform::Auto,
            max_hops: DEFAULT_MAX_HOPS,
            include_builtin: false,
            severity_threshold: None,
            output: None,
            suppressions: None,
            suppression_mode: SuppressionModeArg::Downgrade,
            gate_on_all: false,
            strict: true,
            baseline_root: None,
            ignore_partial: false,
        };

        let mut buf = Vec::new();
        let code = run_verify_io(&opts, &mut buf);
        assert_eq!(
            code, 2,
            "strict verify should exit 2 on discovered parse errors"
        );
    }
}
