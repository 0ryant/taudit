use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use taudit_core::finding::Severity;
use taudit_core::graph::PipelineSource;
use taudit_core::ignore::{glob_match, IgnoreConfig};
use taudit_core::map;
use taudit_core::ports::ReportSink;
use taudit_core::propagation::DEFAULT_MAX_HOPS;
use taudit_core::rules;
use taudit_parse_ado::AdoParser;
use taudit_parse_gha::GhaParser;
use taudit_parse_gitlab::GitlabParser;
use taudit_report_json::JsonReportSink;
use taudit_report_sarif::SarifReportSink;
use taudit_report_terminal::TerminalReport;
use taudit_sink_cloudevents::CloudEventsJsonlSink;

#[derive(Parser)]
#[command(
    name = "taudit",
    about = "Pipeline authority scanner — models how authority propagates through CI/CD pipelines",
    long_about = "CI/CD is an untyped authority system. taudit makes it explicit, inspectable, and enforceable.\n\n\
                  v0.9.0 is the v1.0 release candidate — the CLI contract, graph schema, and invariant DSL\n\
                  are intended to be stable, but breaking changes are still possible until v1.0 lands.\n\n\
                  Start with `taudit verify --help` for policy enforcement, or see docs/positioning.md.",
    version
)]
enum Cli {
    /// Scan pipeline file(s) for authority findings
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

        /// Verbose output: show node metadata (kind, trust zone, permissions)
        /// for each node in a finding's propagation path.
        #[arg(long, default_value_t = false)]
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

        /// Output format: `text` (default terminal table) or `dot` (Graphviz DOT).
        /// Pipe DOT output to `dot -Tsvg -o map.svg` to render an authority graph.
        #[arg(long, default_value = "text")]
        format: MapFormat,

        /// Restrict the output to the subgraph reachable from a single job.
        /// Most useful with `--format dot`; for `--format text` the table is
        /// filtered to steps belonging to the named job.
        #[arg(long)]
        job: Option<String>,
    },

    /// Emit the canonical authority graph as a versioned, machine-readable export.
    ///
    /// Unlike `taudit map` (human-readable table), `taudit graph` produces the
    /// full graph as JSON conforming to `schemas/authority-graph.v1.json`,
    /// or as Graphviz DOT for visualization. Designed for downstream
    /// consumers (tsign, axiom, runtime cells) that build on the graph.
    Graph {
        /// Path to pipeline YAML file(s) or directory.
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// CI/CD platform. Default: auto (detects from YAML content)
        #[arg(long, default_value = "auto")]
        platform: Platform,

        /// Output format: `json` (default, schema-validated) or `dot` (Graphviz DOT).
        #[arg(long, default_value = "json")]
        format: GraphFormat,

        /// Restrict the output to the subgraph reachable from a single job.
        /// For `--format json` the graph is emitted unfiltered; the flag only
        /// affects `--format dot` (matching `taudit map --job` semantics).
        #[arg(long)]
        job: Option<String>,

        /// Directory containing custom rule YAML files (`*.yml`, `*.yaml`).
        /// Accepted for symmetry with `taudit scan`; rules do not currently
        /// alter the emitted graph but the flag is reserved for future use.
        #[arg(long)]
        rules_dir: Option<PathBuf>,
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

    /// List taudit's built-in rules, or show the full description for one rule.
    ///
    /// `taudit explain`            — list all rules with severity and short description.
    /// `taudit explain <rule-id>`  — show the full description for one rule.
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

    /// Inspect or list authority invariants (built-in and custom).
    ///
    /// Authority invariants are declarative properties that the pipeline
    /// authority graph must satisfy. taudit ships 17 built-in invariants and
    /// loads any custom invariants from `--invariants-dir`.
    Invariants {
        #[command(subcommand)]
        action: InvariantsAction,
    },

    /// Enforce policy invariants — exit non-zero on any violation.
    ///
    /// `verify` is the policy-driven enforcement entrypoint for CI required
    /// checks and merge gates. Unlike `scan` (which always runs the 17
    /// built-in rules), `verify` runs ONLY the user-supplied invariants in
    /// `--policy` unless `--include-builtin` is set.
    ///
    /// Exit codes are deterministic:
    ///   0 — no policy violations
    ///   1 — at least one policy violation
    ///   2 — usage error / file not found / parse error
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

        /// Also run the 17 built-in rules. Their findings count toward
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
}

#[derive(Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
enum GraphFormat {
    Json,
    Dot,
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

/// Detect the CI/CD platform from YAML content by inspecting top-level mapping keys.
///
/// - Top-level `on:` → `GithubActions`.
/// - `stages:` as flat string list (e.g. `["build", "test"]`) → `GitLab`.
/// - `stages:` as list of objects (e.g. `[{stage: build, jobs: [...]}]`) → `AzureDevOps`.
/// - `trigger:`, `pr:`, or `jobs:` (without `on:`) → `AzureDevOps`.
/// - Else → `GithubActions` (safe fallback).
fn detect_platform(content: &str) -> Platform {
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
    telemetry_dir: Option<PathBuf>,
    receipt_dir: Option<PathBuf>,
    log_dir: Option<PathBuf>,
    platform: Platform,
    output: Option<PathBuf>,
    invariants_dir: Option<PathBuf>,
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

    match cli {
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
            telemetry_dir,
            receipt_dir,
            log_dir,
            platform,
            output,
            invariants_dir,
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
                telemetry_dir,
                receipt_dir,
                log_dir,
                platform,
                output,
                invariants_dir,
            })
        }
        Cli::Completions { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
            Ok(())
        }
        Cli::Version => cmd_version(),
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
        } => cmd_map(paths, platform, no_color, format, job),
        Cli::Graph {
            paths,
            platform,
            format,
            job,
            rules_dir,
        } => cmd_graph(paths, platform, format, job, rules_dir),
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
            })
        }
    }
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
    let mut stdout = std::io::stdout().lock();

    // For `--platform auto`, detect each file independently. Otherwise reuse the
    // pre-built parser to avoid extra allocations.
    let parse_one = |path: &PathBuf| -> Result<taudit_core::graph::AuthorityGraph> {
        if platform == Platform::Auto {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            let resolved_platform = resolve_platform(&platform, &content);
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
            writeln!(stdout, "taudit diff")?;
            writeln!(stdout, "  before: {}", before.display())?;
            writeln!(stdout, "  after:  {}", after.display())?;
            writeln!(stdout)?;
            writeln!(
                stdout,
                "graph: nodes {} -> {} ({:+}), edges {} -> {} ({:+})",
                before_graph.nodes.len(),
                after_graph.nodes.len(),
                after_graph.nodes.len() as isize - before_graph.nodes.len() as isize,
                before_graph.edges.len(),
                after_graph.edges.len(),
                after_graph.edges.len() as isize - before_graph.edges.len() as isize,
            )?;
            writeln!(
                stdout,
                "findings: {} -> {} ({:+})",
                before_findings.len(),
                after_findings.len(),
                after_findings.len() as isize - before_findings.len() as isize,
            )?;

            writeln!(stdout)?;
            writeln!(stdout, "added findings: {}", added.len())?;
            for finding in &added {
                let category = finding_category(&finding.category);
                writeln!(
                    stdout,
                    "  + [{:?}] {}: {}",
                    finding.severity, category, finding.message
                )?;
            }

            writeln!(stdout)?;
            writeln!(stdout, "removed findings: {}", removed.len())?;
            for finding in &removed {
                let category = finding_category(&finding.category);
                writeln!(
                    stdout,
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
            serde_json::to_writer_pretty(&mut stdout, &json)
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
        telemetry_dir,
        receipt_dir,
        log_dir,
        platform,
        output,
        invariants_dir,
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
        Some(dir) => match taudit_core::custom_rules::load_rules_dir(dir) {
            Ok(rules) => rules,
            Err(errors) => {
                for err in &errors {
                    eprintln!("error: {err}");
                }
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
            std::fs::File::create(path)
                .with_context(|| format!("Failed to open output file {}", path.display()))?,
        )),
        None => Box::new(stdout_handle.lock()),
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
        let graph = if path.as_os_str() == "-" {
            let mut content = String::new();
            use std::io::Read;
            std::io::stdin()
                .read_to_string(&mut content)
                .with_context(|| "Failed to read from stdin")?;
            // Resolve `Auto` against the stdin content; otherwise reuse the
            // pre-built parser without re-allocating.
            if platform == Platform::Auto {
                let resolved_platform = resolve_platform(&platform, &content);
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
                Ok(c) => c,
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
            let parse_result = if platform == Platform::Auto {
                let resolved_platform = resolve_platform(&platform, &content);
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

        // Apply baseline suppression
        let (findings, suppressed_baseline) = apply_baseline(after_ignore, &baseline_fingerprints);

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
        suppressed_total += suppressed_ignore + suppressed_baseline + suppressed_threshold;

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
                CloudEventsJsonlSink
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
            std::fs::File::create(path)
                .with_context(|| format!("Failed to open output file {}", path.display()))?,
        )),
        None => Box::new(stdout_handle.lock()),
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
    let custom_rules = match load_policy(&opts.policy) {
        Ok(rules) => rules,
        Err(errors) => {
            for err in &errors {
                eprintln!("error: {err}");
            }
            return 2;
        }
    };

    // An empty policy file/dir is almost certainly a misconfiguration in CI —
    // surface it loudly rather than silently exiting 0 on every input.
    if custom_rules.is_empty() && !opts.include_builtin {
        eprintln!(
            "error: no invariants loaded from {} (use --include-builtin to run only built-in rules)",
            opts.policy.display()
        );
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

    let parser_box = make_parser(&opts.platform);
    let parser = parser_box.as_ref();
    let threshold = opts.severity_threshold.as_ref().map(|s| s.to_severity());

    let mut violations: Vec<Violation> = Vec::new();
    let mut sarif_buffer: Vec<(
        taudit_core::graph::AuthorityGraph,
        Vec<taudit_core::finding::Finding>,
    )> = Vec::new();

    // Step 3: parse each pipeline file and evaluate the loaded invariants.
    // For explicitly-named files a parse error is fatal (exit 2). For files
    // discovered via directory walk we warn-and-skip (matches `scan`).
    for tagged_path in &resolved {
        let path = tagged_path.path();
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(err) => match tagged_path {
                ResolvedPath::Explicit(_) => {
                    eprintln!("error: failed to read {}: {err}", path.display());
                    return 2;
                }
                ResolvedPath::Discovered(_) => {
                    eprintln!("warning: skipping {}: {err}", path.display());
                    continue;
                }
            },
        };

        let parse_result = if opts.platform == Platform::Auto {
            let resolved_platform = resolve_platform(&opts.platform, &content);
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
                    eprintln!("warning: skipping {}: {err:#}", path.display());
                    continue;
                }
            },
        };

        let propagation_paths =
            taudit_core::propagation::propagation_analysis(&graph, opts.max_hops);

        // Custom (policy) findings.
        let mut findings = taudit_core::custom_rules::evaluate_custom_rules(
            &graph,
            &propagation_paths,
            &custom_rules,
        );

        // Optionally fold in the 17 built-in rules.
        if opts.include_builtin {
            findings.extend(rules::run_all_rules(&graph, opts.max_hops));
        }

        // Apply the severity threshold (Severity orders Critical < Info).
        if let Some(ref t) = threshold {
            findings.retain(|f| f.severity <= *t);
        }

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
        VerifyFormat::Text => render_verify_text(writer, &violations),
        VerifyFormat::Json => render_verify_json(writer, &violations),
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
        return Err(vec![format!("policy path not found: {}", policy.display())]);
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
fn render_verify_text<W: std::io::Write>(w: &mut W, violations: &[Violation]) -> Result<()> {
    for v in violations {
        writeln!(
            w,
            "{}: {}: {} [{:?}]",
            v.path, v.invariant_id, v.message, v.severity
        )?;
    }
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

/// Render the structured JSON format with stable field names and a versioned
/// schema marker. `summary.by_severity` is a fixed-key object so consumers
/// can index without checking for missing keys.
fn render_verify_json<W: std::io::Write>(w: &mut W, violations: &[Violation]) -> Result<()> {
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
        }
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

/// Load ignore config from file. Tries `--ignore-file` path first,
/// then `.tauditignore` in CWD. Returns empty config if neither exists.
fn load_ignore_config(explicit_path: Option<PathBuf>) -> Result<IgnoreConfig> {
    let path = if let Some(p) = explicit_path {
        // Explicit path must exist — fail immediately, don't fall through to default
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

    let content = std::fs::read_to_string(&p)
        .with_context(|| format!("Failed to read baseline file: {}", p.display()))?;

    let json: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse baseline JSON: {}", p.display()))?;

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
                "Failed to read --dedupe-against file: {}",
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
            // Accept only the documented shape (16 lowercase hex chars).
            // Anything else is silently ignored to avoid a malformed prior
            // file polluting the current run.
            if fp.len() == 16 && fp.chars().all(|c| c.is_ascii_hexdigit()) {
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
) -> Result<()> {
    if no_color || std::env::var_os("NO_COLOR").is_some() {
        colored::control::set_override(false);
    }

    let parser_box = make_parser(&platform);
    let parser = parser_box.as_ref();

    // Track whether --job matched any file so we can give a useful error at the end.
    let mut job_matched_any = false;

    for tagged_path in resolve_paths_tagged(&paths)? {
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
            let resolved_platform = resolve_platform(&platform, &content);
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

        match format {
            MapFormat::Text => {
                let authority_map = map::authority_map(&graph);
                println!("Authority Map: {}\n", path.display());
                print!("{}", map::render_map(&authority_map, term_width()));
                println!();
            }
            MapFormat::Dot => {
                println!("{}", map::render_dot(&graph, job.as_deref()));
            }
        }
    }

    if let Some(ref name) = job {
        if !job_matched_any {
            eprintln!("error: no job named '{name}' found in any scanned file");
            std::process::exit(2);
        }
    }

    Ok(())
}

/// `taudit graph` — emit the canonical authority graph as a versioned,
/// machine-readable export. Mirrors `cmd_map`'s file-resolution and
/// per-file platform sniffing, but produces the graph itself rather than
/// the human-readable map. Default format is JSON conforming to
/// `schemas/authority-graph.v1.json`; `--format dot` reuses the same
/// Graphviz renderer as `taudit map --format dot`.
fn cmd_graph(
    paths: Vec<PathBuf>,
    platform: Platform,
    format: GraphFormat,
    job: Option<String>,
    rules_dir: Option<PathBuf>,
) -> Result<()> {
    // Validate `--rules-dir` early so a bad directory fails fast, even
    // though custom rules don't currently affect the emitted graph
    // (kept for symmetry with `taudit scan`).
    if let Some(dir) = rules_dir.as_ref() {
        if let Err(errors) = taudit_core::custom_rules::load_rules_dir(dir) {
            for err in &errors {
                eprintln!("error: {err}");
            }
            std::process::exit(2);
        }
    }

    let parser_box = make_parser(&platform);
    let parser = parser_box.as_ref();

    let mut job_matched_any = false;

    for tagged_path in resolve_paths_tagged(&paths)? {
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
            let resolved_platform = resolve_platform(&platform, &content);
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
        // Same semantics as `taudit map --job`.
        if let Some(ref name) = job {
            if !map::job_names(&graph).iter().any(|n| n == name) {
                continue;
            }
            job_matched_any = true;
        }

        match format {
            GraphFormat::Json => {
                // Note: --job currently only filters DOT output; the JSON
                // export emits the full graph for every matched file. This
                // matches user expectation that the schema-validated JSON
                // is a faithful, lossless dump.
                let export = taudit_report_json::GraphExport::new(&graph);
                let json = export
                    .to_json_pretty()
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!("{json}");
            }
            GraphFormat::Dot => {
                println!("{}", map::render_dot(&graph, job.as_deref()));
            }
        }
    }

    if let Some(ref name) = job {
        if !job_matched_any {
            eprintln!("error: no job named '{name}' found in any scanned file");
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
    println!("{}", version_report());
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
    let mut out = stdout.lock();

    match rule {
        None => {
            writeln!(out, "{} — {} rules\n", "taudit".bold(), rules.len()).ok();
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
                )
                .ok();
            }
            writeln!(out).ok();
            writeln!(
                out,
                "Use '{}' for full description and remediation guidance.",
                "taudit explain <rule>".bold()
            )
            .ok();
            Ok(())
        }
        Some(id) => {
            let Some(r) = rules.iter().find(|r| r.id == id) else {
                eprintln!("error: unknown rule '{id}'");
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

            writeln!(out, "{} ({})  {}\n", r.id.bold(), r.name, sev_colored,).ok();
            writeln!(out, "  {}\n", r.short_description).ok();
            // Wrap the full description at ~76 cols with a 2-space indent.
            for line in wrap_paragraph(r.full_description, 76) {
                writeln!(out, "  {line}").ok();
            }
            writeln!(out).ok();
            writeln!(out, "  Tags: {}", r.tags.join(", ")).ok();
            writeln!(
                out,
                "\n  See: https://github.com/0ryant/taudit/blob/main/docs/rules/{}.md",
                r.id
            )
            .ok();
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
        let read_dir = std::fs::read_dir(dir)
            .with_context(|| format!("Failed to read invariants directory {}", dir.display()))?;
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
    let mut out = stdout.lock();

    let total = built_in.len() + custom.len();
    writeln!(
        out,
        "{} — {} invariants ({} built-in, {} custom)\n",
        "taudit invariants".bold(),
        total,
        built_in.len(),
        custom.len(),
    )
    .ok();

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
    )
    .ok();
    writeln!(
        out,
        "  {:-<id_width$}  {:-<sev_width$}  {:-<20}",
        "",
        "",
        "",
        id_width = id_width,
        sev_width = sev_width,
    )
    .ok();

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
        )
        .ok();
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
        )
        .ok();
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
        std::fs::write(&path, rendered)
            .with_context(|| format!("Failed to write spec to {}", path.display()))?;
        eprintln!("Wrote CellOS spec to {}", path.display());
    } else {
        println!("{rendered}");
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
/// when it's already concrete.
fn resolve_platform(platform: &Platform, content: &str) -> Platform {
    match platform {
        Platform::Auto => detect_platform(content),
        Platform::GithubActions => Platform::GithubActions,
        Platform::AzureDevOps => Platform::AzureDevOps,
        Platform::GitLab => Platform::GitLab,
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
    parser
        .parse(&content, &source)
        .with_context(|| format!("Failed to parse {source_file}"))
}

fn parse_file(
    parser: &dyn taudit_core::ports::PipelineParser,
    path: &PathBuf,
) -> Result<taudit_core::graph::AuthorityGraph> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
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
            anyhow::bail!("Path not found: {}", path.display());
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
            anyhow::bail!("Path not found: {}", path.display());
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

#[cfg(test)]
mod tests {
    use super::*;
    use taudit_core::finding::{Finding, FindingCategory, Recommendation, Severity};

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
        assert_eq!(detect_platform(yaml), Platform::GithubActions);
    }

    #[test]
    fn auto_detects_azure_devops() {
        // ADO uses `trigger:` / `pr:` / `stages:` / `jobs:` without `on:`.
        let yaml = "trigger:\n  branches:\n    include: [main]\nstages:\n  - stage: build\n    jobs:\n      - job: compile\n        steps:\n          - script: echo hi\n";
        assert_eq!(detect_platform(yaml), Platform::AzureDevOps);
    }

    #[test]
    fn auto_falls_back_to_github_actions_when_yaml_unparseable() {
        let yaml = "::: this is not yaml :::\n  - and: [oops";
        assert_eq!(detect_platform(yaml), Platform::GithubActions);
    }

    #[test]
    fn auto_falls_back_to_github_actions_when_no_markers() {
        let yaml = "name: hello\nversion: 1\n";
        assert_eq!(detect_platform(yaml), Platform::GithubActions);
    }

    #[test]
    fn auto_detects_gitlab_ci_by_stages_string_list() {
        let yaml = "stages:\n  - build\n  - test\n  - deploy\n\nbuild-job:\n  stage: build\n  script:\n    - make\n";
        assert_eq!(detect_platform(yaml), Platform::GitLab);
    }

    #[test]
    fn stages_object_list_still_detects_ado_not_gitlab() {
        // ADO stages: is a list of objects, not strings
        let yaml = "trigger:\n  - main\nstages:\n  - stage: build\n    jobs:\n      - job: compile\n        steps:\n          - script: echo hi\n";
        assert_eq!(detect_platform(yaml), Platform::AzureDevOps);
    }

    #[test]
    fn auto_detects_gitlab_ci_by_image_key() {
        // GitLab CI with image: at top level but no stages:
        let yaml = "image: alpine:latest\n\nbuild:\n  script:\n    - make\n";
        assert_eq!(detect_platform(yaml), Platform::GitLab);
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
        };

        let mut buf = Vec::new();
        let code = run_verify_io(&opts, &mut buf);
        assert_eq!(code, 1);
        let parsed: serde_json::Value =
            serde_json::from_slice(&buf).expect("verify json must be valid");
        assert_eq!(parsed["schema_version"], "taudit.verify.v1");
        assert!(parsed["summary"]["total"].as_u64().unwrap() >= 1);
        assert!(parsed["summary"]["by_severity"].is_object());
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
        };

        let mut buf = Vec::new();
        let code = run_verify_io(&opts, &mut buf);
        assert_eq!(code, 0, "info-severity violation should be filtered out");
    }
}
