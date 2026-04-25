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
use taudit_report_json::JsonReportSink;
use taudit_report_sarif::SarifReportSink;
use taudit_report_terminal::TerminalReport;
use taudit_sink_cloudevents::CloudEventsJsonlSink;

#[derive(Parser)]
#[command(
    name = "taudit",
    about = "Pipeline authority scanner — models how authority propagates through CI/CD pipelines",
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

        /// Minimum severity to cause non-zero exit code.
        /// Findings below this threshold still appear in the report
        /// but don't fail the scan.
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

        /// CI/CD platform to parse. Default: github-actions.
        #[arg(long, default_value = "github-actions")]
        platform: Platform,

        /// Write the report to this file instead of stdout.
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },

    /// Show authority map — which steps access which secrets/identities
    Map {
        /// Path to pipeline YAML file(s) or directory
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// CI/CD platform to parse. Default: github-actions.
        #[arg(long, default_value = "github-actions")]
        platform: Platform,

        /// Disable ANSI color output
        #[arg(long, default_value_t = false)]
        no_color: bool,
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

        /// CI/CD platform to parse. Default: github-actions.
        #[arg(long, default_value = "github-actions")]
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

        /// CI/CD platform to parse. Default: github-actions.
        #[arg(long, default_value = "github-actions")]
        platform: Platform,
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

#[derive(Clone, clap::ValueEnum, Default)]
enum Platform {
    #[default]
    #[value(name = "github-actions")]
    GithubActions,
    #[value(name = "azure-devops")]
    AzureDevOps,
}

impl Platform {
    fn as_str(&self) -> &'static str {
        match self {
            Platform::GithubActions => "github-actions",
            Platform::AzureDevOps => "azure-devops",
        }
    }
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
    telemetry_dir: Option<PathBuf>,
    receipt_dir: Option<PathBuf>,
    log_dir: Option<PathBuf>,
    platform: Platform,
    output: Option<PathBuf>,
}

#[derive(Clone)]
struct RuntimeArtifactPaths {
    telemetry_dir: Option<PathBuf>,
    receipt_dir: Option<PathBuf>,
    log_dir: Option<PathBuf>,
}

fn main() -> Result<()> {
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
            telemetry_dir,
            receipt_dir,
            log_dir,
            platform,
            output,
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
                telemetry_dir,
                receipt_dir,
                log_dir,
                platform,
                output,
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
        } => cmd_map(paths, platform, no_color),
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
    }
}

fn cmd_diff(
    before: PathBuf,
    after: PathBuf,
    format: DiffOutputFormat,
    max_hops: usize,
    platform: Platform,
) -> Result<()> {
    let parser = make_parser(&platform);
    let parser = parser.as_ref();
    let mut stdout = std::io::stdout().lock();

    let before_graph = parse_file(parser, &before)?;
    let after_graph = parse_file(parser, &after)?;

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
        telemetry_dir,
        receipt_dir,
        log_dir,
        platform,
        output,
    } = opts;

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
    let mut exit_code = 0;

    // Load ignore config
    let ignore_config = load_ignore_config(ignore_file)?;

    // Load baseline fingerprints (category + message pairs to suppress)
    let baseline_fingerprints = load_baseline(baseline)?;

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
        let graph = if path.as_os_str() == "-" {
            let mut content = String::new();
            use std::io::Read;
            std::io::stdin()
                .read_to_string(&mut content)
                .with_context(|| "Failed to read from stdin")?;
            parse_content(parser, content, "<stdin>".to_string())?
        } else {
            match parse_file(parser, path) {
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

        if graph.completeness == taudit_core::graph::AuthorityCompleteness::Partial
            || graph.completeness == taudit_core::graph::AuthorityCompleteness::Unknown
        {
            terminal_partial_files += 1;
        }

        let all_findings = rules::run_all_rules(&graph, max_hops);

        // Apply .tauditignore
        let ignore_result = ignore_config.apply(all_findings, &graph.source.file);
        let after_ignore = ignore_result.findings;
        let suppressed_ignore = ignore_result.suppressed_count;

        // Apply baseline suppression
        let (findings, suppressed_baseline) = apply_baseline(after_ignore, &baseline_fingerprints);

        // Exit code uses unfiltered findings (semantics must not change with display filter).
        let has_actionable = match threshold {
            Some(ref thresh) => findings.iter().any(|f| f.severity <= *thresh),
            None => !findings.is_empty(),
        };
        if has_actionable {
            exit_code = 1;
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
                CloudEventsJsonlSink
                    .emit(&mut writer, &graph, &findings)
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
            .emit_multi(&mut writer, &items)
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

fn cmd_map(paths: Vec<PathBuf>, platform: Platform, no_color: bool) -> Result<()> {
    if no_color || std::env::var_os("NO_COLOR").is_some() {
        colored::control::set_override(false);
    }

    let parser_box = make_parser(&platform);
    let parser = parser_box.as_ref();

    for tagged_path in resolve_paths_tagged(&paths)? {
        let path = tagged_path.path().clone();
        let graph = match parse_file(parser, &path) {
            Ok(g) => g,
            Err(err) => match &tagged_path {
                ResolvedPath::Discovered(_) => {
                    eprintln!("warning: skipping {}: {err:#}", path.display());
                    continue;
                }
                ResolvedPath::Explicit(_) => return Err(err),
            },
        };
        let authority_map = map::authority_map(&graph);

        println!("Authority Map: {}\n", path.display());
        print!("{}", map::render_map(&authority_map));
        println!();
    }

    Ok(())
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
            Ok(())
        }
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
        Platform::GithubActions => Box::new(GhaParser),
        Platform::AzureDevOps => Box::new(AdoParser),
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
}
