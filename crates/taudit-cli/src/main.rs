use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};
use std::collections::HashSet;
use std::path::PathBuf;

use taudit_core::finding::Severity;
use taudit_core::graph::PipelineSource;
use taudit_core::ignore::{glob_match, IgnoreConfig};
use taudit_core::map;
use taudit_core::ports::{PipelineParser, ReportSink};
use taudit_core::propagation::DEFAULT_MAX_HOPS;
use taudit_core::rules;
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

        /// Path to ignore file (default: .tauditignore in working directory)
        #[arg(long)]
        ignore_file: Option<PathBuf>,

        /// Disable ANSI color codes in terminal output.
        /// Automatically set when stdout is not a tty.
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

        /// Path to a JSON report from a prior scan. Findings whose
        /// (category, message) pair appears in the baseline are suppressed.
        /// Use this to surface only new findings since the last known-good scan.
        #[arg(long)]
        baseline: Option<PathBuf>,
    },

    /// Show authority map — which steps access which secrets/identities
    Map {
        /// Path to pipeline YAML file(s) or directory
        #[arg(required = true)]
        paths: Vec<PathBuf>,
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
    },
}

#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    Terminal,
    Json,
    Sarif,
    Cloudevents,
}

#[derive(Clone, clap::ValueEnum)]
enum DiffOutputFormat {
    Terminal,
    Json,
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
    baseline: Option<PathBuf>,
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
            baseline,
        } => {
            // Configure color output before any terminal report is emitted.
            // Disable when --no-color is set OR when stdout is not a tty.
            use std::io::IsTerminal;
            if no_color || !std::io::stdout().is_terminal() {
                colored::control::set_override(false);
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
                baseline,
            })
        }
        Cli::Completions { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
            Ok(())
        }
        Cli::Map { paths } => cmd_map(paths),
        Cli::Diff {
            before,
            after,
            format,
            max_hops,
        } => cmd_diff(before, after, format, max_hops),
    }
}

fn cmd_diff(
    before: PathBuf,
    after: PathBuf,
    format: DiffOutputFormat,
    max_hops: usize,
) -> Result<()> {
    let parser = GhaParser;
    let mut stdout = std::io::stdout().lock();

    let before_graph = parse_file(&parser, &before)?;
    let after_graph = parse_file(&parser, &after)?;

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
        baseline,
    } = opts;

    let parser = GhaParser;
    let mut stdout = std::io::stdout().lock();
    let mut exit_code = 0;

    // Load ignore config
    let ignore_config = load_ignore_config(ignore_file)?;

    // Load baseline fingerprints (category + message pairs to suppress)
    let baseline_fingerprints = load_baseline(baseline)?;

    let threshold = severity_threshold.map(|s| s.to_severity());

    // Resolve and filter paths. `-` (stdin) bypasses the glob exclude filter.
    let all_paths = resolve_paths(&paths)?;
    let resolved: Vec<PathBuf> = all_paths
        .into_iter()
        .filter(|p| {
            if p.as_os_str() == "-" {
                return true; // never exclude stdin
            }
            let path_str = p.display().to_string();
            !exclude
                .iter()
                .any(|pattern| glob_match(pattern, &path_str))
        })
        .collect();

    // Quiet mode: accumulate totals across files
    let mut quiet_total = SeverityCounts::default();

    for path in &resolved {
        let graph = if path.as_os_str() == "-" {
            let mut content = String::new();
            use std::io::Read;
            std::io::stdin()
                .read_to_string(&mut content)
                .with_context(|| "Failed to read from stdin")?;
            parse_content(&parser, content, "<stdin>".to_string())?
        } else {
            parse_file(&parser, path)?
        };
        let all_findings = rules::run_all_rules(&graph, max_hops);

        // Apply .tauditignore
        let ignore_result = ignore_config.apply(all_findings, &graph.source.file);
        let after_ignore = ignore_result.findings;
        let suppressed_ignore = ignore_result.suppressed_count;

        // Apply baseline suppression
        let (findings, suppressed_baseline) =
            apply_baseline(after_ignore, &baseline_fingerprints);

        // Determine exit code based on threshold
        let has_actionable = match threshold {
            Some(ref thresh) => findings.iter().any(|f| f.severity <= *thresh),
            None => !findings.is_empty(),
        };
        if has_actionable {
            exit_code = 1;
        }

        if quiet {
            let counts = SeverityCounts::from_findings(&findings);
            quiet_total.add(&counts);
            let total = findings.len();
            let suppressed = suppressed_ignore + suppressed_baseline;
            let sup_note = if suppressed > 0 {
                format!(" ({suppressed} suppressed)")
            } else {
                String::new()
            };
            use std::io::Write;
            writeln!(
                stdout,
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
        } else {
            match format {
                OutputFormat::Terminal => {
                    TerminalReport { verbose }
                        .emit(&mut stdout, &graph, &findings)
                        .with_context(|| "Failed to write terminal report")?;
                    if suppressed_ignore > 0 || suppressed_baseline > 0 {
                        use std::io::Write;
                        let mut notes = Vec::new();
                        if suppressed_ignore > 0 {
                            notes.push(format!(
                                "{} suppressed by .tauditignore",
                                suppressed_ignore
                            ));
                        }
                        if suppressed_baseline > 0 {
                            notes.push(format!(
                                "{} suppressed by baseline",
                                suppressed_baseline
                            ));
                        }
                        writeln!(stdout, "  ({})\n", notes.join(", ")).ok();
                    }
                }
                OutputFormat::Json => {
                    JsonReportSink
                        .emit(&mut stdout, &graph, &findings)
                        .with_context(|| "Failed to write JSON report")?;
                }
                OutputFormat::Sarif => {
                    SarifReportSink
                        .emit(&mut stdout, &graph, &findings)
                        .with_context(|| "Failed to write SARIF report")?;
                }
                OutputFormat::Cloudevents => {
                    CloudEventsJsonlSink
                        .emit(&mut stdout, &graph, &findings)
                        .with_context(|| "Failed to write CloudEvents JSONL")?;
                }
            }
        }
    }

    if quiet && resolved.len() > 1 {
        use std::io::Write;
        writeln!(
            stdout,
            "TOTAL: {} findings — {} critical / {} high / {} medium / {} low",
            quiet_total.total(),
            quiet_total.critical,
            quiet_total.high,
            quiet_total.medium,
            quiet_total.low,
        )
        .ok();
    }

    std::process::exit(exit_code);
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
            let config: IgnoreConfig = serde_yaml::from_str(&content)
                .with_context(|| format!("Failed to parse ignore file: {}", p.display()))?;
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

fn cmd_map(paths: Vec<PathBuf>) -> Result<()> {
    let parser = GhaParser;

    for path in resolve_paths(&paths)? {
        let graph = parse_file(&parser, &path)?;
        let authority_map = map::authority_map(&graph);

        println!("Authority Map: {}\n", path.display());
        print!("{}", map::render_map(&authority_map));
        println!();
    }

    Ok(())
}

fn parse_content(
    parser: &GhaParser,
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

fn parse_file(parser: &GhaParser, path: &PathBuf) -> Result<taudit_core::graph::AuthorityGraph> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    parse_content(parser, content, path.display().to_string())
}

/// Resolve paths: if a directory, find all .yml/.yaml files recursively.
/// If a file, use it directly. `-` is passed through as the stdin sentinel.
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
        assert_eq!(
            removed[0].category,
            FindingCategory::OverPrivilegedIdentity
        );
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
}
