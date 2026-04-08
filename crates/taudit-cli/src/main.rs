use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;

use taudit_core::finding::Severity;
use taudit_core::graph::PipelineSource;
use taudit_core::ignore::IgnoreConfig;
use taudit_core::map;
use taudit_core::ports::{PipelineParser, ReportSink};
use taudit_core::propagation::DEFAULT_MAX_HOPS;
use taudit_core::rules;
use taudit_parse_gha::GhaParser;
use taudit_report_json::JsonReportSink;
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
        /// Path to pipeline YAML file(s) or directory
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
    },

    /// Show authority map — which steps access which secrets/identities
    Map {
        /// Path to pipeline YAML file(s) or directory
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
}

#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    Terminal,
    Json,
    Cloudevents,
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

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli {
        Cli::Scan {
            paths,
            format,
            max_hops,
            severity_threshold,
            ignore_file,
        } => cmd_scan(paths, format, max_hops, severity_threshold, ignore_file),
        Cli::Map { paths } => cmd_map(paths),
    }
}

fn cmd_scan(
    paths: Vec<PathBuf>,
    format: OutputFormat,
    max_hops: usize,
    severity_threshold: Option<SeverityLevel>,
    ignore_file: Option<PathBuf>,
) -> Result<()> {
    let parser = GhaParser;
    let mut stdout = std::io::stdout().lock();
    let mut exit_code = 0;

    // Load ignore config
    let ignore_config = load_ignore_config(ignore_file)?;

    let threshold = severity_threshold.map(|s| s.to_severity());

    for path in resolve_paths(&paths)? {
        let graph = parse_file(&parser, &path)?;
        let all_findings = rules::run_all_rules(&graph, max_hops);

        // Apply ignore rules
        let ignore_result = ignore_config.apply(all_findings, &graph.source.file);
        let findings = ignore_result.findings;
        let suppressed = ignore_result.suppressed_count;

        // Determine exit code based on threshold
        let has_actionable = match threshold {
            Some(ref thresh) => findings.iter().any(|f| f.severity <= *thresh),
            None => !findings.is_empty(),
        };

        if has_actionable {
            exit_code = 1;
        }

        match format {
            OutputFormat::Terminal => {
                TerminalReport
                    .emit(&mut stdout, &graph, &findings)
                    .with_context(|| "Failed to write terminal report")?;
                // Show suppressed count if any
                if suppressed > 0 {
                    use std::io::Write;
                    writeln!(
                        stdout,
                        "  ({} finding{} suppressed by .tauditignore)\n",
                        suppressed,
                        if suppressed == 1 { "" } else { "s" }
                    )
                    .ok();
                }
            }
            OutputFormat::Json => {
                JsonReportSink
                    .emit(&mut stdout, &graph, &findings)
                    .with_context(|| "Failed to write JSON report")?;
            }
            OutputFormat::Cloudevents => {
                CloudEventsJsonlSink
                    .emit(&mut stdout, &graph, &findings)
                    .with_context(|| "Failed to write CloudEvents JSONL")?;
            }
        }
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

fn parse_file(parser: &GhaParser, path: &PathBuf) -> Result<taudit_core::graph::AuthorityGraph> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let source = PipelineSource {
        file: path.display().to_string(),
        repo: None,
        git_ref: None,
    };

    parser
        .parse(&content, &source)
        .with_context(|| format!("Failed to parse {}", path.display()))
}

/// Resolve paths: if a directory, find all .yml/.yaml files recursively.
/// If a file, use it directly.
fn resolve_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();

    for path in paths {
        if path.is_dir() {
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
