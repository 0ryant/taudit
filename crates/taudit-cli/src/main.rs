use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;

use taudit_core::graph::PipelineSource;
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

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli {
        Cli::Scan {
            paths,
            format,
            max_hops,
        } => cmd_scan(paths, format, max_hops),
        Cli::Map { paths } => cmd_map(paths),
    }
}

fn cmd_scan(paths: Vec<PathBuf>, format: OutputFormat, max_hops: usize) -> Result<()> {
    let parser = GhaParser;
    let mut stdout = std::io::stdout().lock();
    let mut exit_code = 0;

    for path in resolve_paths(&paths)? {
        let graph = parse_file(&parser, &path)?;
        let findings = rules::run_all_rules(&graph, max_hops);

        if !findings.is_empty() {
            exit_code = 1;
        }

        match format {
            OutputFormat::Terminal => {
                TerminalReport
                    .emit(&mut stdout, &graph, &findings)
                    .with_context(|| "Failed to write terminal report")?;
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
