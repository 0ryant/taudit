use colored::Colorize;
use taudit_core::error::TauditError;
use taudit_core::finding::{Finding, Recommendation, Severity};
use taudit_core::graph::{AuthorityGraph, NodeKind};
use taudit_core::ports::ReportSink;

/// Reduces `write!(w, ...).map_err(...)` boilerplate.
macro_rules! w {
    ($w:expr, $($arg:tt)*) => {
        write!($w, $($arg)*).map_err(|e| TauditError::Report(e.to_string()))
    };
}

macro_rules! wln {
    ($w:expr) => {
        writeln!($w).map_err(|e| TauditError::Report(e.to_string()))
    };
    ($w:expr, $($arg:tt)*) => {
        writeln!($w, $($arg)*).map_err(|e| TauditError::Report(e.to_string()))
    };
}

pub struct TerminalReport;

impl<W: std::io::Write> ReportSink<W> for TerminalReport {
    fn emit(
        &self,
        w: &mut W,
        graph: &AuthorityGraph,
        findings: &[Finding],
    ) -> Result<(), TauditError> {
        wln!(w)?;
        wln!(
            w,
            "{}",
            format!("Authority Graph: {}", graph.source.file).bold()
        )?;

        let steps = graph.nodes_of_kind(NodeKind::Step).count();
        let secrets = graph.nodes_of_kind(NodeKind::Secret).count();
        let images = graph.nodes_of_kind(NodeKind::Image).count();
        let identities = graph.nodes_of_kind(NodeKind::Identity).count();

        wln!(
            w,
            "  Steps: {} | Secrets: {} | Actions: {} | Identities: {}",
            steps,
            secrets,
            images,
            identities
        )?;

        if findings.is_empty() {
            wln!(w, "\n{}", "No findings.".green().bold())?;
            return Ok(());
        }

        // Summary counts
        let critical = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        let medium = findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        let low = findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count();

        wln!(w)?;
        w!(w, "Findings (")?;
        let mut parts = Vec::new();
        if critical > 0 {
            parts.push(format!("{critical} critical"));
        }
        if high > 0 {
            parts.push(format!("{high} high"));
        }
        if medium > 0 {
            parts.push(format!("{medium} medium"));
        }
        if low > 0 {
            parts.push(format!("{low} low"));
        }
        wln!(w, "{}):", parts.join(", "))?;

        for finding in findings {
            wln!(w)?;

            let severity_label = match finding.severity {
                Severity::Critical => "CRITICAL".red().bold().to_string(),
                Severity::High => "HIGH".yellow().bold().to_string(),
                Severity::Medium => "MEDIUM".blue().bold().to_string(),
                Severity::Low => "LOW".dimmed().to_string(),
                Severity::Info => "INFO".dimmed().to_string(),
            };

            wln!(w, "{}  {}", severity_label, finding.message)?;

            if let Some(ref path) = finding.path {
                w!(w, "          ")?;

                let source_name = graph
                    .node(path.source)
                    .map(|n| n.name.as_str())
                    .unwrap_or("?");
                w!(w, "{}", source_name.cyan())?;

                for edge_id in &path.edges {
                    if let Some(edge) = graph.edge(*edge_id) {
                        let target_name =
                            graph.node(edge.to).map(|n| n.name.as_str()).unwrap_or("?");
                        w!(w, " {} {}", "-->".dimmed(), target_name.cyan())?;
                    }
                }
                wln!(w)?;
            }

            let fix_text = match &finding.recommendation {
                Recommendation::TsafeRemediation { command, .. } => {
                    format!("Fix: {command}")
                }
                Recommendation::CellosRemediation { spec_hint, .. } => {
                    format!("Fix: {spec_hint}")
                }
                Recommendation::PinAction { current, pinned } => {
                    format!("Fix: Pin {current} to {pinned}")
                }
                Recommendation::ReducePermissions { current, minimum } => {
                    format!("Fix: Reduce from '{current}' to '{minimum}'")
                }
                Recommendation::FederateIdentity {
                    static_secret,
                    oidc_provider,
                } => {
                    format!("Fix: Replace {static_secret} with {oidc_provider} OIDC")
                }
                Recommendation::Manual { action } => {
                    format!("Fix: {action}")
                }
            };

            wln!(w, "          {}", fix_text.green())?;
        }

        wln!(w)?;
        Ok(())
    }
}
