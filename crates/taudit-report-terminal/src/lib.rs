use colored::Colorize;
use taudit_core::error::TauditError;
use taudit_core::finding::{Finding, Recommendation, Severity};
use taudit_core::graph::{AuthorityCompleteness, AuthorityGraph, EdgeKind, NodeKind};
use taudit_core::ports::ReportSink;

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

const RULE_WIDTH: usize = 60;

#[derive(Default)]
pub struct TerminalReport {
    pub verbose: bool,
}

impl<W: std::io::Write> ReportSink<W> for TerminalReport {
    fn emit(
        &self,
        w: &mut W,
        graph: &AuthorityGraph,
        findings: &[Finding],
    ) -> Result<(), TauditError> {
        let is_partial = graph.completeness == AuthorityCompleteness::Partial
            || graph.completeness == AuthorityCompleteness::Unknown;

        // ── File section header ──────────────────────────────────
        wln!(w, "{}", "─".repeat(RULE_WIDTH).bright_black())?;
        wln!(
            w,
            "{}",
            format!("Authority Graph: {}", graph.source.file)
                .bright_white()
                .bold()
        )?;

        let steps = graph.nodes_of_kind(NodeKind::Step).count();
        let secrets = graph.nodes_of_kind(NodeKind::Secret).count();
        let images = graph.nodes_of_kind(NodeKind::Image).count();
        let identities = graph.nodes_of_kind(NodeKind::Identity).count();
        wln!(
            w,
            "{}",
            format!(
                "  Steps: {steps} | Secrets: {secrets} | Actions: {images} | Identities: {identities}"
            )
            .bright_black()
        )?;

        // ── Partial graph warning ────────────────────────────────
        if is_partial {
            wln!(w)?;
            match graph.completeness {
                AuthorityCompleteness::Partial => {
                    wln!(
                        w,
                        "  {} partial graph — findings below tagged {}",
                        "note: ⚠".bright_yellow().bold(),
                        "[partial]".yellow().dimmed()
                    )?;
                    for gap in &graph.completeness_gaps {
                        wln!(w, "    {}", format!("- {gap}").yellow())?;
                    }
                }
                AuthorityCompleteness::Unknown => {
                    wln!(
                        w,
                        "  {} completeness unknown — treat as partial",
                        "note: ⚠".bright_yellow().bold()
                    )?;
                }
                AuthorityCompleteness::Complete => {}
            }
        }

        // ── Clean file ───────────────────────────────────────────
        if findings.is_empty() {
            wln!(w, "\n  {}", "✓ no findings".green().bold())?;
            return Ok(());
        }

        // ── Findings ─────────────────────────────────────────────
        wln!(w)?;
        for finding in findings {
            let sev_tag = severity_tag(finding.severity);
            let partial_tag = if is_partial {
                format!(" {}", "[partial]".yellow().dimmed())
            } else {
                String::new()
            };

            wln!(w, "{}{} {}", sev_tag, partial_tag, finding.message.bold())?;

            // Propagation path
            if let Some(ref path) = finding.path {
                let source_name = graph.node(path.source).map(|n| n.name.as_str()).unwrap_or("?");
                let source_kind = graph
                    .node(path.source)
                    .map(|n| node_kind_label(n.kind))
                    .unwrap_or("");

                if path.edges.len() <= 2 {
                    // Short path — inline
                    w!(
                        w,
                        "  {} {} {}",
                        "Path:".bright_black(),
                        source_name.bright_white(),
                        format!("({source_kind})").bright_black()
                    )?;
                    for edge_id in &path.edges {
                        if let Some(edge) = graph.edge(*edge_id) {
                            let target = graph.node(edge.to);
                            let name = target.map(|n| n.name.as_str()).unwrap_or("?");
                            let kind = target.map(|n| node_kind_label(n.kind)).unwrap_or("");
                            w!(
                                w,
                                " {} {} {}",
                                "→".bright_black(),
                                name.bright_white(),
                                format!("({kind})").bright_black()
                            )?;
                        }
                    }
                    wln!(w)?;
                } else {
                    // Long path — vertical
                    wln!(w, "  {}:", "Path".bright_black())?;
                    wln!(
                        w,
                        "      {} {}",
                        source_name.bright_white(),
                        format!("({source_kind})").bright_black()
                    )?;
                    for edge_id in &path.edges {
                        if let Some(edge) = graph.edge(*edge_id) {
                            let target = graph.node(edge.to);
                            let name = target.map(|n| n.name.as_str()).unwrap_or("?");
                            let kind = target.map(|n| node_kind_label(n.kind)).unwrap_or("");
                            wln!(
                                w,
                                "    {} {} {}",
                                "→".bright_black(),
                                name.bright_white(),
                                format!("({kind})").bright_black()
                            )?;
                        }
                    }
                }

                if self.verbose {
                    let mut path_nodes = vec![path.source];
                    for edge_id in &path.edges {
                        if let Some(edge) = graph.edge(*edge_id) {
                            path_nodes.push(edge.to);
                        }
                    }
                    emit_verbose_nodes(w, graph, &path_nodes)?;
                }
            } else if !finding.nodes_involved.is_empty() {
                // No propagation path — show involved nodes
                let nodes = &finding.nodes_involved;
                let display: Vec<String> = nodes
                    .iter()
                    .take(4)
                    .filter_map(|&id| graph.node(id))
                    .map(|n| {
                        format!(
                            "{} {}",
                            n.name.bright_white(),
                            format!("({})", node_kind_label(n.kind)).bright_black()
                        )
                    })
                    .collect();

                let suffix = if nodes.len() > 4 {
                    format!(" {}", format!("…(+{} more)", nodes.len() - 4).bright_black())
                } else {
                    String::new()
                };

                // Use the appropriate connector based on edge semantics
                let connector = if finding
                    .nodes_involved
                    .windows(2)
                    .any(|w| {
                        graph
                            .edges_from(w[0])
                            .any(|e| e.to == w[1] && e.kind == EdgeKind::PersistsTo)
                    })
                {
                    format!(" {} ", "persists→".bright_black())
                } else {
                    format!(" {} ", "→".bright_black())
                };

                wln!(
                    w,
                    "  {} {}{}",
                    "Nodes:".bright_black(),
                    display.join(&connector),
                    suffix
                )?;

                if self.verbose {
                    emit_verbose_nodes(w, graph, nodes)?;
                }
            }

            // Recommendation
            let rec = format_recommendation(&finding.recommendation);
            wln!(w, "  {} {}", "Recommendation:".green().bold(), rec.green())?;
            wln!(w)?;
        }

        Ok(())
    }
}

fn severity_tag(sev: Severity) -> String {
    match sev {
        Severity::Critical => format!("[{}]", "CRITICAL".bright_red().bold().reversed()),
        Severity::High => format!("[{}]", "HIGH".bright_red().bold()),
        Severity::Medium => format!("[{}]", "MEDIUM".yellow().bold()),
        Severity::Low => format!("[{}]", "LOW".bright_yellow()),
        Severity::Info => format!("[{}]", "INFO".bright_cyan()),
    }
}

fn node_kind_label(kind: NodeKind) -> &'static str {
    match kind {
        NodeKind::Step => "step",
        NodeKind::Secret => "secret",
        NodeKind::Identity => "identity",
        NodeKind::Artifact => "artifact",
        NodeKind::Image => "action/image",
    }
}

fn format_recommendation(rec: &Recommendation) -> String {
    match rec {
        Recommendation::TsafeRemediation { command, .. } => command.clone(),
        Recommendation::CellosRemediation { spec_hint, .. } => spec_hint.clone(),
        Recommendation::PinAction { pinned, .. } => format!("Pin to {pinned}"),
        Recommendation::ReducePermissions { minimum, .. } => {
            format!("Reduce permissions to {minimum}")
        }
        Recommendation::FederateIdentity { oidc_provider, .. } => {
            format!("Replace with {oidc_provider} OIDC")
        }
        Recommendation::Manual { action } => action.clone(),
    }
}

fn emit_verbose_nodes<W: std::io::Write>(
    w: &mut W,
    graph: &AuthorityGraph,
    node_ids: &[usize],
) -> Result<(), TauditError> {
    for &id in node_ids {
        if let Some(node) = graph.node(id) {
            let kind = node_kind_label(node.kind);
            let zone = format!("{:?}", node.trust_zone).to_lowercase();
            w!(w, "    {} ({kind}, {zone})", node.name.bright_black())?;
            if let Some(scope) = node.metadata.get("identity_scope") {
                w!(w, ", scope: {scope}")?;
            }
            if let Some(perms) = node.metadata.get("permissions") {
                w!(w, ", permissions: {perms}")?;
            }
            if let Some(digest) = node.metadata.get("digest") {
                w!(w, ", pin: {}…", &digest[..digest.len().min(12)])?;
            }
            if node.metadata.get("inferred").map(|v| v == "true").unwrap_or(false) {
                w!(w, " (inferred)")?;
            }
            wln!(w)?;
        }
    }
    Ok(())
}

/// Print the run-level banner (call once before the scan loop).
pub fn print_banner<W: std::io::Write>(w: &mut W, file_count: usize) -> std::io::Result<()> {
    writeln!(
        w,
        "{}",
        format!(
            "taudit {} — {} {}",
            env!("CARGO_PKG_VERSION"),
            file_count,
            if file_count == 1 { "file" } else { "files" }
        )
        .bright_white()
        .bold()
    )
}

/// Print the run-level summary (call once after the scan loop).
pub fn print_summary<W: std::io::Write>(
    w: &mut W,
    total_files: usize,
    files_with_findings: usize,
    clean_files: usize,
    partial_files: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
) -> std::io::Result<()> {
    writeln!(w, "{}", "─".repeat(RULE_WIDTH).bright_black())?;

    if clean_files > 0 {
        writeln!(
            w,
            "{}",
            format!("✓ {clean_files} {} clean", if clean_files == 1 { "file" } else { "files" })
                .green()
                .bold()
        )?;
    }

    let total_findings = critical + high + medium + low;
    if total_findings == 0 {
        writeln!(w, "{}", "✓ no findings across all files".green().bold())?;
        return Ok(());
    }

    write!(w, "{} ", "Summary".bright_white().bold())?;
    let mut parts = Vec::new();
    if critical > 0 {
        parts.push(format!("{}", format!("{critical} critical").bright_red().bold()));
    }
    if high > 0 {
        parts.push(format!("{}", format!("{high} high").bright_red()));
    }
    if medium > 0 {
        parts.push(format!("{}", format!("{medium} medium").yellow()));
    }
    if low > 0 {
        parts.push(format!("{}", format!("{low} low").bright_yellow()));
    }
    writeln!(w, "{}", parts.join("  "))?;

    writeln!(
        w,
        "{}",
        format!("  Files with findings: {files_with_findings} / {total_files}").bright_black()
    )?;

    if partial_files > 0 {
        writeln!(
            w,
            "{}",
            format!(
                "  Partial graphs: {partial_files} — findings from partial graphs may be incomplete"
            )
            .yellow()
        )?;
    }

    Ok(())
}
