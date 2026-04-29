use colored::Colorize;
use taudit_core::error::TauditError;
use taudit_core::finding::{Finding, FindingSource, Recommendation, Severity};
use taudit_core::graph::{AuthorityCompleteness, AuthorityGraph, EdgeKind, GapKind, NodeKind};
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
                    let header_prefix = match graph.worst_gap_kind() {
                        Some(GapKind::Opaque) => "error: ⛔".red().bold().to_string(),
                        Some(GapKind::Expression) => "note: ·".dimmed().to_string(),
                        // Structural or None
                        _ => "note: ⚠".bright_yellow().bold().to_string(),
                    };
                    wln!(
                        w,
                        "  {} partial graph — findings below tagged {}",
                        header_prefix,
                        "[partial]".yellow().dimmed()
                    )?;
                    for (kind, gap) in graph
                        .completeness_gap_kinds
                        .iter()
                        .zip(graph.completeness_gaps.iter())
                    {
                        let kind_label = match kind {
                            GapKind::Opaque => "[opaque]".red().to_string(),
                            GapKind::Structural => "[structural]".yellow().to_string(),
                            GapKind::Expression => "[expression]".dimmed().to_string(),
                        };
                        wln!(w, "    {} {}", kind_label, gap.dimmed())?;
                    }
                    // Fallback: if gap_kinds is shorter than gaps, print remaining gaps
                    // without prefix (defensive — keeps behaviour graceful if invariants slip).
                    for gap in graph
                        .completeness_gaps
                        .iter()
                        .skip(graph.completeness_gap_kinds.len())
                    {
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

            // Custom-rule provenance prefix: surface the originating YAML
            // file path so an operator scanning the terminal output can tell
            // an authentic built-in finding from a planted custom invariant
            // without re-running with --format json. Built-in findings get
            // no prefix to keep the common path uncluttered.
            let custom_tag = match &finding.source {
                FindingSource::Custom { source_file } => {
                    let label = if source_file.as_os_str().is_empty() {
                        "custom".to_string()
                    } else {
                        // Show the file name only — full path noise overwhelms
                        // terminal width. JSON / SARIF carry the absolute path.
                        let name = source_file
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or_else(|| source_file.to_str().unwrap_or("custom"));
                        format!("custom: {name}")
                    };
                    format!(" {}", format!("[{label}]").magenta().dimmed())
                }
                FindingSource::BuiltIn => String::new(),
            };

            wln!(
                w,
                "{}{}{} {}",
                sev_tag,
                partial_tag,
                custom_tag,
                finding.message.bold()
            )?;

            // Propagation path
            if let Some(ref path) = finding.path {
                let source_name = graph
                    .node(path.source)
                    .map(|n| n.name.as_str())
                    .unwrap_or("?");
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
                    format!(
                        " {}",
                        format!("…(+{} more)", nodes.len() - 4).bright_black()
                    )
                } else {
                    String::new()
                };

                // Use the appropriate connector based on edge semantics
                let connector = if finding.nodes_involved.windows(2).any(|w| {
                    graph
                        .edges_from(w[0])
                        .any(|e| e.to == w[1] && e.kind == EdgeKind::PersistsTo)
                }) {
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
            if node
                .metadata
                .get("inferred")
                .map(|v| v == "true")
                .unwrap_or(false)
            {
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

/// Counts for the run-level summary footer.
pub struct RunSummary {
    pub total_files: usize,
    pub files_with_findings: usize,
    pub clean_files: usize,
    pub partial_files: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

/// Print the run-level summary (call once after the scan loop).
pub fn print_summary<W: std::io::Write>(w: &mut W, s: &RunSummary) -> std::io::Result<()> {
    writeln!(w, "{}", "─".repeat(RULE_WIDTH).bright_black())?;

    if s.clean_files > 0 {
        writeln!(
            w,
            "{}",
            format!(
                "✓ {} {} clean",
                s.clean_files,
                if s.clean_files == 1 { "file" } else { "files" }
            )
            .green()
            .bold()
        )?;
    }

    let total_findings = s.critical + s.high + s.medium + s.low;
    if total_findings == 0 {
        writeln!(w, "{}", "✓ no findings across all files".green().bold())?;
        return Ok(());
    }

    write!(w, "{} ", "Summary".bright_white().bold())?;
    let mut parts = Vec::new();
    if s.critical > 0 {
        parts.push(format!(
            "{}",
            format!("{} critical", s.critical).bright_red().bold()
        ));
    }
    if s.high > 0 {
        parts.push(format!("{}", format!("{} high", s.high).bright_red()));
    }
    if s.medium > 0 {
        parts.push(format!("{}", format!("{} medium", s.medium).yellow()));
    }
    if s.low > 0 {
        parts.push(format!("{}", format!("{} low", s.low).bright_yellow()));
    }
    writeln!(w, "{}", parts.join("  "))?;

    writeln!(
        w,
        "{}",
        format!(
            "  Files with findings: {} / {}",
            s.files_with_findings, s.total_files
        )
        .bright_black()
    )?;

    if s.partial_files > 0 {
        writeln!(
            w,
            "{}",
            format!(
                "  Partial graphs: {} — findings from partial graphs may be incomplete",
                s.partial_files
            )
            .yellow()
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use taudit_core::graph::{GapKind, PipelineSource};
    use taudit_core::ports::ReportSink;

    /// Build a fresh graph for tests. Single mutex-free entry point — keeps each
    /// test self-contained.
    fn test_graph() -> AuthorityGraph {
        AuthorityGraph::new(PipelineSource {
            file: "test.yml".into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        })
    }

    /// Render a graph with no findings and return the raw string. Disables ANSI
    /// colour codes so substring assertions stay deterministic.
    fn render(graph: &AuthorityGraph) -> String {
        // Force colour off so assertions can compare against plain text.
        // Other tests in this binary may run in parallel and re-enable colour;
        // since we set BEFORE rendering and the override is process-global, the
        // only safe pattern across crates is to drop ANSI from the output.
        // We do both: set_override(false) AND strip any residual escapes.
        colored::control::set_override(false);
        let reporter = TerminalReport { verbose: false };
        let mut buf: Vec<u8> = Vec::new();
        reporter
            .emit(&mut buf, graph, &[])
            .expect("emit should succeed");
        let raw = String::from_utf8(buf).expect("utf-8 output");
        strip_ansi(&raw)
    }

    /// Strip ANSI CSI escape sequences (`ESC [ ... <final-byte> `) while
    /// preserving multi-byte UTF-8 (⛔, ⚠, ·, →). Iterates over chars, not
    /// bytes, so glyphs survive intact when colour override happens to be
    /// re-enabled by a neighbouring test sharing this process.
    fn strip_ansi(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\u{1B}' && chars.peek() == Some(&'[') {
                chars.next(); // consume '['
                              // CSI runs until a final byte in 0x40..=0x7E.
                for fc in chars.by_ref() {
                    let cp = fc as u32;
                    if (0x40..=0x7E).contains(&cp) {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn opaque_gap_header_shows_error_prefix() {
        let mut g = test_graph();
        g.mark_partial(GapKind::Opaque, "zero steps");
        let out = render(&g);
        assert!(
            out.contains("error: ⛔"),
            "expected opaque header 'error: ⛔', got:\n{out}"
        );
        assert!(
            out.contains("[opaque]"),
            "expected [opaque] gap label, got:\n{out}"
        );
    }

    #[test]
    fn structural_gap_header_shows_warning_prefix() {
        let mut g = test_graph();
        g.mark_partial(GapKind::Structural, "composite unresolved");
        let out = render(&g);
        assert!(
            out.contains("note: ⚠"),
            "expected structural header 'note: ⚠', got:\n{out}"
        );
        assert!(
            out.contains("[structural]"),
            "expected [structural] gap label, got:\n{out}"
        );
    }

    #[test]
    fn expression_gap_header_shows_note_prefix() {
        let mut g = test_graph();
        g.mark_partial(GapKind::Expression, "matrix hides paths");
        let out = render(&g);
        assert!(
            out.contains("note: ·"),
            "expected expression header 'note: ·', got:\n{out}"
        );
        assert!(
            out.contains("[expression]"),
            "expected [expression] gap label, got:\n{out}"
        );
    }
}
