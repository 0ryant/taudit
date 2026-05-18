use std::borrow::Cow;

use colored::Colorize;
use taudit_core::error::TauditError;
use taudit_core::finding::{Finding, FindingSource, Recommendation, Severity};
use taudit_core::graph::{AuthorityCompleteness, AuthorityGraph, EdgeKind, GapKind, NodeKind};
use taudit_core::ports::ReportSink;

/// Strip ASCII C0/C1 control characters (`\x00`-`\x1F`, `\x7F`-`\x9F`) and a
/// small set of Unicode steering codepoints (RTL/LTR overrides, zero-width
/// joiners, BOM) from `s`, EXCEPT for `\n` and `\t` which are required for
/// legitimate multi-line / tabular terminal output.
///
/// This is the **render-boundary sanitiser** for the terminal sink. Attackers
/// can plant escape-sequence payloads in pipeline YAML keys and custom-rule
/// `name`/`id` fields; once those propagate into `finding.message`,
/// `node.name`, `graph.source.file`, or completeness gap strings, a naive
/// `writeln!("{}", attacker_string.bold())` lets the attacker:
///   * clear the screen with `\x1b[2J\x1b[H` and impersonate a clean run,
///   * wrap subsequent output in fake colour codes (`\x1b[1;32m...\x1b[0m`),
///   * emit BEL (`\x07`) audio,
///   * use RTL override (`\u{202e}`) to reverse glyph order,
///   * inject zero-width joiner (`\u{200d}`) to defeat copy-paste review.
///
/// `colored::ColoredString` only WRAPS its input in CSI sequences — it does
/// not sanitise the wrapped bytes. Callers MUST run this against any
/// attacker-controllable string BEFORE handing it to `.bold()` /
/// `.bright_black()` / `format!`.
///
/// **Performance:** O(n), single-pass. Returns `Cow::Borrowed` (zero-alloc)
/// when the input is already clean; `Cow::Owned` otherwise.
///
/// **Hand-rolled, no new dependencies.**
pub fn strip_control_chars(s: &str) -> Cow<'_, str> {
    if !needs_control_strip(s) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if is_disallowed_control(c) {
            // Drop silently — replacing with a marker would itself be
            // attacker-injectable noise. The threat we're defending is
            // terminal interpretation; once the bytes are gone, the
            // interpretation can't fire.
            continue;
        }
        out.push(c);
    }
    Cow::Owned(out)
}

#[inline]
fn is_disallowed_control(c: char) -> bool {
    match c {
        '\n' | '\t' => false,
        // ASCII C0 (0x00..=0x1F) and DEL (0x7F).
        '\x00'..='\x1F' | '\x7F' => true,
        // C1 control range (0x80..=0x9F) — rarely seen in valid UTF-8 prose
        // but legal codepoints; some terminals interpret them.
        '\u{80}'..='\u{9F}' => true,
        // Bidi / steering codepoints abused for spoofing.
        '\u{200B}' // ZERO WIDTH SPACE
        | '\u{200C}' // ZERO WIDTH NON-JOINER
        | '\u{200D}' // ZERO WIDTH JOINER
        | '\u{200E}' // LEFT-TO-RIGHT MARK
        | '\u{200F}' // RIGHT-TO-LEFT MARK
        | '\u{202A}' // LEFT-TO-RIGHT EMBEDDING
        | '\u{202B}' // RIGHT-TO-LEFT EMBEDDING
        | '\u{202C}' // POP DIRECTIONAL FORMATTING
        | '\u{202D}' // LEFT-TO-RIGHT OVERRIDE
        | '\u{202E}' // RIGHT-TO-LEFT OVERRIDE
        | '\u{2066}' // LEFT-TO-RIGHT ISOLATE
        | '\u{2067}' // RIGHT-TO-LEFT ISOLATE
        | '\u{2068}' // FIRST STRONG ISOLATE
        | '\u{2069}' // POP DIRECTIONAL ISOLATE
        | '\u{FEFF}' // BOM / ZERO WIDTH NO-BREAK SPACE
        => true,
        _ => false,
    }
}

#[inline]
fn needs_control_strip(s: &str) -> bool {
    s.chars().any(is_disallowed_control)
}

/// Sanitise an attacker-controllable inline field at the terminal render
/// boundary and return an owned `String` ready to feed into `colored` or
/// `format!`.
///
/// `strip_control_chars` deliberately preserves `\n` and `\t` for callers
/// that own multi-line terminal layout. The fields passed through `clean`
/// are scalar values interpolated into renderer-owned lines (file names, node
/// names, messages, recommendations, metadata). Fold attacker-supplied line
/// breaks/tabs to spaces here so CRLF in a workflow path cannot mint a forged
/// standalone terminal line.
#[inline]
fn clean(s: &str) -> String {
    let stripped = strip_control_chars(s);
    if !stripped.chars().any(|c| matches!(c, '\n' | '\t')) {
        return stripped.into_owned();
    }

    let mut out = String::with_capacity(stripped.len());
    let mut previous_space = false;
    for c in stripped.chars() {
        if matches!(c, '\n' | '\t') {
            if !previous_space {
                out.push(' ');
                previous_space = true;
            }
        } else {
            previous_space = c == ' ';
            out.push(c);
        }
    }
    out
}

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
        // SECURITY: `graph.source.file` is attacker-controllable (a hostile
        // PR author can rename a workflow file). Strip control characters at
        // the render boundary so a filename like
        // `\x1b[2J\x1b[Hci.yml` cannot clear the screen and impersonate a
        // fresh run. Sister sinks (JSON / SARIF) ship the raw filename — only
        // the terminal renderer interprets escape bytes, so only the terminal
        // renderer sanitises. See `strip_control_chars` doc-comment.
        let source_file_clean = clean(&graph.source.file);
        wln!(w, "{}", "─".repeat(RULE_WIDTH).bright_black())?;
        wln!(
            w,
            "{}",
            format!("Authority Graph: {source_file_clean}")
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
                        // SECURITY: gap strings are derived from parser output
                        // and can include attacker-controlled YAML keys
                        // (composite-action names, expression text). Strip
                        // control chars before colouring.
                        let gap_clean = clean(gap);
                        wln!(w, "    {} {}", kind_label, gap_clean.dimmed())?;
                    }
                    // Fallback: if gap_kinds is shorter than gaps, print remaining gaps
                    // without prefix (defensive — keeps behaviour graceful if invariants slip).
                    for gap in graph
                        .completeness_gaps
                        .iter()
                        .skip(graph.completeness_gap_kinds.len())
                    {
                        let gap_clean = clean(gap);
                        wln!(w, "    {}", format!("- {gap_clean}").yellow())?;
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
            // Default-quiet: per-finding [partial] tags add a lot of inline
            // noise on long runs where every file has Expression/Structural
            // gaps (the common case). Suppress them unless --verbose, with one
            // hard exception: when the worst gap is `Opaque`, the graph is
            // effectively unusable and we always surface `[partial:opaque]`
            // inline so an operator can't miss it. The header warning and the
            // run-summary footer are unaffected — they remain always-on.
            let partial_tag = if is_partial {
                let always_show = graph.worst_gap_kind() == Some(GapKind::Opaque);
                if self.verbose || always_show {
                    if always_show && !self.verbose {
                        format!(" {}", "[partial:opaque]".red().bold())
                    } else {
                        format!(" {}", "[partial]".yellow().dimmed())
                    }
                } else {
                    // Suppressed by default for Expression/Structural gaps.
                    String::new()
                }
            } else {
                String::new()
            };

            // Custom-rule provenance prefix: surface the originating YAML
            // file path so an operator scanning the terminal output can tell
            // an authentic built-in finding from a planted custom invariant
            // without re-running with --format json. Built-in findings get
            // no prefix to keep the common path uncluttered.
            // SECURITY: `source_file` is the path to an attacker-controlled
            // YAML; even the path basename can be crafted to contain ANSI
            // sequences. Sanitise before rendering.
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
                        format!("custom: {}", clean(name))
                    };
                    format!(" {}", format!("[{label}]").magenta().dimmed())
                }
                FindingSource::BuiltIn => String::new(),
            };

            // SECURITY: `finding.message` is the most attacker-reachable
            // field. Custom-rule YAML composes the message as
            // `format!("[{id}] {name}: {nodename}")` — every component is
            // attacker-controllable. Strip control chars before bolding so a
            // crafted message like
            // `"\x1b[2J\x1b[H[1;32m✓ no findings\x1b[0m"`
            // cannot clear the screen and impersonate a clean run.
            let message_clean = clean(&finding.message);
            wln!(
                w,
                "{}{}{} {}",
                sev_tag,
                partial_tag,
                custom_tag,
                message_clean.bold()
            )?;

            // Propagation path
            // SECURITY: every `node.name` originates from YAML keys (step
            // names, secret names, environment names). All are
            // attacker-controllable. Strip control chars before colouring.
            if let Some(ref path) = finding.path {
                let source_name_owned = graph
                    .node(path.source)
                    .map(|n| clean(&n.name))
                    .unwrap_or_else(|| "?".to_string());
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
                        source_name_owned.bright_white(),
                        format!("({source_kind})").bright_black()
                    )?;
                    for edge_id in &path.edges {
                        if let Some(edge) = graph.edge(*edge_id) {
                            let target = graph.node(edge.to);
                            let name = target
                                .map(|n| clean(&n.name))
                                .unwrap_or_else(|| "?".to_string());
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
                        source_name_owned.bright_white(),
                        format!("({source_kind})").bright_black()
                    )?;
                    for edge_id in &path.edges {
                        if let Some(edge) = graph.edge(*edge_id) {
                            let target = graph.node(edge.to);
                            let name = target
                                .map(|n| clean(&n.name))
                                .unwrap_or_else(|| "?".to_string());
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
                // No propagation path — show involved nodes.
                // SECURITY: as above, sanitise each `node.name` before
                // wrapping in `colored` styling.
                let nodes = &finding.nodes_involved;
                let display: Vec<String> = nodes
                    .iter()
                    .take(4)
                    .filter_map(|&id| graph.node(id))
                    .map(|n| {
                        format!(
                            "{} {}",
                            clean(&n.name).bright_white(),
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
            // SECURITY: `Recommendation::Manual { action }` is sourced from
            // custom-rule YAML `description:` (see `evaluate_custom_rules` in
            // `taudit-core/src/custom_rules.rs`). Sanitise before colouring.
            let rec = clean(&format_recommendation(&finding.recommendation));
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
    // SECURITY: every metadata value (`scope`, `permissions`, `digest`) is
    // attacker-controllable — `permissions:` is a top-level YAML map under
    // operator control of the pipeline definition, `digest` comes from
    // `image@sha256:…` text which can be padded with control bytes before
    // the `@`, and `identity_scope` is a free-form string. Strip control
    // chars at the render boundary so a crafted `permissions:` value cannot
    // smuggle ANSI past the verbose-mode renderer.
    for &id in node_ids {
        if let Some(node) = graph.node(id) {
            let kind = node_kind_label(node.kind);
            let zone = format!("{:?}", node.trust_zone).to_lowercase();
            let name_clean = clean(&node.name);
            w!(w, "    {} ({kind}, {zone})", name_clean.bright_black())?;
            if let Some(scope) = node.metadata.get("identity_scope") {
                w!(w, ", scope: {}", clean(scope))?;
            }
            if let Some(perms) = node.metadata.get("permissions") {
                w!(w, ", permissions: {}", clean(perms))?;
            }
            if let Some(digest) = node.metadata.get("digest") {
                let digest_clean = clean(digest);
                w!(w, ", pin: {}…", &digest_clean[..digest_clean.len().min(12)])?;
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
    use taudit_core::finding::{
        Finding, FindingCategory, FindingExtras, FindingSource, Recommendation, Severity,
    };
    use taudit_core::graph::{GapKind, PipelineSource};
    use taudit_core::ports::ReportSink;

    // ── strip_control_chars unit tests ─────────────────────────────

    #[test]
    fn strip_control_chars_passes_clean_text_unchanged() {
        let clean = "AWS_KEY reaches deploy";
        let out = strip_control_chars(clean);
        assert!(
            matches!(out, Cow::Borrowed(_)),
            "clean input must zero-alloc"
        );
        assert_eq!(out, clean);
    }

    #[test]
    fn strip_control_chars_preserves_newline_and_tab() {
        let s = "line1\nline2\tcol";
        let out = strip_control_chars(s);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, s);
    }

    #[test]
    fn strip_control_chars_drops_esc_and_clear_screen() {
        // The headline attack: clear-screen + cursor-home.
        let hostile = "\x1b[2J\x1b[Hfake clean output\x1b[0m";
        let out = strip_control_chars(hostile);
        assert!(!out.contains('\x1b'), "ESC byte must be stripped");
        assert_eq!(out, "[2J[Hfake clean output[0m");
    }

    #[test]
    fn strip_control_chars_drops_bel_and_del() {
        let hostile = "ding\x07then\x7Fdel";
        let out = strip_control_chars(hostile);
        assert!(!out.bytes().any(|b| b == 0x07));
        assert!(!out.bytes().any(|b| b == 0x7F));
        assert_eq!(out, "dingthendel");
    }

    #[test]
    fn strip_control_chars_drops_rtl_and_zwj() {
        let hostile = "user\u{202E}name\u{200D}joiner";
        let out = strip_control_chars(hostile);
        assert!(!out.contains('\u{202E}'));
        assert!(!out.contains('\u{200D}'));
        assert_eq!(out, "usernamejoiner");
    }

    #[test]
    fn strip_control_chars_preserves_emoji_and_unicode_prose() {
        let s = "✓ no findings — Authority Graph: ci.yml";
        let out = strip_control_chars(s);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, s);
    }

    #[test]
    fn strip_control_chars_drops_c1_range() {
        // 0x80..=0x9F is the C1 control range. Some terminals interpret it.
        let hostile = "before\u{0080}\u{009F}after";
        let out = strip_control_chars(hostile);
        assert_eq!(out, "beforeafter");
    }

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

    /// Minimal finding for verbosity tests. Severity Medium so the rendered
    /// line contains `[MEDIUM]` — used as a neighbour in substring assertions
    /// to be sure we're inspecting the per-finding line, not the header.
    fn test_finding() -> Finding {
        Finding {
            severity: Severity::Medium,
            category: FindingCategory::UnpinnedAction,
            path: None,
            nodes_involved: vec![],
            message: "test finding for verbosity gating".into(),
            recommendation: Recommendation::Manual {
                action: "fix".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        }
    }

    /// Render a graph + findings at the requested verbosity. Mirrors the
    /// no-findings `render` helper above, but lets each verbosity test pin
    /// the `verbose` flag explicitly and supply its own findings vector.
    fn render_with(graph: &AuthorityGraph, findings: &[Finding], verbose: bool) -> String {
        colored::control::set_override(false);
        let reporter = TerminalReport { verbose };
        let mut buf: Vec<u8> = Vec::new();
        reporter
            .emit(&mut buf, graph, findings)
            .expect("emit should succeed");
        let raw = String::from_utf8(buf).expect("utf-8 output");
        strip_ansi(&raw)
    }

    #[test]
    fn default_quiet_structural_gap_suppresses_inline_tag() {
        let mut g = test_graph();
        g.mark_partial(GapKind::Structural, "composite unresolved");
        let findings = vec![test_finding()];
        let out = render_with(&g, &findings, false);

        // Header warning stays always-on — confirms we didn't break Phase 1.
        assert!(
            out.contains("note: ⚠"),
            "expected structural header 'note: ⚠', got:\n{out}"
        );
        // The per-finding inline tag must be suppressed in default-quiet mode
        // for Structural gaps. Anchor the search to the finding line itself
        // (after `[MEDIUM]`) so the `[partial]` substring inside the header
        // hint can't false-positive this check.
        let finding_line = out
            .lines()
            .find(|l| l.contains("[MEDIUM]"))
            .expect("expected a finding line containing [MEDIUM]");
        assert!(
            !finding_line.contains("[partial]"),
            "default-quiet should suppress inline [partial] for Structural, \
             but finding line had it: {finding_line}"
        );
        assert!(
            !finding_line.contains("[partial:opaque]"),
            "Structural gap must not render [partial:opaque]: {finding_line}"
        );
    }

    #[test]
    fn default_quiet_opaque_gap_shows_inline_tag() {
        let mut g = test_graph();
        g.mark_partial(GapKind::Opaque, "zero steps");
        let findings = vec![test_finding()];
        let out = render_with(&g, &findings, false);

        // Header still shows the opaque error prefix.
        assert!(
            out.contains("error: ⛔"),
            "expected opaque header 'error: ⛔', got:\n{out}"
        );
        // Opaque gaps override the default-quiet suppression: the inline
        // `[partial:opaque]` tag must appear on the finding line so a total
        // graph failure can't slip past triage.
        let finding_line = out
            .lines()
            .find(|l| l.contains("[MEDIUM]"))
            .expect("expected a finding line containing [MEDIUM]");
        assert!(
            finding_line.contains("[partial:opaque]"),
            "Opaque gap must render inline [partial:opaque] even in quiet mode: {finding_line}"
        );
    }

    #[test]
    fn verbose_structural_gap_shows_inline_tag() {
        let mut g = test_graph();
        g.mark_partial(GapKind::Structural, "composite unresolved");
        let findings = vec![test_finding()];
        let out = render_with(&g, &findings, true);

        // With --verbose the legacy `[partial]` tag returns for non-opaque
        // gaps. Confirm it lands on the finding line, not just the header.
        let finding_line = out
            .lines()
            .find(|l| l.contains("[MEDIUM]"))
            .expect("expected a finding line containing [MEDIUM]");
        assert!(
            finding_line.contains("[partial]"),
            "verbose should render inline [partial] for Structural gap: {finding_line}"
        );
        // Make sure we didn't accidentally promote a structural gap to opaque
        // styling under --verbose.
        assert!(
            !finding_line.contains("[partial:opaque]"),
            "Structural gap must not render [partial:opaque] under --verbose: {finding_line}"
        );
    }

    /// Mirror of `taudit-report-json::tests::json_output_is_byte_deterministic_across_runs`.
    /// The terminal renderer walks the same `AuthorityGraph` HashMaps the JSON
    /// sink does (node metadata, edge endpoints, ordered findings) so any leak
    /// of HashMap order would show up as text-line shuffling between runs.
    /// Force `colored::control::set_override(false)` to drop ANSI (text colour
    /// is process-global state — see `render` above), then emit 9× and assert
    /// every byte matches.
    #[test]
    fn terminal_output_is_byte_deterministic_across_runs() {
        use std::collections::HashMap;
        use taudit_core::graph::{EdgeKind, NodeKind, TrustZone};

        fn build_graph() -> (AuthorityGraph, Vec<Finding>) {
            let mut graph = AuthorityGraph::new(PipelineSource {
                file: "ci.yml".into(),
                repo: None,
                git_ref: None,
                commit_sha: None,
            });
            let secret_a = graph.add_node(NodeKind::Secret, "AWS_KEY", TrustZone::FirstParty);
            let secret_b = graph.add_node(NodeKind::Secret, "DEPLOY_TOKEN", TrustZone::FirstParty);
            let step = graph.add_node(NodeKind::Step, "deploy", TrustZone::FirstParty);
            graph.add_edge(step, secret_a, EdgeKind::HasAccessTo);
            graph.add_edge(step, secret_b, EdgeKind::HasAccessTo);
            if let Some(node) = graph.nodes.get_mut(step) {
                let mut meta: HashMap<String, String> = HashMap::new();
                meta.insert("z_field".into(), "z".into());
                meta.insert("a_field".into(), "a".into());
                meta.insert("m_field".into(), "m".into());
                meta.insert("k_field".into(), "k".into());
                meta.insert("c_field".into(), "c".into());
                node.metadata = meta;
            }
            graph
                .metadata
                .insert("trigger".into(), "pull_request".into());
            graph.metadata.insert("platform".into(), "github".into());
            let findings = vec![Finding {
                severity: Severity::High,
                category: FindingCategory::AuthorityPropagation,
                path: None,
                nodes_involved: vec![secret_a, step],
                message: "AWS_KEY reaches deploy".into(),
                recommendation: Recommendation::Manual {
                    action: "scope it".into(),
                },
                source: FindingSource::BuiltIn,
                extras: FindingExtras::default(),
            }];
            (graph, findings)
        }

        // ANSI escape codes depend on a process-global flag — pin it off so
        // a parallel test that flips it can't smuggle non-determinism in.
        colored::control::set_override(false);

        let mut runs: Vec<Vec<u8>> = Vec::with_capacity(9);
        for _ in 0..9 {
            let (g, f) = build_graph();
            let mut buf: Vec<u8> = Vec::new();
            TerminalReport { verbose: false }
                .emit(&mut buf, &g, &f)
                .expect("emit should succeed");
            runs.push(buf);
        }

        let first = &runs[0];
        for (i, run) in runs.iter().enumerate().skip(1) {
            assert_eq!(
                first, run,
                "run 0 and run {i} produced byte-different terminal output (non-determinism regression)"
            );
        }
    }
}
