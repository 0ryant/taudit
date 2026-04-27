use crate::graph::{
    AuthorityCompleteness, AuthorityGraph, EdgeKind, NodeId, NodeKind, TrustZone,
    META_IDENTITY_SCOPE, META_JOB_NAME,
};
use std::collections::{HashSet, VecDeque};

/// A row in the authority map: one step and its authority grants.
#[derive(Debug)]
pub struct MapRow {
    pub step_name: String,
    pub trust_zone: String,
    /// Index into the `authorities` Vec — true if this step has access.
    pub access: Vec<bool>,
}

/// Authority map: which steps have access to which secrets/identities.
#[derive(Debug)]
pub struct AuthorityMap {
    /// Column headers: authority source names (secrets + identities).
    pub authorities: Vec<String>,
    /// One row per step.
    pub rows: Vec<MapRow>,
}

/// Build the authority map from a graph.
pub fn authority_map(graph: &AuthorityGraph) -> AuthorityMap {
    // Collect authority sources with all metadata needed for disambiguation.
    // Two-pass approach: first gather raw data, then detect collisions and qualify.
    struct RawAuthority {
        id: NodeId,
        name: String,
        zone: String,
        scope: Option<String>,
    }

    let raw: Vec<RawAuthority> = graph
        .authority_sources()
        .map(|n| RawAuthority {
            id: n.id,
            name: n.name.clone(),
            zone: format!("{:?}", n.trust_zone),
            scope: n.metadata.get(META_IDENTITY_SCOPE).cloned(),
        })
        .collect();

    // Pass 1: count name occurrences to detect collisions.
    let mut name_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for r in &raw {
        *name_counts.entry(r.name.as_str()).or_insert(0) += 1;
    }

    // Pass 2: build display names, qualifying any that collide.
    // Track (name, qualifier) occurrences so we can append numeric suffixes
    // when the qualifier alone still collides.
    let mut qualifier_counts: std::collections::HashMap<(String, String), usize> =
        std::collections::HashMap::new();
    for r in &raw {
        if name_counts.get(r.name.as_str()).copied().unwrap_or(0) > 1 {
            let qualifier = r.scope.clone().unwrap_or_else(|| r.zone.clone());
            *qualifier_counts
                .entry((r.name.clone(), qualifier))
                .or_insert(0) += 1;
        }
    }

    let mut seen: std::collections::HashMap<(String, String), usize> =
        std::collections::HashMap::new();
    let authority_names: Vec<String> = raw
        .iter()
        .map(|r| {
            if name_counts.get(r.name.as_str()).copied().unwrap_or(0) <= 1 {
                // Unique name — no qualifier needed.
                r.name.clone()
            } else {
                let qualifier = r.scope.clone().unwrap_or_else(|| r.zone.clone());
                let key = (r.name.clone(), qualifier.clone());
                let total_with_qualifier = qualifier_counts.get(&key).copied().unwrap_or(1);
                let idx = {
                    let entry = seen.entry(key).or_insert(0);
                    *entry += 1;
                    *entry
                };
                if total_with_qualifier <= 1 {
                    // Qualifier alone is sufficient.
                    format!("{} ({})", r.name, qualifier)
                } else {
                    // Multiple share the same qualifier — append numeric index.
                    format!("{} ({}#{})", r.name, qualifier, idx)
                }
            }
        })
        .collect();

    // `authorities` keeps the original node name for internal lookup;
    // `authority_names` holds the qualified display names used for rendering.
    let authorities: Vec<(NodeId, String)> = raw.iter().map(|r| (r.id, r.name.clone())).collect();

    // Build rows for each step
    let mut rows = Vec::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        let mut access = vec![false; authorities.len()];

        for edge in graph.edges_from(step.id) {
            if edge.kind != EdgeKind::HasAccessTo {
                continue;
            }
            // Find which authority column this maps to
            if let Some(idx) = authorities.iter().position(|(id, _)| *id == edge.to) {
                access[idx] = true;
            }
        }

        rows.push(MapRow {
            step_name: step.name.clone(),
            trust_zone: format!("{:?}", step.trust_zone),
            access,
        });
    }

    AuthorityMap {
        authorities: authority_names,
        rows,
    }
}

/// Abbreviate a trust-zone debug string to a 2-char code so the zone column
/// stays narrow regardless of the variant name length.
fn zone_abbr(zone: &str) -> &'static str {
    match zone {
        "FirstParty" => "1P",
        "ThirdParty" => "3P",
        _ => "?",
    }
}

/// Truncate a string to at most `max` chars, appending `…` when cut.
fn trunc(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}

/// Render the authority map as a formatted table string.
///
/// `term_width` controls column-group pagination. Authority columns are
/// packed left-to-right into groups narrow enough to fit; each group is
/// emitted as a separate mini-table with a "(columns M–N of T)" label.
/// Pass `usize::MAX` to disable pagination.
pub fn render_map(map: &AuthorityMap, term_width: usize) -> String {
    if map.rows.is_empty() && map.authorities.is_empty() {
        return "No steps or authority sources found.\n".to_string();
    }

    // Fixed left columns: Step (capped) + Zone (always "1P"/"3P"/"?", 2 chars)
    const MAX_STEP: usize = 28;
    const MAX_COL: usize = 18;
    const ZONE_W: usize = 4; // "Zone" header

    let step_width = map
        .rows
        .iter()
        .map(|r| r.step_name.chars().count().min(MAX_STEP))
        .max()
        .unwrap_or(4)
        .max(4);

    // "Step  Zone  " prefix width (step + 2 spaces + zone + 2 spaces)
    let prefix_width = step_width + 2 + ZONE_W + 2;

    // Build display names for authority columns, capped to MAX_COL.
    let display_names: Vec<String> = map.authorities.iter().map(|a| trunc(a, MAX_COL)).collect();
    let any_truncated = display_names
        .iter()
        .zip(map.authorities.iter())
        .any(|(d, o)| d != o);

    // Each authority column occupies: display_name_width + 2 (leading spaces).
    let auth_widths: Vec<usize> = display_names
        .iter()
        .map(|a| a.chars().count().max(3))
        .collect();

    // Split authorities into column groups that fit inside term_width.
    // Each group: prefix_width + sum(auth_widths[i] + 2).
    // Always include at least 1 column per group to avoid stalling.
    let total_cols = auth_widths.len();
    let mut groups: Vec<(usize, usize)> = Vec::new(); // (start_idx, end_idx exclusive)
    let mut gi = 0;
    while gi < total_cols {
        let mut used = prefix_width;
        let mut end = gi;
        while end < total_cols {
            let next = used + auth_widths[end] + 2;
            if next > term_width && end > gi {
                break;
            }
            used = next;
            end += 1;
        }
        groups.push((gi, end));
        gi = end;
    }

    let multi_group = groups.len() > 1;
    let mut out = String::new();

    for (group_idx, &(start, end)) in groups.iter().enumerate() {
        if multi_group {
            out.push_str(&format!(
                "  columns {}-{} of {}\n",
                start + 1,
                end,
                total_cols
            ));
        }

        // Header row
        out.push_str(&format!(
            "{:<step_w$}  {:<zone_w$}",
            "Step",
            "Zone",
            step_w = step_width,
            zone_w = ZONE_W,
        ));
        for (name, w) in display_names[start..end]
            .iter()
            .zip(&auth_widths[start..end])
        {
            out.push_str(&format!("  {name:^w$}"));
        }
        out.push('\n');

        // Separator
        out.push_str(&"-".repeat(step_width));
        out.push_str("  ");
        out.push_str(&"-".repeat(ZONE_W));
        for w in &auth_widths[start..end] {
            out.push_str("  ");
            out.push_str(&"-".repeat(*w));
        }
        out.push('\n');

        // Data rows
        for row in &map.rows {
            let step_display = trunc(&row.step_name, MAX_STEP);
            let zone_display = zone_abbr(&row.trust_zone);
            out.push_str(&format!(
                "{step_display:<step_width$}  {zone_display:<ZONE_W$}"
            ));
            for (col, w) in auth_widths[start..end].iter().enumerate() {
                let marker = if row.access[start + col] { "✓" } else { "·" };
                out.push_str(&format!("  {marker:^w$}"));
            }
            out.push('\n');
        }

        if group_idx + 1 < groups.len() {
            out.push('\n');
        }
    }

    if any_truncated {
        out.push_str(&format!(
            "\nnote: column names truncated to {MAX_COL} chars\n"
        ));
    }

    out
}

// ── Graphviz DOT rendering ────────────────────────────────

/// DOT shape for a node kind. Stable mapping — referenced by tests and docs.
fn dot_shape(kind: NodeKind) -> &'static str {
    match kind {
        NodeKind::Step => "ellipse",
        NodeKind::Secret => "box",
        NodeKind::Identity => "diamond",
        NodeKind::Artifact => "hexagon",
        NodeKind::Image => "cylinder",
    }
}

/// DOT color for a trust zone. Green/yellow/red ladder by descending trust.
fn dot_color(zone: TrustZone) -> &'static str {
    match zone {
        TrustZone::FirstParty => "green",
        TrustZone::ThirdParty => "yellow",
        TrustZone::Untrusted => "red",
    }
}

/// Snake-case label for an edge kind. Keeps DOT output grep-able and matches
/// the constant names downstream tooling already understands.
fn edge_label(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::HasAccessTo => "has_access_to",
        EdgeKind::Produces => "produces",
        EdgeKind::Consumes => "consumes",
        EdgeKind::UsesImage => "uses_image",
        EdgeKind::DelegatesTo => "delegates_to",
        EdgeKind::PersistsTo => "persists_to",
    }
}

/// Escape a string for safe inclusion inside a DOT double-quoted literal.
/// DOT spec: backslash and double-quote must be escaped; newlines become `\n`.
fn dot_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// Build the set of node ids reachable (in either direction) from any seed
/// node, treating edges as undirected for the purpose of subgraph extraction.
/// This is what `--job <name>` filtering uses: start from every Step in the
/// requested job, then expand outward to capture every secret, identity,
/// image, and artifact transitively connected to that job's authority surface.
fn reachable_set(graph: &AuthorityGraph, seeds: &[NodeId]) -> HashSet<NodeId> {
    let mut visited: HashSet<NodeId> = HashSet::new();
    let mut queue: VecDeque<NodeId> = VecDeque::new();
    for &s in seeds {
        if visited.insert(s) {
            queue.push_back(s);
        }
    }
    while let Some(n) = queue.pop_front() {
        for e in &graph.edges {
            let next = if e.from == n {
                Some(e.to)
            } else if e.to == n {
                Some(e.from)
            } else {
                None
            };
            if let Some(nx) = next {
                if visited.insert(nx) {
                    queue.push_back(nx);
                }
            }
        }
    }
    visited
}

/// Render the authority graph as a Graphviz DOT digraph string.
///
/// When `filter_job` is `Some(name)`, restricts the output to the subgraph
/// reachable (in either edge direction) from any Step node whose
/// `META_JOB_NAME` metadata equals `name`. When `None`, includes every node
/// and edge.
///
/// Output is deterministic — nodes and edges are emitted in their stored
/// (insertion) order, which makes the result diff-friendly and testable.
pub fn render_dot(graph: &AuthorityGraph, filter_job: Option<&str>) -> String {
    let included: Option<HashSet<NodeId>> = match filter_job {
        Some(name) => {
            let seeds: Vec<NodeId> = graph
                .nodes
                .iter()
                .filter(|n| {
                    n.kind == NodeKind::Step
                        && n.metadata.get(META_JOB_NAME).map(String::as_str) == Some(name)
                })
                .map(|n| n.id)
                .collect();
            Some(reachable_set(graph, &seeds))
        }
        None => None,
    };

    let mut out = String::new();
    out.push_str("digraph taudit {\n");
    out.push_str("    rankdir=LR;\n");
    out.push_str("    node [fontname=\"Helvetica\"];\n");

    for node in &graph.nodes {
        if let Some(ref keep) = included {
            if !keep.contains(&node.id) {
                continue;
            }
        }
        out.push_str(&format!(
            "    \"n{}\" [label=\"{}\" shape={} color={}];\n",
            node.id,
            dot_escape(&node.name),
            dot_shape(node.kind),
            dot_color(node.trust_zone),
        ));
    }

    for edge in &graph.edges {
        if let Some(ref keep) = included {
            if !keep.contains(&edge.from) || !keep.contains(&edge.to) {
                continue;
            }
        }
        out.push_str(&format!(
            "    \"n{}\" -> \"n{}\" [label=\"{}\"];\n",
            edge.from,
            edge.to,
            edge_label(edge.kind),
        ));
    }

    out.push_str("}\n");
    out
}

/// Escape a string for safe use inside a Mermaid flowchart **node** or **edge**
/// label (GitHub-Flavored Markdown renderer). We avoid raw `[` `]` `|` and
/// HTML special characters in the emitted source so diagrams stay parseable.
fn mermaid_label_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\n' | '\r' => out.push(' '),
            // Break Mermaid / Markdown delimiters
            '|' => out.push_str("&#124;"),
            '[' => out.push_str("&#91;"),
            ']' => out.push_str("&#93;"),
            '{' | '}' => out.push('·'),
            _ => out.push(c),
        }
    }
    out
}

/// Mermaid `flowchart` node line for a single graph node, matching DOT shape
/// intent (step ≈ rounded, box, diamond, …).
fn mermaid_node_line(node: &crate::graph::Node) -> String {
    let id = node.id;
    let esc = mermaid_label_escape(&node.name);
    match node.kind {
        NodeKind::Step => format!(r#"    n{id}("{esc}")"#),
        NodeKind::Secret => format!(r#"    n{id}["{esc}"]"#),
        NodeKind::Identity => format!(r#"    n{id}{{"{esc}"}}"#),
        NodeKind::Artifact => format!(r#"    n{id}[["{esc}"]]"#),
        NodeKind::Image => format!(r#"    n{id}[("{esc}")]"#),
    }
}

/// Render the authority graph as a Mermaid `flowchart LR` (parity with
/// `render_dot`'s `rankdir=LR`).
///
/// `filter_job` uses the same reachability semantics as [`render_dot`]. When
/// the graph is not [`AuthorityCompleteness::Complete`], a leading `%%`
/// comment notes partiality; JSON export remains the source of detail.
pub fn render_mermaid(graph: &AuthorityGraph, filter_job: Option<&str>) -> String {
    let included: Option<HashSet<NodeId>> = match filter_job {
        Some(name) => {
            let seeds: Vec<NodeId> = graph
                .nodes
                .iter()
                .filter(|n| {
                    n.kind == NodeKind::Step
                        && n.metadata.get(META_JOB_NAME).map(String::as_str) == Some(name)
                })
                .map(|n| n.id)
                .collect();
            Some(reachable_set(graph, &seeds))
        }
        None => None,
    };

    let mut out = String::new();
    if graph.completeness != AuthorityCompleteness::Complete {
        out.push_str(
            "%% taudit: authority graph is not Complete; use JSON for completeness and gaps\n",
        );
    }
    out.push_str("flowchart LR\n");

    for node in &graph.nodes {
        if let Some(ref keep) = included {
            if !keep.contains(&node.id) {
                continue;
            }
        }
        out.push_str(&mermaid_node_line(node));
        out.push('\n');
    }

    for edge in &graph.edges {
        if let Some(ref keep) = included {
            if !keep.contains(&edge.from) || !keep.contains(&edge.to) {
                continue;
            }
        }
        let el = mermaid_label_escape(edge_label(edge.kind));
        out.push_str(&format!("    n{} -->|{}| n{}\n", edge.from, el, edge.to));
    }

    out
}

/// Distinct job names attached to Step nodes via `META_JOB_NAME`.
/// Sorted alphabetically — used to render helpful error messages when a
/// user passes `--job <name>` that doesn't match any step.
pub fn job_names(graph: &AuthorityGraph) -> Vec<String> {
    let mut names: Vec<String> = graph
        .nodes
        .iter()
        .filter(|n| n.kind == NodeKind::Step)
        .filter_map(|n| n.metadata.get(META_JOB_NAME).cloned())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    names.sort();
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::*;

    fn source(file: &str) -> PipelineSource {
        PipelineSource {
            file: file.into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        }
    }

    #[test]
    fn map_shows_step_access() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let secret = g.add_node(NodeKind::Secret, "API_KEY", TrustZone::FirstParty);
        let token = g.add_node(NodeKind::Identity, "GITHUB_TOKEN", TrustZone::FirstParty);
        let build = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        let deploy = g.add_node(NodeKind::Step, "deploy", TrustZone::ThirdParty);

        g.add_edge(build, secret, EdgeKind::HasAccessTo);
        g.add_edge(build, token, EdgeKind::HasAccessTo);
        g.add_edge(deploy, token, EdgeKind::HasAccessTo);

        let map = authority_map(&g);
        assert_eq!(map.authorities.len(), 2);
        assert_eq!(map.rows.len(), 2);

        // build has access to both
        let build_row = &map.rows[0];
        assert!(build_row.access[0]); // API_KEY
        assert!(build_row.access[1]); // GITHUB_TOKEN

        // deploy has access to token only
        let deploy_row = &map.rows[1];
        assert!(!deploy_row.access[0]); // no API_KEY
        assert!(deploy_row.access[1]); // GITHUB_TOKEN
    }

    #[test]
    fn map_renders_table() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let secret = g.add_node(NodeKind::Secret, "KEY", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let map = authority_map(&g);
        let table = render_map(&map, 120);
        assert!(table.contains("build"));
        assert!(table.contains("KEY"));
        assert!(table.contains('✓'));
    }

    #[test]
    fn dot_output_contains_expected_node_and_edge() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let secret = g.add_node(NodeKind::Secret, "API_KEY", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let dot = render_dot(&g, None);
        assert!(dot.starts_with("digraph taudit"), "dot output: {dot}");
        // Node lines for both endpoints with their kind-driven shapes.
        assert!(
            dot.contains(&format!("\"n{step}\" [label=\"build\" shape=ellipse")),
            "missing step node line in: {dot}"
        );
        assert!(
            dot.contains(&format!("\"n{secret}\" [label=\"API_KEY\" shape=box")),
            "missing secret node line in: {dot}"
        );
        // Edge line with snake-case label.
        assert!(
            dot.contains(&format!(
                "\"n{step}\" -> \"n{secret}\" [label=\"has_access_to\"]"
            )),
            "missing edge line in: {dot}"
        );
    }

    #[test]
    fn mermaid_output_contains_expected_node_and_edge() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let secret = g.add_node(NodeKind::Secret, "API_KEY", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let mer = render_mermaid(&g, None);
        assert!(mer.starts_with("flowchart LR"), "mermaid output: {mer}");
        assert!(
            mer.contains(&format!(r#"n{}("build")"#, step)),
            "missing step node line in: {mer}"
        );
        assert!(
            mer.contains(&format!(r#"n{}["API_KEY"]"#, secret)),
            "missing secret node line in: {mer}"
        );
        assert!(
            mer.contains(&format!("n{} -->|has_access_to| n{}", step, secret)),
            "missing edge line in: {mer}"
        );
        assert!(
            !mer.starts_with("%%"),
            "complete graph should not lead with partiality comment: {mer}"
        );
    }

    #[test]
    fn mermaid_partial_graph_leads_with_completeness_comment() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let secret = g.add_node(NodeKind::Secret, "K", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "s", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);
        g.mark_partial("fixture: unresolved composite");

        let mer = render_mermaid(&g, None);
        assert!(
            mer.starts_with("%% taudit: authority graph is not Complete"),
            "expected partiality banner: {mer}"
        );
    }

    #[test]
    fn mermaid_job_filter_matches_dot_subset() {
        let mut g = AuthorityGraph::new(source("ci.yml"));

        let build_secret = g.add_node(NodeKind::Secret, "BUILD_SECRET", TrustZone::FirstParty);
        let mut build_meta = std::collections::HashMap::new();
        build_meta.insert(META_JOB_NAME.to_string(), "build".to_string());
        let build_step =
            g.add_node_with_metadata(NodeKind::Step, "compile", TrustZone::FirstParty, build_meta);
        g.add_edge(build_step, build_secret, EdgeKind::HasAccessTo);

        let deploy_secret = g.add_node(NodeKind::Secret, "DEPLOY_SECRET", TrustZone::FirstParty);
        let mut deploy_meta = std::collections::HashMap::new();
        deploy_meta.insert(META_JOB_NAME.to_string(), "deploy".to_string());
        let deploy_step =
            g.add_node_with_metadata(NodeKind::Step, "ship", TrustZone::FirstParty, deploy_meta);
        g.add_edge(deploy_step, deploy_secret, EdgeKind::HasAccessTo);

        let full = render_mermaid(&g, None);
        let filtered = render_mermaid(&g, Some("build"));

        assert!(full.contains("BUILD_SECRET") && full.contains("DEPLOY_SECRET"));
        assert!(filtered.contains("BUILD_SECRET"));
        assert!(
            !filtered.contains("DEPLOY_SECRET"),
            "deploy-job nodes leaked into build filter: {filtered}"
        );
        assert!(!filtered.contains(r#"("ship")"#));

        assert!(full.lines().count() > filtered.lines().count());
    }

    #[test]
    fn mermaid_escapes_injection_like_node_names() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let secret = g.add_node(NodeKind::Secret, "X\"]; evil", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "a", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let mer = render_mermaid(&g, None);
        // The embedded quote must be entity-encoded, not a raw `"` that could
        // break out of the Mermaid `["..."]` label.
        assert!(mer.contains("&quot;"), "expected entity escape in: {mer}");
        let secret_line = mer
            .lines()
            .find(|l| l.contains('[') && l.contains("evil"))
            .expect("secret node line");
        assert!(
            !secret_line.contains(r#"["X"]"#) && !secret_line.contains(r#"X"];"#),
            "unexpected unescaped delimiters: {secret_line}"
        );
    }

    #[test]
    fn job_filter_produces_subset_of_full_map() {
        // Construct two jobs by hand: `build` (step accesses BUILD_SECRET) and
        // `deploy` (step accesses DEPLOY_SECRET). With no filter all 4 nodes
        // appear; filtering to `build` should drop the deploy step + its secret.
        let mut g = AuthorityGraph::new(source("ci.yml"));

        let build_secret = g.add_node(NodeKind::Secret, "BUILD_SECRET", TrustZone::FirstParty);
        let mut build_meta = std::collections::HashMap::new();
        build_meta.insert(META_JOB_NAME.to_string(), "build".to_string());
        let build_step =
            g.add_node_with_metadata(NodeKind::Step, "compile", TrustZone::FirstParty, build_meta);
        g.add_edge(build_step, build_secret, EdgeKind::HasAccessTo);

        let deploy_secret = g.add_node(NodeKind::Secret, "DEPLOY_SECRET", TrustZone::FirstParty);
        let mut deploy_meta = std::collections::HashMap::new();
        deploy_meta.insert(META_JOB_NAME.to_string(), "deploy".to_string());
        let deploy_step =
            g.add_node_with_metadata(NodeKind::Step, "ship", TrustZone::FirstParty, deploy_meta);
        g.add_edge(deploy_step, deploy_secret, EdgeKind::HasAccessTo);

        let full = render_dot(&g, None);
        let filtered = render_dot(&g, Some("build"));

        // Full output names every node; filtered output drops the deploy job.
        assert!(full.contains("BUILD_SECRET") && full.contains("DEPLOY_SECRET"));
        assert!(filtered.contains("BUILD_SECRET"));
        assert!(
            !filtered.contains("DEPLOY_SECRET"),
            "deploy-job nodes leaked into build filter: {filtered}"
        );
        assert!(!filtered.contains("\"ship\""));

        // Subset by line count: filtered must be strictly smaller than full.
        let full_lines = full.lines().count();
        let filtered_lines = filtered.lines().count();
        assert!(
            filtered_lines < full_lines,
            "filtered DOT ({filtered_lines} lines) not smaller than full ({full_lines})"
        );
    }

    #[test]
    fn job_names_lists_distinct_jobs_sorted() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut a_meta = std::collections::HashMap::new();
        a_meta.insert(META_JOB_NAME.to_string(), "deploy".to_string());
        g.add_node_with_metadata(NodeKind::Step, "s1", TrustZone::FirstParty, a_meta);
        let mut b_meta = std::collections::HashMap::new();
        b_meta.insert(META_JOB_NAME.to_string(), "build".to_string());
        g.add_node_with_metadata(NodeKind::Step, "s2", TrustZone::FirstParty, b_meta);
        let mut c_meta = std::collections::HashMap::new();
        c_meta.insert(META_JOB_NAME.to_string(), "build".to_string());
        g.add_node_with_metadata(NodeKind::Step, "s3", TrustZone::FirstParty, c_meta);

        let names = job_names(&g);
        assert_eq!(names, vec!["build".to_string(), "deploy".to_string()]);
    }
}
