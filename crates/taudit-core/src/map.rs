use crate::graph::{
    AuthorityCompleteness, AuthorityGraph, EdgeKind, Node, NodeId, NodeKind, TrustZone,
    META_IDENTITY_SCOPE, META_JOB_NAME, META_PERMISSIONS,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

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

/// How much context to embed in diagram node labels (DOT / Mermaid).
///
/// [`DiagramLabelDetail::Compact`] preserves historical default: node name only.
/// [`DiagramLabelDetail::Rich`] appends trust zone and selected `metadata` fields
/// already present on nodes (`identity_scope`, `permissions`) — no new graph logic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum DiagramLabelDetail {
    #[default]
    Compact,
    Rich,
}

/// Optional aggregation for DOT authority graphs (ADR 0002 Phase 4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum DotJobCollapse {
    #[default]
    Off,
    /// Merge every [`NodeKind::Step`] in the same `META_JOB_NAME` bucket into one node per job.
    On,
}

#[derive(Clone, Copy)]
enum RichLabelLayout {
    /// Newline-separated blocks (Graphviz `label` string with escaped `\n`).
    DotMultiline,
    /// Single-line segments joined for Mermaid (avoids raw `<br/>` vs HTML escapes).
    MermaidInline,
}

const RICH_META_FIELD_MAX: usize = 96;
const RICH_LABEL_MAX_DOT: usize = 512;
const RICH_LABEL_MAX_MERMAID: usize = 280;

fn diagram_node_label(
    node: &crate::graph::Node,
    detail: DiagramLabelDetail,
    layout: RichLabelLayout,
) -> String {
    match detail {
        DiagramLabelDetail::Compact => node.name.clone(),
        DiagramLabelDetail::Rich => {
            let zone = format!("{:?}", node.trust_zone);
            let sep = match layout {
                RichLabelLayout::DotMultiline => "\n",
                RichLabelLayout::MermaidInline => " | ",
            };
            let mut parts: Vec<String> = Vec::new();
            parts.push(node.name.clone());
            parts.push(format!("zone: {zone}"));
            if let Some(s) = node.metadata.get(META_IDENTITY_SCOPE) {
                parts.push(format!("scope: {}", trunc(s, RICH_META_FIELD_MAX)));
            }
            if let Some(p) = node.metadata.get(META_PERMISSIONS) {
                parts.push(format!("perm: {}", trunc(p, RICH_META_FIELD_MAX)));
            }
            let joined = parts.join(sep);
            let cap = match layout {
                RichLabelLayout::DotMultiline => RICH_LABEL_MAX_DOT,
                RichLabelLayout::MermaidInline => RICH_LABEL_MAX_MERMAID,
            };
            trunc(&joined, cap)
        }
    }
}

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
///
/// `label_detail` controls optional rich labels; [`DiagramLabelDetail::Compact`]
/// preserves the historical default (node name only).
///
/// When `job_collapse` is [`DotJobCollapse::On`], every step in the same
/// `META_JOB_NAME` bucket is drawn as one ellipse inside a `subgraph cluster_*`
/// (Graphviz cluster per job). Non-step nodes keep their canonical `n<id>` ids.
pub fn render_dot(
    graph: &AuthorityGraph,
    filter_job: Option<&str>,
    label_detail: DiagramLabelDetail,
    job_collapse: DotJobCollapse,
) -> String {
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

    match job_collapse {
        DotJobCollapse::Off => render_dot_flat(graph, included, label_detail),
        DotJobCollapse::On => render_dot_collapsed_by_job(graph, included, label_detail),
    }
}

fn render_dot_flat(
    graph: &AuthorityGraph,
    included: Option<HashSet<NodeId>>,
    label_detail: DiagramLabelDetail,
) -> String {
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
        let raw_label = diagram_node_label(node, label_detail, RichLabelLayout::DotMultiline);
        out.push_str(&format!(
            "    \"n{}\" [label=\"{}\" shape={} color={}];\n",
            node.id,
            dot_escape(&raw_label),
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

fn effective_included(
    graph: &AuthorityGraph,
    included: &Option<HashSet<NodeId>>,
) -> HashSet<NodeId> {
    match included {
        Some(s) => s.clone(),
        None => graph.nodes.iter().map(|n| n.id).collect(),
    }
}

fn job_bucket_key(step: &Node) -> String {
    step.metadata
        .get(META_JOB_NAME)
        .cloned()
        .unwrap_or_default()
}

fn job_subgraph_title(key: &str) -> String {
    if key.is_empty() {
        "(no job)".to_string()
    } else {
        key.to_string()
    }
}

fn collapsed_job_node_label(
    job_title: &str,
    step_count: usize,
    worst_zone: TrustZone,
    label_detail: DiagramLabelDetail,
) -> String {
    let steps_note = if step_count == 1 {
        "1 step".to_string()
    } else {
        format!("{step_count} steps")
    };
    match label_detail {
        DiagramLabelDetail::Compact => {
            format!("job: {job_title}\n({steps_note})")
        }
        DiagramLabelDetail::Rich => {
            let zone = format!("{:?}", worst_zone);
            format!("job: {job_title}\n({steps_note})\nzone: {zone}")
        }
    }
}

fn min_trust_zone<'a, I: Iterator<Item = &'a TrustZone>>(zones: I) -> TrustZone {
    zones.fold(TrustZone::FirstParty, |acc, z| {
        if z.is_lower_than(&acc) {
            *z
        } else {
            acc
        }
    })
}

fn render_dot_collapsed_by_job(
    graph: &AuthorityGraph,
    included: Option<HashSet<NodeId>>,
    label_detail: DiagramLabelDetail,
) -> String {
    let eff = effective_included(graph, &included);

    let mut job_keys: Vec<String> = graph
        .nodes
        .iter()
        .filter(|n| n.kind == NodeKind::Step && eff.contains(&n.id))
        .map(job_bucket_key)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    job_keys.sort();

    let job_index: HashMap<String, usize> = job_keys
        .iter()
        .enumerate()
        .map(|(i, k)| (k.clone(), i))
        .collect();

    let mut steps_per_job: HashMap<String, Vec<&Node>> = HashMap::new();
    for n in &graph.nodes {
        if n.kind != NodeKind::Step || !eff.contains(&n.id) {
            continue;
        }
        let k = job_bucket_key(n);
        steps_per_job.entry(k).or_default().push(n);
    }

    let node_by_id: HashMap<NodeId, &Node> = graph.nodes.iter().map(|n| (n.id, n)).collect();

    let mut collapsed_edges: BTreeMap<(String, String), BTreeSet<EdgeKind>> = BTreeMap::new();

    let step_dot_id = |step_id: NodeId| -> Option<String> {
        let n = node_by_id.get(&step_id)?;
        if n.kind != NodeKind::Step {
            return None;
        }
        let idx = *job_index.get(&job_bucket_key(n))?;
        Some(format!("jb{idx}"))
    };

    let non_step_dot_id = |id: NodeId| -> Option<String> {
        let n = node_by_id.get(&id)?;
        if n.kind == NodeKind::Step {
            return None;
        }
        if !eff.contains(&id) {
            return None;
        }
        Some(format!("n{id}"))
    };

    let endpoint_id = |id: NodeId| -> Option<String> {
        if let Some(s) = step_dot_id(id) {
            return Some(s);
        }
        non_step_dot_id(id)
    };

    for e in &graph.edges {
        if !eff.contains(&e.from) || !eff.contains(&e.to) {
            continue;
        }
        let Some(a) = endpoint_id(e.from) else {
            continue;
        };
        let Some(b) = endpoint_id(e.to) else { continue };
        if a == b {
            continue;
        }
        collapsed_edges
            .entry((a.clone(), b.clone()))
            .or_default()
            .insert(e.kind);
    }

    let mut out = String::new();
    out.push_str("digraph taudit {\n");
    out.push_str("    rankdir=LR;\n");
    out.push_str("    node [fontname=\"Helvetica\"];\n");

    for (idx, job_key) in job_keys.iter().enumerate() {
        let steps = steps_per_job
            .get(job_key)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        let worst = min_trust_zone(steps.iter().map(|n| &n.trust_zone));
        let title = job_subgraph_title(job_key);
        let raw_label = collapsed_job_node_label(&title, steps.len(), worst, label_detail);
        out.push_str(&format!("    subgraph cluster_job_{idx} {{\n"));
        out.push_str(&format!("        label=\"job: {}\";\n", dot_escape(&title)));
        out.push_str("        style=\"rounded\";\n");
        out.push_str(&format!(
            "        \"jb{idx}\" [label=\"{}\" shape=ellipse color={}];\n",
            dot_escape(&raw_label),
            dot_color(worst),
        ));
        out.push_str("    }\n");
    }

    for node in &graph.nodes {
        if node.kind == NodeKind::Step {
            continue;
        }
        if !eff.contains(&node.id) {
            continue;
        }
        let raw_label = diagram_node_label(node, label_detail, RichLabelLayout::DotMultiline);
        out.push_str(&format!(
            "    \"n{}\" [label=\"{}\" shape={} color={}];\n",
            node.id,
            dot_escape(&raw_label),
            dot_shape(node.kind),
            dot_color(node.trust_zone),
        ));
    }

    for ((from, to), kinds) in &collapsed_edges {
        let mut kinds_v: Vec<EdgeKind> = kinds.iter().copied().collect();
        kinds_v.sort_unstable();
        let label = kinds_v
            .iter()
            .map(|k| edge_label(*k))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "    \"{}\" -> \"{}\" [label=\"{}\"];\n",
            from,
            to,
            dot_escape(&label),
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
fn mermaid_node_line(node: &crate::graph::Node, display_esc: &str) -> String {
    let id = node.id;
    let esc = display_esc;
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
///
/// `label_detail` matches [`render_dot`] (compact vs rich node labels).
pub fn render_mermaid(
    graph: &AuthorityGraph,
    filter_job: Option<&str>,
    label_detail: DiagramLabelDetail,
) -> String {
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
        let raw = diagram_node_label(node, label_detail, RichLabelLayout::MermaidInline);
        let esc = mermaid_label_escape(&raw);
        out.push_str(&mermaid_node_line(node, &esc));
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

        let dot = render_dot(&g, None, DiagramLabelDetail::Compact, DotJobCollapse::Off);
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

        let mer = render_mermaid(&g, None, DiagramLabelDetail::Compact);
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

        let mer = render_mermaid(&g, None, DiagramLabelDetail::Compact);
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

        let full = render_mermaid(&g, None, DiagramLabelDetail::Compact);
        let filtered = render_mermaid(&g, Some("build"), DiagramLabelDetail::Compact);

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
    fn rich_dot_and_mermaid_include_zone_and_optional_metadata() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut id_meta = std::collections::HashMap::new();
        id_meta.insert(META_IDENTITY_SCOPE.to_string(), "constrained".to_string());
        id_meta.insert(
            META_PERMISSIONS.to_string(),
            "{ contents: read }".to_string(),
        );
        let id = g.add_node_with_metadata(
            NodeKind::Identity,
            "GITHUB_TOKEN",
            TrustZone::FirstParty,
            id_meta,
        );
        let step = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        g.add_edge(step, id, EdgeKind::HasAccessTo);

        let dot = render_dot(&g, None, DiagramLabelDetail::Rich, DotJobCollapse::Off);
        assert!(
            dot.contains("zone: FirstParty"),
            "rich dot should include zone: {dot}"
        );
        assert!(
            dot.contains("scope: constrained"),
            "rich dot should include identity scope: {dot}"
        );
        assert!(
            dot.contains("perm:"),
            "rich dot should include permissions summary: {dot}"
        );

        let mer = render_mermaid(&g, None, DiagramLabelDetail::Rich);
        assert!(mer.contains("zone: FirstParty"), "rich mermaid: {mer}");
        assert!(mer.contains("scope: constrained"), "rich mermaid: {mer}");
        assert!(mer.contains("perm:"), "rich mermaid: {mer}");

        let mer_c = render_mermaid(&g, None, DiagramLabelDetail::Compact);
        assert!(
            !mer_c.contains("zone: FirstParty"),
            "compact must not add zone line: {mer_c}"
        );
    }

    #[test]
    fn mermaid_escapes_injection_like_node_names() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let secret = g.add_node(NodeKind::Secret, "X\"]; evil", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "a", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let mer = render_mermaid(&g, None, DiagramLabelDetail::Compact);
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

        let full = render_dot(&g, None, DiagramLabelDetail::Compact, DotJobCollapse::Off);
        let filtered = render_dot(
            &g,
            Some("build"),
            DiagramLabelDetail::Compact,
            DotJobCollapse::Off,
        );

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
    fn dot_job_collapse_emits_cluster_per_job_and_merges_step_edges() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let shared = g.add_node(NodeKind::Secret, "SHARED", TrustZone::FirstParty);

        let mut build_meta = std::collections::HashMap::new();
        build_meta.insert(META_JOB_NAME.to_string(), "build".to_string());
        let s1 = g.add_node_with_metadata(
            NodeKind::Step,
            "compile",
            TrustZone::FirstParty,
            build_meta.clone(),
        );
        let s2 =
            g.add_node_with_metadata(NodeKind::Step, "lint", TrustZone::ThirdParty, build_meta);
        g.add_edge(s1, shared, EdgeKind::HasAccessTo);
        g.add_edge(s2, shared, EdgeKind::HasAccessTo);

        let mut deploy_meta = std::collections::HashMap::new();
        deploy_meta.insert(META_JOB_NAME.to_string(), "deploy".to_string());
        let s3 =
            g.add_node_with_metadata(NodeKind::Step, "ship", TrustZone::FirstParty, deploy_meta);
        let deploy_secret = g.add_node(NodeKind::Secret, "DEPLOY_KEY", TrustZone::FirstParty);
        g.add_edge(s3, deploy_secret, EdgeKind::HasAccessTo);

        let flat = render_dot(&g, None, DiagramLabelDetail::Compact, DotJobCollapse::Off);
        let collapsed = render_dot(&g, None, DiagramLabelDetail::Compact, DotJobCollapse::On);

        assert!(
            flat.contains("compile") && flat.contains("lint"),
            "flat dot should name each step: {flat}"
        );
        assert!(
            !collapsed.contains("compile") && !collapsed.contains("lint"),
            "collapsed dot should not repeat per-step names: {collapsed}"
        );
        assert!(
            collapsed.contains("subgraph cluster_job_0"),
            "expected cluster subgraph: {collapsed}"
        );
        assert!(
            collapsed.contains("subgraph cluster_job_1"),
            "expected second cluster: {collapsed}"
        );
        assert!(
            collapsed.contains("label=\"job: build\"")
                && collapsed.contains("label=\"job: deploy\""),
            "cluster titles: {collapsed}"
        );
        assert!(
            collapsed.contains(&format!("\"jb0\" -> \"n{}\"", shared)),
            "merged edge from build job bucket to secret: {collapsed}"
        );
        assert!(
            collapsed.lines().filter(|l| l.contains("ellipse")).count()
                < flat.lines().filter(|l| l.contains("ellipse")).count(),
            "collapsed should have fewer ellipse nodes than flat"
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
