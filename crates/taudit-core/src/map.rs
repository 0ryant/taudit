use crate::graph::{AuthorityGraph, EdgeKind, NodeId, NodeKind, META_IDENTITY_SCOPE};

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
            out.push_str(&format!("  {:^w$}", name, w = w));
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
                "{:<step_w$}  {:<zone_w$}",
                step_display,
                zone_display,
                step_w = step_width,
                zone_w = ZONE_W,
            ));
            for (col, w) in auth_widths[start..end].iter().enumerate() {
                let marker = if row.access[start + col] { "✓" } else { "·" };
                out.push_str(&format!("  {:^w$}", marker, w = w));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::*;

    fn source(file: &str) -> PipelineSource {
        PipelineSource {
            file: file.into(),
            repo: None,
            git_ref: None,
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
}
