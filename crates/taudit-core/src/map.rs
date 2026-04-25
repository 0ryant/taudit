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

/// Render the authority map as a formatted table string.
pub fn render_map(map: &AuthorityMap) -> String {
    if map.rows.is_empty() && map.authorities.is_empty() {
        return "No steps or authority sources found.\n".to_string();
    }

    // Calculate column widths
    let step_width = map
        .rows
        .iter()
        .map(|r| r.step_name.len())
        .max()
        .unwrap_or(4)
        .max(4);

    let zone_width = map
        .rows
        .iter()
        .map(|r| r.trust_zone.len())
        .max()
        .unwrap_or(4)
        .max(4);

    // Clamp authority column names to MAX_COL chars with ellipsis to prevent
    // wide tables from wrapping. `chars().count()` handles Unicode correctly.
    const MAX_COL: usize = 20;

    let display_names: Vec<String> = map
        .authorities
        .iter()
        .map(|a| {
            let char_count = a.chars().count();
            if char_count > MAX_COL {
                let mut s: String = a.chars().take(MAX_COL - 1).collect();
                s.push('…');
                s
            } else {
                a.clone()
            }
        })
        .collect();
    let any_truncated = display_names
        .iter()
        .zip(map.authorities.iter())
        .any(|(d, o)| d != o);

    let auth_widths: Vec<usize> = display_names
        .iter()
        .map(|a| a.chars().count().max(3))
        .collect();

    let mut out = String::new();

    // Header
    out.push_str(&format!(
        "{:<step_w$}  {:<zone_w$}",
        "Step",
        "Zone",
        step_w = step_width,
        zone_w = zone_width
    ));
    for (i, auth) in display_names.iter().enumerate() {
        out.push_str(&format!("  {:^w$}", auth, w = auth_widths[i]));
    }
    out.push('\n');

    // Separator
    out.push_str(&"-".repeat(step_width));
    out.push_str("  ");
    out.push_str(&"-".repeat(zone_width));
    for w in &auth_widths {
        out.push_str("  ");
        out.push_str(&"-".repeat(*w));
    }
    out.push('\n');

    // Rows
    for row in &map.rows {
        out.push_str(&format!(
            "{:<step_w$}  {:<zone_w$}",
            row.step_name,
            row.trust_zone,
            step_w = step_width,
            zone_w = zone_width
        ));
        for (i, &has) in row.access.iter().enumerate() {
            let marker = if has { "X" } else { "." };
            out.push_str(&format!("  {:^w$}", marker, w = auth_widths[i]));
        }
        out.push('\n');
    }

    if any_truncated {
        out.push_str(&format!(
            "\nNote: column names truncated to {} chars.\n",
            MAX_COL
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
        let table = render_map(&map);
        assert!(table.contains("build"));
        assert!(table.contains("KEY"));
        assert!(table.contains("X"));
    }
}
