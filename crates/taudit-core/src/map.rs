use crate::graph::{AuthorityGraph, EdgeKind, NodeKind};

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
    // Collect authority sources (secrets + identities) in stable order
    let authorities: Vec<_> = graph
        .authority_sources()
        .map(|n| (n.id, n.name.clone()))
        .collect();

    let authority_names: Vec<String> = authorities.iter().map(|(_, name)| name.clone()).collect();

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

    let auth_widths: Vec<usize> = map.authorities.iter().map(|a| a.len().max(3)).collect();

    let mut out = String::new();

    // Header
    out.push_str(&format!(
        "{:<step_w$}  {:<zone_w$}",
        "Step",
        "Zone",
        step_w = step_width,
        zone_w = zone_width
    ));
    for (i, auth) in map.authorities.iter().enumerate() {
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
