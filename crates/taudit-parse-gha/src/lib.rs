use std::collections::HashMap;

use serde::Deserialize;
use taudit_core::error::TauditError;
use taudit_core::graph::*;
use taudit_core::ports::PipelineParser;

/// GitHub Actions workflow parser.
pub struct GhaParser;

impl PipelineParser for GhaParser {
    fn platform(&self) -> &str {
        "github-actions"
    }

    fn parse(&self, content: &str, source: &PipelineSource) -> Result<AuthorityGraph, TauditError> {
        let workflow: GhaWorkflow = serde_yaml::from_str(content)
            .map_err(|e| TauditError::Parse(format!("YAML parse error: {e}")))?;

        let mut graph = AuthorityGraph::new(source.clone());
        let mut secret_ids: HashMap<String, NodeId> = HashMap::new();

        // Workflow-level permissions -> GITHUB_TOKEN identity node
        let token_id = if let Some(ref perms) = workflow.permissions {
            let perm_string = perms.to_string();
            let mut meta = HashMap::new();
            meta.insert(META_PERMISSIONS.into(), perm_string);
            Some(graph.add_node_with_metadata(
                NodeKind::Identity,
                "GITHUB_TOKEN",
                TrustZone::FirstParty,
                meta,
            ))
        } else {
            None
        };

        for (job_name, job) in &workflow.jobs {
            // Job-level permissions override workflow-level
            let job_token_id = if let Some(ref perms) = job.permissions {
                let perm_string = perms.to_string();
                let mut meta = HashMap::new();
                meta.insert(META_PERMISSIONS.into(), perm_string);
                Some(graph.add_node_with_metadata(
                    NodeKind::Identity,
                    format!("GITHUB_TOKEN ({})", job_name),
                    TrustZone::FirstParty,
                    meta,
                ))
            } else {
                token_id
            };

            for (step_idx, step) in job.steps.iter().enumerate() {
                let default_name = format!("{}[{}]", job_name, step_idx);
                let step_name = step.name.as_deref().unwrap_or(&default_name);

                // Determine trust zone and create image node if `uses:` present
                let (trust_zone, image_node_id) = if let Some(ref uses) = step.uses {
                    let (zone, image_id) = classify_action(uses, &mut graph);
                    (zone, Some(image_id))
                } else {
                    // Inline `run:` step — first party
                    (TrustZone::FirstParty, None)
                };

                let step_id = graph.add_node(NodeKind::Step, step_name, trust_zone);

                // Link step to action image
                if let Some(img_id) = image_node_id {
                    graph.add_edge(step_id, img_id, EdgeKind::UsesImage);
                }

                // Link step to GITHUB_TOKEN if it exists
                if let Some(tok_id) = job_token_id {
                    graph.add_edge(step_id, tok_id, EdgeKind::HasAccessTo);
                }

                // Process secrets from `env:` block
                if let Some(ref env) = step.env {
                    for env_val in env.values() {
                        if is_secret_reference(env_val) {
                            let secret_name = extract_secret_name(env_val);
                            // Check if secret node already exists
                            let secret_id =
                                find_or_create_secret(&mut graph, &mut secret_ids, &secret_name);
                            graph.add_edge(step_id, secret_id, EdgeKind::HasAccessTo);
                        }
                    }
                }

                // Process secrets from `with:` block
                if let Some(ref with) = step.with {
                    for val in with.values() {
                        if is_secret_reference(val) {
                            let secret_name = extract_secret_name(val);
                            let secret_id =
                                find_or_create_secret(&mut graph, &mut secret_ids, &secret_name);
                            graph.add_edge(step_id, secret_id, EdgeKind::HasAccessTo);
                        }
                    }
                }
            }
        }

        Ok(graph)
    }
}

/// Classify a `uses:` reference into trust zone and create image node.
fn classify_action(uses: &str, graph: &mut AuthorityGraph) -> (TrustZone, NodeId) {
    let pinned = is_sha_pinned(uses);
    let is_local = uses.starts_with("./");

    let zone = if is_local {
        TrustZone::FirstParty
    } else if pinned {
        TrustZone::ThirdParty
    } else {
        TrustZone::Untrusted
    };

    let mut meta = HashMap::new();
    if pinned {
        if let Some(sha) = uses.split('@').next_back() {
            meta.insert(META_DIGEST.into(), sha.into());
        }
    }

    let id = graph.add_node_with_metadata(NodeKind::Image, uses, zone, meta);
    (zone, id)
}

fn is_secret_reference(val: &str) -> bool {
    val.contains("${{ secrets.")
}

fn extract_secret_name(val: &str) -> String {
    // Extract from patterns like "${{ secrets.MY_SECRET }}"
    if let Some(start) = val.find("secrets.") {
        let after = &val[start + 8..];
        let end = after
            .find(|c: char| !c.is_alphanumeric() && c != '_')
            .unwrap_or(after.len());
        after[..end].to_string()
    } else {
        val.to_string()
    }
}

fn find_or_create_secret(
    graph: &mut AuthorityGraph,
    cache: &mut HashMap<String, NodeId>,
    name: &str,
) -> NodeId {
    if let Some(&id) = cache.get(name) {
        return id;
    }
    let id = graph.add_node(NodeKind::Secret, name, TrustZone::FirstParty);
    cache.insert(name.to_string(), id);
    id
}

// ── Serde models for GHA YAML ──────────────────────────

/// Flexible permissions: can be a string ("write-all") or a map.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Permissions {
    String(String),
    Map(HashMap<String, String>),
}

impl std::fmt::Display for Permissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Permissions::String(s) => write!(f, "{s}"),
            Permissions::Map(m) => {
                let parts: Vec<String> = m.iter().map(|(k, v)| format!("{k}: {v}")).collect();
                write!(f, "{{ {} }}", parts.join(", "))
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct GhaWorkflow {
    #[serde(default)]
    pub permissions: Option<Permissions>,
    #[serde(default)]
    pub jobs: HashMap<String, GhaJob>,
}

#[derive(Debug, Deserialize)]
pub struct GhaJob {
    #[serde(default)]
    pub permissions: Option<Permissions>,
    #[serde(default)]
    pub steps: Vec<GhaStep>,
}

#[derive(Debug, Deserialize)]
pub struct GhaStep {
    pub name: Option<String>,
    pub uses: Option<String>,
    pub run: Option<String>,
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
    #[serde(rename = "with", default)]
    pub with: Option<HashMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> AuthorityGraph {
        let parser = GhaParser;
        let source = PipelineSource {
            file: "test.yml".into(),
            repo: None,
            git_ref: None,
        };
        parser.parse(yaml, &source).unwrap()
    }

    #[test]
    fn parses_simple_workflow() {
        let yaml = r#"
permissions: write-all
jobs:
  build:
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Build
        run: make build
"#;
        let graph = parse(yaml);
        assert!(graph.nodes.len() >= 3); // GITHUB_TOKEN + 2 steps + 1 image
    }

    #[test]
    fn detects_secret_in_env() {
        let yaml = r#"
jobs:
  deploy:
    steps:
      - name: Deploy
        run: ./deploy.sh
        env:
          AWS_KEY: "${{ secrets.AWS_ACCESS_KEY_ID }}"
"#;
        let graph = parse(yaml);
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "AWS_ACCESS_KEY_ID");
    }

    #[test]
    fn classifies_unpinned_action_as_untrusted() {
        let yaml = r#"
jobs:
  ci:
    steps:
      - uses: actions/checkout@v4
"#;
        let graph = parse(yaml);
        let images: Vec<_> = graph.nodes_of_kind(NodeKind::Image).collect();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].trust_zone, TrustZone::Untrusted);
    }

    #[test]
    fn classifies_sha_pinned_action_as_third_party() {
        let yaml = r#"
jobs:
  ci:
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
"#;
        let graph = parse(yaml);
        let images: Vec<_> = graph.nodes_of_kind(NodeKind::Image).collect();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].trust_zone, TrustZone::ThirdParty);
    }

    #[test]
    fn classifies_local_action_as_first_party() {
        let yaml = r#"
jobs:
  ci:
    steps:
      - uses: ./.github/actions/my-action
"#;
        let graph = parse(yaml);
        let images: Vec<_> = graph.nodes_of_kind(NodeKind::Image).collect();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].trust_zone, TrustZone::FirstParty);
    }

    #[test]
    fn detects_secret_in_with() {
        let yaml = r#"
jobs:
  deploy:
    steps:
      - name: Publish
        uses: some-org/publish@v1
        with:
          token: "${{ secrets.NPM_TOKEN }}"
"#;
        let graph = parse(yaml);
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "NPM_TOKEN");
    }

    #[test]
    fn workflow_level_permissions_create_identity() {
        let yaml = r#"
permissions: write-all
jobs:
  ci:
    steps:
      - run: echo hi
"#;
        let graph = parse(yaml);
        let identities: Vec<_> = graph.nodes_of_kind(NodeKind::Identity).collect();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].name, "GITHUB_TOKEN");
        assert_eq!(
            identities[0].metadata.get(META_PERMISSIONS).unwrap(),
            "write-all"
        );
    }
}
