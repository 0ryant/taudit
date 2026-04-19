use std::collections::HashMap;

use serde::Deserialize;
use taudit_core::error::TauditError;
use taudit_core::graph::*;
use taudit_core::ports::PipelineParser;

/// Metadata key for marking inferred (not precisely mapped) secret references.
const META_INFERRED_VAL: &str = "true";

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

        let is_pull_request_target = workflow
            .triggers
            .as_ref()
            .map(trigger_has_pull_request_target)
            .unwrap_or(false);

        // Workflow-level permissions -> GITHUB_TOKEN identity node
        let token_id = if let Some(ref perms) = workflow.permissions {
            let perm_string = perms.to_string();
            let scope = IdentityScope::from_permissions(&perm_string);
            let mut meta = HashMap::new();
            meta.insert(META_PERMISSIONS.into(), perm_string.clone());
            meta.insert(META_IDENTITY_SCOPE.into(), format!("{scope:?}").to_lowercase());
            // OIDC: id-token: write → token is OIDC-capable (federated scope).
            // Check the formatted substring directly — Permissions::Map fmt produces
            // "id-token: write" so this won't false-positive on "contents: write".
            if perm_string.contains("id-token: write") || perm_string == "write-all" {
                meta.insert(META_OIDC.into(), "true".into());
            }
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
                let scope = IdentityScope::from_permissions(&perm_string);
                let mut meta = HashMap::new();
                meta.insert(META_PERMISSIONS.into(), perm_string.clone());
                meta.insert(META_IDENTITY_SCOPE.into(), format!("{scope:?}").to_lowercase());
                if perm_string.contains("id-token: write") {
                    meta.insert(META_OIDC.into(), "true".into());
                }
                Some(graph.add_node_with_metadata(
                    NodeKind::Identity,
                    format!("GITHUB_TOKEN ({})", job_name),
                    TrustZone::FirstParty,
                    meta,
                ))
            } else {
                token_id
            };

            // Reusable workflow: job.uses= means this job delegates to another workflow.
            // We cannot resolve it inline — mark the graph partial and skip steps.
            if let Some(ref uses) = job.uses {
                let trust_zone = if is_sha_pinned(uses) {
                    TrustZone::ThirdParty
                } else {
                    TrustZone::Untrusted
                };
                let rw_id = graph.add_node(NodeKind::Image, uses, trust_zone);
                // Synthetic step represents this job delegating to the called workflow
                let job_step_id =
                    graph.add_node(NodeKind::Step, job_name, TrustZone::FirstParty);
                graph.add_edge(job_step_id, rw_id, EdgeKind::DelegatesTo);
                if let Some(tok_id) = job_token_id {
                    graph.add_edge(job_step_id, tok_id, EdgeKind::HasAccessTo);
                }
                graph.mark_partial(format!(
                    "reusable workflow '{}' in job '{}' cannot be resolved inline — authority within the called workflow is unknown",
                    uses, job_name
                ));
                continue;
            }

            // Matrix strategy: authority shape may differ per matrix entry — mark Partial
            if job
                .strategy
                .as_ref()
                .and_then(|s| s.get("matrix"))
                .is_some()
            {
                graph.mark_partial(format!(
                    "job '{}' uses matrix strategy — authority shape may differ per matrix entry",
                    job_name
                ));
            }

            // Container: job-level container image — add as Image node and capture ID
            // so each step in this job can be linked to it via UsesImage.
            let container_image_id: Option<NodeId> = if let Some(ref container) = job.container {
                let image_str = container.image();
                let pinned = is_docker_digest_pinned(image_str);
                let trust_zone = if pinned {
                    TrustZone::ThirdParty
                } else {
                    TrustZone::Untrusted
                };
                let mut meta = HashMap::new();
                meta.insert(META_CONTAINER.into(), "true".into());
                if pinned {
                    if let Some(digest) = image_str.split("@sha256:").nth(1) {
                        meta.insert(META_DIGEST.into(), format!("sha256:{}", digest));
                    }
                }
                Some(graph.add_node_with_metadata(NodeKind::Image, image_str, trust_zone, meta))
            } else {
                None
            };

            for (step_idx, step) in job.steps.iter().enumerate() {
                let default_name = format!("{}[{}]", job_name, step_idx);
                let step_name = step.name.as_deref().unwrap_or(&default_name);

                // Determine trust zone and create image node if `uses:` present
                let (trust_zone, image_node_id) = if let Some(ref uses) = step.uses {
                    let (zone, image_id) = classify_action(uses, &mut graph);
                    (zone, Some(image_id))
                } else if is_pull_request_target {
                    // run: step in a pull_request_target workflow — may execute fork code
                    (TrustZone::Untrusted, None)
                } else {
                    // Inline `run:` step — first party
                    (TrustZone::FirstParty, None)
                };

                let step_id = graph.add_node(NodeKind::Step, step_name, trust_zone);

                // Link step to action image
                if let Some(img_id) = image_node_id {
                    graph.add_edge(step_id, img_id, EdgeKind::UsesImage);
                }

                // Link step to job container — steps run inside the container's execution
                // environment, so a floating container is a supply chain risk for every step.
                if let Some(img_id) = container_image_id {
                    graph.add_edge(step_id, img_id, EdgeKind::UsesImage);
                }

                // Link step to GITHUB_TOKEN if it exists
                if let Some(tok_id) = job_token_id {
                    graph.add_edge(step_id, tok_id, EdgeKind::HasAccessTo);
                }

                // Cloud identity inference: detect known OIDC cloud auth actions and
                // create an Identity node representing the assumed cloud identity.
                if let Some(ref uses) = step.uses {
                    if let Some(cloud_id) =
                        classify_cloud_auth(uses, step.with.as_ref(), &mut graph)
                    {
                        graph.add_edge(step_id, cloud_id, EdgeKind::HasAccessTo);
                    }
                }

                // Process secrets from workflow-level `env:` (inherited by all jobs/steps)
                if let Some(ref env) = workflow.env {
                    for env_val in env.values() {
                        if is_secret_reference(env_val) {
                            let secret_name = extract_secret_name(env_val);
                            let secret_id =
                                find_or_create_secret(&mut graph, &mut secret_ids, &secret_name);
                            graph.add_edge(step_id, secret_id, EdgeKind::HasAccessTo);
                        }
                    }
                }

                // Process secrets from job-level `env:` (inherited by all steps)
                if let Some(ref env) = job.env {
                    for env_val in env.values() {
                        if is_secret_reference(env_val) {
                            let secret_name = extract_secret_name(env_val);
                            let secret_id =
                                find_or_create_secret(&mut graph, &mut secret_ids, &secret_name);
                            graph.add_edge(step_id, secret_id, EdgeKind::HasAccessTo);
                        }
                    }
                }

                // Process secrets from step-level `env:` block
                if let Some(ref env) = step.env {
                    for env_val in env.values() {
                        if is_secret_reference(env_val) {
                            let secret_name = extract_secret_name(env_val);
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

                // Detect inferred secrets in `run:` script blocks
                if let Some(ref run) = step.run {
                    if run.contains("${{ secrets.") {
                        // Extract secret names from the shell script
                        let mut pos = 0;
                        while let Some(start) = run[pos..].find("secrets.") {
                            let abs_start = pos + start + 8;
                            let remaining = &run[abs_start..];
                            let end = remaining
                                .find(|c: char| !c.is_alphanumeric() && c != '_')
                                .unwrap_or(remaining.len());
                            let secret_name = &remaining[..end];
                            if !secret_name.is_empty() {
                                let secret_id = find_or_create_secret(
                                    &mut graph,
                                    &mut secret_ids,
                                    secret_name,
                                );
                                // Mark as inferred — not precisely mapped
                                if let Some(node) = graph.nodes.get_mut(secret_id) {
                                    node.metadata
                                        .insert(META_INFERRED.into(), META_INFERRED_VAL.into());
                                }
                                graph.add_edge(step_id, secret_id, EdgeKind::HasAccessTo);
                                graph.mark_partial(format!(
                                    "secret '{}' referenced in run: script — inferred, not precisely mapped",
                                    secret_name
                                ));
                            }
                            pos = abs_start + end;
                        }
                    }
                }
            }
        }

        Ok(graph)
    }
}

/// Returns true if the workflow's `on:` triggers include `pull_request_target`.
/// GHA `on:` is polymorphic: string, sequence, or mapping.
fn trigger_has_pull_request_target(triggers: &serde_yaml::Value) -> bool {
    const PRT: &str = "pull_request_target";
    match triggers {
        serde_yaml::Value::String(s) => s == PRT,
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .any(|v| v.as_str().map(|s| s == PRT).unwrap_or(false)),
        serde_yaml::Value::Mapping(map) => map
            .iter()
            .any(|(k, _)| k.as_str().map(|s| s == PRT).unwrap_or(false)),
        _ => false,
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

/// Detect known OIDC cloud authentication actions and create an Identity node
/// representing the cloud identity that will be assumed.
///
/// Only handles the OIDC/federated path — static credential inputs (e.g.
/// `aws-secret-access-key: ${{ secrets.X }}`) are already captured by the
/// regular `with:` secret scanning and don't need a separate Identity node.
///
/// Returns `Some(NodeId)` of the created Identity, or `None` if not recognized.
fn classify_cloud_auth(
    uses: &str,
    with: Option<&HashMap<String, String>>,
    graph: &mut AuthorityGraph,
) -> Option<NodeId> {
    // Strip `@version` — match any version of the action
    let action = uses.split('@').next().unwrap_or(uses);

    match action {
        "aws-actions/configure-aws-credentials" => {
            // OIDC path: role-to-assume present (no static access key needed)
            let w = with?;
            let role = w.get("role-to-assume")?;
            // ARN format: arn:aws:iam::123456789012:role/my-role
            // Split on '/' to get the role name; fall back to the full value.
            let short = role.split('/').next_back().unwrap_or(role.as_str());
            let mut meta = HashMap::new();
            meta.insert(META_OIDC.into(), "true".into());
            meta.insert(META_IDENTITY_SCOPE.into(), "broad".into());
            meta.insert(META_PERMISSIONS.into(), "AWS role assumption (OIDC)".into());
            Some(graph.add_node_with_metadata(
                NodeKind::Identity,
                format!("AWS/{short}"),
                TrustZone::FirstParty,
                meta,
            ))
        }
        "google-github-actions/auth" => {
            // OIDC path: workload_identity_provider present
            let w = with?;
            let provider = w.get("workload_identity_provider")?;
            let short = provider.split('/').next_back().unwrap_or(provider.as_str());
            let mut meta = HashMap::new();
            meta.insert(META_OIDC.into(), "true".into());
            meta.insert(META_IDENTITY_SCOPE.into(), "broad".into());
            meta.insert(META_PERMISSIONS.into(), "GCP workload identity federation".into());
            Some(graph.add_node_with_metadata(
                NodeKind::Identity,
                format!("GCP/{short}"),
                TrustZone::FirstParty,
                meta,
            ))
        }
        "azure/login" => {
            // OIDC path: client-id present without client-secret
            let w = with?;
            let client_id = w.get("client-id")?;
            // Only treat as OIDC if no static client-secret is provided
            if w.contains_key("client-secret") {
                return None; // static SP creds captured by with: secret scanning
            }
            let mut meta = HashMap::new();
            meta.insert(META_OIDC.into(), "true".into());
            meta.insert(META_IDENTITY_SCOPE.into(), "broad".into());
            meta.insert(META_PERMISSIONS.into(), "Azure federated credential (OIDC)".into());
            Some(graph.add_node_with_metadata(
                NodeKind::Identity,
                format!("Azure/{client_id}"),
                TrustZone::FirstParty,
                meta,
            ))
        }
        _ => None,
    }
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
    /// Workflow trigger(s). Polymorphic: string, sequence, or mapping.
    #[serde(rename = "on", default)]
    pub triggers: Option<serde_yaml::Value>,
    #[serde(default)]
    pub permissions: Option<Permissions>,
    /// Workflow-level env vars, inherited by all jobs and steps.
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
    #[serde(default)]
    pub jobs: HashMap<String, GhaJob>,
}

/// Job-level container config. Polymorphic: string image or map with `image:` key.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ContainerConfig {
    Image(String),
    Full { image: String },
}

impl ContainerConfig {
    pub fn image(&self) -> &str {
        match self {
            ContainerConfig::Image(s) => s,
            ContainerConfig::Full { image } => image,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct GhaJob {
    #[serde(default)]
    pub permissions: Option<Permissions>,
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
    #[serde(default)]
    pub steps: Vec<GhaStep>,
    /// Reusable workflow reference — `uses: owner/repo/.github/workflows/foo.yml@ref`
    #[serde(default)]
    pub uses: Option<String>,
    /// Job container image.
    #[serde(default)]
    pub container: Option<ContainerConfig>,
    /// Matrix/strategy configuration. When a matrix is present, the authority
    /// shape may differ per matrix entry — graph is marked Partial.
    #[serde(default)]
    pub strategy: Option<serde_yaml::Value>,
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
    fn inferred_secret_in_run_block_detected() {
        let yaml = r#"
jobs:
  deploy:
    steps:
      - name: Deploy
        run: |
          curl -H "Authorization: ${{ secrets.API_TOKEN }}" https://api.example.com
"#;
        let graph = parse(yaml);
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "API_TOKEN");
        assert_eq!(
            secrets[0].metadata.get(META_INFERRED),
            Some(&"true".to_string())
        );
        assert_eq!(graph.completeness, AuthorityCompleteness::Partial);
        assert!(!graph.completeness_gaps.is_empty());
    }

    #[test]
    fn job_level_env_inherited_by_steps() {
        let yaml = r#"
jobs:
  build:
    env:
      DB_PASSWORD: "${{ secrets.DB_PASSWORD }}"
    steps:
      - name: Step A
        run: echo "a"
      - name: Step B
        run: echo "b"
"#;
        let graph = parse(yaml);
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert_eq!(secrets.len(), 1, "one secret node (deduplicated)");

        // Both steps should have access to the secret
        let secret_id = secrets[0].id;
        let accessing_steps = graph
            .edges_to(secret_id)
            .filter(|e| e.kind == EdgeKind::HasAccessTo)
            .count();
        assert_eq!(accessing_steps, 2, "both steps inherit job-level env");
    }

    #[test]
    fn identity_scope_set_on_token() {
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
        assert_eq!(
            identities[0].metadata.get(META_IDENTITY_SCOPE),
            Some(&"broad".to_string())
        );
    }

    #[test]
    fn constrained_identity_scope() {
        let yaml = r#"
permissions:
  contents: read
jobs:
  ci:
    steps:
      - run: echo hi
"#;
        let graph = parse(yaml);
        let identities: Vec<_> = graph.nodes_of_kind(NodeKind::Identity).collect();
        assert_eq!(identities.len(), 1);
        assert_eq!(
            identities[0].metadata.get(META_IDENTITY_SCOPE),
            Some(&"constrained".to_string())
        );
    }

    #[test]
    fn pull_request_target_string_trigger_marks_run_steps_untrusted() {
        let yaml = r#"
on: pull_request_target
jobs:
  check:
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 2);

        // run: step should be Untrusted (might execute fork code)
        let run_step = steps.iter().find(|s| s.name.contains("check[1]")).unwrap();
        assert_eq!(
            run_step.trust_zone,
            TrustZone::Untrusted,
            "run: step in pull_request_target workflow should be Untrusted"
        );

        // uses: step keeps its own trust zone (SHA-pinned = ThirdParty)
        let checkout_step = steps.iter().find(|s| s.name.contains("check[0]")).unwrap();
        assert_eq!(checkout_step.trust_zone, TrustZone::ThirdParty);
    }

    #[test]
    fn pull_request_target_sequence_trigger_marks_run_steps_untrusted() {
        let yaml = r#"
on: [push, pull_request_target]
jobs:
  ci:
    steps:
      - run: echo hi
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps[0].trust_zone, TrustZone::Untrusted);
    }

    #[test]
    fn pull_request_target_mapping_trigger_marks_run_steps_untrusted() {
        let yaml = r#"
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  ci:
    steps:
      - run: echo hi
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps[0].trust_zone, TrustZone::Untrusted);
    }

    #[test]
    fn push_trigger_does_not_mark_run_steps_untrusted() {
        let yaml = r#"
on: push
jobs:
  ci:
    steps:
      - run: echo hi
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(
            steps[0].trust_zone,
            TrustZone::FirstParty,
            "push-triggered run: steps should remain FirstParty"
        );
    }

    #[test]
    fn workflow_level_env_inherited_by_all_steps() {
        let yaml = r#"
env:
  DB_URL: "${{ secrets.DATABASE_URL }}"
jobs:
  build:
    steps:
      - name: Step A
        run: echo "a"
  test:
    steps:
      - name: Step B
        run: echo "b"
"#;
        let graph = parse(yaml);
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert_eq!(secrets.len(), 1, "one secret node (deduplicated)");

        // Both steps in both jobs should inherit the workflow-level secret
        let secret_id = secrets[0].id;
        let accessing_steps = graph
            .edges_to(secret_id)
            .filter(|e| e.kind == EdgeKind::HasAccessTo)
            .count();
        assert_eq!(accessing_steps, 2, "both steps inherit workflow-level env");
    }

    #[test]
    fn matrix_strategy_marks_graph_partial() {
        let yaml = r#"
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
    steps:
      - run: echo hi
"#;
        let graph = parse(yaml);
        assert_eq!(graph.completeness, AuthorityCompleteness::Partial);
        assert!(
            graph
                .completeness_gaps
                .iter()
                .any(|g| g.contains("matrix")),
            "matrix strategy should be recorded as a completeness gap"
        );
    }

    #[test]
    fn job_without_matrix_does_not_mark_partial() {
        let yaml = r#"
jobs:
  build:
    steps:
      - run: cargo build
"#;
        let graph = parse(yaml);
        assert_eq!(graph.completeness, AuthorityCompleteness::Complete);
    }

    #[test]
    fn reusable_workflow_creates_image_and_marks_partial() {
        let yaml = r#"
jobs:
  call:
    uses: org/repo/.github/workflows/deploy.yml@main
"#;
        let graph = parse(yaml);
        let images: Vec<_> = graph.nodes_of_kind(NodeKind::Image).collect();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].name, "org/repo/.github/workflows/deploy.yml@main");
        assert_eq!(images[0].trust_zone, TrustZone::Untrusted); // not SHA-pinned

        // Step node representing the job delegation
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].name, "call");

        // DelegatesTo edge from step to reusable workflow image
        let delegates: Vec<_> = graph
            .edges_from(steps[0].id)
            .filter(|e| e.kind == EdgeKind::DelegatesTo)
            .collect();
        assert_eq!(delegates.len(), 1);

        assert_eq!(graph.completeness, AuthorityCompleteness::Partial);
    }

    #[test]
    fn reusable_workflow_sha_pinned_is_third_party() {
        let yaml = r#"
jobs:
  call:
    uses: org/repo/.github/workflows/deploy.yml@a5ac7e51b41094c92402da3b24376905380afc29
"#;
        let graph = parse(yaml);
        let images: Vec<_> = graph.nodes_of_kind(NodeKind::Image).collect();
        assert_eq!(images[0].trust_zone, TrustZone::ThirdParty);
    }

    #[test]
    fn container_unpinned_creates_image_node_untrusted() {
        let yaml = r#"
jobs:
  build:
    container: ubuntu:22.04
    steps:
      - run: echo hi
"#;
        let graph = parse(yaml);
        let images: Vec<_> = graph.nodes_of_kind(NodeKind::Image).collect();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].name, "ubuntu:22.04");
        assert_eq!(images[0].trust_zone, TrustZone::Untrusted);
        assert_eq!(
            images[0].metadata.get(META_CONTAINER),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn container_digest_pinned_creates_image_node_third_party() {
        let yaml = r#"
jobs:
  build:
    container:
      image: "ubuntu@sha256:a5ac7e51b41094c92402da3b24376905380afc29a5ac7e51b41094c92402da3b"
    steps:
      - run: echo hi
"#;
        let graph = parse(yaml);
        let images: Vec<_> = graph.nodes_of_kind(NodeKind::Image).collect();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].trust_zone, TrustZone::ThirdParty);
        assert_eq!(
            images[0].metadata.get(META_CONTAINER),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn oidc_permission_tags_identity_with_meta_oidc() {
        let yaml = r#"
permissions:
  id-token: write
  contents: read
jobs:
  ci:
    steps:
      - run: echo hi
"#;
        let graph = parse(yaml);
        let identities: Vec<_> = graph.nodes_of_kind(NodeKind::Identity).collect();
        assert_eq!(identities.len(), 1);
        assert_eq!(
            identities[0].metadata.get(META_OIDC),
            Some(&"true".to_string()),
            "id-token: write should mark identity as OIDC-capable"
        );
    }

    #[test]
    fn non_oidc_permission_does_not_tag_meta_oidc() {
        let yaml = r#"
permissions:
  contents: read
jobs:
  ci:
    steps:
      - run: echo hi
"#;
        let graph = parse(yaml);
        let identities: Vec<_> = graph.nodes_of_kind(NodeKind::Identity).collect();
        assert_eq!(identities.len(), 1);
        assert!(
            identities[0].metadata.get(META_OIDC).is_none(),
            "contents:read should not tag as OIDC"
        );
    }

    #[test]
    fn contents_write_without_id_token_does_not_tag_oidc() {
        // Regression: "contents: write" contains "write" but not "id-token: write".
        // Should NOT be tagged as OIDC-capable.
        let yaml = r#"
permissions:
  contents: write
jobs:
  ci:
    steps:
      - run: echo hi
"#;
        let graph = parse(yaml);
        let identities: Vec<_> = graph.nodes_of_kind(NodeKind::Identity).collect();
        assert_eq!(identities.len(), 1);
        assert!(
            identities[0].metadata.get(META_OIDC).is_none(),
            "contents:write without id-token must not be tagged OIDC"
        );
    }

    #[test]
    fn write_all_permission_tags_identity_as_oidc() {
        // `permissions: write-all` grants every permission including id-token: write.
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
        assert_eq!(
            identities[0].metadata.get(META_OIDC),
            Some(&"true".to_string()),
            "write-all grants all permissions including id-token: write"
        );
    }

    #[test]
    fn container_steps_linked_to_container_image() {
        let yaml = r#"
jobs:
  build:
    container: ubuntu:22.04
    steps:
      - name: Step A
        run: echo "a"
      - name: Step B
        run: echo "b"
"#;
        let graph = parse(yaml);
        let images: Vec<_> = graph.nodes_of_kind(NodeKind::Image).collect();
        assert_eq!(images.len(), 1);
        let container_id = images[0].id;

        // Both steps must have UsesImage edges to the container
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 2);
        for step in &steps {
            let links: Vec<_> = graph
                .edges_from(step.id)
                .filter(|e| e.kind == EdgeKind::UsesImage && e.to == container_id)
                .collect();
            assert_eq!(links.len(), 1, "step '{}' must link to container", step.name);
        }
    }

    #[test]
    fn container_authority_propagates_to_floating_image() {
        // Integration: authority from a step running in a floating container should
        // propagate to the container Image node (Untrusted), generating a finding.
        let yaml = r#"
permissions: write-all
jobs:
  build:
    container: ubuntu:22.04
    steps:
      - run: echo hi
"#;
        use taudit_core::rules;
        use taudit_core::propagation::DEFAULT_MAX_HOPS;
        let graph = parse(yaml);
        let findings = rules::run_all_rules(&graph, DEFAULT_MAX_HOPS);
        // Should detect: GITHUB_TOKEN (broad) propagates to ubuntu:22.04 (Untrusted) via step
        assert!(
            findings.iter().any(|f| f.category == taudit_core::finding::FindingCategory::AuthorityPropagation),
            "authority should propagate from step to floating container"
        );
    }

    #[test]
    fn aws_oidc_creates_identity_node() {
        let yaml = r#"
jobs:
  deploy:
    steps:
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/my-deploy-role
          aws-region: us-east-1
"#;
        let graph = parse(yaml);
        let identities: Vec<_> = graph.nodes_of_kind(NodeKind::Identity).collect();
        assert_eq!(identities.len(), 1);
        // ARN arn:aws:iam::123456789012:role/my-deploy-role → last '/' segment
        assert_eq!(identities[0].name, "AWS/my-deploy-role");
        assert_eq!(
            identities[0].metadata.get(META_OIDC),
            Some(&"true".to_string())
        );
        assert_eq!(
            identities[0].metadata.get(META_IDENTITY_SCOPE),
            Some(&"broad".to_string())
        );
    }

    #[test]
    fn gcp_oidc_creates_identity_node() {
        let yaml = r#"
jobs:
  deploy:
    steps:
      - name: Authenticate to GCP
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: projects/123/locations/global/workloadIdentityPools/my-pool/providers/my-provider
          service_account: my-sa@my-project.iam.gserviceaccount.com
"#;
        let graph = parse(yaml);
        let identities: Vec<_> = graph.nodes_of_kind(NodeKind::Identity).collect();
        assert_eq!(identities.len(), 1);
        assert!(identities[0].name.starts_with("GCP/"));
        assert_eq!(
            identities[0].metadata.get(META_OIDC),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn azure_oidc_creates_identity_node() {
        let yaml = r#"
jobs:
  deploy:
    steps:
      - name: Azure login
        uses: azure/login@v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
"#;
        let graph = parse(yaml);
        let identities: Vec<_> = graph.nodes_of_kind(NodeKind::Identity).collect();
        assert_eq!(identities.len(), 1);
        assert!(identities[0].name.starts_with("Azure/"));
        assert_eq!(
            identities[0].metadata.get(META_OIDC),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn azure_static_sp_does_not_create_identity_node() {
        // When client-secret is present, it's a static service principal — not OIDC.
        // The secret scanning in with: handles this; classify_cloud_auth returns None.
        let yaml = r#"
jobs:
  deploy:
    steps:
      - name: Azure login
        uses: azure/login@v2
        with:
          client-id: my-client-id
          client-secret: ${{ secrets.AZURE_CLIENT_SECRET }}
          tenant-id: my-tenant
"#;
        let graph = parse(yaml);
        // Identity node should NOT be created by cloud auth inference
        let identities: Vec<_> = graph.nodes_of_kind(NodeKind::Identity).collect();
        assert!(
            identities.is_empty(),
            "static SP should not create an OIDC Identity node"
        );
        // But the secret SHOULD be captured by existing with: scanning
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "AZURE_CLIENT_SECRET");
    }

    #[test]
    fn aws_static_creds_do_not_create_identity_node() {
        // Static access key path — no role-to-assume, so classify_cloud_auth returns None.
        // The access key secret is captured by with: scanning.
        let yaml = r#"
jobs:
  deploy:
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
"#;
        let graph = parse(yaml);
        let identities: Vec<_> = graph.nodes_of_kind(NodeKind::Identity).collect();
        assert!(identities.is_empty(), "static AWS creds must not create Identity node");
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert_eq!(secrets.len(), 2, "both static secrets captured");
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
