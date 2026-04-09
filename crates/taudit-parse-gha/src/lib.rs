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
            // OIDC: id-token: write → token is OIDC-capable (federated scope)
            if perm_string.contains("id-token") && perm_string.contains("write") {
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
                if perm_string.contains("id-token") && perm_string.contains("write") {
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

            // Container: job-level container image — add as Image node
            if let Some(ref container) = job.container {
                let image_str = container.image();
                let trust_zone = if is_docker_digest_pinned(image_str) {
                    TrustZone::ThirdParty
                } else {
                    TrustZone::Untrusted
                };
                let mut meta = HashMap::new();
                meta.insert(META_CONTAINER.into(), "true".into());
                if is_docker_digest_pinned(image_str) {
                    if let Some(digest) = image_str.split("@sha256:").nth(1) {
                        meta.insert(META_DIGEST.into(), format!("sha256:{}", digest));
                    }
                }
                graph.add_node_with_metadata(NodeKind::Image, image_str, trust_zone, meta);
            }

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

                // Link step to GITHUB_TOKEN if it exists
                if let Some(tok_id) = job_token_id {
                    graph.add_edge(step_id, tok_id, EdgeKind::HasAccessTo);
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
