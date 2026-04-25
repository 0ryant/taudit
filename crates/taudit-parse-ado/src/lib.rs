use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use taudit_core::error::TauditError;
use taudit_core::graph::*;
use taudit_core::ports::PipelineParser;

/// Azure DevOps YAML pipeline parser.
pub struct AdoParser;

impl PipelineParser for AdoParser {
    fn platform(&self) -> &str {
        "azure-devops"
    }

    fn parse(&self, content: &str, source: &PipelineSource) -> Result<AuthorityGraph, TauditError> {
        let mut de = serde_yaml::Deserializer::from_str(content);
        let doc = de
            .next()
            .ok_or_else(|| TauditError::Parse("empty YAML document".into()))?;
        let pipeline: AdoPipeline = AdoPipeline::deserialize(doc)
            .map_err(|e| TauditError::Parse(format!("YAML parse error: {e}")))?;
        let extra_docs = de.next().is_some();

        let mut graph = AuthorityGraph::new(source.clone());
        if extra_docs {
            graph.mark_partial(
                "file contains multiple YAML documents (--- separator) — only the first was analyzed".to_string(),
            );
        }

        // Detect PR trigger — sets graph-level META_TRIGGER for trigger_context_mismatch.
        let has_pr_trigger = pipeline.pr.is_some();
        if has_pr_trigger {
            graph.metadata.insert(META_TRIGGER.into(), "pr".into());
        }

        let mut secret_ids: HashMap<String, NodeId> = HashMap::new();

        // System.AccessToken is always present — equivalent to GITHUB_TOKEN.
        // Tagged implicit: ADO injects this token into every task by platform design;
        // its exposure to marketplace tasks is structural, not a fixable misconfiguration.
        let mut meta = HashMap::new();
        meta.insert(META_IDENTITY_SCOPE.into(), "broad".into());
        meta.insert(META_IMPLICIT.into(), "true".into());
        let token_id = graph.add_node_with_metadata(
            NodeKind::Identity,
            "System.AccessToken",
            TrustZone::FirstParty,
            meta,
        );

        // Pipeline-level pool: adds Image node, tagged self-hosted when applicable.
        process_pool(&pipeline.pool, &mut graph);

        // Pipeline-level variable groups and named secrets.
        // plain_vars tracks non-secret named variables so $(VAR) refs in scripts
        // don't generate false-positive Secret nodes for plain config values.
        let mut plain_vars: HashSet<String> = HashSet::new();
        let pipeline_secret_ids = process_variables(
            &pipeline.variables,
            &mut graph,
            &mut secret_ids,
            "pipeline",
            &mut plain_vars,
        );

        // Determine pipeline structure: stages → jobs → steps, or jobs → steps, or steps only
        if let Some(ref stages) = pipeline.stages {
            for stage in stages {
                // Stage-level template reference — delegate and mark Partial
                if let Some(ref tpl) = stage.template {
                    let stage_name = stage.stage.as_deref().unwrap_or("stage");
                    add_template_delegation(stage_name, tpl, token_id, &mut graph);
                    continue;
                }

                let stage_name = stage.stage.as_deref().unwrap_or("stage").to_string();
                let stage_secret_ids = process_variables(
                    &stage.variables,
                    &mut graph,
                    &mut secret_ids,
                    &stage_name,
                    &mut plain_vars,
                );

                for job in &stage.jobs {
                    let job_name = job.effective_name();
                    let job_secret_ids = process_variables(
                        &job.variables,
                        &mut graph,
                        &mut secret_ids,
                        &job_name,
                        &mut plain_vars,
                    );

                    process_pool(&job.pool, &mut graph);

                    let all_secrets: Vec<NodeId> = pipeline_secret_ids
                        .iter()
                        .chain(&stage_secret_ids)
                        .chain(&job_secret_ids)
                        .copied()
                        .collect();

                    process_steps(
                        job.steps.as_deref().unwrap_or(&[]),
                        &job_name,
                        token_id,
                        &all_secrets,
                        &plain_vars,
                        &mut graph,
                        &mut secret_ids,
                    );

                    if let Some(ref tpl) = job.template {
                        add_template_delegation(&job_name, tpl, token_id, &mut graph);
                    }
                }
            }
        } else if let Some(ref jobs) = pipeline.jobs {
            for job in jobs {
                let job_name = job.effective_name();
                let job_secret_ids = process_variables(
                    &job.variables,
                    &mut graph,
                    &mut secret_ids,
                    &job_name,
                    &mut plain_vars,
                );

                process_pool(&job.pool, &mut graph);

                let all_secrets: Vec<NodeId> = pipeline_secret_ids
                    .iter()
                    .chain(&job_secret_ids)
                    .copied()
                    .collect();

                process_steps(
                    job.steps.as_deref().unwrap_or(&[]),
                    &job_name,
                    token_id,
                    &all_secrets,
                    &plain_vars,
                    &mut graph,
                    &mut secret_ids,
                );

                if let Some(ref tpl) = job.template {
                    add_template_delegation(&job_name, tpl, token_id, &mut graph);
                }
            }
        } else if let Some(ref steps) = pipeline.steps {
            process_steps(
                steps,
                "pipeline",
                token_id,
                &pipeline_secret_ids,
                &plain_vars,
                &mut graph,
                &mut secret_ids,
            );
        }

        Ok(graph)
    }
}

/// Process an ADO `pool:` block. ADO pools come in two shapes:
///   - `pool: my-self-hosted-pool` (string shorthand — always self-hosted)
///   - `pool: { name: my-pool }` (named pool — self-hosted)
///   - `pool: { vmImage: ubuntu-latest }` (Microsoft-hosted)
///   - `pool: { name: my-pool, vmImage: ubuntu-latest }` (hosted; vmImage wins)
///
/// Creates an Image node representing the agent environment. Self-hosted pools
/// are tagged with META_SELF_HOSTED so downstream rules can flag them.
fn process_pool(pool: &Option<serde_yaml::Value>, graph: &mut AuthorityGraph) {
    let Some(pool_val) = pool else {
        return;
    };

    let (image_name, is_self_hosted) = match pool_val {
        serde_yaml::Value::String(s) => (s.clone(), true),
        serde_yaml::Value::Mapping(map) => {
            let name = map.get("name").and_then(|v| v.as_str());
            let vm_image = map.get("vmImage").and_then(|v| v.as_str());
            match (name, vm_image) {
                (_, Some(vm)) => (vm.to_string(), false),
                (Some(n), None) => (n.to_string(), true),
                (None, None) => return,
            }
        }
        _ => return,
    };

    let mut meta = HashMap::new();
    if is_self_hosted {
        meta.insert(META_SELF_HOSTED.into(), "true".into());
    }
    graph.add_node_with_metadata(NodeKind::Image, image_name, TrustZone::FirstParty, meta);
}

/// Process a variable list, creating Secret nodes and returning their IDs.
/// Returns IDs for secrets only (not variable groups, which are opaque).
/// Populates `plain_vars` with the names of non-secret named variables so
/// downstream `$(VAR)` scanning can skip them.
fn process_variables(
    variables: &Option<AdoVariables>,
    graph: &mut AuthorityGraph,
    cache: &mut HashMap<String, NodeId>,
    scope: &str,
    plain_vars: &mut HashSet<String>,
) -> Vec<NodeId> {
    let mut ids = Vec::new();

    let vars = match variables.as_ref() {
        Some(v) => v,
        None => return ids,
    };

    for var in &vars.0 {
        match var {
            AdoVariable::Group { group } => {
                // Skip template-expression group names like `${{ parameters.env }}`.
                // We can't resolve them statically — mark Partial but don't create
                // a misleading Secret node with the expression as its name.
                if group.contains("${{") {
                    graph.mark_partial(format!(
                        "variable group in {scope} uses template expression — group name unresolvable at parse time"
                    ));
                    continue;
                }
                let mut meta = HashMap::new();
                meta.insert(META_VARIABLE_GROUP.into(), "true".into());
                let id = graph.add_node_with_metadata(
                    NodeKind::Secret,
                    group.as_str(),
                    TrustZone::FirstParty,
                    meta,
                );
                cache.insert(group.clone(), id);
                ids.push(id);
                graph.mark_partial(format!(
                    "variable group '{group}' in {scope} — contents unresolvable without ADO API access"
                ));
            }
            AdoVariable::Named {
                name, is_secret, ..
            } => {
                if *is_secret {
                    let id = find_or_create_secret(graph, cache, name);
                    ids.push(id);
                } else {
                    plain_vars.insert(name.clone());
                }
            }
        }
    }

    ids
}

/// Process a list of ADO steps, adding nodes and edges to the graph.
fn process_steps(
    steps: &[AdoStep],
    job_name: &str,
    token_id: NodeId,
    inherited_secrets: &[NodeId],
    plain_vars: &HashSet<String>,
    graph: &mut AuthorityGraph,
    cache: &mut HashMap<String, NodeId>,
) {
    for (idx, step) in steps.iter().enumerate() {
        // Template step — delegation, mark partial
        if let Some(ref tpl) = step.template {
            let step_name = step
                .display_name
                .as_deref()
                .or(step.name.as_deref())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("{job_name}[{idx}]"));
            add_template_delegation(&step_name, tpl, token_id, graph);
            continue;
        }

        // Determine step kind and trust zone
        let (step_name, trust_zone, inline_script) = classify_step(step, job_name, idx);

        let step_id = graph.add_node(NodeKind::Step, &step_name, trust_zone);

        // Every step has access to System.AccessToken
        graph.add_edge(step_id, token_id, EdgeKind::HasAccessTo);

        // checkout step with persistCredentials: true writes the token to .git/config on disk,
        // making it accessible to all subsequent steps and filesystem-level attackers.
        if step.checkout.is_some() && step.persist_credentials == Some(true) {
            graph.add_edge(step_id, token_id, EdgeKind::PersistsTo);
        }

        // `checkout: self` pulls the repo being built. In a PR trigger context this
        // is the untrusted fork head — tag the step so downstream rules can gate on
        // trigger context. Default ADO checkout (`checkout: self`) is the common case.
        if let Some(ref ck) = step.checkout {
            if ck == "self" {
                if let Some(node) = graph.nodes.get_mut(step_id) {
                    node.metadata
                        .insert(META_CHECKOUT_SELF.into(), "true".into());
                }
            }
        }

        // Inherited pipeline/stage/job secrets
        for &secret_id in inherited_secrets {
            graph.add_edge(step_id, secret_id, EdgeKind::HasAccessTo);
        }

        // Service connection detection from task inputs (case-insensitive key match)
        if let Some(ref inputs) = step.inputs {
            let service_conn_keys = [
                "azuresubscription",
                "connectedservicename",
                "connectedservicenamearm",
                "kubernetesserviceconnection",
            ];
            for (raw_key, val) in inputs {
                let lower = raw_key.to_lowercase();
                if !service_conn_keys.contains(&lower.as_str()) {
                    continue;
                }
                let conn_name = yaml_value_as_str(val).unwrap_or(raw_key.as_str());
                if !conn_name.starts_with("$(") {
                    let mut meta = HashMap::new();
                    meta.insert(META_SERVICE_CONNECTION.into(), "true".into());
                    meta.insert(META_IDENTITY_SCOPE.into(), "broad".into());
                    // ADO service connections are the platform's federated-identity equivalent
                    // (modern Azure service connections use workload identity federation /
                    // OIDC). Tag them so uplift_without_attestation treats ADO pipelines with
                    // the same OIDC-parity logic applied to GHA.
                    meta.insert(META_OIDC.into(), "true".into());
                    let conn_id = graph.add_node_with_metadata(
                        NodeKind::Identity,
                        conn_name,
                        TrustZone::FirstParty,
                        meta,
                    );
                    graph.add_edge(step_id, conn_id, EdgeKind::HasAccessTo);
                }
            }

            // Detect $(varName) references in task input values
            for val in inputs.values() {
                if let Some(s) = yaml_value_as_str(val) {
                    extract_dollar_paren_secrets(s, step_id, plain_vars, graph, cache);
                }
            }
        }

        // Detect $(varName) in step env values
        if let Some(ref env) = step.env {
            for val in env.values() {
                extract_dollar_paren_secrets(val, step_id, plain_vars, graph, cache);
            }
        }

        // Detect $(varName) in inline script text
        if let Some(ref script) = inline_script {
            extract_dollar_paren_secrets(script, step_id, plain_vars, graph, cache);
        }

        // Detect ##vso[task.setvariable] — environment gate mutation in ADO pipelines
        if let Some(ref script) = inline_script {
            let lower = script.to_lowercase();
            if lower.contains("##vso[task.setvariable") {
                if let Some(node) = graph.nodes.get_mut(step_id) {
                    node.metadata
                        .insert(META_WRITES_ENV_GATE.into(), "true".into());
                }
            }
        }
    }
}

/// Classify an ADO step, returning (name, trust_zone, inline_script_text).
fn classify_step(
    step: &AdoStep,
    job_name: &str,
    idx: usize,
) -> (String, TrustZone, Option<String>) {
    let default_name = || format!("{job_name}[{idx}]");

    let name = step
        .display_name
        .as_deref()
        .or(step.name.as_deref())
        .map(|s| s.to_string())
        .unwrap_or_else(default_name);

    if step.task.is_some() {
        (name, TrustZone::Untrusted, None)
    } else if let Some(ref s) = step.script {
        (name, TrustZone::FirstParty, Some(s.clone()))
    } else if let Some(ref s) = step.bash {
        (name, TrustZone::FirstParty, Some(s.clone()))
    } else if let Some(ref s) = step.powershell {
        (name, TrustZone::FirstParty, Some(s.clone()))
    } else if let Some(ref s) = step.pwsh {
        (name, TrustZone::FirstParty, Some(s.clone()))
    } else {
        (name, TrustZone::FirstParty, None)
    }
}

/// Add a DelegatesTo edge from a synthetic step node to a template image node.
///
/// Trust zone heuristic: templates referenced with `@repository` (e.g. `steps/deploy.yml@templates`)
/// pull code from an external repository and are Untrusted. Plain relative paths like
/// `steps/deploy.yml` resolve within the same repo and are FirstParty — mirroring how GHA
/// treats `./local-action`.
fn add_template_delegation(
    step_name: &str,
    template_path: &str,
    token_id: NodeId,
    graph: &mut AuthorityGraph,
) {
    let tpl_trust_zone = if template_path.contains('@') {
        TrustZone::Untrusted
    } else {
        TrustZone::FirstParty
    };
    let step_id = graph.add_node(NodeKind::Step, step_name, TrustZone::FirstParty);
    let tpl_id = graph.add_node(NodeKind::Image, template_path, tpl_trust_zone);
    graph.add_edge(step_id, tpl_id, EdgeKind::DelegatesTo);
    graph.add_edge(step_id, token_id, EdgeKind::HasAccessTo);
    graph.mark_partial(format!(
        "template '{template_path}' cannot be resolved inline — authority within the template is unknown"
    ));
}

/// Extract `$(varName)` references from a string, creating Secret nodes for
/// non-predefined and non-plain ADO variables.
/// Only content that is a valid ADO variable identifier (`[A-Za-z][A-Za-z0-9_]*`)
/// is treated as a variable reference. This rejects PowerShell sub-expressions
/// (`$($var)`), ADO template expressions (`${{ ... }}`), shell commands (`$(date)`),
/// and anything with spaces or special characters.
fn extract_dollar_paren_secrets(
    text: &str,
    step_id: NodeId,
    plain_vars: &HashSet<String>,
    graph: &mut AuthorityGraph,
    cache: &mut HashMap<String, NodeId>,
) {
    let mut pos = 0;
    let bytes = text.as_bytes();
    while pos < bytes.len() {
        if pos + 2 < bytes.len() && bytes[pos] == b'$' && bytes[pos + 1] == b'(' {
            let start = pos + 2;
            if let Some(end_offset) = text[start..].find(')') {
                let var_name = &text[start..start + end_offset];
                if is_valid_ado_identifier(var_name)
                    && !is_predefined_ado_var(var_name)
                    && !plain_vars.contains(var_name)
                {
                    let id = find_or_create_secret(graph, cache, var_name);
                    // Mark secrets embedded in -var flag arguments: their values appear in
                    // pipeline logs (command string is logged before masking, and Terraform
                    // itself logs -var values in plan output and debug traces).
                    if is_in_terraform_var_flag(text, pos) {
                        if let Some(node) = graph.nodes.get_mut(id) {
                            node.metadata
                                .insert(META_CLI_FLAG_EXPOSED.into(), "true".into());
                        }
                    }
                    graph.add_edge(step_id, id, EdgeKind::HasAccessTo);
                }
                pos = start + end_offset + 1;
                continue;
            }
        }
        pos += 1;
    }
}

/// Returns true if the `$(VAR)` at `var_pos` is inside a Terraform `-var` flag argument.
/// Pattern: the line before `$(VAR)` contains `-var` and `=`, indicating `-var "key=$(VAR)"`.
fn is_in_terraform_var_flag(text: &str, var_pos: usize) -> bool {
    let line_start = text[..var_pos].rfind('\n').map(|p| p + 1).unwrap_or(0);
    let line_before = &text[line_start..var_pos];
    // Must contain -var (the flag) and = (the key=value assignment)
    line_before.contains("-var") && line_before.contains('=')
}

/// Returns true if `name` is a valid ADO variable identifier.
/// ADO variable names start with a letter and contain only letters, digits,
/// and underscores. Anything else — PowerShell vars (`$name`), template
/// expressions (`{{ ... }}`), shell commands (`date`), or complex expressions
/// (`name -join ','`) — is rejected.
fn is_valid_ado_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() => {
            chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        }
        _ => false,
    }
}

/// Returns true if a variable name is a well-known ADO predefined variable.
/// These are system-provided and never represent secrets.
fn is_predefined_ado_var(name: &str) -> bool {
    let prefixes = [
        "Build.",
        "Agent.",
        "System.",
        "Pipeline.",
        "Release.",
        "Environment.",
        "Strategy.",
        "Deployment.",
        "Resources.",
        "TF_BUILD",
    ];
    prefixes.iter().any(|p| name.starts_with(p)) || name == "TF_BUILD"
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

fn yaml_value_as_str(val: &serde_yaml::Value) -> Option<&str> {
    val.as_str()
}

// ── Serde models for ADO YAML ─────────────────────────────

/// Top-level ADO pipeline definition.
/// ADO pipelines come in three shapes:
///   (a) stages → jobs → steps
///   (b) jobs → steps (no stages key)
///   (c) steps only (no stages or jobs key)
#[derive(Debug, Deserialize)]
pub struct AdoPipeline {
    #[serde(default)]
    pub trigger: Option<serde_yaml::Value>,
    #[serde(default)]
    pub pr: Option<serde_yaml::Value>,
    #[serde(default)]
    pub variables: Option<AdoVariables>,
    #[serde(default)]
    pub stages: Option<Vec<AdoStage>>,
    #[serde(default)]
    pub jobs: Option<Vec<AdoJob>>,
    #[serde(default)]
    pub steps: Option<Vec<AdoStep>>,
    #[serde(default)]
    pub pool: Option<serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
pub struct AdoStage {
    /// Stage identifier. Absent when the stage entry is a template reference.
    #[serde(default)]
    pub stage: Option<String>,
    /// Stage-level template reference (`- template: path/to/stage.yml`).
    #[serde(default)]
    pub template: Option<String>,
    #[serde(default)]
    pub variables: Option<AdoVariables>,
    #[serde(default)]
    pub jobs: Vec<AdoJob>,
}

#[derive(Debug, Deserialize)]
pub struct AdoJob {
    /// Regular job identifier
    #[serde(default)]
    pub job: Option<String>,
    /// Deployment job identifier
    #[serde(default)]
    pub deployment: Option<String>,
    #[serde(default)]
    pub variables: Option<AdoVariables>,
    #[serde(default)]
    pub steps: Option<Vec<AdoStep>>,
    #[serde(default)]
    pub pool: Option<serde_yaml::Value>,
    /// Job-level template reference
    #[serde(default)]
    pub template: Option<String>,
}

impl AdoJob {
    pub fn effective_name(&self) -> String {
        self.job
            .as_deref()
            .or(self.deployment.as_deref())
            .unwrap_or("job")
            .to_string()
    }
}

#[derive(Debug, Deserialize)]
pub struct AdoStep {
    /// Task reference e.g. `AzureCLI@2`
    #[serde(default)]
    pub task: Option<String>,
    /// Inline script (cmd/sh)
    #[serde(default)]
    pub script: Option<String>,
    /// Inline bash script
    #[serde(default)]
    pub bash: Option<String>,
    /// Inline PowerShell script
    #[serde(default)]
    pub powershell: Option<String>,
    /// Cross-platform PowerShell
    #[serde(default)]
    pub pwsh: Option<String>,
    /// Step-level template reference
    #[serde(default)]
    pub template: Option<String>,
    #[serde(rename = "displayName", default)]
    pub display_name: Option<String>,
    /// Legacy name alias
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
    /// Task inputs (key → value, but values may be nested)
    #[serde(default)]
    pub inputs: Option<HashMap<String, serde_yaml::Value>>,
    /// Checkout step target (e.g. `self`, a repo alias, or `none`)
    #[serde(default)]
    pub checkout: Option<String>,
    /// When true on a checkout step, writes credentials to .git/config for subsequent steps.
    #[serde(rename = "persistCredentials", default)]
    pub persist_credentials: Option<bool>,
}

/// ADO `variables:` block. Can be a sequence (list of group/name-value entries)
/// or a mapping (variableName: value). We normalise both into a Vec<AdoVariable>.
#[derive(Debug, Default)]
pub struct AdoVariables(pub Vec<AdoVariable>);

impl<'de> serde::Deserialize<'de> for AdoVariables {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = serde_yaml::Value::deserialize(deserializer)?;
        let mut vars = Vec::new();

        match raw {
            serde_yaml::Value::Sequence(seq) => {
                for item in seq {
                    if let Some(map) = item.as_mapping() {
                        if let Some(group_val) = map.get("group") {
                            if let Some(group) = group_val.as_str() {
                                vars.push(AdoVariable::Group {
                                    group: group.to_string(),
                                });
                                continue;
                            }
                        }
                        let name = map
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let value = map
                            .get("value")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let is_secret = map
                            .get("isSecret")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        vars.push(AdoVariable::Named {
                            name,
                            value,
                            is_secret,
                        });
                    }
                }
            }
            serde_yaml::Value::Mapping(map) => {
                for (k, v) in map {
                    let name = k.as_str().unwrap_or("").to_string();
                    let value = v.as_str().unwrap_or("").to_string();
                    vars.push(AdoVariable::Named {
                        name,
                        value,
                        is_secret: false,
                    });
                }
            }
            _ => {}
        }

        Ok(AdoVariables(vars))
    }
}

#[derive(Debug)]
pub enum AdoVariable {
    Group {
        group: String,
    },
    Named {
        name: String,
        value: String,
        is_secret: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> AuthorityGraph {
        let parser = AdoParser;
        let source = PipelineSource {
            file: "azure-pipelines.yml".into(),
            repo: None,
            git_ref: None,
        };
        parser.parse(yaml, &source).unwrap()
    }

    #[test]
    fn parses_simple_pipeline() {
        let yaml = r#"
trigger:
  - main

jobs:
  - job: Build
    steps:
      - script: echo hello
        displayName: Say hello
"#;
        let graph = parse(yaml);
        assert!(graph.nodes.len() >= 2); // System.AccessToken + step
    }

    #[test]
    fn system_access_token_created() {
        let yaml = r#"
steps:
  - script: echo hi
"#;
        let graph = parse(yaml);
        let identities: Vec<_> = graph.nodes_of_kind(NodeKind::Identity).collect();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].name, "System.AccessToken");
        assert_eq!(
            identities[0].metadata.get(META_IDENTITY_SCOPE),
            Some(&"broad".to_string())
        );
    }

    #[test]
    fn variable_group_creates_secret_and_marks_partial() {
        let yaml = r#"
variables:
  - group: MySecretGroup

steps:
  - script: echo hi
"#;
        let graph = parse(yaml);
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "MySecretGroup");
        assert_eq!(
            secrets[0].metadata.get(META_VARIABLE_GROUP),
            Some(&"true".to_string())
        );
        assert_eq!(graph.completeness, AuthorityCompleteness::Partial);
        assert!(
            graph
                .completeness_gaps
                .iter()
                .any(|g| g.contains("MySecretGroup")),
            "completeness gap should name the variable group"
        );
    }

    #[test]
    fn task_with_azure_subscription_creates_service_connection_identity() {
        let yaml = r#"
steps:
  - task: AzureCLI@2
    displayName: Deploy to Azure
    inputs:
      azureSubscription: MyServiceConnection
      scriptType: bash
      inlineScript: az group list
"#;
        let graph = parse(yaml);
        let identities: Vec<_> = graph.nodes_of_kind(NodeKind::Identity).collect();
        // System.AccessToken + service connection
        assert_eq!(identities.len(), 2);
        let conn = identities
            .iter()
            .find(|i| i.name == "MyServiceConnection")
            .unwrap();
        assert_eq!(
            conn.metadata.get(META_SERVICE_CONNECTION),
            Some(&"true".to_string())
        );
        assert_eq!(
            conn.metadata.get(META_IDENTITY_SCOPE),
            Some(&"broad".to_string())
        );
    }

    #[test]
    fn task_with_connected_service_name_creates_identity() {
        let yaml = r#"
steps:
  - task: SqlAzureDacpacDeployment@1
    inputs:
      ConnectedServiceNameARM: MySqlConnection
"#;
        let graph = parse(yaml);
        let identities: Vec<_> = graph.nodes_of_kind(NodeKind::Identity).collect();
        assert!(
            identities.iter().any(|i| i.name == "MySqlConnection"),
            "connectedServiceNameARM should create identity"
        );
    }

    #[test]
    fn script_step_classified_as_first_party() {
        let yaml = r#"
steps:
  - script: echo hi
    displayName: Say hi
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].trust_zone, TrustZone::FirstParty);
    }

    #[test]
    fn bash_step_classified_as_first_party() {
        let yaml = r#"
steps:
  - bash: echo hi
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps[0].trust_zone, TrustZone::FirstParty);
    }

    #[test]
    fn task_step_classified_as_untrusted() {
        let yaml = r#"
steps:
  - task: DotNetCoreCLI@2
    inputs:
      command: build
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].trust_zone, TrustZone::Untrusted);
    }

    #[test]
    fn dollar_paren_var_in_script_creates_secret() {
        let yaml = r#"
steps:
  - script: |
      curl -H "Authorization: $(MY_API_TOKEN)" https://api.example.com
    displayName: Call API
"#;
        let graph = parse(yaml);
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "MY_API_TOKEN");
    }

    #[test]
    fn predefined_ado_var_not_treated_as_secret() {
        let yaml = r#"
steps:
  - script: |
      echo $(Build.BuildId)
      echo $(Agent.WorkFolder)
      echo $(System.DefaultWorkingDirectory)
    displayName: Print vars
"#;
        let graph = parse(yaml);
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert!(
            secrets.is_empty(),
            "predefined ADO vars should not be treated as secrets, got: {:?}",
            secrets.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn template_reference_creates_delegates_to_and_marks_partial() {
        let yaml = r#"
steps:
  - template: steps/deploy.yml
    parameters:
      env: production
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 1);

        let images: Vec<_> = graph.nodes_of_kind(NodeKind::Image).collect();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].name, "steps/deploy.yml");

        let delegates: Vec<_> = graph
            .edges_from(steps[0].id)
            .filter(|e| e.kind == EdgeKind::DelegatesTo)
            .collect();
        assert_eq!(delegates.len(), 1);

        assert_eq!(graph.completeness, AuthorityCompleteness::Partial);
    }

    #[test]
    fn top_level_steps_no_jobs() {
        let yaml = r#"
steps:
  - script: echo a
  - script: echo b
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 2);
    }

    #[test]
    fn top_level_jobs_no_stages() {
        let yaml = r#"
jobs:
  - job: JobA
    steps:
      - script: echo a
  - job: JobB
    steps:
      - script: echo b
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 2);
    }

    #[test]
    fn stages_with_nested_jobs_parsed() {
        let yaml = r#"
stages:
  - stage: Build
    jobs:
      - job: Compile
        steps:
          - script: cargo build
  - stage: Test
    jobs:
      - job: UnitTest
        steps:
          - script: cargo test
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 2);
    }

    #[test]
    fn all_steps_linked_to_system_access_token() {
        let yaml = r#"
steps:
  - script: echo a
  - task: SomeTask@1
    inputs: {}
"#;
        let graph = parse(yaml);
        let token: Vec<_> = graph.nodes_of_kind(NodeKind::Identity).collect();
        assert_eq!(token.len(), 1);
        let token_id = token[0].id;

        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        for step in &steps {
            let links: Vec<_> = graph
                .edges_from(step.id)
                .filter(|e| e.kind == EdgeKind::HasAccessTo && e.to == token_id)
                .collect();
            assert_eq!(
                links.len(),
                1,
                "step '{}' must link to System.AccessToken",
                step.name
            );
        }
    }

    #[test]
    fn named_secret_variable_creates_secret_node() {
        let yaml = r#"
variables:
  - name: MY_PASSWORD
    value: dummy
    isSecret: true

steps:
  - script: echo hi
"#;
        let graph = parse(yaml);
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "MY_PASSWORD");
    }

    #[test]
    fn variables_as_mapping_parsed() {
        let yaml = r#"
variables:
  MY_VAR: hello
  ANOTHER_VAR: world

steps:
  - script: echo hi
"#;
        let graph = parse(yaml);
        // Mapping-style variables without isSecret — no secret nodes created
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert!(
            secrets.is_empty(),
            "plain mapping vars should not create secret nodes"
        );
    }

    #[test]
    fn persist_credentials_creates_persists_to_edge() {
        let yaml = r#"
steps:
  - checkout: self
    persistCredentials: true
  - script: git push
"#;
        let graph = parse(yaml);
        let token_id = graph
            .nodes_of_kind(NodeKind::Identity)
            .find(|n| n.name == "System.AccessToken")
            .expect("System.AccessToken must exist")
            .id;

        let persists_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::PersistsTo && e.to == token_id)
            .collect();
        assert_eq!(
            persists_edges.len(),
            1,
            "checkout with persistCredentials: true must produce exactly one PersistsTo edge"
        );
    }

    #[test]
    fn checkout_without_persist_credentials_no_persists_to_edge() {
        let yaml = r#"
steps:
  - checkout: self
  - script: echo hi
"#;
        let graph = parse(yaml);
        let persists_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::PersistsTo)
            .collect();
        assert!(
            persists_edges.is_empty(),
            "checkout without persistCredentials should not produce PersistsTo edge"
        );
    }

    #[test]
    fn var_flag_secret_marked_as_cli_flag_exposed() {
        let yaml = r#"
steps:
  - script: |
      terraform apply \
        -var "db_password=$(db_password)" \
        -var "api_key=$(api_key)"
    displayName: Terraform apply
"#;
        let graph = parse(yaml);
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert!(!secrets.is_empty(), "should detect secrets from -var flags");
        for secret in &secrets {
            assert_eq!(
                secret.metadata.get(META_CLI_FLAG_EXPOSED),
                Some(&"true".to_string()),
                "secret '{}' passed via -var flag should be marked cli_flag_exposed",
                secret.name
            );
        }
    }

    #[test]
    fn non_var_flag_secret_not_marked_as_cli_flag_exposed() {
        let yaml = r#"
steps:
  - script: |
      curl -H "Authorization: $(MY_TOKEN)" https://api.example.com
"#;
        let graph = parse(yaml);
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert_eq!(secrets.len(), 1);
        assert!(
            !secrets[0].metadata.contains_key(META_CLI_FLAG_EXPOSED),
            "non -var secret should not be marked as cli_flag_exposed"
        );
    }

    #[test]
    fn step_linked_to_variable_group_secret() {
        let yaml = r#"
variables:
  - group: ProdSecrets

steps:
  - script: deploy.sh
"#;
        let graph = parse(yaml);
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert_eq!(secrets.len(), 1);
        let secret_id = secrets[0].id;

        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        let links: Vec<_> = graph
            .edges_from(steps[0].id)
            .filter(|e| e.kind == EdgeKind::HasAccessTo && e.to == secret_id)
            .collect();
        assert_eq!(
            links.len(),
            1,
            "step should be linked to variable group secret"
        );
    }

    #[test]
    fn pr_trigger_sets_meta_trigger_on_graph() {
        let yaml = r#"
pr:
  - '*'

steps:
  - script: echo hi
"#;
        let graph = parse(yaml);
        assert_eq!(
            graph.metadata.get(META_TRIGGER),
            Some(&"pr".to_string()),
            "ADO pr: trigger should set graph META_TRIGGER"
        );
    }

    #[test]
    fn self_hosted_pool_by_name_creates_image_with_self_hosted_metadata() {
        let yaml = r#"
pool:
  name: my-self-hosted-pool

steps:
  - script: echo hi
"#;
        let graph = parse(yaml);
        let images: Vec<_> = graph.nodes_of_kind(NodeKind::Image).collect();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].name, "my-self-hosted-pool");
        assert_eq!(
            images[0].metadata.get(META_SELF_HOSTED),
            Some(&"true".to_string()),
            "pool.name without vmImage must be tagged self-hosted"
        );
    }

    #[test]
    fn vm_image_pool_is_not_tagged_self_hosted() {
        let yaml = r#"
pool:
  vmImage: ubuntu-latest

steps:
  - script: echo hi
"#;
        let graph = parse(yaml);
        let images: Vec<_> = graph.nodes_of_kind(NodeKind::Image).collect();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].name, "ubuntu-latest");
        assert!(
            !images[0].metadata.contains_key(META_SELF_HOSTED),
            "pool.vmImage is Microsoft-hosted — must not be tagged self-hosted"
        );
    }

    #[test]
    fn checkout_self_step_tagged_with_meta_checkout_self() {
        let yaml = r#"
steps:
  - checkout: self
  - script: echo hi
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 2);
        let checkout_step = steps
            .iter()
            .find(|s| s.metadata.contains_key(META_CHECKOUT_SELF))
            .expect("one step must be tagged META_CHECKOUT_SELF");
        assert_eq!(
            checkout_step.metadata.get(META_CHECKOUT_SELF),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn vso_setvariable_sets_meta_writes_env_gate() {
        let yaml = r###"
steps:
  - script: |
      echo "##vso[task.setvariable variable=FOO]bar"
    displayName: Set variable
"###;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 1);
        assert_eq!(
            steps[0].metadata.get(META_WRITES_ENV_GATE),
            Some(&"true".to_string()),
            "##vso[task.setvariable] must mark META_WRITES_ENV_GATE"
        );
    }
}
