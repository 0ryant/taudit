use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use taudit_core::error::TauditError;
use taudit_core::graph::*;
use taudit_core::ports::PipelineParser;

/// Regex-free check: does `s` contain `terraform apply` followed by
/// `-auto-approve` or `--auto-approve` (anywhere on the same line, or on a
/// nearby line when the previous line ends in a shell continuation `\` /
/// PowerShell continuation `` ` ``)?
///
/// Case-sensitive on purpose — Terraform's CLI is case-sensitive and these
/// tokens never appear capitalised in real-world pipelines.
fn script_does_terraform_auto_apply(s: &str) -> bool {
    let lines: Vec<&str> = s.lines().collect();
    for (i, raw_line) in lines.iter().enumerate() {
        // Strip trailing comment.
        let line = raw_line.split('#').next().unwrap_or("");
        if !(line.contains("terraform apply") || line.contains("terraform\tapply")) {
            continue;
        }
        if line.contains("auto-approve") {
            return true;
        }
        // Continuation: peek a few lines forward for the flag.
        let mut continuing = line.trim_end().ends_with('\\') || line.trim_end().ends_with('`');
        let mut j = i + 1;
        while continuing && j < lines.len() && j < i + 4 {
            let next = lines[j].split('#').next().unwrap_or("");
            if next.contains("auto-approve") {
                return true;
            }
            continuing = next.trim_end().ends_with('\\') || next.trim_end().ends_with('`');
            j += 1;
        }
    }
    false
}

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
        let pipeline: AdoPipeline = match AdoPipeline::deserialize(doc) {
            Ok(p) => p,
            Err(e) => {
                // Real-world ADO template fragments often wrap their root content in
                // a parameter conditional like `- ${{ if eq(parameters.X, true) }}:`
                // followed by a list of jobs. That is not a standard YAML mapping at
                // the root, so serde_yaml fails with a "did not find expected key"
                // error. These files are intended to be `template:`-included from a
                // parent pipeline; analyzing them in isolation is not meaningful.
                // Return a near-empty graph marked Partial instead of crashing the scan.
                let msg = e.to_string();
                let looks_like_template_fragment = (msg.contains("did not find expected key")
                    || (msg.contains("parameters")
                        && msg.contains("invalid type: map")
                        && msg.contains("expected a sequence")))
                    && has_root_parameter_conditional(content);
                if looks_like_template_fragment {
                    let mut graph = AuthorityGraph::new(source.clone());
                    graph
                        .metadata
                        .insert(META_PLATFORM.into(), "azure-devops".into());
                    graph.mark_partial(
                        GapKind::Structural,
                        "ADO template fragment with top-level parameter conditional — root structure depends on parent pipeline context".to_string(),
                    );
                    graph.stamp_edge_authority_summaries();
                    return Ok(graph);
                }
                return Err(TauditError::Parse(format!("YAML parse error: {e}")));
            }
        };
        let extra_docs = de.next().is_some();

        let mut graph = AuthorityGraph::new(source.clone());
        graph
            .metadata
            .insert(META_PLATFORM.into(), "azure-devops".into());
        if extra_docs {
            graph.mark_partial(
                GapKind::Expression,
                "file contains multiple YAML documents (--- separator) — only the first was analyzed".to_string(),
            );
        }

        // Detect PR trigger — sets graph-level META_TRIGGER for trigger_context_mismatch.
        // A genuine ADO PR trigger is always a mapping (`pr:\n  branches:...`) or a
        // sequence (`pr:\n  - main`). Scalar opt-out forms — `pr: none`, `pr: ~`,
        // `pr: false`, `pr: ""` — must NOT be treated as active triggers.
        // Checking is_mapping()||is_sequence() is more robust than enumerating every
        // scalar opt-out value (serde_yaml 0.9 parses "none" as a string, "~" as a
        // string, and `null` as null — the shape test handles all forms uniformly).
        let has_pr_trigger = pipeline
            .pr
            .as_ref()
            .map(|v| v.is_mapping() || v.is_sequence())
            .unwrap_or(false);
        if has_pr_trigger {
            graph.metadata.insert(META_TRIGGER.into(), "pr".into());
        }

        // Capture resources.repositories[] declarations and detect aliases that
        // are actually referenced by an `extends:`, `template: x@alias`, or
        // `checkout: alias`. The result is JSON-encoded into graph metadata
        // for the `template_extends_unpinned_branch` rule to consume.
        process_repositories(&pipeline, content, &mut graph);

        // Capture top-level `parameters:` declarations (used by
        // parameter_interpolation_into_shell). ADO defaults missing `type:`
        // to string, so a missing/empty type is treated as a string.
        if let Some(ref params) = pipeline.parameters {
            for p in params {
                let name = match p.name.as_ref() {
                    Some(n) if !n.is_empty() => n.clone(),
                    _ => continue,
                };
                let param_type = p.param_type.clone().unwrap_or_default();
                let has_values_allowlist =
                    p.values.as_ref().map(|v| !v.is_empty()).unwrap_or(false);
                graph.parameters.insert(
                    name,
                    ParamSpec {
                        param_type,
                        has_values_allowlist,
                    },
                );
            }
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

        // Pipeline-level permissions block — when present and non-broad (no write
        // permissions), downgrade System.AccessToken from broad → constrained so
        // over_privileged_identity does not fire on already-restricted pipelines.
        if let Some(ref perms_val) = pipeline.permissions {
            if !ado_permissions_are_broad(perms_val) {
                let perms_str = ado_permissions_display(perms_val);
                graph.nodes[token_id]
                    .metadata
                    .insert(META_IDENTITY_SCOPE.into(), "constrained".into());
                graph.nodes[token_id]
                    .metadata
                    .insert(META_PERMISSIONS.into(), perms_str);
            }
        }

        // Pipeline-level pool: adds Image node, tagged self-hosted when applicable.
        process_pool(&pipeline.pool, &pipeline.workspace, &mut graph);

        // Pipeline-level variable groups and named secrets.
        // pipeline_plain_vars tracks non-secret named variables so $(VAR) refs
        // in scripts don't generate false-positive Secret nodes for plain
        // config values. Stage/job scopes clone and extend this set so plain
        // variables do not leak sideways into unrelated stages or jobs.
        // pipeline_has_variable_groups is set when any pipeline-scope group is encountered so
        // extract_dollar_paren_secrets can avoid creating per-variable Secret
        // nodes from opaque groups (BUG-3).
        let mut pipeline_plain_vars: HashSet<String> = HashSet::new();
        let mut pipeline_has_variable_groups = false;
        let pipeline_secret_ids = process_variables(
            &pipeline.variables,
            &mut graph,
            &mut secret_ids,
            "pipeline",
            &mut pipeline_plain_vars,
            &mut pipeline_has_variable_groups,
        );

        // Determine pipeline structure: stages → jobs → steps, or jobs → steps, or steps only
        if let Some(ref stages) = pipeline.stages {
            for stage in stages {
                // Stage-level template reference — delegate and mark Partial
                if let Some(ref tpl) = stage.template {
                    let stage_name = stage.stage.as_deref().unwrap_or("stage");
                    add_template_delegation(stage_name, tpl, token_id, None, &mut graph);
                    continue;
                }

                let stage_name = stage.stage.as_deref().unwrap_or("stage").to_string();
                let mut stage_plain_vars = pipeline_plain_vars.clone();
                let mut stage_has_variable_groups = false;
                let stage_secret_ids = process_variables(
                    &stage.variables,
                    &mut graph,
                    &mut secret_ids,
                    &stage_name,
                    &mut stage_plain_vars,
                    &mut stage_has_variable_groups,
                );
                let stage_scope_has_variable_groups =
                    pipeline_has_variable_groups || stage_has_variable_groups;

                let stage_condition = non_empty_condition(&stage.condition);
                if let Some(c) = stage_condition {
                    mark_condition_partial(&mut graph, "stage", &stage_name, c);
                }
                let stage_depends_on = stage.depends_on.as_ref().map(|d| d.as_csv());

                for job in &stage.jobs {
                    let job_name = job.effective_name();
                    let mut job_plain_vars = stage_plain_vars.clone();
                    let mut job_has_variable_groups = false;
                    let job_secret_ids = process_variables(
                        &job.variables,
                        &mut graph,
                        &mut secret_ids,
                        &job_name,
                        &mut job_plain_vars,
                        &mut job_has_variable_groups,
                    );
                    let step_scope_has_variable_groups =
                        stage_scope_has_variable_groups || job_has_variable_groups;

                    let effective_workspace =
                        job.workspace.as_ref().or(pipeline.workspace.as_ref());
                    process_pool(&job.pool, &effective_workspace.cloned(), &mut graph);

                    let all_secrets: Vec<NodeId> = pipeline_secret_ids
                        .iter()
                        .chain(&stage_secret_ids)
                        .chain(&job_secret_ids)
                        .copied()
                        .collect();

                    let steps_start = graph.nodes.len();

                    let job_condition = non_empty_condition(&job.condition);
                    if let Some(c) = job_condition {
                        mark_condition_partial(&mut graph, "job", &job_name, c);
                    }
                    // Job's `dependsOn:` overrides any stage-level value when both
                    // are present (job-level wins for the job's own ordering); fall
                    // back to the stage-level value otherwise so the chain still
                    // surfaces on the steps.
                    let job_depends_on = job
                        .depends_on
                        .as_ref()
                        .map(|d| d.as_csv())
                        .or_else(|| stage_depends_on.clone());

                    let outer_condition = join_conditions(stage_condition, job_condition);

                    let job_steps = job.all_steps();
                    process_steps(
                        &job_steps,
                        &job_name,
                        token_id,
                        &all_secrets,
                        &job_plain_vars,
                        step_scope_has_variable_groups,
                        outer_condition.as_deref(),
                        job_depends_on.as_deref(),
                        &mut graph,
                        &mut secret_ids,
                    );

                    if let Some(ref tpl) = job.template {
                        add_template_delegation(
                            &job_name,
                            tpl,
                            token_id,
                            Some(&job_name),
                            &mut graph,
                        );
                    }

                    if job.has_environment_binding() {
                        tag_job_steps_env_approval(&mut graph, steps_start);
                    }
                }
            }
        } else if let Some(ref jobs) = pipeline.jobs {
            for job in jobs {
                let job_name = job.effective_name();
                let mut job_plain_vars = pipeline_plain_vars.clone();
                let mut job_has_variable_groups = false;
                let job_secret_ids = process_variables(
                    &job.variables,
                    &mut graph,
                    &mut secret_ids,
                    &job_name,
                    &mut job_plain_vars,
                    &mut job_has_variable_groups,
                );
                let step_scope_has_variable_groups =
                    pipeline_has_variable_groups || job_has_variable_groups;

                let effective_workspace = job.workspace.as_ref().or(pipeline.workspace.as_ref());
                process_pool(&job.pool, &effective_workspace.cloned(), &mut graph);

                let all_secrets: Vec<NodeId> = pipeline_secret_ids
                    .iter()
                    .chain(&job_secret_ids)
                    .copied()
                    .collect();

                let steps_start = graph.nodes.len();

                let job_condition = non_empty_condition(&job.condition);
                if let Some(c) = job_condition {
                    mark_condition_partial(&mut graph, "job", &job_name, c);
                }
                let job_depends_on = job.depends_on.as_ref().map(|d| d.as_csv());

                let job_steps = job.all_steps();
                process_steps(
                    &job_steps,
                    &job_name,
                    token_id,
                    &all_secrets,
                    &job_plain_vars,
                    step_scope_has_variable_groups,
                    job_condition,
                    job_depends_on.as_deref(),
                    &mut graph,
                    &mut secret_ids,
                );

                if let Some(ref tpl) = job.template {
                    add_template_delegation(&job_name, tpl, token_id, Some(&job_name), &mut graph);
                }

                if job.has_environment_binding() {
                    tag_job_steps_env_approval(&mut graph, steps_start);
                }
            }
        } else if let Some(ref steps) = pipeline.steps {
            process_steps(
                steps,
                "pipeline",
                token_id,
                &pipeline_secret_ids,
                &pipeline_plain_vars,
                pipeline_has_variable_groups,
                None,
                None,
                &mut graph,
                &mut secret_ids,
            );
        }

        // Cross-platform misclassification trap (red-team R2 #5): a YAML file
        // shaped like ADO at the top level (stages/jobs/steps present) but whose
        // body uses constructs the ADO parser doesn't recognise will deserialize
        // without errors and yield no Step nodes. Marking Partial surfaces the
        // gap instead of returning completeness=complete on a clean-but-empty
        // graph (which a CI gate would treat as "passed").
        let step_count = graph
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Step)
            .count();
        let had_step_carrier = pipeline.stages.as_ref().is_some_and(|s| !s.is_empty())
            || pipeline.jobs.as_ref().is_some_and(|j| !j.is_empty())
            || pipeline.steps.as_ref().is_some_and(|s| !s.is_empty());
        if step_count == 0 && had_step_carrier {
            graph.mark_partial(
                GapKind::Structural,
                "stages/jobs/steps parsed but produced 0 step nodes — possible non-ADO YAML wrong-platform-classified".to_string(),
            );
        }

        graph.stamp_edge_authority_summaries();
        Ok(graph)
    }
}

/// Returns `Some(trimmed)` when an ADO `condition:` value is present and
/// carries non-whitespace content. Empty strings and pure-whitespace values
/// (which ADO treats as "no condition", same as omitting the key) yield
/// `None` so the parser does not mark a Partial-Expression gap for noise.
fn non_empty_condition(c: &Option<String>) -> Option<&str> {
    let s = c.as_deref()?.trim();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Join the optional outer condition chain (already AND-joined for stage and
/// job) with this scope's condition, producing the final ` AND `-joined chain
/// to stamp on Step nodes via `META_CONDITION`. Either side may be absent.
fn join_conditions(outer: Option<&str>, inner: Option<&str>) -> Option<String> {
    match (outer, inner) {
        (None, None) => None,
        (Some(o), None) => Some(o.to_string()),
        (None, Some(i)) => Some(i.to_string()),
        (Some(o), Some(i)) => Some(format!("{o} AND {i}")),
    }
}

/// Mark the graph Partial with `GapKind::Expression` and a reason that names
/// the scope kind ("stage" / "job" / "step"), the entity's display name, and
/// the literal condition text — enough for an operator to grep findings
/// against `condition:` clauses in the source pipeline.
fn mark_condition_partial(
    graph: &mut AuthorityGraph,
    scope_kind: &str,
    name: &str,
    condition: &str,
) {
    graph.mark_partial(
        GapKind::Expression,
        format!(
            "ADO {scope_kind} '{name}' condition: '{condition}' — runtime evaluation not modelled"
        ),
    );
}

/// Process an ADO `pool:` block. ADO pools come in two shapes:
///   - `pool: my-self-hosted-pool` (string shorthand — always self-hosted)
///   - `pool: { name: my-pool }` (named pool — self-hosted)
///   - `pool: { vmImage: ubuntu-latest }` (Microsoft-hosted)
///   - `pool: { name: my-pool, vmImage: ubuntu-latest }` (hosted; vmImage wins)
///
/// Creates an Image node representing the agent environment. Self-hosted pools
/// Returns `true` when an ADO pipeline-level `permissions:` value implies a
/// broad (write-capable) token scope, `false` when every scope is `none` or
/// `read` (i.e. the token has been explicitly restricted).
///
/// ADO permission values are the strings `"read"`, `"write"`, and `"none"`.
/// Any unrecognised shape is conservatively treated as broad.
fn ado_permissions_are_broad(perms: &serde_yaml::Value) -> bool {
    if let Some(map) = perms.as_mapping() {
        map.values().any(|v| v.as_str() == Some("write"))
    } else {
        // Scalar form: ADO accepts "read", "write", "none" as pipeline-level
        // permission values. "read" and "none" are constrained; "write" is
        // broad. Anything else (null, tilde, empty, unrecognised string) is
        // conservatively treated as broad (unknown = risky).
        matches!(perms.as_str(), Some("write"))
    }
}

/// Format an ADO `permissions:` YAML value into a compact human-readable
/// string for the finding message (e.g. `"contents: none, idToken: none"`).
fn ado_permissions_display(perms: &serde_yaml::Value) -> String {
    if let Some(map) = perms.as_mapping() {
        map.iter()
            .filter_map(|(k, v)| {
                let key = k.as_str()?;
                let val = v.as_str().unwrap_or("?");
                Some(format!("{key}: {val}"))
            })
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        perms.as_str().unwrap_or("none").to_string()
    }
}

/// are tagged with META_SELF_HOSTED so downstream rules can flag them.
///
/// When `workspace` is provided and contains `clean:` with a truthy value
/// (`true`, `all`, `outputs`, `resources`), the Image node is also tagged
/// with META_WORKSPACE_CLEAN.
fn process_pool(
    pool: &Option<serde_yaml::Value>,
    workspace: &Option<serde_yaml::Value>,
    graph: &mut AuthorityGraph,
) {
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
    if has_workspace_clean(workspace) {
        meta.insert(META_WORKSPACE_CLEAN.into(), "true".into());
    }
    graph.add_node_with_metadata(NodeKind::Image, image_name, TrustZone::FirstParty, meta);
}

/// Returns `true` when the ADO `workspace:` value specifies a `clean:` setting
/// that wipes the workspace between runs. Recognised truthy forms:
///   - `workspace: { clean: all }`
///   - `workspace: { clean: outputs }`
///   - `workspace: { clean: resources }`
///   - `workspace: { clean: true }`
fn has_workspace_clean(workspace: &Option<serde_yaml::Value>) -> bool {
    let Some(ws) = workspace else {
        return false;
    };
    let Some(map) = ws.as_mapping() else {
        return false;
    };
    let Some(clean) = map.get("clean") else {
        return false;
    };
    match clean {
        serde_yaml::Value::Bool(b) => *b,
        serde_yaml::Value::String(s) => {
            let lower = s.to_ascii_lowercase();
            matches!(lower.as_str(), "all" | "outputs" | "resources" | "true")
        }
        _ => false,
    }
}

/// Scan the parsed pipeline for `resources.repositories[]` declarations and
/// determine which aliases are referenced inside the same file. Stores the
/// result as a JSON-encoded array in `graph.metadata[META_REPOSITORIES]`.
///
/// Usage signal — an alias is "used" when it appears in any of:
///   - `template: <path>@<alias>` (anywhere — top-level extends, stage, job, step)
///   - `extends:` referencing `template: <path>@<alias>`
///   - `checkout: <alias>` (steps consume an external repo into the workspace)
///
/// The `extends:` and per-step `template:` references are resolved by walking
/// the parsed Value tree; the raw text is only used for the `checkout:` case
/// (cheap substring scan, robust to YAML shape variation).
fn process_repositories(pipeline: &AdoPipeline, raw_content: &str, graph: &mut AuthorityGraph) {
    let resources = match pipeline.resources.as_ref() {
        Some(r) if !r.repositories.is_empty() => r,
        _ => return,
    };

    // Collect all aliases referenced as `template: x@alias`. We walk every
    // `template:` field appearing in the parsed pipeline (extends and steps
    // already deserialize to their own paths; stages/jobs use the per-job
    // template field). The raw YAML walk via serde_yaml::Value covers all
    // shapes uniformly without re-deriving structure-specific models.
    let mut used_aliases: HashSet<String> = HashSet::new();

    if let Some(ref ext) = pipeline.extends {
        collect_template_alias_refs(ext, &mut used_aliases);
    }
    if let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(raw_content) {
        collect_template_alias_refs(&value, &mut used_aliases);
        collect_checkout_alias_refs(&value, &mut used_aliases);
    }

    // Build the JSON-encoded repository descriptor list.
    let mut entries: Vec<serde_json::Value> = Vec::with_capacity(resources.repositories.len());
    for repo in &resources.repositories {
        let used = used_aliases.contains(&repo.repository);
        let mut obj = serde_json::Map::new();
        obj.insert(
            "alias".into(),
            serde_json::Value::String(repo.repository.clone()),
        );
        if let Some(ref t) = repo.repo_type {
            obj.insert("repo_type".into(), serde_json::Value::String(t.clone()));
        }
        if let Some(ref n) = repo.name {
            obj.insert("name".into(), serde_json::Value::String(n.clone()));
        }
        if let Some(ref r) = repo.git_ref {
            obj.insert("ref".into(), serde_json::Value::String(r.clone()));
        }
        obj.insert("used".into(), serde_json::Value::Bool(used));
        entries.push(serde_json::Value::Object(obj));
    }

    if let Ok(json) = serde_json::to_string(&serde_json::Value::Array(entries)) {
        graph.metadata.insert(META_REPOSITORIES.into(), json);
    }
}

/// Walk a YAML value and record every `template: <ref>@<alias>` alias seen.
/// Recurses into mappings and sequences so it catches references in extends,
/// stages, jobs, steps, and conditional blocks indiscriminately.
fn collect_template_alias_refs(value: &serde_yaml::Value, sink: &mut HashSet<String>) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                if k.as_str() == Some("template") {
                    if let Some(s) = v.as_str() {
                        if let Some(alias) = parse_template_alias(s) {
                            sink.insert(alias);
                        }
                    }
                }
                collect_template_alias_refs(v, sink);
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for v in seq {
                collect_template_alias_refs(v, sink);
            }
        }
        _ => {}
    }
}

/// Walk a YAML value and record every `checkout: <alias>` value seen, except
/// `self` and `none` which are platform keywords (not external repo aliases).
fn collect_checkout_alias_refs(value: &serde_yaml::Value, sink: &mut HashSet<String>) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                if k.as_str() == Some("checkout") {
                    if let Some(s) = v.as_str() {
                        if s != "self" && s != "none" && !s.is_empty() {
                            sink.insert(s.to_string());
                        }
                    }
                }
                collect_checkout_alias_refs(v, sink);
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for v in seq {
                collect_checkout_alias_refs(v, sink);
            }
        }
        _ => {}
    }
}

/// Extract `<alias>` from a `template: <path>@<alias>` reference. Returns
/// None for plain in-repo paths (`templates/deploy.yml`) which target the
/// current pipeline's repo, not an external `resources.repositories[]` entry.
fn parse_template_alias(template_ref: &str) -> Option<String> {
    let at = template_ref.rfind('@')?;
    let alias = &template_ref[at + 1..];
    if alias.is_empty() {
        None
    } else {
        Some(alias.to_string())
    }
}

/// Tag every Step node added since `start_idx` with META_ENV_APPROVAL.
/// Used after `process_steps` for a job whose `environment:` is configured —
/// the environment binding indicates the job sits behind a manual approval
/// gate, which is an isolation boundary that breaks automatic propagation.
fn tag_job_steps_env_approval(graph: &mut AuthorityGraph, start_idx: usize) {
    for node in graph.nodes.iter_mut().skip(start_idx) {
        if node.kind == NodeKind::Step {
            node.metadata
                .insert(META_ENV_APPROVAL.into(), "true".into());
        }
    }
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
    has_variable_groups: &mut bool,
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
                    graph.mark_partial(
                        GapKind::Expression,
                        format!(
                            "variable group in {scope} uses template expression — group name unresolvable at parse time"
                        ),
                    );
                    continue;
                }
                *has_variable_groups = true;
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
                graph.mark_partial(
                    GapKind::Structural,
                    format!(
                        "variable group '{group}' in {scope} — contents unresolvable without ADO API access"
                    ),
                );
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
///
/// `outer_condition` is the AND-joined chain of stage- and job-level
/// `condition:` expressions that gate this step's containing job at runtime.
/// When present, it (combined with any per-step `condition:`) is stamped onto
/// every emitted Step node via `META_CONDITION` so downstream rules can see
/// that the step is conditionally reachable.
///
/// `outer_depends_on` is the comma-joined `dependsOn:` predecessor list
/// inherited from the job (or stage). Stamped onto Step nodes via
/// `META_DEPENDS_ON` only when non-default (the parser does not synthesise
/// the implicit "depends on previous job/stage" link).
#[allow(clippy::too_many_arguments)]
fn process_steps(
    steps: &[AdoStep],
    job_name: &str,
    token_id: NodeId,
    inherited_secrets: &[NodeId],
    plain_vars: &HashSet<String>,
    has_variable_groups: bool,
    outer_condition: Option<&str>,
    outer_depends_on: Option<&str>,
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
            add_template_delegation(&step_name, tpl, token_id, Some(job_name), graph);
            continue;
        }

        // Determine step kind and trust zone
        let (step_name, trust_zone, inline_script) = classify_step(step, job_name, idx);

        // Step-level condition: mark Partial-Expression and join with the
        // outer (stage + job) chain so the step's META_CONDITION reflects the
        // full ` AND `-joined gate it actually sits behind at runtime.
        let step_condition = non_empty_condition(&step.condition);
        if let Some(c) = step_condition {
            mark_condition_partial(graph, "step", &step_name, c);
        }
        let effective_condition = join_conditions(outer_condition, step_condition);

        // Step-level `dependsOn:` overrides the inherited (job-level) value
        // when present. Default behaviour (no key) inherits from the job —
        // and at the job level we already only stamped non-default values,
        // so absence at both layers means we stamp nothing.
        let effective_depends_on = step
            .depends_on
            .as_ref()
            .map(|d| d.as_csv())
            .or_else(|| outer_depends_on.map(|s| s.to_string()));

        let step_id = graph.add_node(NodeKind::Step, &step_name, trust_zone);

        // Stamp parent job name so consumers (e.g. `taudit map --job`) can
        // attribute steps back to their containing job.
        if let Some(node) = graph.nodes.get_mut(step_id) {
            node.metadata.insert(META_JOB_NAME.into(), job_name.into());
            // Stamp the raw inline script body so script-aware rules
            // (env-export of secrets, secret materialisation to files,
            // Key Vault → plaintext) can pattern-match on the actual
            // command text the agent will run.
            if let Some(ref body) = inline_script {
                node.metadata.insert(META_SCRIPT_BODY.into(), body.clone());
            }
            // Stamp the AND-joined chain of stage/job/step `condition:`
            // expressions that gate this step at runtime. Consumed by
            // `apply_compensating_controls` to downgrade severity on
            // findings whose firing step is gated behind a conditional.
            if let Some(ref c) = effective_condition {
                node.metadata.insert(META_CONDITION.into(), c.clone());
            }
            // Stamp the comma-joined non-default `dependsOn:` predecessor
            // list. No consumer rule yet — parser-side hook for future
            // cross-job taint analysis.
            if let Some(ref d) = effective_depends_on {
                if !d.is_empty() {
                    node.metadata.insert(META_DEPENDS_ON.into(), d.clone());
                }
            }
        }

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
                "environmentservicename",
                "backendservicearm",
            ];
            // determinism: sort by key — same YAML must produce same NodeId order
            let mut input_entries: Vec<(&String, &serde_yaml::Value)> = inputs.iter().collect();
            input_entries.sort_by(|a, b| a.0.cmp(b.0));
            for (raw_key, val) in input_entries {
                let lower = raw_key.to_lowercase();
                if !service_conn_keys.contains(&lower.as_str()) {
                    continue;
                }
                let conn_name = yaml_value_as_str(val).unwrap_or(raw_key.as_str());
                if !conn_name.starts_with("$(") {
                    // Stamp the connection name onto the step itself so rules
                    // that need the name (e.g. terraform_auto_approve_in_prod)
                    // don't have to traverse edges.
                    if let Some(node) = graph.nodes.get_mut(step_id) {
                        node.metadata
                            .insert(META_SERVICE_CONNECTION_NAME.into(), conn_name.to_string());
                    }

                    let mut meta = HashMap::new();
                    meta.insert(META_SERVICE_CONNECTION.into(), "true".into());
                    meta.insert(META_IDENTITY_SCOPE.into(), "broad".into());
                    // ADO pipeline YAML does not embed the authentication scheme
                    // of the service endpoint (WorkloadIdentityFederation vs.
                    // ServicePrincipal), so we cannot reliably determine whether a
                    // connection uses OIDC.  Leave META_OIDC unset -- the safe
                    // default -- so that rules like service_connection_scope_mismatch
                    // can fire on classic SPN connections.
                    let conn_id = graph.add_node_with_metadata(
                        NodeKind::Identity,
                        conn_name,
                        TrustZone::FirstParty,
                        meta,
                    );
                    graph.add_edge(step_id, conn_id, EdgeKind::HasAccessTo);
                }
            }

            // addSpnToEnvironment: true exposes federated SPN material
            // (idToken, servicePrincipalKey, servicePrincipalId, tenantId)
            // to the step's inline script via env vars. Stamp the step so
            // addspn_with_inline_script can pattern-match without traversal.
            if let Some(val) = input_value(inputs, "addSpnToEnvironment") {
                let truthy = match val {
                    serde_yaml::Value::Bool(b) => *b,
                    serde_yaml::Value::String(s) => s.eq_ignore_ascii_case("true"),
                    _ => false,
                };
                if truthy {
                    if let Some(node) = graph.nodes.get_mut(step_id) {
                        node.metadata
                            .insert(META_ADD_SPN_TO_ENV.into(), "true".into());
                    }
                }
            }

            // TerraformCLI@N / TerraformTaskV1..V4 with command: apply +
            // commandOptions containing auto-approve = same as inline
            // `terraform apply --auto-approve`. Detect once here so the rule
            // can read a single META_TERRAFORM_AUTO_APPROVE marker.
            let task_lower = step
                .task
                .as_deref()
                .map(|t| t.to_lowercase())
                .unwrap_or_default();
            let is_terraform_task = task_lower.starts_with("terraformcli@")
                || task_lower.starts_with("terraformtask@")
                || task_lower.starts_with("terraformtaskv");
            if is_terraform_task {
                let cmd_lower = input_str(inputs, "command")
                    .map(|s| s.to_lowercase())
                    .unwrap_or_default();
                let opts = input_str(inputs, "commandOptions").unwrap_or("");
                if cmd_lower == "apply" && opts.contains("auto-approve") {
                    if let Some(node) = graph.nodes.get_mut(step_id) {
                        node.metadata
                            .insert(META_TERRAFORM_AUTO_APPROVE.into(), "true".into());
                    }
                }
            }

            // Detect $(varName) references in task input values
            // determinism: sort by key — same YAML must produce same NodeId order
            let mut paren_entries: Vec<(&String, &serde_yaml::Value)> = inputs.iter().collect();
            paren_entries.sort_by(|a, b| a.0.cmp(b.0));
            for (_k, val) in paren_entries {
                if let Some(s) = yaml_value_as_str(val) {
                    extract_dollar_paren_secrets(
                        s,
                        step_id,
                        plain_vars,
                        has_variable_groups,
                        graph,
                        cache,
                    );
                }
            }
        }

        // Inline-script detection of `terraform apply --auto-approve`.
        // Done after inputs processing so we can OR the two signals into a
        // single META_TERRAFORM_AUTO_APPROVE marker on the step.
        if let Some(ref body) = inline_script {
            if script_does_terraform_auto_apply(body) {
                if let Some(node) = graph.nodes.get_mut(step_id) {
                    node.metadata
                        .insert(META_TERRAFORM_AUTO_APPROVE.into(), "true".into());
                }
            }
        }

        // Detect $(varName) in step env values
        if let Some(ref env) = step.env {
            // determinism: sort by key — same YAML must produce same NodeId order
            let mut env_entries: Vec<(&String, &String)> = env.iter().collect();
            env_entries.sort_by(|a, b| a.0.cmp(b.0));
            for (_k, val) in env_entries {
                extract_dollar_paren_secrets(
                    val,
                    step_id,
                    plain_vars,
                    has_variable_groups,
                    graph,
                    cache,
                );
            }
        }

        // Detect $(varName) in inline script text
        if let Some(ref script) = inline_script {
            extract_dollar_paren_secrets(
                script,
                step_id,
                plain_vars,
                has_variable_groups,
                graph,
                cache,
            );
        }

        // Detect ##vso[task.setvariable] — environment gate mutation in ADO pipelines.
        // META_WRITES_ENV_GATE marks the step as writing to the env gate (always).
        // META_ENV_GATE_WRITES_SECRET_VALUE marks when the written value contains a
        // $(secretRef) expression — i.e., a secret is being propagated (BUG-4: plain
        // integer writes like `##vso[task.setvariable variable=Count]3` should not
        // fire as secret-exfiltration findings).
        if let Some(ref script) = inline_script {
            let lower = script.to_lowercase();
            if lower.contains("##vso[task.setvariable") {
                if let Some(node) = graph.nodes.get_mut(step_id) {
                    node.metadata
                        .insert(META_WRITES_ENV_GATE.into(), "true".into());
                    node.metadata
                        .insert(META_SETVARIABLE_ADO.into(), "true".into());
                    if setvariable_value_contains_secret_ref(script) {
                        node.metadata
                            .insert(META_ENV_GATE_WRITES_SECRET_VALUE.into(), "true".into());
                    }
                }
            }
        }
    }
}

/// Classify an ADO step, returning (name, trust_zone, inline_script_text).
///
/// `inline_script_text` is populated whenever the step has script content —
/// either as a top-level `script:`/`bash:`/`powershell:`/`pwsh:` key, or as a
/// task input (`Bash@3.inputs.script`, `PowerShell@2.inputs.script`,
/// `AzureCLI@2.inputs.inlineScript`, `AzurePowerShell@5.inputs.Inline`, …).
/// Task-input keys are matched case-insensitively because the ADO YAML schema
/// is itself case-insensitive on input names.
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
        // Task step — script body may live in inputs.{script,inlineScript,Inline}.
        let inline = extract_task_inline_script(step.inputs.as_ref());
        (name, TrustZone::Untrusted, inline)
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

/// Pull an inline script body out of a task step's `inputs:` mapping.
/// Recognises the three common conventions:
///   - `inputs.script` (Bash@3, PowerShell@2 — when targetType: inline)
///   - `inputs.inlineScript` (AzureCLI@2)
///   - `inputs.Inline` (AzurePowerShell@5 — note the capital I)
///
/// Match is case-insensitive so a hand-written pipeline using `Script:` or
/// `INLINESCRIPT:` is still picked up.
fn extract_task_inline_script(
    inputs: Option<&HashMap<String, serde_yaml::Value>>,
) -> Option<String> {
    let inputs = inputs?;
    const KEYS: &[&str] = &["script", "inlinescript", "inline"];
    // determinism: sort by key — same YAML must produce same NodeId order
    // (first-match semantics: ensure the same key wins across runs when more
    // than one of `script`/`inlineScript`/`Inline` is present in the same task)
    let mut entries: Vec<(&String, &serde_yaml::Value)> = inputs.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    for (raw_key, val) in entries {
        let lower = raw_key.to_lowercase();
        if KEYS.contains(&lower.as_str()) {
            if let Some(s) = val.as_str() {
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

fn input_value<'a>(
    inputs: &'a HashMap<String, serde_yaml::Value>,
    wanted: &str,
) -> Option<&'a serde_yaml::Value> {
    let mut entries: Vec<(&String, &serde_yaml::Value)> = inputs.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    entries
        .into_iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| value)
}

fn input_str<'a>(inputs: &'a HashMap<String, serde_yaml::Value>, wanted: &str) -> Option<&'a str> {
    input_value(inputs, wanted).and_then(yaml_value_as_str)
}

/// Add a DelegatesTo edge from a synthetic step node to a template image node.
///
/// Trust zone heuristic: templates referenced with `@repository` (e.g. `steps/deploy.yml@templates`)
/// pull code from an external repository and are Untrusted. Plain relative paths like
/// `steps/deploy.yml` resolve within the same repo and are FirstParty — mirroring how GHA
/// treats `./local-action`.
///
/// `job_name` is `Some` when the delegation is created inside a job's scope
/// (job-level template, or template step inside `process_steps`); it is `None`
/// for stage-level template delegations that don't belong to a specific job.
fn add_template_delegation(
    step_name: &str,
    template_path: &str,
    token_id: NodeId,
    job_name: Option<&str>,
    graph: &mut AuthorityGraph,
) {
    let tpl_trust_zone = if template_path.contains('@') {
        TrustZone::Untrusted
    } else {
        TrustZone::FirstParty
    };
    let step_id = graph.add_node(NodeKind::Step, step_name, TrustZone::FirstParty);
    if let Some(jn) = job_name {
        if let Some(node) = graph.nodes.get_mut(step_id) {
            node.metadata.insert(META_JOB_NAME.into(), jn.into());
        }
    }
    let tpl_id = graph.add_node(NodeKind::Image, template_path, tpl_trust_zone);
    graph.add_edge(step_id, tpl_id, EdgeKind::DelegatesTo);
    graph.add_edge(step_id, token_id, EdgeKind::HasAccessTo);
    graph.mark_partial(
        GapKind::Structural,
        format!(
            "template '{template_path}' cannot be resolved inline — authority within the template is unknown"
        ),
    );
}

/// Returns true if a `##vso[task.setvariable ...]VALUE` call's VALUE contains
/// an ADO `$(secretRef)` expression — i.e., the step is writing a secret-derived
/// value into the environment gate (BUG-4: plain integers and PowerShell vars
/// like `$psVar` should not fire the secret-exfiltration rule).
fn setvariable_value_contains_secret_ref(script: &str) -> bool {
    for line in script.lines() {
        let lower = line.to_lowercase();
        if !lower.contains("##vso[task.setvariable") {
            continue;
        }
        // The value starts after the closing `]` of the ##vso directive.
        if let Some(close_bracket) = line.find(']') {
            let value_part = &line[close_bracket + 1..];
            if contains_unescaped_variable_ref(value_part) {
                return true;
            }
        }
    }
    false
}

fn contains_unescaped_variable_ref(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut pos = 0;
    while pos + 1 < bytes.len() {
        if bytes[pos] == b'$' && bytes[pos + 1] == b'(' {
            if pos == 0 || bytes[pos - 1] != b'$' {
                return true;
            }
            pos += 2;
            continue;
        }
        pos += 1;
    }
    false
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
    has_variable_groups: bool,
    graph: &mut AuthorityGraph,
    cache: &mut HashMap<String, NodeId>,
) {
    let mut pos = 0;
    let bytes = text.as_bytes();
    while pos < bytes.len() {
        if pos + 2 < bytes.len() && bytes[pos] == b'$' && bytes[pos + 1] == b'(' {
            if pos > 0 && bytes[pos - 1] == b'$' {
                pos += 2;
                continue;
            }
            let start = pos + 2;
            if let Some(end_offset) = text[start..].find(')') {
                let var_name = &text[start..start + end_offset];
                // BUG-3: when variable groups are present the group is opaque —
                // any $(VAR) could be a plain config value from the group.
                // Only create a Secret node if the var was explicitly declared
                // as a secret (is already in cache) or there are no groups.
                let already_declared_secret = cache.contains_key(var_name);
                if is_valid_ado_identifier(var_name)
                    && !is_predefined_ado_var(var_name)
                    && !plain_vars.contains(var_name)
                    && (!has_variable_groups || already_declared_secret)
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
/// Matches `-var key=$(VAR)` and `-var=key=$(VAR)` but not `-var-file`.
fn is_in_terraform_var_flag(text: &str, var_pos: usize) -> bool {
    let line_start = text[..var_pos].rfind('\n').map(|p| p + 1).unwrap_or(0);
    let line_before = &text[line_start..var_pos];
    let mut matches: Vec<(usize, &str)> = line_before.match_indices("-var").collect();
    matches.reverse();
    for (idx, _) in matches {
        if idx > 0 {
            let prev = line_before[..idx].chars().next_back();
            if prev.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                continue;
            }
        }
        let mut after = &line_before[idx + "-var".len()..];
        if after.starts_with('-') {
            continue;
        }
        after = after.trim_start();
        if let Some(rest) = after.strip_prefix('=') {
            after = rest.trim_start();
        }
        after = after.trim_start_matches(['"', '\'']);
        if after.contains('=') {
            return true;
        }
    }
    false
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
    /// `stages:` is normally a sequence of stage objects, but real-world
    /// pipelines also use `stages: ${{ parameters.stages }}` (a template
    /// expression that resolves at runtime to a list). The custom
    /// deserializer accepts both shapes; non-sequence shapes resolve to
    /// `None` and the graph is marked Partial downstream.
    #[serde(default, deserialize_with = "deserialize_optional_stages")]
    pub stages: Option<Vec<AdoStage>>,
    #[serde(default)]
    pub jobs: Option<Vec<AdoJob>>,
    #[serde(default)]
    pub steps: Option<Vec<AdoStep>>,
    #[serde(default)]
    pub pool: Option<serde_yaml::Value>,
    /// Pipeline-level `workspace:` block. The only security-relevant field is
    /// `clean:` (`outputs`, `resources`, `all`, or `true`), which causes the
    /// agent to wipe the workspace between runs. Used to tag self-hosted Image
    /// nodes with `META_WORKSPACE_CLEAN`.
    #[serde(default)]
    pub workspace: Option<serde_yaml::Value>,
    /// `resources:` block — repository declarations, container declarations,
    /// pipeline declarations. We only consume `repositories[]` today.
    /// Pre-2019 ADO accepts a sequence form (`resources: [- repo: self]`)
    /// which has no `repositories:` key — the custom deserializer accepts
    /// both shapes and treats the sequence form as an empty resources block.
    #[serde(default, deserialize_with = "deserialize_optional_resources")]
    pub resources: Option<AdoResources>,
    /// Top-level `extends:` directive — `extends: { template: x@alias, ... }`.
    /// Captured raw so we can scan for `template: x@alias` references that
    /// consume a `resources.repositories[]` entry.
    #[serde(default)]
    pub extends: Option<serde_yaml::Value>,
    /// Top-level `parameters:` declarations. Each entry has at minimum a
    /// `name`; `type` defaults to `string` when omitted. `values:` is an
    /// optional allowlist that constrains caller input.
    /// ADO accepts two shapes: the typed sequence form
    /// (`- name: foo \n type: string \n default: bar`) and the legacy
    /// untyped map form (`parameters: { foo: bar, baz: '' }`) used in
    /// older template fragments. The custom deserializer normalizes both.
    #[serde(default, deserialize_with = "deserialize_optional_parameters")]
    pub parameters: Option<Vec<AdoParameter>>,
    /// Pipeline-level `permissions:` block. Controls the scope of
    /// `System.AccessToken` for all jobs in the pipeline unless overridden
    /// at the job level. Parsed to detect explicit scope restriction (e.g.
    /// `contents: none`) so `over_privileged_identity` doesn't fire on
    /// pipelines that have already locked down their token.
    #[serde(default)]
    pub permissions: Option<serde_yaml::Value>,
}

/// Accept either a sequence of `AdoParameter` (modern typed form) or a
/// mapping of parameter name → default value (legacy untyped form used in
/// many template fragments). For the map form, each key becomes an
/// `AdoParameter` with the key as `name` and no type/values. Returns `None`
/// for any other shape (e.g. a bare template expression).
///
/// Implemented as a serde Visitor (rather than going through
/// `serde_yaml::Value`) so that downstream struct deserialization uses
/// serde's native lazy iteration — this avoids serde_yaml's strict
/// duplicate-key detection on `${{ else }}`-style template-conditional
/// keys that appear in stage/job `parameters:` blocks of unrelated entries.
fn deserialize_optional_parameters<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<AdoParameter>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{MapAccess, SeqAccess, Visitor};
    use std::fmt;

    struct ParamsVisitor;

    impl<'de> Visitor<'de> for ParamsVisitor {
        type Value = Option<Vec<AdoParameter>>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a sequence of parameter declarations, a mapping of name→default, null, or a template expression")
        }

        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_any(self)
        }

        // Bare scalar (template expression like `${{ parameters.X }}`) —
        // can't statically enumerate; treat as absent.
        fn visit_str<E: serde::de::Error>(self, _v: &str) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_string<E: serde::de::Error>(self, _v: String) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_bool<E: serde::de::Error>(self, _v: bool) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_i64<E: serde::de::Error>(self, _v: i64) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_u64<E: serde::de::Error>(self, _v: u64) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_f64<E: serde::de::Error>(self, _v: f64) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(item) = seq.next_element::<serde_yaml::Value>()? {
                if let Ok(p) = serde_yaml::from_value::<AdoParameter>(item) {
                    out.push(p);
                }
            }
            Ok(Some(out))
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            // Legacy untyped map form: name → default-value. We collect
            // names; defaults are intentionally discarded (matches typed-
            // form semantics where `default:` is also ignored).
            let mut out = Vec::new();
            while let Some(key) = map.next_key::<serde_yaml::Value>()? {
                let _ignore = map.next_value::<serde::de::IgnoredAny>()?;
                let name = match key {
                    serde_yaml::Value::String(s) if !s.is_empty() => s,
                    _ => continue,
                };
                out.push(AdoParameter {
                    name: Some(name),
                    param_type: None,
                    values: None,
                });
            }
            Ok(Some(out))
        }
    }

    deserializer.deserialize_any(ParamsVisitor)
}

/// Accept either an `AdoResources` mapping (modern form with `repositories:`,
/// `containers:`, `pipelines:`) or the legacy sequence form (`resources: [-
/// repo: self]`, pre-2019 ADO syntax). The legacy form has no
/// `repositories:` key, so we return an empty `AdoResources` for it — the
/// repository-tracking rules then see no aliases to track, which is correct
/// (legacy `repo: self` declares no external repositories).
fn deserialize_optional_resources<'de, D>(deserializer: D) -> Result<Option<AdoResources>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{MapAccess, SeqAccess, Visitor};
    use std::fmt;

    struct ResourcesVisitor;

    impl<'de> Visitor<'de> for ResourcesVisitor {
        type Value = Option<AdoResources>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an AdoResources mapping or a legacy `- repo:` sequence")
        }

        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_any(self)
        }

        // Legacy sequence form — drain it without producing any
        // repository entries. Modern rules track aliases via the
        // `AdoResources.repositories[]` shape, which the legacy form
        // does not produce.
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
            Ok(Some(AdoResources::default()))
        }

        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            let r = AdoResources::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
            Ok(Some(r))
        }
    }

    deserializer.deserialize_any(ResourcesVisitor)
}

/// Accept either a sequence of `AdoStage` (the normal form) or a bare
/// template expression (`stages: ${{ parameters.stages }}`) which resolves
/// at runtime. For the template-expression case, return `None` so the
/// pipeline still parses; the graph will simply contain no stages from this
/// scope (downstream code already handles empty stage lists).
fn deserialize_optional_stages<'de, D>(deserializer: D) -> Result<Option<Vec<AdoStage>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{SeqAccess, Visitor};
    use std::fmt;

    struct StagesVisitor;

    impl<'de> Visitor<'de> for StagesVisitor {
        type Value = Option<Vec<AdoStage>>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a sequence of stages or a template expression")
        }

        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_any(self)
        }
        fn visit_str<E: serde::de::Error>(self, _v: &str) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_string<E: serde::de::Error>(self, _v: String) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
            let stages =
                Vec::<AdoStage>::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))?;
            Ok(Some(stages))
        }
    }

    deserializer.deserialize_any(StagesVisitor)
}

/// `resources:` block. Only `repositories[]` is modelled today.
#[derive(Debug, Default, Deserialize)]
pub struct AdoResources {
    #[serde(default)]
    pub repositories: Vec<AdoRepository>,
}

/// A single `resources.repositories[]` entry — declares an external repo
/// alias the pipeline can consume via `template: x@alias`, `extends:`, or
/// `checkout: alias`.
#[derive(Debug, Deserialize)]
pub struct AdoRepository {
    /// The alias used by consumers (`template: file@<repository>`).
    pub repository: String,
    /// `git`, `github`, `bitbucket`, or `azureGit`.
    #[serde(default, rename = "type")]
    pub repo_type: Option<String>,
    /// Full repo path (e.g. `org/repo`).
    #[serde(default)]
    pub name: Option<String>,
    /// Optional ref. Absent = default branch (mutable). Present forms:
    /// `refs/tags/v1.2.3`, `refs/heads/main`, bare branch `main`, or a SHA.
    #[serde(default, rename = "ref")]
    pub git_ref: Option<String>,
}

/// Pipeline / template `parameters:` entry. We deliberately ignore `default:`
/// — only the name, type, and `values:` allowlist matter for our rules.
#[derive(Debug, Deserialize)]
pub struct AdoParameter {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(rename = "type", default)]
    pub param_type: Option<String>,
    #[serde(default)]
    pub values: Option<Vec<serde_yaml::Value>>,
}

/// ADO `dependsOn:` accepts two YAML shapes — a single string
/// (`dependsOn: my_job`) or a sequence of strings
/// (`dependsOn: [a, b, c]`). The untagged enum normalises both at
/// deserialization time so callers can iterate uniformly.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum DependsOn {
    Single(String),
    Multiple(Vec<String>),
}

impl DependsOn {
    /// Comma-joined predecessor list suitable for stamping into
    /// `META_DEPENDS_ON` on a Step node. Empty entries are dropped.
    pub fn as_csv(&self) -> String {
        match self {
            DependsOn::Single(s) => s.trim().to_string(),
            DependsOn::Multiple(v) => v
                .iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(","),
        }
    }
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
    /// Stage-level runtime gate. ADO evaluates this expression at queue time;
    /// when false, every job (and therefore every step) inside the stage is
    /// skipped. The parser cannot evaluate the expression statically, so its
    /// presence is recorded as a Partial-Expression gap and its text is stamped
    /// onto child Step nodes via `META_CONDITION`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    /// Stage-level explicit `dependsOn:`. Default behaviour is "depends on the
    /// previous stage" — only the explicit form is captured.
    #[serde(rename = "dependsOn", default, skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<DependsOn>,
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
    /// Deployment-job nested strategy: runOnce/rolling/canary all share the
    /// shape `strategy.{runOnce,rolling,canary}.deploy.steps`. We only need
    /// the steps — the strategy choice itself doesn't change authority flow.
    #[serde(default)]
    pub strategy: Option<AdoStrategy>,
    #[serde(default)]
    pub pool: Option<serde_yaml::Value>,
    /// Job-level `workspace:` block. The only security-relevant field is
    /// `clean:` which causes the agent to wipe the workspace between runs.
    #[serde(default)]
    pub workspace: Option<serde_yaml::Value>,
    /// Job-level template reference
    #[serde(default)]
    pub template: Option<String>,
    /// Deployment-job environment binding. Two YAML shapes:
    ///
    ///   - `environment: production` (string shorthand)
    ///   - `environment: { name: staging, resourceType: VirtualMachine }` (mapping)
    ///
    /// When present, the environment may have approvals/checks attached in ADO's
    /// environment configuration. Approvals are a manual gate — authority cannot
    /// propagate past one without human intervention. We treat any `environment:`
    /// binding as an approval candidate and tag the job's steps so propagation
    /// rules can downgrade severity. (We can't see the approval config from YAML
    /// alone; the binding is the strongest signal available at parse time.)
    #[serde(default)]
    pub environment: Option<serde_yaml::Value>,
    /// Job-level runtime gate. Evaluated at job-queue time; controls whether
    /// the job's steps run. Cannot be statically evaluated — recorded as a
    /// Partial-Expression gap and stamped onto the job's Step nodes via
    /// `META_CONDITION` (joined with any stage-level condition).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    /// Job-level explicit `dependsOn:`. Default behaviour is "depends on the
    /// previous job" — only the explicit form is captured.
    #[serde(rename = "dependsOn", default, skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<DependsOn>,
}

impl AdoJob {
    pub fn effective_name(&self) -> String {
        self.job
            .as_deref()
            .or(self.deployment.as_deref())
            .unwrap_or("job")
            .to_string()
    }

    /// Returns the effective step list for this job.
    ///
    /// Regular jobs put steps under `steps:` directly. Deployment jobs nest
    /// them under `strategy.{runOnce,rolling,canary}.{deploy,preDeploy,
    /// postDeploy,routeTraffic,onSuccess,onFailure}.steps`. We merge all
    /// strategy-nested step lists into a single sequence so downstream rules
    /// see them as part of the job. Order: regular `steps:` first, then any
    /// strategy-nested steps in deterministic phase order.
    pub fn all_steps(&self) -> Vec<AdoStep> {
        let mut out: Vec<AdoStep> = Vec::new();
        if let Some(ref s) = self.steps {
            out.extend(s.iter().cloned());
        }
        if let Some(ref strat) = self.strategy {
            for phase in strat.phases() {
                if let Some(ref s) = phase.steps {
                    out.extend(s.iter().cloned());
                }
            }
        }
        out
    }

    /// Returns true when the job is bound to an `environment:` — either the
    /// string form (`environment: production`) or the mapping form with a
    /// non-empty `name:` field. An empty mapping or empty string is ignored.
    pub fn has_environment_binding(&self) -> bool {
        match self.environment.as_ref() {
            None => false,
            Some(serde_yaml::Value::String(s)) => !s.trim().is_empty(),
            Some(serde_yaml::Value::Mapping(m)) => m
                .get("name")
                .and_then(|v| v.as_str())
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false),
            _ => false,
        }
    }
}

/// Deployment-job `strategy:` block. ADO ships three strategies — runOnce,
/// rolling, canary — each with multiple lifecycle phases that may carry
/// their own step list. We capture all of them; the AdoJob::all_steps
/// helper flattens them into one sequence.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct AdoStrategy {
    #[serde(default, rename = "runOnce")]
    pub run_once: Option<AdoStrategyRunOnce>,
    #[serde(default)]
    pub rolling: Option<AdoStrategyRunOnce>,
    #[serde(default)]
    pub canary: Option<AdoStrategyRunOnce>,
}

impl AdoStrategy {
    /// Iterate over every populated lifecycle phase across all strategies.
    pub fn phases(&self) -> Vec<&AdoStrategyPhase> {
        let mut out: Vec<&AdoStrategyPhase> = Vec::new();
        for runner in [&self.run_once, &self.rolling, &self.canary]
            .iter()
            .copied()
            .flatten()
        {
            for phase in [
                &runner.deploy,
                &runner.pre_deploy,
                &runner.post_deploy,
                &runner.route_traffic,
            ]
            .into_iter()
            .flatten()
            {
                out.push(phase);
            }
            if let Some(ref on) = runner.on {
                if let Some(ref s) = on.success {
                    out.push(s);
                }
                if let Some(ref f) = on.failure {
                    out.push(f);
                }
            }
        }
        out
    }
}

/// Lifecycle phases carried by every deployment strategy. Each phase may
/// have its own `steps:`. Covering all six avoids silently dropping
/// privileged setup/teardown steps from the authority graph.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct AdoStrategyRunOnce {
    #[serde(default)]
    pub deploy: Option<AdoStrategyPhase>,
    #[serde(default, rename = "preDeploy")]
    pub pre_deploy: Option<AdoStrategyPhase>,
    #[serde(default, rename = "postDeploy")]
    pub post_deploy: Option<AdoStrategyPhase>,
    #[serde(default, rename = "routeTraffic")]
    pub route_traffic: Option<AdoStrategyPhase>,
    #[serde(default)]
    pub on: Option<AdoStrategyOn>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct AdoStrategyOn {
    #[serde(default)]
    pub success: Option<AdoStrategyPhase>,
    #[serde(default)]
    pub failure: Option<AdoStrategyPhase>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct AdoStrategyPhase {
    #[serde(default)]
    pub steps: Option<Vec<AdoStep>>,
}

#[derive(Debug, Deserialize, Clone)]
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
    /// Step-level runtime gate. Evaluated by the agent before it dispatches
    /// the step; when false the step is skipped (status: Skipped). Cannot be
    /// statically evaluated — recorded as a Partial-Expression gap and stamped
    /// onto the Step node via `META_CONDITION`, joined with any
    /// stage/job-level conditions stacked above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    /// Step-level explicit `dependsOn:`. Rare on individual steps (more common
    /// at job/stage level) but accepted by ADO; captured for symmetry.
    #[serde(rename = "dependsOn", default, skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<DependsOn>,
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

/// Heuristic: does this YAML have a top-level parameter conditional wrapper
/// (e.g. `- ${{ if eq(parameters.X, true) }}:`) at column 0 or as the first
/// list item? This is the construct that breaks root-level mapping parses but
/// is valid in an ADO template fragment included by a parent pipeline.
fn has_root_parameter_conditional(content: &str) -> bool {
    for line in content.lines() {
        let trimmed = line.trim_start();
        // Strip an optional leading list marker so we match both
        // `- ${{ if ... }}:` and bare `${{ if ... }}:` forms.
        let candidate = trimmed.strip_prefix("- ").unwrap_or(trimmed);
        if candidate.starts_with("${{")
            && (candidate.contains("if ") || candidate.contains("if("))
            && candidate.trim_end().ends_with(":")
        {
            return true;
        }
    }
    false
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
            commit_sha: None,
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
        // External variable group is unresolvable without ADO API access —
        // that's a Structural break in the authority chain, not an expression
        // substitution.
        assert!(
            graph.completeness_gap_kinds.contains(&GapKind::Structural),
            "variable group gap must be Structural, got: {:?}",
            graph.completeness_gap_kinds
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
    fn service_connection_does_not_get_unconditional_oidc_tag() {
        let yaml = r#"
steps:
  - task: AzureCLI@2
    displayName: Deploy to Azure
    inputs:
      azureSubscription: MyClassicSpnConnection
      scriptType: bash
      inlineScript: az group list
"#;
        let graph = parse(yaml);
        let conn = graph
            .nodes_of_kind(NodeKind::Identity)
            .find(|i| i.name == "MyClassicSpnConnection")
            .expect("service connection identity should exist");
        assert_eq!(
            conn.metadata.get(META_OIDC),
            None,
            "service connections must not be tagged META_OIDC without a clear OIDC signal"
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

    #[test]
    fn environment_key_tags_job_with_env_approval() {
        // String form: `environment: production`
        let yaml_string_form = r#"
jobs:
  - deployment: DeployWeb
    environment: production
    steps:
      - script: echo deploying
        displayName: Deploy
"#;
        let g1 = parse(yaml_string_form);
        let tagged: Vec<_> = g1
            .nodes_of_kind(NodeKind::Step)
            .filter(|s| s.metadata.get(META_ENV_APPROVAL) == Some(&"true".to_string()))
            .collect();
        assert!(
            !tagged.is_empty(),
            "string-form `environment:` must tag job's step nodes with META_ENV_APPROVAL"
        );

        // Mapping form: `environment: { name: staging }`
        let yaml_mapping_form = r#"
jobs:
  - deployment: DeployAPI
    environment:
      name: staging
      resourceType: VirtualMachine
    steps:
      - script: echo deploying
        displayName: Deploy
"#;
        let g2 = parse(yaml_mapping_form);
        let tagged2: Vec<_> = g2
            .nodes_of_kind(NodeKind::Step)
            .filter(|s| s.metadata.get(META_ENV_APPROVAL) == Some(&"true".to_string()))
            .collect();
        assert!(
            !tagged2.is_empty(),
            "mapping-form `environment: {{ name: ... }}` must tag job's step nodes"
        );

        // Negative: a job with no `environment:` must not be tagged
        let yaml_no_env = r#"
jobs:
  - job: Build
    steps:
      - script: echo building
"#;
        let g3 = parse(yaml_no_env);
        let any_tagged = g3
            .nodes_of_kind(NodeKind::Step)
            .any(|s| s.metadata.contains_key(META_ENV_APPROVAL));
        assert!(
            !any_tagged,
            "jobs without `environment:` must not carry META_ENV_APPROVAL"
        );
    }

    #[test]
    fn root_parameter_conditional_template_fragment_does_not_crash_and_marks_partial() {
        // Real-world repro: an ADO template fragment whose root content is wrapped
        // in a parameter conditional (`- ${{ if eq(parameters.X, true) }}:`) followed
        // by a list of jobs. This is valid when `template:`-included from a parent
        // pipeline, but parsing it standalone fails with "did not find expected key".
        // The parser must now return a Partial graph instead of a fatal error.
        let yaml = r#"
parameters:
  msabs_ws2022: false

- ${{ if eq(parameters.msabs_ws2022, true) }}:
  - job: packer_ws2022
    displayName: Build WS2022 Gold Image
    steps:
      - task: PackerTool@0
"#;
        let parser = AdoParser;
        let source = PipelineSource {
            file: "fragment.yml".into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        };
        let result = parser.parse(yaml, &source);
        let graph = result.expect("template fragment must not crash the parser");
        assert!(
            matches!(graph.completeness, AuthorityCompleteness::Partial),
            "template-fragment graph must be marked Partial"
        );
        let saw_fragment_gap = graph
            .completeness_gaps
            .iter()
            .any(|g| g.contains("template fragment") && g.contains("parent pipeline"));
        assert!(
            saw_fragment_gap,
            "completeness_gaps must mention the template-fragment reason, got: {:?}",
            graph.completeness_gaps
        );
        // A template fragment's root structure depends on the parent pipeline
        // — this is a Structural break, not a missing expression value.
        assert_eq!(
            graph.completeness_gap_kinds.len(),
            1,
            "template-fragment graph should record exactly one gap kind"
        );
        assert_eq!(graph.completeness_gap_kinds[0], GapKind::Structural);
    }

    #[test]
    fn environment_tag_isolated_to_gated_job_only() {
        // Two jobs side by side: only the deployment job has environment.
        // Steps from the non-gated job must NOT be tagged.
        let yaml = r#"
jobs:
  - job: Build
    steps:
      - script: echo build
        displayName: build-step
  - deployment: DeployProd
    environment: production
    steps:
      - script: echo deploy
        displayName: deploy-step
"#;
        let g = parse(yaml);
        let build_step = g
            .nodes_of_kind(NodeKind::Step)
            .find(|s| s.name == "build-step")
            .expect("build-step must exist");
        let deploy_step = g
            .nodes_of_kind(NodeKind::Step)
            .find(|s| s.name == "deploy-step")
            .expect("deploy-step must exist");
        assert!(
            !build_step.metadata.contains_key(META_ENV_APPROVAL),
            "non-gated job's step must not be tagged"
        );
        assert_eq!(
            deploy_step.metadata.get(META_ENV_APPROVAL),
            Some(&"true".to_string()),
            "gated deployment job's step must be tagged"
        );
    }

    // ── resources.repositories[] capture ──────────────────────

    fn repos_meta(graph: &AuthorityGraph) -> Vec<serde_json::Value> {
        let raw = graph
            .metadata
            .get(META_REPOSITORIES)
            .expect("META_REPOSITORIES must be set");
        serde_json::from_str(raw).expect("META_REPOSITORIES must be valid JSON")
    }

    #[test]
    fn resources_repositories_captured_with_used_flag_when_referenced_by_extends() {
        let yaml = r#"
resources:
  repositories:
    - repository: shared-templates
      type: git
      name: Platform/shared-templates
      ref: refs/heads/main

extends:
  template: pipeline.yml@shared-templates
"#;
        let graph = parse(yaml);
        let entries = repos_meta(&graph);
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e["alias"], "shared-templates");
        assert_eq!(e["repo_type"], "git");
        assert_eq!(e["name"], "Platform/shared-templates");
        assert_eq!(e["ref"], "refs/heads/main");
        assert_eq!(e["used"], true);
    }

    #[test]
    fn resources_repositories_used_via_checkout_alias() {
        // Mirrors the msigeurope-adf-finance-reporting corpus shape.
        let yaml = r#"
resources:
  repositories:
    - repository: adf_publish
      type: git
      name: org/adf-finance-reporting
      ref: refs/heads/adf_publish

jobs:
  - job: deploy
    steps:
      - checkout: adf_publish
"#;
        let graph = parse(yaml);
        let entries = repos_meta(&graph);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["alias"], "adf_publish");
        assert_eq!(entries[0]["used"], true);
    }

    #[test]
    fn resources_repositories_unreferenced_alias_is_marked_not_used() {
        // Declared but no `template: x@alias`, no `checkout: alias`, no extends.
        let yaml = r#"
resources:
  repositories:
    - repository: orphan-templates
      type: git
      name: Platform/orphan
      ref: main

jobs:
  - job: build
    steps:
      - script: echo hi
"#;
        let graph = parse(yaml);
        let entries = repos_meta(&graph);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["alias"], "orphan-templates");
        assert_eq!(entries[0]["used"], false);
    }

    #[test]
    fn resources_repositories_absent_when_no_resources_block() {
        let yaml = r#"
jobs:
  - job: build
    steps:
      - script: echo hi
"#;
        let graph = parse(yaml);
        assert!(!graph.metadata.contains_key(META_REPOSITORIES));
    }

    #[test]
    fn parse_template_alias_extracts_segment_after_at() {
        assert_eq!(
            parse_template_alias("steps/deploy.yml@templates"),
            Some("templates".to_string())
        );
        assert_eq!(parse_template_alias("local/path.yml"), None);
        assert_eq!(parse_template_alias("path@"), None);
    }

    #[test]
    fn parameters_as_map_form_parses_as_named_parameters() {
        // Real-world repro from Azure/aks-engine, PowerShell/PowerShell, dotnet/maui:
        // legacy template fragments declare `parameters:` as a mapping of
        // name → default-value rather than the modern typed sequence form.
        // Both shapes must parse; the map form yields parameters with names
        // but no type/values allowlist (so they default to "string" downstream).
        let yaml = r#"
parameters:
  name: ''
  k8sRelease: ''
  apimodel: 'examples/e2e-tests/kubernetes/release/default/definition.json'
  createVNET: false

jobs:
  - job: build
    steps:
      - script: echo $(name)
"#;
        let graph = parse(yaml);
        // Parse must succeed and capture the four parameter names.
        assert!(graph.parameters.contains_key("name"));
        assert!(graph.parameters.contains_key("k8sRelease"));
        assert!(graph.parameters.contains_key("apimodel"));
        assert!(graph.parameters.contains_key("createVNET"));
        assert_eq!(graph.parameters.len(), 4);
    }

    #[test]
    fn parameters_as_typed_sequence_form_still_parses() {
        // Make sure the modern form still works after the polymorphic
        // deserializer change.
        let yaml = r#"
parameters:
  - name: env
    type: string
    default: prod
    values:
      - prod
      - staging
  - name: skipTests
    type: boolean
    default: false

jobs:
  - job: build
    steps:
      - script: echo hi
"#;
        let graph = parse(yaml);
        let env_param = graph.parameters.get("env").expect("env captured");
        assert_eq!(env_param.param_type, "string");
        assert!(env_param.has_values_allowlist);
        let skip_param = graph
            .parameters
            .get("skipTests")
            .expect("skipTests captured");
        assert_eq!(skip_param.param_type, "boolean");
        assert!(!skip_param.has_values_allowlist);
    }

    #[test]
    fn resources_as_legacy_sequence_form_parses_to_empty_resources() {
        // Real-world repro from Azure/azure-cli, Chinachu/Mirakurun: pre-2019
        // ADO syntax allows `resources:` as a list of `- repo: self` entries,
        // not the modern `resources: { repositories: [...] }` mapping. Modern
        // ADO still tolerates the legacy form. We must accept both shapes
        // without crashing the parse.
        let yaml = r#"
resources:
- repo: self

trigger:
  - main

jobs:
  - job: build
    steps:
      - script: echo hi
"#;
        let graph = parse(yaml);
        // No external repositories declared (legacy form has none) — so the
        // META_REPOSITORIES metadata key is absent.
        assert!(!graph.metadata.contains_key(META_REPOSITORIES));
        // But the job still parses.
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 1);
    }

    #[test]
    fn stages_as_template_expression_parses_with_no_stages() {
        // Real-world repro from dotnet/diagnostics templatePublic.yml:
        // `stages: ${{ parameters.stages }}` resolves at runtime. The static
        // parser cannot enumerate stages from a template expression — we
        // accept the file without crashing and the resulting graph simply
        // contains no stages from the template-expression scope.
        let yaml = r#"
parameters:
  - name: stages
    type: stageList

stages: ${{ parameters.stages }}
"#;
        let graph = parse(yaml);
        // Graph must exist (no crash).
        assert!(graph.parameters.contains_key("stages"));
    }

    // ── Cross-platform misclassification trap (red-team R2 #5) ─────

    #[test]
    fn jobs_carrier_without_steps_marks_partial() {
        // ADO `jobs:` carrier present but each job has no `steps:` and no
        // `template:`. process_steps([]) adds nothing. Result: 0 Step nodes
        // despite a non-empty job carrier — must mark Partial so a CI gate
        // doesn't treat completeness=complete + 0 findings as "passed".
        let yaml = r#"
jobs:
  - job: build
    pool:
      vmImage: ubuntu-latest
"#;
        let graph = parse(yaml);
        let step_count = graph
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Step)
            .count();
        assert_eq!(step_count, 0);
        assert_eq!(graph.completeness, AuthorityCompleteness::Partial);
        assert!(
            graph
                .completeness_gaps
                .iter()
                .any(|g| g.contains("0 step nodes")),
            "completeness_gaps must mention 0 step nodes: {:?}",
            graph.completeness_gaps
        );
        // A jobs/steps carrier that yields zero step nodes is a Structural
        // break — the authority chain stops mid-graph rather than hiding a
        // value behind an expression.
        assert!(
            graph.completeness_gap_kinds.contains(&GapKind::Structural),
            "0-step-nodes gap must be Structural, got: {:?}",
            graph.completeness_gap_kinds
        );
    }

    #[test]
    fn jobs_carrier_with_empty_jobs_list_does_not_mark_partial() {
        // Defensive: an empty `jobs:` list is NOT a carrier — there is no
        // job content to be confused about. Stays Complete.
        let yaml = r#"
jobs: []
"#;
        let graph = parse(yaml);
        let zero_step_gap = graph
            .completeness_gaps
            .iter()
            .any(|g| g.contains("0 step nodes"));
        assert!(
            !zero_step_gap,
            "empty jobs: list is not a carrier; got: {:?}",
            graph.completeness_gaps
        );
    }

    // ── Bug regression: pr: none not suppressing PR-specific rules ──────────

    #[test]
    fn pr_none_does_not_set_meta_trigger() {
        // `pr: none` is an explicit opt-out. Parser must require a mapping or
        // sequence for a real PR trigger; scalars are all opt-outs.
        let yaml = r#"
schedules:
  - cron: "0 5 * * 1"
pr: none
trigger: none
steps:
  - script: echo hello
"#;
        let graph = parse(yaml);
        assert!(
            !graph.metadata.contains_key(META_TRIGGER),
            "pr: none must not set META_TRIGGER; got: {:?}",
            graph.metadata.get(META_TRIGGER)
        );
    }

    #[test]
    fn pr_tilde_does_not_set_meta_trigger() {
        // `pr: ~` is YAML null written as tilde — also an opt-out.
        let yaml = "pr: ~\nsteps:\n  - script: echo hello\n";
        let graph = parse(yaml);
        assert!(
            !graph.metadata.contains_key(META_TRIGGER),
            "pr: ~ must not set META_TRIGGER; got: {:?}",
            graph.metadata.get(META_TRIGGER)
        );
    }

    #[test]
    fn pr_false_does_not_set_meta_trigger() {
        // `pr: false` — boolean false means disabled.
        let yaml = "pr: false\nsteps:\n  - script: echo hello\n";
        let graph = parse(yaml);
        assert!(
            !graph.metadata.contains_key(META_TRIGGER),
            "pr: false must not set META_TRIGGER; got: {:?}",
            graph.metadata.get(META_TRIGGER)
        );
    }

    #[test]
    fn pr_sequence_sets_meta_trigger() {
        // Shorthand sequence form: `pr:\n  - main` is also a real PR trigger.
        let yaml = "pr:\n  - main\nsteps:\n  - script: echo hello\n";
        let graph = parse(yaml);
        assert_eq!(
            graph.metadata.get(META_TRIGGER).map(|s| s.as_str()),
            Some("pr"),
            "pr: [main] must set META_TRIGGER=pr"
        );
    }

    #[test]
    fn pr_with_branches_sets_meta_trigger() {
        // Positive guard: a real PR trigger mapping must still set META_TRIGGER.
        let yaml = r#"
pr:
  branches:
    include:
      - main
steps:
  - script: echo hello
"#;
        let graph = parse(yaml);
        assert_eq!(
            graph.metadata.get(META_TRIGGER).map(|s| s.as_str()),
            Some("pr"),
            "real pr: block must set META_TRIGGER=pr"
        );
    }

    // ── Bug regression: permissions: contents: none parsed as empty string ──
    // E2E test: parser → rule — the only test that catches the full chain.

    #[test]
    fn over_privileged_identity_does_not_fire_when_permissions_contents_none() {
        // Full chain: ADO parser + over_privileged_identity rule.
        // Previously the parser ignored `permissions:`, leaving the token at
        // broad scope and firing the rule on every restricted pipeline.
        use taudit_core::rules::over_privileged_identity;
        let yaml = r#"
trigger: none
permissions:
  contents: none
steps:
  - script: echo hello
"#;
        let graph = parse(yaml);
        let findings = over_privileged_identity(&graph);
        let token_findings: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.nodes_involved.iter().any(|&id| {
                    graph
                        .node(id)
                        .map(|n| n.name == "System.AccessToken")
                        .unwrap_or(false)
                })
            })
            .collect();
        assert!(
            token_findings.is_empty(),
            "over_privileged_identity must not fire on System.AccessToken when \
             permissions: contents: none is set; got: {token_findings:#?}"
        );
    }

    #[test]
    fn pipeline_level_permissions_none_constrains_token() {
        // `permissions: contents: none` at pipeline level must downgrade
        // System.AccessToken from broad → constrained so over_privileged_identity
        // does not fire on an already-locked-down pipeline.
        let yaml = r#"
trigger: none
permissions:
  contents: none
steps:
  - script: echo hello
"#;
        let graph = parse(yaml);
        let token = graph
            .nodes_of_kind(NodeKind::Identity)
            .find(|n| n.name == "System.AccessToken")
            .expect("System.AccessToken must always be present");
        assert_eq!(
            token.metadata.get(META_IDENTITY_SCOPE).map(|s| s.as_str()),
            Some("constrained"),
            "permissions: contents: none must constrain the token; got: {:?}",
            token.metadata.get(META_IDENTITY_SCOPE)
        );
    }

    #[test]
    fn pipeline_level_permissions_write_keeps_token_broad() {
        // A pipeline with write permissions must keep System.AccessToken broad.
        let yaml = r#"
trigger: none
permissions:
  contents: write
steps:
  - script: echo hello
"#;
        let graph = parse(yaml);
        let token = graph
            .nodes_of_kind(NodeKind::Identity)
            .find(|n| n.name == "System.AccessToken")
            .expect("System.AccessToken must always be present");
        assert_eq!(
            token.metadata.get(META_IDENTITY_SCOPE).map(|s| s.as_str()),
            Some("broad"),
            "permissions: contents: write must keep the token broad; got: {:?}",
            token.metadata.get(META_IDENTITY_SCOPE)
        );
    }

    #[test]
    fn pipeline_level_permissions_read_scalar_constrains_token() {
        // `permissions: read` (scalar, not a map) must also downgrade the token.
        // Previously the scalar branch treated "read" as broad (incorrect).
        let yaml = "trigger: none\npermissions: read\nsteps:\n  - script: echo hello\n";
        let graph = parse(yaml);
        let token = graph
            .nodes_of_kind(NodeKind::Identity)
            .find(|n| n.name == "System.AccessToken")
            .expect("System.AccessToken must always be present");
        assert_eq!(
            token.metadata.get(META_IDENTITY_SCOPE).map(|s| s.as_str()),
            Some("constrained"),
            "permissions: read must constrain the token; got: {:?}",
            token.metadata.get(META_IDENTITY_SCOPE)
        );
    }

    #[test]
    fn pipeline_level_permissions_write_scalar_keeps_token_broad() {
        // `permissions: write` (scalar) keeps the token broad.
        let yaml = "trigger: none\npermissions: write\nsteps:\n  - script: echo hello\n";
        let graph = parse(yaml);
        let token = graph
            .nodes_of_kind(NodeKind::Identity)
            .find(|n| n.name == "System.AccessToken")
            .expect("System.AccessToken must always be present");
        assert_eq!(
            token.metadata.get(META_IDENTITY_SCOPE).map(|s| s.as_str()),
            Some("broad"),
            "permissions: write scalar must keep token broad; got: {:?}",
            token.metadata.get(META_IDENTITY_SCOPE)
        );
    }

    #[test]
    fn pipeline_level_permissions_contents_read_constrains_token() {
        // Map form with contents: read — should constrain.
        let yaml =
            "trigger: none\npermissions:\n  contents: read\nsteps:\n  - script: echo hello\n";
        let graph = parse(yaml);
        let token = graph
            .nodes_of_kind(NodeKind::Identity)
            .find(|n| n.name == "System.AccessToken")
            .expect("System.AccessToken must always be present");
        assert_eq!(
            token.metadata.get(META_IDENTITY_SCOPE).map(|s| s.as_str()),
            Some("constrained"),
            "permissions: contents: read must constrain; got: {:?}",
            token.metadata.get(META_IDENTITY_SCOPE)
        );
    }

    #[test]
    fn empty_pipeline_does_not_mark_partial_for_zero_steps() {
        // No top-level stages/jobs/steps at all — there's no carrier, so the
        // 0-step-nodes guard must NOT fire. A genuinely empty pipeline stays
        // Complete.
        let yaml = r#"
trigger:
  - main
"#;
        let graph = parse(yaml);
        let zero_step_gap = graph
            .completeness_gaps
            .iter()
            .any(|g| g.contains("0 step nodes"));
        assert!(
            !zero_step_gap,
            "no carrier means no 0-step gap reason; got: {:?}",
            graph.completeness_gaps
        );
    }

    /// regression: ADO HashMap iteration must be deterministic across runs.
    ///
    /// Before the fix, `step.env` and `step.inputs` (both `HashMap`s populated
    /// by serde_yaml) were iterated in HashMap-random order at four call sites
    /// in `taudit-parse-ado`. That randomness leaked into `NodeId` allocation
    /// (Secret/Identity nodes get IDs in the order they're added) and edge
    /// append order, which then leaked into `pipeline_identity_material_hash`
    /// and silently broke baseline suppression — same YAML, different hash on
    /// each run.
    ///
    /// Fixture uses non-alphabetic-insertion-order keys (`Z_VAR/A_VAR/M_VAR/...`)
    /// so the pre-fix HashMap bucket ordering is overwhelmingly unlikely to
    /// align with the now-enforced sorted iteration. We parse the same YAML
    /// nine times in sequence and assert that
    /// `compute_pipeline_identity_material_hash` is byte-identical across all
    /// runs. Mirrors `taudit-report-json`'s
    /// `json_output_is_byte_deterministic_across_runs` test pattern.
    #[test]
    fn ado_hashmap_iteration_is_deterministic_across_runs() {
        // Multiple `$(VAR)` references in both `env:` and task `inputs:` so
        // every secret-creating HashMap-iteration site in the parser is
        // exercised. Names chosen so HashMap hash bucket order has near-zero
        // chance of accidentally aligning with the enforced sorted order.
        let yaml = r#"
trigger:
  - main

pool:
  vmImage: ubuntu-latest

steps:
  - task: AzureCLI@2
    displayName: Deploy
    inputs:
      azureSubscription: $(SUB_CONN)
      scriptType: bash
      inlineScript: |
        echo $(MIDDLE_INPUT_VAR)
        echo $(ALPHA_INPUT_VAR)
        echo $(ZULU_INPUT_VAR)
    env:
      Z_VAR: $(Z_SECRET)
      A_VAR: $(A_SECRET)
      M_VAR: $(M_SECRET)
      Q_VAR: $(Q_SECRET)
      B_VAR: $(B_SECRET)
"#;

        // Capture the structural shape of the graph that the bug report
        // identified as drifting: NodeId allocation order (id, kind, name,
        // trust_zone) and edge append order ((from, to, kind)). We
        // intentionally exclude `node.metadata` from the comparison — that
        // map's serialisation is a separate concern handled by the JSON sink
        // (see `taudit-report-json::json_output_is_byte_deterministic_across_runs`).
        fn structural_fingerprint(graph: &taudit_core::graph::AuthorityGraph) -> String {
            let mut out = String::new();
            for n in &graph.nodes {
                out.push_str(&format!(
                    "N {} {:?} {} {:?}\n",
                    n.id, n.kind, n.name, n.trust_zone
                ));
            }
            for e in &graph.edges {
                out.push_str(&format!("E {} {} {:?}\n", e.from, e.to, e.kind));
            }
            out
        }

        let mut hashes: Vec<String> = Vec::with_capacity(9);
        let mut fingerprints: Vec<String> = Vec::with_capacity(9);
        for _ in 0..9 {
            let graph = parse(yaml);
            hashes.push(taudit_core::baselines::compute_pipeline_identity_material_hash(&graph));
            fingerprints.push(structural_fingerprint(&graph));
        }

        let first_hash = &hashes[0];
        for (i, h) in hashes.iter().enumerate().skip(1) {
            assert_eq!(
                first_hash, h,
                "run 0 and run {i} produced different pipeline_identity_material_hash \
                 — ADO parser HashMap iteration is non-deterministic"
            );
        }

        let first_fp = &fingerprints[0];
        for (i, fp) in fingerprints.iter().enumerate().skip(1) {
            assert_eq!(
                first_fp, fp,
                "run 0 and run {i} produced different graph node-id / edge ordering \
                 — ADO parser HashMap iteration is non-deterministic"
            );
        }
    }

    // ── condition: / dependsOn: modelling (RC blocker A) ─────────────────────
    //
    // The ADO parser previously ignored stage / job / step `condition:` and
    // `dependsOn:` keys entirely, which made `apply_compensating_controls`
    // unable to credit conditional runtime gates and caused
    // `trigger_context_mismatch`-class rules to fire at full severity on
    // jobs the runtime would never execute on a PR build (deep audit
    // 02-ado-parser.md, finding 10).

    #[test]
    fn step_condition_marks_partial_with_expression_gap() {
        let yaml = r#"
steps:
  - script: deploy.sh
    displayName: Deploy
    condition: eq(variables['Build.SourceBranch'], 'refs/heads/main')
"#;
        let graph = parse(yaml);
        assert_eq!(graph.completeness, AuthorityCompleteness::Partial);
        assert!(
            graph.completeness_gap_kinds.contains(&GapKind::Expression),
            "step condition must produce an Expression gap, got: {:?}",
            graph.completeness_gap_kinds
        );
        // Reason text must cite the conditional so an operator can grep
        // findings against the source pipeline's `condition:` clauses.
        assert!(
            graph.completeness_gaps.iter().any(|g| g.contains("step")
                && g.contains("Deploy")
                && g.contains("eq(variables['Build.SourceBranch']")),
            "gap reason must name scope, step, and condition: {:?}",
            graph.completeness_gaps
        );
    }

    #[test]
    fn job_condition_propagates_to_step_metadata() {
        let yaml = r#"
jobs:
  - job: DeployProd
    condition: eq(variables['Build.SourceBranch'], 'refs/heads/main')
    steps:
      - script: deploy.sh
        displayName: Run deploy
"#;
        let graph = parse(yaml);
        let step = graph
            .nodes_of_kind(NodeKind::Step)
            .find(|n| n.name == "Run deploy")
            .expect("step node must exist");
        // No step-level condition was declared, so META_CONDITION carries
        // ONLY the job-level expression — verbatim, no ` AND ` joiner.
        assert_eq!(
            step.metadata.get(META_CONDITION),
            Some(&"eq(variables['Build.SourceBranch'], 'refs/heads/main')".to_string()),
            "job-level condition must propagate to step META_CONDITION"
        );
        // Job-level condition also marks the graph Partial-Expression so
        // downstream consumers know the runtime gate is opaque.
        assert!(graph.completeness_gap_kinds.contains(&GapKind::Expression));
    }

    #[test]
    fn stacked_conditions_join_with_and() {
        let yaml = r#"
stages:
  - stage: Deploy
    condition: succeeded()
    jobs:
      - job: Prod
        condition: eq(variables['env'], 'prod')
        steps:
          - script: deploy.sh
            displayName: Deploy step
            condition: ne(variables['Build.Reason'], 'PullRequest')
"#;
        let graph = parse(yaml);
        let step = graph
            .nodes_of_kind(NodeKind::Step)
            .find(|n| n.name == "Deploy step")
            .expect("step node must exist");
        let chain = step
            .metadata
            .get(META_CONDITION)
            .expect("step must carry META_CONDITION");
        // Stage → Job → Step joined with ` AND ` in declaration order.
        assert_eq!(
            chain,
            "succeeded() AND eq(variables['env'], 'prod') AND ne(variables['Build.Reason'], 'PullRequest')",
            "stacked conditions must AND-join in stage→job→step order"
        );
        // Each scope's condition contributed a separate gap reason.
        let expression_gap_count = graph
            .completeness_gap_kinds
            .iter()
            .filter(|k| **k == GapKind::Expression)
            .count();
        assert!(
            expression_gap_count >= 3,
            "stage + job + step conditions must each mark Partial-Expression, got {expression_gap_count}"
        );
    }

    #[test]
    fn depends_on_string_form_parses() {
        let yaml = r#"
jobs:
  - job: Build
    steps:
      - script: build.sh
  - job: Deploy
    dependsOn: Build
    steps:
      - script: deploy.sh
        displayName: Deploy
"#;
        let graph = parse(yaml);
        let step = graph
            .nodes_of_kind(NodeKind::Step)
            .find(|n| n.name == "Deploy")
            .expect("Deploy step must exist");
        assert_eq!(
            step.metadata.get(META_DEPENDS_ON),
            Some(&"Build".to_string()),
            "single-string dependsOn must stamp the predecessor name verbatim"
        );
    }

    #[test]
    fn depends_on_sequence_form_parses() {
        let yaml = r#"
jobs:
  - job: A
    steps: [{ script: a.sh }]
  - job: B
    steps: [{ script: b.sh }]
  - job: C
    steps: [{ script: c.sh }]
  - job: Final
    dependsOn:
      - A
      - B
      - C
    steps:
      - script: final.sh
        displayName: Final step
"#;
        let graph = parse(yaml);
        let step = graph
            .nodes_of_kind(NodeKind::Step)
            .find(|n| n.name == "Final step")
            .expect("Final step must exist");
        assert_eq!(
            step.metadata.get(META_DEPENDS_ON),
            Some(&"A,B,C".to_string()),
            "sequence-form dependsOn must comma-join predecessors in declaration order"
        );
    }

    #[test]
    fn conditional_step_finding_is_downgraded_via_compensating_control() {
        // Untrusted task step (TrustZone::Untrusted) with access to a
        // pipeline secret would normally fire `untrusted_with_authority`
        // at Critical. With a `condition:` gate present on the job, the
        // Suppression-5 ADO conditional-gate CC must downgrade to High,
        // record the original severity, and credit the gate as a CC.
        let yaml = r#"
variables:
  - name: DEPLOY_KEY
    value: $(MySecret)
    isSecret: true
jobs:
  - job: ProdDeploy
    condition: eq(variables['Build.SourceBranch'], 'refs/heads/main')
    steps:
      - task: AzureCLI@2
        displayName: Deploy to prod
        inputs:
          azureSubscription: ProdConnection
          scriptType: bash
          inlineScript: |
            echo "$(DEPLOY_KEY)" > /tmp/key
            az login --service-principal -u $SP -p $(DEPLOY_KEY)
"#;
        let graph = parse(yaml);
        let mut findings =
            taudit_core::rules::run_all_rules(&graph, taudit_core::propagation::DEFAULT_MAX_HOPS);
        // Find the Critical finding the rule would have emitted absent the
        // compensating-control pass — note `run_all_rules` already applies
        // the CC pass, so post-pass severity is what we read here.
        let f = findings
            .iter_mut()
            .find(|f| {
                f.category == taudit_core::finding::FindingCategory::UntrustedWithAuthority
                    && f.message.contains("DEPLOY_KEY")
            })
            .expect(
                "untrusted_with_authority must fire on the AzureCLI@2 step accessing DEPLOY_KEY",
            );
        assert_eq!(
            f.severity,
            taudit_core::finding::Severity::High,
            "Critical must be downgraded one tier to High by the ADO conditional-gate CC"
        );
        assert_eq!(
            f.extras.original_severity,
            Some(taudit_core::finding::Severity::Critical),
            "original_severity must record Critical so the audit trail survives"
        );
        assert!(
            f.extras
                .compensating_controls
                .iter()
                .any(|c| c.starts_with("ADO conditional gate")),
            "compensating_controls must include the ADO conditional-gate entry, got: {:?}",
            f.extras.compensating_controls
        );
    }

    #[test]
    fn variable_groups_are_scoped_to_their_stage_or_job() {
        let yaml = r#"
stages:
  - stage: UsesGroup
    variables:
      - group: OpaqueGroup
    jobs:
      - job: A
        steps:
          - script: echo $(OPAQUE_VALUE)
  - stage: NoGroup
    jobs:
      - job: B
        steps:
          - script: echo $(STAGE_TWO_SECRET)
"#;
        let graph = parse(yaml);
        assert!(
            graph
                .nodes_of_kind(NodeKind::Secret)
                .any(|n| n.name == "STAGE_TWO_SECRET"),
            "variable group in first stage must not suppress secret refs in unrelated stages"
        );
    }

    #[test]
    fn plain_variables_are_scoped_to_their_stage_or_job() {
        let yaml = r#"
stages:
  - stage: PlainStage
    variables:
      - name: SHARED_NAME
        value: plain
    jobs:
      - job: A
        steps:
          - script: echo $(SHARED_NAME)
  - stage: SecretRefStage
    jobs:
      - job: B
        steps:
          - script: echo $(SHARED_NAME)
"#;
        let graph = parse(yaml);
        assert!(
            graph
                .nodes_of_kind(NodeKind::Secret)
                .any(|n| n.name == "SHARED_NAME"),
            "plain variable in one stage must not suppress same-name secret refs in another stage"
        );
    }

    #[test]
    fn escaped_ado_variable_refs_are_not_secret_refs() {
        let yaml = r###"
steps:
  - script: |
      echo $$(NOT_A_SECRET)
      echo "##vso[task.setvariable variable=Count]$$(NOT_A_SECRET)"
    displayName: Escaped
"###;
        let graph = parse(yaml);
        assert!(
            !graph
                .nodes_of_kind(NodeKind::Secret)
                .any(|n| n.name == "NOT_A_SECRET"),
            "$$(VAR) is an escaped literal and must not create a Secret node"
        );
        let step = graph
            .nodes_of_kind(NodeKind::Step)
            .find(|n| n.name == "Escaped")
            .expect("step exists");
        assert!(
            !step
                .metadata
                .contains_key(META_ENV_GATE_WRITES_SECRET_VALUE),
            "escaped setvariable value must not be treated as secret-derived"
        );
    }

    #[test]
    fn terraform_var_flag_detection_ignores_var_file() {
        let yaml = r#"
steps:
  - script: terraform apply -var-file=$(TFVARS_FILE)
    displayName: Var file
  - script: terraform apply -var "password=$(TF_PASSWORD)"
    displayName: Var value
"#;
        let graph = parse(yaml);
        let tfvars = graph
            .nodes_of_kind(NodeKind::Secret)
            .find(|n| n.name == "TFVARS_FILE")
            .expect("TFVARS_FILE secret exists");
        assert!(
            !tfvars.metadata.contains_key(META_CLI_FLAG_EXPOSED),
            "-var-file path should not be classified as an exposed -var value"
        );
        let password = graph
            .nodes_of_kind(NodeKind::Secret)
            .find(|n| n.name == "TF_PASSWORD")
            .expect("TF_PASSWORD secret exists");
        assert_eq!(
            password
                .metadata
                .get(META_CLI_FLAG_EXPOSED)
                .map(String::as_str),
            Some("true"),
            "-var key=$(SECRET) should still be marked as command-line exposed"
        );
    }

    #[test]
    fn task_input_lookup_is_case_insensitive() {
        let yaml = r#"
steps:
  - task: TerraformTaskV4@4
    displayName: Terraform
    inputs:
      Command: apply
      CommandOptions: -auto-approve
  - task: AzureCLI@2
    displayName: SPN
    inputs:
      AddSpnToEnvironment: TRUE
      InLineScRiPt: echo hi
"#;
        let graph = parse(yaml);
        let terraform = graph
            .nodes_of_kind(NodeKind::Step)
            .find(|n| n.name == "Terraform")
            .expect("terraform step");
        assert_eq!(
            terraform
                .metadata
                .get(META_TERRAFORM_AUTO_APPROVE)
                .map(String::as_str),
            Some("true")
        );
        let spn = graph
            .nodes_of_kind(NodeKind::Step)
            .find(|n| n.name == "SPN")
            .expect("spn step");
        assert_eq!(
            spn.metadata.get(META_ADD_SPN_TO_ENV).map(String::as_str),
            Some("true")
        );
        assert_eq!(
            spn.metadata.get(META_SCRIPT_BODY).map(String::as_str),
            Some("echo hi"),
            "mixed-case inline script input key should be detected"
        );
    }
}
