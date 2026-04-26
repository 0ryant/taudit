use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use taudit_core::error::TauditError;
use taudit_core::graph::*;
use taudit_core::ports::PipelineParser;

/// Metadata key for marking inferred (not precisely mapped) secret references.
const META_INFERRED_VAL: &str = "true";

/// Local metadata key marking a Step node that was inlined from a composite
/// action's `runs.steps`. Lets downstream consumers (and tests) distinguish
/// inlined sub-steps from steps written directly in the workflow.
const META_COMPOSITE_STEP: &str = "composite_step";

/// Local metadata key on the inlined Step recording the source action path
/// (e.g. `./.github/actions/my-action`) so consumers can attribute findings.
const META_COMPOSITE_SOURCE: &str = "composite_source";

/// GitHub Actions workflow parser.
pub struct GhaParser;

impl PipelineParser for GhaParser {
    fn platform(&self) -> &str {
        "github-actions"
    }

    fn parse(&self, content: &str, source: &PipelineSource) -> Result<AuthorityGraph, TauditError> {
        let mut de = serde_yaml::Deserializer::from_str(content);
        let doc = de
            .next()
            .ok_or_else(|| TauditError::Parse("empty YAML document".into()))?;
        let workflow: GhaWorkflow = GhaWorkflow::deserialize(doc)
            .map_err(|e| TauditError::Parse(format!("YAML parse error: {e}")))?;
        let extra_docs = de.next().is_some();

        let mut graph = AuthorityGraph::new(source.clone());
        if extra_docs {
            graph.mark_partial(
                "file contains multiple YAML documents (--- separator) — only the first was analyzed".to_string(),
            );
        }
        let mut secret_ids: HashMap<String, NodeId> = HashMap::new();

        // Workflow-level `env:` may be a template expression (e.g. `env: ${{ matrix }}`)
        // whose shape is unknown statically. Mark Partial once and skip env processing
        // for that scope; static rules cannot reason about runtime-resolved env shapes.
        if let Some(EnvSpec::Template(_)) = workflow.env {
            graph.mark_partial(
                "workflow-level env: uses template expression — environment variable shape unknown"
                    .to_string(),
            );
        }

        let is_pull_request_target = workflow
            .triggers
            .as_ref()
            .map(trigger_has_pull_request_target)
            .unwrap_or(false);

        // Record every recognised trigger as a comma-separated list so rules
        // can reason about combinations (e.g. `pull_request_target`,
        // `pull_request`, `workflow_run`, `issue_comment`). Backwards-compatible:
        // existing single-value consumers that match exact strings on
        // `pull_request_target` are preserved by writing that token first when
        // present.
        let trigger_list = collect_trigger_names(workflow.triggers.as_ref());
        if !trigger_list.is_empty() {
            // Place pull_request_target first so consumers that use string
            // equality (older rules) still match the canonical legacy value.
            let mut ordered: Vec<&str> = Vec::new();
            if trigger_list.iter().any(|t| t == "pull_request_target") {
                ordered.push("pull_request_target");
            }
            for t in &trigger_list {
                if t != "pull_request_target" {
                    ordered.push(t);
                }
            }
            // If we only have `pull_request_target`, write it bare so the
            // legacy `== "pull_request_target"` predicate keeps working.
            let value = if ordered.len() == 1 {
                ordered[0].to_string()
            } else {
                ordered.join(",")
            };
            graph.metadata.insert(META_TRIGGER.into(), value);
        } else if is_pull_request_target {
            graph
                .metadata
                .insert(META_TRIGGER.into(), "pull_request_target".into());
        }

        // Workflow-level permissions -> GITHUB_TOKEN identity node
        let token_id = if let Some(ref perms) = workflow.permissions {
            let perm_string = perms.to_string();
            let scope = IdentityScope::from_permissions(&perm_string);
            let mut meta = HashMap::new();
            meta.insert(META_PERMISSIONS.into(), perm_string.clone());
            meta.insert(
                META_IDENTITY_SCOPE.into(),
                format!("{scope:?}").to_lowercase(),
            );
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

        // Iterate jobs in sorted order so node IDs (and therefore every
        // edge `from`/`to`, every finding `nodes_involved`, every JSON
        // emit) are byte-deterministic across runs. `workflow.jobs` is a
        // HashMap whose iteration order is randomised per process — without
        // sorting here, two runs of the same file produce different node
        // IDs, which silently breaks `taudit diff`, cache keys, and any
        // downstream SIEM that hashes the JSON.
        let mut sorted_jobs: Vec<(&String, &GhaJob)> = workflow.jobs.iter().collect();
        sorted_jobs.sort_by(|a, b| a.0.cmp(b.0));
        for (job_name, job) in sorted_jobs {
            // Job-level `env:` may be a template expression (e.g. `env: ${{ matrix }}`)
            // whose shape is unknown statically. Mark Partial once per job and skip
            // env processing for that scope.
            if let Some(EnvSpec::Template(_)) = job.env {
                graph.mark_partial(format!(
                    "job '{job_name}' env: uses template expression — environment variable shape unknown"
                ));
            }

            // Job-level permissions override workflow-level
            let job_token_id = if let Some(ref perms) = job.permissions {
                let perm_string = perms.to_string();
                let scope = IdentityScope::from_permissions(&perm_string);
                let mut meta = HashMap::new();
                meta.insert(META_PERMISSIONS.into(), perm_string.clone());
                meta.insert(
                    META_IDENTITY_SCOPE.into(),
                    format!("{scope:?}").to_lowercase(),
                );
                if perm_string.contains("id-token: write") {
                    meta.insert(META_OIDC.into(), "true".into());
                }
                Some(graph.add_node_with_metadata(
                    NodeKind::Identity,
                    format!("GITHUB_TOKEN ({job_name})"),
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
                let job_step_id = graph.add_node(NodeKind::Step, job_name, TrustZone::FirstParty);
                if let Some(node) = graph.nodes.get_mut(job_step_id) {
                    node.metadata.insert(META_JOB_NAME.into(), job_name.clone());
                }
                graph.add_edge(job_step_id, rw_id, EdgeKind::DelegatesTo);
                if let Some(tok_id) = job_token_id {
                    graph.add_edge(job_step_id, tok_id, EdgeKind::HasAccessTo);
                }
                graph.mark_partial(format!(
                    "reusable workflow '{uses}' in job '{job_name}' cannot be resolved inline — authority within the called workflow is unknown"
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
                    "job '{job_name}' uses matrix strategy — authority shape may differ per matrix entry"
                ));
            }

            // Self-hosted runner detection: `runs-on: self-hosted` or a sequence
            // that includes `self-hosted`. Creates an Image node tagged with
            // META_SELF_HOSTED so downstream rules can flag the job. Hosted
            // runners (ubuntu-latest, etc.) are not represented as Image nodes —
            // this keeps the graph focused on non-default attack surface.
            if is_self_hosted_runner(job.runs_on.as_ref()) {
                let runner_name = runner_label(job.runs_on.as_ref()).unwrap_or("self-hosted");
                let mut meta = HashMap::new();
                meta.insert(META_SELF_HOSTED.into(), "true".into());
                graph.add_node_with_metadata(
                    NodeKind::Image,
                    runner_name,
                    TrustZone::FirstParty,
                    meta,
                );
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
                        meta.insert(META_DIGEST.into(), format!("sha256:{digest}"));
                    }
                }
                Some(graph.add_node_with_metadata(NodeKind::Image, image_str, trust_zone, meta))
            } else {
                None
            };

            for (step_idx, step) in job.steps.iter().enumerate() {
                let default_name = format!("{job_name}[{step_idx}]");
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

                // Stamp parent job name so consumers (e.g. `taudit map --job`)
                // can attribute steps back to their containing job. Also
                // stamp the raw `run:` script body so script-aware rules
                // (runtime_script_fetched_from_floating_url,
                // untrusted_api_response_to_env_sink) can pattern-match on
                // the actual command text the runner will execute.
                if let Some(node) = graph.nodes.get_mut(step_id) {
                    node.metadata.insert(META_JOB_NAME.into(), job_name.clone());
                    if let Some(ref body) = step.run {
                        if !body.is_empty() {
                            node.metadata.insert(META_SCRIPT_BODY.into(), body.clone());
                        }
                    }
                }

                // Link step to action image
                if let Some(img_id) = image_node_id {
                    graph.add_edge(step_id, img_id, EdgeKind::UsesImage);
                }

                // Composite action inlining: if this step uses a local action
                // (`./path`), try to load its `action.yml` and inline `runs.steps`
                // as Step nodes with DelegatesTo edges from the calling step.
                // On any failure (missing file, non-composite, parse error) the
                // helper marks the graph Partial and returns without inlining.
                if let Some(ref uses) = step.uses {
                    if uses.starts_with("./") {
                        try_inline_composite_action(
                            uses,
                            &source.file,
                            step_id,
                            job_name,
                            job_token_id,
                            container_image_id,
                            is_pull_request_target,
                            &mut graph,
                            &mut secret_ids,
                        );
                    }
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

                // Attestation action detection
                if let Some(ref uses) = step.uses {
                    let action = uses.split('@').next().unwrap_or(uses);
                    if matches!(
                        action,
                        "actions/attest-build-provenance" | "sigstore/cosign-installer"
                    ) {
                        if let Some(node) = graph.nodes.get_mut(step_id) {
                            node.metadata.insert(META_ATTESTS.into(), "true".into());
                        }
                    }
                }

                // actions/checkout detection. Tag unconditionally — downstream rules
                // gate on trigger context (pull_request / pull_request_target) to
                // decide whether the checkout is pulling untrusted fork code. Tagging
                // here avoids trigger-ordering dependencies across jobs.
                if let Some(ref uses) = step.uses {
                    let action = uses.split('@').next().unwrap_or(uses);
                    if action == "actions/checkout" {
                        if let Some(node) = graph.nodes.get_mut(step_id) {
                            node.metadata
                                .insert(META_CHECKOUT_SELF.into(), "true".into());
                        }
                    }
                }

                // Process secrets from workflow-level `env:` (inherited by all jobs/steps).
                // Template-shaped envs are skipped here — graph already marked Partial above.
                // Iterate env keys in sorted order so secret-node creation
                // order is deterministic across runs (HashMap iteration is
                // randomised per process; secret IDs leak that randomness
                // into the JSON output otherwise).
                if let Some(env_map) = workflow.env.as_ref().and_then(EnvSpec::as_map) {
                    let mut entries: Vec<(&String, &String)> = env_map.iter().collect();
                    entries.sort_by(|a, b| a.0.cmp(b.0));
                    for (_k, env_val) in entries {
                        if is_secret_reference(env_val) {
                            let secret_name = extract_secret_name(env_val);
                            let secret_id =
                                find_or_create_secret(&mut graph, &mut secret_ids, &secret_name);
                            graph.add_edge(step_id, secret_id, EdgeKind::HasAccessTo);
                        }
                    }
                }

                // Process secrets from job-level `env:` (inherited by all steps).
                // Template-shaped envs are skipped here — graph already marked Partial above.
                if let Some(env_map) = job.env.as_ref().and_then(EnvSpec::as_map) {
                    let mut entries: Vec<(&String, &String)> = env_map.iter().collect();
                    entries.sort_by(|a, b| a.0.cmp(b.0));
                    for (_k, env_val) in entries {
                        if is_secret_reference(env_val) {
                            let secret_name = extract_secret_name(env_val);
                            let secret_id =
                                find_or_create_secret(&mut graph, &mut secret_ids, &secret_name);
                            graph.add_edge(step_id, secret_id, EdgeKind::HasAccessTo);
                        }
                    }
                }

                // Process secrets from step-level `env:` block.
                // If this step's env: is a template expression, mark Partial once for
                // this step and skip env processing.
                match step.env.as_ref() {
                    Some(EnvSpec::Map(env_map)) => {
                        let mut entries: Vec<(&String, &String)> = env_map.iter().collect();
                        entries.sort_by(|a, b| a.0.cmp(b.0));
                        for (_k, env_val) in entries {
                            if is_secret_reference(env_val) {
                                let secret_name = extract_secret_name(env_val);
                                let secret_id = find_or_create_secret(
                                    &mut graph,
                                    &mut secret_ids,
                                    &secret_name,
                                );
                                graph.add_edge(step_id, secret_id, EdgeKind::HasAccessTo);
                            }
                        }
                    }
                    Some(EnvSpec::Template(_)) => {
                        graph.mark_partial(format!(
                            "step '{step_name}' in job '{job_name}' env: uses template expression — environment variable shape unknown"
                        ));
                    }
                    None => {}
                }

                // Process secrets from `with:` block, plus detect any
                // `${{ env.X }}` reference. `env.X` does NOT produce a
                // HasAccessTo edge (the value is sourced from the ambient
                // runner environment, not directly from the secrets store)
                // but it IS the consumer half of the env-gate laundering
                // pattern that `secret_via_env_gate_to_untrusted_consumer`
                // detects. Stamping META_READS_ENV here lets the rule run
                // without re-walking the YAML.
                //
                // Sort keys so secret node creation order is deterministic
                // across runs.
                if let Some(ref with) = step.with {
                    let mut reads_env = false;
                    let mut entries: Vec<(&String, &String)> = with.iter().collect();
                    entries.sort_by(|a, b| a.0.cmp(b.0));
                    for (_k, val) in entries {
                        if is_secret_reference(val) {
                            let secret_name = extract_secret_name(val);
                            let secret_id =
                                find_or_create_secret(&mut graph, &mut secret_ids, &secret_name);
                            graph.add_edge(step_id, secret_id, EdgeKind::HasAccessTo);
                        }
                        if is_env_reference(val) {
                            reads_env = true;
                        }
                    }
                    if reads_env {
                        if let Some(node) = graph.nodes.get_mut(step_id) {
                            node.metadata.insert(META_READS_ENV.into(), "true".into());
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
                                let secret_id =
                                    find_or_create_secret(&mut graph, &mut secret_ids, secret_name);
                                // Mark as inferred — not precisely mapped
                                if let Some(node) = graph.nodes.get_mut(secret_id) {
                                    node.metadata
                                        .insert(META_INFERRED.into(), META_INFERRED_VAL.into());
                                }
                                graph.add_edge(step_id, secret_id, EdgeKind::HasAccessTo);
                                graph.mark_partial(format!(
                                    "secret '{secret_name}' referenced in run: script — inferred, not precisely mapped"
                                ));
                            }
                            pos = abs_start + end;
                        }
                    }
                }

                // Detect writes to the GHA environment gate.
                // Broad detection: presence of GITHUB_ENV or GITHUB_PATH in a run script
                // covers every redirect form (`>> $GITHUB_ENV`, `>> "$GITHUB_ENV"`,
                // `>> ${GITHUB_ENV}`, `tee -a $GITHUB_PATH`, etc.) without brittle
                // multi-variant string matching. Reading these vars without writing is
                // extremely rare in practice, making this an acceptable tradeoff for
                // completeness.
                if let Some(ref run) = step.run {
                    let writes_gate = run.contains("GITHUB_ENV") || run.contains("GITHUB_PATH");
                    if writes_gate {
                        if let Some(node) = graph.nodes.get_mut(step_id) {
                            node.metadata
                                .insert(META_WRITES_ENV_GATE.into(), "true".into());
                        }
                    }
                    // `${{ env.X }}` references inside a run: body — same
                    // consumer signal as the with: detection above. A run
                    // step that interpolates env via the template engine
                    // is reading from the runner-managed env table just
                    // like a uses: action would.
                    if is_env_reference(run) {
                        if let Some(node) = graph.nodes.get_mut(step_id) {
                            node.metadata.insert(META_READS_ENV.into(), "true".into());
                        }
                    }
                }
            }
        }

        // Cross-platform misclassification trap (red-team R2 #5): a YAML file
        // wrapping ADO/GitLab content in a `jobs:` mapping deserializes here
        // without errors but yields no recognisable Step nodes. Marking
        // Partial surfaces the gap rather than silently returning a clean
        // graph with completeness=complete (which a CI gate would treat as
        // "passed").
        let step_count = graph
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Step)
            .count();
        if step_count == 0 && !workflow.jobs.is_empty() {
            graph.mark_partial(
                "jobs: parsed but produced 0 step nodes — possible non-GHA YAML wrong-platform-classified".to_string(),
            );
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

/// Collects every trigger name from a workflow's `on:` field. Returns the
/// canonical event tokens (`pull_request`, `pull_request_target`,
/// `workflow_run`, `issue_comment`, `push`, etc.) in source order, deduped.
fn collect_trigger_names(triggers: Option<&serde_yaml::Value>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push_unique = |s: &str| {
        if !s.is_empty() && !out.iter().any(|e| e == s) {
            out.push(s.to_string());
        }
    };
    let Some(val) = triggers else {
        return out;
    };
    match val {
        serde_yaml::Value::String(s) => push_unique(s),
        serde_yaml::Value::Sequence(seq) => {
            for v in seq {
                if let Some(s) = v.as_str() {
                    push_unique(s);
                }
            }
        }
        serde_yaml::Value::Mapping(map) => {
            for (k, _) in map {
                if let Some(s) = k.as_str() {
                    push_unique(s);
                }
            }
        }
        _ => {}
    }
    out
}

/// Returns true if `runs-on` names a self-hosted runner.
///
/// GHA `runs-on` is polymorphic: a string (`ubuntu-latest`, `self-hosted`), a
/// sequence (`[self-hosted, linux, x64]`), or — for group selection — a mapping
/// (`{ group: my-group, labels: [...] }`). Any form that contains `self-hosted`
/// (as a string, sequence entry, or label entry) is considered self-hosted.
/// Explicit `group:` without `self-hosted` is also self-hosted by construction.
fn is_self_hosted_runner(runs_on: Option<&serde_yaml::Value>) -> bool {
    const SH: &str = "self-hosted";
    let Some(val) = runs_on else {
        return false;
    };
    match val {
        serde_yaml::Value::String(s) => s == SH,
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .any(|v| v.as_str().map(|s| s == SH).unwrap_or(false)),
        serde_yaml::Value::Mapping(map) => {
            if map.contains_key("group") {
                return true;
            }
            if let Some(labels) = map.get("labels") {
                match labels {
                    serde_yaml::Value::String(s) => s == SH,
                    serde_yaml::Value::Sequence(seq) => seq
                        .iter()
                        .any(|v| v.as_str().map(|s| s == SH).unwrap_or(false)),
                    _ => false,
                }
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Extract a human-readable label from a `runs-on` value for naming the Image
/// node. Prefers the first non-`self-hosted` label in a sequence (more specific),
/// falls back to the string value or "self-hosted".
fn runner_label(runs_on: Option<&serde_yaml::Value>) -> Option<&str> {
    let val = runs_on?;
    match val {
        serde_yaml::Value::String(s) => Some(s.as_str()),
        serde_yaml::Value::Sequence(seq) => {
            for v in seq {
                if let Some(s) = v.as_str() {
                    if s != "self-hosted" {
                        return Some(s);
                    }
                }
            }
            seq.first().and_then(|v| v.as_str())
        }
        serde_yaml::Value::Mapping(map) => map.get("group").and_then(|v| v.as_str()),
        _ => None,
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

/// Resolve a local action path (e.g. `./.github/actions/my-action`) against
/// the workflow's filesystem location. Tries each ancestor of the workflow
/// file's directory, returning the first `action.yml` (or `action.yaml`)
/// found. Returns `None` if no matching file exists within ~6 levels up.
///
/// The cap exists because (a) GHA repos rarely nest workflows that deep and
/// (b) without it we'd `stat` the entire path-to-root for every local action.
fn resolve_local_action_path(pipeline_file: &str, uses_path: &str) -> Option<std::path::PathBuf> {
    let start = Path::new(pipeline_file).parent().unwrap_or(Path::new("."));
    let mut current = Some(start);
    for _ in 0..6 {
        let dir = current?;
        let candidate = dir.join(uses_path);
        let yml = candidate.join("action.yml");
        if yml.exists() {
            return Some(yml);
        }
        let yaml = candidate.join("action.yaml");
        if yaml.exists() {
            return Some(yaml);
        }
        current = dir.parent();
    }
    None
}

/// Try to load and inline a local composite action's steps into the graph.
///
/// Resolves `uses_path` (a `./...` reference) relative to the workflow file's
/// directory, reads `action.yml`, and — only if `runs.using == "composite"` —
/// creates a Step node per `runs.steps` entry with a DelegatesTo edge from
/// `calling_step_id`. Inlined steps inherit the calling job's GITHUB_TOKEN and
/// container image links, run the same secret-detection logic over their
/// `env:` / `with:` / `run:` fields, and adopt the parent's trust zone rules
/// (Untrusted for `run:` steps under `pull_request_target`).
///
/// On any unresolvable case (file not found, parse error, non-composite
/// `using`, missing `runs.steps`) the graph is marked Partial with a reason
/// and the function returns without inlining. We never propagate errors — a
/// missing action.yml is a completeness gap, not a fatal parse failure.
#[allow(clippy::too_many_arguments)]
fn try_inline_composite_action(
    uses_path: &str,
    pipeline_file: &str,
    calling_step_id: NodeId,
    job_name: &str,
    job_token_id: Option<NodeId>,
    container_image_id: Option<NodeId>,
    is_pull_request_target: bool,
    graph: &mut AuthorityGraph,
    secret_cache: &mut HashMap<String, NodeId>,
) {
    // GHA semantics: `./...` paths in `uses:` are resolved relative to the
    // **repository root**, not the workflow file's directory. We don't know
    // where the repo root is from a single file path, so we walk up from the
    // workflow's directory probing for the action at each level. This handles
    // both the common case (`.github/workflows/x.yml` → repo root two levels
    // up) and edge cases (workflow at repo root, nested mono-repos).
    let action_path = match resolve_local_action_path(pipeline_file, uses_path) {
        Some(p) => p,
        None => {
            graph.mark_partial(format!("composite action not found: {uses_path}"));
            return;
        }
    };

    let content = match std::fs::read_to_string(&action_path) {
        Ok(c) => c,
        Err(e) => {
            graph.mark_partial(format!(
                "failed to read composite action '{uses_path}': {e}"
            ));
            return;
        }
    };

    let action: serde_yaml::Value = match serde_yaml::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            graph.mark_partial(format!(
                "failed to parse composite action '{uses_path}': {e}"
            ));
            return;
        }
    };

    // Only `using: composite` is supported. docker/node20/etc. hide steps
    // behind a runtime we cannot introspect — mark Partial.
    let using = action
        .get("runs")
        .and_then(|r| r.get("using"))
        .and_then(|u| u.as_str())
        .unwrap_or("");
    if using != "composite" {
        graph.mark_partial(format!(
            "non-composite local action: {uses_path} (using: {using})"
        ));
        return;
    }

    let steps = match action
        .get("runs")
        .and_then(|r| r.get("steps"))
        .and_then(|s| s.as_sequence())
    {
        Some(s) => s,
        None => {
            graph.mark_partial(format!("composite action '{uses_path}' has no runs.steps"));
            return;
        }
    };

    for (idx, step) in steps.iter().enumerate() {
        let step_map = match step.as_mapping() {
            Some(m) => m,
            None => continue,
        };

        let name = step_map
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{uses_path}[{idx}]"));

        let uses = step_map.get("uses").and_then(|v| v.as_str());
        let run = step_map.get("run").and_then(|v| v.as_str());

        // Trust zone mirrors the workflow-level rule: `run:` steps under a
        // pull_request_target trigger may execute fork code.
        let (trust_zone, image_node_id) = if let Some(u) = uses {
            let (zone, image_id) = classify_action(u, graph);
            (zone, Some(image_id))
        } else if is_pull_request_target {
            (TrustZone::Untrusted, None)
        } else {
            (TrustZone::FirstParty, None)
        };

        let inlined_id = graph.add_node(NodeKind::Step, &name, trust_zone);
        // Tag so downstream consumers can identify inlined sub-steps.
        if let Some(node) = graph.nodes.get_mut(inlined_id) {
            node.metadata
                .insert(META_COMPOSITE_STEP.into(), "true".into());
            node.metadata
                .insert(META_COMPOSITE_SOURCE.into(), uses_path.into());
            // Inlined sub-steps belong to the calling job — propagate parent
            // job name so per-job filtering captures composite-action steps too.
            node.metadata.insert(META_JOB_NAME.into(), job_name.into());
            // Stamp the script body for inlined `run:` steps so script-aware
            // rules see them too.
            if let Some(body) = run {
                if !body.is_empty() {
                    node.metadata
                        .insert(META_SCRIPT_BODY.into(), body.to_string());
                }
            }
        }

        // DelegatesTo edge: calling step → inlined sub-step.
        graph.add_edge(calling_step_id, inlined_id, EdgeKind::DelegatesTo);

        if let Some(img_id) = image_node_id {
            graph.add_edge(inlined_id, img_id, EdgeKind::UsesImage);
        }
        if let Some(img_id) = container_image_id {
            graph.add_edge(inlined_id, img_id, EdgeKind::UsesImage);
        }
        if let Some(tok_id) = job_token_id {
            graph.add_edge(inlined_id, tok_id, EdgeKind::HasAccessTo);
        }

        // Secret detection on `env:` block.
        if let Some(env_val) = step_map.get("env").and_then(|v| v.as_mapping()) {
            for v in env_val.values() {
                if let Some(s) = v.as_str() {
                    if is_secret_reference(s) {
                        let secret_name = extract_secret_name(s);
                        let secret_id = find_or_create_secret(graph, secret_cache, &secret_name);
                        graph.add_edge(inlined_id, secret_id, EdgeKind::HasAccessTo);
                    }
                }
            }
        }

        // Secret detection on `with:` block.
        if let Some(with_val) = step_map.get("with").and_then(|v| v.as_mapping()) {
            for v in with_val.values() {
                if let Some(s) = v.as_str() {
                    if is_secret_reference(s) {
                        let secret_name = extract_secret_name(s);
                        let secret_id = find_or_create_secret(graph, secret_cache, &secret_name);
                        graph.add_edge(inlined_id, secret_id, EdgeKind::HasAccessTo);
                    }
                }
            }
        }

        // Inferred secrets in `run:` script blocks (mirrors workflow-level logic).
        if let Some(run_str) = run {
            if run_str.contains("${{ secrets.") {
                let mut pos = 0;
                while let Some(start) = run_str[pos..].find("secrets.") {
                    let abs_start = pos + start + 8;
                    let remaining = &run_str[abs_start..];
                    let end = remaining
                        .find(|c: char| !c.is_alphanumeric() && c != '_')
                        .unwrap_or(remaining.len());
                    let secret_name = &remaining[..end];
                    if !secret_name.is_empty() {
                        let secret_id = find_or_create_secret(graph, secret_cache, secret_name);
                        if let Some(node) = graph.nodes.get_mut(secret_id) {
                            node.metadata
                                .insert(META_INFERRED.into(), META_INFERRED_VAL.into());
                        }
                        graph.add_edge(inlined_id, secret_id, EdgeKind::HasAccessTo);
                        graph.mark_partial(format!(
                            "secret '{secret_name}' referenced in composite action run: script — inferred, not precisely mapped"
                        ));
                    }
                    pos = abs_start + end;
                }
            }

            // GHA env-gate write detection (mirrors workflow-level logic).
            let writes_gate = run_str.contains("GITHUB_ENV") || run_str.contains("GITHUB_PATH");
            if writes_gate {
                if let Some(node) = graph.nodes.get_mut(inlined_id) {
                    node.metadata
                        .insert(META_WRITES_ENV_GATE.into(), "true".into());
                }
            }
        }
    }
}

fn is_secret_reference(val: &str) -> bool {
    val.contains("${{ secrets.")
}

/// True for any `${{ env.<NAME> }}` template expression. Covers the
/// canonical $GITHUB_ENV laundering consumer pattern (a step reads
/// `env.CLOUD_KEY` after a previous step wrote `CLOUD_KEY=$secret` to
/// `$GITHUB_ENV`) without conflating with ordinary first-party `env:`
/// declarations on the consuming step itself. We tolerate the lenient
/// whitespace forms GHA accepts (`${{env.X}}`, `${{   env.X   }}`).
fn is_env_reference(val: &str) -> bool {
    // Cheap fast path — bail before substring scan if the marker isn't
    // present at all. The `env.` substring on its own is too noisy
    // (matches `step.env.X`, `inputs.env_var`), so we anchor on the
    // GHA template open-brace plus any whitespace.
    if !val.contains("${{") {
        return false;
    }
    // Strip whitespace around any template-open and look for the literal
    // token sequence `env.`. This catches `${{env.X}}`, `${{ env.X }}`,
    // and `${{    env.X    }}` while rejecting `${{ steps.x.env.foo }}`.
    let mut idx = 0;
    while let Some(rel) = val[idx..].find("${{") {
        let after = &val[idx + rel + 3..];
        let trimmed = after.trim_start();
        if trimmed.starts_with("env.") {
            return true;
        }
        idx += rel + 3;
    }
    false
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
            meta.insert(
                META_PERMISSIONS.into(),
                "GCP workload identity federation".into(),
            );
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
            meta.insert(
                META_PERMISSIONS.into(),
                "Azure federated credential (OIDC)".into(),
            );
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

/// Polymorphic `env:` block. Normally a map of name → value, but in some
/// real-world workflows the entire `env:` value is a template expression
/// (e.g. `env: ${{ matrix }}`), where the shape resolves at runtime.
///
/// When the value is a template string, downstream code must mark the graph
/// Partial — environment variable shape is unknown to static analysis.
///
/// The map variant uses a custom deserializer (`deserialize_env_map`) that
/// stringifies scalar values. GHA accepts non-string scalars in env values
/// (`COVERAGE: false`, `RUST_BACKTRACE: 1`, `TARGET_FLAGS:` (null)); a strict
/// `HashMap<String, String>` rejects them and breaks 200+ real-world workflows.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum EnvSpec {
    #[serde(deserialize_with = "deserialize_env_map")]
    Map(HashMap<String, String>),
    Template(String),
}

/// Deserialize a GHA `env:` map, stringifying scalar values so that
/// non-string scalars (booleans, numbers, null, YAML anchors resolving
/// to scalars) round-trip into `HashMap<String, String>`.
///
/// Rejects nested mappings/sequences — those would indicate the value
/// is not a real env value and we should fall through to the `Template`
/// variant or fail loudly. Null values become the empty string, matching
/// how GHA itself surfaces an unset env var.
fn deserialize_env_map<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let raw: HashMap<String, serde_yaml::Value> = HashMap::deserialize(deserializer)?;
    let mut out = HashMap::with_capacity(raw.len());
    for (k, v) in raw {
        let s = match v {
            serde_yaml::Value::String(s) => s,
            serde_yaml::Value::Bool(b) => b.to_string(),
            serde_yaml::Value::Number(n) => n.to_string(),
            serde_yaml::Value::Null => String::new(),
            // Mappings / sequences in env values are not legal GHA — but
            // rather than crash the whole workflow, fail this variant so
            // the untagged enum can try `Template` next.
            other => {
                return Err(D::Error::custom(format!(
                    "env value for `{k}` is not a scalar: {other:?}"
                )))
            }
        };
        out.insert(k, s);
    }
    Ok(out)
}

impl EnvSpec {
    /// Returns the env map if statically known, or `None` if it is a template
    /// expression whose shape resolves at runtime.
    pub fn as_map(&self) -> Option<&HashMap<String, String>> {
        match self {
            EnvSpec::Map(m) => Some(m),
            EnvSpec::Template(_) => None,
        }
    }

    /// Returns the raw template expression, if this `env:` is a template.
    pub fn as_template(&self) -> Option<&str> {
        match self {
            EnvSpec::Template(s) => Some(s.as_str()),
            EnvSpec::Map(_) => None,
        }
    }
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
    /// Polymorphic: typically a map, but can be a template expression
    /// (e.g. `env: ${{ matrix }}`) whose shape is unknown statically.
    #[serde(default)]
    pub env: Option<EnvSpec>,
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
    /// Job-level env vars. Polymorphic: typically a map, but can be a
    /// template expression (e.g. `env: ${{ matrix }}`) whose shape is unknown
    /// statically.
    #[serde(default)]
    pub env: Option<EnvSpec>,
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
    /// Runner label(s). Can be a string (`ubuntu-latest`), a sequence
    /// (`[self-hosted, linux]`), or absent for reusable workflows.
    #[serde(rename = "runs-on", default)]
    pub runs_on: Option<serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
pub struct GhaStep {
    pub name: Option<String>,
    pub uses: Option<String>,
    pub run: Option<String>,
    /// Step-level env vars. Polymorphic: typically a map, but can be a
    /// template expression (e.g. `env: ${{ matrix }}`) whose shape is unknown
    /// statically.
    #[serde(default)]
    pub env: Option<EnvSpec>,
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
            commit_sha: None,
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
            graph.completeness_gaps.iter().any(|g| g.contains("matrix")),
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
            !identities[0].metadata.contains_key(META_OIDC),
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
            !identities[0].metadata.contains_key(META_OIDC),
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
            assert_eq!(
                links.len(),
                1,
                "step '{}' must link to container",
                step.name
            );
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
        use taudit_core::propagation::DEFAULT_MAX_HOPS;
        use taudit_core::rules;
        let graph = parse(yaml);
        let findings = rules::run_all_rules(&graph, DEFAULT_MAX_HOPS);
        // Should detect: GITHUB_TOKEN (broad) propagates to ubuntu:22.04 (Untrusted) via step
        assert!(
            findings
                .iter()
                .any(|f| f.category == taudit_core::finding::FindingCategory::AuthorityPropagation),
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
        assert!(
            identities.is_empty(),
            "static AWS creds must not create Identity node"
        );
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert_eq!(secrets.len(), 2, "both static secrets captured");
    }

    #[test]
    fn pull_request_target_sets_meta_trigger_on_graph() {
        let yaml = r#"
on: pull_request_target
jobs:
  ci:
    steps:
      - run: echo hi
"#;
        let graph = parse(yaml);
        assert_eq!(
            graph.metadata.get(META_TRIGGER),
            Some(&"pull_request_target".to_string())
        );
    }

    #[test]
    fn github_env_write_in_run_sets_meta_writes_env_gate() {
        let yaml = r#"
jobs:
  build:
    steps:
      - name: Set version
        run: echo "VERSION=1.0" >> $GITHUB_ENV
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 1);
        assert_eq!(
            steps[0].metadata.get(META_WRITES_ENV_GATE),
            Some(&"true".to_string()),
            "run: with >> $GITHUB_ENV must mark META_WRITES_ENV_GATE"
        );
    }

    #[test]
    fn attest_action_sets_meta_attests() {
        let yaml = r#"
jobs:
  release:
    steps:
      - name: Attest
        uses: actions/attest-build-provenance@v1
        with:
          subject-path: dist/*
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 1);
        assert_eq!(
            steps[0].metadata.get(META_ATTESTS),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn self_hosted_string_runs_on_creates_image_with_self_hosted_metadata() {
        let yaml = r#"
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo hi
"#;
        let graph = parse(yaml);
        let images: Vec<_> = graph.nodes_of_kind(NodeKind::Image).collect();
        let runner = images
            .iter()
            .find(|i| i.metadata.contains_key(META_SELF_HOSTED))
            .expect("self-hosted runner Image node must be created");
        assert_eq!(
            runner.metadata.get(META_SELF_HOSTED),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn self_hosted_in_sequence_runs_on_creates_image_with_self_hosted_metadata() {
        let yaml = r#"
jobs:
  build:
    runs-on: [self-hosted, linux, x64]
    steps:
      - run: echo hi
"#;
        let graph = parse(yaml);
        let images: Vec<_> = graph.nodes_of_kind(NodeKind::Image).collect();
        let runner = images
            .iter()
            .find(|i| i.metadata.contains_key(META_SELF_HOSTED))
            .expect("self-hosted runner Image node must be created");
        assert_eq!(
            runner.metadata.get(META_SELF_HOSTED),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn hosted_runner_does_not_create_self_hosted_image() {
        let yaml = r#"
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#;
        let graph = parse(yaml);
        let self_hosted_images: Vec<_> = graph
            .nodes_of_kind(NodeKind::Image)
            .filter(|i| i.metadata.contains_key(META_SELF_HOSTED))
            .collect();
        assert!(
            self_hosted_images.is_empty(),
            "hosted runner must not produce a self-hosted Image node"
        );
    }

    #[test]
    fn actions_checkout_step_tagged_with_meta_checkout_self() {
        let yaml = r#"
jobs:
  ci:
    steps:
      - uses: actions/checkout@v4
      - run: echo hi
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        let checkout_step = steps
            .iter()
            .find(|s| s.metadata.contains_key(META_CHECKOUT_SELF))
            .expect("actions/checkout step must be tagged META_CHECKOUT_SELF");
        assert_eq!(
            checkout_step.metadata.get(META_CHECKOUT_SELF),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn actions_checkout_sha_pinned_also_tagged() {
        let yaml = r#"
jobs:
  ci:
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 1);
        assert_eq!(
            steps[0].metadata.get(META_CHECKOUT_SELF),
            Some(&"true".to_string()),
            "SHA-pinned checkout must still be tagged — rule gates on trigger context"
        );
    }

    #[test]
    fn non_checkout_uses_not_tagged_checkout_self() {
        let yaml = r#"
jobs:
  ci:
    steps:
      - uses: some-org/other-action@v1
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 1);
        assert!(
            !steps[0].metadata.contains_key(META_CHECKOUT_SELF),
            "non-checkout uses: must not be tagged"
        );
    }

    /// Build a unique temp directory under the OS temp root. We avoid pulling
    /// in the `tempfile` crate (no new deps allowed) — uniqueness comes from
    /// PID + a per-call atomic counter, which is sufficient for serial tests.
    fn make_temp_dir(label: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "taudit-gha-test-{}-{}-{}",
            std::process::id(),
            n,
            label
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn parse_at(yaml: &str, file: &str) -> AuthorityGraph {
        let parser = GhaParser;
        let source = PipelineSource {
            file: file.into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        };
        parser.parse(yaml, &source).unwrap()
    }

    #[test]
    fn composite_action_steps_inlined_into_graph() {
        let dir = make_temp_dir("composite-inline");
        let workflows_dir = dir.join(".github/workflows");
        let action_dir = dir.join(".github/actions/my-action");
        std::fs::create_dir_all(&workflows_dir).unwrap();
        std::fs::create_dir_all(&action_dir).unwrap();

        let action_yml = r#"
name: My Action
runs:
  using: composite
  steps:
    - name: Install deps
      run: npm install
      shell: bash
    - name: Build
      uses: actions/setup-node@v4
      with:
        node-version: '18'
"#;
        std::fs::write(action_dir.join("action.yml"), action_yml).unwrap();

        let workflow = r#"
jobs:
  ci:
    steps:
      - name: Run my action
        uses: ./.github/actions/my-action
"#;
        let workflow_path = workflows_dir.join("ci.yml");
        std::fs::write(&workflow_path, workflow).unwrap();

        let graph = parse_at(workflow, workflow_path.to_str().unwrap());

        // Calling step + 2 inlined steps = 3 Step nodes.
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 3, "calling step + 2 inlined sub-steps");

        let inlined: Vec<_> = steps
            .iter()
            .filter(|s| s.metadata.contains_key(META_COMPOSITE_STEP))
            .collect();
        assert_eq!(inlined.len(), 2, "two inlined composite steps");
        assert!(inlined.iter().any(|s| s.name == "Install deps"));
        assert!(inlined.iter().any(|s| s.name == "Build"));

        // Calling step has DelegatesTo edges to both inlined steps.
        let calling = steps
            .iter()
            .find(|s| !s.metadata.contains_key(META_COMPOSITE_STEP))
            .expect("calling step present");
        let delegates: Vec<_> = graph
            .edges_from(calling.id)
            .filter(|e| e.kind == EdgeKind::DelegatesTo)
            .collect();
        assert_eq!(delegates.len(), 2, "two DelegatesTo edges to inlined steps");

        // The inlined `uses: actions/setup-node@v4` step must produce an Image node.
        assert!(
            graph
                .nodes_of_kind(NodeKind::Image)
                .any(|n| n.name == "actions/setup-node@v4"),
            "inlined uses: must create Image node"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_action_yml_marks_graph_partial() {
        let dir = make_temp_dir("missing-action");
        let workflows_dir = dir.join(".github/workflows");
        std::fs::create_dir_all(&workflows_dir).unwrap();

        // Note: no action.yml created — the path doesn't exist.
        let workflow = r#"
jobs:
  ci:
    steps:
      - uses: ./.github/actions/missing-action
"#;
        let workflow_path = workflows_dir.join("ci.yml");
        std::fs::write(&workflow_path, workflow).unwrap();

        let graph = parse_at(workflow, workflow_path.to_str().unwrap());

        assert_eq!(graph.completeness, AuthorityCompleteness::Partial);
        assert!(
            graph
                .completeness_gaps
                .iter()
                .any(|g| g.contains("composite action not found") && g.contains("missing-action")),
            "missing action.yml must be recorded as a completeness gap, got: {:?}",
            graph.completeness_gaps
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_composite_local_action_marks_graph_partial() {
        let dir = make_temp_dir("non-composite");
        let workflows_dir = dir.join(".github/workflows");
        let action_dir = dir.join(".github/actions/docker-action");
        std::fs::create_dir_all(&workflows_dir).unwrap();
        std::fs::create_dir_all(&action_dir).unwrap();

        // Docker-based local action: steps are inside the image, not visible.
        let action_yml = r#"
name: Docker Action
runs:
  using: docker
  image: Dockerfile
"#;
        std::fs::write(action_dir.join("action.yml"), action_yml).unwrap();

        let workflow = r#"
jobs:
  ci:
    steps:
      - uses: ./.github/actions/docker-action
"#;
        let workflow_path = workflows_dir.join("ci.yml");
        std::fs::write(&workflow_path, workflow).unwrap();

        let graph = parse_at(workflow, workflow_path.to_str().unwrap());

        assert_eq!(graph.completeness, AuthorityCompleteness::Partial);
        assert!(
            graph
                .completeness_gaps
                .iter()
                .any(|g| g.contains("non-composite local action")),
            "docker action must mark graph Partial, got: {:?}",
            graph.completeness_gaps
        );

        // No inlined steps — only the calling step.
        let inlined: Vec<_> = graph
            .nodes_of_kind(NodeKind::Step)
            .filter(|s| s.metadata.contains_key(META_COMPOSITE_STEP))
            .collect();
        assert!(inlined.is_empty(), "non-composite must not inline steps");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn composite_action_inlined_step_secrets_captured() {
        let dir = make_temp_dir("composite-secrets");
        let workflows_dir = dir.join(".github/workflows");
        let action_dir = dir.join(".github/actions/deploy");
        std::fs::create_dir_all(&workflows_dir).unwrap();
        std::fs::create_dir_all(&action_dir).unwrap();

        let action_yml = r#"
name: Deploy
runs:
  using: composite
  steps:
    - name: Push
      run: |
        curl -H "Authorization: ${{ secrets.DEPLOY_TOKEN }}" https://example.com
      shell: bash
    - name: Notify
      uses: some-org/notify@v1
      with:
        api-key: "${{ secrets.NOTIFY_KEY }}"
"#;
        std::fs::write(action_dir.join("action.yml"), action_yml).unwrap();

        let workflow = r#"
jobs:
  release:
    steps:
      - uses: ./.github/actions/deploy
"#;
        let workflow_path = workflows_dir.join("release.yml");
        std::fs::write(&workflow_path, workflow).unwrap();

        let graph = parse_at(workflow, workflow_path.to_str().unwrap());

        let secret_names: Vec<_> = graph
            .nodes_of_kind(NodeKind::Secret)
            .map(|s| s.name.as_str())
            .collect();
        assert!(
            secret_names.contains(&"DEPLOY_TOKEN"),
            "run: secret in composite step must be captured, got: {secret_names:?}"
        );
        assert!(
            secret_names.contains(&"NOTIFY_KEY"),
            "with: secret in composite step must be captured, got: {secret_names:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
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

    #[test]
    fn job_env_template_expression_does_not_crash_and_marks_partial() {
        // Real-world repro from scikit-learn unit-tests.yml: job-level `env:`
        // is a bare template expression (`${{ matrix }}`) instead of a map.
        // Historically the GHA parser deserialized env: as `HashMap<String,String>`
        // and crashed with "invalid type: string ..., expected a map". The parser
        // must now tolerate this gracefully: parse succeeds, graph is marked Partial
        // with a reason that mentions the template-shaped env.
        let yaml = r#"
jobs:
  unit-tests:
    env: ${{ matrix }}
    steps:
      - run: pytest
"#;
        let graph = parse(yaml);
        // No crash — parse returned a graph.
        assert!(
            matches!(graph.completeness, AuthorityCompleteness::Partial),
            "graph must be marked Partial when env: is a template expression"
        );
        let saw_template_gap = graph
            .completeness_gaps
            .iter()
            .any(|g| g.contains("env:") && g.contains("template"));
        assert!(
            saw_template_gap,
            "completeness_gaps must mention env: template, got: {:?}",
            graph.completeness_gaps
        );
        // Steps still parsed normally.
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 1, "the single step must still be parsed");
    }

    #[test]
    fn env_with_non_string_scalar_values_parses() {
        // Real-world repro from BurntSushi/ripgrep ci.yml and many others:
        // GHA env values can be booleans (`COVERAGE: false`), integers
        // (`RUST_BACKTRACE: 1`), or null (`TARGET_FLAGS:`). A naive
        // HashMap<String, String> deserializer rejects these. After the fix,
        // they round-trip — booleans/numbers as their textual form,
        // null as the empty string.
        let yaml = r#"
jobs:
  test:
    env:
      RUST_BACKTRACE: 1
      COVERAGE: false
      TARGET_FLAGS:
      CARGO: cargo
    steps:
      - run: cargo test
"#;
        let graph = parse(yaml);
        // Parse must succeed and produce the step node.
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 1, "expected the single step to parse");
        // Graph stays Complete — env: is a real map, not a template.
        assert!(
            !matches!(graph.completeness, AuthorityCompleteness::Partial)
                || !graph
                    .completeness_gaps
                    .iter()
                    .any(|g| g.contains("env:") && g.contains("template")),
            "non-string env values must not mark the graph Partial via the env-template path"
        );
    }

    #[test]
    fn step_env_with_boolean_and_integer_values_parses() {
        // Same regression class but at step-level env: instead of job-level.
        let yaml = r#"
jobs:
  build:
    steps:
      - name: build
        run: make
        env:
          DEBUG: true
          RETRIES: 3
          OPTIONAL_FLAG:
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 1);
    }

    #[test]
    fn meta_job_name_set_on_step_nodes() {
        let yaml = r#"
jobs:
  build:
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Compile
        run: make build
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert!(!steps.is_empty(), "expected at least one Step node");
        for step in &steps {
            assert_eq!(
                step.metadata.get(META_JOB_NAME).map(String::as_str),
                Some("build"),
                "Step {:?} missing META_JOB_NAME=build",
                step.name
            );
        }
    }

    // ── Cross-platform misclassification trap (red-team R2 #5) ─────

    #[test]
    fn jobs_without_steps_marks_partial() {
        // `jobs:` is non-empty (parser deserializes them happily) but every
        // job has no `steps:` block — the GHA parser produces 0 Step nodes.
        // This is the canonical "wrong-platform smuggle" shape: an attacker
        // gets a misclassified file past auto-detect, no recognisable steps
        // get materialised, and the previous behaviour was completeness =
        // complete + 0 findings = "passed". Now Partial.
        let yaml = r#"
on:
  push:
jobs:
  build:
    runs-on: ubuntu-latest
"#;
        let graph = parse(yaml);
        let step_count = graph
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Step)
            .count();
        assert_eq!(step_count, 0, "no steps: present means 0 Step nodes");
        assert_eq!(
            graph.completeness,
            AuthorityCompleteness::Partial,
            "0-step-nodes despite non-empty jobs: must mark Partial"
        );
        assert!(
            graph
                .completeness_gaps
                .iter()
                .any(|g| g.contains("0 step nodes")),
            "completeness_gaps must mention 0 step nodes: {:?}",
            graph.completeness_gaps
        );
    }

    #[test]
    fn empty_workflow_no_jobs_does_not_mark_partial_for_zero_steps() {
        // An entirely empty workflow (no `jobs:` at all) has nothing to
        // classify — completeness should not flip to Partial just because
        // there are zero step nodes (the source had no carrier).
        let yaml = "name: empty\non:\n  push:\n";
        let graph = parse(yaml);
        let zero_step_gap = graph
            .completeness_gaps
            .iter()
            .any(|g| g.contains("0 step nodes"));
        assert!(
            !zero_step_gap,
            "no jobs: in source means no 0-step gap reason; got: {:?}",
            graph.completeness_gaps
        );
    }
}
