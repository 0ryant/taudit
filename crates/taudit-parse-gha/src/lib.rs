use std::collections::{BTreeMap, HashMap};

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
        let mut de = serde_yaml::Deserializer::from_str(content);
        let doc = de
            .next()
            .ok_or_else(|| TauditError::Parse("empty YAML document".into()))?;
        let workflow: GhaWorkflow = GhaWorkflow::deserialize(doc)
            .map_err(|e| TauditError::Parse(format!("YAML parse error: {e}")))?;
        let extra_docs = de.next().is_some();

        let mut graph = AuthorityGraph::new(source.clone());
        graph
            .metadata
            .insert(META_PLATFORM.into(), "github-actions".into());
        if workflow.permissions.is_none() {
            // Negative-space marker: lets the
            // `no_workflow_level_permissions_block` rule detect the absence
            // of any top-level `permissions:` declaration without re-reading
            // the source YAML. The same rule will additionally check for the
            // absence of any per-job permissions block.
            graph
                .metadata
                .insert(META_NO_WORKFLOW_PERMISSIONS.into(), "true".into());
        }
        if extra_docs {
            graph.mark_partial(
                GapKind::Expression,
                "file contains multiple YAML documents (--- separator) — only the first was analyzed".to_string(),
            );
        }
        let mut secret_ids: HashMap<String, NodeId> = HashMap::new();
        let mut artifact_ids: HashMap<String, NodeId> = HashMap::new();

        // Workflow-level `env:` may be a template expression (e.g. `env: ${{ matrix }}`)
        // whose shape is unknown statically. Mark Partial once and skip env processing
        // for that scope; static rules cannot reason about runtime-resolved env shapes.
        if let Some(EnvSpec::Template(_)) = workflow.env {
            graph.mark_partial(
                GapKind::Expression,
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

        // Stamp the full trigger list so non-PRT-only rules can fire on
        // issue_comment, pull_request_review*, workflow_run, etc. Use a
        // separate key from META_TRIGGER so the existing
        // trigger_context_mismatch contract is preserved.
        if let Some(triggers) = workflow.triggers.as_ref() {
            let names = collect_trigger_names(Some(triggers));
            if !names.is_empty() {
                graph.metadata.insert(META_TRIGGERS.into(), names.join(","));
            }
            let inputs = collect_dispatch_inputs(triggers);
            if !inputs.is_empty() {
                graph
                    .metadata
                    .insert(META_DISPATCH_INPUTS.into(), inputs.join(","));
            }
            let call_inputs = collect_workflow_call_inputs(triggers);
            if !call_inputs.is_empty() {
                graph
                    .metadata
                    .insert(META_GHA_WORKFLOW_CALL_INPUTS.into(), call_inputs.join(","));
            }
        }

        // Workflow-level permissions -> GITHUB_TOKEN identity node. When the
        // workflow omits `permissions:`, the token still exists; its actual
        // scope is inherited from enterprise/org/repo defaults, which are
        // outside the YAML. Model it as unknown authority instead of absent.
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
            let mut meta = HashMap::new();
            meta.insert(META_IDENTITY_SCOPE.into(), "unknown".into());
            meta.insert(META_IMPLICIT.into(), "true".into());
            Some(graph.add_node_with_metadata(
                NodeKind::Identity,
                "GITHUB_TOKEN",
                TrustZone::FirstParty,
                meta,
            ))
        };

        // Accumulator for `jobs.<id>.outputs.*` records across every job.
        // Format described on `META_JOB_OUTPUTS`. Built bottom-up here, then
        // serialized into graph metadata once after the job loop finishes.
        let mut job_output_records: Vec<String> = Vec::new();

        // Iterate jobs in sorted order so node IDs (and therefore every
        // edge `from`/`to`, every finding `nodes_involved`, every JSON
        // emit) are byte-deterministic across runs.
        let mut sorted_jobs: Vec<(&String, &GhaJob)> = workflow.jobs.iter().collect();
        sorted_jobs.sort_by(|a, b| a.0.cmp(b.0));
        for (job_name, job) in sorted_jobs {
            // YAML `steps[].id` -> bool tracking whether that step holds an
            // OIDC identity. Used when classifying job outputs that read
            // `${{ steps.<id>.outputs.X }}` so R4 can distinguish OIDC-derived
            // values from plain step outputs.
            let mut step_oidc_by_yaml_id: HashMap<String, bool> = HashMap::new();
            // Job-level `env:` may be a template expression (e.g. `env: ${{ matrix }}`)
            // whose shape is unknown statically. Mark Partial once per job and skip
            // env processing for that scope.
            if let Some(EnvSpec::Template(_)) = job.env {
                graph.mark_partial(
                    GapKind::Expression,
                    format!(
                        "job '{job_name}' env: uses template expression — environment variable shape unknown"
                    ),
                );
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
                let trust_zone = if is_pin_semantically_valid(uses) {
                    TrustZone::ThirdParty
                } else {
                    TrustZone::Untrusted
                };
                let rw_id = graph.add_node(NodeKind::Image, uses, trust_zone);
                // Synthetic step represents this job delegating to the called workflow
                let job_step_id = graph.add_node(NodeKind::Step, job_name, TrustZone::FirstParty);
                if let Some(node) = graph.nodes.get_mut(job_step_id) {
                    node.metadata.insert(META_JOB_NAME.into(), job_name.clone());
                    node.metadata.insert(
                        META_GHA_ACTION.into(),
                        uses.split('@').next().unwrap_or(uses).into(),
                    );
                    if let Some(runs_on) = job.runs_on.as_ref().and_then(yaml_value_compact) {
                        node.metadata.insert(META_GHA_RUNS_ON.into(), runs_on);
                    }
                    let condition = combined_condition(job.if_cond.as_deref(), None);
                    if let Some(condition) = condition {
                        node.metadata.insert(META_CONDITION.into(), condition);
                    }
                    if let Some(with) = job.with.as_ref() {
                        let mut entries: Vec<(&String, &serde_yaml::Value)> = with.iter().collect();
                        entries.sort_by(|a, b| a.0.cmp(b.0));
                        let rendered: Vec<String> = entries
                            .into_iter()
                            .filter_map(|(key, value)| {
                                yaml_scalar_to_string(value).map(|scalar| format!("{key}={scalar}"))
                            })
                            .collect();
                        if !rendered.is_empty() {
                            node.metadata
                                .insert(META_GHA_WITH_INPUTS.into(), rendered.join("\n"));
                        }
                    }
                    // Stamp `secrets: inherit` so downstream rules can flag wide-open
                    // secret forwarding. The `secrets:` block on a reusable-workflow
                    // call is either the literal string "inherit" or a mapping —
                    // only the string form forwards every caller secret.
                    if let Some(serde_yaml::Value::String(s)) = job.secrets.as_ref() {
                        if s == "inherit" {
                            node.metadata
                                .insert(META_SECRETS_INHERIT.into(), "true".into());
                        }
                    }
                }
                graph.add_edge(job_step_id, rw_id, EdgeKind::DelegatesTo);
                if let Some(tok_id) = job_token_id {
                    graph.add_edge(job_step_id, tok_id, EdgeKind::HasAccessTo);
                }

                // F13: workflow-level `env:` is in scope for the caller's
                // evaluation of `secrets:` mapping values and `with:` inputs
                // even when delegating to a reusable workflow. Job-level
                // `env:` does NOT propagate into reusable-workflow callees per
                // GHA semantics, so we merge ONLY workflow.env. (The synthetic
                // step represents the caller-side evaluation context, not the
                // callee's execution environment.)
                if let Some(env_map) = workflow.env.as_ref().and_then(EnvSpec::as_map) {
                    let mut entries: Vec<(&String, &String)> = env_map.iter().collect();
                    entries.sort_by(|a, b| a.0.cmp(b.0));
                    for (_k, env_val) in entries {
                        for secret_name in iter_secret_refs(env_val) {
                            let secret_id =
                                find_or_create_secret(&mut graph, &mut secret_ids, secret_name);
                            graph.add_edge(job_step_id, secret_id, EdgeKind::HasAccessTo);
                        }
                    }
                }

                // F6: `secrets:` mapping form on a reusable-workflow call —
                // `secrets: { CHILD: ${{ secrets.PARENT }} }`. Each value is a
                // template expression evaluated in the caller context, so any
                // `secrets.X` reference produces a HasAccessTo edge to the
                // caller-side secret. (The literal string `inherit` form is
                // already handled above.) Sorted by key for determinism —
                // mirrors the v1.1.0-beta.1 sort pattern used elsewhere.
                if let Some(serde_yaml::Value::Mapping(map)) = job.secrets.as_ref() {
                    let mut entries: Vec<(&str, &str)> = map
                        .iter()
                        .filter_map(|(k, v)| Some((k.as_str()?, v.as_str()?)))
                        .collect();
                    entries.sort_by(|a, b| a.0.cmp(b.0));
                    for (_child_name, val) in entries {
                        for secret_name in iter_secret_refs(val) {
                            let secret_id =
                                find_or_create_secret(&mut graph, &mut secret_ids, secret_name);
                            graph.add_edge(job_step_id, secret_id, EdgeKind::HasAccessTo);
                        }
                    }
                }

                graph.mark_partial(
                    GapKind::Structural,
                    format!(
                        "reusable workflow '{uses}' in job '{job_name}' cannot be resolved inline — authority within the called workflow is unknown"
                    ),
                );
                continue;
            }

            // Matrix strategy: authority shape may differ per matrix entry — mark Partial
            if job
                .strategy
                .as_ref()
                .and_then(|s| s.get("matrix"))
                .is_some()
            {
                graph.mark_partial(
                    GapKind::Expression,
                    format!(
                        "job '{job_name}' uses matrix strategy — authority shape may differ per matrix entry"
                    ),
                );
            }

            if job
                .services
                .as_ref()
                .is_some_and(|services| !yaml_value_is_empty(services))
            {
                graph.mark_partial(
                    GapKind::Structural,
                    format!(
                        "job '{job_name}' uses service containers — services, ports, volumes, options, and registry credentials are not modeled"
                    ),
                );
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
                if let Some(options) = container.options() {
                    if !options.is_empty() {
                        meta.insert(META_GHA_CONTAINER_OPTIONS.into(), options.to_string());
                    }
                }
                let unsupported = container.unsupported_static_fields();
                if !unsupported.is_empty() {
                    graph.mark_partial(
                        GapKind::Structural,
                        format!(
                            "job '{job_name}' container {} not modeled; only image/options are complete",
                            unsupported.join(", ")
                        ),
                    );
                }
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
                    if let Some(runs_on) = job.runs_on.as_ref().and_then(yaml_value_compact) {
                        node.metadata.insert(META_GHA_RUNS_ON.into(), runs_on);
                    }
                    let condition =
                        combined_condition(job.if_cond.as_deref(), step.if_cond.as_deref());
                    if let Some(condition) = condition {
                        node.metadata.insert(META_CONDITION.into(), condition);
                    }
                    if let Some(ref uses) = step.uses {
                        let action = uses.split('@').next().unwrap_or(uses);
                        node.metadata.insert(META_GHA_ACTION.into(), action.into());
                        if let Some(with) = step.with.as_ref() {
                            let mut entries: Vec<(&String, &serde_yaml::Value)> =
                                with.iter().collect();
                            entries.sort_by(|a, b| a.0.cmp(b.0));
                            let mut rendered = Vec::new();
                            for (key, value) in entries {
                                if let Some(scalar) = yaml_scalar_to_string(value) {
                                    rendered.push(format!("{key}={scalar}"));
                                }
                            }
                            if !rendered.is_empty() {
                                node.metadata
                                    .insert(META_GHA_WITH_INPUTS.into(), rendered.join("\n"));
                            }
                        }
                    }
                    if let Some(ref body) = step.run {
                        if !body.is_empty() {
                            node.metadata.insert(META_SCRIPT_BODY.into(), body.clone());
                        }
                    }
                    // Fork-check stamping. A step inherits its job-level
                    // `if:` (if any) plus its own `if:`. Either one carrying
                    // the standard fork-check pattern is sufficient — both
                    // forms guard the step from running on fork-PR contexts.
                    let job_check = job
                        .if_cond
                        .as_deref()
                        .map(is_fork_check_expression)
                        .unwrap_or(false);
                    let step_check = step
                        .if_cond
                        .as_deref()
                        .map(is_fork_check_expression)
                        .unwrap_or(false);
                    if job_check || step_check {
                        node.metadata.insert(META_FORK_CHECK.into(), "true".into());
                    }
                }

                // Link step to action image
                if let Some(img_id) = image_node_id {
                    graph.add_edge(step_id, img_id, EdgeKind::UsesImage);
                }

                // Composite action references (`uses: ./path`) are NOT inlined.
                //
                // Earlier versions walked the filesystem from `pipeline_file`'s
                // parent looking for an `action.yml` to inline. That made the
                // graph dependent on (a) whether `pipeline_file` was absolute
                // or relative, (b) the binary's CWD, and (c) whether the
                // consumer copied the YAML to a sandbox without the surrounding
                // repo. Same input bytes, different graphs — a parser-purity
                // violation.
                //
                // We now treat all `./local-action` references as Partial and
                // record a Structural completeness gap. This matches the
                // schema's additive-only semver discipline (findings only get
                // MORE conservative). Downstream rules that care about the
                // inlined sub-steps will simply not fire — preferred over
                // CWD-dependent false confidence.
                if let Some(ref uses) = step.uses {
                    if uses.starts_with("./") {
                        graph.mark_partial(
                            GapKind::Structural,
                            format!(
                                "composite action not resolved (local action '{uses}' — taudit does not read filesystem)"
                            ),
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
                let mut step_holds_oidc = false;
                if let Some(ref uses) = step.uses {
                    if let Some(cloud_id) =
                        classify_cloud_auth(uses, step.with.as_ref(), &mut graph)
                    {
                        graph.add_edge(step_id, cloud_id, EdgeKind::HasAccessTo);
                        step_holds_oidc = true;
                    }
                }
                // The job's GITHUB_TOKEN itself can be OIDC-capable
                // (`permissions: id-token: write`). When that's the case every
                // step in the job inherits the OIDC scope.
                if let Some(tok_id) = job_token_id {
                    if let Some(tok_node) = graph.nodes.get(tok_id) {
                        if tok_node.metadata.contains_key(META_OIDC) {
                            step_holds_oidc = true;
                        }
                    }
                }
                if let Some(ref yaml_id) = step.id {
                    step_oidc_by_yaml_id.insert(yaml_id.clone(), step_holds_oidc);
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
                            // Stamp the verbatim `with.ref` value (if any) so
                            // taint rules (R6) can see whether dispatch input
                            // flows into a checkout ref.
                            if let Some(with) = step.with.as_ref() {
                                if let Some(r) = with.get("ref").and_then(yaml_scalar_to_string) {
                                    node.metadata.insert(META_CHECKOUT_REF.into(), r);
                                }
                            }
                        }
                    }
                }

                // Stamp the raw `run:` body so script-body rules (R6
                // manual_dispatch_input_to_url_or_command) can pattern-match
                // without needing a parser hook of their own. Mirrors the
                // META_SCRIPT_BODY contract used by the ADO inline-script rules.
                if let Some(ref run) = step.run {
                    if !run.is_empty() {
                        if let Some(node) = graph.nodes.get_mut(step_id) {
                            node.metadata.insert(META_SCRIPT_BODY.into(), run.clone());
                        }
                    }
                }

                // Artifact-download detection. The known artifact-download
                // actions are flagged structurally so downstream rules can
                // correlate "download → interpret" pairs in the same job
                // without re-walking the YAML.
                if let Some(ref uses) = step.uses {
                    let action = uses.split('@').next().unwrap_or(uses);
                    if matches!(
                        action,
                        "actions/download-artifact" | "dawidd6/action-download-artifact"
                    ) {
                        if let Some(node) = graph.nodes.get_mut(step_id) {
                            node.metadata
                                .insert(META_DOWNLOADS_ARTIFACT.into(), "true".into());
                        }
                    }
                }

                // Artifact graph edges: upload → Produces, download → Consumes.
                // These let artifact_boundary_crossing fire when an untrusted
                // producer step hands off to a privileged consumer step.
                if let Some(ref uses) = step.uses {
                    let action = uses.split('@').next().unwrap_or(uses);
                    if action == "actions/upload-artifact" {
                        // Only create an artifact edge when `name:` is explicitly
                        // set. Anonymous uploads (no name) can't be correlated with
                        // a specific download and would silently merge unrelated
                        // jobs — skip them to avoid false positives.
                        if let Some(artifact_name) = step
                            .with
                            .as_ref()
                            .and_then(|w| w.get("name"))
                            .and_then(yaml_scalar_to_string)
                        {
                            // Artifact inherits the producer step's trust zone so
                            // future rules checking the artifact node see the right
                            // provenance (BUG-3 fix).
                            let art_id = find_or_create_artifact(
                                &mut graph,
                                &mut artifact_ids,
                                &artifact_name,
                                trust_zone,
                            );
                            graph.add_edge(step_id, art_id, EdgeKind::Produces);
                        }
                    } else if matches!(
                        action,
                        "actions/download-artifact" | "dawidd6/action-download-artifact"
                    ) {
                        // Same rationale: omitting `name:` means "download all
                        // artifacts" (wildcard), which we can't correlate to a
                        // specific producer — skip to avoid incorrect Consumes
                        // edges — skip to avoid incorrect Consumes edges.
                        if let Some(artifact_name) = step
                            .with
                            .as_ref()
                            .and_then(|w| w.get("name"))
                            .and_then(yaml_scalar_to_string)
                        {
                            // If the upload step hasn't been seen yet, use Untrusted
                            // as a conservative default. The zone will be correct when
                            // the upload is processed first (the common cross-job flow).
                            let art_id = find_or_create_artifact(
                                &mut graph,
                                &mut artifact_ids,
                                &artifact_name,
                                TrustZone::Untrusted,
                            );
                            graph.add_edge(art_id, step_id, EdgeKind::Consumes);
                        }
                    }
                }

                // Artifact-interpretation detection. A step that pipes a file
                // into a privileged sink (`>> $GITHUB_ENV`/`>> $GITHUB_OUTPUT`,
                // `eval`, `unzip`/`tar -x`, or `cat`/`jq`-with-redirect) is
                // treated as an interpreter of any artifact downloaded earlier
                // in the same job. Mirrors the existing GITHUB_ENV gate logic
                // — broad substring match keeps the rule deterministic.
                if let Some(ref run) = step.run {
                    let interprets = run.contains("unzip ")
                        || run.contains("unzip\n")
                        || run.contains("tar -x")
                        || run.contains("tar x")
                        || run.contains(" eval ")
                        || run.contains("\neval ")
                        || run.starts_with("eval ")
                        || run.contains(" cat ")
                        || run.contains("\ncat ")
                        || run.starts_with("cat ")
                        || run.contains("jq ");
                    if interprets {
                        if let Some(node) = graph.nodes.get_mut(step_id) {
                            node.metadata
                                .insert(META_INTERPRETS_ARTIFACT.into(), "true".into());
                        }
                    }
                }
                // actions/github-script bodies that post comments back to PRs
                // are also considered interpretation sinks — the `script:` body
                // typically reads a downloaded file and posts its content.
                if let Some(ref uses) = step.uses {
                    let action = uses.split('@').next().unwrap_or(uses);
                    if action == "actions/github-script" {
                        if let Some(with) = step.with.as_ref() {
                            if let Some(script) = with.get("script").and_then(yaml_scalar_to_string)
                            {
                                let posts_comment = script.contains("createComment")
                                    || script.contains("updateComment")
                                    || script.contains("createCommitComment")
                                    || script.contains("createReview");
                                let reads_file = script.contains("readFileSync")
                                    || script.contains("readFile(")
                                    || script.contains("require('fs')")
                                    || script.contains("require(\"fs\")");
                                if posts_comment && reads_file {
                                    if let Some(node) = graph.nodes.get_mut(step_id) {
                                        node.metadata
                                            .insert(META_INTERPRETS_ARTIFACT.into(), "true".into());
                                    }
                                }
                            }
                        }
                    }
                }

                // Build the EFFECTIVE per-step env map by merging workflow ⊕
                // job ⊕ step (step wins, then job, then workflow). GHA semantics:
                // a step-level `env: { K: literal }` SHADOWS the workflow- or
                // job-level value of `K` for that step at runtime. If we add
                // HasAccessTo edges from each scope independently, a literal
                // shadow at the step level still leaves a phantom edge to the
                // outer secret — a false positive. Merge first, then emit edges
                // only for the effective values.
                //
                // If step.env is a template expression, we cannot statically
                // know which keys it covers — mark Partial once and fall back
                // to the workflow⊕job effective map (best-effort, but at least
                // we record the gap).
                //
                // Iterate keys in sorted order so secret-node creation order
                // is deterministic across runs (HashMap iteration is randomised
                // per process; secret IDs leak that randomness into the JSON
                // output otherwise).
                let step_env_template = matches!(step.env.as_ref(), Some(EnvSpec::Template(_)));
                if step_env_template {
                    graph.mark_partial(
                        GapKind::Expression,
                        format!(
                            "step '{step_name}' in job '{job_name}' env: uses template expression — environment variable shape unknown"
                        ),
                    );
                }

                let mut effective_env: HashMap<String, String> = HashMap::new();
                if let Some(env_map) = workflow.env.as_ref().and_then(EnvSpec::as_map) {
                    for (k, v) in env_map {
                        effective_env.insert(k.clone(), v.clone());
                    }
                }
                if let Some(env_map) = job.env.as_ref().and_then(EnvSpec::as_map) {
                    for (k, v) in env_map {
                        effective_env.insert(k.clone(), v.clone());
                    }
                }
                if let Some(EnvSpec::Map(env_map)) = step.env.as_ref() {
                    for (k, v) in env_map {
                        effective_env.insert(k.clone(), v.clone());
                    }
                }

                let mut effective_entries: Vec<(&String, &String)> = effective_env.iter().collect();
                effective_entries.sort_by(|a, b| a.0.cmp(b.0));
                if !effective_entries.is_empty() {
                    let rendered_env: Vec<String> = effective_entries
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect();
                    if let Some(node) = graph.nodes.get_mut(step_id) {
                        node.metadata
                            .insert(META_GHA_ENV_ASSIGNMENTS.into(), rendered_env.join("\n"));
                    }
                }
                for (_k, env_val) in effective_entries {
                    // Walk every `secrets.X` reference inside the value's
                    // template spans — concatenated multi-secret values
                    // (`${{ secrets.A }}-${{ secrets.B }}`) yield BOTH names.
                    for secret_name in iter_secret_refs(env_val) {
                        let secret_id =
                            find_or_create_secret(&mut graph, &mut secret_ids, secret_name);
                        graph.add_edge(step_id, secret_id, EdgeKind::HasAccessTo);
                    }
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
                    let mut entries: Vec<(&String, &serde_yaml::Value)> = with.iter().collect();
                    entries.sort_by(|a, b| a.0.cmp(b.0));
                    for (_k, val) in entries {
                        // Multi-secret-aware: a single `with:` value may
                        // concatenate several secrets (`${{ secrets.A }}-${{ secrets.B }}`).
                        for scalar in yaml_scalar_strings(val) {
                            for secret_name in iter_secret_refs(&scalar) {
                                let secret_id =
                                    find_or_create_secret(&mut graph, &mut secret_ids, secret_name);
                                graph.add_edge(step_id, secret_id, EdgeKind::HasAccessTo);
                            }
                            if is_env_reference(&scalar) {
                                reads_env = true;
                            }
                        }
                    }
                    if reads_env {
                        if let Some(node) = graph.nodes.get_mut(step_id) {
                            node.metadata.insert(META_READS_ENV.into(), "true".into());
                        }
                    }
                }

                // Stamp the raw `run:` body as META_SCRIPT_BODY so script-aware
                // rules (script_injection_via_untrusted_context, gh_cli_with_default_token_escalating, …)
                // can pattern-match against it without re-parsing the YAML.
                if let Some(ref run) = step.run {
                    if !run.is_empty() {
                        if let Some(node) = graph.nodes.get_mut(step_id) {
                            node.metadata.insert(META_SCRIPT_BODY.into(), run.clone());
                        }
                    }
                }

                // For `actions/github-script`, the JS body lives in `with.script:`.
                // Stamp it as META_SCRIPT_BODY too — the same script-injection
                // patterns apply (interpolation of github.event.* into JS code).
                if let Some(ref uses) = step.uses {
                    let action = uses.split('@').next().unwrap_or(uses);
                    if action == "actions/github-script" {
                        if let Some(with) = step.with.as_ref() {
                            if let Some(script) = with.get("script").and_then(yaml_scalar_to_string)
                            {
                                if !script.is_empty() {
                                    if let Some(node) = graph.nodes.get_mut(step_id) {
                                        node.metadata.insert(META_SCRIPT_BODY.into(), script);
                                    }
                                }
                            }
                        }
                    }
                }

                // Interactive debug actions (tmate / upterm) — stamp the action ref so
                // `interactive_debug_action_in_authority_workflow` can flag it without
                // re-walking the steps. Match by action prefix (any version).
                if let Some(ref uses) = step.uses {
                    let action = uses.split('@').next().unwrap_or(uses);
                    let is_debug = matches!(
                        action,
                        "mxschmitt/action-tmate"
                            | "lhotari/action-upterm"
                            | "actions/tmate"
                            | "owenthereal/action-upterm"
                            | "csexton/debugger-action"
                    );
                    if is_debug {
                        if let Some(node) = graph.nodes.get_mut(step_id) {
                            node.metadata
                                .insert(META_INTERACTIVE_DEBUG.into(), uses.clone());
                        }
                    }
                }

                // `actions/cache` — stamp the `key:` input so the cache-poisoning
                // rule can pattern-match against PR-derived expressions
                // (github.head_ref / event.pull_request.head.ref / actor).
                // Covers the top-level action and the save/restore variants.
                if let Some(ref uses) = step.uses {
                    let action = uses.split('@').next().unwrap_or(uses);
                    let is_cache = matches!(
                        action,
                        "actions/cache" | "actions/cache/save" | "actions/cache/restore"
                    );
                    if is_cache {
                        if let Some(with) = step.with.as_ref() {
                            if let Some(key) = with.get("key").and_then(yaml_scalar_to_string) {
                                if !key.is_empty() {
                                    if let Some(node) = graph.nodes.get_mut(step_id) {
                                        node.metadata.insert(META_CACHE_KEY.into(), key);
                                    }
                                }
                            }
                        }
                    }
                }

                // Detect inferred secrets in `run:` script blocks. Only counts
                // `secrets.X` references that appear INSIDE a `${{ … }}` template
                // span — literal substrings in shell paths or comments
                // (`# loads /etc/secrets.conf`, `cp $SECRETS_DIR/secrets.json`)
                // do not produce phantom Secret nodes.
                if let Some(ref run) = step.run {
                    // Collect names first to avoid borrowing `run` while we
                    // mutate `graph`, and to dedupe per-step (a single run
                    // body that mentions `secrets.X` 5× still needs only one
                    // HasAccessTo edge).
                    let mut seen: std::collections::BTreeSet<&str> =
                        std::collections::BTreeSet::new();
                    for name in iter_secret_refs(run) {
                        seen.insert(name);
                    }
                    for secret_name in seen {
                        let secret_id =
                            find_or_create_secret(&mut graph, &mut secret_ids, secret_name);
                        // Mark as inferred — not precisely mapped.
                        if let Some(node) = graph.nodes.get_mut(secret_id) {
                            node.metadata
                                .insert(META_INFERRED.into(), META_INFERRED_VAL.into());
                        }
                        graph.add_edge(step_id, secret_id, EdgeKind::HasAccessTo);
                        graph.mark_partial(
                            GapKind::Expression,
                            format!(
                                "secret '{secret_name}' referenced in run: script — inferred, not precisely mapped"
                            ),
                        );
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

            // ── Job outputs (`jobs.<id>.outputs.<name>: <expression>`) ──────
            // Classify each output value by source so R4
            // (sensitive_value_in_job_output) can fire on credentials whose
            // values land in the unmasked `needs.<job>.outputs.*` channel.
            if let Some(outputs) = job.outputs.as_ref() {
                // Sort by output name so META_JOB_OUTPUTS is byte-deterministic
                // across runs. `outputs` is a HashMap (randomised iteration);
                // mirror the v1.1.0-beta.1 pattern used elsewhere.
                let mut output_entries: Vec<(&String, &String)> = outputs.iter().collect();
                output_entries.sort_by(|a, b| a.0.cmp(b.0));
                for (out_name, out_value) in output_entries {
                    let source = classify_job_output_source(out_value, &step_oidc_by_yaml_id);
                    job_output_records.push(format!("{job_name}\t{out_name}\t{source}"));
                }
            }
        }

        if !job_output_records.is_empty() {
            graph
                .metadata
                .insert(META_JOB_OUTPUTS.into(), job_output_records.join("|"));
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
                GapKind::Structural,
                "jobs: parsed but produced 0 step nodes — possible non-GHA YAML wrong-platform-classified".to_string(),
            );
        }

        graph.stamp_edge_authority_summaries();
        Ok(graph)
    }
}

/// Classify a `jobs.<id>.outputs.<name>` value by its highest-risk source.
/// Order of precedence: `secret` > `oidc` > `step_output` > `literal`. Strict
/// substring scanning — covers every quoting variant GHA accepts because the
/// expression body always contains `secrets.X` or `steps.X.outputs.Y`
/// verbatim regardless of whitespace inside `${{ … }}`.
fn classify_job_output_source(
    value: &str,
    step_oidc_by_yaml_id: &HashMap<String, bool>,
) -> &'static str {
    if value.contains("secrets.") {
        return "secret";
    }
    // Look for `steps.<id>.outputs.` and check each referenced step's OIDC bit.
    let mut cursor = 0;
    let mut saw_step_output = false;
    while let Some(rel) = value[cursor..].find("steps.") {
        let abs = cursor + rel + "steps.".len();
        let rest = &value[abs..];
        // Step id terminates at `.` (we expect `.outputs.` to follow).
        let id_end = rest
            .find(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
            .unwrap_or(rest.len());
        let step_yaml_id = &rest[..id_end];
        if !step_yaml_id.is_empty() && rest[id_end..].starts_with(".outputs.") {
            saw_step_output = true;
            if step_oidc_by_yaml_id
                .get(step_yaml_id)
                .copied()
                .unwrap_or(false)
            {
                return "oidc";
            }
        }
        cursor = abs + id_end;
    }
    if saw_step_output {
        "step_output"
    } else {
        "literal"
    }
}

/// Returns true if the workflow's `on:` triggers include `pull_request_target`.
/// GHA `on:` is polymorphic: string, sequence, or mapping.
/// Returns true when a GHA `if:` expression matches the standard fork-check
/// pattern: `github.event.pull_request.head.repo.fork == false` (or the
/// negated `!= true`), or the equivalent
/// `github.event.pull_request.head.repo.full_name == github.repository`.
/// Whitespace is normalised before matching so the canonical Grafana form
/// (`if: github.event.pull_request.head.repo.full_name == github.repository`)
/// is detected alongside the more terse `repo.fork == false` variant.
///
/// The check is conservative — it requires the canonical predicate on the
/// raw expression. Wrapping the predicate inside a larger boolean
/// expression that ANDs additional clauses (e.g. `&& github.actor != ...`)
/// is still detected because the substring match on the canonical form is
/// preserved. ORing it away (`|| true`) would defeat the check, but that
/// pattern is not seen in practice and would itself be a code-review red
/// flag.
pub fn is_fork_check_expression(expr: &str) -> bool {
    let normalised: String = expr.split_whitespace().collect::<Vec<_>>().join(" ");
    let lower = normalised.to_lowercase();
    // `repo.fork == false` (and the negated `!= true`)
    if lower.contains("github.event.pull_request.head.repo.fork == false")
        || lower.contains("github.event.pull_request.head.repo.fork != true")
    {
        return true;
    }
    // `head.repo.full_name == github.repository` — Grafana canonical form.
    // Tolerate either ordering of the equality operands.
    if lower.contains("github.event.pull_request.head.repo.full_name == github.repository")
        || lower.contains("github.repository == github.event.pull_request.head.repo.full_name")
    {
        return true;
    }
    false
}

fn trigger_has_pull_request_target(triggers: &serde_yaml::Value) -> bool {
    collect_trigger_names(Some(triggers))
        .iter()
        .any(|t| t == "pull_request_target")
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

/// Extract the list of `workflow_dispatch.inputs.<name>` keys declared by a
/// workflow. Returns an empty Vec if `on:` is not a mapping, has no
/// `workflow_dispatch` entry, or the entry has no `inputs:` mapping.
fn collect_dispatch_inputs(triggers: &serde_yaml::Value) -> Vec<String> {
    let map = match triggers {
        serde_yaml::Value::Mapping(m) => m,
        _ => return Vec::new(),
    };
    let dispatch = match map
        .iter()
        .find(|(k, _)| k.as_str() == Some("workflow_dispatch"))
    {
        Some((_, v)) => v,
        None => return Vec::new(),
    };
    let inputs = match dispatch.get("inputs").and_then(|v| v.as_mapping()) {
        Some(m) => m,
        None => return Vec::new(),
    };
    inputs
        .iter()
        .filter_map(|(k, _)| k.as_str().map(str::to_string))
        .collect()
}

/// Extract the list of `workflow_call.inputs.<name>` keys declared by a
/// reusable workflow. Returns an empty Vec if `on:` is not a mapping, has no
/// `workflow_call` trigger, or the trigger has no `inputs:` mapping.
fn collect_workflow_call_inputs(triggers: &serde_yaml::Value) -> Vec<String> {
    let map = match triggers {
        serde_yaml::Value::Mapping(m) => m,
        _ => return Vec::new(),
    };
    let call = match map
        .iter()
        .find(|(k, _)| k.as_str() == Some("workflow_call"))
    {
        Some((_, v)) => v,
        None => return Vec::new(),
    };
    let inputs = match call.get("inputs").and_then(|v| v.as_mapping()) {
        Some(m) => m,
        None => return Vec::new(),
    };
    inputs
        .iter()
        .filter_map(|(k, _)| k.as_str().map(str::to_string))
        .collect()
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
    let semantically_pinned = is_pin_semantically_valid(uses);
    let is_local = uses.starts_with("./");

    let zone = if is_local {
        TrustZone::FirstParty
    } else if semantically_pinned {
        TrustZone::ThirdParty
    } else {
        TrustZone::Untrusted
    };

    let mut meta = HashMap::new();
    // Record digest metadata if structurally pinned (even if semantically
    // invalid — the SHA is still useful for diagnostics/display).
    if is_sha_pinned(uses) {
        if let Some(sha) = uses.split('@').next_back() {
            meta.insert(META_DIGEST.into(), sha.into());
        }
    }

    let id = graph.add_node_with_metadata(NodeKind::Image, uses, zone, meta);
    (zone, id)
}

/// Yields every `secrets.<name>` reference found INSIDE any `${{ … }}` template
/// span in the input. Whitespace-tolerant (handles `${{secrets.X}}`,
/// `${{ secrets.X }}`, `${{   secrets.X   }}`, tabs, newlines). Handles
/// concatenated multi-secret values (`${{ secrets.A }}-${{ secrets.B }}` yields
/// both `A` and `B`). Does NOT match literal `secrets.X` substrings outside
/// template spans (shell paths, comments, JSON file names like `secrets.json`).
///
/// UTF-8-aware: uses `char_indices`, never byte arithmetic into the middle of a
/// multi-byte sequence. Zero regex — keeps the parser ReDoS-free.
///
/// Implementation: scan for `${{` opens, find the matching `}}` close (or end
/// of string if unterminated), then scan only the inner span for `secrets.`
/// followed by an identifier (`[A-Za-z0-9_]+`). The identifier terminates at
/// the first non-identifier char, which catches `secrets.A }}-${{ secrets.B`,
/// `secrets.A || secrets.B`, etc.
fn iter_secret_refs(s: &str) -> impl Iterator<Item = &str> {
    SecretRefIter {
        src: s,
        cursor: 0,
        // When inside a template span, this is `Some(end_byte_offset)`.
        // When outside, this is `None`.
        span_end: None,
    }
}

struct SecretRefIter<'a> {
    src: &'a str,
    cursor: usize,
    span_end: Option<usize>,
}

impl<'a> Iterator for SecretRefIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        loop {
            // If we're not inside a template span, find the next one.
            if self.span_end.is_none() {
                let rel = self.src.get(self.cursor..)?.find("${{")?;
                let span_start = self.cursor + rel + 3; // skip "${{"
                                                        // Locate the matching "}}" so we only scan WITHIN this template.
                                                        // GHA does not nest `${{`, so a flat search is correct.
                let inner = &self.src[span_start..];
                let span_len = inner.find("}}").unwrap_or(inner.len());
                self.cursor = span_start;
                self.span_end = Some(span_start + span_len);
            }
            let span_end = self.span_end.expect("span_end set just above");

            if self.cursor >= span_end {
                // Done with this span — advance past `}}` (2 bytes) and resume.
                self.cursor = span_end.saturating_add(2).min(self.src.len());
                self.span_end = None;
                continue;
            }
            let window = &self.src[self.cursor..span_end];
            let Some(rel) = window.find("secrets.") else {
                self.cursor = span_end.saturating_add(2).min(self.src.len());
                self.span_end = None;
                continue;
            };
            let name_start = self.cursor + rel + "secrets.".len();
            // Identifier terminates at first non-[A-Za-z0-9_] char (or span end).
            let tail = &self.src[name_start..span_end];
            let name_len = tail
                .char_indices()
                .find(|(_, c)| !c.is_ascii_alphanumeric() && *c != '_')
                .map(|(i, _)| i)
                .unwrap_or(tail.len());
            // Advance cursor past this identifier so the next call resumes
            // after it (lets us find a second secret in the same span).
            self.cursor = name_start + name_len;
            if name_len == 0 {
                // `secrets.` followed by no identifier — skip and continue.
                continue;
            }
            return Some(&self.src[name_start..name_start + name_len]);
        }
    }
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

fn find_or_create_artifact(
    graph: &mut AuthorityGraph,
    cache: &mut HashMap<String, NodeId>,
    name: &str,
    zone: TrustZone,
) -> NodeId {
    if let Some(&id) = cache.get(name) {
        return id;
    }
    let id = graph.add_node(NodeKind::Artifact, name, zone);
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
    with: Option<&HashMap<String, serde_yaml::Value>>,
    graph: &mut AuthorityGraph,
) -> Option<NodeId> {
    // Strip `@version` — match any version of the action
    let action = uses.split('@').next().unwrap_or(uses);

    match action {
        "aws-actions/configure-aws-credentials" => {
            // OIDC path: role-to-assume present (no static access key needed)
            let w = with?;
            let role = w.get("role-to-assume").and_then(yaml_scalar_to_string)?;
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
            let provider = w
                .get("workload_identity_provider")
                .and_then(yaml_scalar_to_string)?;
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
            let client_id = w.get("client-id").and_then(yaml_scalar_to_string)?;
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
///
/// The map variant uses `BTreeMap` (not `HashMap`) so the rendered
/// `Display` output (`{ contents: read, id-token: write }`) is sorted by
/// scope name and byte-deterministic across runs. `META_PERMISSIONS` is
/// emitted into JSON / SARIF / `taudit map` text directly, and a HashMap's
/// randomised iteration order otherwise leaks into every artifact. The
/// substring check at the workflow- and job-permissions emission sites
/// (`perm_string.contains("id-token: write")`) still works — BTreeMap
/// produces the same `key: value` shape, just sorted.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Permissions {
    String(String),
    Map(BTreeMap<String, String>),
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

fn yaml_scalar_to_string(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        serde_yaml::Value::Null => Some(String::new()),
        _ => None,
    }
}

fn yaml_value_compact(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::Sequence(seq) => {
            let parts: Vec<String> = seq.iter().filter_map(yaml_scalar_to_string).collect();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(","))
            }
        }
        serde_yaml::Value::Mapping(map) => {
            let mut parts: Vec<String> = map
                .iter()
                .filter_map(|(k, v)| {
                    Some(format!(
                        "{}={}",
                        yaml_scalar_to_string(k)?,
                        yaml_value_compact(v)?
                    ))
                })
                .collect();
            parts.sort();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(","))
            }
        }
        scalar => yaml_scalar_to_string(scalar),
    }
}

fn yaml_value_is_empty(value: &serde_yaml::Value) -> bool {
    match value {
        serde_yaml::Value::Null => true,
        serde_yaml::Value::String(s) => s.trim().is_empty(),
        serde_yaml::Value::Sequence(seq) => seq.is_empty(),
        serde_yaml::Value::Mapping(map) => map.is_empty(),
        _ => false,
    }
}

fn combined_condition(job_if: Option<&str>, step_if: Option<&str>) -> Option<String> {
    match (job_if, step_if) {
        (Some(job), Some(step)) if !job.is_empty() && !step.is_empty() => {
            Some(format!("{job} AND {step}"))
        }
        (Some(job), _) if !job.is_empty() => Some(job.to_string()),
        (_, Some(step)) if !step.is_empty() => Some(step.to_string()),
        _ => None,
    }
}

fn yaml_scalar_strings(value: &serde_yaml::Value) -> Vec<String> {
    match value {
        serde_yaml::Value::Sequence(seq) => seq.iter().filter_map(yaml_scalar_to_string).collect(),
        serde_yaml::Value::Mapping(map) => map.values().filter_map(yaml_scalar_to_string).collect(),
        scalar => yaml_scalar_to_string(scalar).into_iter().collect(),
    }
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
    Full {
        image: String,
        #[serde(default)]
        options: Option<String>,
        #[serde(default)]
        credentials: Option<Box<serde_yaml::Value>>,
        #[serde(default)]
        ports: Option<Box<serde_yaml::Value>>,
        #[serde(default)]
        volumes: Option<Box<serde_yaml::Value>>,
    },
}

impl ContainerConfig {
    pub fn image(&self) -> &str {
        match self {
            ContainerConfig::Image(s) => s,
            ContainerConfig::Full { image, .. } => image,
        }
    }

    pub fn options(&self) -> Option<&str> {
        match self {
            ContainerConfig::Image(_) => None,
            ContainerConfig::Full { options, .. } => options.as_deref(),
        }
    }

    fn unsupported_static_fields(&self) -> Vec<&'static str> {
        let ContainerConfig::Full {
            credentials,
            ports,
            volumes,
            ..
        } = self
        else {
            return Vec::new();
        };

        let mut fields = Vec::new();
        if credentials
            .as_ref()
            .is_some_and(|value| !yaml_value_is_empty(value))
        {
            fields.push("container credentials");
        }
        if ports
            .as_ref()
            .is_some_and(|value| !yaml_value_is_empty(value))
        {
            fields.push("container ports");
        }
        if volumes
            .as_ref()
            .is_some_and(|value| !yaml_value_is_empty(value))
        {
            fields.push("container volumes");
        }
        fields
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
    /// `with:` inputs passed to a reusable workflow call.
    #[serde(rename = "with", default)]
    pub with: Option<HashMap<String, serde_yaml::Value>>,
    /// `secrets:` block on a reusable-workflow `uses:` call. Polymorphic:
    /// the literal string `inherit` (`secrets: inherit`) or a mapping of
    /// secret-name → expression (`secrets: { TOKEN: ${{ secrets.X }} }`).
    /// We accept it as opaque YAML and inspect the variant in the parser.
    #[serde(default)]
    pub secrets: Option<serde_yaml::Value>,
    /// Job container image.
    #[serde(default)]
    pub container: Option<ContainerConfig>,
    /// Service containers are a separate execution surface. v1.2.0-rc.1
    /// records a typed structural gap rather than silently claiming support.
    #[serde(default)]
    pub services: Option<serde_yaml::Value>,
    /// Matrix/strategy configuration. When a matrix is present, the authority
    /// shape may differ per matrix entry — graph is marked Partial.
    #[serde(default)]
    pub strategy: Option<serde_yaml::Value>,
    /// Runner label(s). Can be a string (`ubuntu-latest`), a sequence
    /// (`[self-hosted, linux]`), or absent for reusable workflows.
    #[serde(rename = "runs-on", default)]
    pub runs_on: Option<serde_yaml::Value>,
    /// `jobs.<id>.outputs:` map (output name → expression). Captured for the
    /// `sensitive_value_in_job_output` rule which inspects each value for
    /// `secrets.*` / `steps.*.outputs.*` references and credential-shaped
    /// names. Empty / absent for jobs that declare no outputs.
    #[serde(default)]
    pub outputs: Option<HashMap<String, String>>,
    /// Job-level `if:` condition. Captured verbatim so rules can scan for
    /// the standard fork-check pattern
    /// (`github.event.pull_request.head.repo.fork == false` or the
    /// equivalent `head.repo.full_name == github.repository`). Job-level
    /// `if:` applies to every step the job contains.
    #[serde(rename = "if", default)]
    pub if_cond: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GhaStep {
    pub name: Option<String>,
    /// Optional YAML `id:` — the symbolic name used by `steps.<id>.outputs.*`
    /// references in expressions. Captured so output-flow rules can resolve
    /// which step produced a referenced output.
    pub id: Option<String>,
    pub uses: Option<String>,
    pub run: Option<String>,
    /// Step-level env vars. Polymorphic: typically a map, but can be a
    /// template expression (e.g. `env: ${{ matrix }}`) whose shape is unknown
    /// statically.
    #[serde(default)]
    pub env: Option<EnvSpec>,
    #[serde(rename = "with", default)]
    pub with: Option<HashMap<String, serde_yaml::Value>>,
    /// Step-level `if:` condition. Captured verbatim so rules can detect
    /// the standard fork-check pattern.
    #[serde(rename = "if", default)]
    pub if_cond: Option<String>,
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
    fn uses_step_records_action_and_scalar_with_inputs() {
        let yaml = r#"
jobs:
  deploy:
    steps:
      - uses: aws-actions/amazon-ecr-login@v2
        with:
          mask-password: false
          registries: "123456789012"
"#;
        let graph = parse(yaml);
        let step = graph
            .nodes_of_kind(NodeKind::Step)
            .find(|n| n.name == "deploy[0]")
            .expect("uses step");
        assert_eq!(
            step.metadata.get(META_GHA_ACTION).map(String::as_str),
            Some("aws-actions/amazon-ecr-login")
        );
        let inputs = step
            .metadata
            .get(META_GHA_WITH_INPUTS)
            .expect("with inputs");
        assert!(inputs.contains("mask-password=false"));
        assert!(inputs.contains("registries=123456789012"));
    }

    #[test]
    fn parser_stamps_new_exploit_rule_metadata() {
        let yaml = r#"
on:
  workflow_call:
    inputs:
      image:
        type: string
jobs:
  call:
    uses: org/repo/.github/workflows/reuse.yml@main
    runs-on: ${{ inputs.runner }}
    secrets: inherit
    with:
      image: ${{ inputs.image }}
  deploy:
    runs-on: [ubuntu-latest]
    if: ${{ needs.plan.outputs.pr_run_mode == 'upload' }}
    env:
      NODE_OPTIONS: --require=./hook.js
    container:
      image: ${{ inputs.image }}
      options: --privileged
    steps:
      - name: Publish
        if: ${{ github.event_name == 'push' }}
        run: npm publish
"#;
        let graph = parse(yaml);
        assert_eq!(
            graph
                .metadata
                .get(META_GHA_WORKFLOW_CALL_INPUTS)
                .map(String::as_str),
            Some("image")
        );

        let call = graph
            .nodes_of_kind(NodeKind::Step)
            .find(|n| n.name == "call")
            .expect("synthetic reusable call step");
        assert_eq!(
            call.metadata.get(META_SECRETS_INHERIT).map(String::as_str),
            Some("true")
        );
        assert!(
            call.metadata
                .get(META_GHA_WITH_INPUTS)
                .map(|v| v.contains("image=${{ inputs.image }}"))
                .unwrap_or(false),
            "reusable-call with inputs should be stamped"
        );
        assert_eq!(
            call.metadata.get(META_GHA_RUNS_ON).map(String::as_str),
            Some("${{ inputs.runner }}")
        );

        let publish = graph
            .nodes_of_kind(NodeKind::Step)
            .find(|n| n.name == "Publish")
            .expect("publish step");
        assert!(
            publish
                .metadata
                .get(META_GHA_ENV_ASSIGNMENTS)
                .map(|v| v.contains("NODE_OPTIONS=--require=./hook.js"))
                .unwrap_or(false),
            "effective env assignments should be stamped on steps"
        );
        assert_eq!(
            publish.metadata.get(META_CONDITION).map(String::as_str),
            Some("${{ needs.plan.outputs.pr_run_mode == 'upload' }} AND ${{ github.event_name == 'push' }}")
        );

        let container = graph
            .nodes_of_kind(NodeKind::Image)
            .find(|n| n.metadata.get(META_CONTAINER).map(String::as_str) == Some("true"))
            .expect("container image node");
        assert_eq!(
            container
                .metadata
                .get(META_GHA_CONTAINER_OPTIONS)
                .map(String::as_str),
            Some("--privileged")
        );
    }

    #[test]
    fn with_non_scalar_values_do_not_fail_parse() {
        let yaml = r#"
jobs:
  check:
    steps:
      - name: Label
        uses: actions/github-script@v7
        with:
          script: |
            core.info("ok")
          labels:
            - bug
            - ci
          token: "${{ secrets.GITHUB_TOKEN }}"
"#;
        let graph = parse(yaml);
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert!(
            secrets.iter().any(|s| s.name == "GITHUB_TOKEN"),
            "scalar values inside with: must still be scanned for secrets"
        );
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
        // Inferred secret in a `run:` shell script — the structure is intact,
        // a value-shaped reference hides behind a shell-script expression.
        assert!(
            graph.completeness_gap_kinds.contains(&GapKind::Expression),
            "inferred secret in run: must record an Expression-kind gap, got: {:?}",
            graph.completeness_gap_kinds
        );
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
        // Matrix is a runtime expression hiding values across job instances —
        // the graph structure for one matrix entry is intact.
        assert!(
            graph.completeness_gap_kinds.contains(&GapKind::Expression),
            "matrix strategy must record an Expression-kind gap, got: {:?}",
            graph.completeness_gap_kinds
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
        // Reusable workflow `uses:` is unresolvable here — the called workflow's
        // authority chain is invisible, which is a Structural gap, not an
        // expression substitution.
        assert!(
            graph.completeness_gap_kinds.contains(&GapKind::Structural),
            "reusable workflow must record a Structural-kind gap, got: {:?}",
            graph.completeness_gap_kinds
        );
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
    fn service_containers_and_container_credentials_mark_structural_partial() {
        let graph = parse(include_str!(
            "../../../tests/fixtures/gha-service-containers-and-credentials.yml"
        ));
        assert_eq!(
            graph.completeness,
            AuthorityCompleteness::Partial,
            "service containers and private container credentials are not fully modeled"
        );
        assert!(
            graph.completeness_gap_kinds.contains(&GapKind::Structural),
            "service/container execution surface gaps must be structural, got: {:?}",
            graph.completeness_gap_kinds
        );
        assert!(
            graph
                .completeness_gaps
                .iter()
                .any(|g| g.contains("service containers")),
            "service container gap should be explicit: {:?}",
            graph.completeness_gaps
        );
        assert!(
            graph
                .completeness_gaps
                .iter()
                .any(|g| g.contains("container credentials")),
            "job container credentials gap should be explicit: {:?}",
            graph.completeness_gaps
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
        let identities: Vec<_> = graph
            .nodes_of_kind(NodeKind::Identity)
            .filter(|n| n.name != "GITHUB_TOKEN")
            .collect();
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
        let identities: Vec<_> = graph
            .nodes_of_kind(NodeKind::Identity)
            .filter(|n| n.name != "GITHUB_TOKEN")
            .collect();
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
        let identities: Vec<_> = graph
            .nodes_of_kind(NodeKind::Identity)
            .filter(|n| n.name != "GITHUB_TOKEN")
            .collect();
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
        let identities: Vec<_> = graph
            .nodes_of_kind(NodeKind::Identity)
            .filter(|n| n.name != "GITHUB_TOKEN")
            .collect();
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
        let identities: Vec<_> = graph
            .nodes_of_kind(NodeKind::Identity)
            .filter(|n| n.name != "GITHUB_TOKEN")
            .collect();
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
    fn composite_action_reference_marks_graph_partial_without_inlining() {
        // Post-fix behaviour: composite-action references are NOT inlined.
        // Earlier versions walked the filesystem from the workflow's directory
        // looking for `action.yml`; that made the graph CWD-dependent. We now
        // mark the graph Partial with a Structural gap and never read disk.
        let dir = make_temp_dir("composite-no-inline");
        let workflows_dir = dir.join(".github/workflows");
        let action_dir = dir.join(".github/actions/my-action");
        std::fs::create_dir_all(&workflows_dir).unwrap();
        std::fs::create_dir_all(&action_dir).unwrap();

        // Real action.yml on disk — must be ignored.
        let action_yml = r#"
name: My Action
runs:
  using: composite
  steps:
    - name: Install deps
      run: npm install
      shell: bash
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

        // Only the calling step — no inlining.
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 1, "no composite-action step inlining");

        // Graph is Partial with a Structural gap mentioning the local action.
        assert_eq!(graph.completeness, AuthorityCompleteness::Partial);
        assert!(
            graph.completeness_gap_kinds.contains(&GapKind::Structural),
            "local action reference must record a Structural-kind gap, got: {:?}",
            graph.completeness_gap_kinds
        );
        assert!(
            graph
                .completeness_gaps
                .iter()
                .any(|g| g.contains("composite action not resolved")
                    && g.contains("./.github/actions/my-action")),
            "gap reason must name the action and explain non-resolution, got: {:?}",
            graph.completeness_gaps
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_action_yml_marks_graph_partial() {
        // Whether `action.yml` exists on disk is irrelevant after the fix —
        // any `./local-action` reference is treated as Partial without
        // touching the filesystem.
        let dir = make_temp_dir("missing-action");
        let workflows_dir = dir.join(".github/workflows");
        std::fs::create_dir_all(&workflows_dir).unwrap();

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
            graph.completeness_gaps.iter().any(
                |g| g.contains("composite action not resolved") && g.contains("missing-action")
            ),
            "missing local action must be recorded as a completeness gap, got: {:?}",
            graph.completeness_gaps
        );
        assert!(
            graph.completeness_gap_kinds.contains(&GapKind::Structural),
            "unresolved composite action must record a Structural-kind gap, got: {:?}",
            graph.completeness_gap_kinds
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_composite_local_action_marks_graph_partial() {
        // Post-fix: we don't read action.yml, so we cannot distinguish
        // composite from docker locally. Either way the answer is the same:
        // mark Partial and don't pretend to know what's inside.
        let dir = make_temp_dir("non-composite");
        let workflows_dir = dir.join(".github/workflows");
        let action_dir = dir.join(".github/actions/docker-action");
        std::fs::create_dir_all(&workflows_dir).unwrap();
        std::fs::create_dir_all(&action_dir).unwrap();

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
            graph.completeness_gap_kinds.contains(&GapKind::Structural),
            "local action reference must record a Structural-kind gap, got: {:?}",
            graph.completeness_gap_kinds
        );

        // Only the calling step exists — no inlined sub-steps.
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 1, "must not inline any sub-steps");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn composite_action_secrets_not_captured_after_partial_marking() {
        // Post-fix: secrets that live INSIDE a composite action's `action.yml`
        // are NOT visible to the parser (we don't read the file). The graph
        // is marked Partial so downstream rules know there's hidden authority.
        // This is the deliberate trade-off vs CWD-dependent inlining.
        let dir = make_temp_dir("composite-secrets-hidden");
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
            !secret_names.contains(&"DEPLOY_TOKEN"),
            "secret hidden inside composite action must NOT leak into the graph, got: {secret_names:?}"
        );
        assert_eq!(
            graph.completeness,
            AuthorityCompleteness::Partial,
            "composite action reference must mark graph Partial"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn step_env_literal_shadows_workflow_level_secret() {
        // regression: step.env shadowing must drop workflow/job-level secret
        // edges for the shadowed key
        //
        // GHA semantics: a step-level `env: { K: literal }` shadows the
        // workflow- or job-level value of `K` for that step. Earlier versions
        // emitted HasAccessTo edges from EACH scope independently, so a
        // literal shadow at the step level still left a phantom edge from the
        // step to the outer secret. After the fix, edges are emitted only for
        // the merged effective env map.
        let yaml = r#"
on: pull_request_target
env:
  TOKEN: ${{ secrets.PROD_TOKEN }}
jobs:
  build:
    steps:
      - run: ./scan.sh
        env:
          TOKEN: literal-non-secret
"#;
        let graph = parse(yaml);

        // The PROD_TOKEN secret node may or may not exist (deduplication
        // could keep it from being created at all). What MUST hold is: no
        // step has a HasAccessTo edge to a Secret node named PROD_TOKEN.
        let prod_token_id = graph
            .nodes_of_kind(NodeKind::Secret)
            .find(|n| n.name == "PROD_TOKEN")
            .map(|n| n.id);

        if let Some(secret_id) = prod_token_id {
            let leaks = graph
                .edges_to(secret_id)
                .filter(|e| e.kind == EdgeKind::HasAccessTo)
                .count();
            assert_eq!(
                leaks, 0,
                "step-level env literal must shadow workflow-level secret — \
                 expected 0 HasAccessTo edges to PROD_TOKEN, found {leaks}"
            );
        }
    }

    #[test]
    fn step_env_secret_shadows_workflow_level_secret() {
        // Variant of the shadowing test where step.env replaces the same key
        // with a DIFFERENT secret. The step must have access to the new
        // secret only — not the shadowed one.
        let yaml = r#"
on: pull_request_target
env:
  TOKEN: ${{ secrets.PROD_TOKEN }}
jobs:
  build:
    steps:
      - run: ./scan.sh
        env:
          TOKEN: ${{ secrets.STAGING_TOKEN }}
"#;
        let graph = parse(yaml);

        let secret_names: Vec<_> = graph
            .nodes_of_kind(NodeKind::Secret)
            .map(|s| s.name.clone())
            .collect();

        // STAGING_TOKEN must be present; PROD_TOKEN must not be reachable.
        assert!(
            secret_names.contains(&"STAGING_TOKEN".to_string()),
            "shadowing secret must be in the graph, got: {secret_names:?}"
        );

        let prod_id = graph
            .nodes_of_kind(NodeKind::Secret)
            .find(|n| n.name == "PROD_TOKEN")
            .map(|n| n.id);
        if let Some(prod_id) = prod_id {
            let leaks = graph
                .edges_to(prod_id)
                .filter(|e| e.kind == EdgeKind::HasAccessTo)
                .count();
            assert_eq!(
                leaks, 0,
                "step-level env secret must shadow workflow-level secret \
                 (no HasAccessTo edge to PROD_TOKEN), found {leaks}"
            );
        }
    }

    #[test]
    fn composite_action_resolution_does_not_depend_on_cwd() {
        // regression: composite-action resolution must not depend on CWD
        //
        // Before the fix, `resolve_local_action_path` walked up from
        // `pipeline_file`'s parent calling `Path::exists()` on disk; the same
        // YAML produced different graphs depending on (a) whether
        // `pipeline_file` was absolute or relative, (b) the binary's CWD,
        // (c) whether the consumer copied the YAML to a sandbox without the
        // surrounding repo. After the B1 fix, the parser never reads the
        // filesystem for composite actions — `./local-action` references are
        // unconditionally Partial.
        let dir = make_temp_dir("cwd-independence");
        let workflows_dir = dir.join(".github/workflows");
        let action_dir = dir.join(".github/actions/x");
        std::fs::create_dir_all(&workflows_dir).unwrap();
        std::fs::create_dir_all(&action_dir).unwrap();

        let action_yml = r#"
name: X
runs:
  using: composite
  steps:
    - run: echo hi
      shell: bash
"#;
        std::fs::write(action_dir.join("action.yml"), action_yml).unwrap();

        let workflow = r#"
jobs:
  ci:
    steps:
      - uses: ./.github/actions/x
"#;
        let workflow_path = workflows_dir.join("ci.yml");
        std::fs::write(&workflow_path, workflow).unwrap();

        // Parse 1: from CWD inside the temp dir, with a relative pipeline_file.
        let prev_cwd = std::env::current_dir().ok();
        std::env::set_current_dir(&dir).unwrap();
        let graph_inside = parse_at(workflow, ".github/workflows/ci.yml");
        if let Some(p) = prev_cwd {
            std::env::set_current_dir(p).unwrap();
        }

        // Parse 2: from outside the temp dir, with an absolute pipeline_file.
        let abs_workflow_path = workflow_path.to_str().unwrap().to_string();
        let graph_outside = parse_at(workflow, &abs_workflow_path);

        // B1: both must be Partial — composite action filesystem walking is
        // gone, so neither inlines.
        assert_eq!(
            graph_inside.completeness,
            AuthorityCompleteness::Partial,
            "graph parsed from inside the worktree must be Partial"
        );
        assert_eq!(
            graph_outside.completeness,
            AuthorityCompleteness::Partial,
            "graph parsed from outside the worktree must be Partial"
        );
        // CWD-independence: completeness values must match exactly.
        assert_eq!(
            graph_inside.completeness, graph_outside.completeness,
            "CWD-relative vs absolute pipeline_file must produce identical completeness"
        );
        // And neither path may inline composite-action sub-steps.
        assert_eq!(
            graph_inside.nodes_of_kind(NodeKind::Step).count(),
            1,
            "inside parse must not inline composite sub-steps"
        );
        assert_eq!(
            graph_outside.nodes_of_kind(NodeKind::Step).count(),
            1,
            "outside parse must not inline composite sub-steps"
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
    fn omitted_workflow_permissions_create_unknown_implicit_identity() {
        let yaml = r#"
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
            identities[0].metadata.get(META_IDENTITY_SCOPE).unwrap(),
            "unknown"
        );
        assert_eq!(identities[0].metadata.get(META_IMPLICIT).unwrap(), "true");
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
        // Job-level `env:` as a template expression is the canonical
        // Expression-kind gap — env shape is hidden, structure is intact.
        assert!(
            graph.completeness_gap_kinds.contains(&GapKind::Expression),
            "job-level env: template must record an Expression-kind gap, got: {:?}",
            graph.completeness_gap_kinds
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
        // `jobs:` parsed but produced 0 step nodes — the graph carrier is
        // missing entirely. Structural, because there are no recognisable
        // steps for the authority chain to attach to.
        assert!(
            graph.completeness_gap_kinds.contains(&GapKind::Structural),
            "0-step-nodes gap must be Structural, got: {:?}",
            graph.completeness_gap_kinds
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

    // -- B3 regression: all-zero SHA must not be treated as pinned --

    #[test]
    fn all_zero_sha_action_is_untrusted() {
        let yaml = r#"
jobs:
  ci:
    steps:
      - uses: actions/setup-python@0000000000000000000000000000000000000000
"#;
        let graph = parse(yaml);
        let images: Vec<_> = graph.nodes_of_kind(NodeKind::Image).collect();
        assert_eq!(images.len(), 1);
        assert_eq!(
            images[0].trust_zone,
            TrustZone::Untrusted,
            "all-zero SHA must be classified as Untrusted, not ThirdParty"
        );
    }

    #[test]
    fn real_sha_pinned_action_is_third_party() {
        // Non-zero 40-char hex SHA -- the normal legitimate case.
        let yaml = r#"
jobs:
  ci:
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
"#;
        let graph = parse(yaml);
        let images: Vec<_> = graph.nodes_of_kind(NodeKind::Image).collect();
        assert_eq!(images.len(), 1);
        assert_eq!(
            images[0].trust_zone,
            TrustZone::ThirdParty,
            "legitimate SHA-pinned action must be classified as ThirdParty"
        );
    }

    #[test]
    fn upload_artifact_creates_produces_edge() {
        let yaml = r#"
permissions:
  contents: read
jobs:
  build:
    steps:
      - uses: actions/upload-artifact@v4
        with:
          name: my-dist
          path: ./dist
"#;
        let graph = parse(yaml);
        let artifacts: Vec<_> = graph.nodes_of_kind(NodeKind::Artifact).collect();
        assert_eq!(
            artifacts.len(),
            1,
            "upload-artifact should create one Artifact node"
        );
        assert_eq!(artifacts[0].name, "my-dist");
        let produces_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Produces && e.to == artifacts[0].id)
            .collect();
        assert_eq!(
            produces_edges.len(),
            1,
            "upload step must have Produces edge to artifact"
        );
    }

    #[test]
    fn download_artifact_creates_consumes_edge() {
        let yaml = r#"
jobs:
  deploy:
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: my-dist
"#;
        let graph = parse(yaml);
        let artifacts: Vec<_> = graph.nodes_of_kind(NodeKind::Artifact).collect();
        assert_eq!(
            artifacts.len(),
            1,
            "download-artifact should create one Artifact node"
        );
        let consumes_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Consumes && e.from == artifacts[0].id)
            .collect();
        assert_eq!(
            consumes_edges.len(),
            1,
            "download step must have Consumes edge from artifact"
        );
    }

    #[test]
    fn upload_download_same_name_share_artifact_node() {
        let yaml = r#"
permissions:
  contents: read
jobs:
  build:
    steps:
      - uses: actions/upload-artifact@v4
        with:
          name: shared-dist
          path: ./dist
  deploy:
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: shared-dist
"#;
        let graph = parse(yaml);
        let artifacts: Vec<_> = graph.nodes_of_kind(NodeKind::Artifact).collect();
        assert_eq!(
            artifacts.len(),
            1,
            "same artifact name must reuse the same Artifact node"
        );
        let produces: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Produces)
            .collect();
        let consumes: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Consumes)
            .collect();
        assert_eq!(produces.len(), 1, "one Produces edge");
        assert_eq!(consumes.len(), 1, "one Consumes edge");
        assert_eq!(produces[0].to, artifacts[0].id);
        assert_eq!(consumes[0].from, artifacts[0].id);
    }

    #[test]
    fn upload_artifact_without_name_creates_no_edge() {
        // upload-artifact with no `name:` must not create an Artifact node or
        // Produces edge (anonymous uploads can't be correlated and would silently
        // merge unrelated jobs).
        let yaml = r#"
jobs:
  build:
    steps:
      - uses: actions/upload-artifact@v4
        with:
          path: ./dist
"#;
        let graph = parse(yaml);
        let artifacts: Vec<_> = graph.nodes_of_kind(NodeKind::Artifact).collect();
        assert!(
            artifacts.is_empty(),
            "upload-artifact without name: must not create an Artifact node; got: {artifacts:#?}"
        );
        let produces: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Produces)
            .collect();
        assert!(
            produces.is_empty(),
            "upload-artifact without name: must not create a Produces edge"
        );
    }

    #[test]
    fn download_artifact_without_name_creates_no_edge() {
        // download-artifact with no `name:` means "download all" (wildcard) —
        // we can't correlate it to a specific producer, so no Consumes edge
        // should be created.
        let yaml = r#"
jobs:
  deploy:
    steps:
      - uses: actions/download-artifact@v4
"#;
        let graph = parse(yaml);
        let consumes: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Consumes)
            .collect();
        assert!(
            consumes.is_empty(),
            "download-artifact without name: must not create a Consumes edge"
        );
    }

    // ── Regression: F1 (P1) ────────────────────────────────────────────────
    // The legacy run-script extractor matched every literal `secrets.X`
    // substring — comments and shell paths produced phantom Secret nodes
    // (`json`, `conf`). The fix walks only INSIDE `${{ … }}` template spans.
    #[test]
    fn secret_extractor_ignores_literal_substrings_outside_template_spans() {
        let yaml = r#"
jobs:
  deploy:
    steps:
      - name: Mixed shell + template
        run: |
          # loads /etc/secrets.conf
          cp $SECRETS_DIR/secrets.json /tmp/
          curl -H "Authorization: ${{ secrets.REAL_TOKEN }}" https://api.example.com
"#;
        let graph = parse(yaml);
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert_eq!(
            secrets.len(),
            1,
            "only `REAL_TOKEN` should be a Secret node — phantoms `conf`/`json` must not appear; got: {:?}",
            secrets.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
        assert_eq!(secrets[0].name, "REAL_TOKEN");
    }

    // ── Regression: F2 (P1) ────────────────────────────────────────────────
    // The previous `is_secret_reference` required the literal `${{ secrets.`
    // (one canonical space). GHA accepts every whitespace variant. This test
    // pins the tight, no-space form.
    #[test]
    fn secret_extractor_handles_tight_template_spacing() {
        let yaml = r#"
jobs:
  deploy:
    steps:
      - name: Tight template
        run: echo "x"
        env:
          TOK: "${{secrets.TIGHT}}"
"#;
        let graph = parse(yaml);
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "TIGHT");
        let secret_id = secrets[0].id;
        let edges = graph
            .edges_to(secret_id)
            .filter(|e| e.kind == EdgeKind::HasAccessTo)
            .count();
        assert_eq!(
            edges, 1,
            "tight `${{{{secrets.X}}}}` must produce HasAccessTo edge"
        );
    }

    // ── Regression: F3 (P1) ────────────────────────────────────────────────
    // The previous `extract_secret_name` returned ONLY the first secret per
    // value. Concatenated multi-secret values silently dropped the rest.
    #[test]
    fn secret_extractor_finds_all_secrets_in_concatenated_value() {
        let yaml = r#"
jobs:
  deploy:
    steps:
      - name: Concatenated
        run: echo "x"
        env:
          COMBINED: "${{ secrets.A }}-${{ secrets.B }}"
"#;
        let graph = parse(yaml);
        let secret_names: std::collections::BTreeSet<&str> = graph
            .nodes_of_kind(NodeKind::Secret)
            .map(|n| n.name.as_str())
            .collect();
        assert!(secret_names.contains("A"), "secret A must be detected");
        assert!(secret_names.contains("B"), "secret B must be detected");
        assert_eq!(
            secret_names.len(),
            2,
            "exactly two secrets, got: {secret_names:?}"
        );
        // Both edges from the step.
        for name in ["A", "B"] {
            let id = graph
                .nodes_of_kind(NodeKind::Secret)
                .find(|n| n.name == name)
                .expect("secret node")
                .id;
            let edges = graph
                .edges_to(id)
                .filter(|e| e.kind == EdgeKind::HasAccessTo)
                .count();
            assert!(edges >= 1, "missing HasAccessTo edge for secret {name}");
        }
    }

    // ── Regression: F6 (P1) ────────────────────────────────────────────────
    // Reusable workflow `secrets:` mapping form was silently dropped — only
    // the literal `inherit` string was honoured.
    #[test]
    fn reusable_workflow_secrets_mapping_form_propagates_edges() {
        let yaml = r#"
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    secrets:
      CHILD: ${{ secrets.PARENT }}
      OTHER: ${{ secrets.SECONDARY }}
"#;
        let graph = parse(yaml);
        let secret_names: std::collections::BTreeSet<&str> = graph
            .nodes_of_kind(NodeKind::Secret)
            .map(|n| n.name.as_str())
            .collect();
        assert!(
            secret_names.contains("PARENT"),
            "secrets: mapping value `${{{{ secrets.PARENT }}}}` must produce a Secret node; got: {secret_names:?}"
        );
        assert!(
            secret_names.contains("SECONDARY"),
            "secrets: mapping must iterate ALL keys, not just the first; got: {secret_names:?}"
        );
        // The synthetic step (named after the job) holds the HasAccessTo edges.
        let parent_id = graph
            .nodes_of_kind(NodeKind::Secret)
            .find(|n| n.name == "PARENT")
            .unwrap()
            .id;
        let edges = graph
            .edges_to(parent_id)
            .filter(|e| e.kind == EdgeKind::HasAccessTo)
            .count();
        assert!(edges >= 1, "synthetic step must HasAccessTo PARENT");
    }

    // ── Regression: F13 (P2) ───────────────────────────────────────────────
    // The synthetic step created for `job.uses:` skipped workflow-level env
    // secret edges. workflow.env IS in scope for the caller's evaluation of
    // a reusable-workflow call (the caller resolves `${{ secrets.X }}` /
    // `${{ env.X }}` BEFORE handing values to the callee).
    #[test]
    fn reusable_workflow_synthetic_step_inherits_workflow_env_secrets() {
        let yaml = r#"
env:
  GLOBAL_TOKEN: "${{ secrets.GLOBAL }}"
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
"#;
        let graph = parse(yaml);
        let global = graph
            .nodes_of_kind(NodeKind::Secret)
            .find(|n| n.name == "GLOBAL");
        assert!(
            global.is_some(),
            "workflow.env secret `GLOBAL` must produce a Secret node visible to the synthetic step"
        );
        let global_id = global.unwrap().id;
        let edges = graph
            .edges_to(global_id)
            .filter(|e| e.kind == EdgeKind::HasAccessTo)
            .count();
        assert!(
            edges >= 1,
            "synthetic step for reusable workflow must inherit workflow.env HasAccessTo edge"
        );
    }

    // ── Regression: F4 (P1) ────────────────────────────────────────────────
    // `META_JOB_OUTPUTS` was built by iterating a HashMap — randomised order
    // leaked into JSON / SARIF output. Multiple runs must produce a
    // byte-identical string.
    #[test]
    fn gha_meta_job_outputs_is_deterministic_across_runs() {
        let yaml = r#"
jobs:
  emit:
    runs-on: ubuntu-latest
    outputs:
      zebra: literal-z
      apple: literal-a
      mango: literal-m
      kilo: literal-k
      foxtrot: literal-f
    steps:
      - run: echo hi
"#;
        let mut prev: Option<String> = None;
        for i in 0..9 {
            let graph = parse(yaml);
            let cur = graph
                .metadata
                .get(META_JOB_OUTPUTS)
                .cloned()
                .unwrap_or_default();
            assert!(
                !cur.is_empty(),
                "META_JOB_OUTPUTS must be populated on a workflow with outputs"
            );
            if let Some(p) = &prev {
                assert_eq!(
                    p, &cur,
                    "META_JOB_OUTPUTS drifted on run {i}: {p:?} vs {cur:?}"
                );
            }
            prev = Some(cur);
        }
    }

    // ── Regression: F5 (P1) ────────────────────────────────────────────────
    // `Permissions::Map` rendered through HashMap iteration — order leaked
    // into META_PERMISSIONS in JSON / SARIF / `taudit map`. With a BTreeMap
    // backing the map variant, the rendered string is now sorted by key.
    #[test]
    fn gha_meta_permissions_is_deterministic_across_runs() {
        let yaml = r#"
permissions:
  contents: read
  id-token: write
  packages: write
  actions: read
  pull-requests: write
jobs:
  ci:
    steps:
      - run: echo hi
"#;
        let mut prev: Option<String> = None;
        for i in 0..9 {
            let graph = parse(yaml);
            let identities: Vec<_> = graph.nodes_of_kind(NodeKind::Identity).collect();
            assert_eq!(identities.len(), 1, "one GITHUB_TOKEN identity");
            let cur = identities[0]
                .metadata
                .get(META_PERMISSIONS)
                .cloned()
                .expect("META_PERMISSIONS must be stamped");
            if let Some(p) = &prev {
                assert_eq!(
                    p, &cur,
                    "META_PERMISSIONS drifted on run {i}: {p:?} vs {cur:?}"
                );
            }
            prev = Some(cur);
        }
    }
}
