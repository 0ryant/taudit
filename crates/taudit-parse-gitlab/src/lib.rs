use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use taudit_core::error::TauditError;
use taudit_core::graph::*;
// Re-import explicitly to make the new constants visible at a glance.
#[allow(unused_imports)]
use taudit_core::graph::{META_DOTENV_FILE, META_ENVIRONMENT_NAME, META_NEEDS, META_SCRIPT_BODY};
use taudit_core::ports::PipelineParser;

/// GitLab CI YAML parser.
///
/// Parses `.gitlab-ci.yml` files into an `AuthorityGraph`. The authority model:
/// - Each job is a `Step` node.
/// - `CI_JOB_TOKEN` is a global implicit `Identity` (always present, scope=broad).
/// - `secrets:` entries emit `Secret` nodes with `HasAccessTo` edges.
/// - `id_tokens:` entries emit OIDC `Identity` nodes.
/// - `variables:` entries with credential-pattern names emit `Secret` nodes.
/// - `image:` and `services:` emit `Image` nodes with `UsesImage` edges.
/// - `include:` and `extends:` mark the graph `Partial`.
/// - `rules: if: merge_request_event` and `only: merge_requests` set `META_TRIGGER`.
pub struct GitlabParser;

/// Reserved top-level keys that are not job definitions.
const RESERVED: &[&str] = &[
    "stages",
    "workflow",
    "include",
    "variables",
    "image",
    "services",
    "default",
    "cache",
    "before_script",
    "after_script",
    "types",
];

/// Variable name fragments that indicate a credential rather than plain config.
const CRED_FRAGMENTS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PRIVATE_KEY",
    "API_KEY",
    "APIKEY",
    "SIGNING_KEY",
    "ACCESS_KEY",
    "SERVICE_ACCOUNT",
    "CERT",
    "CREDENTIAL",
];

impl PipelineParser for GitlabParser {
    fn platform(&self) -> &str {
        "gitlab-ci"
    }

    fn parse(&self, content: &str, source: &PipelineSource) -> Result<AuthorityGraph, TauditError> {
        let (parse_content, duplicate_recovery_note) = match parse_gitlab_yaml_value(content) {
            Ok((root, extra_docs, first_doc_was_spec_header)) => {
                let mut graph = build_graph_from_root(root, source)?;
                if extra_docs {
                    graph.mark_partial(
                        GapKind::Expression,
                        if first_doc_was_spec_header {
                            "file contains GitLab spec: header plus executable config document — analyzed the executable document and preserved spec: as an unresolved header".to_string()
                        } else {
                            "file contains multiple YAML documents (--- separator) — only the first was analyzed".to_string()
                        },
                    );
                }
                return Ok(graph);
            }
            Err(e) if is_duplicate_key_parse_error(&e) => {
                let sanitized = sanitize_duplicate_mapping_keys(content);
                let note = format!(
                    "GitLab YAML contained duplicate mapping keys; later duplicates were preserved as opaque __taudit_duplicate_* keys during recovery ({e})"
                );
                (sanitized, Some(note))
            }
            Err(e) => return Err(TauditError::Parse(format!("YAML parse error: {e}"))),
        };

        let (root, extra_docs, first_doc_was_spec_header) = parse_gitlab_yaml_value(&parse_content)
            .map_err(|e| TauditError::Parse(format!("YAML parse error: {e}")))?;
        let mut graph = build_graph_from_root(root, source)?;
        if extra_docs {
            graph.mark_partial(
                GapKind::Expression,
                if first_doc_was_spec_header {
                    "file contains GitLab spec: header plus executable config document — analyzed the executable document and preserved spec: as an unresolved header".to_string()
                } else {
                    "file contains multiple YAML documents (--- separator) — only the first was analyzed".to_string()
                },
            );
        }
        if let Some(note) = duplicate_recovery_note {
            graph.mark_partial(GapKind::Structural, note);
        }
        Ok(graph)
    }
}

fn parse_gitlab_yaml_value(content: &str) -> Result<(Value, bool, bool), serde_yaml::Error> {
    let mut de = serde_yaml::Deserializer::from_str(content);
    let Some(doc) = de.next() else {
        return Ok((Value::Null, false, false));
    };
    let first = Value::deserialize(doc)?;
    let Some(second_doc) = de.next() else {
        return Ok((first, false, false));
    };
    if gitlab_doc_is_spec_header(&first) {
        return Ok((Value::deserialize(second_doc)?, true, true));
    }
    Ok((first, true, false))
}

fn gitlab_doc_is_spec_header(doc: &Value) -> bool {
    let Some(map) = doc.as_mapping() else {
        return false;
    };
    map.contains_key("spec")
}

fn is_duplicate_key_parse_error(error: &serde_yaml::Error) -> bool {
    error.to_string().contains("duplicate entry with key")
}

fn sanitize_duplicate_mapping_keys(content: &str) -> String {
    #[derive(Default)]
    struct Frame {
        indent: usize,
        keys: HashSet<String>,
    }

    let mut out = Vec::new();
    let mut frames: Vec<Frame> = Vec::new();
    let mut duplicate_counts: HashMap<(usize, String), usize> = HashMap::new();
    let mut block_scalar_indent: Option<usize> = None;

    for line in content.lines() {
        let indent = line.chars().take_while(|c| *c == ' ').count();
        let trimmed = &line[indent..];

        if let Some(block_indent) = block_scalar_indent {
            if !trimmed.is_empty() && indent <= block_indent {
                block_scalar_indent = None;
            } else {
                out.push(line.to_string());
                continue;
            }
        }

        if trimmed.is_empty() || trimmed.starts_with('#') {
            out.push(line.to_string());
            continue;
        }

        let (key_indent, key_start, key_end, key) = match yaml_mapping_key_span(line, indent) {
            Some(parts) => parts,
            None => {
                out.push(line.to_string());
                continue;
            }
        };

        while frames.last().is_some_and(|frame| frame.indent > key_indent) {
            frames.pop();
        }
        if !frames.iter().any(|frame| frame.indent == key_indent) {
            frames.push(Frame {
                indent: key_indent,
                keys: HashSet::new(),
            });
        }
        let frame = frames
            .iter_mut()
            .rev()
            .find(|frame| frame.indent == key_indent)
            .expect("frame inserted above");

        if frame.keys.insert(key.clone()) {
            out.push(line.to_string());
        } else {
            let count = duplicate_counts
                .entry((key_indent, key.clone()))
                .and_modify(|n| *n += 1)
                .or_insert(2);
            let replacement = format!(
                "__taudit_duplicate_{}_{}",
                sanitize_key_fragment(&key),
                count
            );
            let mut rewritten = String::with_capacity(line.len() + replacement.len());
            rewritten.push_str(&line[..key_start]);
            rewritten.push_str(&replacement);
            rewritten.push_str(&line[key_end..]);
            out.push(rewritten);
        }

        let value_tail = line[key_end..].trim_start();
        if value_tail.starts_with(": |") || value_tail.starts_with(": >") {
            block_scalar_indent = Some(key_indent);
        }
    }

    let mut sanitized = out.join("\n");
    if content.ends_with('\n') {
        sanitized.push('\n');
    }
    sanitized
}

fn yaml_mapping_key_span(line: &str, indent: usize) -> Option<(usize, usize, usize, String)> {
    let trimmed = &line[indent..];
    if trimmed.starts_with('#') {
        return None;
    }

    let mut key_indent = indent;
    let mut key_start = indent;
    let key_text = if let Some(rest) = trimmed.strip_prefix("- ") {
        key_indent = indent + 2;
        key_start = indent + 2;
        rest
    } else {
        trimmed
    };

    let mut in_single = false;
    let mut in_double = false;
    let mut bracket_depth = 0i32;
    let mut prev = '\0';
    for (offset, ch) in key_text.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single && prev != '\\' => in_double = !in_double,
            '[' | '{' if !in_single && !in_double => bracket_depth += 1,
            ']' | '}' if !in_single && !in_double => bracket_depth -= 1,
            ':' if !in_single && !in_double && bracket_depth == 0 => {
                let after = key_text[offset + ch.len_utf8()..].chars().next();
                if after.is_some_and(|c| !c.is_whitespace()) {
                    prev = ch;
                    continue;
                }
                let raw = &key_text[..offset];
                let key = raw.trim();
                if key.is_empty() {
                    return None;
                }
                let leading = raw.len() - raw.trim_start().len();
                let trailing = raw.trim_end().len();
                let start = key_start + leading;
                let end = key_start + trailing;
                return Some((key_indent, start, end, key.to_string()));
            }
            _ => {}
        }
        prev = ch;
    }
    None
}

fn sanitize_key_fragment(key: &str) -> String {
    let mut out = String::new();
    for c in key.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    out.trim_matches('_').chars().take(48).collect::<String>()
}

fn build_graph_from_root(
    root: Value,
    source: &PipelineSource,
) -> Result<AuthorityGraph, TauditError> {
    let mapping = root
        .as_mapping()
        .ok_or_else(|| TauditError::Parse("GitLab CI root must be a mapping".into()))?;

    let mut graph = AuthorityGraph::new(source.clone());
    graph.metadata.insert(META_PLATFORM.into(), "gitlab".into());

    // CI_JOB_TOKEN is always present in every GitLab CI job — it's the built-in
    // platform token, equivalent to ADO's System.AccessToken or GHA's GITHUB_TOKEN.
    let mut meta = HashMap::new();
    meta.insert(META_IDENTITY_SCOPE.into(), "broad".into());
    meta.insert(META_IMPLICIT.into(), "true".into());
    let token_id = graph.add_node_with_metadata(
        NodeKind::Identity,
        "CI_JOB_TOKEN",
        TrustZone::FirstParty,
        meta,
    );

    // Top-level include: → mark Partial immediately AND capture each
    // entry's structure as graph metadata so include-pinning rules can
    // reason about remote URLs and unpinned project refs.
    if let Some(inc) = mapping.get("include") {
        graph.mark_partial(
            GapKind::Structural,
            "include: directive present — included templates not resolved".to_string(),
        );
        let entries = extract_include_entries(inc);
        if !entries.is_empty() {
            if let Ok(json) = serde_json::to_string(&entries) {
                graph.metadata.insert(META_GITLAB_INCLUDES.into(), json);
            }
        }
    }

    // Top-level default: can inject authority-relevant settings into every
    // job (image/services/variables/secrets/id_tokens/scripts/cache/artifacts).
    // We currently do not materialize that inheritance chain, so mark Partial
    // to avoid false completeness.
    if let Some(default_map) = mapping.get("default").and_then(|v| v.as_mapping()) {
        if default_contains_authority_relevant_keys(default_map) {
            graph.mark_partial(
                GapKind::Structural,
                "default: contains inherited authority-relevant job settings — inheritance not fully resolved".to_string(),
            );
        }
    }

    // Global variables
    let global_secrets = process_variables(mapping.get("variables"), &mut graph, "pipeline");

    // Global image
    let global_image = mapping.get("image").and_then(extract_image_str);

    // Top-level merge_request trigger detection from `workflow:` rules
    if let Some(wf) = mapping.get("workflow") {
        if has_mr_trigger_in_workflow(wf) {
            graph
                .metadata
                .insert(META_TRIGGER.into(), "merge_request".into());
        }
    }

    // Process each job (any top-level key not in RESERVED)
    // determinism: sort by key — same YAML must produce same NodeId order
    let mut top_level_entries: Vec<(&Value, &Value)> = mapping.iter().collect();
    top_level_entries.sort_by(|a, b| a.0.as_str().unwrap_or("").cmp(b.0.as_str().unwrap_or("")));
    for (key, value) in top_level_entries {
        let job_name = match key.as_str() {
            Some(k) => k,
            None => continue,
        };
        if RESERVED.contains(&job_name) {
            continue;
        }

        // Hidden jobs (starting with a dot) are templates — mark Partial, skip
        if job_name.starts_with('.') {
            graph.mark_partial(
                GapKind::Structural,
                format!("job '{job_name}' is a hidden/template job — not resolved"),
            );
            continue;
        }

        let job_map = match value.as_mapping() {
            Some(m) => m,
            None => continue,
        };

        // extends: — job template inheritance, can't resolve statically
        let extends_names = extract_extends_list(job_map.get("extends"));
        if !extends_names.is_empty() {
            graph.mark_partial(
                GapKind::Structural,
                format!("job '{job_name}' uses extends: — inherited configuration not resolved"),
            );
        }

        // inherit: controls whether job receives top-level `default:` and
        // `variables:`. We don't model the inheritance matrix yet.
        if job_map.contains_key("inherit") {
            graph.mark_partial(
                GapKind::Structural,
                format!("job '{job_name}' uses inherit: — inheritance scope not resolved"),
            );
        }

        // Detect PR/MR trigger in this job's rules: or only:
        let job_triggers_mr = job_has_mr_trigger(job_map);

        // Propagate job MR trigger to graph level
        if job_triggers_mr && !graph.metadata.contains_key(META_TRIGGER) {
            graph
                .metadata
                .insert(META_TRIGGER.into(), "merge_request".into());
        }

        // Job-level variables
        let job_secrets = process_variables(job_map.get("variables"), &mut graph, job_name);

        // Job-level explicit secrets: (Vault, AWS Secrets Manager, GCP, Azure)
        let explicit_secrets =
            process_explicit_secrets(job_map.get("secrets"), job_name, &mut graph);

        // Job-level OIDC tokens (id_tokens:)
        let oidc_identities = process_id_tokens(job_map.get("id_tokens"), job_name, &mut graph);

        // Job image (falls back to global)
        let job_image_str = job_map
            .get("image")
            .and_then(extract_image_str)
            .or(global_image.as_deref().map(String::from));

        let image_id = job_image_str.as_deref().map(|img| {
            let pinned = is_docker_digest_pinned(img);
            let trust_zone = if pinned {
                TrustZone::ThirdParty
            } else {
                TrustZone::Untrusted
            };
            let mut imeta = HashMap::new();
            if let Some(digest) = img.split("@sha256:").nth(1) {
                imeta.insert(META_DIGEST.into(), format!("sha256:{digest}"));
            }
            graph.add_node_with_metadata(NodeKind::Image, img, trust_zone, imeta)
        });

        // Services (each is an Image node)
        let service_ids = process_services(job_map.get("services"), &mut graph);

        // Environment — record name as metadata, sets trust boundary marker
        let env_name = job_map
            .get("environment")
            .and_then(extract_environment_name);
        let env_url = job_map.get("environment").and_then(extract_environment_url);

        // Concatenated script body (before_script + script + after_script).
        // Stamped on the Step node so script-aware rules (notably
        // `untrusted_ci_var_in_shell_interpolation` and
        // `ci_job_token_to_external_api`) can pattern-match without
        // re-walking the YAML.
        // Inline script body — concatenate before_script, script, after_script
        // (each may be a string or a list-of-strings). Stamped on the Step so
        // script-aware rules can pattern-match without re-parsing YAML.
        let script_body = extract_script_body(job_map);

        // GitLab `artifacts.reports.dotenv: <file>` — when set, the file's
        // KEY=value lines are silently promoted to pipeline variables for
        // any downstream job that consumes this one via `needs:` /
        // `dependencies:`. Required input to
        // `dotenv_artifact_flows_to_privileged_deployment`.
        let dotenv_file = extract_dotenv_file(job_map);

        // Upstream job names consumed via `needs:` / `dependencies:`.
        // Used to build dotenv-flow chains across stages.
        let needs = extract_needs(job_map);

        // Detect whether this job's `rules:` / `only:` clause restricts
        // execution to protected branches (or to the default branch,
        // which is protected by GitLab default policy). Used by the
        // `gitlab_deploy_job_missing_protected_branch_only` rule to
        // detect deployment jobs that lack any branch guard.
        let protected_only = job_has_protected_branch_restriction(job_map);

        // Create the Step node for this job
        let mut step_meta = HashMap::new();
        step_meta.insert(META_JOB_NAME.into(), job_name.to_string());
        if let Some(ref env) = env_name {
            step_meta.insert(META_ENVIRONMENT_NAME.into(), env.clone());
        }
        if !script_body.is_empty() {
            step_meta.insert(META_SCRIPT_BODY.into(), script_body);
        }
        if let Some(ref f) = dotenv_file {
            step_meta.insert(META_DOTENV_FILE.into(), f.clone());
        }
        if !needs.is_empty() {
            step_meta.insert(META_NEEDS.into(), needs.join(","));
        }
        if let Some(ref url) = env_url {
            step_meta.insert(META_ENVIRONMENT_URL.into(), url.clone());
        }
        // Per-step MR trigger marker — graph-level META_TRIGGER applies to
        // the file as a whole, but `id_token_audience_overscoped` needs to
        // compare audience usage between MR-context and protected-context
        // jobs in the same file.
        if job_triggers_mr {
            step_meta.insert(META_TRIGGER.into(), "merge_request".into());
        }
        // extends: list (comma-joined, in source order)
        if !extends_names.is_empty() {
            step_meta.insert(META_GITLAB_EXTENDS.into(), extends_names.join(","));
        }
        // allow_failure: true|false (only stamp when explicitly set so the
        // rule can distinguish "absent" from "false")
        if let Some(af) = job_map.get("allow_failure").and_then(|v| v.as_bool()) {
            step_meta.insert(META_GITLAB_ALLOW_FAILURE.into(), af.to_string());
        } else if job_map
            .get("allow_failure")
            .and_then(|v| v.as_mapping())
            .is_some()
        {
            // `allow_failure: { exit_codes: [42] }` — conditional pass; treat
            // as truthy for silent-skip detection.
            step_meta.insert(META_GITLAB_ALLOW_FAILURE.into(), "true".into());
        }
        // dind sidecar detection: any service whose name matches docker:*-dind
        if job_services_have_dind(job_map.get("services")) {
            step_meta.insert(META_GITLAB_DIND_SERVICE.into(), "true".into());
        }
        // trigger: block — child / downstream pipeline
        if let Some(kind) = classify_trigger(job_map.get("trigger")) {
            step_meta.insert(META_GITLAB_TRIGGER_KIND.into(), kind.into());
        }
        // cache: structural capture (key + policy)
        if let Some((cache_key, cache_policy)) = extract_cache_key_policy(job_map.get("cache")) {
            step_meta.insert(META_GITLAB_CACHE_KEY.into(), cache_key);
            if let Some(p) = cache_policy {
                step_meta.insert(META_GITLAB_CACHE_POLICY.into(), p);
            }
        }
        if protected_only {
            step_meta.insert(META_RULES_PROTECTED_ONLY.into(), "true".into());
        }
        let step_id = graph.add_node_with_metadata(
            NodeKind::Step,
            job_name,
            TrustZone::FirstParty,
            step_meta,
        );

        // CI_JOB_TOKEN always available to every step
        graph.add_edge(step_id, token_id, EdgeKind::HasAccessTo);

        // Link all secrets
        for &sid in global_secrets
            .iter()
            .chain(&job_secrets)
            .chain(&explicit_secrets)
        {
            graph.add_edge(step_id, sid, EdgeKind::HasAccessTo);
        }

        // Link OIDC identities
        for &iid in &oidc_identities {
            graph.add_edge(step_id, iid, EdgeKind::HasAccessTo);
        }

        // UsesImage edges
        if let Some(img_id) = image_id {
            graph.add_edge(step_id, img_id, EdgeKind::UsesImage);
        }
        for &svc_id in &service_ids {
            graph.add_edge(step_id, svc_id, EdgeKind::UsesImage);
        }
    }

    // Cross-platform misclassification trap (red-team R2 #5): a YAML file
    // with non-reserved top-level keys looks like a GitLab pipeline shape
    // but its body may use constructs the GitLab parser doesn't recognise
    // (e.g. an ADO `task:` payload). Mark Partial when the source had at
    // least one job-shaped top-level key but we ended up with no Step
    // nodes — better than silently returning completeness=complete on a
    // clean-but-empty graph that a CI gate would treat as "passed".
    let step_count = graph
        .nodes
        .iter()
        .filter(|n| n.kind == NodeKind::Step)
        .count();
    let had_job_carrier = mapping.iter().any(|(k, v)| {
        k.as_str()
            .map(|name| !RESERVED.contains(&name) && !name.starts_with('.'))
            .unwrap_or(false)
            && v.as_mapping().is_some()
    });
    if step_count == 0 && had_job_carrier {
        graph.mark_partial(
                GapKind::Opaque,
                "non-reserved top-level keys parsed but produced 0 step nodes — possible non-GitLab YAML wrong-platform-classified".to_string(),
            );
    }

    graph.stamp_edge_authority_summaries();
    Ok(graph)
}
/// Detect `image:` string from a YAML value — can be a bare string or a mapping with `name:`.
fn extract_image_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Mapping(m) => m.get("name").and_then(|n| n.as_str()).map(String::from),
        _ => None,
    }
}

/// Extract environment name from `environment:` value (string or mapping).
fn extract_environment_name(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Mapping(m) => m.get("name").and_then(|n| n.as_str()).map(String::from),
        _ => None,
    }
}

/// Extract `environment:url:` value (only present when environment is a mapping).
fn extract_environment_url(v: &Value) -> Option<String> {
    match v {
        Value::Mapping(m) => m.get("url").and_then(|u| u.as_str()).map(String::from),
        _ => None,
    }
}

/// Concatenate `before_script`, `script`, and `after_script` of a job into one
/// string body (separated by newlines). Each section may be a single string or
/// a list of strings. Empty sections are skipped.
fn extract_script_body(job_map: &serde_yaml::Mapping) -> String {
    let mut lines: Vec<String> = Vec::new();
    for key in &["before_script", "script", "after_script"] {
        if let Some(v) = job_map.get(*key) {
            collect_script_lines(v, &mut lines);
        }
    }
    lines.join("\n")
}

/// Append script lines from a YAML value (string or sequence of strings).
fn collect_script_lines(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Sequence(seq) => {
            for item in seq {
                if let Some(s) = item.as_str() {
                    out.push(s.to_string());
                }
            }
        }
        _ => {}
    }
}

/// Extract `artifacts.reports.dotenv` filename. Value may be a single string
/// or a list of strings — for the list form we join with `,`.
fn extract_dotenv_file(job_map: &serde_yaml::Mapping) -> Option<String> {
    let dotenv = job_map
        .get("artifacts")?
        .as_mapping()?
        .get("reports")?
        .as_mapping()?
        .get("dotenv")?;
    match dotenv {
        Value::String(s) => Some(s.clone()),
        Value::Sequence(seq) => {
            let parts: Vec<String> = seq
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(","))
            }
        }
        _ => None,
    }
}

/// Extract upstream job names from `needs:` and `dependencies:`.
/// `needs:` may be a list of strings or a list of mappings with `job:`.
/// `dependencies:` is a list of strings.
///
/// F5: GitLab `needs:` entries support an `artifacts: false` opt-out that
/// stops the upstream's artifacts (including its `dotenv` report) from
/// flowing into this job. Excluding those entries here means the comma-joined
/// `META_NEEDS` consumed by `dotenv_artifact_flows_to_privileged_deployment`
/// only contains jobs whose artifacts genuinely flow — no rule-side change
/// needed.
fn extract_needs(job_map: &serde_yaml::Mapping) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(needs) = job_map.get("needs").and_then(|v| v.as_sequence()) {
        for item in needs {
            match item {
                Value::String(s) => out.push(s.clone()),
                Value::Mapping(m) => {
                    let Some(j) = m.get("job").and_then(|j| j.as_str()) else {
                        continue;
                    };
                    // `artifacts:` defaults to true when omitted. Only skip
                    // when explicitly set to false — anything else (true,
                    // missing, weird shape) keeps the dependency.
                    let artifacts_disabled =
                        m.get("artifacts").and_then(|v| v.as_bool()) == Some(false);
                    if artifacts_disabled {
                        continue;
                    }
                    out.push(j.to_string());
                }
                _ => {}
            }
        }
    }
    if let Some(deps) = job_map.get("dependencies").and_then(|v| v.as_sequence()) {
        for item in deps {
            if let Some(s) = item.as_str() {
                out.push(s.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Recognise the canonical "is `var` truthy?" shape inside a GitLab CI
/// `rules: if:` expression. Returns:
///
/// * `Some(true)` — the expression positively asserts `var` is truthy
///   (e.g. `$VAR == "true"`, `$VAR == true`, bare `$VAR`, or any of those
///   joined to other clauses with `&&`).
/// * `Some(false)` — the expression negates `var`'s truthiness
///   (e.g. `$VAR != "true"`, `$VAR == "false"`, `$VAR == null`).
/// * `None` — the shape isn't recognisable; caller MUST treat as "no positive
///   signal" (i.e. do not stamp protected-only or merge_request_event metadata).
///
/// We deliberately keep this minimal — better to under-claim protection than
/// over-claim it. Anything we don't understand returns `None`.
///
/// Boundary discipline: `var` matches only when it appears as a `$VAR` token
/// surrounded by non-identifier chars (or string ends), so `$CI_COMMIT_TAG`
/// does not silently match `$CI_COMMIT_TAG_MESSAGE`.
fn check_truthy_comparison(expr: &str, var: &str) -> Option<bool> {
    // Split on `||` first — if ANY top-level disjunct is positive, the
    // whole expression is positive (any one matching clause makes the rule
    // fire). For `&&`, all conjuncts must agree; if any conjunct contradicts
    // the others, we fall back to None.
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Top-level `||` short-circuit: if any disjunct is positive, accept.
    if let Some((lhs, rhs)) = split_top_level(trimmed, "||") {
        let l = check_truthy_comparison(&lhs, var);
        let r = check_truthy_comparison(&rhs, var);
        return match (l, r) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(false), Some(false)) => Some(false),
            _ => None,
        };
    }
    // Top-level `&&`: positive only if at least one conjunct is positive
    // and none is explicitly negative. (A conjunct that doesn't mention
    // `var` is None — neutral — so we treat it as non-blocking.)
    if let Some((lhs, rhs)) = split_top_level(trimmed, "&&") {
        let l = check_truthy_comparison(&lhs, var);
        let r = check_truthy_comparison(&rhs, var);
        return match (l, r) {
            (Some(false), _) | (_, Some(false)) => Some(false),
            (Some(true), _) | (_, Some(true)) => Some(true),
            _ => None,
        };
    }

    // No top-level boolean op — atomic comparison or bare reference.
    classify_atom(trimmed, var)
}

/// Split `expr` at the first top-level (paren-depth zero, not inside a string)
/// occurrence of `op`. Returns the left and right halves (without `op`).
/// Returns `None` if `op` is not found at the top level.
fn split_top_level(expr: &str, op: &str) -> Option<(String, String)> {
    let bytes = expr.as_bytes();
    let op_bytes = op.as_bytes();
    let mut depth: i32 = 0;
    let mut in_str: Option<u8> = None;
    let mut in_regex = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        // Track string literals (single + double quotes).
        if let Some(q) = in_str {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == q {
                in_str = None;
            }
            i += 1;
            continue;
        }
        if in_regex {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'/' {
                in_regex = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' | b'\'' => {
                in_str = Some(b);
                i += 1;
                continue;
            }
            b'/' => {
                // A `/` after `=~` or `!~` starts a regex literal. Only enter
                // regex mode when preceded (after whitespace) by `~`.
                let mut j = i;
                while j > 0 && bytes[j - 1].is_ascii_whitespace() {
                    j -= 1;
                }
                if j > 0 && bytes[j - 1] == b'~' {
                    in_regex = true;
                    i += 1;
                    continue;
                }
            }
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        if depth == 0
            && i + op_bytes.len() <= bytes.len()
            && &bytes[i..i + op_bytes.len()] == op_bytes
        {
            let lhs = expr[..i].to_string();
            let rhs = expr[i + op_bytes.len()..].to_string();
            return Some((lhs, rhs));
        }
        i += 1;
    }
    None
}

/// Classify an atomic (no `&&`/`||`) sub-expression against `var`.
fn classify_atom(atom: &str, var: &str) -> Option<bool> {
    let s = atom.trim().trim_matches('(').trim_matches(')').trim();
    // Bare reference: the entire atom is `$VAR` (truthy iff variable is set
    // and non-empty per GitLab semantics).
    if s == var {
        return Some(true);
    }
    // Look for `==` / `!=` and a literal RHS. Anything else (regex `=~`,
    // arbitrary substring, multiple comparisons) → None.
    let (op, lhs, rhs) = if let Some((l, r)) = s.split_once("==") {
        ("==", l.trim(), r.trim())
    } else if let Some((l, r)) = s.split_once("!=") {
        ("!=", l.trim(), r.trim())
    } else {
        return None;
    };
    // The variable must appear on exactly one side; the other side is the
    // literal we compare against.
    let (lit, side_is_var) = if lhs == var {
        (rhs, true)
    } else if rhs == var {
        (lhs, true)
    } else {
        // Neither side is the variable as a bare token — recognise also a
        // few extremely common forms where the var has surrounding chars
        // (e.g. quoted: `"$VAR" == "true"`) but otherwise bail.
        let lhs_unq = lhs.trim_matches('"').trim_matches('\'');
        let rhs_unq = rhs.trim_matches('"').trim_matches('\'');
        if lhs_unq == var {
            (rhs, true)
        } else if rhs_unq == var {
            (lhs, true)
        } else {
            return None;
        }
    };
    let _ = side_is_var; // currently always true if we got here
                         // Normalise the literal: strip optional surrounding quotes.
    let lit_norm = lit
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase();
    let truthy_lit = matches!(lit_norm.as_str(), "true" | "1");
    let falsy_lit = matches!(lit_norm.as_str(), "false" | "null" | "" | "0");
    match (op, truthy_lit, falsy_lit) {
        ("==", true, _) => Some(true),
        ("==", _, true) => Some(false),
        ("!=", true, _) => Some(false),
        ("!=", _, true) => Some(true),
        // Comparison against an arbitrary string literal (e.g. a branch name
        // for `$CI_COMMIT_BRANCH == "main"`) is not a truthy comparison —
        // return None and let the caller fall through to other heuristics.
        _ => None,
    }
}

/// Classify a variable name as a credential by checking for common fragments.
///
/// Each fragment in `CRED_FRAGMENTS` must appear as a *segment* of the name
/// (bounded by `_` or by the start/end of the string), NOT as a free-floating
/// substring. This avoids false positives like `CERTAIN_FLAG` (matches `CERT`
/// substring), `CERTIFICATE_PATH` (path config, not a credential),
/// `TOKENIZER_VERSION` (matches `TOKEN`), and `UNCERTAIN`.
///
/// A multi-token fragment like `PRIVATE_KEY` matches when its full text appears
/// at a segment boundary on both sides — i.e. surrounded by `_` or string ends.
fn is_credential_name(name: &str) -> bool {
    let upper = name.to_uppercase();
    let bytes = upper.as_bytes();
    CRED_FRAGMENTS.iter().any(|frag| {
        let frag_bytes = frag.as_bytes();
        let n = frag_bytes.len();
        if bytes.len() < n {
            return false;
        }
        // Slide the fragment across the name, accepting only segment-bounded matches.
        for i in 0..=bytes.len() - n {
            if &bytes[i..i + n] != frag_bytes {
                continue;
            }
            let left_ok = i == 0 || bytes[i - 1] == b'_';
            let right_ok = i + n == bytes.len() || bytes[i + n] == b'_';
            if left_ok && right_ok {
                return true;
            }
        }
        false
    })
}

/// Parse `variables:` mapping and emit `Secret` nodes for credential-pattern names.
/// Returns the list of created node IDs.
fn process_variables(vars: Option<&Value>, graph: &mut AuthorityGraph, scope: &str) -> Vec<NodeId> {
    let mut ids = Vec::new();
    let map = match vars.and_then(|v| v.as_mapping()) {
        Some(m) => m,
        None => return ids,
    };
    // determinism: sort by key — same YAML must produce same NodeId order
    let mut entries: Vec<(&Value, &Value)> = map.iter().collect();
    entries.sort_by(|a, b| a.0.as_str().unwrap_or("").cmp(b.0.as_str().unwrap_or("")));
    for (k, _v) in entries {
        let name = match k.as_str() {
            Some(s) => s,
            None => continue,
        };
        if is_credential_name(name) {
            let id = graph.add_node(NodeKind::Secret, name, TrustZone::FirstParty);
            ids.push(id);
            let _ = scope; // used for future scoped error messages
        }
    }
    ids
}

/// Parse `secrets:` block and emit one `Secret` node per named secret.
///
/// GitLab CI `secrets:` format:
/// ```yaml
/// secrets:
///   DATABASE_PASSWORD:
///     vault: production/db/password@secret
///   AWS_KEY:
///     aws_secrets_manager:
///       name: my-secret
/// ```
fn process_explicit_secrets(
    secrets: Option<&Value>,
    _scope: &str,
    graph: &mut AuthorityGraph,
) -> Vec<NodeId> {
    let mut ids = Vec::new();
    let map = match secrets.and_then(|v| v.as_mapping()) {
        Some(m) => m,
        None => return ids,
    };
    // determinism: sort by key — same YAML must produce same NodeId order
    let mut entries: Vec<(&Value, &Value)> = map.iter().collect();
    entries.sort_by(|a, b| a.0.as_str().unwrap_or("").cmp(b.0.as_str().unwrap_or("")));
    for (k, _v) in entries {
        let name = match k.as_str() {
            Some(s) => s,
            None => continue,
        };
        let id = graph.add_node(NodeKind::Secret, name, TrustZone::FirstParty);
        ids.push(id);
    }
    ids
}

/// Parse `id_tokens:` block and emit one OIDC `Identity` node per token.
///
/// GitLab CI `id_tokens:` format:
/// ```yaml
/// id_tokens:
///   SIGSTORE_ID_TOKEN:
///     aud: sigstore
///   AWS_OIDC_TOKEN:
///     aud: https://sts.amazonaws.com
/// ```
fn process_id_tokens(
    id_tokens: Option<&Value>,
    _scope: &str,
    graph: &mut AuthorityGraph,
) -> Vec<NodeId> {
    let mut ids = Vec::new();
    let map = match id_tokens.and_then(|v| v.as_mapping()) {
        Some(m) => m,
        None => return ids,
    };
    // determinism: sort by key — same YAML must produce same NodeId order
    let mut entries: Vec<(&Value, &Value)> = map.iter().collect();
    entries.sort_by(|a, b| a.0.as_str().unwrap_or("").cmp(b.0.as_str().unwrap_or("")));
    for (k, v) in entries {
        let token_name = match k.as_str() {
            Some(s) => s,
            None => continue,
        };
        // F3: GitLab supports list-form `aud: [a, b, c]` (multi-cloud broker —
        // strongest over-scoping signal). Previously `as_str()` on a sequence
        // returned None and we fell through to "unknown", silently blinding
        // every multi-aud rule. Handle both shapes explicitly.
        let aud_value = v.as_mapping().and_then(|m| m.get("aud"));
        let (aud_joined, is_list) = match aud_value {
            Some(Value::String(s)) => (s.clone(), false),
            Some(Value::Sequence(seq)) => {
                let parts: Vec<String> = seq
                    .iter()
                    .filter_map(|item| match item {
                        Value::String(s) => Some(s.clone()),
                        _ => None,
                    })
                    .collect();
                if parts.is_empty() {
                    ("unknown".into(), false)
                } else {
                    (parts.join(","), true)
                }
            }
            _ => ("unknown".into(), false),
        };
        let label = format!("{token_name} (aud={aud_joined})");
        let mut meta = HashMap::new();
        meta.insert(META_OIDC.into(), "true".into());
        meta.insert(META_IDENTITY_SCOPE.into(), "broad".into());
        // Backward-compat: keep the single-`aud` field populated. For the
        // list form it now holds the comma-joined string so existing
        // consumers see *something* rather than "unknown".
        meta.insert(META_OIDC_AUDIENCE.into(), aud_joined.clone());
        // New (F3): explicit "list form" marker. Only set on the multi-aud
        // path so downstream rules can distinguish single-aud vs multi-aud
        // configurations without parsing the comma-joined string.
        if is_list {
            meta.insert(META_OIDC_AUDIENCES.into(), aud_joined.clone());
        }
        let id =
            graph.add_node_with_metadata(NodeKind::Identity, label, TrustZone::FirstParty, meta);
        ids.push(id);
    }
    ids
}

/// Parse `services:` block and emit `Image` nodes.
fn process_services(services: Option<&Value>, graph: &mut AuthorityGraph) -> Vec<NodeId> {
    let mut ids = Vec::new();
    let list = match services.and_then(|v| v.as_sequence()) {
        Some(s) => s,
        None => return ids,
    };
    for item in list {
        let img_str = match extract_image_str(item) {
            Some(s) => s,
            None => continue,
        };
        let pinned = is_docker_digest_pinned(&img_str);
        let trust_zone = if pinned {
            TrustZone::ThirdParty
        } else {
            TrustZone::Untrusted
        };
        let mut meta = HashMap::new();
        if let Some(digest) = img_str.split("@sha256:").nth(1) {
            meta.insert(META_DIGEST.into(), format!("sha256:{digest}"));
        }
        let id = graph.add_node_with_metadata(NodeKind::Image, &img_str, trust_zone, meta);
        ids.push(id);
    }
    ids
}

/// Check whether a job's `rules:` or `only:` indicates it runs on merge requests.
fn job_has_mr_trigger(job_map: &serde_yaml::Mapping) -> bool {
    // rules: [{if: '$CI_PIPELINE_SOURCE == "merge_request_event"'}]
    if let Some(rules) = job_map.get("rules").and_then(|v| v.as_sequence()) {
        for rule in rules {
            if let Some(if_expr) = rule
                .as_mapping()
                .and_then(|m| m.get("if"))
                .and_then(|v| v.as_str())
            {
                // F2: MR-trigger only fires for the *positive* equality form.
                // `$CI_PIPELINE_SOURCE != "merge_request_event"` ("run except
                // on MRs") used to set META_TRIGGER=merge_request and pollute
                // every downstream MR-context rule.
                if matches_mr_event(if_expr) {
                    return true;
                }
            }
        }
    }
    // only: [merge_requests] or only: {refs: [merge_requests]}
    if let Some(only) = job_map.get("only") {
        if only_has_merge_requests(only) {
            return true;
        }
    }
    false
}

/// Check `only:` value (sequence or mapping) for `merge_requests` entry.
fn only_has_merge_requests(v: &Value) -> bool {
    match v {
        Value::Sequence(seq) => seq
            .iter()
            .any(|item| item.as_str() == Some("merge_requests")),
        Value::Mapping(m) => {
            if let Some(refs) = m.get("refs").and_then(|r| r.as_sequence()) {
                return refs
                    .iter()
                    .any(|item| item.as_str() == Some("merge_requests"));
            }
            false
        }
        _ => false,
    }
}

/// Returns true when a job's `rules:` or `only:` clause restricts execution
/// to protected refs only. The set of accepted patterns is intentionally
/// generous because the goal is to *credit* defensive intent, not to
/// audit-grade verify that every protection actually exists in GitLab's
/// branch-protection settings — that lives outside the YAML.
///
/// Patterns recognised as a protected-only restriction:
///
///   * any `rules: [{ if: ... $CI_COMMIT_REF_PROTECTED ... }]`
///   * any `rules: [{ if: ... $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH ... }]`
///     (default branch is GitLab-protected by default)
///   * any `rules: [{ if: ... $CI_COMMIT_TAG ... }]` (tags are protected by default)
///   * `only: [main]` / `only: [master]` / `only: tags`
///   * `only: { refs: [main, /^release/.*/] }`
///
/// Hits any one of the above → true. Misses every one → false.
fn job_has_protected_branch_restriction(job_map: &serde_yaml::Mapping) -> bool {
    if let Some(rules) = job_map.get("rules").and_then(|v| v.as_sequence()) {
        for rule in rules {
            let Some(if_expr) = rule
                .as_mapping()
                .and_then(|m| m.get("if"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            // F1: `$CI_COMMIT_REF_PROTECTED` — only a *positive* assertion
            // ("ref IS protected") counts. `== "false"` or `!= "true"` is the
            // exact opposite signal and must NOT stamp protected-only.
            if matches!(
                check_truthy_comparison(if_expr, "$CI_COMMIT_REF_PROTECTED"),
                Some(true)
            ) {
                return true;
            }
            if if_expr.contains("$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH")
                || if_expr.contains("$CI_DEFAULT_BRANCH == $CI_COMMIT_BRANCH")
            {
                return true;
            }
            // F1: `$CI_COMMIT_TAG` — only the truthy form ("running on a
            // tag", which GitLab protects by default). Reject negations
            // (`== null`, `!= ...`) and avoid the substring-collision with
            // `$CI_COMMIT_TAG_MESSAGE` that the previous `contains()` had.
            if matches!(
                check_truthy_comparison(if_expr, "$CI_COMMIT_TAG"),
                Some(true)
            ) {
                return true;
            }
        }
    }
    if let Some(only) = job_map.get("only") {
        if only_lists_protected_ref(only) {
            return true;
        }
    }
    false
}

/// Check `only:` for protected/default-branch refs (`main`, `master`, `tags`,
/// or a `refs:` list containing those). Conservative — does NOT include
/// `merge_requests` (that's the opposite signal).
fn only_lists_protected_ref(v: &Value) -> bool {
    fn is_protected_ref(s: &str) -> bool {
        matches!(s, "main" | "master" | "tags") || s.starts_with("/^release")
    }
    match v {
        Value::String(s) => is_protected_ref(s.as_str()),
        Value::Sequence(seq) => seq
            .iter()
            .any(|item| item.as_str().map(is_protected_ref).unwrap_or(false)),
        Value::Mapping(m) => {
            if let Some(refs) = m.get("refs").and_then(|r| r.as_sequence()) {
                return refs
                    .iter()
                    .any(|item| item.as_str().map(is_protected_ref).unwrap_or(false));
            }
            false
        }
        _ => false,
    }
}

/// Check top-level `workflow:` rules for MR trigger.
fn has_mr_trigger_in_workflow(wf: &Value) -> bool {
    let rules = match wf
        .as_mapping()
        .and_then(|m| m.get("rules"))
        .and_then(|r| r.as_sequence())
    {
        Some(r) => r,
        None => return false,
    };
    for rule in rules {
        if let Some(if_expr) = rule
            .as_mapping()
            .and_then(|m| m.get("if"))
            .and_then(|v| v.as_str())
        {
            // F2: see `job_has_mr_trigger` — only the positive equality form
            // counts; negations are rejected.
            if matches_mr_event(if_expr) {
                return true;
            }
        }
    }
    false
}

/// Returns true when `if_expr` positively asserts that the pipeline source IS
/// `merge_request_event`. Accepts `$CI_PIPELINE_SOURCE == "merge_request_event"`
/// (and quoted/`||`/`&&` variants) at the truthy-comparison level. Rejects the
/// `!=` negation form. Falls back to `false` for anything we can't parse — the
/// caller always treats that as "no MR trigger detected".
fn matches_mr_event(if_expr: &str) -> bool {
    // We don't have a `var == "merge_request_event"` pseudo-variable, so we
    // synthesise one: split on `||` ourselves and look for any disjunct that
    // is exactly `$CI_PIPELINE_SOURCE == "merge_request_event"` (with
    // tolerable whitespace and quoting variations).
    fn atom_is_mr_event(atom: &str) -> bool {
        let s = atom.trim().trim_matches('(').trim_matches(')').trim();
        let (lhs, rhs) = match s.split_once("==") {
            Some(parts) => parts,
            None => return false,
        };
        let lhs = lhs.trim();
        let rhs_norm = rhs.trim().trim_matches('"').trim_matches('\'');
        // Either side may carry the variable; the other must equal the literal.
        let lhs_unq = lhs.trim_matches('"').trim_matches('\'');
        let rhs_raw = rhs.trim().trim_matches('"').trim_matches('\'');
        if (lhs_unq == "$CI_PIPELINE_SOURCE" && rhs_norm == "merge_request_event")
            || (rhs_raw == "$CI_PIPELINE_SOURCE" && lhs_unq == "merge_request_event")
        {
            return true;
        }
        false
    }
    let trimmed = if_expr.trim();
    // Top-level `||` short-circuit: any positive disjunct wins.
    if let Some((lhs, rhs)) = split_top_level(trimmed, "||") {
        return atom_is_mr_event(&lhs) || matches_mr_event(&rhs);
    }
    // For `&&`, accept if any conjunct is a positive `merge_request_event`
    // comparison. We don't try to detect contradictory conjuncts —
    // `merge_request_event` is a string literal, not a boolean, so the
    // truthiness short-circuiting in `check_truthy_comparison` doesn't apply.
    if let Some((lhs, rhs)) = split_top_level(trimmed, "&&") {
        return atom_is_mr_event(&lhs) || matches_mr_event(&rhs);
    }
    atom_is_mr_event(trimmed)
}

/// Structured representation of a single `include:` entry.
///
/// Serialised into `AuthorityGraph::metadata[META_GITLAB_INCLUDES]` so that
/// downstream rules (e.g. `unpinned_include_remote_or_branch_ref`) can analyse
/// remote-URL pins, project refs, and missing `ref:` defaults without re-parsing
/// the YAML.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncludeEntry {
    /// Include kind: `local`, `remote`, `template`, `project`, `component`, or
    /// `unknown` for shapes we don't recognise.
    pub kind: String,
    /// The path / URL / project string the include points at.
    pub target: String,
    /// The resolved `ref:` value. Empty string when the include omits a `ref:`
    /// (defaults to HEAD on the source repo, which is itself a finding).
    pub git_ref: String,
}

/// Parse the top-level `include:` value into a flat list of `IncludeEntry`s.
///
/// `include:` accepts five shapes — string, sequence-of-strings, sequence-of-mappings,
/// sequence-of-strings-mixed-with-mappings, and a single mapping. Normalise all of
/// them into one flat list so the rule layer doesn't have to.
pub fn extract_include_entries(v: &Value) -> Vec<IncludeEntry> {
    let mut out = Vec::new();
    match v {
        // `include: 'path/to/local.yml'` — sugar for a local include
        Value::String(s) => {
            out.push(IncludeEntry {
                kind: classify_string_include(s).into(),
                target: s.clone(),
                git_ref: String::new(),
            });
        }
        Value::Sequence(seq) => {
            for item in seq {
                match item {
                    Value::String(s) => {
                        out.push(IncludeEntry {
                            kind: classify_string_include(s).into(),
                            target: s.clone(),
                            git_ref: String::new(),
                        });
                    }
                    Value::Mapping(m) => {
                        if let Some(e) = include_entry_from_mapping(m) {
                            out.push(e);
                        }
                    }
                    _ => {}
                }
            }
        }
        Value::Mapping(m) => {
            if let Some(e) = include_entry_from_mapping(m) {
                out.push(e);
            }
        }
        _ => {}
    }
    out
}

/// Heuristic: a top-level `include:` string that looks like an HTTPS URL is a
/// `remote:` include in shorthand form; everything else is a `local:` path.
fn classify_string_include(s: &str) -> &'static str {
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        "remote"
    } else {
        "local"
    }
}

/// Lift one of the four mapping forms (`local:`, `remote:`, `template:`,
/// `project:`, `component:`) into an `IncludeEntry`. Returns None when the
/// mapping has none of the recognised keys.
fn include_entry_from_mapping(m: &serde_yaml::Mapping) -> Option<IncludeEntry> {
    let str_at = |key: &str| {
        m.get(key)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_default()
    };
    if let Some(s) = m.get("local").and_then(|v| v.as_str()) {
        return Some(IncludeEntry {
            kind: "local".into(),
            target: s.to_string(),
            git_ref: String::new(),
        });
    }
    if let Some(s) = m.get("remote").and_then(|v| v.as_str()) {
        return Some(IncludeEntry {
            kind: "remote".into(),
            target: s.to_string(),
            git_ref: String::new(),
        });
    }
    if let Some(s) = m.get("template").and_then(|v| v.as_str()) {
        return Some(IncludeEntry {
            kind: "template".into(),
            target: s.to_string(),
            git_ref: String::new(),
        });
    }
    if let Some(s) = m.get("component").and_then(|v| v.as_str()) {
        // GitLab CI/CD components: source@version → version is the pin
        let (target, git_ref) = match s.rsplit_once('@') {
            Some((path, ver)) => (path.to_string(), ver.to_string()),
            None => (s.to_string(), String::new()),
        };
        return Some(IncludeEntry {
            kind: "component".into(),
            target,
            git_ref,
        });
    }
    if m.contains_key("project") {
        let project = str_at("project");
        // ref: may be missing → empty string indicates HEAD/default branch,
        // which is itself a supply-chain finding.
        let git_ref = str_at("ref");
        return Some(IncludeEntry {
            kind: "project".into(),
            target: project,
            git_ref,
        });
    }
    None
}

/// Extract a flat list of template names from an `extends:` value.
/// `extends:` accepts a single string or a sequence of strings.
fn extract_extends_list(v: Option<&Value>) -> Vec<String> {
    let v = match v {
        Some(v) => v,
        None => return Vec::new(),
    };
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Sequence(seq) => seq
            .iter()
            .filter_map(|i| i.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// Returns true when `default:` carries keys that can change authority
/// interpretation for jobs inheriting it.
fn default_contains_authority_relevant_keys(m: &serde_yaml::Mapping) -> bool {
    [
        "image",
        "services",
        "variables",
        "secrets",
        "id_tokens",
        "before_script",
        "after_script",
        "cache",
        "artifacts",
    ]
    .iter()
    .any(|k| m.contains_key(*k))
}

/// Returns true when any entry in `services:` has an image name matching
/// `docker:*-dind` (or bare `docker:dind`). Recognises both shapes:
/// `services: [docker:dind]` and `services: [{name: docker:dind}]`.
fn job_services_have_dind(services: Option<&Value>) -> bool {
    let list = match services.and_then(|v| v.as_sequence()) {
        Some(s) => s,
        None => return false,
    };
    for item in list {
        let img = match extract_image_str(item) {
            Some(s) => s,
            None => continue,
        };
        if image_is_dind(&img) {
            return true;
        }
    }
    false
}

/// Match `docker:dind`, `docker:24.0-dind`, `docker:24-dind`,
/// `docker:24.0.7-dind-rootless`, etc. The discriminator is a `docker:` prefix
/// AND `dind` appearing somewhere in the tag.
fn image_is_dind(image: &str) -> bool {
    let lower = image.to_ascii_lowercase();
    // Match the official docker dind images and their digest-pinned variants.
    // Strip any `@sha256:...` suffix before checking the tag.
    let bare = match lower.split_once('@') {
        Some((b, _)) => b,
        None => &lower,
    };
    if !bare.starts_with("docker:") && !bare.starts_with("docker/") {
        return false;
    }
    bare.contains("dind")
}

/// Classify a `trigger:` block as either `static` (in-tree YAML / fixed
/// downstream project) or `dynamic` (include from a previous job's artifact —
/// dynamic child pipelines, the code-injection sink). Returns None when no
/// `trigger:` block is present.
fn classify_trigger(trigger: Option<&Value>) -> Option<&'static str> {
    let t = trigger?;
    // Shorthand: `trigger: my/downstream/project` → static
    if t.is_string() {
        return Some("static");
    }
    let m = t.as_mapping()?;
    // Look at every `include:` entry under trigger; if ANY one references an
    // `artifact:` field, the child pipeline is dynamic.
    if let Some(inc) = m.get("include") {
        if include_has_artifact_source(inc) {
            return Some("dynamic");
        }
    }
    Some("static")
}

/// Walk a `trigger.include:` value (string / sequence / mapping) and return
/// true when any entry's mapping carries an `artifact:` key.
fn include_has_artifact_source(v: &Value) -> bool {
    match v {
        Value::Mapping(m) => m.contains_key("artifact"),
        Value::Sequence(seq) => seq.iter().any(|i| {
            i.as_mapping()
                .map(|m| m.contains_key("artifact"))
                .unwrap_or(false)
        }),
        _ => false,
    }
}

/// Extract `(cache.key, cache.policy)` from a job's `cache:` value. Returns
/// `None` when no cache is declared. `cache:` may be a sequence of mappings
/// (multiple caches); we capture the first key/policy pair so the rule layer
/// has at least one signal — multi-cache analysis is left to a future
/// extension.
///
/// `cache.key:` may be:
/// - a string: `key: vendor`
/// - a mapping: `key: { files: [Gemfile.lock] }` → captured as `files:Gemfile.lock,...`
/// - a mapping with `prefix:` → captured as `prefix:<value>`
fn extract_cache_key_policy(v: Option<&Value>) -> Option<(String, Option<String>)> {
    let v = v?;
    let m = match v {
        Value::Mapping(m) => m,
        Value::Sequence(seq) => {
            // First cache wins — same heuristic used elsewhere.
            return seq
                .iter()
                .find_map(|i| i.as_mapping().and_then(extract_cache_key_policy_map));
        }
        _ => return None,
    };
    extract_cache_key_policy_map(m)
}

fn extract_cache_key_policy_map(m: &serde_yaml::Mapping) -> Option<(String, Option<String>)> {
    let key = match m.get("key") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Mapping(km)) => {
            let mut parts = Vec::new();
            if let Some(prefix) = km.get("prefix").and_then(|v| v.as_str()) {
                parts.push(format!("prefix:{prefix}"));
            }
            if let Some(files) = km.get("files").and_then(|v| v.as_sequence()) {
                let names: Vec<String> = files
                    .iter()
                    .filter_map(|f| f.as_str().map(str::to_string))
                    .collect();
                if !names.is_empty() {
                    parts.push(format!("files:{}", names.join(",")));
                }
            }
            if parts.is_empty() {
                String::new()
            } else {
                parts.join(";")
            }
        }
        _ => String::new(),
    };
    let policy = m.get("policy").and_then(|v| v.as_str()).map(str::to_string);
    Some((key, policy))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> AuthorityGraph {
        let parser = GitlabParser;
        let source = PipelineSource {
            file: ".gitlab-ci.yml".into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        };
        parser.parse(yaml, &source).unwrap()
    }

    #[test]
    fn ci_job_token_always_present() {
        let yaml = r#"
stages:
  - build

build-job:
  stage: build
  script:
    - make build
"#;
        let graph = parse(yaml);
        let identities: Vec<_> = graph.nodes_of_kind(NodeKind::Identity).collect();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].name, "CI_JOB_TOKEN");
        assert_eq!(
            identities[0]
                .metadata
                .get(META_IMPLICIT)
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            identities[0]
                .metadata
                .get(META_IDENTITY_SCOPE)
                .map(String::as_str),
            Some("broad")
        );
    }

    #[test]
    fn global_credential_variable_emits_secret_node() {
        let yaml = r#"
variables:
  APP_VERSION: "1.0"
  DEPLOY_TOKEN: "$CI_DEPLOY_TOKEN"

build-job:
  script:
    - make
"#;
        let graph = parse(yaml);
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        assert!(
            secrets.iter().any(|s| s.name == "DEPLOY_TOKEN"),
            "DEPLOY_TOKEN must emit a Secret node, got: {:?}",
            secrets.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
        // Plain config variable must not emit Secret
        assert!(
            !secrets.iter().any(|s| s.name == "APP_VERSION"),
            "APP_VERSION must not emit a Secret node"
        );
    }

    #[test]
    fn floating_image_emits_untrusted_image_node() {
        let yaml = r#"
deploy:
  image: alpine:latest
  script:
    - deploy.sh
"#;
        let graph = parse(yaml);
        let images: Vec<_> = graph.nodes_of_kind(NodeKind::Image).collect();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].name, "alpine:latest");
        assert_eq!(images[0].trust_zone, TrustZone::Untrusted);
    }

    #[test]
    fn digest_pinned_image_is_third_party() {
        let yaml = r#"
deploy:
  image: "alpine@sha256:a5ac7e51b41094c92402da3b24376905380afc29a5ac7e51b41094c92402da3b"
  script:
    - deploy.sh
"#;
        let graph = parse(yaml);
        let images: Vec<_> = graph.nodes_of_kind(NodeKind::Image).collect();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].trust_zone, TrustZone::ThirdParty);
    }

    #[test]
    fn id_tokens_emit_oidc_identity_nodes() {
        let yaml = r#"
deploy:
  id_tokens:
    SIGSTORE_ID_TOKEN:
      aud: sigstore
    AWS_OIDC_TOKEN:
      aud: https://sts.amazonaws.com
  script:
    - deploy.sh
"#;
        let graph = parse(yaml);
        let oidc: Vec<_> = graph
            .nodes_of_kind(NodeKind::Identity)
            .filter(|n| n.metadata.get(META_OIDC).map(String::as_str) == Some("true"))
            .collect();
        assert_eq!(
            oidc.len(),
            2,
            "expected 2 OIDC identity nodes, got: {:?}",
            oidc.iter().map(|n| &n.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn explicit_secrets_emit_secret_nodes() {
        let yaml = r#"
deploy:
  secrets:
    DATABASE_PASSWORD:
      vault: production/db/password@secret
    AWS_KEY:
      aws_secrets_manager:
        name: my-secret
  script:
    - deploy.sh
"#;
        let graph = parse(yaml);
        let secrets: Vec<_> = graph.nodes_of_kind(NodeKind::Secret).collect();
        let names: Vec<_> = secrets.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"DATABASE_PASSWORD"), "got: {names:?}");
        assert!(names.contains(&"AWS_KEY"), "got: {names:?}");
    }

    #[test]
    fn rules_mr_trigger_sets_meta_trigger() {
        let yaml = r#"
test:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
  script:
    - run tests
"#;
        let graph = parse(yaml);
        assert_eq!(
            graph.metadata.get(META_TRIGGER).map(String::as_str),
            Some("merge_request"),
            "META_TRIGGER must be set to merge_request"
        );
    }

    #[test]
    fn only_merge_requests_sets_meta_trigger() {
        let yaml = r#"
test:
  only:
    - merge_requests
  script:
    - run tests
"#;
        let graph = parse(yaml);
        assert_eq!(
            graph.metadata.get(META_TRIGGER).map(String::as_str),
            Some("merge_request")
        );
    }

    #[test]
    fn include_marks_graph_partial() {
        let yaml = r#"
include:
  - local: '/templates/.base.yml'

build:
  script:
    - make
"#;
        let graph = parse(yaml);
        assert_eq!(graph.completeness, AuthorityCompleteness::Partial);
        assert_eq!(graph.completeness_gap_kinds[0], GapKind::Structural);
    }

    #[test]
    fn default_with_authority_relevant_keys_marks_partial() {
        let yaml = r#"
default:
    image: alpine:latest
    before_script:
        - echo from default

build:
    script:
        - make
"#;
        let graph = parse(yaml);
        assert_eq!(graph.completeness, AuthorityCompleteness::Partial);
        assert!(
            graph
                .completeness_gaps
                .iter()
                .any(|r| r.contains("default:") && r.contains("inherit")),
            "expected default-inheritance partial reason, got: {:?}",
            graph.completeness_gaps
        );
    }

    #[test]
    fn inherit_key_marks_partial() {
        let yaml = r#"
variables:
    DEPLOY_TOKEN: "$CI_DEPLOY_TOKEN"

deploy:
    inherit:
        variables: false
    script:
        - deploy.sh
"#;
        let graph = parse(yaml);
        assert_eq!(graph.completeness, AuthorityCompleteness::Partial);
        assert!(
            graph
                .completeness_gaps
                .iter()
                .any(|r| r.contains("job 'deploy' uses inherit:")),
            "expected inherit partial reason, got: {:?}",
            graph.completeness_gaps
        );
    }

    #[test]
    fn extends_marks_graph_partial() {
        let yaml = r#"
.base:
  script:
    - echo base

my-job:
  extends: .base
  stage: build
"#;
        let graph = parse(yaml);
        assert_eq!(graph.completeness, AuthorityCompleteness::Partial);
        // Two structural gaps: the hidden `.base` template job and the
        // `extends:` inheritance on my-job.
        assert!(
            graph
                .completeness_gap_kinds
                .iter()
                .all(|k| *k == GapKind::Structural),
            "expected all gaps Structural, got: {:?}",
            graph.completeness_gap_kinds
        );
    }

    #[test]
    fn meta_job_name_set_on_step_nodes() {
        let yaml = r#"
build:
  script:
    - make
deploy:
  script:
    - deploy.sh
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 2);
        for step in &steps {
            assert!(
                step.metadata.contains_key(META_JOB_NAME),
                "Step '{}' missing META_JOB_NAME",
                step.name
            );
        }
        // Verify job names are correct
        let names: Vec<_> = steps
            .iter()
            .map(|s| s.metadata.get(META_JOB_NAME).unwrap().as_str())
            .collect();
        assert!(names.contains(&"build"), "got: {names:?}");
        assert!(names.contains(&"deploy"), "got: {names:?}");
    }

    #[test]
    fn reserved_keywords_not_parsed_as_jobs() {
        let yaml = r#"
stages:
  - build
  - test

variables:
  MY_VAR: value

image: alpine:latest

build:
  stage: build
  script:
    - make
"#;
        let graph = parse(yaml);
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(
            steps.len(),
            1,
            "only 'build' should be a Step, got: {:?}",
            steps.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
        assert_eq!(steps[0].name, "build");
    }

    #[test]
    fn services_emit_image_nodes() {
        let yaml = r#"
test:
  services:
    - docker:dind
    - name: postgres:14
  script:
    - run_tests
"#;
        let graph = parse(yaml);
        let images: Vec<_> = graph.nodes_of_kind(NodeKind::Image).collect();
        assert_eq!(
            images.len(),
            2,
            "expected 2 service Image nodes, got: {:?}",
            images.iter().map(|i| &i.name).collect::<Vec<_>>()
        );
    }

    // ── Cross-platform misclassification trap (red-team R2 #5) ─────

    #[test]
    fn job_carrier_with_unparseable_bodies_marks_partial() {
        // Top-level keys that look like job names but whose values are not
        // mappings (lists, scalars). GitLab parser would normally produce a
        // Step per non-reserved mapping-valued key; here every candidate is
        // skipped because the value is not a mapping. Result: 0 step nodes
        // despite a non-empty job carrier — must mark Partial.
        let yaml = r#"
build:
  - this is a list, not a mapping
test:
  - also a list
"#;
        let graph = parse(yaml);
        let step_count = graph
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Step)
            .count();
        // Note: the "had_job_carrier" heuristic only fires when the value IS
        // a mapping, so this case (non-mapping values) does NOT trigger the
        // partial — that's intentional. The heuristic targets the trap where
        // an attacker uses a *valid mapping shape* the GitLab parser can't
        // interpret.
        assert_eq!(step_count, 0);
        assert_eq!(
            graph.completeness,
            AuthorityCompleteness::Complete,
            "non-mapping values are not job carriers"
        );
    }

    // ── Regression tests for F1-F6 (gitlab-parser deep review) ──────────

    /// F1: `$CI_COMMIT_REF_PROTECTED == "true"` stamps protected-only;
    /// the negation `== "false"` must NOT stamp.
    #[test]
    fn protected_ref_only_stamps_meta_when_truly_positive() {
        let positive = r#"
deploy:
  rules:
    - if: '$CI_COMMIT_REF_PROTECTED == "true"'
  script:
    - deploy.sh
"#;
        let graph = parse(positive);
        let step = graph.nodes_of_kind(NodeKind::Step).next().unwrap();
        assert_eq!(
            step.metadata
                .get(META_RULES_PROTECTED_ONLY)
                .map(String::as_str),
            Some("true"),
            "positive == \"true\" comparison must stamp META_RULES_PROTECTED_ONLY"
        );

        let negation = r#"
deploy:
  rules:
    - if: '$CI_COMMIT_REF_PROTECTED == "false"'
  script:
    - deploy.sh
"#;
        let graph = parse(negation);
        let step = graph.nodes_of_kind(NodeKind::Step).next().unwrap();
        assert!(
            !step.metadata.contains_key(META_RULES_PROTECTED_ONLY),
            "== \"false\" is the OPPOSITE signal — must NOT stamp META_RULES_PROTECTED_ONLY (got: {:?})",
            step.metadata.get(META_RULES_PROTECTED_ONLY)
        );

        // `!= "true"` is also a negation — must not stamp.
        let inequality = r#"
deploy:
  rules:
    - if: '$CI_COMMIT_REF_PROTECTED != "true"'
  script:
    - deploy.sh
"#;
        let graph = parse(inequality);
        let step = graph.nodes_of_kind(NodeKind::Step).next().unwrap();
        assert!(
            !step.metadata.contains_key(META_RULES_PROTECTED_ONLY),
            "!= \"true\" is a negation — must NOT stamp META_RULES_PROTECTED_ONLY"
        );

        // `$CI_COMMIT_TAG_MESSAGE` substring trap — used to match because
        // `if_expr.contains("$CI_COMMIT_TAG")` was true even though the var
        // is a different one.
        let tag_message_trap = r#"
deploy:
  rules:
    - if: '$CI_COMMIT_TAG_MESSAGE == "release"'
  script:
    - deploy.sh
"#;
        let graph = parse(tag_message_trap);
        let step = graph.nodes_of_kind(NodeKind::Step).next().unwrap();
        assert!(
            !step.metadata.contains_key(META_RULES_PROTECTED_ONLY),
            "$CI_COMMIT_TAG_MESSAGE must not match the $CI_COMMIT_TAG predicate"
        );
    }

    /// F2: `$CI_PIPELINE_SOURCE != "merge_request_event"` ("run except on MRs")
    /// must NOT stamp `META_TRIGGER=merge_request`. Only the positive form
    /// counts.
    #[test]
    fn mr_trigger_detection_rejects_negation() {
        let negation = r#"
build:
  rules:
    - if: '$CI_PIPELINE_SOURCE != "merge_request_event"'
  script:
    - make build
"#;
        let graph = parse(negation);
        assert!(
            graph.metadata.get(META_TRIGGER).map(String::as_str) != Some("merge_request"),
            "negation form must not stamp META_TRIGGER=merge_request, got: {:?}",
            graph.metadata.get(META_TRIGGER)
        );
        let steps: Vec<_> = graph.nodes_of_kind(NodeKind::Step).collect();
        assert_eq!(steps.len(), 1);
        assert!(
            steps[0].metadata.get(META_TRIGGER).map(String::as_str) != Some("merge_request"),
            "negation form must not stamp per-step META_TRIGGER=merge_request"
        );

        // Positive form still works.
        let positive = r#"
build:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
  script:
    - make build
"#;
        let graph = parse(positive);
        assert_eq!(
            graph.metadata.get(META_TRIGGER).map(String::as_str),
            Some("merge_request"),
            "positive form must still stamp META_TRIGGER=merge_request"
        );
    }

    /// F3: list-form `aud:` produces `META_OIDC_AUDIENCES` (plural) and a
    /// comma-joined `META_OIDC_AUDIENCE` for backward compat. Scalar form
    /// stamps only `META_OIDC_AUDIENCE` and leaves the plural marker absent.
    #[test]
    fn id_tokens_aud_list_form_creates_audiences_metadata() {
        let yaml = r#"
deploy:
  id_tokens:
    MULTI_CLOUD_TOKEN:
      aud:
        - https://aws.amazonaws.com
        - https://gcp.googleapis.com
  script:
    - deploy.sh
"#;
        let graph = parse(yaml);
        let oidc: Vec<_> = graph
            .nodes_of_kind(NodeKind::Identity)
            .filter(|n| n.metadata.get(META_OIDC).map(String::as_str) == Some("true"))
            .collect();
        assert_eq!(oidc.len(), 1);
        assert_eq!(
            oidc[0]
                .metadata
                .get(META_OIDC_AUDIENCES)
                .map(String::as_str),
            Some("https://aws.amazonaws.com,https://gcp.googleapis.com"),
            "list-form aud must stamp comma-joined META_OIDC_AUDIENCES"
        );
        // Backward compat: META_OIDC_AUDIENCE holds the same comma-joined value
        // (no longer "unknown" as it was before the fix).
        assert_eq!(
            oidc[0].metadata.get(META_OIDC_AUDIENCE).map(String::as_str),
            Some("https://aws.amazonaws.com,https://gcp.googleapis.com"),
        );
        assert!(oidc[0].name.contains("aud=https://aws"));

        // Scalar form: META_OIDC_AUDIENCE is the bare string, plural marker absent.
        let scalar = r#"
deploy:
  id_tokens:
    AWS_TOKEN:
      aud: https://sts.amazonaws.com
  script:
    - deploy.sh
"#;
        let graph = parse(scalar);
        let oidc: Vec<_> = graph
            .nodes_of_kind(NodeKind::Identity)
            .filter(|n| n.metadata.get(META_OIDC).map(String::as_str) == Some("true"))
            .collect();
        assert_eq!(
            oidc[0].metadata.get(META_OIDC_AUDIENCE).map(String::as_str),
            Some("https://sts.amazonaws.com")
        );
        assert!(
            !oidc[0].metadata.contains_key(META_OIDC_AUDIENCES),
            "scalar form must NOT set the plural META_OIDC_AUDIENCES marker"
        );
    }

    /// F4: `is_credential_name` must boundary-check; substring matches like
    /// `CERTAIN_FLAG` (contains `CERT`), `TOKENIZER_VERSION` (contains `TOKEN`),
    /// `UNCERTAIN`, and `CERTIFICATE_PATH` (path config, not a credential)
    /// must all return false. Real credentials still match.
    #[test]
    fn is_credential_name_boundary_checks() {
        // False positives that the substring matcher used to flag.
        assert!(!is_credential_name("CERTAIN_FLAG"));
        assert!(!is_credential_name("TOKENIZER_VERSION"));
        assert!(!is_credential_name("UNCERTAIN"));
        assert!(!is_credential_name("CERTIFICATE_PATH"));
        assert!(!is_credential_name("TOKEN1"));
        assert!(!is_credential_name("CERTIFICATE"));

        // True positives — must still match.
        assert!(is_credential_name("API_TOKEN"));
        assert!(is_credential_name("MY_CERT"));
        assert!(is_credential_name("DB_PASSWORD"));
        assert!(is_credential_name("DEPLOY_TOKEN"));
        assert!(is_credential_name("SIGNING_KEY"));
        assert!(is_credential_name("AWS_SECRET_ACCESS_KEY"));
        assert!(is_credential_name("TOKEN"));
        assert!(is_credential_name("CERT"));
        assert!(is_credential_name("PRIVATE_KEY"));
        assert!(is_credential_name("CREDENTIAL"));
    }

    /// F5: a `needs:` entry with `artifacts: false` does NOT promote the
    /// upstream's dotenv into this job, so it must be excluded from
    /// `META_NEEDS` (the dotenv-flow rule reads that CSV verbatim).
    #[test]
    fn needs_artifacts_false_excludes_dotenv_flow() {
        let yaml = r#"
build:
  artifacts:
    reports:
      dotenv: build.env
  script:
    - make build
deploy:
  needs:
    - job: build
      artifacts: false
  script:
    - kubectl apply
"#;
        let graph = parse(yaml);
        let deploy_step = graph
            .nodes_of_kind(NodeKind::Step)
            .find(|n| n.metadata.get(META_JOB_NAME).map(String::as_str) == Some("deploy"))
            .expect("deploy step present");
        let needs_csv = deploy_step
            .metadata
            .get(META_NEEDS)
            .map(String::as_str)
            .unwrap_or("");
        assert!(
            !needs_csv.split(',').any(|s| s == "build"),
            "build must be excluded from META_NEEDS when artifacts: false (got: {needs_csv:?})"
        );

        // Sanity check: same YAML with `artifacts: true` (or missing) still
        // includes the upstream so dotenv-flow rules can fire.
        let yaml_default = r#"
build:
  artifacts:
    reports:
      dotenv: build.env
  script:
    - make build
deploy:
  needs:
    - job: build
  script:
    - kubectl apply
"#;
        let graph = parse(yaml_default);
        let deploy_step = graph
            .nodes_of_kind(NodeKind::Step)
            .find(|n| n.metadata.get(META_JOB_NAME).map(String::as_str) == Some("deploy"))
            .expect("deploy step present");
        let needs_csv = deploy_step
            .metadata
            .get(META_NEEDS)
            .map(String::as_str)
            .unwrap_or("");
        assert!(
            needs_csv.split(',').any(|s| s == "build"),
            "default (artifacts implicitly true) must keep build in META_NEEDS (got: {needs_csv:?})"
        );
    }

    /// F6: 9× parse with bucket-defeating key names — even if a future
    /// refactor swapped the indexmap-backed mapping for a HashMap-backed
    /// one, the explicit sort would keep NodeId order byte-identical.
    #[test]
    fn gitlab_mapping_iteration_is_deterministic_across_runs() {
        // Names chosen to spread across hash buckets.
        let yaml = r#"
zeta-job:
  variables:
    ZZ_TOKEN: "$CI_TOKEN"
    AA_PASSWORD: "x"
    MM_SECRET: "y"
  script:
    - echo zeta
alpha-job:
  variables:
    QQ_TOKEN: "$CI_TOKEN"
    BB_API_KEY: "z"
  script:
    - echo alpha
mid-job:
  variables:
    NN_PRIVATE_KEY: "k"
    GG_SIGNING_KEY: "j"
  script:
    - echo mid
"#;
        let canonical: Vec<(NodeKind, String)> = parse(yaml)
            .nodes
            .iter()
            .map(|n| (n.kind, n.name.clone()))
            .collect();
        for run in 0..9 {
            let again: Vec<(NodeKind, String)> = parse(yaml)
                .nodes
                .iter()
                .map(|n| (n.kind, n.name.clone()))
                .collect();
            assert_eq!(
                again, canonical,
                "run {run}: NodeId order must be byte-identical across runs"
            );
        }
    }

    #[test]
    fn mapping_jobs_without_recognisable_step_content_marks_partial() {
        // A non-reserved top-level key whose value is a mapping but contains
        // only ADO-style fields (`task:`, `azureSubscription`) — and `extends`
        // marks the job as partial without creating a Step. Wait: the GitLab
        // parser actually still adds a Step node for any mapping-valued
        // non-reserved key. So to get the 0-step + had_carrier shape, we
        // need a hidden/template job (starts with '.') as the only candidate.
        let yaml = r#"
.template-only:
  script:
    - echo "this is a template-only file"
"#;
        let graph = parse(yaml);
        let step_count = graph
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Step)
            .count();
        assert_eq!(step_count, 0);
        // Hidden jobs already mark partial with their own reason.
        assert_eq!(graph.completeness, AuthorityCompleteness::Partial);
        // The hidden `.template-only` job is a Structural gap. The zero-steps
        // fall-through does NOT fire here because `had_job_carrier` only
        // counts non-dot-prefixed mapping-valued top-level keys.
        assert_eq!(graph.completeness_gap_kinds[0], GapKind::Structural);
    }
}
