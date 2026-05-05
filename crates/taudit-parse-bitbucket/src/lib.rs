use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use serde_yaml::Value;
use taudit_core::error::TauditError;
use taudit_core::graph::*;
use taudit_core::ports::PipelineParser;

pub struct BitbucketParser;

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
    "KEYSTORE",
    "SSH_KEY",
];

impl PipelineParser for BitbucketParser {
    fn platform(&self) -> &str {
        "bitbucket"
    }

    fn parse(&self, content: &str, source: &PipelineSource) -> Result<AuthorityGraph, TauditError> {
        let (root, extra_docs, duplicate_recovery_note) = match parse_bitbucket_yaml_value(content)
        {
            Ok((root, extra_docs)) => (root, extra_docs, None),
            Err(e) if is_duplicate_key_parse_error(&e) => {
                let sanitized = sanitize_duplicate_mapping_keys(content);
                let note = format!(
                    "Bitbucket YAML contained duplicate mapping keys; later duplicates were preserved as opaque __taudit_duplicate_* keys during recovery ({e})"
                );
                let (root, extra_docs) = parse_bitbucket_yaml_value(&sanitized)
                    .map_err(|e| TauditError::Parse(format!("YAML parse error: {e}")))?;
                (root, extra_docs, Some(note))
            }
            Err(e) => return Err(TauditError::Parse(format!("YAML parse error: {e}"))),
        };

        let mapping = root.as_mapping().ok_or_else(|| {
            TauditError::Parse("Bitbucket Pipelines root must be a mapping".into())
        })?;

        let mut graph = AuthorityGraph::new(source.clone());
        graph
            .metadata
            .insert(META_PLATFORM.into(), "bitbucket".into());
        if extra_docs {
            graph.mark_partial(
                GapKind::Expression,
                "file contains multiple YAML documents (--- separator) — only the first was analyzed"
                    .to_string(),
            );
        }
        if let Some(note) = duplicate_recovery_note {
            graph.mark_partial(GapKind::Structural, note);
        }

        let definitions = mapping.get("definitions");
        let service_images = collect_defined_services(definitions);
        let global_image = mapping.get("image").and_then(extract_image_str);
        let Some(pipelines) = mapping.get("pipelines").and_then(|v| v.as_mapping()) else {
            graph.mark_partial(
                GapKind::Structural,
                "Bitbucket file has no top-level pipelines: mapping".to_string(),
            );
            graph.stamp_edge_authority_summaries();
            return Ok(graph);
        };

        let mut secret_ids = HashMap::new();
        let mut prior_artifacts = Vec::new();
        let mut triggers = HashSet::new();
        let mut contexts = Vec::new();
        collect_pipeline_contexts(pipelines, &mut contexts, &mut triggers);

        if !triggers.is_empty() {
            let mut list: Vec<_> = triggers.into_iter().collect();
            list.sort();
            if list.contains(&"pull_request") {
                graph
                    .metadata
                    .insert(META_TRIGGER.into(), "pull_request".into());
            }
            graph.metadata.insert(META_TRIGGERS.into(), list.join(","));
        }

        for ctx in contexts {
            process_step_carrier(
                ctx.value,
                &ctx.name,
                ctx.trigger,
                global_image.as_deref(),
                &service_images,
                &mut graph,
                &mut secret_ids,
                &mut prior_artifacts,
            );
        }

        graph.stamp_edge_authority_summaries();
        Ok(graph)
    }
}

fn parse_bitbucket_yaml_value(content: &str) -> Result<(Value, bool), serde_yaml::Error> {
    let mut de = serde_yaml::Deserializer::from_str(content);
    let Some(doc) = de.next() else {
        return Ok((Value::Null, false));
    };
    let root = Value::deserialize(doc)?;
    Ok((root, de.next().is_some()))
}

fn is_duplicate_key_parse_error(error: &serde_yaml::Error) -> bool {
    error.to_string().contains("duplicate entry with key")
}

#[derive(Clone)]
struct PipelineContext<'a> {
    name: String,
    trigger: &'static str,
    value: &'a Value,
}

fn collect_pipeline_contexts<'a>(
    pipelines: &'a serde_yaml::Mapping,
    out: &mut Vec<PipelineContext<'a>>,
    triggers: &mut HashSet<&'static str>,
) {
    for (key, value) in pipelines {
        let Some(kind) = key.as_str() else {
            continue;
        };
        match kind {
            "default" => {
                triggers.insert("push");
                out.push(PipelineContext {
                    name: "default".into(),
                    trigger: "push",
                    value,
                });
            }
            "branches" | "tags" | "pull-requests" | "custom" => {
                let trigger = match kind {
                    "pull-requests" => "pull_request",
                    "custom" => "manual",
                    "tags" => "tag",
                    _ => "push",
                };
                triggers.insert(trigger);
                if let Some(map) = value.as_mapping() {
                    for (pattern, body) in map {
                        let label = pattern.as_str().unwrap_or("*");
                        out.push(PipelineContext {
                            name: format!("{kind}:{label}"),
                            trigger,
                            value: body,
                        });
                    }
                }
            }
            _ => {
                graphless_ignore(value);
            }
        }
    }
}

fn graphless_ignore(_: &Value) {}

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

fn process_step_carrier(
    value: &Value,
    context: &str,
    trigger: &'static str,
    global_image: Option<&str>,
    service_images: &HashMap<String, String>,
    graph: &mut AuthorityGraph,
    secret_ids: &mut HashMap<String, NodeId>,
    prior_artifacts: &mut Vec<NodeId>,
) {
    match value {
        Value::Sequence(seq) => {
            for item in seq {
                process_step_carrier(
                    item,
                    context,
                    trigger,
                    global_image,
                    service_images,
                    graph,
                    secret_ids,
                    prior_artifacts,
                );
            }
        }
        Value::Mapping(map) => {
            if let Some(step) = map.get("step") {
                process_step(
                    step,
                    context,
                    trigger,
                    global_image,
                    service_images,
                    graph,
                    secret_ids,
                    prior_artifacts,
                );
            } else if let Some(parallel) = map.get("parallel") {
                if let Some(steps) = parallel.get("steps") {
                    process_step_carrier(
                        steps,
                        context,
                        trigger,
                        global_image,
                        service_images,
                        graph,
                        secret_ids,
                        prior_artifacts,
                    );
                } else {
                    process_step_carrier(
                        parallel,
                        context,
                        trigger,
                        global_image,
                        service_images,
                        graph,
                        secret_ids,
                        prior_artifacts,
                    );
                }
            }
        }
        _ => {}
    }
}

fn process_step(
    value: &Value,
    context: &str,
    trigger: &'static str,
    global_image: Option<&str>,
    service_images: &HashMap<String, String>,
    graph: &mut AuthorityGraph,
    secret_ids: &mut HashMap<String, NodeId>,
    prior_artifacts: &mut Vec<NodeId>,
) {
    let Some(map) = value.as_mapping() else {
        graph.mark_partial(
            GapKind::Structural,
            format!("Bitbucket step in {context} is not a mapping"),
        );
        return;
    };

    let name = map
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(context)
        .to_string();
    let mut meta = HashMap::new();
    meta.insert(META_JOB_NAME.into(), context.to_string());
    meta.insert(META_TRIGGER.into(), trigger.to_string());
    if let Some(deployment) = map.get("deployment").and_then(|v| v.as_str()) {
        meta.insert(META_ENVIRONMENT_NAME.into(), deployment.to_string());
        if is_protected_deployment_name(deployment) {
            meta.insert(META_ENV_APPROVAL.into(), "true".into());
        }
    }
    let script_body = extract_script_body(map.get("script"));
    if !script_body.is_empty() {
        meta.insert(META_SCRIPT_BODY.into(), script_body.clone());
    }
    if map.get("oidc").and_then(|v| v.as_bool()) == Some(true) {
        meta.insert(META_OIDC.into(), "true".into());
    }
    if step_looks_self_hosted(map) {
        meta.insert(META_SELF_HOSTED.into(), "true".into());
    }

    let step_id = graph.add_node_with_metadata(NodeKind::Step, name, TrustZone::FirstParty, meta);

    for artifact_id in prior_artifacts.iter().copied() {
        graph.add_edge(artifact_id, step_id, EdgeKind::Consumes);
    }

    if map.get("oidc").and_then(|v| v.as_bool()) == Some(true) {
        let mut id_meta = HashMap::new();
        id_meta.insert(META_OIDC.into(), "true".into());
        id_meta.insert(META_IDENTITY_SCOPE.into(), "broad".into());
        id_meta.insert(META_IMPLICIT.into(), "true".into());
        let id = graph.add_node_with_metadata(
            NodeKind::Identity,
            "BITBUCKET_STEP_OIDC_TOKEN",
            TrustZone::FirstParty,
            id_meta,
        );
        graph.add_edge(step_id, id, EdgeKind::HasAccessTo);
    }

    let step_image = map
        .get("image")
        .and_then(extract_image_str)
        .or_else(|| global_image.map(str::to_string));
    if let Some(image) = step_image {
        let image_id = add_image(graph, &image);
        graph.add_edge(step_id, image_id, EdgeKind::UsesImage);
    }

    if let Some(services) = map.get("services").and_then(|v| v.as_sequence()) {
        for service in services {
            let Some(name) = service.as_str() else {
                continue;
            };
            let image = service_images.get(name).cloned().unwrap_or_else(|| {
                if name == "docker" {
                    "docker:dind".into()
                } else {
                    name.into()
                }
            });
            let image_id = add_image(graph, &image);
            graph.add_edge(step_id, image_id, EdgeKind::UsesImage);
        }
    }

    for pipe in extract_pipe_refs(map.get("script")) {
        let image_id = add_image(graph, &pipe);
        graph.add_edge(step_id, image_id, EdgeKind::UsesImage);
    }

    for secret_name in extract_env_secret_refs(&script_body) {
        let secret_id = find_or_create_secret(graph, secret_ids, &secret_name);
        graph.add_edge(step_id, secret_id, EdgeKind::HasAccessTo);
    }

    if let Some(artifacts) = map.get("artifacts") {
        for artifact in extract_artifact_names(artifacts) {
            let artifact_id = graph.add_node(NodeKind::Artifact, artifact, TrustZone::FirstParty);
            graph.add_edge(step_id, artifact_id, EdgeKind::Produces);
            prior_artifacts.push(artifact_id);
        }
    }
}

fn add_image(graph: &mut AuthorityGraph, image: &str) -> NodeId {
    let trust_zone = if is_docker_digest_pinned(image) {
        TrustZone::ThirdParty
    } else {
        TrustZone::Untrusted
    };
    let mut meta = HashMap::new();
    if let Some(digest) = image.split("@sha256:").nth(1) {
        meta.insert(META_DIGEST.into(), format!("sha256:{digest}"));
    }
    graph.add_node_with_metadata(NodeKind::Image, image, trust_zone, meta)
}

fn extract_image_str(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Mapping(m) => m.get("name").and_then(|v| v.as_str()).map(str::to_string),
        _ => None,
    }
}

fn collect_defined_services(definitions: Option<&Value>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(services) = definitions
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get("services"))
        .and_then(|v| v.as_mapping())
    else {
        return out;
    };
    for (name, body) in services {
        let Some(name) = name.as_str() else {
            continue;
        };
        if let Some(image) = body
            .as_mapping()
            .and_then(|m| m.get("image"))
            .and_then(extract_image_str)
        {
            out.insert(name.to_string(), image);
        } else if name == "docker" {
            out.insert(name.to_string(), "docker:dind".into());
        }
    }
    out
}

fn extract_script_body(value: Option<&Value>) -> String {
    let mut lines = Vec::new();
    collect_script_lines(value, &mut lines);
    lines.join("\n")
}

fn collect_script_lines(value: Option<&Value>, out: &mut Vec<String>) {
    match value {
        Some(Value::String(s)) => out.push(s.clone()),
        Some(Value::Sequence(seq)) => {
            for item in seq {
                if let Some(s) = item.as_str() {
                    out.push(s.to_string());
                } else if let Some(pipe) = item
                    .as_mapping()
                    .and_then(|m| m.get("pipe"))
                    .and_then(|v| v.as_str())
                {
                    out.push(format!("pipe: {pipe}"));
                }
            }
        }
        _ => {}
    }
}

fn extract_pipe_refs(value: Option<&Value>) -> Vec<String> {
    let mut out = Vec::new();
    let Some(Value::Sequence(seq)) = value else {
        return out;
    };
    for item in seq {
        if let Some(pipe) = item
            .as_mapping()
            .and_then(|m| m.get("pipe"))
            .and_then(|v| v.as_str())
        {
            out.push(pipe.to_string());
        }
    }
    out
}

fn extract_artifact_names(value: &Value) -> Vec<String> {
    match value {
        Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Value::Mapping(map) => map
            .get("paths")
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn is_protected_deployment_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("prod") || lower.contains("stag") || lower.contains("deploy")
}

fn step_looks_self_hosted(map: &serde_yaml::Mapping) -> bool {
    map.get("runs-on")
        .and_then(|v| v.as_str())
        .map(|s| s.to_ascii_lowercase().contains("self"))
        .unwrap_or(false)
}

fn extract_env_secret_refs(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        if j < bytes.len() && bytes[j] == b'{' {
            j += 1;
            let start = j;
            while j < bytes.len() && is_var_char(bytes[j]) {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'}' {
                let name = &body[start..j];
                if is_credential_name(name) {
                    out.push(name.to_string());
                }
                i = j + 1;
                continue;
            }
        } else {
            let start = j;
            while j < bytes.len() && is_var_char(bytes[j]) {
                j += 1;
            }
            if j > start {
                let name = &body[start..j];
                if is_credential_name(name) {
                    out.push(name.to_string());
                }
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out.sort();
    out.dedup();
    out
}

fn is_var_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_credential_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    CRED_FRAGMENTS.iter().any(|frag| {
        let frag_bytes = frag.as_bytes();
        let n = frag_bytes.len();
        if bytes.len() < n {
            return false;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> AuthorityGraph {
        let parser = BitbucketParser;
        let source = PipelineSource {
            file: "bitbucket-pipelines.yml".into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        };
        parser.parse(yaml, &source).unwrap()
    }

    #[test]
    fn parses_step_image_script_oidc_and_secret_refs() {
        let yaml = r#"
image: node:20
pipelines:
  pull-requests:
    "**":
      - step:
          name: test
          oidc: true
          script:
            - echo $DEPLOY_TOKEN
"#;
        let graph = parse(yaml);
        assert_eq!(graph.metadata.get(META_PLATFORM).unwrap(), "bitbucket");
        assert_eq!(graph.metadata.get(META_TRIGGER).unwrap(), "pull_request");
        assert_eq!(graph.nodes_of_kind(NodeKind::Step).count(), 1);
        assert!(graph
            .nodes_of_kind(NodeKind::Identity)
            .any(|n| n.name == "BITBUCKET_STEP_OIDC_TOKEN"));
        assert!(graph
            .nodes_of_kind(NodeKind::Secret)
            .any(|n| n.name == "DEPLOY_TOKEN"));
        assert!(graph
            .nodes_of_kind(NodeKind::Image)
            .any(|n| n.name == "node:20"));
    }

    #[test]
    fn parses_pipes_services_and_artifacts() {
        let yaml = r#"
definitions:
  services:
    docker:
      memory: 2048
pipelines:
  default:
    - step:
        name: build
        services: [docker]
        script:
          - pipe: atlassian/aws-s3-deploy:1.1.0
        artifacts:
          - dist/**
    - step:
        name: deploy
        script:
          - cat dist/file
"#;
        let graph = parse(yaml);
        assert!(graph
            .nodes_of_kind(NodeKind::Image)
            .any(|n| n.name == "docker:dind"));
        assert!(graph
            .nodes_of_kind(NodeKind::Image)
            .any(|n| n.name == "atlassian/aws-s3-deploy:1.1.0"));
        assert!(graph
            .nodes_of_kind(NodeKind::Artifact)
            .any(|n| n.name == "dist/**"));
        assert!(graph.edges.iter().any(|e| e.kind == EdgeKind::Consumes));
    }
}
