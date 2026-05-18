# taudit-parse-gitlab

GitLab CI YAML parser for taudit authority graphs.

This crate converts `.gitlab-ci.yml` content into taudit's typed `AuthorityGraph`, capturing GitLab CI/CD authority flow for security analysis. It models jobs, implicit `CI_JOB_TOKEN` authority, secrets, ID tokens, images, services, includes, extends, artifacts, dotenv handoffs, protected-branch hints, and merge request trigger context.

## What It Models

- Job nodes and the implicit broad `CI_JOB_TOKEN` identity.
- Credential-shaped variables, `secrets:`, `id_tokens:`, images, services, artifacts, and dotenv reports.
- `rules:`, `only:`, protected-branch indicators, environment names, child-pipeline triggers, and include/extends metadata.
- Duplicate YAML key recovery that preserves later keys as opaque metadata and marks the graph partial.

Rule evaluation lives in `taudit-core`; this crate only parses and annotates.

## Install

```toml
[dependencies]
taudit-core = "3"
taudit-parse-gitlab = "3"
```

## Basic Use

```rust
use taudit_core::graph::PipelineSource;
use taudit_core::ports::PipelineParser;
use taudit_parse_gitlab::GitlabParser;

let source = PipelineSource {
    file: ".gitlab-ci.yml".into(),
    repo: None,
    git_ref: None,
    commit_sha: None,
};

let graph = GitlabParser.parse(pipeline_yaml, &source)?;
```

## Use Cases

- Add GitLab CI support to a custom taudit-powered scanner.
- Build graph evidence for GitLab supply-chain and merge-request security review.
- Feed GitLab authority graphs into JSON, SARIF, CloudEvents, or custom report sinks.

## Related Docs

- Product README: <https://github.com/0ryant/taudit>
- Authority graph spec: <https://github.com/0ryant/taudit/blob/main/docs/authority-graph.md>
- Rule catalogue: <https://github.com/0ryant/taudit/blob/main/docs/rules/index.md>
