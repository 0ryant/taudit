# taudit-parse-bitbucket

Bitbucket Pipelines YAML parser for taudit authority graphs.

This crate turns `bitbucket-pipelines.yml` content into taudit's typed `AuthorityGraph`, giving security tools a graph-native view of Bitbucket CI/CD authority flow. It focuses on pipeline steps, deployment contexts, variables that look like credentials, images, services, artifacts, pull request triggers, and duplicate-key recovery.

## What It Produces

- Step nodes for Bitbucket pipeline execution units.
- Secret nodes for credential-shaped variables such as tokens, passwords, private keys, API keys, and SSH keys.
- Image nodes for global, step-level, and service containers.
- Artifact and authority edges that allow `taudit-core` rules to reason over trust-boundary crossings.
- Partial-graph markers when a file lacks a usable `pipelines:` mapping or uses multiple YAML documents.

Rule evaluation lives in `taudit-core`; this crate only parses and annotates.

## Install

```toml
[dependencies]
taudit-core = "3"
taudit-parse-bitbucket = "3"
```

## Basic Use

```rust
use taudit_core::graph::PipelineSource;
use taudit_core::ports::PipelineParser;
use taudit_parse_bitbucket::BitbucketParser;

let source = PipelineSource {
    file: "bitbucket-pipelines.yml".into(),
    repo: None,
    git_ref: None,
    commit_sha: None,
};

let graph = BitbucketParser.parse(pipeline_yaml, &source)?;
```

## Use Cases

- Add Bitbucket Pipelines support to an in-process taudit scanner.
- Convert Bitbucket CI/CD config into a graph for custom DevSecOps dashboards.
- Run taudit authority propagation rules against Bitbucket pipeline fixtures.

## Related Docs

- Product README: <https://github.com/0ryant/taudit>
- Authority graph spec: <https://github.com/0ryant/taudit/blob/main/docs/authority-graph.md>
- Rule catalogue: <https://github.com/0ryant/taudit/blob/main/docs/rules/index.md>
