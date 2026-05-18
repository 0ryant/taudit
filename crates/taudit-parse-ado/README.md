# taudit-parse-ado

Azure DevOps YAML parser for taudit authority graphs.

This crate converts Azure Pipelines YAML into taudit's typed `AuthorityGraph`, preserving CI/CD authority relationships such as variable groups, service connections, deployment environments, scripts, tasks, artifacts, and PR-triggered trust boundaries. It is a parser adapter for DevSecOps tooling that needs Azure DevOps supply-chain security analysis without invoking the full CLI.

## What It Detects In The Graph

- `System.AccessToken`, service connections, variable groups, and secret-like variables.
- Deployment jobs, environment approval metadata, production-environment hints, and self-hosted pools.
- Script bodies, Terraform auto-approve patterns, `task.setvariable` environment gates, and helper authority paths.
- Template and resource repository references that may make the graph partial.

The crate parses and annotates. Rule evaluation lives in `taudit-core`.

## Install

```toml
[dependencies]
taudit-core = "3"
taudit-parse-ado = "3"
```

## Basic Use

```rust
use taudit_core::graph::PipelineSource;
use taudit_core::ports::PipelineParser;
use taudit_parse_ado::AdoParser;

let source = PipelineSource {
    file: "azure-pipelines.yml".into(),
    repo: None,
    git_ref: None,
    commit_sha: None,
};

let graph = AdoParser.parse(pipeline_yaml, &source)?;
```

## Optional Context

`AdoParserContext` carries optional organization, project, and PAT fields for enrichment plumbing. The current parser treats the PAT as sensitive input and does not persist it into graph metadata.

```rust
use taudit_parse_ado::{AdoParser, AdoParserContext};

let ctx = AdoParserContext {
    org: Some("example-org".into()),
    project: Some("platform".into()),
    pat: None,
};

let graph = AdoParser.parse_with_context(pipeline_yaml, &source, Some(&ctx))?;
```

## Related Docs

- Product README: <https://github.com/0ryant/taudit>
- Azure DevOps adoption guide: <https://github.com/0ryant/taudit/blob/main/docs/adoption-day0-day1.md>
- Authority graph spec: <https://github.com/0ryant/taudit/blob/main/docs/authority-graph.md>
- Rule catalogue: <https://github.com/0ryant/taudit/blob/main/docs/rules/index.md>
