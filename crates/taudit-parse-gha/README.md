# taudit-parse-gha

GitHub Actions workflow parser for taudit authority graphs.

This crate parses GitHub Actions YAML into taudit's typed `AuthorityGraph`, so tools can reason about `GITHUB_TOKEN`, secrets, OIDC, reusable workflows, actions, containers, artifacts, trigger context, permissions, and trust-boundary crossings as graph data instead of raw YAML strings.

## What It Models

- Jobs, steps, local actions, third-party actions, containers, services, and artifacts.
- `permissions:` scope, OIDC availability, `GITHUB_TOKEN`, and secret references.
- Pull request, `pull_request_target`, `workflow_run`, `issue_comment`, dispatch, and reusable workflow triggers.
- Fork-check guards, cache/helper handoffs, environment mutation, and manifest authority metadata used by taudit rules.
- Partial graph reasons when expressions, reusable workflows, composites, or multiple YAML documents hide static authority flow.

Rule evaluation lives in `taudit-core`; this crate only parses and annotates.

## Install

```toml
[dependencies]
taudit-core = "3"
taudit-parse-gha = "3"
```

## Basic Use

```rust
use taudit_core::graph::PipelineSource;
use taudit_core::ports::PipelineParser;
use taudit_parse_gha::GhaParser;

let source = PipelineSource {
    file: ".github/workflows/release.yml".into(),
    repo: None,
    git_ref: None,
    commit_sha: None,
};

let graph = GhaParser.parse(workflow_yaml, &source)?;
```

## Use Cases

- Embed GitHub Actions authority analysis in a Rust service.
- Precompute authority graphs for SARIF, JSON, CloudEvents, or custom gates.
- Test new GitHub Actions supply-chain security rules against parsed graph fixtures.

## Related Docs

- Product README: <https://github.com/0ryant/taudit>
- GitHub Actions golden paths: <https://github.com/0ryant/taudit/blob/main/docs/golden-paths.md>
- Authority graph spec: <https://github.com/0ryant/taudit/blob/main/docs/authority-graph.md>
- Rule catalogue: <https://github.com/0ryant/taudit/blob/main/docs/rules/index.md>
