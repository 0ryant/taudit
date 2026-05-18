# taudit-core

Deterministic authority graph and rule engine for taudit CI/CD security analysis.

`taudit-core` is the engine crate behind the `taudit` CLI. It models how credentials, tokens, identities, images, and artifacts flow through CI/CD pipelines, then evaluates graph-backed security rules over that authority model. It is useful for custom scanners, test harnesses, and advanced integrations that need graph propagation rather than only serialized output.

## What This Crate Provides

- `AuthorityGraph` construction, mutation, completeness tracking, and metadata handling.
- Propagation analysis for authority paths across graph edges.
- Built-in taudit rules for GitHub Actions, Azure DevOps, GitLab CI, Bitbucket Pipelines, and cross-platform CI/CD supply-chain risks.
- Baselines, suppressions, ignore-file handling, custom invariant rules, and finding fingerprints.
- Render helpers for maps, DOT, Mermaid, summary output, and exploit-path exports.

## Important Boundary

`taudit-core` is not the stable public wire contract. External consumers that only need Rust types for emitted JSON, SARIF, CloudEvents, or authority graph documents should use `taudit-api`.

Use `taudit-core` when you need to run analysis in-process.

## Install

```toml
[dependencies]
taudit-core = "3"
taudit-parse-gha = "3"
```

## Parse And Analyze

```rust
use taudit_core::graph::PipelineSource;
use taudit_core::ports::PipelineParser;
use taudit_core::propagation::DEFAULT_MAX_HOPS;
use taudit_core::rules;
use taudit_parse_gha::GhaParser;

let yaml = r#"
name: ci
on: [pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"#;

let source = PipelineSource {
    file: ".github/workflows/ci.yml".into(),
    repo: None,
    git_ref: None,
    commit_sha: None,
};

let graph = GhaParser.parse(yaml, &source)?;
let findings = rules::run_all_rules(&graph, DEFAULT_MAX_HOPS);
```

## Use Cases

- Embed taudit analysis in a service instead of shelling out to the CLI.
- Build custom DevSecOps gates over authority graph semantics.
- Test new CI/CD security rules against graph fixtures.
- Generate graph artifacts for supply-chain security evidence.

## Related Docs

- Product README: <https://github.com/0ryant/taudit>
- Authority graph spec: <https://github.com/0ryant/taudit/blob/main/docs/authority-graph.md>
- Custom rules: <https://github.com/0ryant/taudit/blob/main/docs/custom-rules.md>
- Baselines: <https://github.com/0ryant/taudit/blob/main/docs/baselines.md>
- Suppressions: <https://github.com/0ryant/taudit/blob/main/docs/suppressions.md>
