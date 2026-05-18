# taudit-api

Stable Rust wire types for taudit JSON, SARIF, CloudEvents, and authority graph output.

Use this crate when a downstream tool needs typed access to taudit's emitted contracts without depending on the full analysis engine. It is the public Rust integration surface for CI/CD security tooling, DevSecOps automation, SIEM ingestion, supply-chain security workflows, and authority graph consumers.

## What This Crate Owns

- Finding types, severity values, recommendations, source metadata, and fix effort fields.
- Authority graph node, edge, trust-zone, identity-scope, and completeness types.
- Stable metadata-key constants used by parsers, report sinks, and downstream consumers.
- Serializable contract shapes shared across JSON, SARIF, and CloudEvents output.

## When To Use It

Use `taudit-api` if you are writing:

- a Rust consumer for `taudit scan --format json`;
- a SARIF or CloudEvents post-processor that wants taudit enums instead of ad hoc strings;
- a dashboard, SIEM bridge, Backstage plugin, merge gate, or policy service that stores taudit findings;
- an integration with sibling tools such as tsign or axiom.

Use the `taudit` CLI or parser/report crates instead if you need to parse pipeline YAML or render output.

## Install

```toml
[dependencies]
taudit-api = "0.4"
```

## Basic Use

```rust
use taudit_api::{Finding, FindingCategory, Severity};

fn is_blocking(finding: &Finding) -> bool {
    finding.severity <= Severity::High
        && finding.category == FindingCategory::AuthorityPropagation
}
```

Most consumers deserialize taudit JSON into their own envelope and use these types for the nested finding and graph fields.

## Stability

`taudit-api` is currently `0.x`. Additive fields or variants can land in minor releases. Breaking serde or enum changes require a new minor version and a CHANGELOG migration note. At `1.0`, standard SemVer applies: `1.x` is additive and `2.0` is the next breaking line.

## Related Docs

- Product README: <https://github.com/0ryant/taudit>
- User guide: <https://github.com/0ryant/taudit/blob/main/USERGUIDE.md>
- Authority graph contract: <https://github.com/0ryant/taudit/blob/main/docs/authority-graph.md>
- Finding fingerprint contract: <https://github.com/0ryant/taudit/blob/main/docs/finding-fingerprint.md>
