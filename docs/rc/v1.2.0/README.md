# v1.2.0 RC Plan

Selected direction: `v1.2.0-rc.1: Authority Evidence Platform`.

The council direction is to make taudit feel less like another workflow scanner
and more like an evidence-bearing trust primitive: public contracts first,
ordered authority evidence second, and operator proof surfaces third. The release
candidate exists to prove that direction on real inputs before the stable lane
inherits the promise.

## Control Documents

- [Charter](charter.md) - selected direction, release promise, gates, and first
  tranche.
- [Code-complete lanes](code-complete-lanes.md) - ADR-backed subtask backlog
  for parallel agents to take the RC to code complete.
- [Execution lanes](workstreams/execution-lanes.md) - ownership, merge order, and
  verification matrix for parallel work.

## Workstreams

| Workstream | Role in the RC |
| --- | --- |
| [Contract platform](workstreams/contract-platform.md) | Defines the public API, schema, report, SARIF, and CloudEvents contract boundary. |
| [Authority-timed evidence](workstreams/authority-timed-evidence.md) | Makes helper-resolution findings depend on ordered, typed authority evidence. |
| [Marketplace trust pack](workstreams/marketplace-trust-pack.md) | Proves the product in GitHub Actions, Azure DevOps, VS Code, release assets, and adoption docs. |
| [Parser completeness corpus](workstreams/parser-completeness-corpus.md) | Replaces broad parser claims with measured completeness, pinned real inputs, and typed gaps. |
| [Release gates and SemVer](workstreams/release-gates-semver.md) | Sets the `v1.2.0-rc.1` lane, version choices, changelog contract, and stable-promotion gates. |
| [Execution lanes](workstreams/execution-lanes.md) | Keeps six-agent follow-up work disjoint, reviewable, and release-contract aware. |

## Operating Rule

This folder may lead the implementation, but it may not overclaim it. If code,
schemas, outputs, or marketplace proof lag behind the plan, the RC remains
blocked until the evidence catches up.
