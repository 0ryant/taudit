# ADR 0010: Public contract boundary and API readiness

- **Status:** Accepted
- **Date:** 2026-05-18
- **Context:** [ADR 0001](0001-graph-native-exports-and-leverage.md), [ADR 0003](0003-strategic-spine-adoption-phased.md), [contract platform workstream](../rc/v1.2.0/workstreams/contract-platform.md), [taudit-api README](../../crates/taudit-api/README.md).

## Context

taudit has multiple public surfaces: `taudit-api`, authority graph JSON, scan
JSON, SARIF, CloudEvents, exploit graph JSON, baselines, suppressions, and CLI
exit codes. `taudit-core` and parser crates are published, but they are
implementation surfaces unless a specific type is promoted into the public
contract.

The RC must not accidentally freeze internal Rust structs or schema details as
`taudit-api` 1.0.

## Decision

The public contract boundary for v1.2 is:

- `taudit-api` when a consumer wants Rust wire types;
- `schemas/authority-graph.v1.json` for authority graph JSON;
- `schemas/exploit-graph.v1.json` for exploit graph JSON;
- `contracts/schemas/taudit-report.schema.json` for scan JSON;
- SARIF 2.1.0 output contract as documented and tested;
- `contracts/schemas/taudit-cloudevent-finding-v1.schema.json`;
- suppression, baseline, fingerprint, finding-group, and exit-code contracts.

`taudit-core`, parser crates, reporter crates, and sink crates may remain
published implementation crates, but release notes must not present their
internals as the stable embedding API.

`taudit-api` is not promoted to 1.0 until a readiness checklist and conformance
harness pass. If v1.2 changes public wire fields, the API line bumps
intentionally, likely to a new prerelease minor, before the CLI tag.

## Lane Ownership

- **L2 API/contracts** owns `crates/taudit-api/`, schema files,
  `contracts/schemas/`, contract examples, and conformance fixtures.
- **L5 reports/sinks** owns projection of public fields into JSON, SARIF,
  terminal, and CloudEvents after L2 freezes names.
- **L1 release coordination** owns semver declaration in the changelog.

## Acceptance Gates

- public boundary matrix is committed and linked from RC docs
- conformance harness covers graph JSON, scan JSON, SARIF, CloudEvents, and
  reference consumers
- `cargo doc -p taudit-api --no-deps`
- semver check or explicit pre-1.0 compatibility review for `taudit-api`
- release notes classify every public contract delta

## Consequences

The product can move fast in implementation crates while giving downstream
consumers one explicit contract lane. Any future `taudit-api` 1.0 claim must be
evidence-backed, not aspirational.
