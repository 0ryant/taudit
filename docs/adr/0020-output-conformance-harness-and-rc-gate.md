# ADR 0020: Output conformance harness and RC gate

- **Status:** Accepted
- **Date:** 2026-05-18
- **Context:** [RELEASE_GATES.md](../RELEASE_GATES.md), [contract platform workstream](../rc/v1.2.0/workstreams/contract-platform.md), [execution lanes](../rc/v1.2.0/workstreams/execution-lanes.md).

## Context

The RC needs one gate that proves the public contract as consumed, not only
individual unit tests. Today, some important assertions live in narrow tests,
and examples are not a complete current-output profile.

## Decision

Add a conformance harness before the RC tag. It validates:

- authority graph JSON;
- exploit graph JSON;
- scan JSON;
- SARIF;
- CloudEvents;
- contract examples;
- reference consumers;
- identity parity;
- evidence parity;
- suppression parity;
- exit-code matrix.

This harness becomes a release gate for `v1.2.0-rc.1`.

## Lane Ownership

- **QA/conformance** owns the harness target and CI wiring.
- **L2 contracts** owns schemas and examples.
- **L5 reports/sinks** owns sink parity tests.
- **L1 release coordination** owns release-gate enforcement.

## Acceptance Gates

- harness has a local command or `just` recipe
- `.github/workflows/quality.yml` or release workflow invokes it for tag
  readiness
- failure output names the violated contract
- `docs/RELEASE_GATES.md` links the harness

## Consequences

The RC cannot be tagged while only part of the public output contract is checked.
This reduces drift between schemas, examples, sinks, and release notes.
