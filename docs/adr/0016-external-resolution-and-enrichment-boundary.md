# ADR 0016: External resolution and enrichment boundary

- **Status:** Accepted
- **Date:** 2026-05-18
- **Context:** [parser completeness workstream](../rc/v1.2.0/workstreams/parser-completeness-corpus.md), [TODOS.md](../../TODOS.md), [positioning](../positioning.md).

## Context

taudit is offline by default. Some platform constructs can be resolved
deterministically from local files; others require provider APIs or remote
repositories. Azure DevOps variable-group enrichment already has an opt-in
direction that changes graph completeness when live provider state is supplied.

## Decision

Default scan and verify remain offline and deterministic.

External resolution is split:

- deterministic local resolution may run when the operator supplies a repo root
  or local include path;
- remote provider resolution is opt-in and scoped to explicit flags;
- failed remote enrichment degrades to typed partiality unless the operator
  selects a strict mode;
- provider credentials must never be logged, persisted, or copied into reports;
- baselines produced with provider enrichment must record that live provider
  state affected the graph.

ADO variable-group enrichment is permitted as an opt-in deterministic exception
for the run, not as cached truth. The minimum inputs are organization, project,
and PAT or masked environment value. The required PAT scope is read-only
variable-group access.

## Lane Ownership

- **L3 ADO parser/enrichment** owns REST client behavior, parser context, mocks,
  and fallback typed gaps.
- **L5 CLI/output** owns flags, stderr warnings, and report metadata.
- **L6 docs** owns reproducibility and baseline caveats.

## Acceptance Gates

- mock tests cover secret versus plain variables, permission failure, network
  failure, expired token, and partial fallback
- secret-safety tests prove PAT values do not appear in logs, JSON, SARIF,
  CloudEvents, snapshots, or baseline metadata
- baseline docs explain live-state reproducibility
- release notes state whether enrichment ships in the RC or remains deferred

## Consequences

Enterprise ADO noise can be reduced without weakening the core offline promise.
The same boundary can later govern GHA reusable workflow fetches, GitLab include
fetches, and Bitbucket pipe metadata.
