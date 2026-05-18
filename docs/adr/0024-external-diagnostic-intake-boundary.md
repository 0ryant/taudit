# ADR 0024: External diagnostic intake boundary

- **Status:** Accepted
- **Date:** 2026-05-18
- **Context:** [positioning](../positioning.md), [integration index](../integrations/index.md), [CI mirrors](../integrations/ci-mirrors.md).

## Context

Workflow linters and scanners can provide useful diagnostic context, but taudit's
authority graph must remain the source of truth for authority propagation.
External diagnostics must not silently become graph evidence.

## Decision

External diagnostics, including SARIF from actionlint or other tools, are
triage context only unless a future ADR defines a verified translation into
authority graph facts.

If external intake is added:

- it is opt-in;
- it is represented as external diagnostic context;
- it cannot make a graph `Complete`;
- it cannot create authority edges by itself;
- it cannot satisfy ordered authority evidence from ADR 0011;
- it must preserve source attribution.

## Lane Ownership

- **Post-RC integration lane** owns any external diagnostic intake design.
- **L2 contracts** owns schema boundaries if external context is serialized.
- **L4 core** owns any future verified graph-fact translation.

## Acceptance Gates

- tests prove external diagnostics do not create authority edges by default
- docs call external data advisory
- release notes identify the feature as triage context

## Consequences

taudit can integrate with broader CI hygiene without diluting its graph-first
authority model.
