# ADR 0013: Evidence rendering and output ceiling

- **Status:** Accepted
- **Date:** 2026-05-18
- **Context:** [ADR 0005](0005-authority-edge-classifier-and-witness-handoff.md), [ADR 0006](0006-exploit-path-view-and-ruleset.md), [authority-timed evidence workstream](../rc/v1.2.0/workstreams/authority-timed-evidence.md).

## Context

Authority evidence is useful only if each output surface states what was proven.
The same internal model may carry static evidence, inferred edges, catalog
facts, witness status, and internal disclosure triage. Those are not equivalent
claims.

## Decision

Default customer output may render:

- static source facts;
- inferred path facts;
- helper resolution, authority transport, and authority origin;
- confidence;
- witness status as an evidence-strength label;
- same-job caveat;
- remediation and hardening labels;
- technical score if it is defined as static technical priority.

Default customer output must not render:

- disclosure score;
- CVE workflow metadata;
- recommended disclosure route;
- witness-spec next action;
- canary values;
- private hosted-run artifacts;
- observed sink claims without explicit observed evidence input.

Each reporter decides its own shape, but the output ceiling is shared. Terminal
may summarize; JSON, SARIF, and CloudEvents must preserve structured fields when
the public contract includes them.

## Lane Ownership

- **L2 API/contracts** owns field classification as public, sink-visible,
  verbose-only, internal-gated, or absent.
- **L5 reports/sinks** owns projection and snapshot tests.
- **L1 release coordination** owns changelog disclosure of any output delta.

## Acceptance Gates

- helper-authority fixtures assert public evidence fields are present in the
  required sinks
- negative fixtures assert internal fields do not leak by default
- SARIF properties, CloudEvents extensions, JSON fields, and terminal verbose
  output are documented
- release notes name evidence-rendering changes

## Consequences

The product can use richer internal evidence while preserving customer-safe
language and avoiding accidental disclosure tooling in public artifacts.
