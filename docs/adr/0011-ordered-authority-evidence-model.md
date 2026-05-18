# ADR 0011: Ordered authority evidence model

- **Status:** Accepted
- **Date:** 2026-05-18
- **Context:** [ADR 0005](0005-authority-edge-classifier-and-witness-handoff.md), [ADR 0006](0006-exploit-path-view-and-ruleset.md), [authority-timed evidence workstream](../rc/v1.2.0/workstreams/authority-timed-evidence.md).

## Context

The existing exploit-path view and helper-authority rules already infer useful
paths. The missing center is a shared ordered evidence model consumed by parsers,
core rules, exploit graph projection, schemas, reports, and sinks.

Without that model, rules can drift into broad PATH lint, and reports can make
stronger claims than the static evidence supports.

## Decision

v1.2 authority-timed findings require explicit ordered evidence events. The
minimal public model contains:

- `PathMutation` with step index, job id, channel, and source trust zone;
- `SecretMaterialized` or `AuthorityMaterialized` with step index, authority
  origin, and authority class;
- `HelperExecution` with step index, command, helper resolution, and call site;
- `HelperReceivesAuthority` with authority transport and confidence;
- optional witness status, same-job caveat, technical score, and product label.

The core ordering invariant is:

```text
PathMutation.step_index < AuthorityMaterialized.step_index <= HelperExecution.step_index
```

Rules may not emit a helper-resolution authority finding unless the ordered
evidence exists. Default output remains classifier language. It must not claim
CVE status, exploitation, disclosure acceptance, observed sink behavior, witness
next actions, canary details, or private source anchors.

## Lane Ownership

- **L2 API/contracts** owns public wire fields and schema naming.
- **L3 parser parity** owns platform-specific step/event stamping.
- **L4 core graph/rules** owns event builder, ordered predicate, catalog
  consumption, and downgrade logic.
- **L5 reports/sinks** owns projection without overclaiming.

## Acceptance Gates

- fixtures cover positive order, reversed order, same-step, cross-job negative,
  and missing materialization cases
- helper resolution, authority transport, and authority origin are enums or
  schema-backed values, not ad hoc message strings
- exploit graph JSON validates against schema
- default-output tests prove no internal witness, CVE, disclosure, canary, or
  private-anchor leakage
- `cargo test -p taudit-cli --test exploit_path_graph`

## Consequences

This turns the RC's flagship detection value into evidence-bearing product
behavior rather than a rule bundle. It also unlocks lower false positives,
stable SIEM filtering, and internal witness handoff without making taudit the
proof engine.
