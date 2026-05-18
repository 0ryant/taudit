# ADR 0023: Ecosystem evidence envelope and stack contracts

- **Status:** Accepted
- **Date:** 2026-05-18
- **Context:** [positioning](../positioning.md), [ecosystem evidence schema](../../contracts/schemas/ecosystem-evidence-envelope-v0.schema.json), [tsign consumer docs](../integrations/tsign-consumer.md), [axiom consumer docs](../integrations/axiom-consumer.md).

## Context

Authority Evidence Platform unlocks stack use by sibling systems, but taudit
must stay the graph and evidence producer. It must not become the attestation
system, enforcement brain, runtime writer, or external policy orchestrator.

## Decision

Post-RC stack work is split into explicit contracts:

- ecosystem evidence envelope v1 for shared correlation fields;
- `tsign` authority graph predicate contract for signing graph claims;
- `axiom` decision contract for consuming graph and attestation evidence;
- `tsafe` and runtime remediation contract for linking findings to containment
  evidence without giving taudit runtime authority.

taudit may emit or consume fields such as `correlationid`, `scanrunid`,
`pipelineId`, `subject` URN, `provenanceparent`, rules version, and invariant
set digest. It does not enforce runtime changes or write to sibling runtimes.

## Lane Ownership

- **Post-RC ecosystem lane** owns integration schemas and docs.
- **L5 CloudEvents/output** owns additive fields that stay within taudit.
- **Sibling project owners** own tsign, axiom, tsafe, and runtime behavior.

## Acceptance Gates

- taudit output validates against its own schemas and the ecosystem envelope
  version it claims
- stack smoke tests run outside the v1.2 RC unless explicitly scoped
- docs separate taudit producer responsibilities from sibling consumer duties

## Consequences

The RC can unlock a larger trust stack without bloating taudit into every layer
of that stack.
