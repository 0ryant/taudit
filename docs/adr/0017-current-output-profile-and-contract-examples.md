# ADR 0017: Current output profile and contract examples

- **Status:** Accepted
- **Date:** 2026-05-18
- **Context:** [contracts examples](../../contracts/examples), [report schema](../../contracts/schemas/taudit-report.schema.json), [CloudEvents schema](../../contracts/schemas/taudit-cloudevent-finding-v1.schema.json).

## Context

Schemas may allow optional fields for backward compatibility, while current
taudit output may always emit those fields. Compatibility examples can therefore
validate while failing to demonstrate the current output contract.

## Decision

v1.2 keeps two related concepts:

- compatibility schemas: permissive enough for supported older documents;
- current output profile: the fields current taudit promises to emit.

Contract examples must include the current profile. A current-profile assertion
must fail when current outputs omit promised identity, evidence, schema URI,
source, provenance, suppression, or event fields, even if the compatibility
schema would still validate.

## Lane Ownership

- **L2 schemas/examples** owns schema compatibility and current-profile rules.
- **L5 reports/sinks** owns generated or golden examples.
- **QA/conformance** owns profile checks in release gates.

## Acceptance Gates

- contract examples are regenerated or refreshed from real fixtures
- schema validation passes
- current-profile validation checks required current fields
- examples include identity fields from ADR 0012 and public evidence fields from
  ADR 0013 when those fields are shipped

## Consequences

Downstream consumers can learn from examples without reverse-engineering live
CLI output, and compatibility does not hide current-output regressions.
