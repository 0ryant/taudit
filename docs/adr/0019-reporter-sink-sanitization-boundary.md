# ADR 0019: Reporter and sink sanitization boundary

- **Status:** Accepted
- **Date:** 2026-05-18
- **Context:** [output injection corpus](../../crates/taudit-cli/tests/output_injection_corpus.rs), [terminal reporter](../../crates/taudit-report-terminal/src/lib.rs), [SARIF reporter](../../crates/taudit-report-sarif/src/lib.rs).

## Context

Pipeline YAML and custom invariant strings are attacker-controlled in many
review contexts. Reporters must be safe to render, while machine outputs must
preserve structured values for downstream consumers.

## Decision

The sanitization boundary is sink-specific:

- terminal strips control bytes and renders safe human text;
- SARIF escapes markdown and location surfaces according to SARIF expectations;
- JSON and CloudEvents preserve raw structured values through JSON encoding;
- no rendered or sanitized value participates in fingerprint, suppression key,
  or group id computation.

Every hostile rendering fixture must preserve stable identity across sinks.

## Lane Ownership

- **L5 reports/sinks** owns reporter behavior and snapshots.
- **L4 core** owns identity computation before rendering.
- **QA/conformance** owns hostile corpus tests.

## Acceptance Gates

- hostile corpus covers control bytes, markdown links, SARIF-sensitive text,
  path separators, CRLF, and long fields
- identity is stable across raw and sanitized projections
- JSON and CloudEvents keep machine-readable values valid
- terminal snapshots remain readable and safe

## Consequences

taudit can be used in PR comments, terminals, code scanning, and SIEM pipelines
without turning reporter rendering into a second parsing or mutation layer.
