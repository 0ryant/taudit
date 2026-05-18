# ADR 0012: Public output identity contract

- **Status:** Accepted
- **Date:** 2026-05-18
- **Context:** [contract platform workstream](../rc/v1.2.0/workstreams/contract-platform.md), [cross-sink contract test](../../crates/taudit-cli/tests/cross_sink_contract.rs), [finding fingerprint docs](../finding-fingerprint.md).

## Context

Current cross-sink tests pin `rule_id` and `fingerprint`. The RC promise is
stronger: JSON, SARIF, CloudEvents, baselines, suppressions, and terminal
triage must preserve the same finding identity and operator waiver identity.

## Decision

Canonical public finding identity is:

- `rule_id`;
- `fingerprint`;
- `suppression_key`;
- `finding_group_id`;
- platform token;
- source file identity;
- scan or event provenance when a sink supports it.

Core and `taudit-api` own meaning. Reporters and sinks only project identity.
No reporter-specific sanitization may participate in fingerprint input.

CloudEvents category, event type, platform token, and Bitbucket token behavior
must be documented and tested so consumers do not parse sink-local conventions.

## Lane Ownership

- **L2 API/contracts** owns field definitions in Rust API and schemas.
- **L4 core** owns `rule_id_for`, `compute_fingerprint`,
  `compute_suppression_key`, and `compute_finding_group_id`.
- **L5 reports/sinks** owns exact projection across JSON, SARIF, terminal, and
  CloudEvents.
- **QA/conformance** owns cross-sink identity expansion.

## Acceptance Gates

- one fixture proves identity equality across JSON, SARIF, CloudEvents, baseline
  material, and suppression lookup
- terminal verbose output exposes enough identity for triage without changing
  fingerprint inputs
- contract examples include current identity fields
- `cargo test -p taudit --test cross_sink_contract`

## Consequences

Downstream SIEMs, baselines, suppressions, PR bots, and future stack consumers
can join findings without re-deriving identity or parsing human messages.
