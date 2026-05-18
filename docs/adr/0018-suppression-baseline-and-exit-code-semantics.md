# ADR 0018: Suppression, baseline, and exit-code semantics

- **Status:** Accepted
- **Date:** 2026-05-18
- **Context:** [verify docs](../verify.md), [baselines docs](../baselines.md), [suppressions docs](../suppressions.md), [CLI contract tests](../../crates/taudit-cli/tests/cli_contract.rs).

## Context

Adoption depends on predictable gating. Operators need to know how scan versus
verify, baselines, suppressions, severity thresholds, and partiality interact.
They also need stable exit codes.

## Decision

The release contract includes one maintained matrix for:

- `scan` versus `verify`;
- baseline new-only versus gate-on-all;
- severity threshold;
- dedupe;
- `suppress`, `downgrade`, and `tag-only` suppression modes;
- expired, unmatched, and critical waivers;
- `--show-all`;
- `--ignore-partial`;
- exit codes `0`, `1`, and `2`.

`scan` stays informational. `verify` is the policy gate. Structural failures and
configuration errors exit `2`. Violations exit `1`. Passing gates exit `0`.
Suppression metadata must survive every machine sink even when a finding is
hidden or downgraded for human output.

## Lane Ownership

- **L5 CLI/output** owns `crates/taudit-cli/src/main.rs`, report projection, and
  table-driven tests.
- **L4 core** owns baseline and suppression matching semantics.
- **L6 docs** owns matrix publication.

## Acceptance Gates

- table-driven CLI tests cover all matrix rows
- cross-sink tests prove suppression metadata survives JSON, SARIF, and
  CloudEvents
- docs state every exit code and waiver mode
- changelog calls out any behavior delta

## Consequences

Teams can make taudit a required check without guessing which findings block
merges or why a historical finding still appears in audit output.
