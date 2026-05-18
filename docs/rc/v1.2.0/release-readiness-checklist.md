# v1.2.0-rc.1 Release Readiness Checklist

Status: QA-08 wiring document. This file is a checklist, not proof.

This document joins the RC release gates from [RELEASE_GATES.md](../../RELEASE_GATES.md), the v1.2 release contract in [ADR 0009](../../adr/0009-v1-2-release-contract-and-semver-map.md), the conformance gate in [ADR 0020](../../adr/0020-output-conformance-harness-and-rc-gate.md), and the proof receipt contract in [ADR 0021](../../adr/0021-operator-proof-receipt-contract.md).

## Gate Boundary

`v1.2.0-rc.1` tag readiness means the release candidate can be tagged and published as a prerelease. It does not mean stable `v1.2.0` is ready.

Stable promotion is blocked until the latest RC completes the soak, corpus, fuzz, dogfood, semver, and closeout receipt gates in [RELEASE_GATES.md](../../RELEASE_GATES.md) section 2.2.

## QA-08 Required Checks

Run these from the repository root with fresh output before the RC tag is pushed.

| Gate | Command or review | Required result | Evidence owner |
| --- | --- | --- | --- |
| Release harness | `python scripts/release_harness.py check --tag v1.2.0-rc.1` | exits zero after CLI version and `CHANGELOG.md` tag section align | L1 |
| Publish metadata | `python scripts/check-crates-publish-metadata.py --expected-release-version 1.2.0-rc.1` | exits zero after crate-version map decisions are final | L1 |
| Conformance harness | `python scripts/conformance_harness.py --root . --format json` | reports `status: pass`, zero failing checks, zero pending checks, and full conformance | L5/QA |
| Changelog contract | review `CHANGELOG.md` `## v1.2.0-rc.1` | starts with `Detection delta (read first)` and names finding-count, FP/FN, schema, output, CLI, fingerprint, suppression, migration, and crate-version impact | L1 |
| Release workflow semantics | review release workflow and harness behavior | GitHub release is prerelease and not Latest for hyphenated tags | L1 |
| Proof ledger shape | [proof ledger](../../proof/v1.2.0-rc.1/README.md) and [surface ledger](../../proof/v1.2.0-rc.1/surface-ledger.md) | required receipt rows exist before tag; rows are not cited as proof until completed | L6 |

## QA-08 Required Receipts

Record completed receipts under `docs/proof/v1.2.0-rc.1/` after the tag workflow or equivalent fallback produces the evidence. Planned rows are not proof.

| Receipt ID | Surface | Required before calling RC complete |
| --- | --- | --- |
| REL-001 | GitHub release assets and checksums | release URL, asset names, SHA-256 checksums, source commit SHA, timestamp, operator, outcome, residual risk |
| REL-002 | SBOM assets | SPDX and CycloneDX asset names, checksums, release URL, source commit SHA, timestamp, operator, outcome, residual risk |
| REL-003 | GitHub Artifact Attestations | `gh attestation verify` evidence for at least one archive and one SBOM, source commit SHA, timestamp, operator, outcome, residual risk |
| CRATE-001 | crates.io publish | crates.io URL/readback, package version, source commit SHA, checksum or registry digest where available, timestamp, operator, outcome, residual risk |
| CRATE-002 | docs.rs render | docs.rs URL/build status, package version, source commit SHA, timestamp, operator, outcome, residual risk |
| DOC-001 | Docs link/path audit | link/path check command, source commit SHA, timestamp, operator, outcome, residual risk |

Adoption-surface receipts such as GitHub Action, Azure DevOps task, VS Code, marketplace media, and external listing backlinks are required only for claims that name those surfaces as live, hosted, installable, or published in the RC.

## Stable Promotion Handoff

Do not reuse QA-08 as a stable gate waiver. The stable `v1.2.0` promotion needs the latest RC closeout receipts plus:

- one-week semantic soak with no parser, public wire-type, or fingerprint semantic payload changes;
- zero new P0/P1 public-contract findings during the soak;
- public corpus dogfood pass from [dogfood-corpus.md](../../dogfood-corpus.md);
- scheduled fuzz clean during the soak;
- maintainer dogfood report;
- CI outage fallback record when GitHub Actions cannot produce the normal release artifacts;
- `cargo semver-checks check-release --workspace --all-features`;
- empty `CHANGELOG.md` `## Unreleased` stub re-scaffolded for the next cycle.

## Current Status

As of this checklist, the RC remains pending until the commands above pass and receipts are recorded. Do not cite this file as release proof; cite the command output and completed receipt files.

## Next Dependency Unblocked

L1-07 and QA-08 can now review release readiness without confusing RC tag/publish readiness with stable promotion.
