# ADR 0021: Operator proof receipt contract

- **Status:** Accepted
- **Date:** 2026-05-18
- **Context:** [marketplace trust pack](../rc/v1.2.0/workstreams/marketplace-trust-pack.md), [TODOS.md](../../TODOS.md), [release trust](../release-trust.md).

## Context

The RC adoption story depends on external surfaces: GitHub Marketplace action,
Azure DevOps task, VS Code extension, crates.io, GitHub release assets, SBOMs,
and attestations. Local scaffolding is not proof that an operator can use those
surfaces.

## Decision

Operator proof is recorded as receipts, not prose claims.

A receipt contains:

- surface name;
- version, tag, or extension id;
- source commit;
- run URL or listing URL;
- artifact name and checksum when applicable;
- result;
- date;
- bounded claim;
- residual risk;
- evidence owner.

No doc, README, marketplace copy, or release note may say a surface is published,
installable, hosted-smoked, or proven until a receipt exists.

The receipt home for this RC is `docs/proof/v1.2.0-rc.1/`.

## Lane Ownership

- **L6 docs/operator evidence** owns proof files and adoption copy.
- **External surface owners** own GitHub Action, Azure DevOps, and VS Code hosted
  runs.
- **L1 release coordination** owns release asset, SBOM, attestation, crates.io,
  and docs.rs receipts.

## Acceptance Gates

- GitHub Action has hosted SHA smoke, immutable tag, moving `v1`, release, and
  Marketplace receipt before Marketplace-ready copy ships
- Azure DevOps task has hosted smoke and artifact receipt before task-ready copy
  ships
- VS Code has package, checksum, install smoke, command smoke, and listing
  readback before extension-published copy ships
- release assets, checksums, SBOMs, attestations, crates.io, and docs.rs are
  recorded after the tag workflow

## Consequences

Operator-facing claims become auditable. This also prevents local-only demos and
screenshots from being mistaken for marketplace readiness.
