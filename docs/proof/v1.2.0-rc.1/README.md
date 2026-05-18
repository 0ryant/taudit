# v1.2.0-rc.1 Proof Ledger

This directory stores proof receipts for the `v1.2.0-rc.1` adoption surfaces.
The directory is proof storage, not proof by itself.

A file here proves only the claim supported by its completed receipt fields and
attached command/run evidence. Templates, planned inventories, and empty ledger
rows are not receipts and must not be cited as proof that a surface is live,
published, installable, hosted-smoked, or release-ready.

## Rules

- Use [receipt-template.md](receipt-template.md) for every receipt.
- Keep unproven surfaces marked planned/pending receipt.
- Do not widen a claim beyond the receipt outcome.
- Do not store secrets, tokens, raw PATs, private URLs, or unsanitized logs.
- Record residual risk even when the outcome passes.
- Link receipts from adoption docs only after the required fields are complete.

## Status Values

| Status | Meaning |
| --- | --- |
| Template | Format only; not evidence. |
| Planned/pending receipt | Required proof has not been recorded. |
| Receipt recorded | Required fields are complete and evidence is linked. |
| Receipt rejected | Evidence exists but does not satisfy the gate. |
| Superseded | A newer receipt replaces the claim. |

## Files

| File | Purpose |
| --- | --- |
| [receipt-template.md](receipt-template.md) | Required field template for completed receipts. |
| [surface-ledger.md](surface-ledger.md) | Planned receipt inventory for GitHub Action, Azure DevOps, VS Code, crates.io/docs.rs, release trust, marketplace media, and docs links. |
| [templates/release-asset-receipt.md](templates/release-asset-receipt.md) | Template for `REL-001` release asset and checksum receipts. |
| [templates/sbom-receipt.md](templates/sbom-receipt.md) | Template for `REL-002` SPDX and CycloneDX SBOM receipts. |
| [templates/attestation-receipt.md](templates/attestation-receipt.md) | Template for `REL-003` artifact attestation receipts. |
| [templates/crates-io-receipt.md](templates/crates-io-receipt.md) | Template for `CRATE-001` crates.io publish/readback receipts. |
| [templates/docs-rs-receipt.md](templates/docs-rs-receipt.md) | Template for `CRATE-002` docs.rs render/readback receipts. |
| [templates/github-action-receipt.md](templates/github-action-receipt.md) | Template for `GHA-001` through `GHA-004` GitHub Action receipts. |
| [templates/azure-task-receipt.md](templates/azure-task-receipt.md) | Template for `ADO-001` and `ADO-002` Azure DevOps task receipts. |
| [templates/vscode-extension-receipt.md](templates/vscode-extension-receipt.md) | Template for `VSC-001` through `VSC-004` VS Code extension receipts. |
| [proof-ledger-template.md](../../rc/v1.2.0/proof-ledger-template.md) | RC guide for copying surface templates and adding completed ledger rows. |
| [adoption-proof-audit.md](../../rc/v1.2.0/adoption-proof-audit.md) | Current L6-01 through L6-05 audit and claim ceiling. |

## Authority

- [ADR 0021: Operator proof receipt contract](../../adr/0021-operator-proof-receipt-contract.md)
- [ADR 0022: Adoption doc version and link policy](../../adr/0022-adoption-doc-version-and-link-policy.md)
