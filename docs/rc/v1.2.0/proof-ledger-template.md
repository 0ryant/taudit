# Proof Ledger Template

Status: Template only. This file is not a receipt and is not proof that a
surface is live, published, installable, hosted-smoked, or release-ready.

Use this guide to create receipts under
[docs/proof/v1.2.0-rc.1](../../proof/v1.2.0-rc.1/). Template field tokens use
the form `{{TEMPLATE_FIELD:name}}`; they are intentionally incomplete and must
be replaced with concrete evidence before a receipt can be cited.

## Surface Templates

| Surface | Receipt ID range | Template | Required before claim |
| --- | --- | --- | --- |
| Release assets | REL-001 | [release asset receipt](../../proof/v1.2.0-rc.1/templates/release-asset-receipt.md) | release asset and checksum claims |
| SBOM assets | REL-002 | [SBOM receipt](../../proof/v1.2.0-rc.1/templates/sbom-receipt.md) | SPDX or CycloneDX SBOM claims |
| Artifact attestations | REL-003 | [attestation receipt](../../proof/v1.2.0-rc.1/templates/attestation-receipt.md) | attestation or provenance verification claims |
| crates.io | CRATE-001 | [crates.io receipt](../../proof/v1.2.0-rc.1/templates/crates-io-receipt.md) | package-published or installable-from-registry claims |
| docs.rs | CRATE-002 | [docs.rs receipt](../../proof/v1.2.0-rc.1/templates/docs-rs-receipt.md) | public API docs rendered claims |
| GitHub Action | GHA-001 through GHA-004 | [GitHub Action receipt](../../proof/v1.2.0-rc.1/templates/github-action-receipt.md) | hosted smoke, tag, release, or Marketplace claims |
| Azure DevOps task | ADO-001 through ADO-002 | [Azure task receipt](../../proof/v1.2.0-rc.1/templates/azure-task-receipt.md) | package/readback or hosted `Taudit@1` task claims |
| VS Code extension | VSC-001 through VSC-004 | [VS Code extension receipt](../../proof/v1.2.0-rc.1/templates/vscode-extension-receipt.md) | package, install, command-smoke, listing, or readback claims |

## Copy Rules

1. Copy the narrowest template into `docs/proof/v1.2.0-rc.1/`.
2. Name the file with the receipt ID and surface, for example
   `REL-001-release-assets.md`.
3. Keep `Status: Template only` until every `{{TEMPLATE_FIELD:name}}` token is
   replaced with concrete evidence.
4. Link the completed receipt from
   [surface-ledger.md](../../proof/v1.2.0-rc.1/surface-ledger.md) only after the
   required evidence supports the bounded claim.
5. Do not paste secrets, raw tokens, private URLs, or unsanitized logs.
6. Keep the claim narrower than the evidence when uncertain.

## Ledger Row Template

| Receipt ID | Surface | Gate | Status | Receipt path | Claim ceiling |
| --- | --- | --- | --- | --- | --- |
| `{{TEMPLATE_FIELD:receipt_id}}` | `{{TEMPLATE_FIELD:surface}}` | `{{TEMPLATE_FIELD:gate}}` | Template | `{{TEMPLATE_FIELD:receipt_path}}` | `{{TEMPLATE_FIELD:claim_ceiling}}` |

The row above is a template row. It does not record proof and must not replace a
planned/pending receipt row unless a completed receipt exists.

## Next Dependency Unblocked

L1-08, L6-06, L6-07, L6-08, and QA-08 can now collect surface evidence against
surface-specific templates without changing adoption copy before receipts exist.
