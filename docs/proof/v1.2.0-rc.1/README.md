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
| [adoption-proof-audit.md](../../rc/v1.2.0/adoption-proof-audit.md) | Current L6-01 through L6-05 audit and claim ceiling. |

## Authority

- [ADR 0021: Operator proof receipt contract](../../adr/0021-operator-proof-receipt-contract.md)
- [ADR 0022: Adoption doc version and link policy](../../adr/0022-adoption-doc-version-and-link-policy.md)
