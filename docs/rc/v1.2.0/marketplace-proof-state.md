# v1.2.0-rc.1 Marketplace Proof State

Status: proof-gated state for L6-03 and L6-04.

This file reconciles the GitHub Action, VS Code, and Azure DevOps marketplace
surfaces for published-copy wording. It does not prove an external surface by
itself. A surface may have local contracts, package manifests, runtime tranche
notes, or implementation checklists; published-copy claims still require a
completed receipt under [docs/proof/v1.2.0-rc.1/](../../proof/v1.2.0-rc.1/README.md).

## Claim Rule

Until the relevant receipt exists, use "planned", "proof-gated", or
"planned/pending receipt". Do not describe the surface as live, installable,
ready for adopters, hosted-smoked, or proven from local scaffolds, manifests,
or tranche notes alone.

## Surface State

| Surface | Local state this repo may cite | Receipt required before stronger wording | Published-copy state |
| --- | --- | --- | --- |
| GitHub Marketplace action | Contract, wrapper checklist, and local/runtime notes exist for `0ryant/taudit-action`; hosted runner execution, immutable tag, moving `v1`, release, and listing receipts are not recorded in this RC ledger. | GHA-001 through GHA-004 in [surface-ledger.md](../../proof/v1.2.0-rc.1/surface-ledger.md). | Planned/pending receipt. |
| VS Code extension | Local docs disagree: operator-facing docs avoid publication proof while runtime notes record `algol.taudit-vscode@0.1.6`. No completed VS Code receipt is recorded in this RC ledger. | VSC-001 through VSC-004 in [surface-ledger.md](../../proof/v1.2.0-rc.1/surface-ledger.md). | Planned/pending receipt for published-copy claims. |
| Azure DevOps task | Contract, manifests, live-proof checklist, and runtime readback notes exist; no real `Taudit@1` operator-run receipt is recorded in this RC ledger. | ADO-001 and ADO-002 in [surface-ledger.md](../../proof/v1.2.0-rc.1/surface-ledger.md). | Planned/pending receipt for task-ready adoption proof. |

## Backlog State

- `TODOS.md` is proof-gated: implementation checklist items do not imply
  Marketplace publication, installability, tag readiness, or hosted smoke.
- External listing backlinks and marketplace media stay planned/pending receipt
  until the source surface receipt exists and the backlink/media receipt is
  recorded.
- README, USERGUIDE, provider docs, proof receipts, parser/core/output files,
  and release harness files were outside this lane's write scope.

## Next Dependency Unblocked

L6-06, L6-07, and L6-08 can now record proof packs without debating wording
state first. L6-02 and L6-12 can use this file as the bounded reference when
removing marketplace overclaims from broader operator docs.
