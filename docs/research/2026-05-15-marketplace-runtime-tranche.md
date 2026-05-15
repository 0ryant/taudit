# GitHub Marketplace Runtime Tranche

Date: 2026-05-15
Scope: current tranche ledger for `0ryant/taudit-action` after the latest VS
Code and Azure DevOps marketplace publish work landed on `main`, plus the
follow-on action contract/runtime fix at commit
`b292eb855604b6a0a98d033e630290c8f1284c15`.

## Goal

Keep the GitHub Marketplace action lane resumable without losing the newer VS
Code and Azure DevOps publish evidence, blockers, and dependency ordering.

## Lanes

- Lane A: Action publish gate recovery
- Lane B: Action runtime and ledger sync
- Lane C: Hosted proof and blocker clearance
- Lane D: Cross-marketplace proof and backlink alignment

## Task Count

9 concrete tasks remain across 4 lanes.

## Task Ledger

### Lane A - Action publish gate recovery

1. [ ] Re-run hosted SHA smoke for `0ryant/taudit-action` commit
   `b292eb855604b6a0a98d033e630290c8f1284c15` in the disposable smoke repo once
   GitHub billing/spending-limit state is cleared.
2. [ ] Record runner-start evidence plus smoke outputs for that run:
   action SHA, `taudit-version`, `exit-code`, and `outcome`.
3. [ ] Cut the first immutable action tag only after hosted smoke executes and
   passes.
4. [ ] Move or create `v1` only after the immutable tag resolves correctly.
5. [ ] Create the GitHub release and Marketplace publish entry only after tags
   and smoke evidence are both complete.

### Lane B - Action runtime and ledger sync

6. [x] Keep the action ledger aligned with the current taudit release evidence:
   the last supervised tranche already moved the action repo to taudit `1.1.4`
   and fixed the runtime entrypoint.
7. [x] Carry forward the newer marketplace runtime outputs added in commit
   `c508dec`, including the Azure live-proof checklist, media shot list, and
   dogfood/self-audit guidance.

### Lane C - Hosted proof and blocker clearance

8. [ ] Clear the external GitHub-hosted smoke blocker without violating the
   Marketplace no-workflows rule for the action repo. Keep the smoke in a
   disposable external repo or equivalent hosted environment.
9. [ ] Keep action tags blocked until hosted smoke produces real runner
   execution evidence. Local smoke alone is not enough.

### Lane D - Cross-marketplace proof and backlink alignment

10. [ ] After action publish is unblocked, link the action listing/README to
    the live VS Code listing, live Azure DevOps listing, golden path, and demo
    story. Do not point at unpublished sibling listings.
11. [ ] Reuse the committed media/proof plan only after at least one live Azure
    DevOps `Taudit@1` receipt and one working VS Code publish path are recorded.

## Current Evidence

- observed: [`2026-05-14-marketplace-publish-supervised-tranche.md`](2026-05-14-marketplace-publish-supervised-tranche.md)
  records that `0ryant/taudit-action` is public, has root `action.yml`, has no
  workflows in the action repo, points `main` at taudit `1.1.4`, and pushed
  action commit `04afde52cdb8d4c96640672d92bfe74e9592a353`.
- observed: `0ryant/taudit-action` `main` now points at commit
  `b292eb855604b6a0a98d033e630290c8f1284c15`, which fixed graph-mode contract
  drift so `graph` no longer inherits `verify` or `scan`-only flags and wrapper
  graph output is persisted consistently.
- observed: the same tranche records local action gates passing:
  `npm test`, `npm run check`, `actionlint examples/*.yml`, and a local
  real-asset smoke that emitted `exit-code=0`, `outcome=pass`, and
  `taudit-version=1.1.4`.
- observed: the action runtime fix at
  `b292eb855604b6a0a98d033e630290c8f1284c15` was reverified locally with
  `npm test`, `npm run check`, and `actionlint examples/*.yml`.
- observed: the same tranche records hosted SHA smoke run `25891309430`
  failing before any runner step started because GitHub reported failed recent
  payments or a spending-limit block.
- observed: VS Code extension publish completed successfully as
  `algol.taudit-vscode@0.1.6`.
- observed: Azure DevOps extension authenticated readback confirmed
  `algol.taudit-azure-pipelines@0.1.9` live.
- observed: [`../integrations/azure-devops-marketplace-extension-contract.md`](../integrations/azure-devops-marketplace-extension-contract.md)
  is implemented v1, and
  [`../integrations/azure-devops-live-proof-checklist.md`](../integrations/azure-devops-live-proof-checklist.md)
  now defines the exact receipt needed for one real `Taudit@1` execution.
- observed: current package metadata on `main` is
  `integrations/vscode-extension/package.json` version `0.1.6` and
  `integrations/azure-devops-extension/package.json` plus
  `integrations/azure-devops-extension/vss-extension.json` version `0.1.9`.
- observed: recent marketplace commits on `main` include
  `c508dec Add marketplace runtime tranche outputs`,
  `9589946 Align ADO task context flags with CLI behavior`,
  `a46e2b0 Fix ADO relative path coercion in task wrapper`,
  `761a18c chore: sync marketplace package versions`, and
  `2b6a980 chore: finalize marketplace release metadata`.

## Hard Blockers

### Direct action blocker

- GitHub-hosted smoke for `0ryant/taudit-action` still has no runner-execution
  receipt. The last hosted attempt failed before the job started because of
  GitHub billing/spending-limit state. Until this is cleared, do not cut the
  immutable action tag, move `v1`, or create the Marketplace release entry.

### Cross-marketplace blocker that affects proof polish

- No real Azure DevOps `Taudit@1` live-proof receipt is recorded yet, so the
  cross-marketplace proof/media pack is still incomplete even though the VS
  Code and Azure DevOps listings are now live.

## Exact Next Steps

1. Restore a working GitHub-hosted smoke path for the disposable
   `taudit-action-smoke` repo and rerun the SHA smoke against action commit
   `b292eb855604b6a0a98d033e630290c8f1284c15`.
2. If the run starts and passes, capture the run URL plus the emitted
   `taudit-version`, `exit-code`, and `outcome` values in this ledger.
3. Only then cut the immutable action tag, verify tag resolution, move or
   create `v1`, and create the GitHub release / Marketplace publish entry.
4. In parallel but outside the direct action gate, capture one real Azure
   DevOps `Taudit@1` receipt so the action listing can reuse live sibling
   backlinks and proof media with a real hosted pipeline proof point.
