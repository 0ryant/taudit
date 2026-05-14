# Marketplace Publish Supervised Tranche

Date: 2026-05-14
Stop floor: 2026-05-15 01:13 BST
Scope: GitHub Marketplace readiness and publish path for `0ryant/taudit-action`.

## Source Of Truth

- Council ratification: merge taudit PR #28 first, then immutable action tag, moving `v1`, GitHub release, hosted smoke, Marketplace Agreement/UI publish.
- GitHub Marketplace docs: action repo must be public, contain one root action metadata file, and contain no workflow files; publishing is through a release UI with Marketplace checkbox and Developer Agreement gate.

## Tasks

- [x] T1: Reconcile taudit branch with current `origin/main`.
- [x] T2: Diagnose and fix PR #28 failing `quality` check.
- [ ] T3: Keep/update the task ledger with observed blockers and decisions.
- [ ] T4: Run local release-equivalent verification after fixes.
- [ ] T5: Mark PR #28 ready and merge once green or record blocker.
- [ ] T6: Verify `0ryant/taudit-action` Marketplace repo shape.
- [ ] T7: Add hosted smoke path if compatible with Marketplace no-workflows rule, or create disposable external smoke plan.
- [ ] T8: Cut immutable action tag only after PR #28 is merged and smoke path is ready.
- [ ] T9: Move/create `v1` only after immutable tag resolution is verified.
- [ ] T10: Create GitHub release only after tag checks pass.
- [ ] T11: Complete Marketplace UI/Developer Agreement publish if available; otherwise record exact external blocker.
- [ ] T12: End with clean repos, pushed state, and explicit residual risks.

## Evidence Log

- 2026-05-14 23:13 BST: PR #28 observed as draft/open with one failed
  `quality` check and `origin/main` 14 commits ahead of the branch.
- Failed GitHub check root cause: `scripts/generate-authority-invariant-schema.py
  --check` reported stale schema/category enums.
- Merged `origin/main` into `codex/marketplace-action-tranche`; merge commit
  `bbeddc9`.
- Regenerated schema check passed: `All four schemas match generator output.`
- Isolated validator venv check passed:
  `OK: validated 13 file(s) against authority-invariant-v1.schema.json`.

## Decisions

- DEC[1]: Use a temporary Python virtualenv for local YAML validation because
  the managed system Python rejects direct `pip install --user` under PEP 668.

## Stop Conditions

- Hosted smoke failure.
- Tag or release mismatch.
- Marketplace metadata warning/error.
- Developer Agreement or 2FA UI blocks publication.
- Any unreviewed code/security gate failure.
