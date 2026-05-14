# Marketplace Publish Supervised Tranche

Date: 2026-05-14
Stop floor: 2026-05-15 01:13 BST
Scope: GitHub Marketplace readiness and publish path for `0ryant/taudit-action`.

Parallel track:
Visual Studio Marketplace planning now lives in
[`2026-05-15-visual-studio-marketplace-publish-track.md`](2026-05-15-visual-studio-marketplace-publish-track.md).

## Source Of Truth

- Council ratification: merge taudit PR #28 first, then immutable action tag, moving `v1`, GitHub release, hosted smoke, Marketplace Agreement/UI publish.
- GitHub Marketplace docs: action repo must be public, contain one root action metadata file, and contain no workflow files; publishing is through a release UI with Marketplace checkbox and Developer Agreement gate.

## Tasks

- [x] T1: Reconcile taudit branch with current `origin/main`.
- [x] T2: Diagnose and fix PR #28 failing `quality` check.
- [x] T3: Keep/update the task ledger with observed blockers and decisions.
- [x] T4: Run local release-equivalent verification after fixes.
- [x] T5: Mark PR #28 ready and merge once green or record blocker.
- [x] T6: Verify `0ryant/taudit-action` Marketplace repo shape.
- [x] T7: Add hosted smoke path if compatible with Marketplace no-workflows rule, or create disposable external smoke plan.
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
- 2026-05-14 23:21 BST: Observed `v1.1.2` GitHub release has zero assets.
- Failed `v1.1.2` release run root cause:
  `cargo-semver-checks 0.47.0` requires Rust 1.91, but the release tag uses
  Rust 1.88. The log itself identifies `cargo-semver-checks 0.44.0` as the
  Rust-1.88-compatible version.
- Observed `taudit@1.1.3` is not present on crates.io (`404 Not Found`).
- Local release gate passed for `v1.1.3`: `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `python3 scripts/check-crates-publish-metadata.py
  --expected-release-version 1.1.3`, `python3 scripts/release_harness.py check
  --tag v1.1.3`, `cargo deny check licenses bans sources`, `cargo audit`, and
  `rustup run 1.88.0 cargo semver-checks check-release --workspace
  --all-features`.
- Tested `cargo-semver-checks 0.44.0`; it installs on Rust 1.88 but cannot parse
  this workspace's Rust 1.88 rustdoc JSON format. `0.46.0` passed the local
  Rust 1.88 semver gate.
- The `v1.1.3` tag release workflow failed before asset generation because
  `cargo-semver-checks 0.46.0` requires Rust 1.90 when installed in CI.
- Council ratified cutting `v1.1.4` with Rust 1.90 isolated only to the
  `cargo-semver-checks` install/check steps. Normal taudit MSRV, build, and test
  gates stay on Rust 1.88.
- PR #28 merged to `main` at merge commit
  `6f1927fb1d258b9b6babdc9ef5854966f7ff88c3` after all GitHub checks passed.
- `v1.1.4` release workflow run `25890117240` passed end to end. GitHub release
  `v1.1.4` is non-draft/non-prerelease and has 12 uploaded assets: five
  platform archives, five checksum files, and SPDX/CycloneDX SBOMs.
- crates.io shows `taudit 1.1.4` created at `2026-05-14T23:15:49.060868Z`.
- `0ryant/taudit-action` Marketplace shape verified: public repository, root
  `action.yml`, no workflows in the action repository.
- `0ryant/taudit-action` `main` now points at `taudit 1.1.4` and includes a
  fixed `bin/taudit-action` entrypoint. Pushed action commit:
  `04afde52cdb8d4c96640672d92bfe74e9592a353`.
- Local action gates passed after the entrypoint fix: `npm test` (14 tests),
  `npm run check`, `actionlint examples/*.yml`.
- Local real-asset smoke passed from `/tmp/taudit-action-smoke` by invoking
  `bin/taudit-action` with `INPUT_VERSION=1.1.4`; output contained
  `exit-code=0`, `outcome=pass`, and `taudit-version=1.1.4`.
- Hosted SHA smoke was attempted in `0ryant/taudit-action-smoke` run
  `25891309430` against action commit
  `04afde52cdb8d4c96640672d92bfe74e9592a353`. GitHub failed the job before any
  runner step started. Check-run annotation: "The job was not started because
  recent account payments have failed or your spending limit needs to be
  increased. Please check the 'Billing & plans' section in your settings".
- Council ratified stopping before action tags until GitHub hosted smoke can
  actually execute. Do not create immutable `v1.0.0`, movable `v1`, or
  Marketplace release from local evidence alone.

## Decisions

- DEC[1]: Use a temporary Python virtualenv for local YAML validation because
  the managed system Python rejects direct `pip install --user` under PEP 668.
- DEC[2]: Council ratified superseding the assetless `v1.1.2` release with a
  fresh `v1.1.3` cut from fixed main. Do not move, retag, or manually backfill
  `v1.1.2`.
- DEC[3]: Supersede failed `v1.1.3` with `v1.1.4`, isolating Rust 1.90 to
  semver-checks only while keeping the crate's release build/test toolchain at
  Rust 1.88.
- DEC[4]: Stop before action tags because the required GitHub-hosted smoke is
  blocked by account billing/spending-limit state and produced no runner
  execution evidence.

## Stop Conditions

- Hosted smoke failure.
- Tag or release mismatch.
- Marketplace metadata warning/error.
- Developer Agreement or 2FA UI blocks publication.
- Any unreviewed code/security gate failure.
