# Release Gates + SemVer Workstream

## Goal

Define the v1.2.0-rc.1 release direction so the next candidate is useful for
real adopters without turning crates.io into a scratchpad. The target release
shape is `v1.2.0-rc.1` for the CLI product, with stable promotion to `v1.2.0`
only after the written release gates are satisfied and the changelog detection
delta is honest enough for pinned CI consumers.

This workstream owns the release-lane decision, SemVer rationale, changelog
delta requirements, and publish-churn controls for the v1.2.0 RC. It does not
own feature scope.

## Why This Takes taudit Skyward

taudit is judged like a compiler, linter, and security control-plane tool, not
like a throwaway CLI. `docs/release-strategy.md` already frames stable releases
around trust, version pinning, detection semantics, and a calm crates.io lane.
For v1.2.0, that discipline is the product: users can test the next detection
model explicitly through `v1.2.0-rc.1`, while stable users stay on the latest
non-prerelease line until the RC has survived real inputs, fuzzing, and public
contract checks.

The `rc` name matters. `docs/RELEASE_GATES.md` distinguishes beta churn from an
RC that is "stable in intent; soak in progress." That makes v1.2.0-rc.1 a
credible pilot artifact while still refusing the stable promise until the gates
clear.

## Current Evidence

- `docs/release-strategy.md` defines two lanes: stable trust on crates.io and
  edge velocity through prerelease or GitHub-side artifacts. It also states that
  detection semantics are part of the public API and that patch releases must
  not smuggle graph reinterpretation.
- `docs/release-strategy.md` and `.github/workflows/release.yml` agree that
  both stable tags (`vM.m.p`) and prerelease tags (`vM.m.p-*`) publish through
  the same release workflow, while Cargo's resolver keeps prereleases out of
  stable dependency resolution unless consumers opt in explicitly.
- `docs/RELEASE_GATES.md` defines the lane names (`beta.N`, `rc.N`, stable),
  beta-to-RC gates, and RC-to-stable gates: one-week soak, zero new P0/P1 public
  contract findings, public-corpus dogfood, scheduled fuzz cleanliness,
  maintainer self-attestation, CI outage fallback, blocker closure, and
  `CHANGELOG.md` reset.
- `CHANGELOG.md` shows the pattern to keep: every recent stable and prerelease
  carries `Detection delta (read first)`, with explicit directionality for
  finding count, false-positive/false-negative shifts, schema changes, and
  migration notes.
- `CHANGELOG.md` also records the failure mode to avoid: `v1.1.0-rc.2`
  partially published lower-level crates before the top-level product crate,
  and `v1.1.0-rc.3` added a metadata gate to prevent that class of churn.
- `.github/workflows/release.yml` runs fmt, clippy, workspace tests, release
  harness validation, `cargo deny`, `cargo audit`, SBOM generation, archive
  builds, artifact attestations, and crates.io publish. Stable tags additionally
  run `cargo semver-checks`; prerelease tags skip that CI step and rely on
  changelog migration notes until stable promotion.
- `scripts/release_harness.py` requires tag shape `vX.Y.Z` or
  `vX.Y.Z-suffix`, requires the CLI crate version to match the tag version,
  extracts release notes from the matching `CHANGELOG.md` heading, and marks
  hyphenated GitHub releases as prereleases.
- `scripts/check-crates-publish-metadata.py` allows the CLI product version,
  `taudit-api`, and implementation crates to have separate SemVer tracks, but
  it requires implementation crate versions to remain coherent and path
  dependency versions to match the actual target crate versions.
- `release-plz.toml` currently only points release-plz at `CHANGELOG.md`; it is
  not a release authority for v1.2.0 version selection or unattended publishing.
- Current workspace versions are `taudit` CLI `1.1.5`, `taudit-api` `0.4.1`,
  and implementation crates such as `taudit-core` `3.0.1` as observed through
  `cargo metadata --no-deps --format-version 1`.
- `docs/release-trust.md` documents the tagged artifact trust surface:
  checksums, SPDX and CycloneDX SBOMs, GitHub build attestations, and a publish
  job that waits for release creation, SBOMs, and archive builds.

## Deliverables

- **RC naming plan:** cut the first candidate as `v1.2.0-rc.1`, set the CLI
  manifest to `version = "1.2.0-rc.1"`, add a `CHANGELOG.md` section headed
  `## v1.2.0-rc.1`, and let the release harness create or normalize a GitHub
  prerelease. Consumers opt in with `cargo install taudit --version
  1.2.0-rc.1` or an exact Cargo requirement.
- **Prerelease lane discipline:** publish `v1.2.0-rc.1` to crates.io only when
  it is a coherent release candidate, not for every merge. Churn before RC
  readiness belongs in GitHub workflow artifacts, nightly-style GitHub
  prereleases, or source builds as described by `docs/release-strategy.md`.
- **Stable promotion rule:** promote to `v1.2.0` only when the latest RC payload
  clears `docs/RELEASE_GATES.md` section 2.2. Parser logic, JSON/SARIF/
  CloudEvents wire types, or fingerprint semantic changes after `rc.1` require
  `rc.2` and a restarted soak.
- **Changelog detection delta contract:** every v1.2.0 RC and the final stable
  entry must start with `Detection delta (read first)`. The paragraph or table
  must compare against the previous stable line and the previous RC, state
  whether users should expect more or fewer findings, call out FP/FN movement,
  and name schema, CLI, fingerprint, or migration impact.
- **SemVer choice map:** record a per-crate decision before tagging:
  `taudit` CLI uses `1.2.0-rc.1` for the product release if v1.2.0 is additive
  versus v1.1.x; a patch is reserved for no detection/schema/CLI behaviour
  change, and `2.0.0` is reserved for authority-model, fingerprint, schema, or
  CLI compatibility breaks.
- **`taudit-api` version choice:** keep `0.4.1` if no wire-type contract changes
  are shipped. If JSON/SARIF/CloudEvents public wire types change, bump the API
  line intentionally, for example to `0.5.0-rc.1`, and update workspace
  dependency requirements to the compatible `0.5` form expected by
  `scripts/check-crates-publish-metadata.py`.
- **Implementation crate version choice:** keep implementation crates on the
  existing published line when their package contents do not need a new publish.
  If implementation crates change, bump all non-API implementation crates
  coherently. Use patch for compatible fixes, minor for additive public Rust API,
  and a major such as `4.0.0-rc.1` if `cargo semver-checks` or intentional API
  review shows a break, even if the CLI product remains `1.2.0-rc.1`.
- **Release trust statement:** v1.2.0-rc.1 is not acceptable until the release
  workflow can produce the same trust surface as stable releases: release notes
  from `CHANGELOG.md`, binary archives, checksums, SPDX and CycloneDX SBOMs,
  GitHub attestations, and crates.io publish after dependent jobs succeed.
- **Churn guard:** no stable tag should be cut merely to repair messaging,
  discoverability, or release-object metadata unless it is the coherent unit of
  change the stable lane is meant to carry. Prefer fixing prerelease release
  notes or cutting a superseding RC over creating registry noise.

## Acceptance Criteria

- `CHANGELOG.md` contains a `v1.2.0-rc.1` section with `Detection delta (read
  first)`, explicit FP/FN and finding-count direction, migration notes, and no
  stale claim that stable consumers auto-receive the RC.
- The CLI crate version equals `1.2.0-rc.1` when the `v1.2.0-rc.1` tag is cut,
  satisfying `scripts/release_harness.py`.
- The crate-version map is written down before tagging: CLI product version,
  `taudit-api` wire-contract version, and coherent implementation crate version
  line are each justified by detection, schema, CLI, or Rust API impact.
- `scripts/check-crates-publish-metadata.py --expected-release-version
  1.2.0-rc.1` passes before any tag is pushed.
- The release workflow marks `v1.2.0-rc.1` as a GitHub prerelease and does not
  mark it Latest, matching the hyphenated-tag behavior in
  `.github/workflows/release.yml` and `scripts/release_harness.py`.
- Stable promotion to `v1.2.0` is blocked until the latest RC completes the
  `docs/RELEASE_GATES.md` section 2.2 soak and trust gates with no semantic
  payload changes that would require a new RC.
- `release-plz.toml` remains changelog-only for this workstream unless a
  separate reviewed change makes release-plz part of the audited release
  authority.

## Risks / Non-Goals

- **Risk: RCs can still create registry churn.** Cargo protects stable
  consumers from prerelease resolution, but every crates.io version is still a
  permanent public signal. Use RC numbers sparingly.
- **Risk: prerelease semver checks are skipped in CI.** That is intentional per
  `docs/release-strategy.md`, but stable promotion must run the semver gate and
  must not rely on a prerelease suffix to hide Rust API or wire-contract churn.
- **Risk: partial publish recurrence.** The `v1.1.0-rc.2` incident in
  `CHANGELOG.md` shows why metadata and dependency-version checks must run
  before any registry upload.
- **Risk: API/core/product version confusion.** The CLI version is the product
  version. `taudit-api` is the public embedding and wire-type contract.
  `taudit-core` and parser/reporter/sink crates are implementation crates that
  must still be semver-honest because they are published.
- **Non-goal: define v1.2.0 feature scope.** This brief decides how the release
  is named, gated, versioned, trusted, and promoted.
- **Non-goal: make release-plz the publisher.** The current config in
  `release-plz.toml` is only a changelog path.
- **Non-goal: promise stable dates.** Calendar targets can be useful elsewhere,
  but stable promotion here is evidence-gated.

## Suggested Verification

- `python3 scripts/release_harness.py check --tag v1.2.0-rc.1`
- `python3 scripts/check-crates-publish-metadata.py --expected-release-version 1.2.0-rc.1`
- `cargo metadata --no-deps --format-version 1` and inspect CLI, `taudit-api`,
  implementation crate, and path dependency versions.
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo deny check licenses bans sources`
- `cargo audit`
- For stable promotion only: `cargo semver-checks check-release --workspace --all-features`
- After the tag workflow: verify `gh release view v1.2.0-rc.1` reports a
  prerelease, release assets exist, checksums match, SBOMs are attached, and
  `gh attestation verify` succeeds for at least one archive and one SBOM as
  described in `docs/release-trust.md`.
