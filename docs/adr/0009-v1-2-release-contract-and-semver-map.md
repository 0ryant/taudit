# ADR 0009: v1.2 release contract and SemVer map

- **Status:** Accepted
- **Date:** 2026-05-18
- **Context:** [ADR 0004](0004-prereleases-publish-to-crates-io.md), [ADR 0007](0007-standardize-release-harness.md), [v1.2 RC charter](../rc/v1.2.0/charter.md), [release gates and SemVer workstream](../rc/v1.2.0/workstreams/release-gates-semver.md).

## Context

The v1.2 direction is a release candidate, not an immediate stable promise. The
CLI package is currently on the stable product line, while `v1.2.0-rc.1` will
need its own changelog entry, crate-version map, release notes, and prerelease
workflow evidence before tagging.

The council found two hard facts during planning: the CLI manifest was still
`1.1.5`, and the release harness and publish metadata checker reject a
`v1.2.0-rc.1` tag until the manifest and changelog agree.

## Decision

The v1.2 RC product tag is `v1.2.0-rc.1`.

Before a tag is cut:

1. The CLI crate version must be `1.2.0-rc.1`.
2. `CHANGELOG.md` must contain `## v1.2.0-rc.1`.
3. The changelog entry must start with `Detection delta (read first)`.
4. The release entry must name finding-count, false-positive, false-negative,
   schema, output, CLI, fingerprint, suppression, and migration impact.
5. The release entry must record the crate-version map for `taudit`,
   `taudit-api`, and implementation crates.
6. GitHub release semantics must remain prerelease and not Latest.

`taudit-api` and implementation crates may stay on their current lines only
when the release ships no public Rust or wire-contract change for them. Any
public wire-type change requires an intentional API version decision before
tagging.

## Lane Ownership

- **L1 release coordination** owns `CHANGELOG.md`, root `Cargo.toml`,
  `crates/*/Cargo.toml`, `Cargo.lock`, release scripts, and release notes.
- **L2 API/contracts** must approve any `taudit-api`, schema, or output surface
  bump before L1 tags.
- **L6 docs/operator evidence** owns adoption copy that names the RC.

## Acceptance Gates

- `python scripts/release_harness.py check --tag v1.2.0-rc.1`
- `python scripts/check-crates-publish-metadata.py --expected-release-version 1.2.0-rc.1`
- `cargo metadata --locked --format-version 1`
- release workflow review confirms prerelease, not Latest
- changelog review confirms the detection delta and crate-version map

## Consequences

The RC can be published to crates.io, but only as a coherent prerelease. The
stable `v1.2.0` tag remains blocked by release gates, soak, corpus evidence, and
any new semantic payload that requires a second RC.
