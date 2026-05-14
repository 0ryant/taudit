# ADR 0007: Standardize releases through a repo-owned harness

- **Status:** Accepted
- **Date:** 2026-05-13
- **Context:** [release-strategy.md](../release-strategy.md), [RELEASE_GATES.md](../RELEASE_GATES.md), [release-trust.md](../release-trust.md), [ADR 0004](0004-prereleases-publish-to-crates-io.md), [`.github/workflows/release.yml`](../../.github/workflows/release.yml).

## Context

taudit's release story depends on three things being true at the same time:

1. the tag version must match the publishable crate versions,
2. the tag must have a matching changelog entry that explains the release, and
3. the GitHub release object must exist and carry the same stable or prerelease lane semantics as the tag.

Until now, those checks were split across workflow shell snippets and one metadata helper:

- `scripts/check-crates-publish-metadata.py` validated publishable crate metadata and version coherence,
- `.github/workflows/release.yml` created the GitHub release object inline with `gh release create`, and
- the GitHub release notes body came from `--generate-notes` rather than the repo-owned `CHANGELOG.md` entry.

That shape is too loose for a project that explicitly sells determinism and release trust. It allows the release object, changelog, and published crate to drift from one another, and it gives operators no single local command that mirrors what CI considers a valid release.

The concrete signals behind this ADR were:

- stable crates existed on crates.io with matching git tags but missing GitHub
   release objects,
- historical stable changelog entries existed at the tagged source snapshots but
   not in the checked-out working tree, and
- maintainers had no single repo-owned command to repair that drift.

## Decision

1. **Add a repo-owned release harness** at `scripts/release_harness.py`.
   It is the single entrypoint for:
   - validating a release tag against the CLI version,
   - requiring a matching `CHANGELOG.md` section,
   - delegating to the existing publish-metadata validator, and
   - creating or normalizing the GitHub release object from the changelog-backed notes body.

2. **GitHub release notes come from `CHANGELOG.md`, not generated notes.**
   The harness extracts the exact `## vX.Y.Z...` section and uses that as the GitHub release body. The changelog becomes the canonical explanation for both crates.io and GitHub consumers.

3. **The release workflow calls the harness instead of open-coded shell logic.**
   The workflow stays tag-triggered, but the validation and GitHub release creation steps route through the same harness operators can run locally.

4. **Local operators get matching entrypoints in `justfile`.**
   Release-day validation and release-object standardization are exposed as explicit recipes so the repo no longer relies on CI-only knowledge.

5. **Historical backfill uses the tagged source snapshot, not current `main`.**
   The harness accepts `--source-ref <tag>` so release notes and version checks
   can be derived from the tagged `CHANGELOG.md` and manifest state when
   repairing old GitHub release objects.

## Consequences

### Positive

- The release object, changelog, and published crate version are forced through one repo-owned path.
- Stable and prerelease lane semantics are standardized in one place instead of repeated in shell snippets.
- Future release-story fixes happen in one harness rather than scattered workflow edits.
- Operators can run the same checks locally before pushing a tag.

### Negative

- The workflow now depends on a Python harness that must stay compatible with both CI and local environments.
- Historical tags still require an explicit backfill invocation; the ADR adds a
   repair path, but it does not auto-repair older tags on its own.

### Follow-up

- If we later need asset-bundle verification or more historical repair logic,
  extend the harness rather than adding more inline workflow shell.
