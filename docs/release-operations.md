# Release operations

Maintainer-facing release operations are standardized through
`scripts/release_harness.py`. The harness is the canonical path for validating a
tag, rendering changelog-backed notes, and creating or normalizing the GitHub
release object.

Policy lives in [release-strategy.md](release-strategy.md) and
[RELEASE_GATES.md](RELEASE_GATES.md). This page is the practical runbook.

## Current release cut

For a new tag on the checked-out release commit:

```bash
just release-check v1.1.3
just release-notes v1.1.3
just release-standardize v1.1.3
```

What each command does:

1. `release-check` validates tag shape, requires the CLI version to match the
   tag, requires a matching `CHANGELOG.md` section, and runs the publish
   metadata validator.
2. `release-notes` prints the exact changelog section that will become the
   GitHub release body.
3. `release-standardize` creates or updates the GitHub release object from that
   changelog body and applies the stable or prerelease lane semantics implied by
   the tag.

The tag-triggered GitHub Actions workflow uses the same harness, so local and
CI release behavior stay aligned.

## Historical backfill

For a stable or prerelease tag that already exists in git and crates.io, but is
missing or has a drifted GitHub release object:

```bash
just release-backfill v1.1.2
```

That command reads `CHANGELOG.md` and `crates/taudit-cli/Cargo.toml` from the
tagged source snapshot rather than the current working tree, then creates or
normalizes the GitHub release object for the historical tag.

Backfill intentionally skips the publish metadata check because it does not
re-publish crates; it only repairs the GitHub release surface.

## Direct harness usage

If you need to run the harness without `just`:

```bash
python scripts/release_harness.py check --tag v1.1.3 --require-local-tag
python scripts/release_harness.py notes --tag v1.1.3
python scripts/release_harness.py ensure-github-release --tag v1.1.3

python scripts/release_harness.py ensure-github-release \
  --tag v1.1.2 \
  --source-ref v1.1.2 \
  --skip-publish-metadata
```

## Failure modes

- Missing changelog section: add the exact `## vX.Y.Z...` section first.
- Tag/version mismatch: fix the CLI version or use the correct tag.
- Historical backfill on current `main`: pass `--source-ref <tag>` and
  `--skip-publish-metadata`.
- `gh release view` still fails after standardization: confirm `gh` auth and
  repository permissions, then rerun the harness with `--repo OWNER/REPO`.