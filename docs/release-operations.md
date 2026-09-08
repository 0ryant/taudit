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

## Channel cut order

A taudit release touches up to five channels. Cut them in this order, because
the later ones resolve assets or versions published by the earlier ones.

| # | Channel | Source of truth | Publish mechanism | Depends on |
|---|---------|-----------------|-------------------|------------|
| 1 | git tag + GitHub release | `CHANGELOG.md`, `crates/taudit-cli/Cargo.toml` | `just release-standardize vX.Y.Z` | — |
| 2 | crates.io (`taudit` + implementation crates) | crate manifests | `release.yml` publish job, or manual `cargo publish` in the workflow's order | tag |
| 3 | GitHub release assets (5 archives + `.sha256`) | `release.yml` build matrix, or `scripts/release_assets.py` | `release.yml`, or `gh release upload` | release object |
| 4 | Chocolatey (`taudit`) | `packaging/chocolatey/` | `just choco-sync`, then `choco push` (see `packaging/README.md`) | Windows asset (3) |
| 5a | VS Marketplace — Azure DevOps task (`algol.taudit-azure-pipelines`) | `integrations/azure-devops-extension/` | `npm run preflight`, then `tfx extension publish` | assets for every platform the task's default `version` pins (3) |
| 5b | VS Marketplace — VS Code extension (`algol.taudit-vscode`) | `integrations/vscode-extension/` | `azure-pipelines.vscode-extension.yml` publish stage, or `vsce publish` | nothing (it runs a locally installed `taudit`); republish only when the extension source changed |

Publisher credentials (crates.io token, Chocolatey API key, Marketplace PAT)
live in the tsafe vault and are injected per process with `tsafe exec`; they
are never pasted into a shell or committed.

Check the Marketplace state without credentials:

```bash
curl -s -X POST https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery \
  -H 'Content-Type: application/json' -H 'Accept: application/json;api-version=7.1-preview.1' \
  -d '{"filters":[{"criteria":[{"filterType":7,"value":"algol.taudit-vscode"}]}],"flags":1}'
```

## CI outage: local asset drill

`RELEASE_GATES.md` §2.2 requires the fallback to be recorded when GitHub
Actions is unavailable. v1.3.1 and v1.3.2 were published to crates.io with no
release assets at all, which left every asset-resolving channel (Azure DevOps
task default pin, Homebrew, Chocolatey) stranded on 1.1.x. The drill:

1. Run the quality gate locally (`just check`, plus `cargo deny` / `cargo audit`
   if installed) and `just release-check vX.Y.Z`.
2. Build each asset with the CI archive names:
   - Windows, on a Windows host: `just release-asset x86_64-pc-windows-msvc`
   - Linux x86_64, from any host with Docker (`cross` 0.2.5 cannot resolve the
     pinned `1.88` channel from a Windows host; from Git Bash prefix the
     command with `MSYS_NO_PATHCONV=1` so `/work` is not rewritten):
     ```bash
     docker run --rm -v "$PWD:/work" -v "$PWD/dist/linux-x86_64:/out" -w /work \
       rust:1.88 cargo build --release --locked -p taudit --target-dir /out
     just release-asset-from x86_64-unknown-linux-gnu dist/linux-x86_64/release/taudit
     ```
   - Linux aarch64: same with `--platform linux/arm64` (QEMU, slow), or on an
     arm64 host.
   - macOS x86_64 / aarch64: on a Mac, `just release-asset <triple>` for each
     (the packaging script refuses a binary whose `--version` disagrees with
     the manifest, so a stale `target/` cannot ship).
   - **No Mac / no arm64 host:** run `azure-pipelines.release-assets.yml` in
     the Azure DevOps project (org `0ryant`). It builds macOS x86_64 + aarch64
     and Linux aarch64 from the *published* crates.io tarball for the version
     you pass, so hosted agents never touch the private git dependencies, and
     publishes `release-assets-macos` / `release-assets-linux-aarch64`
     pipeline artifacts with the CI archive names. Requires the crate to be on
     crates.io first (channel 2). Queue it with
     `az pipelines run --project taudit --name taudit-release-assets --parameters version=X.Y.Z`
     (PAT from the vault via `tsafe exec --keys ado/PAT --env AZURE_DEVOPS_EXT_PAT=ado/PAT`),
     then `az pipelines runs artifact download` and upload with `gh`.
3. Upload: `gh release upload vX.Y.Z dist/taudit-*.tar.gz dist/taudit-*.zip dist/*.sha256 --clobber`.
4. Record in the release notes which assets were built locally. Locally built
   assets have **no** SLSA provenance attestation and **no** SBOM; do not claim
   `gh attestation verify` works for them. If Actions comes back, re-running
   the tag workflow replaces them with attested builds (`--clobber`).
5. Only after the assets for every platform the Azure DevOps task can run on
   (linux x86_64, windows x86_64, macos aarch64 at minimum) are live may the
   task's default `version` pin and the extension be published; otherwise
   pipelines using the default break at download time.

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