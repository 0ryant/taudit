# Packaging Manifests

This directory is the tracked source of truth for taudit package-manager manifests.

It exists so packaging metadata can be reviewed and versioned like any other release contract rather than living only in release automation or ad hoc tap repositories.

## Layout

- `homebrew/` — Homebrew formula for a third-party tap
- `nix/` — Nix derivation
- `chocolatey/` — Chocolatey community package source (`taudit.nuspec` + `tools/chocolateyinstall.ps1`)
- `apt/` — APT repository build/sign script and runbook (`build-apt-repo.sh`, `README.md`)
- `nfpm/` — nFPM template the `.deb` / `.rpm` are rendered from
- `RELEASE-CHANNELS.md` — the model every channel here rests on

## Homebrew

The Homebrew formula is intended for a third-party tap repository such as `homebrew-taudit`.

Typical flow:

1. copy `packaging/homebrew/taudit.rb` into the tap repo as `Formula/taudit.rb`
2. replace placeholder SHA-256 values with the published release asset hashes
3. commit and push the tap update

## Nix

The Nix derivation builds taudit from the tagged source release.

Release maintenance:

1. bump `version`
2. update the source hash
3. update the Cargo dependency hash

## apt (Debian/Ubuntu)

`apt/` holds the repository build script and the full runbook; `nfpm/taudit.yaml`
is the package template. The `.deb` is built by nFPM from the **already-built**
release binary, so it ships the same bytes as `taudit-x86_64-linux.tar.gz`.

The built, signed repo is published to this repository's `gh-pages` branch and
served by GitHub Pages at `https://0ryant.github.io/taudit/apt`. taudit's source
repo is public, so unlike tsafe there is no separate `-releases` assets repo.

The repo's `Release` file is signed with a free, self-generated OpenPGP key held
in the vault under `apt/taudit/` — apt refuses an unsigned repo. That is
repo-integrity signing; the binary inside the `.deb` is unsigned like every other
channel. Details and the two Windows-specific gpg gotchas: [`apt/README.md`](apt/README.md).

```bash
just deb && just apt-index      # then sign + install-test per apt/README.md
```

## Homebrew

`just homebrew-sync` sets the formula's version and all four platform `sha256`
values from the release sidecars. It fails if any of the four archives is
missing rather than leaving a placeholder, so the formula is either fully
truthful for a version or the command errors.

Copy the filled formula to the `homebrew-taudit` tap as `Formula/taudit.rb`.

## Chocolatey

The Chocolatey package does not bundle a binary. Its install script downloads
`taudit-x86_64-windows.zip` from the GitHub release for the matching `vX.Y.Z`
tag and verifies the SHA-256 stamped into the script, so the release asset must
exist (and be anonymously downloadable) before the package can install at all.

Per release:

1. build or download the Windows asset and its `.sha256` sidecar into `dist/`
   (`just release-asset x86_64-pc-windows-msvc`, or fetch the CI-built asset)
2. `just choco-sync` — stamps version, tag URLs, and checksum into
   `chocolatey/taudit.nuspec` and `chocolatey/tools/chocolateyinstall.ps1`, then
   runs `choco pack` into `dist/taudit.X.Y.Z.nupkg`
3. once the GitHub release and its Windows asset are live, test from an
   elevated shell: `choco install taudit --source dist -y`, `taudit --version`,
   `choco uninstall taudit -y`
4. push with the API key injected only into the push process, never pasted
   into a shell: `tsafe exec -- choco push dist/taudit.X.Y.Z.nupkg --source https://push.chocolatey.org/`
5. record the moderation state in the release notes. The package is **not**
   installable by the public until Chocolatey moderation approves it, so do
   not document `choco install taudit` in the README before that.

Chocolatey moderation guidelines (the three raised on tsafe's first
submission) are handled in the nuspec:

- `iconUrl` — the 128×128 Marketplace icon
  (`integrations/vscode-extension/assets/icon.png`) served by jsDelivr, pinned
  to the commit that last changed the file rather than a tag, so the URL is
  permanent and valid before the release tag exists. If the icon changes, re-pin
  to the new commit.
- `projectUrl` (crates.io product page) and `projectSourceUrl` (GitHub source
  repository) are different, and the latter points at source code.
- `<title>` is more descriptive than the bare package id.

## Notes

- These files may contain placeholder hashes until a concrete release is cut.
- Release asset names are fixed by `.github/workflows/release.yml` and mirrored
  by `scripts/release_assets.py`: `taudit-{x86_64,aarch64}-{linux,macos}.tar.gz`
  and `taudit-x86_64-windows.zip`, each with a `<name>.sha256` sidecar in
  `sha256sum` format. Every channel above resolves those exact names.
- A manifest here is only a tracked source file. It does not by itself prove
  that a channel is live, submitted, approved, or installable for a tag; the
  maintainer cutting the release verifies each channel and records what was
  actually published.
- Treat `packaging/` as the reviewable source of truth for package-manager metadata.