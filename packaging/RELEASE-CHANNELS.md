# taudit release channels

How taudit ships to package managers. Adapted from the portfolio playbook in the
tsafe repo (`packaging/RELEASE-CHANNELS.md` there, the reference implementation);
this file is the taudit-specific version and the one to follow here.

`docs/release-operations.md` is the per-release runbook and cut order. This file
explains the model each channel rests on.

## The model, and where taudit differs from tsafe

tsafe's source repo is private, so it publishes artifacts through a separate
public `tsafe-releases` repo that package manifests fetch from. **taudit's source
repo is public**, which removes that whole layer:

| | tsafe | taudit |
|---|---|---|
| Source repo | private | **public** |
| Release assets | public `tsafe-releases` repo | **this repo's own GitHub Releases** |
| apt hosting | Pages on `tsafe-releases` | **Pages on this repo's `gh-pages` branch** |
| apt signing key | `apt/GPG_SIGNING_KEY` | **`apt/taudit/GPG_SIGNING_KEY`** (per-tool) |

Everything else carries over unchanged:

- **crates.io is the primary channel.** `cargo install taudit` always works.
- **Manifests fetch by URL + checksum.** No channel bundles a binary; each one
  downloads a release archive and verifies its SHA-256.
- **Every key and token lives in the tsafe vault** and is used through
  `tsafe exec`. It is never on a command line, in shell history, or handled in
  the clear. This is the rule the whole thing rests on.
- **Per-tool trust anchors.** taudit signs its apt repo with its own key, not
  tsafe's, so one channel's key compromise does not implicate another tool.

## Signing posture

- **Binaries are unsigned** on every platform. No paid Authenticode, no Apple
  notarization. An "unknown publisher" prompt is the accepted cost of a free OSS
  project; the release notes say so rather than implying otherwise.
- **apt is the exception, because its signature is free and mandatory.** A modern
  apt client refuses an unsigned repo, so the `Release` file is signed with a
  self-generated OpenPGP key. That is repo-integrity signing, not code signing.
- **Integrity everywhere:** a `<archive>.sha256` sidecar per asset (what
  `release.yml` writes and the Azure DevOps task installer verifies), rolled up
  into a `SHA256SUMS`, and the same hashes pinned into the Homebrew formula and
  the Chocolatey install script.
- **Provenance where CI produced it:** assets built by the tag workflow carry
  GitHub build-provenance attestations and SBOMs. Assets built locally or on
  Azure DevOps during a CI outage do **not**, and the release notes must say
  which is which. Never tell a user to run `gh attestation verify` against an
  asset that has no attestation.

## The channels

| Channel | Manifest source | Verifies | Gate before publishing |
|---|---|---|---|
| crates.io | crate manifests | registry TLS | tag + quality gate |
| GitHub Releases | `release.yml` / `scripts/release_assets.py` | `.sha256` sidecars | archives built for every target |
| Chocolatey | `packaging/chocolatey/` | sha256 in the install script | Windows asset live and anonymously downloadable |
| apt | `packaging/apt/` + `packaging/nfpm/` | OpenPGP `Release` signature | signed index install-tested locally |
| Homebrew | `packaging/homebrew/taudit.rb` | sha256 per platform | all four tarballs live |
| VS Marketplace ×2 | `integrations/` | Marketplace signing | assets live for every platform the task pins |

## Per-release sequence

Ordered, because each step consumes what the previous one published. The full
runbook with commands is in `docs/release-operations.md`.

1. **Tag + GitHub release** from the changelog section.
2. **crates.io** publish.
3. **Release assets** — five archives + `.sha256` sidecars, then `SHA256SUMS`.
4. **Sync the manifests** from those checksums: `just choco-sync`,
   `just homebrew-sync`. Neither invents a hash; both read the sidecars, and both
   fail loudly if an archive is missing rather than writing a placeholder.
5. **Chocolatey** — pack, install-test elevated, push. First-time and every new
   version goes through community moderation; the install claim stays "not
   installable until approved" until it is.
6. **apt** — build the `.deb`, build the index, sign from the vault,
   install-test, publish to `gh-pages`. See `packaging/apt/README.md`.
7. **Homebrew** — push the filled formula to the `homebrew-taudit` tap.
8. **Marketplace extensions** — only after every platform asset the task pins is
   live, or pipelines on the default version break at download time.

## Honest channel status

A manifest in this directory is a tracked source file. It does not prove a
channel is live, submitted, approved, or installable. Do not document an install
command for a channel until that specific version is actually installable through
it — the Chocolatey moderation queue is the usual reason a version exists but
cannot yet be installed.
