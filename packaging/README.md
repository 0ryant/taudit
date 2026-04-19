# Packaging Manifests

This directory is the tracked source of truth for taudit package-manager manifests.

It exists so packaging metadata can be reviewed and versioned like any other release contract rather than living only in release automation or ad hoc tap repositories.

## Layout

- `homebrew/` — Homebrew formula for a third-party tap
- `nix/` — Nix derivation

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

## Notes

- These files may contain placeholder hashes until a concrete release is cut.
- Treat `packaging/` as the reviewable source of truth for package-manager metadata.