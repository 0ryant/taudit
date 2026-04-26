# release/

Signing material for taudit release artifacts.

## Status

**Not yet active.** `taudit.pub` in this directory is a **placeholder**
— there is no corresponding private key, no release artifact has been
signed against it, and verification with this key WILL fail.

Cryptographic signing of release archives is tracked under
"Future work — signed releases (minisign)" in `../docs/release-trust.md`.
The placeholder file exists so the verification path
(`release/taudit.pub` checked into the repo, downloaded by consumers)
is wired and ready to swap in once a real keypair is generated.

## Files

| File          | Purpose                                                      |
| ------------- | ------------------------------------------------------------ |
| `taudit.pub`  | minisign Ed25519 public key (placeholder until signing ships) |
| `README.md`   | This file                                                    |

## Activating signing

When a real keypair is generated:

1. Replace the contents of `taudit.pub` with the real public key
   (single line, base64, prefixed with `untrusted comment:`).
2. Update `docs/release-trust.md` — move the "Future work" section
   into "Trust boundary" and document the signing cadence.
3. Add `.minisig` files as release assets per the recipe in
   `docs/release-trust.md`.

The private key MUST be generated and kept offline; CI must not ever
hold it. Signing happens maintainer-side after the GitHub release is
created by the tag workflow.
