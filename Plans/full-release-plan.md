# taudit full release plan

This plan assumes a public open-source v0.1 release under 0ryant.

## Council synthesis

The release blocker is trust surface, not missing features. The core product already looks credible, but the public package and repository story are not yet coherent enough to tag and publish.

The council converged on three release gates:

1. Release integrity
2. Product proof
3. Convenience and expansion

Only the first two gates should block `v0.1.0`.

## Gate 1: Release integrity

- [x] Add top-level license file matching `MIT OR Apache-2.0`
- [x] Correct repository ownership references from `ktilcock` to `0ryant`
- [x] Replace placeholder source-install text in `README.md`
- [x] Make homepage/repository links consistent across manifests and docs
- [ ] Ensure the canonical public repo URL resolves at `github.com/0ryant/taudit` before the next publish/tag
- [x] Add `SECURITY.md` with disclosure path and expected response model
- [x] Add `CONTRIBUTING.md` with local quality gate and development flow
- [x] Add `CHANGELOG.md` with initial release notes for `v0.1.0`
- [x] Decide support posture: GitHub Issues only, or add `SUPPORT.md`

## Gate 2: Product proof

- [x] Verify the documented install path from a clean environment
- [x] Verify the documented source-build path from a clean checkout
- [x] Re-run canonical examples and confirm README output still matches reality
- [x] Regenerate or refresh example reports if output has drifted
- [x] Treat JSON schema files and example reports as release contracts
- [x] Confirm terminal, JSON, SARIF, and CloudEvents outputs work as documented
- [x] Confirm test counts and product claims in `README.md` are still accurate
- [ ] Tag only after docs, examples, and shipped behavior match exactly

## Gate 3: Convenience and expansion

These improve adoption but should not block the first public tag.

- [x] Add `SUPPORT.md` if issue templates are not enough
- [x] Add GitHub issue templates for bug reports and feature requests
- [x] Add release-page copy with one canonical install path and one canonical example
- [x] Add release-trust documentation for archives, checksums, and SBOM
- [ ] Add package-manager distribution beyond `cargo install` if demand justifies it
- [ ] Expand parser coverage beyond GitHub Actions

## Release order

1. Fix identity and legal surface.
2. Fix README install and usage accuracy.
3. Add minimum governance docs.
4. Re-verify examples, schemas, and report outputs.
5. Cut `v0.1.0` only after a clean install and example replay succeed.

## Explicit non-blockers

- Homebrew or other package-manager polish
- A second CI parser
- Broad support automation beyond basic issue handling
- Major feature expansion unrelated to release trust

## Suggested launch posture

- Support: GitHub Issues for product support
- Security: private disclosure path in `SECURITY.md`
- License: dual MIT or Apache-2.0
- Install: one canonical `cargo install` path and one source-build path
- Proof: one canonical workflow example and one canonical machine-readable report example