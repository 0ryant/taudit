# ADR 0004: Prereleases publish to crates.io, gated by Cargo's resolver

- **Status:** Accepted
- **Date:** 2026-05-01
- **Context:** [release-strategy.md](../release-strategy.md), prior tag automation in [`.github/workflows/release.yml`](../../.github/workflows/release.yml).

## Context

taudit ships on a two-lane release model: **stable** (crates.io, version-pinned, conservative) and **edge** (fast iteration). The earliest framing in [release-strategy.md §4](../release-strategy.md) left two split options on the table for prereleases:

1. **GitHub-only edge** — prerelease tags create GitHub releases but skip `cargo publish`.
2. **crates.io prereleases** — prerelease tags publish to crates.io alongside stable, relying on Cargo's resolver to keep stable consumers safe.

The doc allowed both but the practical-split table leaned toward option 1 ("`cargo publish` runs only for stable tags").

In practice, option 1 is friction we don't want to pay: bleeding-edge consumers (downstream pilots, internal CI matrices, contributors testing detection deltas before stable promotion) end up downloading binaries from GitHub Releases and `cargo install --git`, neither of which gives them the same dependency-pinning ergonomics as crates.io. The "edge harness" stays second-class.

The product question: *Can we publish prereleases to crates.io without eroding stable-lane trust?*

## Decision

1. **Prereleases publish to crates.io** under semver pre-release identifiers (`vM.m.p-beta.N`, `vM.m.p-rc.N`, etc.). The same `cargo publish` step that runs on stable tags also runs on prerelease tags. No separate registry, no GitHub-only fork.

2. **The release workflow trigger widens** to match both `v[0-9]+.[0-9]+.[0-9]+` (stable) and `v[0-9]+.[0-9]+.[0-9]+-*` (prerelease). One workflow, two lanes, with a single conditional that sets `--prerelease` on `gh release create` when the tag carries a hyphen.

3. **Stable-lane safety comes from Cargo's resolver, not from withholding the artifact.** The resolver's prerelease-skip rule is the gate: a version requirement without a pre-release component **never** matches a pre-release version. So a consumer with `taudit = "1.1"` or running `cargo install taudit` (no version) cannot accidentally pull `1.1.0-beta.1` — they continue to resolve the latest stable. Prereleases are opt-in via explicit version pin only (`taudit = "=1.1.0-beta.1"`, `cargo install taudit --version 1.1.0-beta.1`).

4. **Changelog honesty applies equally.** Prerelease entries spell out detection delta and FP/FN risk per the [release-strategy doc](../release-strategy.md). A `-beta.N` suffix is not a license to skip the trust paragraph.

5. **GitHub release metadata distinguishes the lane.** Prerelease tags create releases with the `--prerelease` flag set, removing the **Latest** badge in the UI and excluding the release from `gh release view --latest`. Asset downloads (binaries, SBOMs, attestations) work identically.

6. **Yank semantics are independent.** A bad prerelease can be yanked without affecting stable; a yanked stable does not retroactively yank a related prerelease.

## Consequences

### Positive

- **Single workflow, single registry.** Maintainers don't keep two parallel release pipelines in their heads. The cost of cutting a `-beta.N` is the same as cutting a stable patch.
- **Better ergonomics for early adopters.** A pilot team can pin `taudit = "=1.1.0-beta.1"` in their `Cargo.toml`, lock it, and roll forward at their own pace — same workflow they use for any other crate.
- **Detection-delta dialogue happens earlier.** Bleeding-edge consumers can run a `-beta.N` against their own pipelines and surface false positives before the version reaches stable. The `1.0.x → 1.1.0-beta.1 → 1.1.0` path becomes a real soak window, not a private branch.
- **No invented mechanism.** This is exactly how compilers, lints, and tooling crates already handle prereleases on crates.io (e.g. `cargo`, `clippy`, `tokio` previews, `rustfmt`). taudit fits the prevailing pattern.

### Negative / costs

- **`cargo publish` cost on every prerelease.** Each tag triggers an actual registry publish (irreversible without yank). Mistakes here are not "delete the GitHub Release and re-tag"; the version is permanently consumed.
  - *Mitigation:* the existing CI gates (fmt, clippy, test, deny, audit) run on prerelease tags too. A bad prerelease can be yanked but the version number cannot be reused — pre-flight quality is not optional.
- **Footgun for unbounded version requirements.** A consumer pinning `taudit = "*"` is technically still safe because Cargo's prerelease-skip rule applies to `*` too — but a consumer literally writing `taudit = "1.1.0-*"` is asking to track prereleases and will get them. We document this; we don't try to prevent it.
- **More versions in the registry index over time.** Cosmetic only; crates.io has no hard cap and the resolver doesn't pay a meaningful cost for the extra versions.

### Trust framing

The single non-obvious load-bearing claim is that **Cargo's resolver protection is sufficient**. We rely on it the same way the rest of the Rust ecosystem does. If a future change to Cargo were to weaken prerelease-skip semantics (extremely unlikely — it is documented stable behaviour), this ADR would need revisiting. We do not invent our own gate.

## Follow-up

- [`.github/workflows/release.yml`](../../.github/workflows/release.yml) trigger widened to match prerelease tags, with conditional `--prerelease` on `gh release create`.
- [release-strategy.md §4](../release-strategy.md) rewritten with explicit consumer-resolution table and the reconciled "publish to both lanes" policy. The earlier "`cargo publish` runs only for stable tags" framing is superseded by this ADR.
- First prerelease cut: **v1.1.0-beta.1**, bundling all post-v1.0.12 unreleased work (determinism contract fixes, GHA env shadowing, composite-action CWD removal, ecosystem CI standardisation, FinOps smoke).

## Compliance

- Release workflow gate-matrix unchanged: prerelease tags must pass fmt, clippy, test, deny, audit before publish.
- `CHANGELOG.md` carries a section per prerelease tag, with the same detection-delta + FP/FN paragraph required of stable releases.
- The maintainer checklist in [release-strategy.md §Maintainer checklist](../release-strategy.md#maintainer-checklist-before-cargo-publish) applies identically to prerelease tags. A `-beta.N` is not a draft.

## References

- [release-strategy.md](../release-strategy.md) — versioning policy, cadence, gate, mechanics.
- Cargo book, version requirements: <https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#version-requirement-syntax>
- crates.io publishing reference: <https://doc.rust-lang.org/cargo/reference/publishing.html>
- Cargo source on prerelease handling (resolver): `cargo::core::resolver::version_prefs` (search for `pre_release`).
