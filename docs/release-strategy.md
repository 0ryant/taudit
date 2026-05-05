# Release strategy — stable vs edge

taudit behaves more like a **static analysis engine for authority propagation** than a hobby CLI. Consumers judge it like **compilers, linters, and security tools**: version pinning must stay meaningful, and the **registry** must not broadcast “this might change underneath you tomorrow.”

This page is the **policy** for *when* and *how* we version. For *what* a tag ships and how to verify binaries and SBOMs, see [`release-trust.md`](release-trust.md).

---

## 1. Two lanes

### Stable lane — crates.io

- **Goal:** **trust** for `cargo install taudit` and pinned CI (`--locked`).
- **Rough ceiling:** about **one publish per calendar week** — a **maximum**, not a quota. Some weeks: **zero** releases (that is good; it signals stability).
- **Better rule than the ceiling:** publish when you have a **coherent, defensible unit of change** — and **never** the old pattern of **multiple registry drops per day**.
- **Contents:** bug fixes, small features, and changes where **detection and contracts are unambiguous** (see [Hard gate](#2-hard-gate-for-cratesio) below).
- **Versioning:** **patch and minor only** on the `1.x` line today (`1.0.x`, `1.1.x`, …). Reserve **major** for a **model** or **compatibility** story consumers must opt into (see [Version semantics](#3-version-semantics)).

### Edge lane — GitHub

- **Goal:** **velocity** — try ideas, ship often, get feedback without implying registry stability.
- **Mechanism:** **unlimited** GitHub **pre-releases**, **commit-adjacent tags**, or **nightly-style** builds from `main` (whatever automation the maintainers wire; the *policy* is “fast iteration lives here”).
- **Not a substitute** for a calm crates.io line: teams that need bleeding edge should consume **GitHub releases / artifacts / source**, not expect the same churn on crates.io.

**Split in one line:** velocity → **GitHub (edge)**; trust → **crates.io (stable)**.

---

## 2. Hard gate for crates.io

Publish to **crates.io** only when **all** of the following hold:

1. **Output formats are stable** — JSON graph, SARIF, terminal shape, CloudEvents, and any versioned schema bumps are intentional and documented.
2. **No breaking change** without the right **semver** (and changelog honesty) in:
   - **CLI flags** and exit-code contract where documented as stable
   - **Output schemas** consumers parse
   - **Detection semantics** — *this matters most*: if the **authority model** or how findings are derived **changes meaningfully**, that is **not** a patch release, even if the diff is small.

**Rule of thumb:** for this domain, **detection semantics are part of the public API**. If users would reasonably need to **re-baseline**, **re-triage**, or **re-pin policy** because “the tool sees the pipeline differently,” call that out and bump **minor or major** accordingly — never smuggle it into a patch as “just a fix.”

Security fixes that *must* ship on the registry are allowed **out of band**; the changelog should still spell out **detection impact**.

---

## 3. Version semantics

Avoid “patch spam” where every commit is `1.0.N+1` with no signal. Use semver to **communicate**:

| Line | Meaning (consumer expectation) |
|------|--------------------------------|
| **`1.0.x`** | **Stable behaviour** — fixes and tightening that do not change the *meaning* of authority or materially shift what existing graphs “mean.” |
| **`1.1.x`** (next minor) | **Additive detection** — new rules, new nodes/edges, or new invariants that can **surface more** findings without redefining old ones; migration should be “read changelog, adjust if you care about new checks.” |
| **`2.0.0`** | **Model or compatibility break** — different authority **interpretation**, intentional breaking schema/CLI, or a reset consumers must plan for. |

Patch releases are for **unambiguous** corrections (true bugs, wrong propagation, contract drift that restores documented behaviour) — not for silent **reinterpretation** of the graph.

---

## 4. Prerelease vs stable — mechanics

Separate **stable** and **prerelease** in three places: **semver in manifests**, **Git tags + automation**, and **GitHub Release metadata**.

**Policy (per [ADR 0004](adr/0004-prereleases-publish-to-crates-io.md)):** prereleases publish to **crates.io** alongside stable, gated by Cargo's resolver. The earlier framing ("`cargo publish` runs only for stable tags") is **superseded** — both lanes use the same registry, the same workflow, and the same quality gates. Stable-lane safety comes from how the resolver handles pre-release identifiers, not from withholding the artifact.

### Semver (Cargo and crates.io)

- **Stable:** `version = "M.m.p"` only (no hyphen suffix). Plain semver is what most consumers pin (`cargo install taudit --version M.m.p --locked` or a range like `1.0` that resolves to the latest **non-prerelease**).
- **Prerelease:** Semver **pre-release identifiers** — e.g. `1.1.0-beta.3`, `1.1.0-rc.1` (anything after a **single** hyphen that is not only digits). Published to crates.io the same way as stable; the resolver decides who picks them up.

### How Cargo's resolver handles each lane

This is the load-bearing safety mechanism. **Cargo's rule:** a version requirement without a pre-release component never matches a pre-release version. So pushing `v1.1.0-beta.1` does not affect any consumer who hasn't asked for it explicitly.

| Caller | What gets picked from crates.io |
|--------|-----------------|
| `cargo install taudit` (no `--version`) | **Latest stable.** Skips `1.1.0-beta.1`. Stays on `1.0.12`. |
| `taudit = "1.1"` in `Cargo.toml` | **Latest stable matching `1.1.x`.** If only prereleases exist for `1.1`, errors with "no matching package". |
| `taudit = "1"` or `"1.0"` | Latest stable in that range. Prereleases ignored. |
| `taudit = "*"` | Still latest stable — the prerelease-skip rule applies to `*` too. |
| `cargo update` on a stable-pinned project | Never auto-promotes to a prerelease. |
| `cargo install taudit --version "1.1.0-beta.1"` | Picks the prerelease (explicit opt-in). |
| `taudit = "=1.1.0-beta.1"` in `Cargo.toml` | Picks the prerelease (explicit opt-in). |
| `taudit = "1.1.0-*"` | **Footgun.** Asks to track prereleases — gets them. Document; do not try to prevent. |

When ready to promote: cut `vM.m.0` (no suffix). At next `cargo update`, all `taudit = "1"` / `"1.1"` consumers pull it automatically. The betas remain in the registry as historical artifacts (yankable independently).

### Git tags and CI

The release workflow (`.github/workflows/release.yml`) triggers on **both** of:

- `v[0-9]+.[0-9]+.[0-9]+` — stable tags (e.g. `v1.0.14`, `v1.1.0`).
- `v[0-9]+.[0-9]+.[0-9]+-*` — prerelease tags (e.g. `v1.1.0-beta.1`, `v1.1.0-rc.2`).

The same job graph runs for both: quality → create-release → SBOMs → binaries → `cargo publish`. The only conditional is on `gh release create`, which adds `--prerelease` when the tag carries a hyphen.

**Practical split:**

| Lane | Tag example | Manifest version | GitHub Release flag | crates.io |
|------|-------------|-------------------|---------------------|-----------|
| **Stable** | `v1.1.0` | `1.1.0` | (default — Latest) | published, picked by stable resolvers |
| **Prerelease** | `v1.1.0-beta.1` | `1.1.0-beta.1` | `--prerelease` (no Latest badge) | published, picked only by explicit opt-in |

**Nightly / commit builds** that don't deserve a registry version can skip tags entirely: artifact name includes date or short SHA; attach to a **Pre-release** GH release or leave as workflow-run artifacts only. The crates.io lane stays tag-driven.

### GitHub Release flag

The workflow detects prerelease by checking for a hyphen in the tag name and passes `--prerelease` to `gh release create` accordingly. This:

- Removes the **Latest** badge from the release in the GH UI.
- Excludes the release from `gh release view --latest`.
- Leaves asset downloads (binaries, SBOMs, attestations) working normally — they're just not surfaced as "latest".

`cargo install` doesn't read GH releases at all; this is purely a human/UI concern, orthogonal to the registry mechanics above.

### Yank semantics

- A bad **prerelease** can be yanked without affecting stable. `cargo yank --version 1.1.0-beta.1` removes that one version from new-resolution but leaves stable `1.0.x` and any other prereleases untouched.
- A yanked **stable** does not retroactively yank a related prerelease.
- Yanked versions stay downloadable for existing `Cargo.lock` files (so reproducible builds still work) — yank only blocks **new** resolution.

### Pre-flight quality applies to both lanes

A `-beta.N` or `-rc.N` tag triggers the same fmt / clippy / test / `cargo deny` / `cargo audit` gates as a stable tag. A failing prerelease is not "fix it on the next beta" — fix it before the tag. Once a version number is consumed on crates.io, it cannot be reused (only yanked).

The one lane-specific exception is `cargo semver-checks`: it runs for stable tags, but prerelease tags skip it in CI. Cargo's registry baseline lookup compares a prerelease against the latest stable line, which is exactly the API churn prereleases exist to soak. For prereleases, the required artifact is an explicit CHANGELOG detection/migration note; stable promotion re-enables the semver gate.

---

## 5. Changelog discipline (trust)

Every **crates.io** release note — **stable or prerelease** — should make security engineers **less** nervous, not more. A `-beta.N` suffix is not a license to skip the trust paragraph. At minimum, answer explicitly:

1. **What changed in detection?** (rules, graph construction, trust zones, fingerprints if relevant.)
2. **Will this flag more or fewer issues** than the previous release on typical pipelines?
3. **Any false positive / false negative shifts?** (“We previously missed X; we now report Y” / “Z is no longer raised in case W.”)

If the changelog is silent on detection, **consumers assume the worst** and delay upgrades — which hurts adoption more than honest “we may surface +N findings on repos that …” text.

---

## 6. Cadence in plain language

| Situation | Verdict |
|-----------|---------|
| “One release per week” as a **ceiling** | **Yes** — for **crates.io** stable lane. |
| “Exactly one every week” | **No** — **zero** in a week is healthy. |
| “Ship when you have a defensible unit of change” | **Yes** — primary driver, subject to the ceiling. |
| “Many tags per day on the default registry” | **No** — that pattern reads as instability and breaks pinning culture. |

---

## 7. Trade-offs (explicit)

**High velocity on crates.io (old pattern)**

- Pros: fast iteration, fast maintainer feedback.
- Cons: erodes **external trust**, makes **version pinning unsafe**, discourages **enterprise** adoption.

**Stable lane + edge lane (this model)**

- Pros: signals **maturity**, supports **CI adoption**, matches **DevSecOps** expectations for analysis tools.
- Cons: maintainers feel **friction** (batching, changelog honesty, semver discipline).

---

## Maintainer checklist (before `cargo publish`)

- [ ] Detection / schema / CLI impact assessed and **semver** chosen to match.
- [ ] `CHANGELOG.md` updated with **detection delta** and FP/FN notes where applicable.
- [ ] Docs and examples that pin `cargo install taudit --version …` updated if needed.
- [ ] Git tag `vM.m.p` pushed only when `main` is green and the **bundle** of changes is what stable consumers should pick up together.

For artifact verification after the tag exists, see [`release-trust.md`](release-trust.md).
