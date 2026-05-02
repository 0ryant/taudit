# Release gates — pre-committed promotion criteria

> *"An unwritten gate is vibes wearing a lab coat."* — established at the v1.1.0-rc council, 2026-05-02.

This document is the **promotion contract** for taudit releases. It exists because the v1.1.0-beta cycle surfaced 146 audit findings in code that was tagged `v1.0.x` stable — which means the previous review gate was implicit, and implicit gates rot. Every gate below is **pre-committed in writing** so a soak window can't be retroactively redefined when a procurement clock starts ticking.

Companion docs: [`release-strategy.md`](release-strategy.md) (lane policy: stable / prerelease, semver discipline) · [ADR 0004](adr/0004-prereleases-publish-to-crates-io.md) (prereleases publish to crates.io with resolver gating).

---

## 1. Lane definitions

| Lane | Tag shape | Audience | Stability claim |
|------|-----------|----------|-----------------|
| `vM.m.p-beta.N` | `1.1.0-beta.3` | maintainers, internal CI canaries | "expect churn; do not pin" |
| `vM.m.p-rc.N` | `1.1.0-rc.1` | named pilots, F500 procurement-exception path | "stable in intent; soak in progress" |
| `vM.m.p` | `1.1.0` | crates.io stable resolvers, public docs, marketplace | "promotion gate cleared; pin freely" |

**Why the RC distinction matters:** F500 vendor-management tooling literally has a checkbox that filters out non-GA software for SDLC-control-plane tooling. The string `beta` routes a tool to legal-review-purgatory; the string `rc` with a documented soak SLA routes through pilot-exception paths. Same code, same risk profile, different door opens.

---

## 2. Promotion gates

### 2.1 `beta.N → rc.1`

**Hard gates** (all required, no exceptions):

- [ ] No open P0 finding against the public contract surface (schemas, JSON sink output, SARIF output, CloudEvents output, exit-code semantics).
- [ ] All deep-audit P1s closed in the corresponding wave (track in `/tmp/taudit-deep-review/00-synthesis.md` or a permanent `docs/audit-tracker.md`).
- [ ] `cargo test --workspace` passes.
- [ ] `cargo fmt --all -- --check` clean.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] `python3 scripts/generate-authority-invariant-schema.py --check` clean (Rust↔schema enum drift).
- [ ] `cargo semver-checks check-release` clean against the previous published baseline.
- [ ] CHANGELOG entry under `## v{tag}` includes the **Detection delta (read first)** paragraph (see [`release-strategy.md` §5](release-strategy.md#5-changelog-discipline-trust)).

**RC blockers (per-cycle)** — listed in the active CHANGELOG `Unreleased` section. The current cycle's RC blockers for `1.1.0-rc.1` are:

1. **Output-injection sanitisation:** ANSI escape stripping in terminal sink + Markdown escaping in SARIF `result.message.text`. Regression test `output_injection_corpus.rs` lands **in CI**, not just the fix.
2. **ADO `condition:` and `dependsOn:` modelling:** unmodelled today; gates 40% of typical enterprise ADO estates. Either ship the model or document the gap with a named workaround in pilot brief and pin full fix to v1.2.
3. **`taudit-api` wire-types crate extracted, versioned `0.x`:** declares the JSON contract every Action / Template / Task / Backstage plugin will consume; `0.x` admits semver blast-radius until 1.0 stabilisation.

### 2.2 `rc.N → vM.m.p` stable

> **Operating-model note.** taudit ships as a small-team / solo-maintainer OSS project. There is no enterprise sales motion, no GTM team, no roster of named pilots that maintainers can summon for a 14-day soak by sending an email. An earlier draft of this section asked for "≥2 concurrent pilots × recorded reference call" — that gate assumed a sales motion that doesn't exist for this project, and a gate the maintainer cannot clear becomes "wait forever," which is the same failure mode as no gate at all. This revision replaces that requirement with stability signals a maintainer can produce alone.

**Hard gates** (all required):

- [ ] **14-day calendar soak** since the latest `rc.N` tag, with no new commits to `main` that touch parser logic, the JSON/SARIF/CloudEvents wire types, or `compute_fingerprint`. (Documentation, tests, and CI changes do not reset the clock; semantic changes do.)
- [ ] **Zero new P0/P1 findings** against the public contract surface during the soak. A P1 raised externally (issue tracker, fuzz finding, security disclosure) resets the clock to the day of the fix tag.
- [ ] **Public-corpus dogfood pass.** taudit successfully scans a curated corpus of ≥100 real-world pipeline files sourced from public GitHub / GitLab / ADO repos (covering all three platforms, varied sizes, including known-pathological shapes) without crashing, hanging, or producing schema-invalid output. Maintain the corpus list in `docs/dogfood-corpus.md` with sources and rationale; refresh quarterly.
- [ ] **Fuzz clean during soak.** `scheduled-fuzz.yml` runs (Tuesday cron) over the soak window report no new crashers, no new schema-invalid outputs, no new panics on hostile YAML.
- [ ] **Maintainer self-attestation.** The maintainer runs taudit on the workspace's own CI YAML (`.github/workflows/`, `azure-pipelines.yml`, `.gitlab-ci.yml`, `bitbucket-pipelines.yml`) plus at least two sibling-project CI estates (e.g. tsign, axiom, CellOS once they exist) and writes the findings up as a public dogfood report committed to `docs/dogfood/v{tag}.md`. This is the "we use it on real code" signal that doesn't require a CISO call.
- [ ] All RC-cycle blockers (§2.1) confirmed resolved at HEAD.
- [ ] CHANGELOG `## Unreleased` empty stub re-scaffolded for the next cycle.

**Abort criteria (auto-rollback to `rc.N+1`):**

- Any P0 raised against the public contract during soak → automatic abort, fix in `rc.N+1`, restart 14-day clock.
- Any P1 raised against the public contract in the **second week** of soak → automatic abort, fix in `rc.N+1`, restart 14-day clock. (Week-1 P1s are typically superficial / fast to fix; week-2 P1s suggest latent shape issues that need a fresh soak.)
- Fuzz finds a new crasher mid-soak → automatic abort if the crasher reproduces on the RC binary; fix in `rc.N+1`.
- Public-corpus regression: a fixture that scanned cleanly on the previous stable now produces schema-invalid output or crashes → automatic abort.

The bar for restarting the soak clock is **deliberately strict.** It is cheaper to ship `rc.5` than to ship a `1.1.0` that gets yanked. But "deliberately strict" is not "impossible" — every gate above is a maintainer-side artifact, not a customer-side dependency.

**What this section deliberately does NOT require.** Pilots, reference calls, signed customer logos, ARR commitments, analyst briefings, recorded testimonials. These are GTM artifacts; they may eventually be useful but they are not stability signals and they cannot gate stable releases of a small-team OSS project. If a pilot relationship organically develops and produces a P0 finding, that finding still gates the release — the relationship is the input, not the gate itself.

### 2.3 Major version bumps (`1.x → 2.0`)

Reserved for **detection-model breaks** — the meaning of an `AuthorityGraph` changes, the trust-zone taxonomy shifts, the fingerprint algorithm bumps, or the schema dialect upgrades. See [`release-strategy.md` §3](release-strategy.md#3-version-semantics).

---

## 3. Calendar-anchored milestones

Version-as-promise rots ("we'll ship signed manifests in 1.2" → 1.3 → 1.5 → never). Calendar quarters anchor.

| Milestone | Calendar target | Lane |
|-----------|-----------------|------|
| `v1.1.0-rc.1` cut | **shipped 2026-05-02** | rc |
| `v1.1.0` stable cut | **earliest 2026-05-16** (14 days post-rc.1, gated on §2.2; slips per soak-clock resets) | stable |
| Signed-manifest support (tsign integration GA) | **target Q1 2027** — slips a quarter at a time, never silently | stable |
| `axiom` enforcement integration GA | **target Q3 2027** — slips a quarter at a time, never silently | stable |
| `v2.0.0` (model break) | **no earlier than 2028** unless detection model fundamentally shifts | major |

**Calendar dates supersede version numbers** in commitment language. If the team is going to slip the v1.1.0 stable cut, it slips a quarter on this doc — not a patch number on a roadmap.

---

## 4. The three roles a gate must clear

Every promotion-gate decision answers three questions, each owned by a distinct lens:

| Lens | Owner role | Question | Failure mode if skipped |
|------|------------|----------|-------------------------|
| **Engineering** | maintainer + `cargo` toolchain | "does the contract surface hold?" | semver lies, breakage between minors |
| **Real-input** | maintainer-curated public corpus + dogfood report + scheduled fuzz | "does the tool work on YAML the maintainer didn't write?" | shipping a tool that only passes its own fixtures |
| **Adversary** | security review (Pentester pass + invariants-author insider model) | "is the output channel a trust artifact, not an injection vector?" | tsign signs attacker-controlled bytes |

A gate that clears two of three is **not** cleared. Skipping the real-input lens produces 146-finding audits on "stable" code (it happened in v1.0.x; the deep audit caught it). Skipping the adversary lens turns trust artifacts into attack surface. Skipping engineering produces semver theatre.

The previous version of this section named "Customer" as the second lens with "designated pilot + reference recording" as the artifact. That rename was wrong for a small-team OSS project — it imported a sales-motion artifact into a stability-signal role. The renamed lens is **Real-input**, and the artifact is the public-corpus + dogfood report from §2.2. If a real customer relationship organically produces stability signal, that's a bonus input to the same lens; it is not the gate itself.

---

## 5. What this document is NOT

- **Not a velocity contract.** Slipping a calendar quarter is preferable to clearing a gate by retroactively narrowing it.
- **Not signed-by-committee.** The maintainer of record makes the call; this doc exists so the call has pre-committed criteria, not so it requires a vote.
- **Not a substitute for `release-strategy.md`.** That doc covers what a release tag *means* to crates.io and consumers. This doc covers *when* a tag is permitted to ship.

---

## 6. Amendment process

Amendments to §2 (hard gates) require a CHANGELOG-visible entry and a brief rationale in `docs/audit-tracker.md`. Amendments to §3 (calendar dates) ship in the `## Unreleased` section of CHANGELOG when the slip is identified, not when the cut would have happened. Amendments to §4 (lens roles) require an ADR.

Pre-commit, then ship. Don't ship, then justify.
