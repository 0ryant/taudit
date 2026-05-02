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

**Hard gates** (all required):

- [ ] **≥2 concurrent pilots completed a 14-day soak window.** "Pilot" = a real organisation running taudit on production CI estate with a designated point of contact and recorded findings volume. n=1 is anecdote, not evidence — Johannes was right, and the cost of getting this wrong is higher than the cost of waiting for the second pilot.
- [ ] **Zero new P0/P1 findings** raised by either pilot during the soak window. A finding raised in week 1 and fixed by week 2 does not reset the clock; a P1 raised in week 13 does.
- [ ] **At least one recorded reference call** with a buyer-side stakeholder (CISO, AppSec lead, Director of Platform) attesting to specific value delivered. The recording is the artifact that converts the next 9 pilots; without it, "we have pilots" is unverifiable.
- [ ] All RC-cycle blockers (§2.1) confirmed resolved against pilot estates, not just internal fixtures.
- [ ] CHANGELOG `## Unreleased` empty stub re-scaffolded for the next cycle.

**Abort criteria (auto-rollback to `rc.N+1`):**

- Any P0 raised by a pilot during the soak window → automatic abort, fix in `rc.N+1`, restart 14-day clock.
- Any P1 raised in the **second week** of soak (suggests latent issue surfacing under real load, not week-1 superficial discovery) → automatic abort, fix in `rc.N+1`, restart 14-day clock.
- Pilot pulls out citing tool quality (not procurement / scheduling / personnel) → automatic abort, retrospective in `docs/audit-tracker.md`, do not re-tag until the named cause is resolved.

The bar for restarting the soak clock is **deliberately strict.** It is cheaper to ship `rc.5` than to ship a `1.1.0` that gets yanked.

### 2.3 Major version bumps (`1.x → 2.0`)

Reserved for **detection-model breaks** — the meaning of an `AuthorityGraph` changes, the trust-zone taxonomy shifts, the fingerprint algorithm bumps, or the schema dialect upgrades. See [`release-strategy.md` §3](release-strategy.md#3-version-semantics).

---

## 3. Calendar-anchored milestones

Version-as-promise rots ("we'll ship signed manifests in 1.2" → 1.3 → 1.5 → never). Calendar quarters anchor.

| Milestone | Calendar target | Lane |
|-----------|-----------------|------|
| `v1.1.0-rc.1` cut | **Q3 2026** (target 2026-07-15) | rc |
| First pilot reference recorded | **Q3 2026** (gate to rc.1, not result of rc.1) | n/a |
| `v1.1.0` stable cut | **earliest Q4 2026** (gated on §2.2; do not promise sooner) | stable |
| Signed-manifest support (tsign integration GA) | **Q1 2027** | stable |
| `axiom` enforcement integration GA | **Q3 2027** | stable |
| `v2.0.0` (model break) | **no earlier than 2028** unless detection model fundamentally shifts | major |

**Calendar dates supersede version numbers** in commitment language. If the team is going to slip the v1.1.0 stable cut, it slips a quarter on this doc — not a patch number on a roadmap.

---

## 4. The three roles a gate must clear

Every promotion-gate decision answers three questions, each owned by a distinct lens:

| Lens | Owner role | Question | Failure mode if skipped |
|------|------------|----------|-------------------------|
| **Engineering** | maintainer + `cargo` toolchain | "does the contract surface hold?" | semver lies, breakage between minors |
| **Customer** | designated pilot + reference recording | "does the tool deliver in a real estate?" | shipping a beautiful tool nobody needs |
| **Adversary** | security review (Pentester pass + invariants-author insider model) | "is the output channel a trust artifact, not an injection vector?" | tsign signs attacker-controlled bytes |

A gate that clears two of three is **not** cleared. Skipping the customer lens produces 146-finding audits on "stable" code. Skipping the adversary lens turns trust artifacts into attack surface. Skipping engineering produces semver theatre.

---

## 5. What this document is NOT

- **Not a velocity contract.** Slipping a calendar quarter is preferable to clearing a gate by retroactively narrowing it.
- **Not signed-by-committee.** The maintainer of record makes the call; this doc exists so the call has pre-committed criteria, not so it requires a vote.
- **Not a substitute for `release-strategy.md`.** That doc covers what a release tag *means* to crates.io and consumers. This doc covers *when* a tag is permitted to ship.

---

## 6. Amendment process

Amendments to §2 (hard gates) require a CHANGELOG-visible entry and a brief rationale in `docs/audit-tracker.md`. Amendments to §3 (calendar dates) ship in the `## Unreleased` section of CHANGELOG when the slip is identified, not when the cut would have happened. Amendments to §4 (lens roles) require an ADR.

Pre-commit, then ship. Don't ship, then justify.
