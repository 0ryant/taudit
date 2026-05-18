# Release gates — pre-committed promotion criteria

> *"An unwritten gate is vibes wearing a lab coat."* — established at the May 2026 RC council.

This document is the **promotion contract** for taudit releases. It exists because a previous beta cycle surfaced 146 audit findings in code that was tagged `v1.0.x` stable — which means the previous review gate was implicit, and implicit gates rot. Every gate below is **pre-committed in writing** so a soak window can't be retroactively redefined when a procurement clock starts ticking.

Companion docs: [`release-strategy.md`](release-strategy.md) (lane policy: stable / prerelease, semver discipline) · [ADR 0004](adr/0004-prereleases-publish-to-crates-io.md) (prereleases publish to crates.io with resolver gating) · [`v1.2.0-rc.1 release readiness checklist`](rc/v1.2.0/release-readiness-checklist.md) (QA-08 receipts and checks).

---

## 1. Lane definitions

| Lane | Tag shape | Audience | Stability claim |
|------|-----------|----------|-----------------|
| `vM.m.p-beta.N` | `1.2.0-beta.3` | maintainers, internal CI canaries | "expect churn; do not pin" |
| `vM.m.p-rc.N` | `1.2.0-rc.1` | named pilots, F500 procurement-exception path | "stable in intent; soak in progress" |
| `vM.m.p` | `1.2.0` | crates.io stable resolvers, public docs, marketplace | "promotion gate cleared; pin freely" |

**Why the RC distinction matters:** F500 vendor-management tooling literally has a checkbox that filters out non-GA software for SDLC-control-plane tooling. The string `beta` routes a tool to legal-review-purgatory; the string `rc` with a documented soak SLA routes through pilot-exception paths. Same code, same risk profile, different door opens.

---

## 2. Promotion gates

### 2.1 RC tag and prerelease publish gates

These gates permit an RC tag such as `v1.2.0-rc.1` to be created and published as a prerelease. They do **not** permit the stable `vM.m.p` tag. Stable promotion remains a separate gate in §2.2.

For the current `v1.2.0-rc.1` cycle, QA-08 is tracked in [`release-readiness-checklist.md`](rc/v1.2.0/release-readiness-checklist.md). That checklist is the join surface for the release harness, publish metadata checker, output conformance harness, changelog review, and proof receipts.

**Pre-tag hard gates** (all required, no exceptions):

- [ ] No open P0 finding against the public contract surface (schemas, JSON sink output, SARIF output, CloudEvents output, exit-code semantics).
- [ ] No unresolved P1 that is marked as an RC blocker in the active ADRs, [`code-complete-lanes.md`](rc/v1.2.0/code-complete-lanes.md), or the CHANGELOG entry for the tag.
- [ ] `cargo test --workspace` passes.
- [ ] `cargo fmt --all -- --check` clean.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] `python3 scripts/generate-authority-invariant-schema.py --check` clean (Rust↔schema enum drift).
- [ ] Prerelease API and wire-contract churn is controlled by explicit CHANGELOG migration notes and the eventual stable-promotion semver gate. Prerelease tags (`*-beta.*`, `*-rc.*`) do not run `cargo semver-checks check-release` because Cargo's registry baseline selection compares them against the latest stable line.
- [ ] `python3 scripts/release_harness.py check --tag v1.2.0-rc.1` passes after the CLI manifest and changelog are aligned.
- [ ] `python3 scripts/check-crates-publish-metadata.py --expected-release-version 1.2.0-rc.1` passes after the crate-version map is final.
- [ ] `python3 scripts/conformance_harness.py --root . --format json` reports full conformance for the current output contract. An `incomplete` result is an RC blocker even when it is deliberate scaffolding.
- [ ] CHANGELOG entry under `## v1.2.0-rc.1` starts with **Detection delta (read first)**, names finding-count direction, FP/FN movement, schema/output/CLI/fingerprint/suppression impact, migration notes, and the crate-version map (see [`release-strategy.md` §5](release-strategy.md#5-changelog-discipline-trust)).
- [ ] The release workflow will publish the RC as a GitHub prerelease and will not mark it Latest.
- [ ] The proof ledger exists with planned receipt rows for the tag workflow output: release assets, checksums, SPDX/CycloneDX SBOMs, GitHub Artifact Attestations, crates.io, docs.rs, and docs link checks.

**Post-tag closeout gates** (required before calling the RC release complete):

- [ ] GitHub release readback proves `v1.2.0-rc.1` is a prerelease and not Latest.
- [ ] Release asset/checksum, SBOM, and attestation receipts are recorded under [`docs/proof/v1.2.0-rc.1/`](proof/v1.2.0-rc.1/README.md).
- [ ] crates.io and docs.rs receipts are recorded or explicitly rejected with the failed evidence and replacement plan.
- [ ] The QA-08 checklist links each completed receipt and records residual risk.

### 2.2 `rc.N → vM.m.p` stable

> **Operating-model note.** taudit ships as a small-team / solo-maintainer OSS project. There is no enterprise sales motion, no GTM team, no roster of named pilots that maintainers can summon for a 14-day soak by sending an email. An earlier draft of this section asked for "≥2 concurrent pilots × recorded reference call" — that gate assumed a sales motion that doesn't exist for this project, and a gate the maintainer cannot clear becomes "wait forever," which is the same failure mode as no gate at all. This revision replaces that requirement with stability signals a maintainer can produce alone.

**Hard gates** (all required):

- [ ] **One-week calendar soak** since the latest `rc.N` tag, with no new commits to the release candidate payload that touch parser logic, the JSON/SARIF/CloudEvents wire types, or `compute_fingerprint`. (Documentation, tests, CI, and release-machinery changes do not reset the clock; semantic changes do.)
- [ ] **Zero new P0/P1 findings** against the public contract surface during the soak. A P1 raised externally (issue tracker, fuzz finding, security disclosure) resets the clock to the day of the fix tag.
- [ ] **RC closeout receipts complete.** The latest RC has the post-tag proof receipts from §2.1, including release assets, checksums, SBOMs, attestations, crates.io, docs.rs, and docs link checks.
- [ ] **Public-corpus dogfood pass.** taudit successfully scans a curated corpus of ≥100 real-world pipeline files sourced from public GitHub / GitLab / ADO repos (covering all three platforms, varied sizes, including known-pathological shapes) without crashing, hanging, or producing schema-invalid output. Maintain the corpus list in `docs/dogfood-corpus.md` with sources and rationale; refresh quarterly.
- [ ] **Fuzz clean during soak.** `scheduled-fuzz.yml` runs (Tuesday cron) over the soak window report no new crashers, no new schema-invalid outputs, no new panics on hostile YAML.
- [ ] **Maintainer self-attestation.** The maintainer runs taudit on the workspace's own CI YAML (`.github/workflows/`, `azure-pipelines.yml`, `.gitlab-ci.yml`, `bitbucket-pipelines.yml`) plus at least two sibling-project CI estates (e.g. tsign, axiom, CellOS once they exist) and writes the findings up as a public dogfood report committed to `docs/dogfood/v{tag}.md`. This is the "we use it on real code" signal that doesn't require a CISO call.
- [ ] **CI outage fallback recorded.** If GitHub Actions is unavailable for the release window, run the equivalent release drills locally and/or in Azure DevOps, record which GitHub-only artifacts are delayed (GitHub Release assets, SBOM attestations, provenance attestations), and do not claim full GitHub release-artifact parity until those artifacts exist.
- [ ] All RC-cycle blockers (§2.1) confirmed resolved at the stable promotion commit.
- [ ] `cargo semver-checks check-release --workspace --all-features` passes for the stable tag.
- [ ] CHANGELOG `## Unreleased` empty stub re-scaffolded for the next cycle.

**Abort criteria (auto-rollback to `rc.N+1`):**

- Any P0 raised against the public contract during soak → automatic abort, fix in `rc.N+1`, restart the one-week clock.
- Any P1 raised against the public contract after the first 72 hours of soak → automatic abort, fix in `rc.N+1`, restart the one-week clock. (Early P1s are typically superficial / fast to fix; later P1s suggest latent shape issues that need a fresh soak.)
- Fuzz finds a new crasher mid-soak → automatic abort if the crasher reproduces on the RC binary; fix in `rc.N+1`.
- Public-corpus regression: a fixture that scanned cleanly on the previous stable now produces schema-invalid output or crashes → automatic abort.

The bar for restarting the soak clock is **deliberately strict.** It is cheaper to ship `rc.5` than to ship a stable tag that gets yanked. But "deliberately strict" is not "impossible" — every gate above is a maintainer-side artifact, not a customer-side dependency.

**What this section deliberately does NOT require.** Pilots, reference calls, signed customer logos, ARR commitments, analyst briefings, recorded testimonials. These are GTM artifacts; they may eventually be useful but they are not stability signals and they cannot gate stable releases of a small-team OSS project. If a pilot relationship organically develops and produces a P0 finding, that finding still gates the release — the relationship is the input, not the gate itself.

### 2.3 Major version bumps (`1.x → 2.0`)

Reserved for **detection-model breaks** — the meaning of an `AuthorityGraph` changes, the trust-zone taxonomy shifts, the fingerprint algorithm bumps, or the schema dialect upgrades. See [`release-strategy.md` §3](release-strategy.md#3-version-semantics).

---

## 3. Calendar-anchored milestones

Version-as-promise rots ("we'll ship signed manifests in 1.2" → 1.3 → 1.5 → never). Calendar quarters anchor.

| Milestone | Calendar target | Lane |
|-----------|-----------------|------|
| `v1.2.0-rc.1` cut | **target: after QA-08 RC tag gates pass** | rc |
| `v1.2.0` stable cut | **target: after the latest v1.2 RC clears §2.2** | stable |
| Signed-manifest support (tsign integration GA) | **target Q1 2027** — slips a quarter at a time, never silently | stable |
| `axiom` enforcement integration GA | **target Q3 2027** — slips a quarter at a time, never silently | stable |
| `v2.0.0` (model break) | **no earlier than 2028** unless detection model fundamentally shifts | major |

**Calendar dates supersede version numbers** in commitment language. If the team is going to slip a stable cut, it slips a quarter on this doc — not a patch number on a roadmap.

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
