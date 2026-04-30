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

## 4. Changelog discipline (trust)

Every **crates.io** (stable) release note should make security engineers **less** nervous, not more. At minimum, answer explicitly:

1. **What changed in detection?** (rules, graph construction, trust zones, fingerprints if relevant.)
2. **Will this flag more or fewer issues** than the previous release on typical pipelines?
3. **Any false positive / false negative shifts?** (“We previously missed X; we now report Y” / “Z is no longer raised in case W.”)

If the changelog is silent on detection, **consumers assume the worst** and delay upgrades — which hurts adoption more than honest “we may surface +N findings on repos that …” text.

---

## 5. Cadence in plain language

| Situation | Verdict |
|-----------|---------|
| “One release per week” as a **ceiling** | **Yes** — for **crates.io** stable lane. |
| “Exactly one every week” | **No** — **zero** in a week is healthy. |
| “Ship when you have a defensible unit of change” | **Yes** — primary driver, subject to the ceiling. |
| “Many tags per day on the default registry” | **No** — that pattern reads as instability and breaks pinning culture. |

---

## 6. Trade-offs (explicit)

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
