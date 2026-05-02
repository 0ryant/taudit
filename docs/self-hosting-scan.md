# Self-Hosting Scan Report
**taudit scanning its sister projects**
Date: 2026-04-26
taudit version: 0.9.0 (binary: target/release/taudit)
Branch: main

---

## Section 1: tsafe Scan

**Project path:** `/Users/rytilcock/prj/tsafe`
**Platform:** GitHub Actions (6 workflow files)
**ADO/GitLab:** Not present — `--policy verify` step skipped (GitHub Actions only)

### Files Scanned

| File | Findings | Critical | High | Medium | Low | Completeness |
|------|----------|----------|------|--------|-----|--------------|
| ci.yml | 10 | 0 | 10 | 0 | 0 | Complete |
| cve-sweep.yml | 5 | 0 | 0 | 5 | 0 | Complete |
| fuzz.yml | 4 | 0 | 4 | 0 | 0 | Complete |
| mutants.yml | 7 | 0 | 7 | 0 | 0 | Partial (matrix) |
| release-plz.yml | 25 | 20 | 2 | 3 | 0 | Complete |
| release.yml | 39 | 0 | 34 | 2 | 3 | Complete |
| **TOTAL** | **90** | **20** | **57** | **10** | **3** | |

### Aggregate Breakdown

**By severity:** critical: 20, high: 57, medium: 10, low: 3
**By category:**
- `authority_propagation`: 64 — GITHUB_TOKEN/secrets flowing to third-party actions
- `over_privileged_identity`: 10 — `actions: write` broader than needed
- `untrusted_with_authority`: 10 — unpinned actions with direct secret access
- `unpinned_action`: 3 — tags not SHA (`@v4`, `@v0.5`, `@stable`)
- `long_lived_credential`: 3 — static signing credentials

### Top 5 Highest-Severity Findings

1. **[CRITICAL] release-plz.yml** — `authority_propagation`
   `GITHUB_TOKEN (release-plz-release)` propagated to `actions/checkout@v4` across trust boundary.
   Unpinned action receives a write-scoped token in the release job.

2. **[CRITICAL] release-plz.yml** — `untrusted_with_authority`
   Untrusted step `Run release-plz release` has direct access to secret `CARGO_REGISTRY_TOKEN`.
   This is the crates.io publish key flowing into an unpinned third-party action (`release-plz/action@v0.5`).

3. **[CRITICAL] release-plz.yml** — `untrusted_with_authority`
   Untrusted step `Run release-plz release` has direct access to secret `GITHUB_TOKEN`.
   Combined with CARGO_REGISTRY_TOKEN in same step — two high-value secrets in one unpinned action.

4. **[CRITICAL] release-plz.yml** — `authority_propagation`
   `CARGO_REGISTRY_TOKEN` propagated to `release-plz/action@v0.5` across trust boundary (×2 findings — PR and release jobs both).
   Pin `release-plz/action` to a SHA digest to bound this finding.

5. **[CRITICAL] release-plz.yml** — `unpinned_action`
   `release-plz/action@v0.5`, `actions/checkout@v4`, `dtolnay/rust-toolchain@stable` — three unpinned tags in release-critical workflows.
   Any of these could be compromised via tag mutation.

### Graph Validation (ci.yml representative)

`taudit graph --format json ci.yml` produced valid JSON conforming to `authority-graph.v1.json`:
- `schema_version: 1.0.0`
- `schema_uri`: `https://taudit.dev/schemas/authority-graph.v1.json`
- `completeness: complete`
- 30 nodes, 29 edges
- All top-level keys present: `schema_version`, `schema_uri`, `graph`

Graph schema: **VALID**

### Gate Verdict

**tsafe: NON-ZERO** (90 findings across 6 files)
The "zero findings" ROADMAP gate is **not met**. This is not close to the gate.

---

## Section 2: Runtime-Isolation Harness Scan

**Searched paths:**
- `/Users/rytilcock/prj/runtime-isolation-harness` — NOT FOUND
- `/Users/rytilcock/prj/cellos` — NOT FOUND
- Full `ls /Users/rytilcock/prj/` enumeration: `0ed`, `0ryant-shell`, `engineering-doctrine`, `taudit`, `tedit`, `tencrypt`, `tsafe` — no runtime-isolation project present on this machine.

**Gate Verdict: SKIPPED** — project not cloned locally. Cannot establish current state. Recommend cloning before declaring the self-hosting gate met or unmet.

---

## Section 3: Cross-Project Observations

**Only one project scanned** (runtime-isolation absent), so cross-project pattern comparison is limited. Within tsafe:

1. **Concentration in release-plz.yml.** 25/90 findings (28%) and all 20 criticals live in a single file. The release automation is the highest-risk surface.

2. **CARGO_REGISTRY_TOKEN is the crown jewel risk.** It appears in criticals because it flows to an unpinned third-party action (`release-plz/action@v0.5`). This is the crates.io publish key; a compromised supply chain here = arbitrary crate publication under the tsafe package name.

3. **`authority_propagation` dominates (71%).** This reflects the structural reality that every workflow grants GITHUB_TOKEN implicitly and every action step receives it. This is a near-universal GitHub Actions pattern — taudit is correctly identifying it but the finding density is very high for a project that's already security-conscious (it uses SHA-pinning in the non-release workflows).

4. **SHA-pinning discipline is inconsistent.** `ci.yml`, `fuzz.yml`, `mutants.yml`, and `release.yml` use SHA digests for third-party actions. `release-plz.yml` uses mutable tags (`@v4`, `@v0.5`, `@stable`). This is the direct cause of the critical elevation — the same token+action combination scores HIGH when pinned (ci.yml) and CRITICAL when unpinned (release-plz.yml). The inconsistency is likely because release-plz.yml was set up by the release-plz onboarding docs, which use tag references.

5. **`mutants.yml` partial graph.** The matrix strategy prevents taudit from fully modeling the authority graph. 7 HIGH findings are tagged `[partial]`. The actual finding count could be higher in a fully expanded matrix.

---

## Section 4: Recommendations

### Findings That Block the "Zero Findings" ROADMAP Gate

**All 90 findings block the gate** as stated. However, in priority order:

**Must fix (critical, directly actionable):**
- Pin `release-plz/action` to a SHA digest in `release-plz.yml`. This resolves the 3 `unpinned_action` findings and reduces most criticals to HIGH (same as pinned workflows).
- Pin `actions/checkout@v4` and `dtolnay/rust-toolchain@stable` in `release-plz.yml` to SHA. This is already done in every other workflow — the inconsistency is the anomaly.
- Consider whether CARGO_REGISTRY_TOKEN needs to be in the release-plz workflow at all, or whether it can be scoped differently.

**Should fix (high volume, systematic):**
- The 64 `authority_propagation` findings reflect GITHUB_TOKEN touching every third-party action. Scoping permissions per-job (principle of least privilege) and splitting jobs that need write access from those that don't would reduce this count. Most non-release workflows already have `contents: read` — the `actions: write` permission appears in several (`ci.yml`, `fuzz.yml`, `mutants.yml`) and is worth auditing whether it's needed.

### Acceptable Risks

- **cve-sweep.yml (5 medium findings):** A cron-only CVE scan with no secret write access. The `authority_propagation` mediums here are structural noise — the token has no write scope in this workflow. Acceptable.
- **fuzz.yml (4 high findings):** A fuzzing workflow with artifact upload but no release capability. The `actions: write` permission driving the HIGH classification should be audited but is lower risk than release workflows.
- **long_lived_credential (3 low findings in release.yml):** Apple notarization and Windows code-signing credentials are genuinely required for the multi-platform binary release. These are not replaceable with OIDC (signing certs are not cloud-provider-issued). These findings are informational.

### Suspected False Positives / taudit Bugs

1. **`rule_id` missing from JSON output.** Every finding in the JSON format has `rule_id: null`. The text format correctly names rules (`authority_propagation`, etc.) via the `category` field, but JSON consumers cannot filter by rule. This is a schema inconsistency — either `rule_id` should be populated or the field should be removed. **Open issue candidate.**

2. **`authority_propagation` HIGH on pinned actions in cve-sweep.yml (5 medium).** The `cve-sweep.yml` job has no `contents: write` or `actions: write` and uses `contents: read` implicitly via GITHUB_TOKEN. The token propagates to pinned SHA actions. Whether this constitutes a meaningful risk is debatable — read-only token to a pinned SHA should arguably score LOW, not MEDIUM. The severity calibration for read-only GITHUB_TOKEN propagation to SHA-pinned actions warrants review. **Potential miscalibration.**

3. **The JSON parse errors observed in the initial run** were a shell-interpolation artifact (backslashes in SHA digests corrupted when passed through bash variable substitution). taudit's JSON output is valid when written to file via `>` redirection. Not a taudit bug.

---

## Appendix

taudit v0.9.0 | 6 tsafe workflows | GitHub Actions | runtime-isolation not present | graph schema valid | ADO verify skipped | 2026-04-26
