# ADR 0003: Strategic spine, merge gate, and adoption (phased tasks)

- **Status:** Accepted
- **Date:** 2026-04-28
- **Context:** Council synthesis on product direction (graph-as-contract, verify/SARIF as primary interface, orthogonality to workflow linters, honest partial graphs, narrow core + thin ecosystem adapters). Complements [ADR 0001](0001-graph-native-exports-and-leverage.md) (exports/leverage) and [ADR 0002](0002-authority-signal-roadmap-phased.md) (authority signal / diagrams / summaries / scale).

## Context

taudit’s differentiation is **typed authority propagation** over a **deterministic, schema’d graph**, with **verify** and SARIF as merge-path consumers. Adoption risk clusters on: (1) **partial or unknown completeness** being read as full coverage, (2) **unclear composition** with syntax/workflow linters, (3) **operational discipline** (version pins, policy dirs, waivers). This ADR records **phased work** so engineering, docs, and CI guidance advance together without scope creep into CVE scanning or full Actions semantics duplication.

## Decision

We execute strategy in **four phases**, each with **goals**, **concrete tasks**, and **non-goals**. Order is intentional: contract and gate truth before broad UX polish; ecosystem remains **adapter-thin**.

---

### Phase 1 — Spine: graph contract + merge gate (docs & CI truth)

**Goal:** Every adopter can run the load-bearing path and produce **evidence artifacts** reproducibly.

| ID | Task | Done when |
|----|------|-----------|
| 1.1 | **Golden path docs** — single page or section chaining: parse → `taudit graph` (JSON) → `taudit scan` / `taudit verify` (SARIF/policy). | Linked from README + USERGUIDE; includes version-pin guidance. |
| 1.2 | **CLI I/O honesty** — document that `taudit graph` emits **only to stdout** (no `-o` / `--output` on `graph`; use shell redirection for files). Contrast with `taudit scan` and `taudit verify`, which support `-o` / `--output`. | Doc + optional `--help` long text cross-link; no false “same flags everywhere” story. |
| 1.3 | **CI recipes** — copy-paste: install pinned `taudit`; `verify --policy <dir>`; SARIF upload; exit codes **0 / 1 / 2** called out. | Example workflow(s) in docs or `.github/` sample snippet. |
| 1.4 | **Schema as contract** — changelog discipline for `schemas/authority-graph.v1.json` and report JSON; consumer note on semver. | ADR 0001/authority-graph.md aligned; breaking vs additive explicit. |

**Non-goals:** New scan categories; runtime enrichment; replacing actionlint.

---

### Phase 2 — Partiality and policy stance at the gate

**Goal:** **Completeness** and **completeness_gaps** cannot be mistaken for “everything was modeled.”

| ID | Task | Done when |
|----|------|-----------|
| 2.1 | **Policy cookbook** — examples for org choices when graph is `partial` or `unknown` (e.g. fail closed, warn-only, allow-list of files). | Doc + sample policy snippets under `docs/` or examples repo path. |
| 2.2 | **Gate-adjacent surfacing** — audit current verify/terminal/JSON paths; ensure completeness is **visible** where operators make pass/fail decisions (not only deep in graph JSON). | Gap list closed or tracked; minimal viable “thin merge summary” if council gap remains. |
| 2.3 | **One vocabulary** — align terms for pass / fail / violations / config error / partial across terminal, verify summary, and docs. | Style pass on USERGUIDE + verify.md + README tables. |

**Non-goals:** Pretty dashboards before the data path is honest; hiding partiality behind severity-only UX.

---

### Phase 3 — Composition and ecosystem (thin adapters)

**Goal:** **Clear lanes**: taudit = authority graph + invariants; workflow linters = YAML/platform correctness; vuln scanners = dependencies/CVEs.

| ID | Task | Done when |
|----|------|-----------|
| 3.1 | **Positioning** — explicit “run with actionlint (or equivalent)” narrative; no claim to subsume full GHA/GitLab/ADO semantics. | positioning.md + README updated. |
| 3.2 | **Integrations index** — tsign (graph digest / attestation), tsafe (scoped execution), CellOS / isolation (per DOCTRINE) with **inputs/outputs** only. | docs/integrations/ cross-links tested. |
| 3.3 | **Optional future hook** — if we ever consume external linter output, document as **optional context**, not merged product surface, until ADR supersedes this. | Either shipped behind flag + ADR or explicitly “not started” in doc backlog. |

**Non-goals:** Bundling Rego/OPA execution inside taudit as the primary policy engine (verify remains the shipped gate).

---

### Phase 4 — Selective model depth (parser) + cross-ADR scale work

**Goal:** Reduce **high-risk** partial graphs where static resolution is feasible; **do not** chase full platform parity inside core.

| ID | Task | Done when |
|----|------|-----------|
| 4.1 | **Triage-driven backlog** — prioritize composite actions, reusable workflows, or includes **only** where corpus/metrics show authority blind spots. | Written backlog with acceptance tests per item. |
| 4.2 | **ADR 0002 alignment** — diagram collapse, `--format summary`, risk-only subgraph, and dense-graph tuning remain under [ADR 0002](0002-authority-signal-roadmap-phased.md). This phase **does not duplicate** those deliverables; link from here. | 0002 status kept current. |
| 4.3 | **Guardrails** — caps, `--force-scan-dense`, and waiver/baseline rules stay documented for org-scale pipelines. | USERGUIDE + verify/baselines docs reviewed after parser changes. |

**Non-goals:** Core becomes a full “Actions brain”; cloud credentialled IAM enrichment in default `scan`/`graph`/`verify`.

---

### Global non-goals (all phases)

- Not positioning the ceiling as diagrams-only — north star remains **typed graph + verify + schemas**.
- Not sacrificing **determinism** or **offline-by-default** for core commands on pipeline YAML.
- Not conflating pipeline authority with **CVE/dependency** scanning.

## Consequences

### Positive

- Phased tasks are **reviewable** and **traceable** to council trade-offs (contract-first vs legibility-first resolved via Phase 2 honesty + vocabulary).
- Clear **separation** from ADR 0002 (signal/render/summary) vs this ADR (strategy, gates, adoption, partiality policy).

### Negative / costs

- Phase 2 may require small product changes (not docs-only); still bounded if scoped to surfacing existing `completeness` fields.
- Phase 4 parser depth is ongoing maintenance; must stay **prioritized**, not open-ended.

## Compliance

- Shippable work carries **tests** (CLI/integration where behavior changes) and **doc** updates per phase.
- CLI contracts: follow [DOCTRINE.md](../DOCTRINE.md) and existing exit-code policies for `verify`.

## References

- [ADR 0001 — Graph-native exports and leverage](0001-graph-native-exports-and-leverage.md)
- [ADR 0002 — Authority signal roadmap (phased)](0002-authority-signal-roadmap-phased.md)
- [Authority graph](../authority-graph.md), [verify](../verify.md), [positioning](../positioning.md)
- [Council — graph as product](../research/2026-04-27-council-graph-as-product.md)

## Appendix: `taudit graph` and output files

**As of v1.0.8** (and current mainline), `taudit graph` has **no** `-o` or `--output` flag. All formats (`json`, `dot`, `mermaid`, `summary`) are written to **stdout**. Persist to a file with shell redirection, for example:

```bash
taudit graph --format json .github/workflows/ci.yml > /tmp/ci-authority-graph.json
```

For comparison, `taudit scan` and `taudit verify` support `-o` / `--output` for machine-readable artifacts.

---

## Implementation status (rolling)

| Phase | Status (2026-04-28) |
|-------|---------------------|
| **1** | Golden paths extended (Path H, stdout note); [`docs/examples/ci-gate-taudit-verify.yml`](../examples/ci-gate-taudit-verify.yml); README + man page + `taudit graph` `--help` text; authority-graph versioning note for `taudit.verify.v1`. |
| **2** | [`docs/policies/cookbook-partial-graphs.md`](../policies/cookbook-partial-graphs.md); **`verify`** text + JSON now include graph modeling / `pipelines` completeness; `verify.md` + USERGUIDE vocabulary aligned (`pass` / `fail` / `could not decide`). |
| **3** | `positioning.md` + README + `docs/integrations/index.md` (actionlint complementary; tsafe / CellOS; future optional linter hook called out as not shipped). |
| **4** | [`docs/research/BACKLOG-parser-depth-adr0003.md`](../research/BACKLOG-parser-depth-adr0003.md); ADR 0002 cross-link unchanged. |
