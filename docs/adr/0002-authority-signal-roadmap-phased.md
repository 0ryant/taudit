# ADR 0002: Authority signal roadmap (phased deliverables, goals, non-goals)

- **Status:** Accepted
- **Status history:** Proposed 2026-04-27 → Accepted 2026-05-02 (all phases shipped in-tree).
- **Date:** 2026-04-27
- **Context:** External product feedback (authority vs YAML, privilege/trust visualization, scale), [Council synthesis on graph tooling](../research/2026-04-27-council-graph-as-product.md), follow-up council read on **risk derivation vs rendering** (2026-04-27), [ADR 0001](0001-graph-native-exports-and-leverage.md) (JSON canonical; Mermaid/DOT as projections)

## Context

taudit already models **execution-relevant authority** (nodes, edges, trust zones, propagation, 61+ built-in rules, `verify` + schema’d JSON). Gaps are mainly **legibility and derived signal**: diagrams under-express what rules already use (e.g. scope/classification), org-scale graphs become hairballs, and **aggregated** path/risk readouts are not yet first-class outputs.

The product question: *How do we deepen “authority reasoning” without fragmenting the contract, bloating the binary, or turning the static scanner into a runtime cloud product?*

## Decision

We adopt a **four-phase roadmap** with explicit **goals**, **deliverables**, and **non-goals** per phase. Phases are **sequential dependencies**: later phases consume earlier contracts and projections.

### Phase 1 — Rich human projections (no schema break)

**Goal:** Diagrams optionally show **the same signal rules already see** (scope, trust zone, key metadata), without changing default verbosity.

**Deliverables:** Opt-in CLI flag on `taudit graph` and `taudit map --format dot|mermaid` (e.g. `--rich-labels`); docs clarifying **JSON = full machine contract**, Mermaid/DOT = **teaching / PR views**; snapshot tests default vs rich.

**Shipped (in-tree):** **`--rich-labels`** on **`taudit graph`** and **`taudit map`** for **`--format dot`** and **`--format mermaid`**; **`taudit map --format mermaid`** uses the same renderer as **`taudit graph --format mermaid`**; default diagram labels unchanged; [docs/research/PHASE1-lanes.md](../research/PHASE1-lanes.md) and CLI / snapshot tests.

**Non-goals:** No mandatory JSON/schema change; no API calls or scoring engine; default diagrams stay compact.

### Phase 2 — Additive machine contract (graph schema 1.x)

**Goal:** Optional **edge-attached** (and narrowly scoped) summaries so consumers need not reverse-engineer raw `META_*` strings for common authority questions.

**Deliverables:** Additive `authority-graph` schema fields (e.g. optional edge metadata / summaries on hot edges such as `HasAccessTo` → identity), parser stamping from existing metadata, changelog + consumer note; rich labels may read the same summaries.

**Shipped (in-tree):** optional per-edge **`authority_summary`** on **`has_access_to` → `identity`** in graph JSON and scan JSON (`trust_zone`, `identity_scope`, `permissions_summary`), stamped post-parse via [`AuthorityGraph::stamp_edge_authority_summaries`](../../crates/taudit-core/src/graph.rs); schemas and snapshots updated.

**Non-goals:** No breaking rename of core `Node`/`Edge` shapes; no unbounded “bag of strings” on every edge without a documented allowlist; still no live IAM/RBAC enrichment in the main pipeline.

### Phase 3 — Deterministic projections (“risk” readouts)

**Goal:** **Read-only** aggregates over the existing graph + propagation (fan-in, boundary crossings, top-N paths) for triage and CI-adjacent workflows.

**Deliverables:** One bounded product surface (e.g. `taudit risk` or `taudit graph --summary json`), deterministic JSON, fixtures; optional exit-code policy only if explicitly designed and documented.

**Shipped (in-tree):** **`taudit graph --format summary`** — bounded propagation rollup JSON (`schemas/authority-propagation-summary.v1.json`), same **`propagation_analysis_checked`** gate as scan; corpus + fixture schema tests.

**Non-goals:** No “blast radius” requiring cloud APIs, live secret inventory, or runner telemetry **inside** the default static scan; no conflation with **`verify`** as the sole policy engine—summaries **inform** policy.

### Phase 4 — Scale and composite policy

**Goal:** Org-scale **views** (collapse, risk-only subgraph) and **path-aware** custom invariants where static YAML supports them.

**Deliverables:** e.g. `--collapse-by job|trust_zone`, `--risk-only` subgraph; `verify` / invariant examples for composite chains where modeled; corpus profiling and dense-graph threshold tuning; parallelism for hot paths **only** after profiling proves need.

**Non-goals:** No bundled Graphviz or full in-house layout engine; no merging **static scan** with **credentialled enrichment** in one command—enrichment remains a **separate** surface and auth story if introduced later.

### Global non-goals (all phases)

- **Not** positioning the ceiling as “diagrams + vague warnings” only — the north star remains **typed authority + contract + verify**.
- **Not** sacrificing **determinism** or **offline-by-default** for core `scan` / `graph` / `verify` on pipeline YAML.
- **Not** runtime **CI policy enforcement** or Rego/OPA-style execution **inside** taudit as a substitute for platform gates—taudit **emits** findings and graph exports; gates **consume** them.

## Consequences

### Positive

- Clear **ordering**: human clarity first, then machine contract, then aggregates, then scale/policy depth.
- **Aligns** external feedback with what the codebase already does (rules, metadata, propagation) vs what is **net-new** (labels, schema fields, projections).
- **Defensible** boundary: static analysis vs optional enrichment stays explicit.

### Negative / costs

- **Schema discipline** in Phase 2 requires migration notes and schema test updates.
- **Rich labels** need escaping/length limits across DOT and Mermaid.
- **Path-shaped rules** (Phase 4) increase rule-engine and test surface area.

## Compliance

- Each phase ships with **tests** (core fixtures + CLI snapshots where applicable) and **docs** (`USERGUIDE.md`, `authority-graph.md`, CLI `--help` as appropriate).
- Competitive or market claims used in outward copy remain **evidence-backed** (see validation rows in product research); this ADR does not assert market uniqueness by itself.

## References

- [ADR 0001 — Graph-native exports and leverage](0001-graph-native-exports-and-leverage.md)
- [Authority graph integration](../authority-graph.md)
- [Positioning](../positioning.md)
