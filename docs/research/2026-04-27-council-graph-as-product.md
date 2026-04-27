# Council: If the graph is the product, how do we leverage it? (2026-04-27)

**Question:** With positioning committed to *authority graph as the primary artifact*, what leverage points matter most, and what do we ship first?

**Method:** Five structured perspectives, then a single consensus list. (Async “council” — not a live meeting.)

---

## 1. Product (adoption and narrative)

- **Leverage:** The graph must be **legible without reading Rust or JSON**. DOT is faithful but **friction** (Graphviz install). A **Mermaid** path lets every README and internal doc embed the same view GitHub already renders.
- **Risk:** Competing on “more findings” blurs the story; the story is **explicit authority** and **honest partiality**.
- **Ask:** First-class **visual export without extra binaries**; keep JSON as the **contract** for machines.

## 2. Engineering (maintainability)

- **Leverage:** One **graph construction** path; all renderers (**DOT, Mermaid, future**) are **pure functions** over `&AuthorityGraph` with identical `--job` filtering. No duplicate graph logic in the CLI.
- **Risk:** Mermaid’s syntax and escaping are brittle — needs **unit tests** and **golden or substring** fixtures like DOT.
- **Ask:** `render_mermaid` beside `render_dot` in `taudit-core`; single filter helper (already `reachable_set` + shared iteration).

## 3. Security (threat of misrepresentation)

- **Leverage:** The graph is **defensible** in audits *when* `completeness: complete` or when `completeness_gaps` are **surfaced** alongside any export.
- **Risk:** A **pretty diagram** that looks “complete” when the graph is **Partial** misleads reviewers. Exports should **not** hide partiality (optional footer line in Mermaid: “Graph completeness: partial — see JSON”).
- **Ask:** Mermaid (and docs) state that **raster/SVG is illustrative**; policy decisions use **JSON + verify**.

## 4. Developer experience (CLI + CI)

- **Leverage:** Piping to `dot` and **not crashing on EPIPE** (fixed for `graph` in 1.0.5) is table stakes; extend the same pattern to **map** and large **scan** paths where applicable.
- **Risk:** **Too many** formats → support burden. Cap at **json | dot | mermaid** for graph in the short term; defer PNG/SVG render **inside** taudit.
- **Ask:** `taudit graph --format mermaid` symmetric with `dot`; document **brew install graphviz** only for high-fidelity DOT.

## 5. Ecosystem (downstream: tsign, axiom, CI platforms)

- **Leverage:** **JSON** remains the **only** format required for attestation and cross-system merge gates. Mermaid and DOT are **human projections**.
- **Risk:** If Mermaid’s layout differs mentally from the JSON edge list, support explains **both** are the same data — add one integration test: **same node/edge count** and labels as DOT for a fixture graph.
- **Ask:** No change to JSON schema for Mermaid; optional later: **Mermaid in examples/consumers** as a small Node script (out of core).

---

## Consensus decisions

| # | Decision |
|---|----------|
| C1 | **Add native Mermaid** output for the authority graph (parity with `render_dot` + `--job` semantics). |
| C2 | **Keep JSON** the canonical, versioned contract; Mermaid is **not** a second source of truth. |
| C3 | **Document** on each export: when to use JSON vs DOT vs Mermaid; **Partial** graphs must stay visible in JSON; Mermaid may include a one-line completeness note. |
| C4 | **Extend EPIPE-safe stdout** to `map` (and scan where high-volume) in a follow-up patch set. |
| C5 | **SARIF line/region** improvement is a **separate** ADR/phase (consumer contract). |

---

## Dissent / revisit triggers

- If **Mermaid 11+** or GitHub’s renderer **breaks** our escaped labels at scale, revisit escaping strategy or require **opt-in** `--format mermaid-strict-id`.
- If **tsign** requires a **canonical visual hash**, Mermaid is explicitly **out of scope** for signing — JSON only.

## Next

- ADR: [0001: Graph native exports and leverage](../adr/0001-graph-native-exports-and-leverage.md)
- Backlog: [implementation backlog](./2026-04-27-implementation-backlog.md)
