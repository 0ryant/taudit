# ADR 0001: Graph-native exports and leverage (Mermaid + strategy)

- **Status:** Accepted
- **Date:** 2026-04-27
- **Context:** [Product research](../research/2026-04-27-graph-as-product-research.md), [Council synthesis](../research/2026-04-27-council-graph-as-product.md)

## Context

taudit’s contract is the **deterministic `AuthorityGraph`** (see [positioning.md](../positioning.md)). Today, human-visible graph views require either **JSON** (machine-oriented) or **Graphviz DOT** (visual, but requires an external `dot` binary for SVG/PNG). Operators and doc authors need a **native, dependency-free** diagram format that renders in **GitHub-flavoured Markdown** and common wikis **without** installing Graphviz.

The product question: *If the graph is the product, how do we maximise leverage without fragmenting the contract?*

## Decision

1. **Add `mermaid` as a first-class `taudit graph --format` option** alongside `json` and `dot`, implemented as a **pure renderer** `render_mermaid(&AuthorityGraph, Option<&str>)` in `taudit-core` (same `--job` filtering semantics as `render_dot`).

2. **JSON remains the only canonical, attested interchange** for downstream tools (tsign, axiom, custom automation). Mermaid (and DOT) are **human projections** — not additional sources of truth.

3. **Completeness:** When `AuthorityGraph::completeness != Complete`, JSON already carries gaps; Mermaid output may append a **comment line** (`%% …`) noting partiality so pasted diagrams do not imply over-confidence.

4. **Stdout behaviour:** Graph output to stdout must treat **broken pipe** (`EPIPE`) as a clean exit (0) for all graph formats, consistent with v1.0.5 `graph` behaviour. **As of v1.0.7**, the same semantics apply to other stdout-heavy commands (`scan`, `map`, `verify`, `diff`, etc.) — see `crates/taudit-cli/src/stdio_epipe.rs`.

5. **Defer** embedded SVG/PNG rendering inside the taudit binary; **defer** SARIF line/column enrichment to a **separate ADR** (touching Code Scanning consumers).

## Consequences

### Positive

- **Lower friction** for READMEs, ADRs, runbooks, and PRs: paste Mermaid into Markdown.
- **Single graph model** — no second graph builder; tests can assert parity with DOT on node/edge counts for shared fixtures.
- **Clear story:** JSON = contract; Mermaid/DOT = views.

### Negative / costs

- **Mermaid escaping** and **GitHub renderer** quirks require ongoing test coverage and possible hotfixes.
- **Layout** is Mermaid’s, not Graphviz’s — visually different from DOT; docs must say both are **the same graph**, different layout engines.

### Follow-up (not part of this ADR’s acceptance)

- EPIPE-safe stdout for `map` / `scan` / etc.: **shipped v1.0.7** (`stdio_epipe` in the CLI crate).
- SARIF `region` objects where spans exist (separate ADR).

## Compliance

- CLI and `taudit-core` tests cover Mermaid output for at least one hand-built graph and one parser-integrated path if feasible.
- [USERGUIDE.md](../USERGUIDE.md) documents `graph --format mermaid` next to `dot` and JSON.

## References

- Mermaid flowchart syntax: <https://mermaid.js.org/syntax/flowchart.html>
- [Implementation backlog](../research/2026-04-27-implementation-backlog.md)
