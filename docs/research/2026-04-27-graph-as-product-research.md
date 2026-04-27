# Product research: the authority graph as the product surface (2026-04-27)

## Executive summary

taudit’s positioning statement — **“the graph is the product”** — is accurate at the data layer: the **typed `AuthorityGraph`**, with deterministic parse → graph, is the re-publishable contract. **Findings, SARIF, terminal output, and PR commentary are downstream views.** This research answers: (1) what the graph enables today, (2) gaps that limit adoption and trust, (3) how other tools expose comparable artifacts, and (4) recommended investment order.

## Current capabilities

| Surface | What ships | Primary consumer |
|--------|------------|------------------|
| `taudit graph --format json` | Versioned graph JSON (schema `authority-graph.v1.json`) | tsign, axiom, programatic diff, custom tooling |
| `taudit graph --format dot` | Graphviz DOT | Visual review, PDF/SVG/PNG via `dot -T…` |
| `taudit map` | Text table or DOT | Human scan of “who holds what authority” |
| `taudit scan` | Terminal / JSON / SARIF / CloudEvents | CI triage, GitHub Code Scanning, SIEM |
| `taudit verify` | Text / JSON / SARIF | Merge gates (policy invariants) |

**Gaps called out in operations (internal + user feedback):**

- **Graphviz is not universal** — `dot` is an extra install; broken pipes from missing `dot` (mitigated in v1.0.5+ for `graph` stdout).
- **JSON is complete but not visual** — teams want “paste into a doc or PR” without a JS pipeline.
- **SARIF primary locations are file-anchored** without line/region in many results — Code Scanning and IDEs are weaker for **per-finding** navigation.
- **Partial graphs** — real workflows often hit matrix/reusable/callback gaps; trust requires honest `completeness` and visible gap text (good) but orgs want **convergence to `Complete`**.

## Adjacent and competitive patterns

- **SAST / IaC (Semgrep, Checkov, tfsec):** lead with **findings in CI**; graph-like “call graph” is secondary. taudit inverts: **graph first**, rules as predicates.
- **Supply chain (Sigstore, SLSA):** attest **build** provenance. taudit models **CI authority**; complementary, not duplicative.
- **GitHub** native: **no** first-party authority graph — opportunity for taudit + optional upload to `dependency-graph` style APIs in future.

## User journeys (condensed)

1. **Engineer in IDE** — Wants a picture of GITHUB_TOKEN reachability in 60 seconds. **DOT+Graphviz** works; **Mermaid** in markdown is lower friction.
2. **Platform / security** — Wants org-wide **diff of graph** or **attestation** of graph at merge — JSON + (future) tsign.
3. **Compliance** — Wants “prove what secret can reach this step” — `map` + invariants, export to evidence bundle.

## Recommendations (investment order)

1. **Native Mermaid** for `taudit graph` (and document parity with `map --format dot`) — zero host deps for “good enough” visualization in README/PR/Notion.
2. **Hardening stdout** (EPIPE) for `map` and other high-volume writers — same semantics as `graph` post-v1.0.5.
3. **SARIF + JSON location enrichment** when YAML spans are available — phased; schema/consumer impact.
4. **Parser depth** to reduce `Partial` on mainstream GHA/ADO/GitLab — largest engineering cost, highest trust payoff.

**Non-goals for the next quarter:** building a second graph engine, replacing GitHub’s workflow UI, or a hosted SaaS for graphs.

## References in-repo

- [positioning.md](../positioning.md) — “graph is the product”
- [authority-graph.md](../authority-graph.md) — schema semantics
- [ROADMAP.md](../ROADMAP.md) — v1.0 charter, completeness parity
- [finding-fingerprint.md](../finding-fingerprint.md) — dedup contract for findings (orthogonal to graph export)

## Research closure

- **Sponsor:** product/engineering (this document).
- **Next step:** [council synthesis](./2026-04-27-council-graph-as-product.md) and [ADR 0001](../adr/0001-graph-native-exports-and-leverage.md).
