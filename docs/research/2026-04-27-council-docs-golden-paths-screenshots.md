# Council (Quick): docs, golden paths, screenshots as first-class

- **Date:** 2026-04-27
- **Mode:** Quick Council — single round, four perspectives (Architect, Designer, Engineer, Researcher)
- **Prompt:** How should taudit treat **documentation**, **golden paths** (blessed copy-paste flows), and **screenshots/diagrams** as first-class alongside code (CI, layout, contributor expectations)?

## Perspectives

**Architect —** Treat user-facing flows as **executable contracts**: fenced commands under a dedicated `docs/golden-paths*` surface, CI (or tests) that run the real binary against **checked-in expectations** so docs cannot drift silently. Visual assets (SVG) should be **generated**, not hand-edited, and regenerated from scripts when CLI output changes. Highest leverage: one golden-path harness before heavy screenshot infra.

**Designer —** Prefer **literal terminal transcripts** (copy-paste + stdout blocks) over bitmap screenshots: accessible, theme-agnostic, grep-able, and they update with snapshot/insta workflows. Reserve images for **spatial** artifacts users cannot reproduce in text (e.g. rendered graph SVG). If screenshots exist, use a **neutral terminal theme** and document the regen command beside the asset.

**Engineer —** Extend existing **insta** + **corpus** patterns instead of a second snapshot stack: `just` targets for doc-adjacent smoke, **`NO_COLOR=1`** for stable text, **`cargo insta test --check`** as a gate where snapshots apply. For graphs, **SVG text diff** in PRs is enough for a CLI; skip pixel-diff until a TUI or HTML product exists.

**Researcher —** Industry patterns: **mdBook** + link-check in CI (Rust ecosystem norm), **Vale** when prose volume grows, **executable fenced blocks** in README/docs as tests (“literate” CI). Small Rust teams usually **do not** run Percy-style screenshot gates for CLIs — **terminal snapshots** are the norm.

## Consensus

1. **Golden paths are code:** run them in CI or integration tests; fail on drift.
2. **Text beats pixels** for CLI onboarding; **SVG (or similar) beats PNG** for graph visuals.
3. **Layer on existing taudit machinery** (corpus suite, insta, `just`) before new doc frameworks.

## In-tree follow-ups (this commit / near-term)

- [`docs/golden-paths.md`](../golden-paths.md) — blessed commands against **committed fixtures**.
- [`docs/media/README.md`](../media/README.md) — policy for generated visuals.
- [`scripts/golden-paths.sh`](../../scripts/golden-paths.sh) + **`just golden-paths`** — fast smoke that those commands still succeed (not full stdout diff yet); wired into **`scripts/quality-gate.sh`** (after `cargo test`) and **`.github/workflows/quality.yml`**.

Escalate to a **full Council debate** if we add mdBook/site generation, link graphs, or prose lint gates — trade-offs multiply.

## References

- Corpus CLI suite: [`crates/taudit-cli/tests/corpus_cli_suite.rs`](../../crates/taudit-cli/tests/corpus_cli_suite.rs)
- Prior product research: [2026-04-27-graph-as-product-research.md](2026-04-27-graph-as-product-research.md)
