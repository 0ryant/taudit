# Golden paths — blessed CLI flows

This page lists **copy-pasteable** commands that should always work on a clean checkout. They use **committed fixtures** under `tests/fixtures/` so paths stay stable in docs and issues.

**Principle:** prefer **terminal transcripts** (commands + key stdout checks) over screenshots. For graph **shape**, use **SVG** from Graphviz (`dot -Tsvg`) or Mermaid in Markdown — see [`docs/media/README.md`](media/README.md).

## Prerequisites

- **From source (dev):** `cargo build -p taudit` then `target/debug/taudit …`, or `cargo run -p taudit -- …`.
- **Installed:** `taudit` on your `PATH` (e.g. `cargo install --path crates/taudit-cli`).
- Stable output in scripts/CI: set **`NO_COLOR=1`** (or pass `--no-color` where supported).

Fixtures used below:

| File | Role |
|------|------|
| [`tests/fixtures/clean.yml`](../tests/fixtures/clean.yml) | Minimal GHA workflow — good for smoke |
| [`tests/fixtures/propagation-leaky.yml`](../tests/fixtures/propagation-leaky.yml) | Exercises propagation + findings |

## Path A — Map (human table)

```bash
NO_COLOR=1 taudit map tests/fixtures/clean.yml --platform github-actions
```

Expect: human-readable step × authority table; exit code **0**.

## Path B — Graph JSON (machine contract)

```bash
NO_COLOR=1 taudit graph tests/fixtures/clean.yml --platform github-actions --format json | head -c 400
```

Expect: JSON containing `"schema_version":"1.0.0"` and a `"graph"` object; exit code **0**.

(Full file is large; use `jq` locally for exploration.)

**Stdout only:** `taudit graph` has **no** `-o` / `--output` flag — all formats go to **stdout**. Persist with a shell redirect, e.g. `> /tmp/graph.json`. (`taudit scan` and `taudit verify` support `-o` / `--output` for SARIF/JSON reports.) See [ADR 0003 appendix](adr/0003-strategic-spine-adoption-phased.md#appendix-taudit-graph-and-output-files).

## Path C — Graph propagation summary

```bash
NO_COLOR=1 taudit graph tests/fixtures/clean.yml --platform github-actions --format summary | jq '.totals'
```

Expect: JSON with `schema_version` **1.0.0**, `method` **bfs_lower_trust_zone_sinks**, and `totals.boundary_path_count` (integer). Exit code **0**.

## Path D — Scan (findings)

```bash
NO_COLOR=1 taudit scan tests/fixtures/propagation-leaky.yml --platform github-actions --format json --quiet | jq '.findings | length'
```

Expect: exit code **0** (scan is informational); at least one finding for this fixture.

## Path E — Diagram export (optional Graphviz)

```bash
NO_COLOR=1 taudit graph tests/fixtures/clean.yml --platform github-actions --format dot | dot -Tsvg -o /tmp/taudit-golden.svg
```

Expect: **dot** on `PATH`; SVG written. Commit regenerated **marketing** SVGs under `docs/media/` only with the regen command recorded in [`docs/media/README.md`](media/README.md).

## Path F — Mermaid (no Graphviz)

```bash
NO_COLOR=1 taudit graph tests/fixtures/clean.yml --platform github-actions --format mermaid | head -n 5
```

Expect: first lines include **`flowchart`** (Mermaid `flowchart LR`); exit code **0**.

## Path H — Merge gate (`verify`) after graph + scan

End-to-end spine: export the graph (optional), scan for findings (informational), gate with explicit policy.

```bash
NO_COLOR=1 taudit graph tests/fixtures/clean.yml --platform github-actions --format json > /tmp/taudit-golden-graph.json
NO_COLOR=1 taudit scan tests/fixtures/clean.yml --platform github-actions --quiet
NO_COLOR=1 taudit verify --policy tests/fixtures/verify-golden-noop-policy.yml tests/fixtures/clean.yml --platform github-actions --format text
```

Expect: graph JSON validates the schema envelope; scan exits **0**; verify exits **0** with `verify: authority graph modeling:` and `verify: 0 violations` (noop policy matches nothing). Replace the policy path with your real `.taudit/policy/` directory in production.

**Pin the binary in CI:** `cargo install taudit --version 1.0.8 --locked` (adjust as you adopt newer releases). Copy-paste workflow: [`docs/examples/ci-gate-taudit-verify.yml`](examples/ci-gate-taudit-verify.yml).

## Path G — Rule catalog (`explain`)

```bash
NO_COLOR=1 taudit explain authority_propagation | head -n 8
```

Expect: rule id and severity in the header; exit code **0**.

## Automation

- **`just golden-paths`** — builds the dev binary and runs [`scripts/golden-paths.sh`](../scripts/golden-paths.sh) (smoke: exit codes + minimal stdout checks). Add stricter **insta** or stdout snapshots later; see [Council research note](research/2026-04-27-council-docs-golden-paths-screenshots.md).
- **`just pre-push-gate`** / **`just quality-gate`** — include the same golden-path smoke after **`cargo test`** (see [`scripts/quality-gate.sh`](../scripts/quality-gate.sh) `run_golden_paths`).
- **`just corpus-suite`** — exhaustive YAML corpus: `scan` + `graph` json + summary on every committed workflow/fixture seed.

## See also

- [USERGUIDE.md](../USERGUIDE.md) — tutorials and CI examples
- [docs/authority-graph.md](authority-graph.md) — graph model, JSON vs Mermaid vs summary
- [docs/verify.md](verify.md) — exit `0` / `1` / `2`, JSON shape including `pipelines` completeness
- [docs/policies/cookbook-partial-graphs.md](policies/cookbook-partial-graphs.md) — gating when graphs are `partial` / `unknown`
- [ADR 0003](adr/0003-strategic-spine-adoption-phased.md) — phased adoption tasks
- [docs/corpus-research.md](corpus-research.md) — large-directory scans and corpus methodology
