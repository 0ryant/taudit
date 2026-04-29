# Policy cookbook — partial and unknown authority graphs

When the parser cannot fully resolve every authority edge, the graph is marked **`partial`** or **`unknown`** with **`completeness_gaps`** explaining why. Operators must decide how to treat that in CI — taudit does not silently upgrade incomplete graphs to “full coverage.”

See [`docs/authority-graph.md`](../authority-graph.md) for the field definitions and [`docs/verify.md`](../verify.md) for merge-gate exit codes (`0` / `1` / `2`).

## Know what `verify` prints

**`taudit verify`** text and JSON (see **Unreleased** in [`CHANGELOG.md`](../../CHANGELOG.md)) include a per-pipeline rollup:

- **Text:** a line `verify: authority graph modeling: N pipeline(s) — complete: …, partial: …, unknown: …` plus one detail line per non-complete pipeline (truncated gap list).
- **JSON:** top-level **`pipelines`** array: `{ "path", "completeness", "completeness_gaps" }` alongside `violations` and `summary`.

Treat **`partial` / `unknown`** as a **first-class signal** at the same tier as violations when designing gates.

## Pattern A — Fail CI if any pipeline is not `complete`

Use the graph export and `jq` (or similar) in a dedicated step **before** or **after** `verify`:

```bash
set -euo pipefail
taudit graph --format json .github/workflows/ci.yml | jq -e '
  .graph.completeness == "complete"
' >/dev/null
```

For multiple files, loop or merge checks. `completeness` in graph JSON is **`complete` | `partial` | `unknown`** (snake_case), matching the graph schema.

## Pattern B — Record gaps but only gate on `verify` violations

Default posture: run **`taudit verify`** as the merge gate; read the **`pipelines`** block in JSON for audit logs / dashboards without failing on partiality alone.

```bash
taudit verify --policy .taudit/policy/ .github/workflows/ --format json -o verify-report.json
jq '.pipelines' verify-report.json
```

## Pattern C — Rely on built-in severity cap on incomplete graphs

Built-in rules cap severity for some finding classes when the graph is incomplete (see README: honest handling of unknowns). Pair **`--include-builtin`** with org policy if you want that behaviour inside **`verify`**.

## Custom invariants and completeness

The YAML invariant DSL does **not** yet expose `completeness` as a `graph_metadata` predicate. Until it does, use **Pattern A** (graph JSON + `jq`) or **`verify` JSON `pipelines`** for completeness-aware gates.

## References

- [ADR 0003 — Strategic spine & adoption](../adr/0003-strategic-spine-adoption-phased.md) Phase 2
- [`docs/verify.md`](../verify.md)
- [`schemas/authority-graph.v1.json`](../../schemas/authority-graph.v1.json)
