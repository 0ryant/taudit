# Policy cookbook — partial and unknown authority graphs

When the parser cannot fully resolve every authority edge, the graph is marked **`partial`** or **`unknown`** with **`completeness_gaps`** explaining why and **`completeness_gap_kinds`** classifying each gap. Operators must decide how to treat that in CI — taudit does not silently upgrade incomplete graphs to “full coverage.”

Gap kinds (least to most severe):

- **`expression`** — a template or matrix expression hides a value; structure intact.
- **`structural`** — an unresolvable component (composite action, reusable workflow, `extends:`, `include:`) breaks the authority chain.
- **`opaque`** — the graph cannot be built at all (zero steps, unknown platform).

The two arrays are **parallel** (same length, same order): `completeness_gaps[i]` is the human-readable reason and `completeness_gap_kinds[i]` is its typed kind.

See [`docs/authority-graph.md`](../authority-graph.md#completeness-gap-kinds) for the field definitions and [`docs/verify.md`](../verify.md) for merge-gate exit codes (`0` / `1` / `2`).

## Know what `verify` prints

**`taudit verify`** text and JSON (see **Unreleased** in [`CHANGELOG.md`](../../CHANGELOG.md)) include a per-pipeline rollup:

- **Text:** a line `verify: authority graph modeling: N pipeline(s) — complete: …, partial: …, unknown: …` plus one detail line per non-complete pipeline (truncated gap list).
- **JSON:** top-level **`pipelines`** array: `{ "path", "completeness", "completeness_gaps" }` alongside `violations` and `summary`. For typed kinds today, run **`taudit graph --format json`** on the same file — the graph export carries the parallel `completeness_gap_kinds` array.

Treat **`partial` / `unknown`** as a **first-class signal** at the same tier as violations when designing gates — and use the **kinds** (Pattern D below) to distinguish template noise (`expression`) from broken authority chains (`structural`) and unmodeled pipelines (`opaque`).

## Pattern A — Fail CI if any pipeline is not `complete`

Use the graph export and `jq` (or similar) in a dedicated step **before** or **after** `verify`:

```bash
set -euo pipefail
taudit graph --format json .github/workflows/ci.yml | jq -e '
  .graph.completeness == "complete"
' >/dev/null
```

For multiple files, loop or merge checks. `completeness` in graph JSON is **`complete` | `partial` | `unknown`** (snake_case), matching the graph schema. Inspect `completeness_gap_kinds` alongside it (see Pattern D) to decide whether the partiality is benign template noise or a real coverage hole.

## Pattern B — Record gaps but only gate on `verify` violations

Default posture: run **`taudit verify`** as the merge gate; read the **`pipelines`** block in JSON for audit logs / dashboards without failing on partiality alone.

```bash
taudit verify --policy .taudit/policy/ .github/workflows/ --format json -o verify-report.json
jq '.pipelines' verify-report.json
```

For typed-kind audit (e.g. counting `structural` gaps across a fleet), pair this with `taudit graph --format json` per file and aggregate `completeness_gap_kinds`.

## Pattern C — Rely on built-in severity cap on incomplete graphs

Built-in rules cap severity for some finding classes when the graph is incomplete (see README: honest handling of unknowns). Pair **`--include-builtin`** with org policy if you want that behaviour inside **`verify`**. The cap fires whenever `completeness != complete`, regardless of which `completeness_gap_kinds` are present.

## Pattern D — Gate on gap kind

The graph export annotates each gap with a typed kind (`expression`, `structural`, `opaque`). Use `jq` to fail CI only when the worst gap kind is `opaque` (fully unresolvable):

```bash
set -euo pipefail
taudit graph --format json .github/workflows/ci.yml | jq -e '
  (.graph.completeness_gap_kinds // []) | map(select(. == "opaque")) | length == 0
' >/dev/null
```

`expression` gaps stay non-blocking — they are template noise, not coverage holes. `structural` gaps represent broken authority chains worth investigating; `opaque` gaps mean taudit could not model the pipeline at all. To also block on `structural` (recommended once the codebase is clean), widen the filter:

```bash
taudit graph --format json .github/workflows/ci.yml | jq -e '
  (.graph.completeness_gap_kinds // []) | map(select(. == "opaque" or . == "structural")) | length == 0
' >/dev/null
```

To compute the worst kind locally for logging:

```bash
taudit graph --format json .github/workflows/ci.yml \
  | jq -r '
      (.graph.completeness_gap_kinds // []) as $k
      | if   ($k | index("opaque"))     then "opaque"
        elif ($k | index("structural")) then "structural"
        elif ($k | index("expression")) then "expression"
        else "complete" end
    '
```

## Custom invariants and completeness

The YAML invariant DSL does **not** yet expose `completeness` or gap kinds as a `graph_metadata` predicate. Until it does, use **Pattern A** or **Pattern D** (graph JSON + `jq`) or **`verify` JSON `pipelines`** for completeness-aware gates.

## References

- [ADR 0003 — Strategic spine & adoption](../adr/0003-strategic-spine-adoption-phased.md) Phase 2
- [`docs/verify.md`](../verify.md)
- [`schemas/authority-graph.v1.json`](../../schemas/authority-graph.v1.json)
