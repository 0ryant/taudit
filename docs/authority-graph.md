# Authority Graph — Versioned Export

taudit's primary asset is the **authority graph** it builds from a CI/CD
pipeline file. Every other output (terminal report, SARIF, CloudEvents,
findings) is derived from this graph. The graph is now a first-class,
machine-readable export — emitted by `taudit graph` and validated against
a stable JSON Schema so that downstream tools (tsign, axiom, runtime
cells, custom auditors) can consume it without reverse-engineering
taudit's internals.

- **Schema**: [`schemas/authority-graph.v1.json`](../schemas/authority-graph.v1.json)
- **Schema URI**: `https://github.com/0ryant/taudit/schemas/authority-graph.v1.json`
- **Schema version**: `1.0.0` (semver — see [Versioning](#versioning))
- **CLI**: `taudit graph <path> [--format json|dot|mermaid|summary] [--platform ...] [--rules-dir ...] [--job ...] [--rich-labels]` — JSON includes optional **`authority_summary`** on `has_access_to` → identity edges (see below). **`summary`** is a separate bounded JSON document (see [Propagation summary](#propagation-summary-format-summary)).

## Quick start

```bash
# Default JSON, schema-conformant, pretty-printed
taudit graph .github/workflows/release.yml

# Graphviz DOT for visualization
taudit graph .github/workflows/release.yml --format dot | dot -Tsvg -o release.svg

# Mermaid flowchart (no Graphviz — paste into Markdown)
taudit graph .github/workflows/release.yml --format mermaid

# Restrict diagram output to a single job's reachable subgraph (dot or mermaid)
# Job IDs are workflow-specific — this repo documents them in USERGUIDE.md
taudit graph .github/workflows/release.yml --format dot --job build
taudit graph .github/workflows/release.yml --format mermaid --job build
taudit graph .github/workflows/security.yml --format mermaid --job taudit-self-scan

# Auto-detect platform (default) or pin it
taudit graph .pipelines/azure-pipelines.yml --platform azure-devops

# Bounded propagation rollup (boundary-crossing paths only; same BFS as rule-engine authority propagation)
taudit graph .github/workflows/release.yml --format summary
```

### At a glance (one graph, several exports)

`json`, `dot`, `mermaid`, and `summary` are different **views** or **rollups** of the same in-memory
`AuthorityGraph` — not separate pipelines.

```text
  workflow YAML
        │
        ▼
   ┌─────────┐
   │  parse  │
   └────┬────┘
        │
        ▼
  ┌──────────────┐
  │ AuthorityGraph│  ← single canonical model
  └───────┬──────┘
          │
   ┌──────┼──────────────────────┐
   ▼      ▼              ▼        ▼
 JSON   DOT         Mermaid   Summary
        │              │         │
   schema-backed   Graphviz   GitHub /   Bounded propagation
   interchange      `dot`     GitLab     JSON (paths to lower
   for tools                 fenced      trust zones only)
                               block
```

`--job` limits **dot** and **mermaid** to a job’s reachable subgraph; **json**
and **summary** stay full-graph when you need lossless `completeness` / `completeness_gaps` or a global propagation rollup.

`taudit map` defaults to the human-readable step×authority **table**; with
`--format dot` or `--format mermaid` it emits the same diagram renderers as
`taudit graph`. `taudit graph --format json` remains the lossless interchange.

### Propagation summary (`--format summary`)

**`taudit graph --format summary`** emits a standalone JSON document validated against
[`schemas/authority-propagation-summary.v1.json`](../schemas/authority-propagation-summary.v1.json):
totals over **boundary-crossing** propagation paths (sink trust zone strictly lower than the authority source),
plus top-N sinks and sources by path count. It is a **read-only triage projection** — it does not replace
**`verify`** or the full graph JSON. **`--max-hops`** and the dense-graph guard match **`taudit scan`**
(use **`--force-scan-dense`** to override on very large graphs). **`--rich-labels`** does not apply.
See [ADR 0002 Phase 3](adr/0002-authority-signal-roadmap-phased.md#phase-3--deterministic-projections-risk-readouts).

### JSON contract vs diagram views (`--rich-labels`)

**JSON** is the **stable machine contract**: full nodes, edges, and parser
`metadata`. **DOT** and **Mermaid** are **views** of that model: default labels
stay short (node name only) so diagrams stay compact in PRs and docs.

Opt in with **`--rich-labels`** on **`taudit graph --format dot|mermaid`** or
**`taudit map --format dot|mermaid`** to append trust zone and selected
metadata the graph already carries (for example identity scope and permissions
summary on identities). JSON output and the graph structure are unchanged; only
the diagram text grows. Prefer the default for large graphs; use rich labels for
small slices, teaching, or review.

## Document shape

Every JSON document emitted by `taudit graph --format json` is wrapped in
a versioned envelope:

```json
{
  "schema_version": "1.0.0",
  "schema_uri": "https://github.com/0ryant/taudit/schemas/authority-graph.v1.json",
  "graph": {
    "source":   { "file": "...", "repo": "...", "git_ref": "..." },
    "nodes":    [ ... ],
    "edges":    [ ... ],
    "completeness":      "complete" | "partial" | "unknown",
    "completeness_gaps": [ "human-readable reasons ..." ],
    "completeness_gap_kinds": [ "expression" | "structural" | "opaque", ... ],
    "metadata":          { "trigger": "push", ... }
  }
}
```

## Graph model

### `NodeKind`

Each node represents one element of the pipeline. The kind is structural,
not a severity label.

| Kind       | What it is                                                               |
| ---------- | ------------------------------------------------------------------------ |
| `step`     | A runnable unit (a `run:` block, an action invocation, an ADO task).     |
| `secret`   | A sensitive value referenced by name (`secrets.FOO`, `$(MY_SECRET)`).    |
| `identity` | A token or principal (`GITHUB_TOKEN`, OIDC identity, service connection).|
| `image`    | An action reference, container image, or self-hosted pool.               |
| `artifact` | Data crossing step boundaries (uploaded artifact, cache, file on disk).  |

### `TrustZone`

Trust is **explicit on every node**, never inferred from kind. Three
zones, ordered by descending trust:

| Zone           | Examples                                                              |
| -------------- | --------------------------------------------------------------------- |
| `first_party`  | `run:` steps you authored, secrets you defined, your own composite actions. |
| `third_party`  | SHA-pinned marketplace actions, digest-pinned containers.             |
| `untrusted`    | Unpinned actions (`@main`), fork-PR inputs, anything mutable upstream.|

Authority crossing from a higher zone to a lower zone is the central risk
signal. Findings are produced when that crossing happens along an edge
that propagates secrets or identities.

### `EdgeKind`

Edges model **authority/data flow**, not syntactic YAML structure. The
design test for an edge variant is "can authority propagate along it?"

| Kind             | Direction                  | Meaning                                                              |
| ---------------- | -------------------------- | -------------------------------------------------------------------- |
| `has_access_to`  | step → secret/identity     | The step reads the credential at runtime.                            |
| `produces`       | step → artifact            | The step writes data that survives the step's lifetime.              |
| `consumes`       | artifact → step            | A later step ingests the artifact (and any authority baked into it). |
| `uses_image`     | step → image               | The step delegates execution to an action or container.              |
| `delegates_to`   | step → step                | Cross-job or composite-action handoff (control transfer).            |
| `persists_to`    | step → secret/identity     | The step writes a credential to disk (e.g. `~/.docker/config.json`); accessible to every subsequent step. |

### Edge `authority_summary` (ADR 0002 Phase 2)

On **`has_access_to`** edges to an **`identity`** node, the graph JSON may
include an optional **`authority_summary`** object: a **small, fixed set**
of strings (`trust_zone`, `identity_scope`, `permissions_summary`) copied
from that identity so consumers do not have to reverse-engineer
`Node.metadata` for routine privilege questions. The field is omitted on
other edges and on older exports. It is not a general-purpose metadata map.

### `AuthorityCompleteness`

| Value      | Meaning                                                                   |
| ---------- | ------------------------------------------------------------------------- |
| `complete` | The parser fully resolved every authority relationship in the file.       |
| `partial`  | Some constructs (composite actions, reusable workflows, shell strings) couldn't be fully resolved. `completeness_gaps` lists why, and `completeness_gap_kinds` annotates each entry with a typed severity (see [Completeness gap kinds](#completeness-gap-kinds)). The graph is still useful — just incomplete. |
| `unknown`  | The parser couldn't determine completeness.                               |

Treat `partial` graphs as a floor on risk: every edge present is real,
but more may exist that the parser couldn't see.

## Completeness gap kinds

`completeness_gaps` and `completeness_gap_kinds` are **parallel arrays** — same length, same order — so a consumer can pair the human-readable reason at index `i` with its typed kind at index `i`. Both are omitted when empty (i.e. on `complete` graphs).

| Kind | Serialised | Meaning |
|---|---|---|
| `Expression` | `"expression"` | A template or matrix expression hides a value; graph structure is intact |
| `Structural` | `"structural"` | An unresolvable component (composite action, reusable workflow, `extends:`, `include:`) breaks the authority chain |
| `Opaque` | `"opaque"` | The graph cannot be built at all (zero steps produced, unknown platform) |

The kinds are ordered by severity: `expression < structural < opaque`. Use the most severe kind present in policy logic to distinguish noise (`expression`) from broken authority chains (`structural`) and unmodeled pipelines (`opaque`). See [`docs/policies/cookbook-partial-graphs.md`](policies/cookbook-partial-graphs.md) — Pattern D — for a `jq` recipe that gates on gap kind.

### Node metadata

`Node.metadata` is an open string-keyed map. Reserved keys are documented
as `META_*` constants in
[`crates/taudit-core/src/graph.rs`](../crates/taudit-core/src/graph.rs).
Selected keys consumers should know about:

- `digest` — present on SHA-pinned action images.
- `permissions` — raw GHA permissions block on identity nodes.
- `identity_scope` — `broad` / `constrained` / `unknown` (computed).
- `oidc` — `"true"` when a workflow has `id-token: write`.
- `inferred` — `"true"` when the node was guessed (e.g. secret from a `run:` block).
- `container` — `"true"` when an image is a job-level container, not a `uses:` action.
- `self_hosted` — `"true"` for self-hosted runner pools.
- `service_connection` — `"true"` for ADO service connections.
- `implicit` — `"true"` for platform-injected tokens (e.g. `System.AccessToken`).
- `variable_group` — `"true"` for ADO variable-group secrets.
- `cli_flag_exposed` — `"true"` when a secret value is interpolated into a CLI flag.
- `writes_env_gate` — `"true"` for steps that write `$GITHUB_ENV` / `##vso[task.setvariable]`.
- `attests` — `"true"` for build-provenance attestation steps.
- `checkout_self` — `"true"` for `checkout: self` (ADO) or default checkout in PR context.
- `env_approval` — `"true"` for steps in jobs gated by environment approvals.
- `job_name` — name of the parent job (set on every step).

Unknown metadata keys are safe to ignore. New non-breaking keys may be
added in any 1.x release.

## Versioning

The schema follows semver with these guarantees:

- **`1.x.y` (additive only)** — new optional fields, new metadata keys,
  new enum values for **open** enums (today: `metadata` keys). Existing
  consumers continue to validate.
- **`2.0.0`** — only when something existing is renamed, removed, or
  retyped; or when a new value is added to a **closed** enum
  (`NodeKind`, `TrustZone`, `EdgeKind`, `AuthorityCompleteness`).
  Consumers must update.

The `schema_version` field at the document root tells consumers exactly
which contract they're parsing. `schema_uri` is the canonical URL of the
schema document and is safe to cache.

**`taudit verify --format json`:** the report uses `schema_version: "taudit.verify.v1"`.
New top-level keys (e.g. per-pipeline `pipelines` with `completeness`) are
**additive** within `1.x` the same way optional graph fields are — consumers
should ignore unknown keys.

## How downstream consumers should use it

Recommended integration pattern:

1. **Pin to a major version**. Read `schema_version`, refuse to parse
   anything outside the major you understand (e.g. accept `1.x.y`,
   reject `2.x.y`).
2. **Validate against the schema** before trusting the document. Cache
   the schema by URI; use a draft-07-capable validator.
3. **Treat `metadata` as open**. Never error on an unknown key.
4. **Honor `completeness`**. If the graph is `partial`, surface that to
   your users — your downstream signal is only as complete as the input.
5. **Use `id` for cross-references inside the graph** (edges reference
   node ids; ids are dense and start at 0). Do not rely on `id` being
   stable across runs of taudit.

The standalone graph export is intentionally minimal — it carries no
findings, no rule output, no remediation. Tools that want findings
should keep using `taudit scan --format json` (which now also includes
`schema_version` and `schema_uri` for the report contract).

## Public metadata keys

Most `META_*` keys on nodes are parser-private — they're internal hints
for the rule engine and may change shape between minor versions. One key
is publicly stable and part of the schema contract:

- **`job_name`** (constant `META_JOB_NAME`) — populated on every Step
  node by all 3 parsers (GHA, ADO, GitLab CI). Records the parent job
  name. Downstream consumers can rely on it for per-job filtering and
  attribution. Other `META_*` keys remain implementation details.

## See also

- [`schemas/authority-graph.v1.json`](../schemas/authority-graph.v1.json) — the schema itself
- [`crates/taudit-core/src/graph.rs`](../crates/taudit-core/src/graph.rs) — Rust source of truth
- [`contracts/schemas/taudit-report.schema.json`](../contracts/schemas/taudit-report.schema.json) — the larger scan-report schema (graph + findings + summary)
