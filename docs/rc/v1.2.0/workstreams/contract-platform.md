# Contract Platform Workstream Brief

## Goal

Make `v1.2.0-rc.1` the contract-platform release: `taudit-api` is ready for
`1.0`, the authority graph/schema contract is auditable, and downstream
consumers can rely on stable boundaries between `taudit-api`, `taudit-core`,
authority-graph JSON, scan JSON, SARIF, and CloudEvents.

The workstream should bias toward contract clarity and conformance evidence
over new detection surface. New rules are valuable only when they do not blur
the public contract.

## Why This Takes taudit Skyward

taudit already frames the typed authority graph as the product, with findings,
SARIF, merge gates, and CloudEvents as consumers of that graph (`README.md`).
The next lift is making that claim externally dependable: downstream tools
should be able to pin `taudit-api` and `schemas/authority-graph.v1.json` with
the same confidence they pin a compiler AST or an event schema.

This unlocks durable ecosystem work:

- `tsign` can sign graph claims without linking the analysis engine.
- `axiom` can enforce graph-derived decisions without reverse-engineering
  report sinks.
- SIEM, Backstage, marketplace actions, IDE extensions, and policy services can
  join on stable `rule_id`, `fingerprint`, `suppression_key`, and graph ids.
- `taudit-core` can keep moving internally while the Rust/wire boundary stays
  boring, versioned, and testable.

## Current Evidence

- Observed: the root README states that the typed authority graph is the
  product and that findings, SARIF, terminal output, PR gates, and CloudEvents
  are consumers (`README.md`).
- Observed: `taudit-api` is the intended public Rust wire surface for JSON,
  SARIF, CloudEvents, and authority-graph output, while `taudit-core` remains
  the in-process engine (`crates/taudit-api/README.md`,
  `crates/taudit-api/src/lib.rs`, `README.md`).
- Observed: `taudit-api` is still `0.4.1`, and its manifest explicitly says
  the contract is not frozen until `1.0` (`crates/taudit-api/Cargo.toml`).
- Observed: the authority graph has a standalone schema with
  `schema_version: "1.0.0"`, `schema_uri`, closed core enums, open metadata, and
  explicit completeness markers (`schemas/authority-graph.v1.json`,
  `docs/authority-graph.md`).
- Observed: the JSON scan report and CloudEvents schema already document
  cross-sink identity for `fingerprint`, `rule_id`, and suppression metadata
  (`contracts/schemas/taudit-report.schema.json`,
  `contracts/schemas/taudit-cloudevent-finding-v1.schema.json`).
- Observed: `cross_sink_contract.rs` pins byte-identical `rule_id` and
  `fingerprint` behavior across JSON, SARIF, and CloudEvents, including
  custom-rule ids and output-injection sanitisation boundaries
  (`crates/taudit-cli/tests/cross_sink_contract.rs`).
- Observed: reference consumers in Python, Go, and TypeScript exercise the
  graph JSON as a sufficient downstream contract and gate on schema major
  version (`examples/consumers/README.md`).
- Observed: roadmap and release policy already treat output formats,
  detection semantics, schemas, and `taudit-api` as public contract surfaces
  (`docs/ROADMAP.md`, `docs/RELEASE_GATES.md`, `docs/release-strategy.md`,
  `CHANGELOG.md`).

## Deliverables

1. `taudit-api` 1.0 readiness decision

   Produce an explicit go/no-go checklist for publishing `taudit-api = "1.0.0"`
   in the `v1.2.0` line. The checklist must cover serde shape stability,
   exported enums, feature flags if any, docs.rs examples, CHANGELOG migration
   notes from `0.4.x`, and semver expectations. It must also state that
   downstream consumers should depend on `taudit-api`, not `taudit-core`
   (`crates/taudit-api/src/lib.rs`).

2. Public contract boundary matrix

   Write the stable boundary in one place:

   - `taudit-api`: public Rust wire types and metadata constants intended for
     embedders.
   - `taudit-core`: internal engine, parser graph construction, propagation,
     rules, suppressions, and finding computation.
   - authority-graph JSON: canonical machine interchange for downstream graph
     consumers (`schemas/authority-graph.v1.json`).
   - scan JSON: graph plus findings plus summary
     (`contracts/schemas/taudit-report.schema.json`).
   - SARIF: code-scanning projection, not a second graph contract.
   - CloudEvents: one finding per event for SIEM/event pipelines
     (`contracts/schemas/taudit-cloudevent-finding-v1.schema.json`).

3. Contract conformance harness

   Add or formalize a harness that runs representative fixtures through:

   - `taudit graph --format json`
   - `taudit scan --format json`
   - `taudit scan --format sarif`
   - `taudit scan --format cloudevents`
   - the Python, Go, and TypeScript reference consumers in `examples/consumers/`

   The harness should validate schema versions, schema URIs, closed enum values,
   required fields, dense node/edge ids, graph completeness fields, and
   cross-sink equality for `rule_id`, `fingerprint`, `suppression_key`, and
   finding group ids where present.

4. Schema/source drift controls

   Ensure Rust types, JSON schemas, docs, and example outputs cannot drift
   silently. Candidate probes include schema validation tests, snapshot
   fixtures, `cargo semver-checks` for `taudit-api`, and a small generated
   diff report for enum values shared between `crates/taudit-api/src/lib.rs`,
   `schemas/authority-graph.v1.json`, `schemas/finding.v1.json`, and
   `contracts/schemas/`.

5. Downstream consumer commitments

   Keep reference consumers as first-class release fixtures. Each consumer must
   fail loudly outside the schema major it understands, ignore unknown metadata,
   and walk edges by `kind` rather than by node-shape assumptions
   (`examples/consumers/README.md`).

6. Release-gate integration

   Tie the contract platform checks into the `v1.2.0-rc.1` release gate. The
   gate should classify contract failures as public-surface P0/P1 issues under
   `docs/RELEASE_GATES.md` and should use `docs/release-operations.md` /
   `scripts/release_harness.py` for tag validation.

## Acceptance Criteria

- `taudit-api` has a documented `1.0` readiness verdict with migration notes
  from `0.4.x` and no unresolved public serde-shape questions.
- A contract boundary matrix exists in docs and matches the crate map in
  `README.md`.
- The conformance harness runs at least one fixture for each supported platform
  and validates graph JSON, scan JSON, SARIF, and CloudEvents.
- Reference consumers still pass against a freshly generated graph JSON fixture.
- Cross-sink tests prove `rule_id`, `fingerprint`, and suppression identity are
  byte-identical where documented.
- JSON graph consumers can pin major `1`, reject future major versions, and
  ignore additive metadata without code changes.
- `taudit-core` remains an implementation dependency, not the promised public
  integration surface for downstream graph/report consumers.
- Release notes for `v1.2.0-rc.1` explicitly state whether the contract surface
  is additive, breaking, or unchanged.

## Risks / Non-Goals

- Risk: promoting `taudit-api` to `1.0` too early freezes accidental enum names,
  serde tags, or metadata constants. Mitigation: require a semver and schema
  review before the version bump.
- Risk: schema and Rust types drift because the schemas are hand-maintained.
  Mitigation: add conformance probes that compare emitted output, not just
  source declarations.
- Risk: downstream tools rely on parser-private `metadata` keys. Mitigation:
  clearly separate stable public keys from opaque metadata and require
  consumers to ignore unknown keys (`docs/authority-graph.md`).
- Risk: SARIF or CloudEvents becomes a competing source of truth. Mitigation:
  keep authority-graph JSON canonical and treat SARIF/CloudEvents as projections.
- Non-goal: no new policy engine, dashboard, runtime monitor, cloud API
  resolver, or CVE scanner in this workstream (`README.md`, `docs/ROADMAP.md`).
- Non-goal: no `schemas/authority-graph.v2.json` unless the workstream finds a
  real model break that cannot be expressed additively.
- Non-goal: no promise that `taudit-core` becomes semver-stable for embedders;
  the stable embedder boundary is `taudit-api`.

## Suggested Verification

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo test -p taudit-cli --test cross_sink_contract`
- `cargo test -p taudit-sink-cloudevents`
- `cargo semver-checks check-release -p taudit-api` before a `taudit-api 1.0`
  publish decision
- `python scripts/generate-authority-invariant-schema.py --check`
- Generate a graph fixture:
  `cargo run -p taudit -- graph tests/fixtures/propagation-leaky.yml --format json`
- Run all reference consumers against that generated graph:
  `python examples/consumers/python/blast_radius.py <graph.json>`,
  `go run ./examples/consumers/go <graph.json>`, and
  `deno run --allow-read examples/consumers/typescript/find-cycles.ts <graph.json>`
- For release prep: `just release-check v1.2.0-rc.1` and
  `just release-notes v1.2.0-rc.1`
