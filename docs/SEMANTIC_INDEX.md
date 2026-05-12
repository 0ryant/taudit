# taudit semantic index

This index maps the repository by concept rather than by directory alone. It is
intended as a fast orientation layer for agents and maintainers.

## Product concept

taudit is a CI/CD authority graph analyzer. It parses pipeline YAML into a typed
authority graph, evaluates built-in and custom authority invariants, and emits
human and machine reports. The graph is the product; findings, SARIF,
CloudEvents, terminal reports, baselines, suppressions, and policy gates are
views or consumers of that graph.

Core domain vocabulary:

- Authority source: `Secret` or `Identity`.
- Authority carrier/sink: `Step`, `Artifact`, `Image`, or delegated workflow.
- Trust zone: `FirstParty`, `ThirdParty`, `Untrusted`.
- Edge kind: `HasAccessTo`, `Produces`, `Consumes`, `UsesImage`,
  `DelegatesTo`, `PersistsTo`.
- Completeness: `Complete`, `Partial`, `Unknown`.
- Gap kind: `Expression`, `Structural`, `Opaque`.

## Workspace crates

| Crate | Role | Primary concepts |
| --- | --- | --- |
| `crates/taudit-api` | Public Rust wire-type contract | `Finding`, `FindingCategory`, `Severity`, `Node`, `Edge`, `AuthorityGraph` component types, metadata constants |
| `crates/taudit-core` | Internal graph/rule engine | graph mutation, propagation BFS, rule catalogue, fingerprints, baselines, suppressions, custom invariants |
| `crates/taudit-cli` | CLI composition root | command parsing, platform selection, file walking, scan/verify/map/graph/diff/baseline/suppressions/remediate |
| `crates/taudit-parse-gha` | GitHub Actions parser | workflow/job/step/env/permissions parsing, GHA triggers, local/composite/reusable workflow partiality |
| `crates/taudit-parse-ado` | Azure DevOps parser | stages/jobs/steps, service connections, variable groups, pools, templates, conditions, environment gates |
| `crates/taudit-parse-gitlab` | GitLab CI parser | jobs, includes, extends, variables, id tokens, services, dotenv artifacts, downstream triggers |
| `crates/taudit-report-terminal` | Human terminal sink | colored/severity output, control-character stripping, terminal report formatting |
| `crates/taudit-report-json` | JSON and graph export sink | report schema envelope, full graph export, summary/completeness gap output |
| `crates/taudit-report-sarif` | SARIF sink | GitHub code scanning output, markdown escaping, rule metadata |
| `crates/taudit-sink-cloudevents` | CloudEvents JSONL sink | one event per finding, correlation id, provenance fields, cross-sink fingerprint/rule id |

## Core files by concept

### Public contract

- `crates/taudit-api/src/lib.rs`: stable wire types and metadata constants.
- `schemas/authority-graph.v1.json`: graph export schema.
- `schemas/exploit-graph.v1.json`: exploit-path graph projection schema.
- `schemas/authority-propagation-summary.v1.json`: propagation rollup schema.
- `schemas/finding.v1.json`: single finding schema.
- `schemas/baseline.v1.json`: baseline file schema.
- `contracts/schemas/taudit-report.schema.json`: scan JSON report schema.
- `contracts/schemas/taudit-cloudevent-finding-v1.schema.json`: CloudEvents schema.
- `contracts/schemas/authority-invariant-v1.schema.json`: custom invariant DSL schema.
- `contracts/examples/`: example report/envelope/event payloads.

### Graph engine

- `crates/taudit-core/src/graph.rs`: mutable `AuthorityGraph`, pin helpers,
  completeness gaps, metadata, edge authority summaries.
- `crates/taudit-core/src/propagation.rs`: authority propagation BFS, dense graph
  guard, adjacency indexing.
- `crates/taudit-core/src/map.rs`: authority map, DOT, Mermaid, job subgraphs.
- `crates/taudit-core/src/summary.rs`: bounded propagation summary document.
- `docs/authority-graph.md`: graph semantics and export contract.
- `docs/adr/0001-graph-native-exports-and-leverage.md`: graph-as-product ADR.

### Rules and findings

- `crates/taudit-core/src/rules.rs`: built-in rule implementations and
  `run_all_rules`.
- `crates/taudit-core/src/finding.rs`: rule id derivation, fingerprints, finding
  group ids.
- `crates/taudit-core/src/custom_rules.rs`: custom invariant DSL loader,
  validation, symlink handling, evaluation.
- `docs/rules/index.md`: built-in rule catalogue.
- `docs/rules/*.md`: per-rule documentation.
- `docs/authority-invariants.md`: custom invariant concept and predicate docs.
- `invariants/starter/`: starter policy bundle.
- `invariants/policies/`: example enterprise policies.

### Parsers

- `crates/taudit-core/src/ports.rs`: `PipelineParser` port.
- `crates/taudit-cli/src/main.rs`: platform detection and parser selection.
- `crates/taudit-parse-gha/src/lib.rs`: GHA YAML to graph.
- `crates/taudit-parse-ado/src/lib.rs`: ADO YAML to graph.
- `crates/taudit-parse-gitlab/src/lib.rs`: GitLab YAML to graph.
- `tests/fixtures/`: cross-platform parser and CLI fixtures.
- `crates/taudit-parse-*/fuzz/`: fuzz targets and seed corpus for parsers.

### CLI commands

- `crates/taudit-cli/src/main.rs`: all clap commands and core command handlers.
- `crates/taudit-cli/src/error_hints.rs`: contextual CLI error hints.
- `crates/taudit-cli/src/remediate.rs`: unstable remediation support.
- `crates/taudit-cli/src/stdio_epipe.rs`: broken-pipe handling.
- `crates/taudit-cli/static/after-long-help.txt`: long help appendix.
- `man/taudit.1`: manual page.
- `USERGUIDE.md`: operator guide.

Command concepts:

- `scan`: parse pipelines, run built-ins and optional invariants, emit reports.
- `verify`: policy gate with stable exit codes.
- `graph`: canonical graph export as JSON/DOT/Mermaid/summary.
- `map`: step x authority table and diagram views.
- `diff`: compare pipeline authority changes.
- `baseline`: capture/accept historical findings.
- `suppressions`: validate and manage explicit finding suppressions.
- `explain`: describe built-in rules.
- `invariants`: list/explain custom and built-in invariants.

### Output sinks

- `crates/taudit-report-terminal/src/lib.rs`: terminal report rendering.
- `crates/taudit-report-json/src/lib.rs`: JSON report and graph export.
- `crates/taudit-report-sarif/src/lib.rs`: SARIF 2.1.0 output.
- `crates/taudit-sink-cloudevents/src/lib.rs`: CloudEvents JSONL output.
- `docs/finding-fingerprint.md`: fingerprint contract.
- `docs/finding-output-enhancements.md`: output fields and grouping.
- `docs/seam-freeze-v1.md`: cross-tool correlation/provenance vocabulary.

### Baselines, ignores, suppressions

- `crates/taudit-core/src/baselines.rs`: baseline file hashing, accepted findings,
  critical waiver validation.
- `crates/taudit-core/src/ignore.rs`: `.tauditignore` category/path matching.
- `crates/taudit-core/src/suppressions.rs`: explicit suppression config,
  downgrade/suppress modes, expiry validation.
- `docs/baselines.md`: rollout and baseline model.
- `docs/suppressions.md`: suppression format and operating model.
- `schemas/baseline.v1.json`: baseline contract.

### Release, governance, and quality

- `.github/workflows/quality.yml`: fmt, clippy, tests, schema drift,
  snapshots, deny, audit, golden paths, self-scan, verify.
- `.github/workflows/release.yml`: release build, SBOM/provenance assets.
- `.github/workflows/scheduled-fuzz.yml`: parser fuzz schedule.
- `.github/workflows/mutation-coverage.yml`: mutation coverage workflow.
- `.github/workflows/security.yml`: security checks.
- `scripts/generate-authority-invariant-schema.py`: Rust enum to schema drift guard.
- `scripts/validate-authority-invariant-yaml.py`: starter invariant validation.
- `scripts/golden-paths.sh`: docs/golden-paths smoke.
- `scripts/quality-gate.sh`: local/CI governance gate wrapper.
- `justfile`: local command aliases.
- `deny.toml`: cargo-deny policy.
- `docs/RELEASE_GATES.md`: release promotion criteria.
- `docs/release-strategy.md`: release lane semantics.
- `docs/release-trust.md`: attestation/SBOM verification.

### Packaging and consumers

- `packaging/homebrew/taudit.rb`: Homebrew formula.
- `packaging/nix/taudit.nix`: Nix package.
- `packaging/docker/cellos-supervisor/Dockerfile`: CellOS supervisor packaging.
- `examples/consumers/typescript/find-cycles.ts`: TypeScript consumer example.
- `examples/consumers/python/blast_radius.py`: Python consumer example.
- `examples/consumers/go/`: Go consumer example.
- `docs/integrations/`: integration guidance for axiom, tsign, CI mirrors.

### Research and planning

- `docs/ROADMAP.md`: historical and current roadmap, but contains stale
  contradictions that should be reconciled before release planning.
- `docs/jobs-phased-lanes.md`: parallel workstream decomposition.
- `TODOS.md`: detailed ADO variable-group enrichment proposal.
- `docs/gaps-implementation-prompt.md`: competitive gap closure plan, partially
  shipped and partially superseded.
- `docs/dogfood-corpus.md`: public-corpus plan, currently a stable-promotion
  blocker until populated.
- `docs/research/`: deeper research notes, sample scans, backlog, and council
  outputs.
- `docs/adr/`: architecture decision records.

## Data flow

1. CLI reads one or more pipeline YAML files.
2. Platform selection chooses GHA, ADO, GitLab, or auto-detection.
3. Parser converts YAML into `AuthorityGraph`.
4. Parser stamps graph metadata, node metadata, trust zones, and completeness
   gaps.
5. Core propagation engine finds authority paths across trust boundaries.
6. Built-in rules and custom invariants evaluate graph/path predicates.
7. Findings receive rule ids, fingerprints, group ids, extras, and source data.
8. Sink emits terminal, JSON, SARIF, or CloudEvents.
9. Baselines/suppressions/verify decide whether the result is advisory,
   downgraded, suppressed, or a gate violation.

## Extension points

- Add a parser: implement `PipelineParser`, add crate dependency to CLI, update
  platform enum/detection, fixtures, docs, and golden paths.
- Add a built-in rule: add `FindingCategory`, implement function in
  `rules.rs`, wire into `run_all_rules`, update schemas, docs, explain output,
  snapshots, and cross-sink tests.
- Add a custom invariant predicate: extend `custom_rules.rs`, update
  `authority-invariant-v1.schema.json` generator and docs, add fixture tests.
- Add an output field: update sink, schema, examples, cross-sink contract tests,
  changelog migration notes, and release-gate public contract review.
- Add a CLI flag: update `main.rs`, help text/man page, USERGUIDE, integration
  docs, and at least one CLI test.

## High-risk files

- `crates/taudit-cli/src/main.rs`: high churn; many features touch it.
- `crates/taudit-core/src/rules.rs`: very large rule catalogue; changes can
  alter detection semantics.
- `crates/taudit-api/src/lib.rs`: public wire contract; breaking changes need
  semver/migration treatment.
- `contracts/schemas/*.json` and `schemas/*.json`: public schemas; keep drift
  tests green.
- `crates/taudit-sink-cloudevents/src/lib.rs`: downstream correlation and
  trust artifact shape.
- Parser crate `src/lib.rs` files: easy to create silent under-modeling if
  partiality is not explicit.

## Search recipes

- Find rule implementation: `rg -n "pub fn <rule_name>|FindingCategory::<Name>" crates/taudit-core/src/rules.rs`
- Find metadata producers: `rg -n "META_<KEY>|metadata.insert" crates/taudit-*`
- Find parser partiality: `rg -n "mark_partial|GapKind" crates/taudit-parse-*`
- Find command handling: `rg -n "enum Cli|match cli|fn .*scan|fn .*verify" crates/taudit-cli/src/main.rs`
- Find schema drift logic: `rg -n "FindingCategory|schema" scripts contracts schemas crates/taudit-*`
- Find output fingerprints: `rg -n "compute_fingerprint|tauditfindingfingerprint|partialFingerprints" crates`
- Find CI gates: `rg -n "cargo test|clippy|insta|fuzz|semver|taudit verify" .github/workflows justfile scripts`

## Known semantic tensions

- `scan` is informational in current CLI help, while historical docs still
  discuss scan as a CI gate. Prefer `verify` for gating.
- Composite action handling has changed over time. Current planning should
  follow current parser behavior and changelog, not older roadmap checkboxes.
- `rules-dir` is an alias; `invariants-dir` is the preferred terminology.
- Complete vs Partial is a product promise. Never hide partiality in a prettier
  output format.
- `taudit-core` exposes some functions publicly for workspace use, but external
  Rust consumers should prefer `taudit-api`.
