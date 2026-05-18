# Schema Drift Controls

Status: L2-09 control design for `v1.2.0-rc.1`. This file documents controls
only; it does not claim that proposed commands exist until they are listed as
observed below.

Source decisions:
[ADR 0017](../../adr/0017-current-output-profile-and-contract-examples.md),
[ADR 0020](../../adr/0020-output-conformance-harness-and-rc-gate.md),
[L2-09](code-complete-lanes.md#l2-api-schemas-contracts),
[L2-08](code-complete-lanes.md#l2-api-schemas-contracts), and
[QA-04](code-complete-lanes.md#qa-and-resilience-gates).

## Evidence Boundary

- Observed: `scripts/generate-authority-invariant-schema.py --check` extracts
  `FindingCategory` from
  [taudit-api/src/lib.rs](../../../crates/taudit-api/src/lib.rs) and checks
  category enums in
  [authority-invariant-v1.schema.json](../../../contracts/schemas/authority-invariant-v1.schema.json),
  [taudit-report.schema.json](../../../contracts/schemas/taudit-report.schema.json),
  [taudit-cloudevent-finding-v1.schema.json](../../../contracts/schemas/taudit-cloudevent-finding-v1.schema.json),
  and [finding.v1.json](../../../schemas/finding.v1.json).
- Observed: [quality.yml](../../../.github/workflows/quality.yml) runs the
  generator in `--check` mode, validates starter invariant YAML, and runs
  report and CloudEvents contract tests.
- Observed: `just contracts` currently runs `cargo test -p taudit-report-json`
  and `cargo test -p taudit-sink-cloudevents`.
- Observed: [current-output-profile.md](current-output-profile.md) defines the
  L2-07 profile target. No executable current-output profile command or ADR
  0020 conformance command was found in `scripts/`, `justfile`, `contracts/`,
  `schemas/`, or `.github/workflows/`.
- Candidate only: Cordance input names two concerns: schema example coverage
  and schema naming clarity. Treat both as prompts for repo-backed checks, not
  as authority, doctrine, or proof of drift.

## Drift Classes

| Drift class | Meaning | Do not confuse with | Failing condition |
| --- | --- | --- | --- |
| Compatibility-schema drift | A published compatibility schema no longer matches the backward-compatible documents it claims to accept, or its closed enums/required fields diverge from the source model. | Current-profile absence. A field may stay optional for old documents while current taudit must emit it. | Schema compile/validation fails; a source enum value is missing from a schema; a schema rejects a supported older example without a version decision. |
| Current-profile drift | Current taudit output omits fields the RC promises to emit, even if the compatibility schema permits omission. | Compatibility schema permissiveness. | A real fixture output or refreshed example lacks promised identity, evidence, schema URI, source, provenance, suppression, or event fields from ADR 0017. |
| Source-enum/schema drift | Rust serde names, schema enum values, examples, and docs disagree on a closed value set. | Open metadata fields. | A Rust enum variant or serde rename is added, removed, or changed without the matching schema, example, docs, semver, and release-note decision. |

## Surface Map

| Surface | Source of truth | Current observed controls | Needed control |
| --- | --- | --- | --- |
| Rust API enums | [taudit-api/src/lib.rs](../../../crates/taudit-api/src/lib.rs): `Severity`, `FindingCategory`, `Recommendation`, `FindingSource`, `FixEffort`, `GapKind`, `AuthorityCompleteness`, `IdentityScope`, `NodeKind`, `TrustZone`, `EdgeKind`. | `FindingCategory` extraction exists through `scripts/extract_finding_categories.py`; stable-promotion semver checks are documented elsewhere. | Extend schema/source drift checks beyond `FindingCategory` so every closed serde enum has an explicit schema location or an explicit "not public" decision. |
| Finding schema | [schemas/finding.v1.json](../../../schemas/finding.v1.json). | CLI integration tests validate emitted findings; generator checks `FindingCategory`; severity/category tests exist. | Compare every public closed enum used by `Finding` and `Recommendation`, not only category/severity. Keep compatibility optionality separate from current-profile required emission. |
| Report schema | [taudit-report.schema.json](../../../contracts/schemas/taudit-report.schema.json). | `cargo test -p taudit-report-json` validates emitted reports, examples, authority graph export, and category coverage. | Add current-profile assertions for report envelope fields, finding identity fields, suppression fields, evidence fields, graph completeness, and schema URI/version. |
| CloudEvents schema | [taudit-cloudevent-finding-v1.schema.json](../../../contracts/schemas/taudit-cloudevent-finding-v1.schema.json). | `cargo test -p taudit-sink-cloudevents` validates emitted events, examples, shared envelope shape, deterministic stable fields, and category coverage. | Add current-profile assertions for extensions such as `tauditfindingfingerprint`, `tauditsuppressionkey`, `tauditruleid`, `tauditplatform`, `tauditfindinggroup`, provenance fields, event type, and data parity with JSON/SARIF where promised. |
| Authority invariant schema | [authority-invariant-v1.schema.json](../../../contracts/schemas/authority-invariant-v1.schema.json). | `scripts/generate-authority-invariant-schema.py --check` regenerates input schema from Rust categories and intentionally excludes reserved output-only categories. `scripts/validate-authority-invariant-yaml.py invariants/starter` validates starter policies. | Add DSL predicate drift checks against `custom_rules.rs` when predicates or matcher fields change. Keep input schema exclusions explicit. |
| Contract examples | [contracts/examples](../../../contracts/examples). | Report and CloudEvents tests validate checked-in examples against schemas. | L2-08 should refresh examples from real fixtures and mark which examples are compatibility examples versus current-profile examples. A future check should fail when examples are stale relative to generated fixture output. |
| Current-output profile | ADR 0017, [current-output-profile.md](current-output-profile.md), and [public-contract-boundary.md](public-contract-boundary.md). | Profile requirements are documented, but no executable profile command was observed. | Add a current-profile manifest or test module that asserts current required fields independently from schema validation. Missing fields should fail even when the compatibility schema passes. |
| Generated docs | Rustdoc/docs.rs for `taudit-api`, schema docs if generated later, and release docs. | No generated-doc drift command observed. Public boundary docs already require `cargo doc -p taudit-api --no-deps` before readiness claims. | Treat generated docs as a projection of source/schema state: build Rustdoc, check local links, and fail release docs that advertise a field, enum, or stability level not backed by source/schema/profile evidence. |

## Existing Commands

These commands were observed in the repo and may be used by implementers today:

```bash
python scripts/generate-authority-invariant-schema.py --check
python scripts/validate-authority-invariant-yaml.py invariants/starter
cargo test -p taudit-report-json
cargo test -p taudit-sink-cloudevents
just contracts
```

Observed failure modes:

- `generate-authority-invariant-schema.py --check` exits non-zero when any of
  the four generated schema targets differ and tells the operator to run the
  `--write` form.
- Report and CloudEvents tests fail with the violated schema path, emitted
  payload, category, or example context, depending on the test.
- `validate-authority-invariant-yaml.py` exits non-zero on YAML parse errors,
  non-object documents, schema validation errors, or an empty input set.

## Proposed Commands

These commands are proposals for L2/L5/QA work. They were not found as existing
commands during this pass.

```bash
just contract-drift
python scripts/check-schema-source-drift.py --check
python scripts/check-current-output-profile.py --profile contracts/current-output-profile.v1.json --fixtures contracts/examples
python scripts/refresh-contract-examples.py --check
just output-conformance
```

Proposed behavior:

- `just contract-drift` should run the existing generator check, schema/source
  enum diff, current-profile check, example freshness check, and focused
  report/CloudEvents contract tests.
- `check-schema-source-drift.py --check` should extract closed serde values
  from `taudit-api` and compare them with their schema enum locations. Values
  with no public schema location must be listed as internal or open metadata.
- `check-current-output-profile.py` should validate real fixture output and
  refreshed examples against the current-profile promises from ADR 0017. It
  should report JSON pointer paths for missing current fields.
- `refresh-contract-examples.py --check` should regenerate examples into a temp
  directory, compare with `contracts/examples`, and fail on drift without
  writing unless a `--write` mode is explicitly requested.
- `just output-conformance` is the ADR 0020 gate shape. Its final name should
  be owned by QA/L5, but it should include graph JSON, exploit graph JSON, scan
  JSON, SARIF, CloudEvents, contract examples, reference consumers, identity
  parity, evidence parity, suppression parity, and exit-code matrix checks.

## Blocking Rules

- A schema-only compatibility relaxation does not satisfy ADR 0017. If current
  taudit promises a field, the profile check must require it.
- A current-output field addition does not automatically require a compatibility
  schema breaking change. Additive optional schema fields may be compatible
  while current-profile examples make the field expected for the RC.
- A Rust enum change is a public-contract change when it serializes into
  finding JSON, report JSON, CloudEvents, authority graph JSON, or invariant
  YAML. It needs a schema decision, example/profile decision, and semver or
  release-note decision.
- Reserved output-only categories remain a special case: output schemas may
  include them while invariant input rejects them. That split is intentional
  only when source comments, generator logic, and schema behavior agree.
- Cordance candidate concerns must not block or pass the gate alone. Promote
  them only after repo evidence identifies a concrete schema, example, or name.

## Handoff

L2-09 can implement the schema/source drift target from this map. L2-08 can use
the same map to refresh examples without confusing compatibility examples with
current-profile examples. QA-04 can fold the observed and proposed checks into
the ADR 0020 conformance harness once that harness exists.
