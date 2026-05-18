# v1.2.0-rc.1 Contract SemVer Rules

Status: L2-12 candidate documentation. This file records the versioning rule
set that release notes and `CHANGELOG.md` must agree with before
`v1.2.0-rc.1` is tagged.

Source decisions: [ADR 0009](../../adr/0009-v1-2-release-contract-and-semver-map.md),
[ADR 0010](../../adr/0010-public-contract-boundary-and-api-readiness.md),
[ADR 0012](../../adr/0012-public-output-identity-contract.md),
[ADR 0013](../../adr/0013-evidence-rendering-and-output-ceiling.md),
[ADR 0017](../../adr/0017-current-output-profile-and-contract-examples.md), and
the [public contract boundary matrix](public-contract-boundary.md).

## Shared Rules

| Rule | Contract meaning | Release action |
| --- | --- | --- |
| Additive schema fields | New optional fields, new open metadata keys, or new documented projections that old consumers can ignore. | Allowed on the current major. Document in release notes and current-output examples if current taudit promises to emit the field. |
| Current-profile requirement | A field may be optional in a compatibility schema while still required in current output examples. | Do not call the field optional in operator-facing copy when ADR 0017 current-profile checks require it. |
| Identity field change | Rename, removal, changed format, or changed derivation of `rule_id`, `fingerprint`, `suppression_key`, `finding_group_id`, platform token, source identity, or provenance. | Public output break. Requires explicit changelog migration note and a reviewed version decision before tag. |
| Evidence field change | Rename, removal, or claim-strength change for public evidence fields allowed by ADR 0013. | Public output break unless it is an additive, documented field below the output ceiling. |
| Closed enum change | New value in a closed enum, renamed value, removed value, or changed semantics of an existing value. | Breaking for that schema line unless the schema explicitly defines the enum as open. |
| Implementation-only change | Parser, core, reporter, or sink internals that do not change emitted contracts or exported `taudit-api` serde shape. | Does not by itself change the public contract. Published implementation crates still need semver-honest crate versions. |

## Surface Rules

| Surface | Current contract version | Additive path | Breaking path | `taudit-api` consequence |
| --- | --- | --- | --- | --- |
| Authority graph JSON | [schemas/authority-graph.v1.json](../../../schemas/authority-graph.v1.json) with `schema_version: "1.0.0"` and graph major `1`. | Use `1.x.y` for optional fields, open metadata keys, and non-breaking documentation of current output. Consumers should accept major `1` and ignore unknown open metadata. | Use `2.0.0` or a new schema line for removed, renamed, or retyped fields, closed enum additions, or changed graph identity/completeness semantics. | Bump only if exported `taudit-api` graph wire types or constants change. |
| Scan/report JSON | [contracts/schemas/taudit-report.schema.json](../../../contracts/schemas/taudit-report.schema.json) with `schema_version: "1.0.0"` today. | Additive fields can remain in report schema major `1` when old consumers can ignore them. ADR 0017 may still require them in current-profile examples. | Removing or renaming current-profile fields, changing finding identity semantics, changing report envelope meaning, or making compatibility consumers reject old v1 documents is breaking. | Keep `0.4.1` if changes are schema/output-only and existing exported Rust types already cover them. Use a prerelease minor if exported report/finding serde shape changes. |
| SARIF projection | SARIF 2.1.0 plus taudit-owned properties and fingerprints documented in the boundary matrix. | Additive taudit-owned `properties` are RC-compatible when documented and covered by conformance parity. | Renaming/removing taudit-owned properties, changing `result.ruleId`, or changing fingerprint semantics is a public output break. SARIF standard shape remains SARIF-owned. | Bump only if the Rust wire surface exported by `taudit-api` changes. |
| CloudEvents | [contracts/schemas/taudit-cloudevent-finding-v1.schema.json](../../../contracts/schemas/taudit-cloudevent-finding-v1.schema.json), CloudEvents `specversion: "1.0"`, one finding per event, schema line `v1`. | Additive extension attributes or `data` fields are RC-compatible when documented, schema-validated, and projected without exceeding ADR 0013. | Renaming/removing extension attributes, changing event type semantics, changing platform token meaning, or changing fingerprint/suppression identity is a public output break and likely needs a new event schema line. | Bump only if event wire types move into or change in `taudit-api`. |
| Exploit graph JSON | [schemas/exploit-graph.v1.json](../../../schemas/exploit-graph.v1.json) with `schema_version: "1.0.0"` and view `exploit`. | Use schema major `1` for additive fields that preserve deterministic projection semantics and the "not proof of exploitability without explicit witness evidence" boundary. | Use `2.0.0` or a new schema line for renamed/removed fields, changed helper/transport/origin enum semantics, changed witness claim strength, or changed projection identity. | Bump only if exploit graph structs are exported or changed in `taudit-api`. |
| Baselines | [schemas/baseline.v1.json](../../../schemas/baseline.v1.json), current schema version pattern `1.x.y`, currently `1.1.0`. | Use `1.x.y` for additive fields such as new capture metadata that old tools can ignore or safely treat as absent. | Use `2.0.0` or a product-major migration for file-shape changes that invalidate existing baselines, locator changes, fingerprint/rule id changes, or gate-outcome semantics that cannot be compatibility-handled. | No bump while baseline structs stay outside `taudit-api`. Bump intentionally if baseline wire types or identity fields are promoted. |
| Suppressions | `.taudit-suppressions.yml` and `.taudit/suppressions.yml` compatibility aliases described in the boundary matrix. | Additive YAML fields are compatible when unknown fields do not weaken waiver review. | Removing public locators, changing downgrade/tag-only semantics, or dropping compatibility aliases is breaking. | No bump unless suppression wire types or identity fields are promoted into `taudit-api`. |
| `taudit-api` Rust crate | `0.4.1` during this RC lane unless L2-02 records a different verdict. | In `0.x`, additive exported serde fields or variants can use a new minor only when the release chooses to publish them. At `1.0`, normal SemVer applies: `1.x` is additive and `2.0` is breaking. | Any breaking exported serde shape, enum, metadata constant, or feature behavior change requires a new minor while `0.x`; after `1.0`, it requires a major. | `1.0` promotion is deferred until docs.rs build, compatibility review, exported type diff, conformance harness, and release notes pass. |

## Changelog Agreement

The `v1.2.0-rc.1` changelog entry must classify each public contract delta as
one of:

- `unchanged`: emitted contract and exported API shape did not change.
- `additive`: current major stays valid and old consumers can ignore the new
  fields.
- `breaking`: consumers must migrate, a new schema line or major is required,
  or `taudit-api` needs an intentional version bump.
- `deferred`: decision is not shipped in this RC and must not be advertised as
  stable.

The changelog must name the product version, the `taudit-api` version decision,
schema version decisions, and whether identity, fingerprint, suppression,
baseline, CloudEvents, SARIF, or exploit graph semantics changed.

## RC Gate

Before L2-12 is considered complete:

- This document and [public-contract-boundary.md](public-contract-boundary.md)
  must agree on every surface classification.
- ADR 0020 conformance must prove current-output examples for graph JSON,
  report JSON, SARIF, CloudEvents, exploit graph, and reference consumers, or
  the release notes must explicitly mark the missing proof as deferred.
- `taudit-api` must either stay `0.4.1` with an explicit no-exported-delta
  statement, move to a prerelease minor with migration notes, or remain deferred
  for later `1.0` promotion.
- Stable `v1.2.0` promotion must wait for the latest RC to clear release gates
  without new semantic payload that would require another RC.

## Residual Risk

This is documentation, not a schema or implementation change. It does not prove
that the changelog has already been updated, that `taudit-api` is ready for
`1.0`, or that ADR 0020 conformance has passed. It gives L1, L2, L5, and QA the
single wording surface they need to make those later checks mechanical.
