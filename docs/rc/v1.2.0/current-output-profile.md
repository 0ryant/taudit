# Current Output Profile

This document defines the L2-07 current-output profile for
`v1.2.0-rc.1`. It turns [ADR 0017](../../adr/0017-current-output-profile-and-contract-examples.md)
into a concrete validation target without changing compatibility schemas or
examples in this lane.

Related decisions and lanes:

- [ADR 0012](../../adr/0012-public-output-identity-contract.md) defines public
  identity: `rule_id`, `fingerprint`, `suppression_key`,
  `finding_group_id`, platform token, source identity, scan provenance, and
  event provenance when a sink supports them.
- [ADR 0013](../../adr/0013-evidence-rendering-and-output-ceiling.md) defines
  public evidence fields and the default-output ceiling.
- [L2-03](code-complete-lanes.md#l2-api-schemas-contracts) owns the
  `ordered_authority_evidence` field freeze. Until that lands in code and
  fixtures, ordered evidence is a required pending profile dependency, not a
  current-output claim.
- [ADR 0020](../../adr/0020-output-conformance-harness-and-rc-gate.md) requires
  one output conformance gate before the RC tag.
- [L2-07](code-complete-lanes.md#l2-api-schemas-contracts) owns current-profile
  checks separate from compatibility schema validation.
- [L2-08](code-complete-lanes.md#l2-api-schemas-contracts) owns refreshed
  contract examples from real fixtures.
- [L5-01 through L5-05](code-complete-lanes.md#l5-cli-reports-sinks-output-identity)
  own identity, evidence, SARIF, CloudEvents, and terminal projection.
- [L5-07 and L5-08](code-complete-lanes.md#l5-cli-reports-sinks-output-identity)
  own suppression, baseline, and exit-code matrix coverage.
- [QA-04 and QA-08](code-complete-lanes.md#qa-and-resilience-gates) own contract
  tests and the final release-readiness gate.

## Compatibility Schema Vs. Current Profile

A compatibility schema answers: "Can this document still be accepted by a v1
consumer?" It may keep fields optional so older reports, events, or baselines
continue to validate.

A current-output profile answers: "Does current taudit emit the fields the RC
promises?" It is stricter than the schema. It must fail when a promised current
field disappears, even if the compatibility schema still accepts the document.

For v1.2.0-rc.1, compatibility validation remains schema-based. Current-profile
validation is a second pass over generated fixtures and checked-in examples. It
asserts required current fields, cross-sink equality, conditional suppression
fields, and absence of fields that ADR 0013 keeps outside default output.

## Support Snapshot

| Surface | Already visible in schemas/examples | Pending Wave 2/3 work |
| --- | --- | --- |
| Report JSON | The report schema defines `schema_uri` and finding identity/evidence/suppression fields as optional for compatibility. Checked-in report examples currently contain only the older required finding shape. Runtime snapshots already show `schema_uri`, `rule_id`, `source`, `fingerprint`, `suppression_key`, `finding_group_id`, and public evidence extras. Ordered authority evidence is still pending L2-03/L4/L5 implementation. | L2-07 must make these current-profile assertions. L2-08 must refresh examples from real fixtures. L5-01 already proves basic identity parity; L5-02 must prove evidence parity, including ordered evidence once shipped. |
| CloudEvents | The CloudEvents schema defines envelope/provenance fields and extension attributes for rule, fingerprint, suppression, platform, finding group, pipeline id, scan run id, and completeness. The checked-in CloudEvent example includes provenance, pipeline id, scan run id, completeness, and `tauditruleid`, but lacks fingerprint, suppression key, platform, and finding group. Platform projection is pending because parser-stamped long tokens and schema short tokens are not yet normalized into one current contract. | L5-04/L5-06 must finish mapping and drift checks. L2-08 must refresh examples so current extensions are visible. |
| SARIF | There is no taudit-owned compatibility schema under `contracts/`. SARIF snapshots show `result.ruleId`, `partialFingerprints.primaryLocationLineHash`, `partialFingerprints["taudit/v1"]`, and taudit properties such as `suppressionKey`, `findingGroupId`, `confidenceScope`, `authorityKinds`, and `taudit-source`. | L5-01/L5-03 must make the projection map explicit and test every public finding extra or documented non-projection. |
| Exploit graph JSON | `schemas/exploit-graph.v1.json` is already strict: it requires `schema_version`, `schema_uri`, `view`, `source`, `paths`, `summary`, and per-path rule/helper/transport/origin/node/edge fields. | L2-11 and ADR 0020 must validate empty, positive, downgrade-suppressed, and observed-evidence-disabled cases in the conformance harness. |
| Baselines | `schemas/baseline.v1.json` requires baseline schema version, pipeline identity, capture provenance, and per-finding `fingerprint`, `rule_id`, `severity`, and `first_seen_at`. | L5-07 must prove scan/verify/baseline/threshold/waiver behavior. Current-profile checks should cover baseline files only when a baseline fixture is generated. |
| Suppressions | Finding schemas include `suppressed`, `original_severity`, and `suppression_reason`; docs define `.taudit-suppressions.yml` locators by `fingerprint` or `suppression_key`. Checked-in contract examples do not cover a matched suppression case. | L5-08 must prove suppression metadata survives JSON, SARIF, and CloudEvents even when human output hides or downgrades a finding. |
| Terminal verbose | Terminal code supports verbose node detail: node name, kind, trust zone, identity scope, permissions, digest, and inferred marker. It also surfaces custom-rule source labels. It does not yet expose enough current identity/evidence/suppression detail for ADR 0012. | L5-05 must add readable sanitized verbose rendering for identity, evidence, and suppression fields, then snapshot it. |

## Current-Profile Assertions

### Report JSON

Profile validation must assert:

- root `schema_version == "1.0.0"`;
- root `schema_uri == "https://taudit.dev/schemas/taudit-report.schema.json"`;
- `graph.source.file`, dense `graph.nodes[].id`, dense `graph.edges[].id`,
  `graph.completeness`, and `summary.completeness`;
- for each finding: `severity`, `category`, `nodes_involved`, `message`,
  `recommendation`, `rule_id`, `source`, `fingerprint`, `suppression_key`,
  and `finding_group_id`;
- `fingerprint` is 32 lowercase hex;
- `suppression_key` is `sk1_` plus 32 lowercase hex;
- `finding_group_id` is a UUID;
- public evidence extras appear when the rule emits them:
  `confidence_scope`, `runtime_preconditions`, `portal_control_dependency`,
  `authority_kinds`, `attacker_surface_kinds`,
  `template_resolution_strength`, `time_to_fix`, and
  `compensating_controls`;
- `ordered_authority_evidence` appears when the L2-03/L4 ordered evidence
  model ships; until then, profile validation must keep it pending rather than
  silently passing as absent;
- matched suppression fixtures include `suppressed`,
  `original_severity`, and `suppression_reason` according to the configured
  waiver mode;
- default customer output does not include disclosure score, witness-spec next
  action, canary values, private hosted-run artifacts, or observed sink claims
  without explicit observed evidence input.

### CloudEvents

Profile validation must assert one JSON object per finding with:

- CloudEvents envelope fields: `specversion == "1.0"`, `id`, `source`,
  `type`, `subject`, `datacontenttype == "application/json"`, and `time`;
- taudit event/provenance fields: `correlationid`, `tauditpipelineid`,
  `tauditscanrunid`, `provenancerepo`, `provenanceproducer`,
  `provenanceversion`, and `provenancekind == "finding"`;
- identity extensions: `tauditruleid`, `tauditfindingfingerprint`,
  `tauditsuppressionkey`, and `tauditfindinggroup`;
- `tauditplatform` only after L5-06 defines how parser-stamped long tokens,
  schema short tokens, and Bitbucket aliases normalize into CloudEvents;
- completeness extensions: `tauditcompleteness` and, for partial graphs with
  typed gaps, `tauditcompletenessgaps`;
- `data` carries the public finding payload fields emitted by the sink,
  including suppression metadata when a suppression matched;
- extension identity values are byte-identical to JSON and SARIF projections.

### SARIF

Profile validation must assert:

- SARIF version `2.1.0`;
- one driver rule entry for each emitted `result.ruleId`;
- `result.ruleId` equals JSON `findings[].rule_id` and CloudEvents
  `tauditruleid`;
- `result.partialFingerprints.primaryLocationLineHash` and
  `result.partialFingerprints["taudit/v1"]` exist and equal JSON
  `findings[].fingerprint`;
- `result.properties.suppressionKey` equals JSON `suppression_key` and
  CloudEvents `tauditsuppressionkey`;
- `result.properties.findingGroupId` equals JSON `finding_group_id` and
  CloudEvents `tauditfindinggroup`;
- public evidence fields are projected into SARIF `properties` or explicitly
  listed as non-projected by L5-03;
- ordered authority evidence is projected or explicitly non-projected after
  L2-03/L4 land the field; ADR 0020 must not treat generic evidence extras as
  a substitute for the ordered evidence object;
- matched suppression fixtures include SARIF suppression metadata, including
  `suppressed` and `originalSeverity` where the mode requires them;
- attacker-controlled text is rendered through the SARIF sanitization boundary
  without changing fingerprint inputs.

### Exploit Graph JSON

Profile validation must assert:

- `schema_version == "1.0.0"`;
- `schema_uri == "https://taudit.dev/schemas/exploit-graph.v1.json"`;
- `view == "exploit"`;
- `source.file`, `paths`, and `summary`;
- summary counts: `path_count`, `observed_path_count`, and
  `authority_path_count`;
- for each path: `rule_id`, `umbrella_rule_id`, `rule_scope`,
  `mutable_channel`, `helper`, `helper_resolution`, `authority_transport`,
  `authority_origin`, `nodes`, and `edges`;
- for each edge: `from`, `to`, `kind`, `confidence`, and
  `authority_bearing`;
- `observed == true` appears only when explicit observed evidence input was
  supplied.

### Suppressions And Baselines

Profile validation must assert:

- suppression fixtures can locate findings by `fingerprint` or
  `suppression_key`;
- suppressed or downgraded findings preserve `fingerprint`,
  `suppression_key`, `rule_id`, and `finding_group_id` across JSON, SARIF, and
  CloudEvents;
- `original_severity` records the rule-emitted severity whenever severity is
  changed by suppression or compensating control;
- `suppression_reason` preserves the operator justification in machine
  outputs;
- baseline files validate against `schemas/baseline.v1.json`;
- baseline findings carry `fingerprint`, `rule_id`, `severity`, and
  `first_seen_at`;
- `pipeline_content_hash` and, when present,
  `pipeline_identity_material_hash` are stable hashes with the documented
  `sha256:` prefix;
- critical baseline waivers require the documented waiver fields before they
  stop gating.

### Terminal Verbose

Profile validation must assert terminal verbose mode remains human-readable,
sanitized, and sufficient for triage. It should include:

- graph source file, node counts, completeness, and typed gap labels;
- finding severity, message, path or involved nodes, and recommendation;
- custom-rule provenance when the finding source is custom;
- node detail for involved nodes: name, kind, trust zone, identity scope,
  permissions, digest prefix, and inferred marker when present;
- ADR 0012 identity once L5-05 lands: rule id, fingerprint,
  suppression key, and finding group id;
- public evidence and suppression cues once L5-05 lands, including ordered
  evidence cues after L2-03/L4 make them public, without exposing ADR 0013
  internal-only fields.

Terminal checks should be regex-based over `--no-color --verbose` output so
ANSI styling changes do not create contract churn.

## Future Validation Strategy

The ADR 0020 conformance harness should run schema validation first and
current-profile validation second.

1. Generate fixtures from real CLI commands for complete, partial, suppressed,
   baseline, CloudEvents, SARIF, report JSON, authority graph JSON, and exploit
   graph JSON cases.
2. Validate each machine artifact against its compatibility schema where one
   exists.
3. Validate each artifact against a current-profile manifest. The manifest
   should use JSONPath-like presence checks, regex checks, enum checks, and
   cross-artifact equality checks.
4. Include negative mutation checks that delete promised current fields such as
   `schema_uri`, `fingerprint`, `suppression_key`, `finding_group_id`,
   `tauditfindingfingerprint`, SARIF `suppressionKey`, and
   `ordered_authority_evidence` once it ships; each mutation must fail the
   profile even if the compatibility schema still validates.
5. Validate absence rules for ADR 0013 by injecting or scanning for forbidden
   default-output fields.
6. Gate the profile in the local ADR 0020 recipe and release workflow. Failure
   output must name the surface, fixture, and missing or mismatched field.

Ownership stays split: L2 updates schemas and the profile manifest, L5 refreshes
generated fixtures and sink snapshots, QA wires the profile into the release
gate, and L1 treats a current-profile failure as an RC blocker.

## Next Dependency Unblocked

This design gives L2-07 a concrete field map and lets L2-08 refresh examples
without changing compatibility schemas. It also gives L5-01 through L5-08 and
QA-04 a shared checklist for the conformance harness.

## Residual Risk

This document is a design target, not proof that every field is currently
implemented or projected. It was written from the observed schemas, examples,
snapshots, ADRs, and RC lane docs available during Wave 2. Concurrent workers
may update examples, sinks, or lane docs after this pass; re-run the profile
design check before treating it as release evidence.
