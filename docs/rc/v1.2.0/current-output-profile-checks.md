# Current Output Profile Checks

Wave 8A adds an offline L2-07 checker for the stricter
[current output profile](current-output-profile.md). It does not change
compatibility schemas and does not generate artifacts. It validates checked-in
JSON examples or release fixtures that were produced by other lanes.

## Command

Run the checker with one or more artifact paths:

```bash
python scripts/current_output_profile_check.py \
  --report-json contracts/examples/over-privileged-report.json \
  --cloudevent-json contracts/examples/over-privileged-finding.cloudevent.json \
  --format json
```

Supported artifact flags:

- `--report-json`
- `--cloudevent-json`
- `--sarif-json` or `--sarif`
- `--exploit-graph-json`
- `--baseline-json`

Each flag can be repeated. CloudEvents can be a single JSON object, a JSON
array, or JSONL.

## Status And Exit Codes

The JSON receipt uses schema `taudit.current-output-profile-check.v1`.

| Status | Exit | Meaning |
| --- | ---: | --- |
| `pass` | 0 | All supplied artifacts satisfy the implemented current-profile checks. |
| `fail` | 1 | A promised current-profile field is missing, malformed, forbidden, or mismatched. |
| `incomplete` | 3 | No failures were found, but a known current-profile dependency is still pending. |

`fail` wins over `incomplete` when both failure and pending issues are present.
This lets release tooling distinguish stale examples from bounded not-yet-wired
dependencies.

## Implemented Checks

Report JSON checks include:

- `schema_version == "1.0.0"` and the canonical `schema_uri`;
- graph source, dense node and edge ids, graph completeness, and summary
  completeness;
- finding identity fields: `rule_id`, `source`, `fingerprint`,
  `suppression_key`, and `finding_group_id`;
- format checks for fingerprint, suppression key, and finding group UUID;
- suppression metadata coherence when suppression fields are present;
- ADR 0013 default-output ceiling scans for forbidden public fields;
- pending status when findings exist but no `ordered_authority_evidence` field
  is present.

CloudEvents checks include:

- CloudEvents 1.0 envelope fields and taudit provenance extensions;
- identity extensions for rule id, fingerprint, suppression key, and finding
  group;
- completeness extension handling, including typed gap labels for partial or
  unknown graphs;
- public `data` payload basics and the same forbidden-field scan.

SARIF checks include:

- SARIF `version == "2.1.0"`;
- driver rule entries for each emitted `result.ruleId`;
- `primaryLocationLineHash` and `taudit/v1` fingerprints;
- taudit suppression and finding-group properties.

Exploit graph checks include:

- version, schema URI, `view == "exploit"`, source, paths, and summary;
- per-path helper, authority transport, origin, node, and edge fields;
- observed evidence gating. Use `--allow-observed-evidence` only for explicit
  observed-evidence fixtures.

Baseline checks include:

- baseline schema major `1.x.y`;
- pipeline content and identity-material hash format;
- finding fingerprint, rule id, severity, and first-seen fields;
- critical waiver metadata when a critical severity override is present.

When two or more machine-output surfaces are supplied, the checker compares
`rule_id`, `fingerprint`, `suppression_key`, and `finding_group_id` by finding
index across report JSON, SARIF, and CloudEvents.

## Current Evidence

The checked-in CloudEvents example currently satisfies the implemented
CloudEvents profile checks. The checked-in report example is intentionally still
treated as stale by this checker because it lacks the stricter current-profile
identity fields and `schema_uri`. L2-08 owns refreshing examples from real
fixtures.

## Residual Risk

The checker is an offline validator. It proves only the supplied artifacts, not
the commands that generated them. It also does not replace compatibility schema
validation. ADR 0020 should run schema validation first and this current-profile
checker second.

Terminal verbose output remains outside this JSON checker and should stay
regex-based over `--no-color --verbose` output as described in
[current-output-profile.md](current-output-profile.md).

## Next Dependency Unblocked

L2-08 can now refresh current-output examples against a concrete failure mode,
and QA-04/ADR 0020 can wire the checker as the second pass after schema
validation without changing the compatibility schemas.
