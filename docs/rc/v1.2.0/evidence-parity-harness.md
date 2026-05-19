# L5-02 Evidence Parity Harness

Status: offline parity harness wired into ADR 0020 for `v1.2.0-rc.1`.

This lane adds a Python-only harness for saved output fixtures. The harness
does not generate fixtures itself; ADR 0020 now generates report JSON, SARIF,
and CloudEvents fixtures and then runs this parity check over them.

## Scope

`scripts/output_evidence_parity.py` compares public identity and evidence key
presence across three saved payloads:

- taudit report JSON;
- SARIF 2.1.0 JSON;
- CloudEvents finding output, either one JSON object, a JSON array, or JSONL.

It is intentionally a fixture checker. It does not execute taudit, validate
schemas, compare rendered terminal output, or prove every evidence value is
byte-identical. ADR 0020 owns generated fixture creation, while Rust cross-sink
tests continue to own value parity for identity fields.

## Compared Fields

Identity fields are current-output obligations. Missing or divergent presence
is a failure.

| Canonical field | JSON | SARIF | CloudEvents |
| --- | --- | --- | --- |
| `rule_id` | `findings[].rule_id` | `runs[].results[].ruleId` | `tauditruleid` |
| `fingerprint` | `findings[].fingerprint` | `partialFingerprints.primaryLocationLineHash` and `partialFingerprints["taudit/v1"]` | `tauditfindingfingerprint` |
| `suppression_key` | `findings[].suppression_key` | `properties.suppressionKey` | `tauditsuppressionkey` |
| `finding_group_id` | `findings[].finding_group_id` | `properties.findingGroupId` | `tauditfindinggroup` |

Public evidence extras are optional per finding, but if any saved sink emits a
key the same key must also be present on the other saved sinks for that finding.

| Canonical field | JSON | SARIF | CloudEvents |
| --- | --- | --- | --- |
| `confidence_scope` | `findings[].confidence_scope` | `properties.confidenceScope` | `data.confidence_scope` |
| `runtime_preconditions` | `findings[].runtime_preconditions` | `properties.runtimePreconditions` | `data.runtime_preconditions` |
| `portal_control_dependency` | `findings[].portal_control_dependency` | `properties.portalControlDependency` | `data.portal_control_dependency` |
| `authority_kinds` | `findings[].authority_kinds` | `properties.authorityKinds` | `data.authority_kinds` |
| `attacker_surface_kinds` | `findings[].attacker_surface_kinds` | `properties.attackerSurfaceKinds` | `data.attacker_surface_kinds` |
| `template_resolution_strength` | `findings[].template_resolution_strength` | `properties.templateResolutionStrength` | `data.template_resolution_strength` |
| `time_to_fix` | `findings[].time_to_fix` | `properties.timeToFix` | `data.time_to_fix` |
| `compensating_controls` | `findings[].compensating_controls` | `properties.compensatingControls` | `data.compensating_controls` |
| `ordered_authority_evidence` | `findings[].ordered_authority_evidence` | `properties.ordered_authority_evidence` | `data.ordered_authority_evidence` |

`ordered_authority_evidence` is special: absence across all sinks reports
`pending`, not `pass`, because the public field is frozen in
[ordered evidence wire fields](ordered-evidence-wire-fields.md) but not wired
through every production sink yet.

## Command

```powershell
python scripts/output_evidence_parity.py `
  --json-report path\to\report.json `
  --sarif path\to\report.sarif `
  --cloudevents path\to\events.jsonl `
  --format json
```

Exit codes:

- `0`: all configured presence checks pass;
- `1`: at least one fixture load, shape, count, or parity check failed;
- `3`: no failures, but one or more evidence checks remain pending.

The JSON output uses `report_kind = "taudit.output_evidence_parity"` and
includes per-check ids, surface presence booleans, and pass/pending/fail counts.

## Verification

Focused tests live in
[`tests/test_output_evidence_parity.py`](../../../tests/test_output_evidence_parity.py).
They cover:

- pending status when `ordered_authority_evidence` is absent everywhere;
- pass status when identity and evidence key presence matches across all three
  saved sinks;
- fail status when a public evidence key is present in JSON/SARIF but absent in
  CloudEvents;
- CLI JSON output and exit code `3` for pending gaps.

## Residual Risk

This harness currently compares key presence, not field values or full object
equivalence. The ADR 0020 gate accepts `ordered_authority_evidence` absence only
as the documented RC deferral. L5-02 remains incomplete for the ordered-evidence
claim until generated current-output fixtures include a positive
helper-authority finding with `ordered_authority_evidence` across JSON, SARIF,
CloudEvents, and terminal verbose output.

## Next Dependency Unblocked

QA-04 and ADR 0020 release wiring can now distinguish real fixture drift from
the known ordered-evidence implementation gap. Once L4/L5 emit the ordered
object, this harness should flip from documented deferral handling to positive
cross-sink presence checks.
