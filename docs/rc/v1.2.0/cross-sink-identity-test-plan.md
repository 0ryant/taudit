# Cross-Sink Identity Test Plan

Status: L5-01 focused parity coverage added for `suppression_key` and
`finding_group_id`.

## Field Map

| Identity | JSON | SARIF | CloudEvents |
| --- | --- | --- | --- |
| Rule id | `findings[].rule_id` | `runs[].results[].ruleId` | `tauditruleid` |
| Fingerprint | `findings[].fingerprint` | `runs[].results[].partialFingerprints.primaryLocationLineHash` | `tauditfindingfingerprint` |
| Suppression key | `findings[].suppression_key` | `runs[].results[].properties.suppressionKey` | `tauditsuppressionkey` |
| Finding group id | `findings[].finding_group_id` | `runs[].results[].properties.findingGroupId` | `tauditfindinggroup` |

## Coverage

- `crates/taudit-cli/tests/cross_sink_contract.rs` now extracts all four
  identity fields from JSON, SARIF, and CloudEvents using the field names
  above.
- `suppression_keys_match_across_all_three_sinks` asserts byte-identical
  `suppression_key` projection for the built-in and custom-rule fixture
  findings.
- `finding_group_ids_match_across_all_three_sinks` asserts byte-identical
  `finding_group_id` projection for both fixture findings.
- The fixture keeps one built-in finding with an auto-derived
  `finding_group_id` and one custom-rule finding with an explicit
  `finding_group_id`, so the test covers derived emission and preservation of
  a caller-supplied group id.
- The existing markdown rendering contract still asserts fingerprint parity
  after sink-specific SARIF sanitization.

## Gaps And Boundaries

No sink gap was observed for `suppression_key` or `finding_group_id`, so no
ignored or expected-failing test was added.

This plan does not claim full L5-08 suppression metadata coverage. Matched
suppression behavior, suppression-mode effects, baseline lookup, and fields
such as `suppressed`, `original_severity`, and `suppression_reason` remain
separate L5-07/L5-08 scope.

## Verification

Required gate:

```text
cargo test -p taudit --test cross_sink_contract
```
