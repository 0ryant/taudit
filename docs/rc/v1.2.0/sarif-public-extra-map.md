# SARIF Public Extra Map

Status: L5-03 projection map for the current v1.2.0 RC profile.

Source decisions:

- [output identity field map](output-identity-field-map.md)
- [output ceiling matrix](output-ceiling-matrix.md)
- [ordered evidence wire fields](ordered-evidence-wire-fields.md)

This file maps every currently public finding extra, identity field, and
evidence-safe field to SARIF 2.1.0 output, or records an intentional
non-projection. It does not promote internal witness, disclosure, canary, or
private hosted-run fields.

## Projected Fields

| Public field | SARIF projection | Notes |
| --- | --- | --- |
| `rule_id` | `runs[].results[].ruleId` | Emitted as the SARIF result field commonly described as `result.ruleId`. |
| `fingerprint` | `runs[].results[].partialFingerprints.primaryLocationLineHash` and `runs[].results[].partialFingerprints["taudit/v1"]` | Both values are byte-identical for the v1 fingerprint line. |
| `suppression_key` | `runs[].results[].properties.suppressionKey` | Operator-stable waiver key with `sk1_` prefix. |
| `finding_group_id` | `runs[].results[].properties.findingGroupId` | Preserves an existing extra or derives the group id from the computed fingerprint. |
| `source` | `runs[].results[].properties["taudit-source"]` | `built-in` for shipped rules; `custom:<path>` for invariant files. The scanned file is separately projected as `runs[].results[].locations[].physicalLocation.artifactLocation.uri`. |
| `time_to_fix` | `runs[].results[].properties.timeToFix` | Values: `trivial`, `small`, `medium`, `large`. |
| `compensating_controls` | `runs[].results[].properties.compensatingControls` | Public control labels that explain a downgrade or neutralizing condition. |
| `suppressed` | `runs[].results[].properties.suppressed` | Public suppression state for consumers that read taudit-owned properties. |
| `original_severity` | `runs[].results[].properties.originalSeverity` | Pre-downgrade severity when a suppression or compensating control changed severity. |
| `suppression_reason` | `runs[].results[].properties.suppressionReason` | Operator-supplied public justification from the matched suppression entry. |
| `confidence_scope` | `runs[].results[].properties.confidenceScope` | Current built-in findings commonly use `yaml_only`. |
| `runtime_preconditions` | `runs[].results[].properties.runtimePreconditions` | Public assumptions that must hold before treating a static finding as live exploitability. |
| `portal_control_dependency` | `runs[].results[].properties.portalControlDependency` | True when exploitability depends on provider-side controls outside the scanned YAML. |
| `authority_kinds` | `runs[].results[].properties.authorityKinds` | Coarse public authority labels such as token, secret, OIDC, service connection, artifact, or image. |
| `attacker_surface_kinds` | `runs[].results[].properties.attackerSurfaceKinds` | Coarse public attacker-surface labels such as mutable dependency refs or script sinks. |
| `template_resolution_strength` | `runs[].results[].properties.templateResolutionStrength` | Public reusable-workflow or template resolution strength. |
| `cve_relationship` | `runs[].results[].properties.cveRelationship` | Relationship to cited advisory classes. This is not a CVE claim. |

## Non-Projected

| Public or candidate field | SARIF decision | Reason |
| --- | --- | --- |
| `fingerprint_anchor` | Non-projected | The raw anchor is consumed by `fingerprint` and `suppression_key` identity computation. Emitting it again would create a second quasi-identity field without adding SARIF triage value. |
| `ordered_authority_evidence` | Deferred until the field exists on public findings | [ordered evidence wire fields](ordered-evidence-wire-fields.md) requires the object to project as `runs[].results[].properties.ordered_authority_evidence` once L2-03/L4 wire it into findings. L5-03 does not invent a placeholder object. |
| `disclosure_score`, disclosure route, CVE workflow state, witness-spec next actions, canary values, private run ids, private log URLs, private source anchors | Non-projected | These are internal-gated or forbidden/default-absent by the output ceiling matrix. Public SARIF must not emit them by default. |

## Test Evidence

`cargo test -p taudit-report-sarif sarif_` covers the current map by asserting
that public extras render into `result.properties`, that `fingerprint_anchor`
does not render raw, and that this document names every projection decision.
