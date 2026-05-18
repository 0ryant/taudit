# v1.2.0-rc.1 CloudEvents Projection Map

Status: L5-04/L5-06 CloudEvents projection and drift closeout.

This map records which public finding and event fields are projected by
`taudit-sink-cloudevents`, where they appear, and which values are intentionally
not projected. It is the RC reference for CloudEvents-specific findability,
identity, platform-token, and extras behavior.

## Event Envelope

| Contract field | CloudEvents projection | Status |
| --- | --- | --- |
| CloudEvents version | `specversion = "1.0"` | Emitted and schema-validated. |
| Event id | `id` UUID v4 per event | Emitted; volatile by design. |
| Source | `source = "taudit"` | Emitted and schema-validated. |
| Event type | `type = "io.taudit.finding.<category>"` | Category-scoped routing. Exact rule identity is `tauditruleid`, including custom rule ids. |
| Subject | `subject = graph.source.file` | Scanned pipeline path; not an identity hash. |
| Content type | `datacontenttype = "application/json"` | Emitted for finding payloads. |
| Event time | `time` RFC 3339 timestamp | Emitted; volatile by design. |
| Correlation id | `correlationid` | One operator-flow join key, constructor/env supplied or UUID fallback. |
| Pipeline id | `tauditpipelineid` | Stable `urn:taudit:pipeline:sha256:<64-hex>` from metadata or deterministic graph material. |
| Scan run id | `tauditscanrunid` | One per sink `emit` call, constructor/env supplied or UUID fallback. |
| Provenance | `provenancerepo`, `provenanceproducer`, `provenanceversion`, `provenancekind` | Emitted as event transport provenance, not finding identity. |

## Identity Extensions

| Public identity | Projection | Notes |
| --- | --- | --- |
| `rule_id` | `tauditruleid` | Byte-identical to JSON `findings[].rule_id` and SARIF `result.ruleId`. |
| `fingerprint` | `tauditfindingfingerprint` | 32 lowercase hex; byte-identical to JSON and SARIF fingerprint fields. |
| `suppression_key` | `tauditsuppressionkey` | `sk1_` plus 32 lowercase hex; waiver identity, not event id. |
| `finding_group_id` | `tauditfindinggroup` | UUID v5 over the fingerprint unless a finding supplies an explicit group id. |
| Graph completeness | `tauditcompleteness` plus optional `tauditcompletenessgaps` | `tauditcompletenessgaps` is emitted only when typed gap entries exist. |

## Platform Token

`tauditplatform` is emitted only when `graph.metadata["platform"]` is present
and recognized. The sink normalizes parser and CLI forms into the public token:

| Input metadata token | Emitted token |
| --- | --- |
| `github-actions`, `gha` | `gha` |
| `azure-devops`, `ado` | `ado` |
| `gitlab`, `gitlab-ci` | `gitlab` |
| `bitbucket`, `bb`, `bitbucket-pipelines` | `bitbucket` |

Unknown platform metadata is omitted rather than forwarded.

## Finding Data Payload

`data` is the public finding payload. It preserves the structured `Finding`
fields and public safe extras when present:

| Public field or extra | Projection |
| --- | --- |
| `severity`, `category`, `path`, `nodes_involved`, `message`, `recommendation`, `source` | `data.<field>` |
| `finding_group_id` | `data.finding_group_id` when supplied by the finding; `tauditfindinggroup` is always the event-level grouping key. |
| `time_to_fix` | `data.time_to_fix` |
| `compensating_controls` | `data.compensating_controls` |
| `suppressed`, `original_severity`, `suppression_reason` | `data.<field>` |
| `confidence_scope` | `data.confidence_scope` |
| `runtime_preconditions` | `data.runtime_preconditions` |
| `portal_control_dependency` | `data.portal_control_dependency` |
| `authority_kinds` | `data.authority_kinds` |
| `attacker_surface_kinds` | `data.attacker_surface_kinds` |
| `template_resolution_strength` | `data.template_resolution_strength` |
| `cve_relationship` | `data.cve_relationship` |

## Non-Projected

| Field or claim | Reason |
| --- | --- |
| `fingerprint_anchor` | Identity input only. Its effect is already captured in `tauditfindingfingerprint` and `tauditsuppressionkey`; it is scrubbed from CloudEvents `data`. |
| Disclosure score, disclosure route, CVE workflow state, witness-spec next action | Internal-gated by the output ceiling and absent from default/public CloudEvents. |
| Private hosted-run artifacts, canary values, private source anchors | Internal-gated or forbidden/default-absent. |
| Observed sink claims without explicit observed evidence input | Forbidden/default-absent; static or inferred evidence must not be upgraded to observed behavior. |

## Verification Surface

Current focused checks live in
[`crates/taudit-sink-cloudevents/src/lib.rs`](../../../crates/taudit-sink-cloudevents/src/lib.rs):

- `platform_metadata_normalizes_parser_tokens_to_public_tokens`
- `data_payload_projects_public_safe_extras_and_omits_fingerprint_anchor`
- `checked_in_example_contains_current_identity_and_platform_fields`
- `emitted_event_matches_cloudevent_schema`
- `checked_in_example_matches_cloudevent_schema`
- `every_finding_category_variant_validates_against_cloudevent_schema`

Downstream dependency unblocked: QA-04 can treat CloudEvents event identity,
platform token behavior, category-scoped event type, suppression/group identity,
and public safe finding extras as explicitly mapped for current-profile checks.
