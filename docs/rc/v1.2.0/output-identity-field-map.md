# v1.2.0-rc.1 Output Identity Field Map

Status: L2-04 field definition from [ADR 0012](../../adr/0012-public-output-identity-contract.md).

This document is the public RC map for finding identity and provenance fields. It does not freeze behavior by itself. Current/proven means the repo already has schema or test evidence for the field; pending means a downstream L5 or QA gate must still prove parity or current-profile readiness before release claims can depend on it.

Reporters and sinks only project identity. Core and `taudit-api` own meaning. Reporter sanitization must not affect identity inputs: terminal control-byte stripping, SARIF markdown escaping, and any future display-only rewriting happen after `rule_id`, `fingerprint`, `suppression_key`, and `finding_group_id` have been computed.

## Status Legend

| Status | Meaning |
| --- | --- |
| Current/proven | Existing output and tests already prove the named cross-sink identity claim. |
| Current/observed | Existing schemas or sink code expose the field, but parity or conformance gates still need to pin it. |
| Pending | Field is part of the RC contract target, but projection, parity, or drift cleanup remains downstream. |
| Non-projected | The sink intentionally has no current field; downstream work must either add one or document the non-projection. |

## Field Map

### `rule_id`

| Aspect | Contract |
| --- | --- |
| Canonical owner | L4 core owns `rule_id_for`; `taudit-api` owns the public `FindingCategory` and `FindingSource` wire types; L5 reporters project the value. |
| JSON field | `findings[].rule_id`; baselines also record `baseline_findings[].rule_id`; suppression entries require `rule_id` for operator review. |
| SARIF projection | `runs[].results[].ruleId`. |
| CloudEvents projection | `tauditruleid` extension attribute. `type` remains category-scoped routing, not the exact rule id. |
| Terminal verbose projection | Current: rendered on the verbose `Identity:` line as `rule_id`. Custom-rule messages may also include the bracketed id in rendered prose. |
| Baseline/suppression role | Stored with baseline and suppression records for display, audit, and mismatch diagnosis. Lookup is by `fingerprint` or `suppression_key`, not by rule id alone. |
| Stability semantics | Snake_case built-in id, or custom invariant id when the message starts with a valid `[id]` prefix. Renaming a public id changes identity and needs migration/release notes. |
| Current/pending status | Current/proven for JSON, SARIF, CloudEvents, and terminal verbose by `cross_sink_contract.rs`, terminal reporter tests, and ADR 0020. |

### `fingerprint`

| Aspect | Contract |
| --- | --- |
| Canonical owner | L4 core owns `compute_fingerprint`; `taudit-api` owns the graph and finding wire inputs; L5 reporters project the computed value. |
| JSON field | `findings[].fingerprint`. |
| SARIF projection | `runs[].results[].partialFingerprints.primaryLocationLineHash` and `runs[].results[].partialFingerprints["taudit/v1"]`. |
| CloudEvents projection | `tauditfindingfingerprint` extension attribute. |
| Terminal verbose projection | Current: rendered on the verbose `Identity:` line as `fingerprint`. |
| Baseline/suppression role | Precise dedup identity. It is the per-finding baseline key and one accepted `.taudit-suppressions.yml` locator. `--dedupe-against` also reads CloudEvents `tauditfindingfingerprint`. |
| Stability semantics | v3 is 32 lowercase hex chars: SHA-256 truncated to 128 bits. Inputs are rule id, normalized scanned file path, category, root authority, ordered involved-node names, and `extras.fingerprint_anchor`. It is insensitive to wall-clock time, taudit version within the line, host/cwd, display message text, and reporter sanitization. |
| Current/pending status | Current/proven across JSON, SARIF, CloudEvents, baseline material, terminal verbose, and existing fingerprint docs. |

### `suppression_key`

| Aspect | Contract |
| --- | --- |
| Canonical owner | L4 core owns `compute_suppression_key`; L5 reporters project the computed value. |
| JSON field | `findings[].suppression_key`. |
| SARIF projection | `runs[].results[].properties.suppressionKey`. |
| CloudEvents projection | `tauditsuppressionkey` extension attribute. |
| Terminal verbose projection | Current: rendered on the verbose `Identity:` line as `suppression_key`. |
| Baseline/suppression role | Stable waiver identity for `.taudit-suppressions.yml`; critical-waiver expiry validation checks both `fingerprint` and `suppression_key`. Baselines currently key entries by `fingerprint`, not by `suppression_key`. |
| Stability semantics | `sk1_` plus 32 lowercase hex chars. Inputs preserve rule, scanned file path, category, root authority, and `extras.fingerprint_anchor`, but deliberately exclude ordered involved-node names so reviewed waivers can survive unrelated topology edits. |
| Current/pending status | Current/proven for JSON, SARIF, CloudEvents, and terminal verbose equality by the L5-01 cross-sink contract tests, terminal reporter tests, and ADR 0020. L5-07/L5-08 still own matched suppression behavior, expiry, downgrade/tag-only modes, and metadata survival when human output hides a finding. |

### `finding_group_id`

| Aspect | Contract |
| --- | --- |
| Canonical owner | L4 core owns `compute_finding_group_id`; JSON/SARIF/CloudEvents reporters derive it from `fingerprint` when the finding did not already carry one. |
| JSON field | `findings[].finding_group_id`. |
| SARIF projection | `runs[].results[].properties.findingGroupId`. |
| CloudEvents projection | `tauditfindinggroup` extension attribute. |
| Terminal verbose projection | Current: rendered on the verbose `Identity:` line as `finding_group_id`. |
| Baseline/suppression role | Grouping and collapse key for SIEMs and dashboards. It is not a baseline key and not a suppression locator. |
| Stability semantics | UUID v5 over the finding `fingerprint` in a fixed namespace. Same fingerprint means same group id; changed fingerprint means changed group id. Namespace changes are major-version breaks. |
| Current/pending status | Current/proven for JSON, SARIF, CloudEvents, and terminal verbose equality by the L5-01 cross-sink contract tests, terminal reporter tests, and ADR 0020. Suppression/baseline behavior remains separate L5-07/L5-08 work. |

### Platform Token

| Aspect | Contract |
| --- | --- |
| Canonical owner | CLI platform resolution and graph metadata population own the emitted token; `taudit-api` owns graph metadata as public wire shape; CloudEvents owns the extension projection. |
| JSON field | `graph.metadata.platform` when stamped. Current CLI behavior preserves parser-stamped metadata; observed parser tokens include long forms such as `github-actions` and `azure-devops` as well as `gitlab`. The JSON schema allows string metadata values, so token spelling is a current-output drift concern rather than a schema failure. |
| SARIF projection | Non-projected today as a taudit-owned identity field. L5 must either add a SARIF property or document the non-projection. |
| CloudEvents projection | `tauditplatform` extension attribute. Current schema accepts `ado`, `bb`, `bitbucket`, `gha`, and `gitlab`; current sink code only forwards those short tokens when the graph metadata already uses them. Parser-stamped long tokens such as `github-actions` and `azure-devops`, plus Bitbucket token spelling, need L5-06 normalization or explicit non-projection documentation. |
| Terminal verbose projection | Current: no dedicated platform token. |
| Baseline/suppression role | Not a waiver locator. Platform selection affects graph construction, which can affect identity inputs indirectly. Consumers must not suppress by platform token alone. |
| Stability semantics | Once emitted, token spelling is public output. Renaming short tokens or switching between `bb` and `bitbucket` is a compatibility break unless explicitly versioned. |
| Current/pending status | Pending. L5-06 must reconcile parser-stamped long tokens, schema short tokens, sink forwarding, docs, event type, and Bitbucket behavior; QA-04 must include platform projection only after the current token contract is explicit. |

### Scanned Source File Identity

| Aspect | Contract |
| --- | --- |
| Canonical owner | `taudit-api` owns `PipelineSource`; parsers and CLI populate `graph.source.file`; L4 consumes it in fingerprint and suppression-key input. |
| JSON field | `graph.source.file`; optional source context may also include `graph.source.repo` and `graph.source.git_ref`. |
| SARIF projection | `runs[].results[].locations[0].physicalLocation.artifactLocation.uri`, with `uriBaseId` set to `%SRCROOT%`. |
| CloudEvents projection | `subject` carries the scanned pipeline file path. `tauditpipelineid` is separate scan provenance, not the path itself. |
| Terminal verbose projection | Current terminal header renders `Authority Graph: ` followed by the scanned file path after terminal-only control-byte sanitization. |
| Baseline/suppression role | `graph.source.file` is part of `fingerprint` and `suppression_key` identity input after slash normalization. Baseline file lookup is content-hash-keyed, but finding-level baseline matching remains fingerprint-keyed. |
| Stability semantics | Path separators normalize to `/` for identity. The path is not collapsed to a basename. Display sanitization must not feed back into identity input. |
| Current/pending status | Current/observed across JSON, SARIF, CloudEvents, and terminal. Current-profile parity remains a QA-04/L2-07 concern. |

### Finding Source Provenance

| Aspect | Contract |
| --- | --- |
| Canonical owner | `taudit-api` owns `FindingSource`; custom-rule loading owns `source_file` population; reporters project provenance so operators can distinguish built-in findings from custom invariant findings. |
| JSON field | `findings[].source`: `"built-in"` or `{ "custom": { "source_file": "rules/my_rule.yml" } }` per the report schema shape. |
| SARIF projection | `runs[].results[].properties["taudit-source"]`: `built-in` or a `custom:` prefix followed by the custom rule source-file path. |
| CloudEvents projection | Current: carried inside the `data` finding payload; no dedicated CloudEvents extension attribute. |
| Terminal verbose projection | Current terminal output omits built-in provenance and shows custom findings as a sanitized `custom:` tag with the custom rule file basename. |
| Baseline/suppression role | Not a baseline key and not a suppression locator. It is provenance for trust and triage. |
| Stability semantics | Do not join findings by custom source path. It is source provenance, not finding identity. Terminal basename shortening and sanitization are display-only. |
| Current/pending status | Current/observed, with CloudEvents extension non-projection to remain explicit if no L5 projection is added. |

### Scan Provenance

| Aspect | Contract |
| --- | --- |
| Canonical owner | CloudEvents sink owns scan-run and correlation identifiers; graph/report schemas own source and metadata context. |
| JSON field | No taudit-report scan-run id today. Report context is `schema_version`, `schema_uri`, `graph.source`, and graph metadata such as `graph.metadata.platform`. |
| SARIF projection | No taudit-owned scan-run id today. Standard SARIF run/tool metadata exists outside this field map. |
| CloudEvents projection | `correlationid`, `tauditpipelineid`, and `tauditscanrunid`. |
| Terminal verbose projection | No stable scan id today. |
| Baseline/suppression role | Not a waiver locator. `tauditpipelineid` can correlate pipeline-content identity, but suppressions and baselines still match findings by `fingerprint` or `suppression_key` according to their contracts. |
| Stability semantics | `tauditpipelineid` is stable for the pipeline identity material used by the sink; `tauditscanrunid` is per sink emission/invocation; `correlationid` is the operator-flow join key. None of these values may feed fingerprint or suppression-key computation. |
| Current/pending status | Current/observed for CloudEvents only. JSON/SARIF/terminal are non-projected unless downstream L5 work adds explicit fields. |

### Event Provenance

| Aspect | Contract |
| --- | --- |
| Canonical owner | CloudEvents sink and CloudEvents schema own event envelope provenance. |
| JSON field | Non-projected in `taudit-report` JSON. |
| SARIF projection | Non-projected as a taudit event envelope. |
| CloudEvents projection | `id`, `source`, `type`, `time`, `provenancerepo`, `provenanceproducer`, `provenanceversion`, and `provenancekind`. |
| Terminal verbose projection | Non-projected. |
| Baseline/suppression role | No baseline or suppression role. These values are event transport provenance, not finding identity. |
| Stability semantics | `id` and `time` are event-volatile. `source` is currently `taudit`. `type` is category-scoped routing, while exact rule identity is `tauditruleid`. Producer/version fields describe the emitter and must not participate in finding identity. |
| Current/pending status | Current/observed in CloudEvents schema and sink code. Event type documentation drift remains in L5-06 before RC readiness. |

## Downstream Acceptance Gates

| Gate | Acceptance required by this map |
| --- | --- |
| L5-01 | Cross-sink contract tests prove byte-identical `rule_id`, `fingerprint`, `suppression_key`, and `finding_group_id` across JSON, SARIF, and CloudEvents. Remaining identity breadth work is fixture variety and interaction with suppression/baseline behavior, not basic field parity. |
| L5-07 | Implement ADR 0018 table-driven CLI tests for scan, verify, baseline new-only/gate-on-all, severity threshold, dedupe, downgrade, tag-only/compat suppress mode, expired/unmatched waivers, critical waivers, `--show-all`, `--ignore-partial`, and exit codes `0`, `1`, and `2`. |
| L5-08 | Prove suppression metadata survives every machine sink even when human output hides, downgrades, or tags a finding. Required fields include `fingerprint`, `suppression_key`, `rule_id`, `suppressed`, `original_severity`, and `suppression_reason` where applicable. |
| QA-04 | Contract tests pass for report JSON, CloudEvents, SARIF, cross-sink identity, and exploit graph outputs. If platform, provenance, or source-file fields are claimed current, QA-04 must validate their schemas and current-profile examples too. |

## Compatibility Notes

- `rule_id`, `fingerprint`, `suppression_key`, and `finding_group_id` now have focused JSON/SARIF/CloudEvents parity coverage.
- `suppression_key` and `finding_group_id` still need broader suppression/baseline behavior coverage before docs can claim the full ADR 0018 waiver story.
- Platform token readiness is intentionally pending because parser-stamped metadata, schema short tokens, sink forwarding, and Bitbucket token projection are not yet one contract.
- Sanitized terminal or SARIF display strings are never identity inputs. Identity uses canonical core inputs before any sink-specific rendering boundary.
