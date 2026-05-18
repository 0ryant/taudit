# Ordered Evidence Wire Fields

Status: design freeze candidate for `v1.2.0-rc.1`.

This document defines the proposed public wire field names for ordered authority
evidence. It does not claim that current code, schemas, examples, SARIF,
CloudEvents, terminal output, or Rust API types already emit these fields.

Source decisions:

- [ADR 0011](../../adr/0011-ordered-authority-evidence-model.md) defines the
  ordered authority evidence model.
- [ADR 0013](../../adr/0013-evidence-rendering-and-output-ceiling.md) defines
  the customer-safe evidence rendering ceiling.
- [L2-03](code-complete-lanes.md#l2-api-schemas-contracts) freezes public
  ordered evidence wire fields.
- [L4-01](code-complete-lanes.md#l4-core-graph-evidence-rules) builds the
  shared ordered event model.
- [L5-02](code-complete-lanes.md#l5-cli-reports-sinks-output-identity) proves
  evidence parity across JSON, SARIF, CloudEvents, and terminal verbose output.

## Public Claim Ceiling

The public ordered evidence surface may claim that taudit found a static or
inferred authority path where earlier mutable helper-resolution state can affect
a later authority-bearing helper invocation.

The public surface may include:

- source facts and inferred path facts;
- event order, job scope, step indexes, helper resolution, authority transport,
  authority origin, authority class, and confidence;
- witness status only as an evidence-strength label;
- same-job caveat text;
- remediation, hardening labels, product labels, and static technical priority
  when separately defined by the output contract.

The public surface must not emit or imply:

- CVE status, disclosure route, disclosure score, or vendor-acceptance
  prediction;
- witness-spec next action, witness command, canary value, private run artifact,
  or private source anchor;
- raw secret values, token payloads, credential file contents, OIDC tokens, or
  generated credential bodies;
- observed sink behavior unless an explicit observed-evidence input supports it;
- internal graph node ids, parser cursor ids, catalog source-scan internals, or
  ad hoc debug traces.

## Public Object Shape

Public sinks should use the nested object name
`ordered_authority_evidence`.

```json
{
  "ordered_authority_evidence": {
    "schema": "taudit.ordered_authority_evidence.v1",
    "scope": {
      "platform": "github-actions",
      "workflow_id": "string",
      "job_id": "string"
    },
    "ordering_invariant": "path_mutation_before_authority_materialization_before_or_at_helper_execution",
    "events": [],
    "predicate": {
      "path_mutation_event_id": "event-path-1",
      "authority_materialization_event_id": "event-auth-1",
      "helper_execution_event_id": "event-helper-1",
      "helper_receives_authority_event_id": "event-transport-1",
      "confidence": "high",
      "same_job_caveat": true
    }
  }
}
```

### Common Event Fields

Every entry in `events` uses these fields.

| Field | Type | Public meaning |
| --- | --- | --- |
| `event_id` | string | Stable id within one finding, exploit path, or emitted evidence object. It is not a global id. |
| `event_kind` | enum string | One of `path_mutation`, `secret_materialized`, `authority_materialized`, `helper_execution`, or `helper_receives_authority`. |
| `job_id` | string | Public job identity used for ordering scope. |
| `step_index` | integer, zero-based | Parser-provided execution order within `job_id`. |
| `step_id` | string or null | Source step id when present. |
| `step_name` | string or null | Source step display name when present and safe to render. |
| `source_location` | object or null | Static source location with `path`, optional `line`, and optional `column`. |
| `evidence_strength` | enum string | `static`, `inferred`, `catalog`, `witness_label`, or `observed`. `observed` requires explicit observed-evidence input. |

`step_index` is the ordering coordinate. `source_location` is explanatory and
must not be used as a substitute for order.

### `PathMutation`

Wire event kind: `path_mutation`.

| Field | Type | Public meaning |
| --- | --- | --- |
| `mutable_channel` | enum string | Mutable helper-resolution channel such as `github_path`, `path_env`, `workspace_path`, `runner_temp`, `toolcache_path`, `shell_env`, or `unknown`. |
| `source_trust_zone` | enum string | Trust zone of the source that can write the mutable channel, using schema/API-backed trust-zone values. |
| `mutation_scope` | enum string | `job`, `step`, `workspace`, `runner`, or `unknown`. |

Public output may say the channel is mutable before later authority is
materialized. It must not emit the attacker-controlled payload, fake helper
body, or canary path.

### `SecretMaterialized` And `AuthorityMaterialized`

Wire event kinds: `secret_materialized` and `authority_materialized`.

Both event kinds share the same public fields. Use `secret_materialized` only
when the evidence is specifically secret materialization; use
`authority_materialized` for broader authority such as OIDC capability,
generated credential file, cloud credential, registry credential, or write
token.

| Field | Type | Public meaning |
| --- | --- | --- |
| `authority_class` | enum string | Class of materialized authority, for example `secret`, `token`, `oidc_request`, `cloud_credential`, `registry_credential`, `credential_file`, or `derived_secret`. |
| `authority_origin` | enum string | Origin such as `caller_provided_secret`, `action_input_secret`, `github_token`, `oidc_request_capability`, `action_minted_cloud_credential`, `action_minted_registry_credential`, `generated_credential_file`, or `derived_secret_payload`. |
| `authority_label` | string or null | Source-level identifier or sanitized class label. Never a secret value. |

Public output may say authority became available at this step. It must not say
the secret value, credential content, or token payload was observed.

### `HelperExecution`

Wire event kind: `helper_execution`.

| Field | Type | Public meaning |
| --- | --- | --- |
| `helper` | string | Normalized helper name such as `npx`, `az`, `gcloud`, `docker`, or `wrangler`. |
| `command` | string or null | Sanitized command display, not raw shell text when raw text may contain secrets. |
| `helper_resolution` | enum string | Schema/API-backed value such as `bare_command`, `shell_string`, `toolkit_which`, `absolute_path`, `toolcache_path`, `action_owned_path`, `user_supplied_absolute_path`, `ambient_path_by_explicit_mode`, or `unknown`. |
| `call_site` | object or null | Public call-site descriptor, for example action name, run step, script key path, or source location. |

Public output may say a helper was invoked through a classified resolution mode.
It must not emit unsanitized argv, env, stdin, script body, or shell expansion.

### `HelperReceivesAuthority`

Wire event kind: `helper_receives_authority`.

| Field | Type | Public meaning |
| --- | --- | --- |
| `helper_execution_event_id` | string | Event id of the helper execution that receives authority. |
| `authority_materialization_event_id` | string | Event id of the materialized authority. |
| `authority_transport` | enum string | `argv`, `stdin`, `env`, `credential_file_path`, `config_file_path`, `workspace_file`, or `oidc_request_env`. |
| `confidence` | enum string | `high`, `medium`, or `low`, based on static, catalog, witness-label, or observed support. |

Public output may say the authority reaches the helper by this transport. It
must not include raw transported values, file contents, or canary material.

## Ordering Invariant

A helper-resolution authority finding requires all four public event concepts in
the same relevant execution scope:

```text
PathMutation.step_index < AuthorityMaterialized.step_index <= HelperExecution.step_index
```

`SecretMaterialized` satisfies the authority materialization position when the
materialized authority class is `secret`.

The public predicate must reference the event ids that satisfy the invariant.
The event list may include extra explanatory events, but the predicate ids are
the ordered evidence used by the finding.

`job_id` is the default scope boundary. Cross-job evidence is negative unless a
future schema/API-backed execution relationship explicitly proves that the
mutable channel and authority path share an execution scope.

## Sink Projection Expectations

| Sink | Expected projection |
| --- | --- |
| JSON report | Emit `ordered_authority_evidence` as a structured object on each helper-authority finding that satisfies the invariant. |
| Exploit graph JSON | Emit the same field names for path evidence when ordered evidence is part of the path projection. The exploit graph remains a deterministic projection, not proof of exploitability. |
| SARIF | Preserve the object under result properties using the same nested field name, `ordered_authority_evidence`. Human SARIF text may summarize but must not add stronger claims. |
| CloudEvents | Preserve the object under event `data.ordered_authority_evidence`. Extension attributes may carry scalar summary fields only if they do not rename the canonical object fields. |
| Terminal default | May summarize the finding and caveat without printing the full object. It must not claim witness proof or observed sink behavior from static evidence. |
| Terminal verbose | Must render the ordered chain using the same public field meanings, including event kind, job id, step indexes, helper resolution, authority transport, authority origin, and confidence. |

L5 parity should compare values after native sink normalization, not prose. A
sink may omit fields only when the sink contract explicitly marks them
non-projectable and the omission is documented.

## Deferred Or Internal Fields

These fields are not part of the public L2-03 wire-field freeze:

| Field or concept | Classification | Reason |
| --- | --- | --- |
| `disclosure_score` | internal-gated | Disclosure triage is not customer-safe default output. |
| `cve_status`, `cve_route`, `vendor_route` | internal-gated | taudit is the classifier, not the CVE workflow authority. |
| `witness_spec`, `witness_command`, `next_witness_action` | internal-gated | Witness handoff is separate from public scan output. |
| `canary_value`, `canary_path`, `fake_helper_body` | absent by default | Canary material and witness payloads must not leak. |
| `private_run_id`, `private_log_url`, `private_source_anchor` | absent by default | Private hosted-run evidence is not public output. |
| `raw_command`, `raw_argv`, `raw_env`, `raw_stdin` | witness-only or absent | Raw execution material can contain secrets. Public `command` is sanitized. |
| `internal_node_id`, `parser_cursor_id`, `catalog_scan_trace` | internal | Implementation diagnostics are not stable public contract. |
| `observed_sink`, `observed_path_count` | deferred public only with explicit evidence | ADR 0013 forbids observed sink claims without observed evidence input. |
| `technical_score`, `product_label`, `remediation_label` | adjacent public contract | These may render publicly when separately defined, but they are not event-order fields. |

## Negative Cases

Later L4 rules must not emit a helper-resolution authority finding when:

- only `PathMutation` exists;
- `AuthorityMaterialized.step_index` is less than or equal to
  `PathMutation.step_index`;
- `HelperExecution.step_index` is less than `AuthorityMaterialized.step_index`;
- path mutation and authority materialization are same-step only;
- the materialization event is missing;
- the helper execution event is missing;
- `HelperReceivesAuthority` is missing;
- events are in different `job_id` scopes without a schema/API-backed
  cross-scope execution relationship;
- helper resolution is downgraded or suppressed by trusted absolute path,
  trusted toolcache path, action-owned path, user-supplied absolute path, or
  explicit ambient mode and no remaining authority-confusion edge exists;
- evidence would require an observed sink claim but only static, inferred, or
  catalog evidence is present.

## Required Fixtures For L4/L5

L4 event-builder and rule fixtures should include:

- positive order: prior `path_mutation`, later `authority_materialized`, and
  same-step or later `helper_execution`;
- positive `secret_materialized` variant satisfying the authority
  materialization position;
- positive transport examples for `argv`, `stdin`, `env`,
  `credential_file_path`, `config_file_path`, `workspace_file`, and
  `oidc_request_env`;
- positive action-minted or generated-credential origin;
- reversed order negative;
- same-step path mutation and authority materialization negative;
- cross-job negative;
- missing materialization negative;
- missing `helper_receives_authority` negative;
- downgrade or suppression examples for trusted absolute path, toolcache path,
  action-owned path, user-supplied absolute path, and explicit ambient mode;
- observed-evidence-disabled fixture proving no observed sink fields render.

L5 sink fixtures should include:

- one JSON, SARIF, CloudEvents, and terminal verbose parity fixture proving the
  required public fields appear consistently;
- one default terminal fixture proving public prose remains bounded and
  customer-safe;
- one leakage fixture proving internal-gated fields, canaries, raw execution
  material, private source anchors, disclosure metadata, and CVE workflow
  metadata are absent by default;
- one schema/current-profile fixture proving the public field names here are the
  names used by schemas and API docs.
