# Core Ordered Evidence Builder

Status: bounded L4-01/L4-02 skeleton for `v1.2.0-rc.1`.

## Scope

`crates/taudit-core/src/evidence.rs` adds the shared core model for ordered
authority evidence events described in
[`ordered-evidence-wire-fields.md`](ordered-evidence-wire-fields.md).

The module defines:

- `OrderedEvidenceEvent` variants for `path_mutation`, `secret_materialized`,
  `authority_materialized`, `helper_execution`, and
  `helper_receives_authority`;
- shared enum values for helper resolution, authority transport, authority
  origin, authority class, mutable channel, mutation scope, evidence strength,
  and confidence;
- `OrderedAuthorityEvidenceBuilder`, which validates the default same-job
  ordering predicate:

```text
PathMutation.step_index < AuthorityMaterialized.step_index <= HelperExecution.step_index
```

`SecretMaterialized` satisfies the authority materialization position.

## Current Predicate Boundary

The builder only proves same-job evidence chains. Cross-job evidence remains
negative unless a later schema/API-backed execution relationship is added. All
events carried in one built evidence object must be in the declared same-job
scope; out-of-scope events are rejected instead of being attached as extra
context.

The builder requires:

- at least one path mutation event;
- at least one secret or authority materialization event;
- at least one helper execution event;
- at least one helper-receives-authority event that references the helper and
  authority events;
- matching `job_id` values for the selected predicate events;
- matching `job_id` values for every emitted event in the evidence object;
- path mutation before authority materialization;
- helper execution at the same step as, or later than, authority
  materialization.

## Deliberate Non-Scope

This lane does not wire parser stamps, helper-authority rule emission,
exploit-path projection, JSON/SARIF/CloudEvents output, terminal rendering, or
schema generation. Existing rule behavior is intentionally unchanged.

## Verification

Core unit coverage currently exercises:

- positive order;
- reversed order negative;
- same-step materialization/execution positive;
- cross-job negative;
- out-of-scope extra-event negative;
- missing materialization negative;
- transport-before-helper negative;
- public authority-origin serialization names.

Command:

```powershell
cargo test -p taudit-core evidence
```

## Next Dependency Unblocked

L4-03/L4-04 can add catalog-backed event producers against the shared enum
surface. L4-05 can then rewrite helper-authority rules to require
`OrderedAuthorityEvidenceBuilder` predicates before emitting ordered authority
findings.
