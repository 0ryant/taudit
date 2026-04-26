# Finding output enhancements (v0.10)

> **Status:** stable. Schema additions are additive; existing v1 consumers ignore unknown fields without breaking.

The blue-team corpus defense report (`MEMORY/WORK/.../blueteam-corpus-defense.md` Section 3) identified five small, additive `Finding` fields that consumers (SIEMs, dashboards, triage queues, IDE viewers) need but cannot derive cheaply. Three of them ship in v0.10:

| Field | Type | Required | Purpose |
|-------|------|----------|---------|
| `finding_group_id` | UUID v5 | optional, auto-derived | Cluster N hops against the same authority root into one display row. |
| `time_to_fix` | enum | optional, per-rule | Coarse remediation effort so triage dashboards can sort by `severity * effort`. |
| `compensating_controls` | string list | optional, per-finding | Detected controls that downgraded severity. Empty when no downgrade applied. |

(The two enhancements deferred to a future patch — `blast_radius_node_count` and `reproduction_steps` — are larger work; see the corpus defense report for the proposals.)

This document describes the field contract. For the suppression-related fields (`suppressed`, `original_severity`, `suppression_reason`) see [`docs/suppressions.md`](suppressions.md).

---

## A. `finding_group_id`

Stable UUID v5 derived from the finding fingerprint. Two findings with the same fingerprint produce the **same** group id — that's the whole point.

### Why

`authority_propagation` fires per hop in a propagation chain. A single `GITHUB_TOKEN` flowing through 8 jobs in a matrix workflow produces 8 findings. The SARIF `partialFingerprints[primaryLocationLineHash]` already collapses these for GitHub Code Scanning (see [`docs/finding-fingerprint.md`](finding-fingerprint.md)). But raw JSON, text, and CloudEvents output emitted **one record per hop** — a SIEM ingesting the CloudEvents stream saw 8 events where a human reviewer needed one grouped advisory.

`finding_group_id` aligns the other formats with what SARIF already does.

### Where it appears

| Format | Field name | Notes |
|--------|-----------|-------|
| JSON  | `findings[].finding_group_id` | UUID v5 string, auto-derived from fingerprint at emission time. |
| SARIF | `result.properties.findingGroupId` | Same value. SARIF viewers expose `properties.*` as raw key/value pairs. |
| CloudEvents | `tauditfindinggroup` extension attribute | CloudEvents 1.0 attribute names are lowercase with no separators — hence `tauditfindinggroup`. |

### How to use it

```sql
-- SIEM dedup query
SELECT
  any_value(severity) AS sev,
  any_value(category) AS rule,
  count(*)            AS hop_count,
  tauditfindinggroup  AS group_id
FROM taudit_events
GROUP BY tauditfindinggroup
ORDER BY hop_count DESC;
```

### Algorithm

`finding_group_id = uuid_v5(NAMESPACE, fingerprint)` where `NAMESPACE` is a fixed UUID embedded in `taudit-core`. Treating the namespace as load-bearing is intentional: changing it would break every consumer that has stored a `finding_group_id`. The namespace will only ever change at a major version.

### Stability

Same fingerprint -> same `finding_group_id`, byte-identical, forever within a major version. The fingerprint contract is documented in [`docs/finding-fingerprint.md`](finding-fingerprint.md).

---

## B. `time_to_fix`

Coarse remediation-effort enum so a triage dashboard can sort by `severity × time_to_fix` and surface the highest-ROI fixes first. Four buckets:

| Variant | Wall-clock estimate | Examples |
|---------|--------------------|----------|
| `trivial` | ~5 min  | SHA-pin an action, add `permissions: {}`, add a fork-check |
| `small`   | ~1 hr   | Audit and narrow a job's permissions block, refactor a step |
| `medium`  | ~1 day  | Restructure a job, introduce an environment gate, sandbox an inline script |
| `large`   | ~1 week+ | Migrate org-wide from PATs to OIDC, change branch protection model |

The buckets are intentionally wide. Precise time estimates would invite argument; the buckets exist to separate "flip a flag" from "rewrite a job" from "renegotiate ops policy".

### Where it appears

| Format | Field name |
|--------|-----------|
| JSON  | `findings[].time_to_fix` |
| SARIF | `result.properties.timeToFix` |
| CloudEvents | inside `data.time_to_fix` (the full Finding payload) |

### Per-rule annotations shipped in v0.10

| Rule | `time_to_fix` |
|------|---------------|
| `unpinned_action` | `trivial` |
| `floating_image` | `trivial` |
| `over_privileged_identity` | `small` |
| `checkout_self_pr_exposure` | `medium` |
| `long_lived_credential` | `large` |

Other rules emit no `time_to_fix` (the field is `Option<FixEffort>`); a future patch will annotate the rest.

### How to use it

```sql
-- Triage dashboard: highest-ROI fixes first
SELECT
  rule, severity, time_to_fix, count(*) AS findings
FROM taudit_events
WHERE severity IN ('critical', 'high')
GROUP BY rule, severity, time_to_fix
ORDER BY
  CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
  CASE time_to_fix WHEN 'trivial' THEN 0 WHEN 'small' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
  findings DESC;
```

### Adding `time_to_fix` to a custom rule

```rust
use taudit_core::finding::{Finding, FindingExtras, FixEffort, ...};

let f = Finding {
    severity: Severity::Medium,
    category: FindingCategory::UnpinnedAction,
    // ... other fields ...
    extras: FindingExtras {
        time_to_fix: Some(FixEffort::Trivial),
        ..FindingExtras::default()
    },
};
```

Or, when starting from an already-built Finding, use the builder helper:

```rust
let f = make_finding(...).with_time_to_fix(FixEffort::Small);
```

---

## C. `compensating_controls`

Human-readable list of detected controls that downgraded a finding's severity. Empty when no downgrade applied.

### Why

A SOC analyst receiving a `trigger_context_mismatch` finding on a workflow that has fork-checks correctly applied should not spend triage time on it — but they also shouldn't see the finding silently disappear. `compensating_controls` is the explanation channel: "this finding fired, but here's the control that already neutralises it."

### Example values

```
- "fork check present: github.event.pull_request.head.repo.fork == false"
- "environment gate present: environment: production-approvers"
- "OIDC token used: no static AWS_* credentials"
```

### Mechanics

When a compensating-control detector identifies a control, it calls `Finding::with_compensating_control("…")`. The helper:

1. Pushes the control description onto `extras.compensating_controls`.
2. Records the original severity into `extras.original_severity` (if not already set).
3. Drops `severity` by one tier (Critical -> High -> ... -> Info).

A finding can carry multiple compensating-control entries; each call drops severity one further tier.

### Where it appears

| Format | Field name |
|--------|-----------|
| JSON  | `findings[].compensating_controls` (omitted if empty) |
| SARIF | `result.properties.compensatingControls` (omitted if empty) |
| CloudEvents | inside `data.compensating_controls` |

### Status of the v0.10 detector set

The fields are in place and the helper API is stable. The actual compensating-control **detectors** (CC-1 through CC-5 in the corpus defense report) ship in a parallel work-stream — those rules will populate this field as they land. Until then, `compensating_controls` is a contract waiting for producers, not an active source of downgrades.

---

## Schema impact

`contracts/schemas/taudit-report.schema.json` gains five optional `Finding` fields:

```json
"finding_group_id":     { "type": "string", "format": "uuid" }
"time_to_fix":          { "type": "string", "enum": ["trivial", "small", "medium", "large"] }
"compensating_controls": { "type": "array", "items": { "type": "string" } }
"suppressed":           { "type": "boolean" }
"original_severity":    { "type": "string", "enum": ["critical", "high", "medium", "low", "info"] }
"suppression_reason":   { "type": "string" }
```

`contracts/schemas/taudit-cloudevent-finding-v1.schema.json` gains one optional CloudEvent extension attribute (`tauditfindinggroup`).

All additions are non-breaking. v1 consumers that pre-date these fields ignore them per JSON-Schema's standard "ignore unknown" semantics.

## See also

- [`docs/suppressions.md`](suppressions.md) — `suppressed`, `original_severity`, `suppression_reason` fields.
- [`docs/finding-fingerprint.md`](finding-fingerprint.md) — fingerprint contract that `finding_group_id` is derived from.
- `MEMORY/WORK/.../blueteam-corpus-defense.md` Sections 3 and 4 — the corpus analysis that motivated these enhancements.
