# `.taudit-suppressions.yml` — per-finding waivers with audit trail

> **Status:** stable as of v0.10. Schema is additive; new fields land at minor versions.

## Why this exists

taudit already ships three coarse mechanisms for cutting noise:

| Mechanism | Granularity | Strength | Weakness |
|-----------|-------------|----------|----------|
| `.tauditignore` | category × file glob | mass-mute | hides whole rule classes |
| `--severity-threshold` | severity floor | global filter | one knob, all rules |
| Starter invariants | positive policy | declarative | says "must"; can't say "accepted" |

What's missing is the **per-finding waiver with audit trail** — the workflow most adopters actually need:

> "We've reviewed this specific authority_propagation finding. The risk is acknowledged by Sarah on the security team. It's safe for the next 90 days. Don't gate CI on it. But don't let it disappear from the audit log either."

`.taudit-suppressions.yml` is that mechanism.

## File location

Looked up in this order:

1. The path passed to `--suppressions <PATH>`. Must exist when supplied (no silent fall-through).
2. `.taudit-suppressions.yml` in the current working directory.
3. `.taudit/suppressions.yml` in the current working directory.
4. Empty config (no waivers).

Both `taudit scan` and `taudit verify` resolve the file the same way, so policy-gated CI sees the same severity levels as informational scans.

When a suppression file is loaded, taudit prints the discovered path to stderr.
If an entry matched no finding in the current run, taudit also warns so stale
or mistyped fingerprints do not fail silently.

## File format

```yaml
# .taudit-suppressions.yml
# Each entry waives one finding by stable fingerprint.
suppressions:
  - fingerprint: "5edb30f4db3b5fa3d7fe7289374b7155"
    rule_id: "untrusted_with_authority"
    reason: "Internal-only action; threat-modeled and accepted by security team."
    accepted_by: "ryan@example.com"
    accepted_at: "2026-04-26"
    expires_at: "2026-07-26"  # optional; required for critical waivers

  - fingerprint: "a3c8d9e1f2b4c5d6a3c8d9e1f2b4c5d6"
    rule_id: "long_lived_credential"
    reason: "External SaaS does not support OIDC yet; rotation policy in place."
    accepted_by: "ryan@example.com"
    accepted_at: "2026-04-26"
    # No expires_at — non-critical, so optional. `taudit suppressions review`
    # will surface it for re-evaluation after 90 days.
```

### Field reference

| Field | Required | Type | Notes |
|-------|----------|------|-------|
| `fingerprint` | yes | 32-char hex | Same value as JSON `findings[].fingerprint`, SARIF `partialFingerprints[primaryLocationLineHash]`, CloudEvents `tauditfindingfingerprint`. |
| `rule_id` | yes | string | Snake-case rule id or custom rule id. Used for human display. |
| `reason` | yes | string | Operator justification. Empty values are rejected — the audit trail is the point. |
| `accepted_by` | yes | string | Identity of the approver: email, GitHub handle, employee id. |
| `accepted_at` | yes | `YYYY-MM-DD` | Date the waiver was created. Drives the 90-day re-review prompt. |
| `expires_at` | conditional | `YYYY-MM-DD` | Optional in general; **required when the waived finding is Critical**. Past dates emit a warning and the waiver does not apply. |

## How a waiver applies

When a finding's fingerprint matches an active suppression entry, taudit applies the waiver according to the configured mode (passed via `--suppression-mode <mode>`; defaults to `downgrade`):

### `downgrade` mode (default)

Severity drops by one tier:

```
Critical -> High -> Medium -> Low -> Info
```

`extras.original_severity` records the rule-emitted severity. `extras.suppression_reason` records the operator reason. The full finding still appears in JSON, SARIF, and CloudEvents output — audit trail preserved.

### `suppress` mode

Severity is unchanged, but `extras.suppressed = true` is set on the finding. Consumers (SIEMs, dashboards) filter on the boolean. `extras.original_severity` and `extras.suppression_reason` are still populated for the audit trail.

In `taudit verify`, `suppress` is tag-only: matched findings still count toward
exit `1` unless another filter removes them (`.tauditignore`, baseline, or
`--severity-threshold`).

Pick `downgrade` when you want the waiver to influence severity-threshold gating; pick `suppress` when you want to keep severity legible to humans but signal "acknowledged" to machines.

## Hard rules

Two operator behaviours are explicit failures rather than warnings:

### 1. Critical findings cannot be fully suppressed without `expires_at`

A waiver entry that targets a Critical finding **must** carry `expires_at`. If it doesn't, `taudit scan` and `taudit verify` exit with code 2 and a clear error message:

```
error: suppression for fingerprint <X> (rule <R>) waives a critical finding
       but has no expires_at — critical waivers must expire
```

This rule exists so a critical finding can never silently disappear forever. If the risk is genuinely accepted permanently, that decision belongs in `.tauditignore` (a different lever, with a different name, that operators must consciously choose).

### 2. Expired waivers do not apply, and emit a warning

When `expires_at` is in the past relative to the current date, the waiver is skipped:

```
WARNING: suppression for fingerprint 5edb30f4db3b5fa3d7fe7289374b7155 expired on 2026-03-01;
         finding restored to original severity
```

The finding appears at its rule-emitted severity. CI gating resumes. Update `expires_at` (after re-reviewing the risk) to renew.

### 3. Unmatched waivers emit a warning

If a suppression entry matched no finding in the current run, taudit prints a
warning naming the fingerprint and rule id. This catches stale suppressions,
copy-paste mistakes, and fingerprint values from a different build or older
fingerprint format.

## CLI commands

### `taudit suppressions list`

Print every loaded entry with its computed status:

```
$ taudit suppressions list
taudit suppressions — 2 suppressions

  5edb30f4db3b5fa3d7fe7289374b7155  untrusted_with_authority  active            expires=2026-07-26    by=ryan@example.com
    reason: Internal-only action; threat-modeled and accepted by security team.
  a3c8d9e1f2b4c5d6a3c8d9e1f2b4c5d6  long_lived_credential     stale-for-review  expires=(no expiry)   by=ryan@example.com
    reason: External SaaS does not support OIDC yet; rotation policy in place.
```

### `taudit suppressions add`

Append a new entry. Pass all fields via flags (scriptable / CI-bot-friendly):

```
$ taudit suppressions add \
    --fingerprint 5edb30f4db3b5fa3d7fe7289374b7155 \
    --rule-id untrusted_with_authority \
    --reason "Internal-only action; threat-modeled" \
    --accepted-by ryan@example.com \
    --expires-at 2026-07-26
appended suppression to .taudit-suppressions.yml
```

Or run with no flags to be prompted for each field interactively.

### `taudit suppressions review`

Sort entries by `accepted_at` and flag any that need attention (expired, expiring within 30 days, or no-expiry-but-older-than-90-days):

```
$ taudit suppressions review
taudit suppressions review — review 2 suppressions

  a3c8d9e1f2b4c5d6  rule=long_lived_credential     status=stale-for-review  accepted_at=2026-01-15  by=ryan@example.com
    reason: External SaaS does not support OIDC yet; rotation policy in place.
  5edb30f4db3b5fa3d7fe7289374b7155  rule=untrusted_with_authority  status=active            accepted_at=2026-04-26  by=ryan@example.com
    expires_at: 2026-07-26
    reason: Internal-only action; threat-modeled and accepted by security team.

1 entry needs review
```

## Output shape

Every output format that emits findings also emits the suppression metadata when an entry matched:

### JSON (`taudit scan --format json`)

```json
{
  "fingerprint": "5edb30f4db3b5fa3d7fe7289374b7155",
  "severity": "high",
  "original_severity": "critical",
  "suppression_reason": "Internal-only action; threat-modeled.",
  "category": "untrusted_with_authority",
  "...": "..."
}
```

### SARIF (`taudit scan --format sarif`)

The SARIF result's `properties` bag includes `originalSeverity` and `suppressed`; the boolean lets GitHub Code Scanning render the finding as "suppressed" rather than "open".

### CloudEvents (`taudit scan --format cloudevents`)

The CloudEvent envelope's `data` payload (the full Finding) includes the new fields. The `tauditfindingfingerprint` and `tauditfindinggroup` extension attributes give SIEMs a stable dedup key across re-runs.

## Recipe: gate CI on critical findings only, but keep audit trail

```yaml
# .taudit-suppressions.yml — accepts a small set of waivers
suppressions:
  - fingerprint: "5edb30f4db3b5fa3d7fe7289374b7155"
    rule_id: "untrusted_with_authority"
    reason: "Internal action; risk owned by platform team."
    accepted_by: "platform@example.com"
    accepted_at: "2026-04-26"
    expires_at: "2026-07-26"
```

```bash
# CI step
taudit verify --policy invariants/starter --severity-threshold critical .github/workflows/
```

The waived finding drops from Critical to High (via `downgrade` mode), falls below `--severity-threshold critical`, and stops gating CI. The full finding still appears in any JSON/SARIF artefact uploaded to your dashboard, with `original_severity: critical` and the operator reason recorded.

## See also

- [`docs/finding-fingerprint.md`](finding-fingerprint.md) — how the 32-hex-char fingerprint is computed.
- [`docs/finding-output-enhancements.md`](finding-output-enhancements.md) — `finding_group_id`, `time_to_fix`, `compensating_controls` fields.
- `MEMORY/WORK/.../blueteam-corpus-defense.md` Section 5 — the SOC-integration analysis that motivated this feature.
