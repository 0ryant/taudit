# `taudit baseline` — Per-Pipeline Baselines

Baselines are taudit's adoption mechanism. They snapshot the findings present
on a pipeline at the moment you onboard it, then surface only **NEW** findings
on subsequent scans. Existing teams can drop taudit into CI without spending
a week triaging historical findings before the first PR turns green.

The mechanism is **opt-in**, **content-hash-keyed**, and **fingerprint-stable**.
Critical findings always count toward exit `1` unless they are explicitly
waived with a time-bounded justification — that property is non-negotiable.

## Migration: v1.1.0-beta.1 baseline hash break

**v1.1.0-beta.1 changed `pipeline_identity_material_hash` to drop NodeId.**
Existing field baselines collected on v1.0.x silently fail-open (suppressions
disabled) until you re-baseline. To migrate:

```bash
taudit baseline init <pipeline-files> --gate-on-all
```

This re-captures the baseline against the new identity-material hash. No
behavioural change beyond hash format. See [CHANGELOG v1.1.0-beta.1](../CHANGELOG.md#v110-beta1--2026-05-01-prerelease)
for full context.

## Synopsis

```text
taudit baseline init    [PATH...] [--root <DIR>] [--captured-by <ID>]
                                  [--platform auto|github-actions|azure-devops|gitlab]
                                  [--max-hops <N>] [--invariants-dir <DIR>]

taudit baseline accept  --pipeline <FILE> --fingerprint <X> --rule-id <Y>
                        --severity <SEV> --reason "<TEXT>"
                        [--severity-override <SEV>] [--expires-at <ISO-8601>]
                        [--root <DIR>]

taudit baseline diff    [PATH...] [--root <DIR>]
                                  [--platform auto|github-actions|azure-devops|gitlab]
                                  [--max-hops <N>] [--invariants-dir <DIR>]

taudit baseline review  [--root <DIR>]
```

## How it works

1. `taudit baseline init <pipeline.yml>` scans the pipeline, records every
   finding's stable [fingerprint](finding-fingerprint.md), and writes
   `<root>/.taudit/baselines/<sha256-of-pipeline-content>.json`.
2. Future `taudit scan <pipeline.yml>` (and `taudit verify`) loads that
   file, diffs the live findings against the baseline, and reports
   per-pipeline as `N NEW, M FIXED, K PRE-EXISTING`.
3. Pre-existing findings no longer drive `verify` exit `1` — **except**
   for criticals without a valid waiver (see below).
4. `taudit baseline accept` upgrades a pre-existing entry into an explicit
   waiver with a `reason_waived` and (for criticals) an `expires_at`.

The baseline file's name is the SHA-256 of the pipeline's bytes. Renaming
or moving the pipeline file preserves the baseline; **editing** the pipeline
changes the hash and requires a fresh `init`. This is intentional: a baseline
is a contract about a specific known pipeline, not a moving target.

## File format

`<root>/.taudit/baselines/<hex>.json` — one file per pipeline. The full
schema lives at [`schemas/baseline.v1.json`](../schemas/baseline.v1.json).

```json
{
  "schema_version": "1.1.0",
  "pipeline_path": ".github/workflows/release.yml",
  "pipeline_content_hash": "sha256:abc123...",
  "pipeline_identity_material_hash": "sha256:def456...",
  "captured_at": "2026-04-26T12:00:00Z",
  "captured_by": "ryan@example.com",
  "captured_with": {
    "taudit_version": "0.10.0",
    "rules_version": "32-builtin"
  },
  "baseline_findings": [
    {
      "fingerprint": "5edb30f4db3b5fa3",
      "rule_id": "untrusted_with_authority",
      "severity": "high",
      "first_seen_at": "2026-04-26T12:00:00Z"
    },
    {
      "fingerprint": "a3c8d9e1f2b4c5d6",
      "rule_id": "trigger_context_mismatch",
      "severity": "critical",
      "first_seen_at": "2026-04-20T10:00:00Z",
      "reason_waived": "Threat-modeled; documented exception ABC-123",
      "severity_override": "critical",
      "expires_at": "2026-07-20T10:00:00Z"
    }
  ]
}
```

`pipeline_identity_material_hash` is additive in `1.1.0+`: newly captured
baselines persist a hash of dependency-like parser material (for example,
GitLab `include:` descriptors, ADO `resources.repositories[]`, and template
delegation edges). During `scan`/`verify`/`baseline diff`, taudit compares the
stored value with the current parse result:

- Match: baseline suppression/diff behaves normally.
- Mismatch: suppression is skipped and taudit asks for a fresh
  `taudit baseline init`.
- Missing field (legacy `1.0.x` baseline): treated as compatible for backward
  compatibility.

Entries are sorted ASC by `fingerprint` for stable git diffs. The
`fingerprint` value is **byte-equal** to the SARIF
`partialFingerprints.primaryLocationLineHash`, the JSON
`findings[].fingerprint`, and the CloudEvents `tauditfindingfingerprint`
extension attribute. A unit test (`baseline_fingerprint_matches_sarif_fingerprint`
in `taudit-core::baselines`) enforces this byte-equality forever.

## Default behaviour & flags

| Command | Default behaviour with baseline present | Override |
|---------|------------------------------------------|----------|
| `taudit scan` | Diff-shaped: only NEW findings + CRITICAL pre-existing without valid waiver are emitted. Pre-existing summarised on stderr. | `--show-all` |
| `taudit verify` | Only NEW findings + CRITICAL pre-existing without valid waiver count toward exit 1. | `--gate-on-all` |
| Both | `<root>/.taudit/baselines/` looked up against CWD. | `--baseline-root <DIR>` |

If `<root>/.taudit/` does not exist, taudit behaves **byte-identically to
v0.9.x** — no banner, no suppression, no behaviour change. This is the
OSS-friendly default.

## Security guarantees

The baseline mechanism creates a path for risk to be accepted — every
waiver mechanism does. The job of the design is to make that path
visible, attributable, expirable, and override-able by severity. Each of
these is enforced by code:

1. **Critical findings always exit 1** unless the entry carries
   `severity_override: critical` AND `reason_waived` (>=10 chars) AND
   `expires_at` no more than 90 days from `first_seen_at`. A plain
   pre-existing critical (no override fields) still fails verify even
   with the entry in the baseline. See
   `BaselineDiff::critical_without_valid_waiver` and the unit tests
   `critical_preexisting_without_waiver_blocks_exit_zero`,
   `critical_with_explicit_waiver_does_not_block`,
   `expired_critical_waiver_no_longer_protects`.
2. **Reasons must be substantive.** `accept` rejects any `--reason`
   shorter than 10 characters with `BaselineError::ReasonTooShort`.
3. **Critical waivers are time-bounded.** `accept` refuses
   `--severity-override critical` without `--expires-at`, and refuses
   any `--expires-at` more than 90 days out. Once the expiry passes,
   `is_valid_critical_waiver` returns `false` and the underlying critical
   counts toward exit `1` again.
4. **Every entry is attributable.** `captured_by`, `captured_at`,
   `first_seen_at`, and `reason_waived` are all recorded. `git log` on
   `.taudit/baselines/*.json` is the audit trail.
5. **Stable fingerprints prevent drift.** Suppressions tied to fingerprints
   that are byte-equal across SARIF, JSON, CloudEvents, and the baseline
   cannot silently drift. Every output format means the same thing by
   "this finding."
6. **Bulk-accept friction.** `accept` operates on a single fingerprint at
   a time. Bulk acceptance requires re-running `init` (which is loud and
   committed under CODEOWNERS review).

## Workflow

### Onboarding a repo

```bash
# Generate a baseline for every workflow.
taudit baseline init .github/workflows/

# Commit the snapshot.
git add .taudit/baselines/
git commit -m "taudit: capture baseline for rollout-2026-Q2"
```

### Reviewing on every PR

```bash
# In CI:
taudit verify --policy invariants/ --include-builtin .github/workflows/
# Exit 0 if no NEW findings (and no unwaived critical pre-existing).
# Exit 1 on a regression.
```

### Waiving a finding

```bash
# Read the fingerprint from the verify failure output, then:
taudit baseline accept \
  --pipeline .github/workflows/release.yml \
  --fingerprint 5edb30f4db3b5fa3 \
  --rule-id untrusted_with_authority \
  --severity high \
  --reason "Vendor action audited 2026-04 — see SECURITY.md#vendor-allowlist"

# Critical waiver — must include severity_override + expires_at.
taudit baseline accept \
  --pipeline .github/workflows/release.yml \
  --fingerprint a3c8d9e1f2b4c5d6 \
  --rule-id trigger_context_mismatch \
  --severity critical \
  --severity-override critical \
  --expires-at 2026-07-20T10:00:00Z \
  --reason "Threat-modeled; documented exception ABC-123"
```

### Auditing waivers

```bash
# List every waiver across every baseline, sorted by expires_at ASC.
# Exits 1 if any critical waiver is missing expires_at.
taudit baseline review
```

## Composition with `.tauditignore` and `--baseline` (legacy JSON)

The three suppression mechanisms compose:

| Mechanism | Scope | Use case |
|-----------|-------|----------|
| `.tauditignore` | Per-rule glob patterns | Wholesale rule-off for a path |
| `--baseline <file.json>` (legacy) | (category, message) tuple | Pre-v0.10 JSON-report baseline |
| `.taudit/baselines/<hash>.json` (this) | Per-pipeline fingerprint waivers with severity escalation | Adopt taudit on existing repos |

All three apply during `scan` in that order: ignore → legacy baseline →
per-pipeline baseline. `verify` skips the ignore/legacy paths and uses
only the per-pipeline baseline. They can coexist; load both if both are
present.

## Limitations & invariants

* **Editing a pipeline invalidates its baseline.** The baseline is keyed
  by the SHA-256 of the pipeline content; modifying the YAML changes the
  key. Re-run `taudit baseline init <pipeline>` to refresh. This is by
  design: a baseline is a contract about a specific known pipeline.
  Renames preserve state because the hash key is path-independent.
* **`stdin` pipelines have no baseline.** `cat ci.yml | taudit scan -`
  cannot resolve a baseline file (no stable filename); the per-pipeline
  baseline machinery is skipped automatically.
* **Forks inherit waivers.** Anyone who clones the repo gets the
  baseline. For critical waivers this is mitigated by the 90-day
  expiry; for high/medium/low waivers it is the reviewer's
  responsibility to audit on adoption (`taudit baseline review`).

## Related

* [`docs/verify.md`](verify.md) — the enforcement contract.
* [`docs/finding-fingerprint.md`](finding-fingerprint.md) — the fingerprint
  algorithm and stability guarantees.
* [`schemas/baseline.v1.json`](../schemas/baseline.v1.json) — the schema.
