# Finding fingerprint

`taudit` attaches a stable cross-run fingerprint to every finding it
emits. SIEMs, suppression databases, and dedup pipelines key on this
value to recognise "the same finding seen on the previous run" without
needing to diff full payloads.

The same fingerprint is surfaced in three output formats:

| Format       | Field                                                     |
|--------------|-----------------------------------------------------------|
| SARIF        | `runs[].results[].partialFingerprints[primaryLocationLineHash]` |
| JSON         | `findings[].fingerprint`                                  |
| CloudEvents  | extension attribute `tauditfindingfingerprint`            |

The values are byte-identical across formats for a given finding —
ingest from any sink, key on the fingerprint, join across alerts.

## Format

A 16-character lowercase hex string — the first 8 bytes of a SHA-256
digest of a canonical input string. 64 bits of entropy is plenty for
finding deduplication and short enough to be glanceable in a SIEM table
column.

```
3f7c2a8b9d1e4f0c
```

## What the fingerprint depends on

**Sensitive to (changing any of these changes the fingerprint):**

* Rule id — either a custom rule's declared id (when the finding's
  message starts with `[id] …`) or the snake_case form of the
  built-in `FindingCategory`
* Source file path (`graph.source.file`)
* Finding category (snake_case)
* Identifying node names. When the finding involves a `Secret` or
  `Identity` node, the root authority's name is used so that
  per-hop findings against a single secret collapse to one
  fingerprint. Otherwise the names of all involved nodes, sorted, are
  used.

**Insensitive to (these can change without breaking suppressions):**

* Wall-clock time
* The finding's user-facing `message` text — operators tweak phrasing
  without wanting suppressions to invalidate
* The `taudit` version string within a major release
* Environment, host, current working directory
* Pipeline file content hash — only the path matters, not the bytes

## Stability guarantee

The fingerprint format is stable within a major version of `taudit`
(1.x.y). A 2.0.0 release MAY change the algorithm; the JSON report's
`schema_version` and the SARIF driver version both surface the current
contract, and any breaking change to the fingerprint will be called
out explicitly in CHANGELOG.

The first 0.x release that ships this contract is v0.10.0. Pre-v0.10.0
SARIF outputs used a `DefaultHasher`-based fingerprint, which the Rust
team explicitly does not stabilise across compiler versions — so values
were not safe to suppress on across `taudit` re-installs even though
the surface field was the same. v0.10.0+ uses SHA-256, which gives a
real cross-version stability guarantee.

## How consumers should use it

**Suppression / muting.** Build a suppression DB keyed on
`(repo, fingerprint)`. When a new scan emits a finding whose
fingerprint is in the DB, drop or mute the alert without re-evaluating
remediation status.

**Cross-format join.** A pipeline ingesting both SARIF (uploaded to
GitHub Code Scanning) and CloudEvents (forwarded to your alert bus)
can join the two streams on fingerprint to attach SARIF-side review
state to CloudEvent-side runtime telemetry.

**Re-run dedup.** Two scans of the same repo at different commits will
share fingerprints for any finding whose root authority and source
file are unchanged, even if line numbers, message text, or
neighbouring code shifted. Group SIEM alerts by fingerprint to count
distinct issues rather than distinct emissions.

## Example

A single scan emits the same finding through all three sinks:

```bash
$ taudit scan --format sarif workflows/deploy.yml \
  | jq '.runs[0].results[0].partialFingerprints'
{
  "primaryLocationLineHash": "3f7c2a8b9d1e4f0c"
}

$ taudit scan --format json workflows/deploy.yml \
  | jq '.findings[0].fingerprint'
"3f7c2a8b9d1e4f0c"

$ taudit scan --format cloudevents workflows/deploy.yml \
  | head -1 | jq '.tauditfindingfingerprint'
"3f7c2a8b9d1e4f0c"
```

A SIEM keyed on the fingerprint sees the same finding regardless of
which sink fed the alert.

## CloudEvents naming

The CloudEvents 1.0 spec restricts extension attribute names to
lowercase ASCII letters and digits — no dashes, no underscores. The
attribute is therefore named `tauditfindingfingerprint` rather than
the more readable `taudit-finding-fingerprint` or
`taudit_finding_fingerprint`. This matches the existing
`tauditcompleteness` extension on the same envelope.
