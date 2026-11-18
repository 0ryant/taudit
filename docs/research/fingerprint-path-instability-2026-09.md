# Finding fingerprints are unstable across invocation style

Status: **open defect**, proposed for the next RC. Needs a decision on the
canonical form before implementation, because the fix changes every fingerprint
and forces a re-baseline.

Found 2026-09-09 while auditing whether the authority and exploit graphs are
deterministic.

## What is stable

Determinism was measured, not assumed. All of these produce byte-identical
output:

| Property | Method | Result |
|---|---|---|
| Repeated runs, same process invocation | `--view exploit` × 5, separate processes | identical |
| Across real-world inputs | 60 public corpus workflows × 3 runs each | 0 non-deterministic |
| Multi-file directory scan | 120-file directory × 3 runs, `graph` and `scan` | identical |
| Across operating systems | Windows and Linux, taudit 1.3.3, same relative path | identical fingerprints |

Rust's `HashMap` uses a per-process random seed, so the repeated-run results
above rule out hash-iteration order leaking into output. Cross-OS equality rules
out line-ending and float-formatting drift.

## What is not stable

`graph.source.file` is stored as the path was typed on the command line. The
fingerprint derives from it, and the only normalisation applied is backslash to
forward slash:

```rust
// crates/taudit-core/src/finding.rs, finding_identity_parts
let file_normalised = graph.source.file.replace('\\', "/");
```

So the same file, same bytes, same binary, gives three different fingerprints:

| Invocation | `graph.source.file` | Fingerprint (first 32) |
|---|---|---|
| `taudit scan f.yml` | `f.yml` | `70474ac4ab128eba18a0947c155d6f03` |
| `taudit scan ./f.yml` | `./f.yml` | `447c21a3fdfbb3f04a7dbce0fc6d264d` |
| `taudit scan /abs/path/f.yml` | `C:/…/f.yml` | `33a102a661a5388950b165c54d9cff4c` |

Finding *counts* are stable at 14 in all three cases, so detection is not
affected. Only identity is.

Two secondary observations:

- `docs/finding-fingerprint.md` says the source path is "normalised to forward
  slashes". A Windows absolute path passed as `C:\…\f.yml` is emitted with
  backslashes intact in `graph.source.file`; only the fingerprint input is
  rewritten. The document describes the fingerprint input, not the output field,
  and reads as though it describes both.
- The same instability reaches `suppression_key` (`sk1_…`), the SARIF
  `partialFingerprints`, and `finding_group_id`, since all derive from the same
  identity parts.

## Why it matters

Baselines and suppressions are keyed on fingerprints, so they silently stop
applying when the invocation style changes. Reproduced:

```
taudit baseline init f.yml          # baseline written from the relative path
taudit scan f.yml                   # 6 findings surfaced, rest matched the baseline
taudit scan /abs/path/f.yml         # 14 findings surfaced, baseline matched nothing
```

There is no warning. The failure presents as "the baseline stopped working" or,
worse, as a quiet increase in findings that a reviewer waves through.

This is not a hypothetical divergence. taudit's own `taudit-pr-diff.yml` scans
with `taudit scan .`, while a developer checking one file naturally runs
`taudit scan .github/workflows/ci.yml`. Those two produce different identities
for the same finding.

## Proposed fix

Canonicalise the source path once, where the graph is constructed, rather than
at fingerprint time. Store the canonical form in `graph.source.file` so the
output field and the fingerprint input agree.

Canonical form should be **repository-root-relative, forward slashes, no `./`
prefix**: `.github/workflows/ci.yml`.

Rejected alternatives, and why:

- **Basename only** (`ci.yml`) — collides across directories, and monorepos with
  per-service pipelines would alias unrelated findings.
- **Relative to the current working directory** — trades one invocation
  dependency for another. Scanning the same absolute path from two different
  directories would still diverge.
- **Absolute path** — embeds the checkout location, so CI and every developer
  machine disagree by construction. This is effectively today's behaviour for
  absolute invocations.

Repository-root-relative is what SARIF consumers already expect for
`artifactLocation.uri`, so it also improves downstream tool alignment.

## Decisions needed before implementing

1. **How is the repository root discovered?** Walking up for `.git` is the
   obvious answer, but taudit must keep working on a directory that is not a git
   checkout (unpacked archive, container build context). Proposed fallback: the
   scan root the user passed. That fallback is itself invocation-dependent, so
   it needs to be recorded in the output rather than silently applied.
2. **Does `graph.source.file` change in the output, or only the fingerprint
   input?** Changing the output field is the honest option and keeps the doc
   true, but it is a visible change to `authority-graph.v1.json` consumers.
3. **Migration.** This re-keys every fingerprint, `suppression_key`,
   `finding_group_id` and SARIF `partialFingerprint`, exactly like the
   SHA-256 to BLAKE3 migration in v1.3.1. It needs the same treatment: a
   Detection-delta note, a one-time re-baseline instruction, and a release where
   both are expected.

Because of (3) this belongs in an RC, not a patch, and warrants an ADR
alongside ADR-0003 rather than a bare code change.

## Reproducing

```bash
mkdir -p /tmp/fp && cp tests/fixtures/propagation-leaky.yml /tmp/fp/f.yml && cd /tmp/fp
for p in f.yml ./f.yml /tmp/fp/f.yml; do
  taudit scan "$p" --platform github-actions --format json --quiet \
    | python -c "import sys,json;print(json.load(sys.stdin)['findings'][0]['fingerprint'])"
done
```
