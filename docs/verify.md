# `taudit verify` — Policy Enforcement Entrypoint

`taudit verify` is the policy-driven enforcement entrypoint for taudit. It is
designed for **CI required-checks**, **PR merge gates**, and any other place
that needs a deterministic, machine-readable yes/no on whether a pipeline
satisfies your organisation's authority policy.

`scan` *describes* what taudit found. `verify` *decides* whether the world is
acceptable, and exits accordingly.

## Synopsis

```text
taudit verify [PATH...] --policy <FILE_OR_DIR>
              [--format text|json|sarif]
              [--platform auto|github-actions|azure-devops|gitlab]
              [--strict]
              [--include-builtin]
              [--severity-threshold critical|high|medium|low|info]
              [--max-hops <N>]
              [--no-color]
              [-o <FILE>]
```

## The Contract

Exit codes are part of the contract. Wire them straight into CI:

| Exit | Meaning |
|------|---------|
| `0`  | No policy violations — **pass** (merge allowed on policy grounds). |
| `1`  | At least one policy violation — **fail** (block the merge). |
| `2`  | Usage or configuration error — **could not decide** (bad CLI args, missing/unreadable policy, empty policy, pipeline parse failure on explicit paths, or `--strict` directory errors). |

Exit `2` is reserved for "we couldn't make a decision" — never conflate it
with "the policy passed". A required CI check that treats `2` as success will
silently let unscanned pipelines through.

## Discovered-file parse/read errors and `--strict`

When `PATH` includes a directory, `verify` discovers `*.yml` / `*.yaml` files
recursively.

- Default (`--strict` not set): read/parse errors on discovered files are
  warned and skipped (explicit file arguments still fail with exit `2`).
- Strict mode (`--strict`): any discovered-file read/parse error is fatal and
  `verify` exits `2`.

## How `verify` differs from `scan`

| Aspect | `scan` | `verify` |
|--------|--------|----------|
| Default rule set | 61 built-in rules always run | Only `--policy` invariants run |
| Built-in rules | Always on | Off by default; opt in with `--include-builtin` |
| Exit code | 0/1 driven by `--severity-threshold` over all findings | 0/1/2 contract above |
| Primary audience | Engineers triaging risk | CI required checks, merge gates |
| Output formats | `terminal`, `json`, `sarif`, `cloudevents` | `text`, `json`, `sarif` |

`verify` is intentionally minimal: load policy, evaluate, exit. It does not
emit telemetry, write receipts, or honour `.tauditignore`. If you want any of
that, run `scan` separately.

## Required argument: `--policy`

`--policy` accepts either:

- A single `.yml`/`.yaml` file containing one invariant.
- A directory; every `*.yml` and `*.yaml` file in it is loaded (recursively
  via the same loader as `scan --rules-dir`, sorted for determinism).

The argument is **required**. There is no implicit default — a CI gate with no
policy is a configuration bug, not a no-op. If the policy directory is empty
and `--include-builtin` is not set, `verify` exits `2` rather than silently
passing every input.

The invariant file format is the same one documented in
[`docs/custom-rules.md`](custom-rules.md).

## Output formats

### `--format text` (default)

One line per violation, plus a final summary:

```text
.github/workflows/release.yml: secret_to_untrusted: [secret_to_untrusted] Secret reaching untrusted step: SIGNING_KEY -> untrusted-org/publish-action@main [Critical]
verify: authority graph modeling: 1 pipeline(s) — complete: 1, partial: 0, unknown: 0
verify: 1 violation (1 critical / 0 high / 0 medium / 0 low / 0 info)
```

The **authority graph modeling** line is always emitted when at least one
pipeline was evaluated — counts `complete` / `partial` / `unknown` and prints
per-pipeline gap detail for anything not `complete`. The **violation summary**
line is always emitted too, even when the count is zero, so CI logs always show
the verdict.

### `--format json`

Stable, versioned schema:

```json
{
  "schema_version": "taudit.verify.v1",
  "violations": [
    {
      "path": ".github/workflows/release.yml",
      "invariant_id": "secret_to_untrusted",
      "severity": "critical",
      "category": "authority_propagation",
      "message": "[secret_to_untrusted] Secret reaching untrusted step: SIGNING_KEY -> untrusted-org/publish-action@main"
    }
  ],
  "summary": {
    "total": 1,
    "by_severity": {
      "critical": 1,
      "high": 0,
      "medium": 0,
      "low": 0,
      "info": 0
    }
  },
  "pipelines": [
    {
      "path": ".github/workflows/release.yml",
      "completeness": "complete",
      "completeness_gaps": []
    }
  ]
}
```

`summary.by_severity` always carries all five keys so consumers can index
without missing-key checks.

**`pipelines`** (next release after v1.0.8; see **Unreleased** in `CHANGELOG.md`): one object per successfully parsed pipeline file,
with the same `completeness` / `completeness_gaps` semantics as the authority
graph JSON (`complete` | `partial` | `unknown`). Text output includes a rollup
line `verify: authority graph modeling: …` before the violation summary. See
[`docs/policies/cookbook-partial-graphs.md`](policies/cookbook-partial-graphs.md)
for org-level gating patterns.

### `--format sarif`

SARIF 2.1.0. Each policy invariant is registered as a SARIF rule (so viewers
like GitHub Code Scanning, VS Code SARIF Viewer, and `sarif-tools` show your
custom rule names — not "unknown rule"). The format reuses
`SarifReportSink::emit_multi_with_custom_rules` so SARIF emitted by `verify`
is byte-compatible with SARIF emitted by `scan`.

## Flags

| Flag | Purpose |
|------|---------|
| `--policy <FILE_OR_DIR>` | Required. Source of invariants. |
| `--format text\|json\|sarif` | Output format. Default `text`. |
| `--platform auto\|github-actions\|azure-devops\|gitlab` | Pipeline format. Default `auto`. |
| `--include-builtin` | Also run the 61 built-in rules; their findings count toward violations. |
| `--severity-threshold <level>` | Only count violations at or above this severity. |
| `--max-hops <N>` | Cap propagation BFS depth (default `taudit_core::propagation::DEFAULT_MAX_HOPS`). |
| `--no-color` | Disable ANSI in `text` output. Also honoured via `NO_COLOR`. |
| `-o, --output <FILE>` | Write report to file instead of stdout. Exit code is unaffected. |

## Authoring a policy file

Minimum viable invariant:

```yaml
id: prod_secret_to_untrusted
name: Production secrets must not reach untrusted code
severity: critical
category: authority_propagation
match:
  source:
    node_type: secret
    metadata:
      environment: production
  sink:
    trust_zone: untrusted
```

See [`docs/custom-rules.md`](custom-rules.md) for the full schema (every
field, every match predicate). For background on what counts as authority,
identity propagation, and trust-zone boundaries, see
[`docs/DOCTRINE.md`](DOCTRINE.md).

## CI integration

### GitHub Actions

```yaml
name: Pipeline policy
on: [pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - name: Install taudit
        run: cargo install taudit --version 1.0.8 --locked
      - name: Verify pipeline policy
        run: taudit verify --policy .taudit/policy/ .github/workflows/
```

Mark this job as a required check. A non-zero exit (1 = violations, 2 =
config error) blocks the merge.

### GitLab CI

```yaml
verify-pipeline-policy:
  stage: test
  script:
    - cargo install taudit --version 1.0.8 --locked
    - taudit verify --policy .taudit/policy/ .gitlab-ci.yml
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

### Azure DevOps

```yaml
- task: Bash@3
  displayName: Verify pipeline policy
  inputs:
    targetType: inline
    script: |
      cargo install taudit --version 1.0.8 --locked
      taudit verify --policy .taudit/policy/ azure-pipelines.yml
```

## Surfacing violations as code-scanning alerts

The SARIF format integrates directly with GitHub's code-scanning UI:

```yaml
- name: Verify pipeline policy
  run: taudit verify --policy .taudit/policy/ --format sarif -o results.sarif .github/workflows/
  continue-on-error: true   # let the upload step run even on violations

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif

- name: Re-fail if violations
  run: taudit verify --policy .taudit/policy/ .github/workflows/
```

The double-invocation is intentional: the first run emits SARIF for the UI,
the second produces the merge-gating exit code.

## See also

- [`docs/custom-rules.md`](custom-rules.md) — invariant schema reference
- [`docs/DOCTRINE.md`](DOCTRINE.md) — authority model and design philosophy
- [`docs/rules/index.md`](rules/index.md) — built-in rule reference
