# GitHub Marketplace Action Contract

Status: implemented v1 contract for dedicated `0ryant/taudit-action`
repository.

Doctrine basis:

- `engineering-doctrine/doctrine/principles/build.md`: build surfaces must be
  explicit; CI orchestrates and scripts implement; tooling is replaceable,
  contracts are not.
- `engineering-doctrine/doctrine/principles/merge-path-evidence-and-pipeline-integrity.md`:
  binding gates must fail the merge path and leave retrievable evidence.
- `engineering-doctrine/doctrine/principles/semantic-versioning.md`: public
  configuration keys and default behavior are versioned contract.

This document defines the Marketplace action surface. The short README snippet
is only the smallest useful example; this file is the contract the action
implementation, README, tests, and release notes must satisfy.

## Contract Identity

| Field | Value |
|-------|-------|
| Publishable unit | `taudit-action` GitHub Action |
| Contract id | `dev.taudit.github-action.v1` |
| Contract version | `1.0.0` |
| Primary file | root `action.yml` in the dedicated action repository |
| Implementation repo | `https://github.com/0ryant/taudit-action` |
| Execution model | thin typed adapter over `taudit` CLI |
| Default mode | `verify` |
| Default permissions | `contents: read` |
| Out of scope | policy authoring, automatic SARIF upload, third-party storage upload, raw CLI passthrough |

## Minimal Workflow

```yaml
permissions:
  contents: read

jobs:
  taudit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-sha>
      - uses: 0ryant/taudit-action@v1
        with:
          mode: verify
          policy: .taudit/policy/
          paths: .github/workflows/
```

The minimal workflow is intentionally small, but not complete contract
documentation. Teams adopting taudit must also understand policy, built-ins,
ignore files, suppressions, baselines, and exit semantics below.

## Input Schema

The action MUST expose only typed inputs. It MUST NOT expose `extra-args`,
`command`, `script`, `shell`, or any raw flag passthrough in v1.

Root `action.yml` MUST declare the same inputs as the table below. The action
repository SHOULD test that `action.yml` and
`contracts/taudit-action-inputs.v1.schema.json` stay in sync.

| Input | Type | Default | Applies to | CLI mapping | Contract |
|-------|------|---------|------------|-------------|----------|
| `mode` | enum: `verify`, `scan`, `graph` | `verify` | all | first CLI subcommand | Invalid value fails before invoking `taudit`. |
| `version` | SemVer string | action release default | all | installer/resolver only | Pins the `taudit` binary. No floating `latest`. |
| `paths` | newline-separated relative paths/globs | `.github/workflows/` | all | positional path args | Empty entries ignored; each value becomes one argv element. |
| `platform` | enum: `auto`, `github-actions`, `azure-devops`, `gitlab`, `bitbucket` | `auto` | all | `--platform` | Must match CLI enum tokens. |
| `ado-org` | string | none | all | `--ado-org` | Optional ADO variable-group enrichment; requires `ado-project` and `ado-pat`. |
| `ado-project` | string | none | all | `--ado-project` | Optional ADO variable-group enrichment; requires `ado-org` and `ado-pat`. |
| `ado-pat` | secret string | none | all | `TAUDIT_ADO_PAT` env for the child process | Optional read-only ADO PAT. Must be masked and never printed or placed in argv. |
| `policy` | workspace-relative file or directory | none | `verify` | `--policy` | Required for `verify`; not a config directory and not a suppressions path. |
| `include-builtin` | boolean | `false` | `verify` | `--include-builtin` | Built-ins are off in `verify` unless explicitly true. |
| `ignore-file` | workspace-relative file | auto-discover | `scan`, `verify` | `--ignore-file` | If set, explicit path must exist; otherwise CLI auto-discovers `.tauditignore`. |
| `suppressions` | workspace-relative file | auto-discover | `scan`, `verify` | `--suppressions` | If set, explicit path must exist; otherwise CLI auto-discovers `.taudit-suppressions.yml` and `.taudit/suppressions.yml`. |
| `suppression-mode` | enum: `downgrade`, `tag-only` | `downgrade` | `scan`, `verify` | `--suppression-mode` | `downgrade` can affect severity gating; `tag-only` is metadata-only for `verify`. |
| `baseline-root` | workspace-relative directory | current workspace | `scan`, `verify` | `--baseline-root` where supported | Root containing `.taudit/baselines/`. |
| `gate-on-all` | boolean | `false` | `verify` | `--gate-on-all` where supported | Overrides baseline-new-only behavior. |
| `strict` | boolean | `false` | `verify` | `--strict` | Discovered-file read/parse errors become exit `2`. |
| `ignore-partial` | boolean | `false` | `verify` | `--ignore-partial` | Suppresses findings produced by partial-graph reasoning; must be visible in summary when enabled. |
| `format` | mode-scoped enum | mode default | all | `--format` | `scan`: `terminal`, `json`, `sarif`, `cloudevents`; `verify`: `text`, `json`, `sarif`; `graph`: `json`, `dot`, `mermaid`, `summary`. |
| `output` | workspace-relative file | none | all | `-o` / `--output` | Writes machine output; parent directory must be inside workspace or explicitly allowed by implementation. |
| `graph-view` | enum: `authority`, `exploit` | `authority` | `graph` | `--view` | Selects authority graph or exploit-candidate graph projection. |
| `severity-threshold` | enum: `critical`, `high`, `medium`, `low`, `info` | CLI default | `scan`, `verify` | `--severity-threshold` | Filters/gates at or above threshold according to CLI command semantics. |
| `max-hops` | positive integer | CLI default | all | `--max-hops` | Reject non-integer, zero, negative, or excessive values before invoking CLI. |
| `no-color` | boolean | `true` | `scan`, `verify` | `--no-color` | Default Action logs should be stable and grep-friendly. |
| `fallback-cargo` | boolean | `false` | install | installer only | If release asset is unavailable, run locked `cargo install`; must be visible in logs. |

### Input JSON Schema

The action repository SHOULD commit this schema as
`contracts/taudit-action-inputs.v1.schema.json` and validate it in tests.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://taudit.dev/schemas/github-action-inputs.v1.json",
  "title": "taudit GitHub Action Inputs",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "mode": { "enum": ["verify", "scan", "graph"], "default": "verify" },
    "version": { "type": "string", "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.-]+)?(\\+[0-9A-Za-z.-]+)?$" },
    "paths": { "type": "string", "default": ".github/workflows/" },
    "platform": { "enum": ["auto", "github-actions", "azure-devops", "gitlab", "bitbucket"], "default": "auto" },
    "ado-org": { "type": "string" },
    "ado-project": { "type": "string" },
    "ado-pat": { "type": "string" },
    "policy": { "type": "string" },
    "include-builtin": { "type": "boolean", "default": false },
    "ignore-file": { "type": "string" },
    "suppressions": { "type": "string" },
    "suppression-mode": { "enum": ["downgrade", "tag-only"], "default": "downgrade" },
    "baseline-root": { "type": "string" },
    "gate-on-all": { "type": "boolean", "default": false },
    "strict": { "type": "boolean", "default": false },
    "ignore-partial": { "type": "boolean", "default": false },
    "format": { "type": "string" },
    "output": { "type": "string" },
    "graph-view": { "enum": ["authority", "exploit"], "default": "authority" },
    "severity-threshold": { "enum": ["critical", "high", "medium", "low", "info"] },
    "max-hops": { "type": "integer", "minimum": 1, "maximum": 10000 },
    "no-color": { "type": "boolean", "default": true },
    "fallback-cargo": { "type": "boolean", "default": false }
  },
  "allOf": [
    {
      "if": {
        "anyOf": [
          { "not": { "required": ["mode"] } },
          { "properties": { "mode": { "const": "verify" } }, "required": ["mode"] }
        ]
      },
      "then": { "required": ["policy"] }
    },
    {
      "dependentRequired": {
        "ado-org": ["ado-project", "ado-pat"],
        "ado-project": ["ado-org", "ado-pat"],
        "ado-pat": ["ado-org", "ado-project"]
      }
    }
  ]
}
```

GitHub Action inputs arrive as strings. The implementation MUST parse booleans
and integers before building argv and MUST fail closed on invalid values.

## Command Mapping

The action is a deterministic adapter. For a given normalized input object it
MUST build the same argv every time.

Example:

```yaml
with:
  mode: verify
  policy: .taudit/policy/
  paths: |
    .github/workflows/
    .github/actions/
  include-builtin: true
  suppressions: .taudit-suppressions.yml
  suppression-mode: tag-only
  baseline-root: .
  gate-on-all: true
  strict: true
  format: json
  output: taudit-verify.json
```

MUST invoke equivalent argv:

```text
taudit verify
  --policy .taudit/policy/
  --platform auto
  --include-builtin
  --suppressions .taudit-suppressions.yml
  --suppression-mode tag-only
  --baseline-root .
  --gate-on-all
  --strict
  --format json
  --no-color
  -o taudit-verify.json
  .github/workflows/
  .github/actions/
```

The implementation MUST use an argv array API such as `execFile`. It MUST NOT
build a shell command string.

## Output Schema

The action MUST expose these GitHub Action outputs:

| Output | Type | Meaning |
|--------|------|---------|
| `exit-code` | integer string | Actual `taudit` process exit code. |
| `outcome` | enum string | `pass`, `violations`, or `config-error`. |
| `report-path` | string | File path written by `output`, if any. |
| `graph-path` | string | Graph file path when `mode=graph` and `output` is set. |
| `findings-count` | integer string | Count parsed from JSON/SARIF where available; empty otherwise. |
| `policy-path` | string | Policy input used for `verify`. |
| `ignore-file-used` | string | Explicit or discovered ignore file, if known. |
| `suppressions-file-used` | string | Explicit or discovered suppressions file, if known. |
| `suppression-mode-used` | enum string | `downgrade` or `tag-only`. |
| `baseline-root-used` | string | Baseline root used for scan/verify. |
| `baseline-status` | enum string | `found`, `missing`, `unused`, or `unknown`. |
| `partial-policy` | enum string | `normal` or `ignore-partial`. |
| `ado-enrichment` | enum string | `unused`, `configured`, or `failed`. |
| `new-findings-count` | integer string | New finding count when parsed from output; empty otherwise. |
| `preexisting-critical-count` | integer string | Pre-existing critical count when parsed; empty otherwise. |
| `waived-count` | integer string | Suppressed/baseline-waived count when parsed; empty otherwise. |
| `taudit-version` | string | Actual binary version invoked. |

The step summary MUST include:

```text
taudit mode: verify
taudit version: <version>
policy: .taudit/policy/
include built-ins: true|false
ignore file: <path|not found|not used>
suppressions: <path|not found|not used> (mode=<downgrade|tag-only>)
baseline root: <path> (<found|missing|unused|unknown>)
partial graph policy: normal|ignore-partial
ADO enrichment: unused|configured|failed
gate: <all findings|new findings + unwaived critical pre-existing|advisory>
exit: <0|1|2> (<pass|violations|config-error>)
```

The summary MUST NOT print secret values, raw environment dumps, or untrusted
argument strings as a shell command.

## Exit Semantics

The action MUST preserve `taudit` exit semantics:

| Exit | Action outcome | Meaning |
|------|----------------|---------|
| `0` | success | No policy violation or advisory command completed. |
| `1` | failure by default | Findings/violations crossed the active gate. |
| `2` | failure | Configuration, usage, parse, missing policy, or cannot-decide error. |

`scan` is advisory/bootstrap unless the action later adds an explicit typed
`fail-on-findings` input. v1 SHOULD NOT add that input until scan-mode gate
semantics are tested separately from `verify`.

## Security Invariants

The action MUST fail Marketplace readiness if any invariant below is broken:

- No raw CLI passthrough in v1.
- No shell command construction from user inputs.
- No implicit secrets or write-token requirement; default permissions are
  `contents: read`.
- `ado-pat` is optional, masked, never echoed, and only accepted with
  `ado-org` plus `ado-project`. The action passes it to `taudit` through
  `TAUDIT_ADO_PAT`, not through argv.
- No same-job SARIF upload with `security-events: write` in untrusted PR jobs.
- Explicit path inputs are normalized and constrained to the workspace unless a
  deliberate exception is documented and tested.
- Missing explicit `policy`, `ignore-file`, or `suppressions` paths fail clearly
  rather than silently falling back.
- `verify` without `policy` fails before invoking `taudit`.
- `verify` does not include built-ins unless `include-builtin` is true.
- `ignore-partial` is explicit and visible; partial/unknown graph coverage is
  not silently hidden.
- Critical waiver behavior remains delegated to taudit and visible in summary:
  critical suppressions require expiry; expired waivers do not apply.

## Compatibility Rules

The action follows SemVer independently from the `taudit` CLI:

- Patch: wrapper fixes, docs, checksum table updates, and compatible output
  additions.
- Minor: new typed inputs, new optional outputs, additional supported formats or
  platforms that do not change defaults.
- Major: removing/renaming inputs or outputs, changing defaults, introducing raw
  passthrough, changing exit behavior, or changing how `verify` maps to CLI
  gates.

Every action release MUST state the default bundled `taudit` version and the
minimum supported CLI version.

## Required Contract Tests

- Input schema rejects unknown keys and invalid enum values.
- ADO enrichment inputs are all-or-none; `ado-pat` is masked and absent from
  argv, summaries, and logs.
- Boolean and integer parsing rejects ambiguous values.
- Each input maps to exactly one intended argv fragment.
- Unset optional inputs emit no argv.
- `verify` without `policy` fails before invoking the CLI.
- `verify` with `policy` excludes built-ins by default and includes them only
  with `include-builtin: true`.
- Explicit missing `policy`, `ignore-file`, or `suppressions` paths fail.
- `.tauditignore`, `.taudit-suppressions.yml`, `.taudit/suppressions.yml`, and
  `.taudit/baselines/` auto-discovery are visible in summary/output.
- `suppression-mode: tag-only` does not make `verify` pass by itself.
- `suppression-mode: downgrade` can affect severity-threshold gating.
- Baseline behavior covers new findings, pre-existing non-critical findings,
  unwaived criticals, waived criticals, and `gate-on-all`.
- `ignore-partial` changes only partial-derived finding treatment and is
  represented in action outputs/summary.
- `graph-view: authority` and `graph-view: exploit` both produce graph output.
- Injection attempts in every path-like input are passed as data, not flags or
  shell syntax.
- Normal and failure logs do not print token-like values.
