# GitHub Marketplace Action UX Research

Date: 2026-05-14

## Decision

The first-class Marketplace UX for `taudit-action` is **verify-first**.

The contract surface is now promoted out of this research note into
[`docs/integrations/github-marketplace-action-contract.md`](../integrations/github-marketplace-action-contract.md).
That document is the source of truth for input schema, output schema, CLI
mapping, exit semantics, security invariants, and compatibility rules.

Default posture:

```yaml
- uses: 0ryant/taudit-action@v1
  with:
    mode: verify
    policy: .taudit/policy/
    paths: .github/workflows/
```

`scan` remains an advisory/bootstrap mode. `graph` is an observability/export
mode. `verify` is the team gate.

`policy` is not a catch-all configuration path. It is the invariant bundle that
defines what the gate enforces. Adoption controls remain separate:

| Control | Purpose | Marketplace action behavior |
|---------|---------|-----------------------------|
| `policy` / `--policy` | Positive invariants: what must be true. Required for `verify`. | Explicit input; no implicit default. |
| `.tauditignore` / `--ignore-file` | Coarse rule/path mute for known classes of noise. | Auto-discover at repo root; optional explicit `ignore-file`. |
| `.taudit-suppressions.yml` / `.taudit/suppressions.yml` / `--suppressions` | Per-finding waiver with approver, reason, and expiry rules. | Auto-discover at repo root; optional explicit `suppressions`. |
| `.taudit/baselines/` / `--baseline-root` | Adoption snapshot: gate on new findings while retaining critical-waiver rules. | Auto-discover at repo root; optional explicit `baseline-root`. |
| `--include-builtin` | Add taudit's built-in rules to policy-mode `verify`. | Explicit boolean; off by default to match CLI semantics. |

## Official Marketplace Constraints

Observed from GitHub's Marketplace publishing docs:

- Marketplace publication expects a public action repository.
- The repository must have a single root `action.yml` or `action.yaml`.
- Metadata files in subfolders are not automatically listed.
- The Marketplace page is built from action metadata.
- Publication happens through a GitHub release with the Marketplace checkbox.
- The publishing owner/org must accept the Marketplace Developer Agreement.
- Release-specific tags such as `v1.0.0` should be immutable release points;
  movable compatibility tags such as `v1` can point at the latest compatible
  version.

Implication: do **not** publish from the main `taudit` repository. Create a
dedicated public repository such as `0ryant/taudit-action`.

## Comparator Findings

### Trivy Action

Observed from `aquasecurity/trivy-action`:

- Marketplace action wraps a CLI with many typed inputs.
- Supports pinned tool version input.
- Generates output files for SARIF and other formats.
- Uses a separate `github/codeql-action/upload-sarif` pattern in examples.
- Uses internal shell code but includes explicit command-injection mitigation
  around generated environment exports.

Takeaway for taudit: typed inputs and pinned tool version are good; raw CLI
surface area should be smaller for v1.

### zizmor Action

Observed from `zizmorcore/zizmor-action`:

- Exposes security-tool-specific modes such as Advanced Security upload,
  annotations, config, persona, severity, and confidence.
- Uploads SARIF conditionally through `github/codeql-action/upload-sarif`.
- Validates versions against a known version/digest map.
- Passes user data through environment variables into an action-owned script.

Takeaway for taudit: version/digest validation and optional SARIF upload are
strong patterns. For taudit v1, SARIF upload should be documented as a separate
step rather than hidden inside the scanner job.

### Gitleaks Action

Observed from `gitleaks/gitleaks-action`:

- Minimal root metadata with a Node runtime entrypoint.
- Marketplace UX is simple, but the action is less transparent from metadata
  alone because most behavior lives in bundled `dist`.

Takeaway for taudit: Node entrypoints are acceptable for cross-platform runner
support, but the README must make behavior and permissions explicit.

### reviewdog/action-actionlint

Observed from `reviewdog/action-actionlint`:

- Clear `fail_level` input makes review behavior explicit.
- Docker packaging is straightforward but less desirable for Windows/macOS
  coverage.
- Raw flag fields exist for mature users, but that is not a good v1 pattern for
  a security-sensitive scanner action.

Takeaway for taudit: explicit failure semantics are valuable. Avoid raw flags
until the wrapper has a hardened parser and compatibility tests.

## Council Ratification

### Convergence

The council converged on:

- **Verify-first default.** `scan` informs; `verify` decides.
- **Dedicated Marketplace repo.** Root `action.yml`, minimal action package,
  not this product repository.
- **No raw `extra-args` in v1.** Replace broad passthrough with typed inputs.
- **Safe argument construction.** User inputs must become argv/env values, not
  shell-concatenated command strings.
- **Pinned binary resolver.** Prefer taudit release assets for speed; support a
  controlled cargo fallback.
- **SARIF upload as separate explicit step.** Keep `security-events: write`
  out of the default scanner job.
- **Cross-platform hosted-runner support.** Linux, macOS, and Windows are part
  of the v1 readiness gate.
- **Separate controls, not one config knob.** Policy selects rules;
  suppressions alter reviewed findings; `.tauditignore` scopes coarse noise;
  baselines control rollout gating.
- **Explain loaded controls.** CI summaries should show which policy,
  suppression file, ignore file, and baseline root were used, plus baseline
  status where available.

### Ratified UX Contract

Inputs for v1:

- `mode`: `verify` (default), `scan`, or `graph`
- `version`: default to current stable taudit release
- `paths`: newline-separated paths/globs
- `platform`: validated enum
- `ado-org`, `ado-project`, `ado-pat`: optional all-or-none ADO enrichment inputs
- `policy`: invariant file or directory; required for `verify`
- `include-builtin`: boolean; opt into built-in rules during `verify`
- `ignore-file`: optional explicit path; otherwise `.tauditignore` auto-discovery
- `suppressions`: optional explicit path; otherwise `.taudit-suppressions.yml`
  and `.taudit/suppressions.yml` auto-discovery
- `suppression-mode`: `downgrade` (default) or `tag-only`
- `baseline-root`: optional explicit root for `.taudit/baselines/`
- `gate-on-all`: boolean; ignore baseline-new-only behavior and gate on all findings
- `strict`: boolean; fail on discovered-file parse/read errors in `verify`
- `ignore-partial`: boolean; explicitly suppress partial-derived findings
- `format`: validated per mode
- `output`: optional file path for machine-readable outputs
- `graph-view`: `authority` or `exploit` for graph mode
- `severity-threshold`: validated enum where applicable
- `max-hops`: bounded positive integer
- `no-color`: boolean
- `fallback-cargo`: controlled boolean

Action outputs and summary fields for v1:

- `exit-code`
- `report-path`
- `graph-path`
- `findings-count` where available from parsed JSON
- `policy-path`
- `ignore-file-used`
- `suppressions-file-used`
- `suppression-mode-used`
- `baseline-root-used`
- `baseline-status`: found, missing, unused, or unsupported for mode
- `partial-policy`: normal or ignore-partial
- `ado-enrichment`: unused, configured, or failed
- `new-findings-count` where available
- `preexisting-critical-count` where available
- `waived-count` where available

No v1 input:

- `extra-args`
- arbitrary shell flags
- arbitrary command override

### README Order

1. Required PR guard: `verify` new authority paths.
2. Configuration model: policy, `.tauditignore`, suppressions, and baselines.
3. Bootstrap existing repos: advisory `scan`, baseline, suppressions.
4. Tighten policy over time.
5. Export graph artifacts.
6. Generate SARIF.
7. Upload SARIF with explicit `security-events: write`.
8. Pinning and security model.

### Configuration UX

The action README should explicitly teach the four control surfaces instead of
presenting one generic config input:

- **Policy:** org rules. `verify` fails closed when missing or empty without
  `include-builtin`.
- **Ignore file:** broad escape hatch. Use for known categories/path globs, not
  normal finding review.
- **Suppressions:** reviewed per-finding waivers. Critical suppressions must
  expire; `tag-only` does not make `verify` pass by itself.
- **Baselines:** rollout mechanism. Existing findings stop blocking by default,
  but unwaived critical pre-existing findings still block; `gate-on-all` restores
  all-finding gating.

The CI step summary should print the same model in operational terms:

```text
taudit mode: verify
policy: .taudit/policy
include built-ins: true
ignore file: .tauditignore
suppressions: .taudit-suppressions.yml (mode=downgrade)
baseline root: .taudit (baseline found)
partial graph policy: normal
ADO enrichment: unused
gate: new findings + unwaived critical pre-existing
```

Copy-paste examples must include:

- Fresh repo strict gate: `mode: verify`, `policy`, `include-builtin: true`.
- Existing repo rollout: `scan`, `baseline init`, then `verify` against the
  baseline.
- Reviewed exception: `taudit suppressions add`, committed
  `.taudit-suppressions.yml`, and clear distinction between `downgrade` and
  `tag-only`.
- Coarse ignore: `.tauditignore` as a deliberate last-resort control.

### Marketplace Tagline

Gate risky GitHub Actions authority paths before they reach main.

## Security Requirements

Block Marketplace publication if any of these are true:

- User-controlled input reaches `sh -c`, `eval`, backticks, unquoted command
  strings, or concatenated flags.
- A v1 `extra-args` field can alter scanner behavior outside typed inputs.
- `policy`, `suppressions`, `ignore-file`, `baseline-root`, or `output` can
  escape the workspace without an explicit design decision and tests.
- PR-controlled config can load plugins, remote scripts, templates, or network
  fetches without explicit allowlisting.
- The scanner job receives secrets, write tokens, cloud credentials, deployment
  credentials, or self-hosted runner access for untrusted PRs.
- SARIF upload runs in the same untrusted PR job that executed scanner input.
- Mutable tool/action references are accepted without version or digest
  validation.

Default PR permissions:

```yaml
permissions:
  contents: read
```

SARIF upload permissions, when explicitly enabled in a trusted workflow:

```yaml
permissions:
  contents: read
  security-events: write
  actions: read # only when needed for private repositories
```

## Implementation Shape

Preferred v1 shape:

- Dedicated repo: `0ryant/taudit-action`.
- Root `action.yml`.
- Node-based dispatcher or composite action that invokes a checked-in
  Node/TypeScript dispatcher.
- Dispatcher uses argv-style process execution, not shell strings.
- Resolver maps runner OS/arch to a taudit release asset and checksum.
- Cargo fallback is explicit and logged as fallback, not default behavior.
- Outputs expose:
  - `exit-code`
  - `report-path`
  - `graph-path`
  - `findings-count` where available from parsed JSON
  - loaded control paths and baseline status, where available

## Test Matrix

Required before Marketplace publication:

- Unit tests for input validation and argv construction.
- Injection tests for `paths`, `policy`, `ignore-file`, `suppressions`,
  `baseline-root`, `output`, and config-like fields.
- Hosted smoke on `ubuntu-latest`, `macos-latest`, and `windows-latest`.
- `scan` mode on clean and leaky fixtures.
- `verify` mode exits:
  - `0` for clean/noop policy
  - `1` for policy violations
  - `2` for missing policy or config error
- `verify` runs only policy rules by default and runs built-ins only with
  `include-builtin: true`.
- Auto-discovery smoke for `.tauditignore`, `.taudit-suppressions.yml`,
  `.taudit/suppressions.yml`, and `.taudit/baselines/`.
- Explicit missing `suppressions`, `policy`, and `ignore-file` paths fail
  clearly instead of silently falling back.
- `suppression-mode: downgrade` can affect threshold gating; `tag-only` remains
  metadata-only.
- Critical suppressions without expiry and expired critical waivers fail or stop
  applying according to CLI contract.
- Baseline smoke: existing non-critical findings do not fail; new findings fail;
  unwaived critical pre-existing findings fail; `gate-on-all` gates all findings.
- `strict: true` fails on discovered-file parse/read errors.
- CI summary/output smoke verifies loaded policy, ignore, suppressions,
  suppression mode, baseline root, and baseline status are visible.
- `graph` mode for `json`, `dot`, `mermaid`, and `summary`.
- Release binary download success for each supported runner.
- Checksum failure test.
- Cargo fallback test.
- SARIF generation test.
- SARIF upload test in a separate trusted workflow.
- Log audit confirming no token-like values are printed.

## Sources

- GitHub Docs: Publishing actions in GitHub Marketplace:
  <https://docs.github.com/en/actions/how-tos/create-and-publish-actions/publish-in-github-marketplace>
- GitHub Docs: Metadata syntax:
  <https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax>
- GitHub Docs: Immutable releases and tags:
  <https://docs.github.com/en/actions/how-tos/create-and-publish-actions/using-immutable-releases-and-tags-to-manage-your-actions-releases>
- GitHub Docs: Script injections:
  <https://docs.github.com/en/actions/concepts/security/script-injections>
- GitHub Docs: Uploading SARIF:
  <https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/uploading-a-sarif-file-to-github>
- Trivy action metadata:
  <https://raw.githubusercontent.com/aquasecurity/trivy-action/master/action.yaml>
- zizmor action metadata:
  <https://raw.githubusercontent.com/zizmorcore/zizmor-action/main/action.yml>
- zizmor action runner:
  <https://raw.githubusercontent.com/zizmorcore/zizmor-action/main/action.sh>
- gitleaks action metadata:
  <https://raw.githubusercontent.com/gitleaks/gitleaks-action/master/action.yml>
- reviewdog actionlint metadata:
  <https://raw.githubusercontent.com/reviewdog/action-actionlint/master/action.yml>
- reviewdog actionlint entrypoint:
  <https://raw.githubusercontent.com/reviewdog/action-actionlint/master/entrypoint.sh>
