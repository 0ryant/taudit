# taudit

Show exactly how secrets and permissions move through your CI/CD pipeline — and where they cross trust boundaries.

```
$ taudit scan .github/workflows/release.yml

Authority Graph: .github/workflows/release.yml
  Steps: 16 | Secrets: 1 | Actions: 11 | Identities: 3

Findings (2 critical, 9 high, 5 medium):

CRITICAL  GITHUB_TOKEN (github-release) propagated to actions/download-artifact@v4 across trust boundary
          GITHUB_TOKEN (github-release) --> actions/download-artifact@v4
          Fix: tsafe exec --ns <scoped-namespace> -- <command>

CRITICAL  Untrusted step 'Download release assets' has direct access to identity 'GITHUB_TOKEN (github-release)'
          Fix: Reduce from '{ contents: write }' to 'minimal required scope'

HIGH  GITHUB_TOKEN (publish) has broad scope (permissions: '{ packages: write, id-token: write }')
          Fix: Reduce from '{ packages: write, id-token: write }' to '{ contents: read }'

MEDIUM  GITHUB_TOKEN (release-artifacts) propagated to actions/checkout@sha across trust boundary
          GITHUB_TOKEN (release-artifacts) --> actions/checkout@11bd71...
          Fix: tsafe exec --ns <scoped-namespace> -- <command>
```

## What it does

taudit builds a directed **authority graph** from your pipeline YAML. Nodes are steps, secrets, identities, and actions. Edges model how authority propagates — which steps can access which secrets, which identities grant which permissions, where data flows across trust boundaries.

Then it walks the graph looking for:

| Rule | Severity | What it catches |
|---|---|---|
| `authority_propagation` | Critical | Secret or identity reaches a step in a lower trust zone |
| `over_privileged_identity` | High | GITHUB_TOKEN / System.AccessToken with broader permissions than needed |
| `unpinned_action` | High | Third-party action without SHA digest pin |
| `untrusted_with_authority` | Critical | Unpinned or untrusted step has direct access to secrets or identities |
| `artifact_boundary_crossing` | High | Artifact from privileged step consumed across a trust boundary |
| `floating_image` | Medium | Container image reference without a digest pin |
| `long_lived_credential` | High | Secret name matches static credential patterns (API keys, passwords) |
| `persisted_credential` | Critical | `persistCredentials: true` writes token to disk, accessible to all subsequent steps |
| `trigger_context_mismatch` | Critical | `pull_request_target` / ADO `pr:` trigger with authority-bearing steps |
| `cross_workflow_authority_chain` | Critical | Authority-bearing step delegates to an external or untrusted workflow |
| `authority_cycle` | High | Workflow delegation graph contains a cycle |
| `uplift_without_attestation` | Info | OIDC-privileged build produces no signed provenance attestation |
| `self_mutating_pipeline` | Critical | Step writes to `GITHUB_ENV` or `GITHUB_PATH`, injecting into subsequent steps |
| `variable_group_in_pr_job` | Critical | ADO variable group secrets reachable from a PR-triggered job |
| `self_hosted_pool_pr_hijack` | Critical | PR pipeline runs on self-hosted agent and checks out the repository |
| `service_connection_scope_mismatch` | High | Broad-scope ADO service connection reachable from a PR-triggered job |

Run `taudit explain` to list all rules, or `taudit explain <rule>` for full description and remediation guidance.

Severity is graduated from real-world signal: constrained identity to SHA-pinned action = Medium. Broad identity to unpinned action = Critical. The tool handles unknowns honestly — if it can't fully resolve the authority graph, it marks it `Partial`, tells you why, and caps findings at High until the graph is complete.

## Install

```bash
cargo install taudit
```

Or build from source:

```bash
git clone https://github.com/0ryant/taudit.git
cd taudit
cargo install --path crates/taudit-cli
```

## Support

- Product support: open a GitHub issue in this repository.
- Security issues: follow the process in `SECURITY.md`.

## Usage

### Scan

```bash
# Scan a single workflow
taudit scan .github/workflows/ci.yml

# Scan all workflows in a directory
taudit scan .github/workflows/

# JSON output (includes full authority graph)
taudit scan .github/workflows/ --format json

# SARIF output for code scanning ingestion
taudit scan .github/workflows/ --format sarif

# CloudEvents JSONL (one event per finding)
taudit scan .github/workflows/ --format cloudevents

# CI mode: fail only on high+ severity
taudit scan .github/workflows/ --severity-threshold high

# Skip generated or vendored workflows
taudit scan .github/workflows/ --exclude 'generated/**'

# Suppress findings already accepted in a baseline report
taudit scan .github/workflows/ --baseline taudit-baseline.json

# Scan an Azure DevOps pipeline
taudit scan .pipelines/azure-pipelines.yml --platform azure-devops

# CI-friendly summary counts only
taudit scan .github/workflows/ --quiet

# Quiet mode + skip files with zero findings (cleaner CI logs)
taudit scan .github/workflows/ --quiet --omit-empty

# Collapse repeated template-instance findings into one summary per file
taudit scan .pipelines/ --platform azure-devops --collapse-template-instances

# Show node metadata in propagation paths
taudit scan .github/workflows/release.yml --verbose

# Disable ANSI colors (also honored via NO_COLOR env var)
taudit scan .github/workflows/ --no-color

# Override runtime artifact destinations
taudit scan .github/workflows/ --telemetry-dir /tmp/taudit/telemetry --receipt-dir /tmp/taudit/receipts --log-dir /tmp/taudit/logs
```

Every `taudit scan` run writes runtime artifacts to XDG-style defaults unless overridden. All three paths are optional — if neither the env var nor HOME can be resolved (e.g. in a minimal CI container) the artifact is silently skipped without failing the scan:

- Telemetry (JSONL): `$TAUDIT_TELEMETRY_DIR` or `$XDG_STATE_HOME/taudit/telemetry` or `$HOME/.local/state/taudit/telemetry`
- Receipts (JSON): `$TAUDIT_RECEIPT_DIR` or `$XDG_DATA_HOME/taudit/receipts` or `$HOME/.local/share/taudit/receipts`
- Logs (plain text): `$TAUDIT_LOG_DIR` or `$XDG_STATE_HOME/taudit/logs` or `$HOME/.local/state/taudit/logs`

**Color in CI**: taudit outputs ANSI color by default. GitHub Actions and Azure DevOps log viewers render ANSI from piped stdout. Disable with `--no-color` or `NO_COLOR=1` (any value). Log files are always written as plain text regardless of this setting.

### Authority Map

```bash
$ taudit map .github/workflows/quality.yml

Step                     Zone        GITHUB_TOKEN
-----------------------  ----------  ------------
quality[0]               ThirdParty       X
Rust toolchain           ThirdParty       X
fmt                      FirstParty       X
clippy                   FirstParty       X
test                     FirstParty       X
```

### Diff

```bash
# Compare two workflow revisions in terminal format
taudit diff before.yml after.yml

# Emit a machine-readable diff payload
taudit diff before.yml after.yml --format json
```

### Runtime isolation smoke (optional)

Run taudit with an execution-isolation runtime harness to verify
platform compatibility:

```bash
just runtime-smoke
```

Notes:
- This smoke recipe is optional and intended for platform-integration validation.
- The smoke uses `tests/fixtures/clean.yml`.

### Emit execution-runtime spec

Generate an execution-cell JSON spec that runs `taudit scan` in an
isolation runtime:

```bash
# Print spec JSON to stdout
taudit emit-spec .github/workflows/ci.yml --severity-threshold high --quiet

# Write spec to a file
taudit emit-spec .github/workflows/ci.yml --output /tmp/taudit-cell.json
```

Then pass that spec to your runtime supervisor/executor.

### Explain rules

```bash
# List all 16 rules with severity
taudit explain

# Full description for a single rule
taudit explain unpinned_action
taudit explain variable_group_in_pr_job
```

### Version

```bash
# Product version shown to customers and operators
taudit version

# Also available via clap's built-in flag
taudit --version
```

### Suppress known-accepted findings

Create `.tauditignore` in your repo root:

```yaml
ignore:
  - category: unpinned_action
    path: ".github/workflows/legacy.yml"
    reason: "Accepted until upstream action replacement"

  - category: over_privileged_identity
    reason: "Token scope required for release workflow"
```

```bash
# Or specify a custom ignore file
taudit scan . --ignore-file .taudit/ignore.yml
```

## How it works

1. **Parse** — GitHub Actions or Azure DevOps YAML into typed nodes (steps, secrets, identities, images) with trust zone classification (FirstParty, ThirdParty, Untrusted). Select platform with `--platform github-actions` (default) or `--platform azure-devops`.
2. **Build graph** — Directed edges model authority flow: `HasAccessTo`, `Produces`, `Consumes`, `UsesImage`, `DelegatesTo`, `PersistsTo`
3. **Propagate** — BFS from authority-bearing sources (secrets, identities) through edges, flagging trust boundary crossings
4. **Analyze** — 16 rules pattern-match against the graph, producing findings with severity, evidence paths, and remediation routing

Trust zones are explicit on every node:
- **FirstParty** — code you own (`run:` steps, local actions)
- **ThirdParty** — SHA-pinned external actions (immutable code)
- **Untrusted** — tag-pinned actions, fork PRs, user input

## Architecture

```
taudit-core             graph, propagation engine, 16 rules, finding model (no I/O)
taudit-parse-gha        GitHub Actions YAML → AuthorityGraph
taudit-parse-ado        Azure DevOps YAML → AuthorityGraph
taudit-report-terminal  colored terminal reporter
taudit-report-json      JSON report adapter
taudit-report-sarif     SARIF 2.1.0 adapter for code scanning platforms
taudit-sink-cloudevents findings → CloudEvents JSONL event stream
taudit-cli              composition root (clap, file I/O, wiring)
```

8 crates, 181 tests, ~8,500 LOC. Ports and adapters — core has zero I/O dependencies.

## CI Integration

```yaml
# .github/workflows/security.yml
- name: Authority audit
  run: |
    cargo install taudit
    taudit scan .github/workflows/ --severity-threshold high
```

Exit codes: `0` = no findings above threshold, `1` = findings above threshold.

## Versioning model

- Crates are versioned independently (no shared workspace version).
- Bump only crates changed by a feature/fix.
- The `taudit` CLI crate version is the product/app version customers see.
- Use `just versions` to print current crate versions.

## Output formats

| Format | Flag | Use case |
|---|---|---|
| Terminal | `--format terminal` (default) | Human review, CI logs |
| JSON | `--format json` | Programmatic consumption, full graph included, top-level `schema_version` |
| SARIF | `--format sarif` | GitHub code scanning and SARIF consumers |
| CloudEvents JSONL | `--format cloudevents` | Event-driven pipelines, SIEM ingestion |

The stable JSON report contract is currently `schema_version: "v1"` and is defined in `contracts/schemas/taudit-report.schema.json`.

## What taudit is not

- Not a secret scanner (use [gitleaks](https://github.com/gitleaks/gitleaks))
- Not a CVE scanner (use [trivy](https://github.com/aquasecurity/trivy))
- Not a policy engine (use [checkov](https://github.com/bridgecrewio/checkov))
- Not a runtime monitor — taudit reads pipeline YAML, offline, always

taudit models a finite set of authority primitives. When every primitive is captured and every failure class has rules, the model is complete. Unlike CVE databases, this problem has an end.

## License

MIT OR Apache-2.0

## Release trust

Release archives ship with SHA-256 checksum files and an SPDX dependency SBOM.
See `docs/release-trust.md` for verification steps.
