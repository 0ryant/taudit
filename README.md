# taudit

> **CI/CD is an untyped authority system. taudit makes it explicit, inspectable, and enforceable.**

taudit models how authority — secrets, identities, tokens, image trust — propagates through a CI/CD pipeline as a deterministic, typed graph. The graph is the product. Findings, SARIF reports, the terminal scanner, and PR-gate enforcement are all consumers of that graph.

```
$ taudit map --format dot .github/workflows/release.yml | dot -Tsvg > release.svg
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

taudit does three things, in this order:

1. **Models authority propagation as a deterministic graph.** Typed `NodeKinds` (`Step`, `Secret`, `Identity`, `Image`, `Artifact`), explicit `TrustZones` (`FirstParty`, `ThirdParty`, `Untrusted`), and named `EdgeKinds` (`HasAccessTo`, `Produces`, `Consumes`, `UsesImage`, `DelegatesTo`, `PersistsTo`). Same YAML in, same graph out. See [`docs/authority-graph.md`](docs/authority-graph.md) for the full specification.
2. **Detects 17 built-in authority invariants** across GitHub Actions, Azure DevOps, and GitLab CI. The graph is what makes the invariants tractable — each rule is a predicate over typed nodes and edges, not a regex over YAML.
3. **Lets you write custom invariants** via declarative YAML rules (`--rules-dir`), and (in v1.0) gate PR merges with `taudit verify` against an explicit invariant set.

### Built-in invariants

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
| `checkout_self_pr_exposure` | Critical | PR-triggered pipeline checks out the repo, landing attacker-controlled code on the runner |

Run `taudit explain` to list all invariants, or `taudit explain <rule>` for full description and remediation guidance. Custom YAML invariants are loaded from `--rules-dir <path>` and participate in the same propagation engine — see [`docs/custom-rules.md`](docs/custom-rules.md).

Severity is graduated from real-world signal: constrained identity to SHA-pinned action = Medium. Broad identity to unpinned action = Critical. The tool handles unknowns honestly — if it can't fully resolve the authority graph, it marks it `Partial`, tells you why, and caps findings at High until the graph is complete.

## Stack positioning

taudit is **the graph layer** of a small, composable stack. It is meant to be combined with sibling projects, not extended into them:

- **taudit** — generates the typed authority graph and checks invariants over it.
- **tsign** — attestation layer (sibling project). Consumes the graph to attach signed claims about which authority paths existed at build time.
- **axiom** — enforcement brain (sibling project). Consumes graphs and attestations to make merge / deploy decisions across many repos.
- **CI providers** (GitHub Actions, Azure DevOps, GitLab CI) — substrate. taudit reads their YAML; it does not replace them.

The graph is the contract between these layers. Keeping it stable, versioned, and inspectable is a higher priority than adding new rules. See [`docs/positioning.md`](docs/positioning.md) for the full framing.

## Outputs

The graph is the artifact. Everything else is a view onto it.

| Output | Command | Use case |
|---|---|---|
| **Graph export (DOT)** | `taudit map --format dot` | Visualize the authority graph; pipe into Graphviz |
| **Graph export (JSON)** | `taudit scan --format json` | Programmatic consumption; full graph included in payload |
| **Map view** | `taudit map` | Human-readable step × authority access table |
| **Scan findings (terminal)** | `taudit scan` (default) | CI logs, human review |
| **SARIF** | `taudit scan --format sarif` | GitHub code scanning and other SARIF consumers |
| **CloudEvents JSONL** | `taudit scan --format cloudevents` | Event-driven pipelines, SIEM ingestion |
| **Diff** | `taudit diff before.yml after.yml` | Authority changes between two pipeline revisions |
| **Verify enforcement** | `taudit verify` *(v1.0)* | PR-gate against an explicit invariant set with semver-stable semantics |
| **Dedicated graph command** | `taudit graph` *(v1.0)* | First-class graph generator separate from scan/map |

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

## Quickstart

Lead with the graph. Everything else is downstream.

```bash
# 1. Generate the authority graph as a Graphviz DOT artifact and render it.
#    (A dedicated `taudit graph` command lands in v1.0; today the graph export
#    lives behind `taudit map --format dot`.)
taudit map --format dot .github/workflows/release.yml | dot -Tsvg > release.svg

# 2. Inspect the same graph as a human-readable access table.
taudit map .github/workflows/release.yml

# 3. Apply the 17 built-in authority invariants and emit findings.
taudit scan .github/workflows/

# 4. Same scan, machine-readable, with the full graph included in the JSON.
taudit scan .github/workflows/ --format json > taudit.json

# 5. Load custom invariants from a directory of YAML rule files.
taudit scan .github/workflows/ --rules-dir .taudit/rules/

# 6. Coming in v1.0 — gate PR merges against an explicit invariant set.
#    taudit verify .github/workflows/ --policy .taudit/policy.yml
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

# Scan an Azure DevOps pipeline (platform auto-detected; or set --platform azure-devops explicitly)
taudit scan .pipelines/azure-pipelines.yml

# CI-friendly summary counts only
taudit scan .github/workflows/ --quiet

# Quiet mode + skip files with zero findings (cleaner CI logs)
taudit scan .github/workflows/ --quiet --omit-empty

# Collapse repeated template-instance findings into one summary per file
taudit scan .pipelines/ --collapse-template-instances

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
# List all 17 rules with severity
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

1. **Parse** — GitHub Actions, Azure DevOps, or GitLab CI YAML into typed nodes (steps, secrets, identities, images) with trust zone classification (FirstParty, ThirdParty, Untrusted). Platform is auto-detected by default (`--platform auto`); override with `--platform github-actions`, `--platform azure-devops`, or `--platform gitlab-ci`.
2. **Build graph** — Directed edges model authority flow: `HasAccessTo`, `Produces`, `Consumes`, `UsesImage`, `DelegatesTo`, `PersistsTo`.
3. **Propagate** — BFS from authority-bearing sources (secrets, identities) through edges, flagging trust boundary crossings.
4. **Apply invariants** — 17 built-in invariants (plus any custom YAML rules) pattern-match against the graph, producing findings with severity, evidence paths, and remediation routing.

Trust zones are explicit on every node:
- **FirstParty** — code you own (`run:` steps, local actions)
- **ThirdParty** — SHA-pinned external actions (immutable code)
- **Untrusted** — tag-pinned actions, fork PRs, user input

The graph is the artifact; steps 3 and 4 are consumers of it. See [`docs/authority-graph.md`](docs/authority-graph.md) for the typed schema.

## Architecture

```
taudit-core              graph, propagation engine, 17 invariants, finding model (no I/O)
taudit-parse-gha         GitHub Actions YAML → AuthorityGraph
taudit-parse-ado         Azure DevOps YAML → AuthorityGraph
taudit-parse-gitlab      GitLab CI YAML → AuthorityGraph
taudit-report-terminal   colored terminal reporter
taudit-report-json       JSON report adapter
taudit-report-sarif      SARIF 2.1.0 adapter for code scanning platforms
taudit-sink-cloudevents  findings → CloudEvents JSONL event stream
taudit-cli               composition root (clap, file I/O, wiring)
```

Ports and adapters — `taudit-core` has zero I/O dependencies, so the graph is reproducible from YAML in isolation.

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

## Report contract

The full output catalogue is in [Outputs](#outputs) above. The stable JSON report contract is currently `schema_version: "v1"` and lives at [`contracts/schemas/taudit-report.schema.json`](contracts/schemas/taudit-report.schema.json). A versioned graph schema (separate from the report contract) lands in v1.0 and will be the contract that downstream tools — tsign, axiom, anything else — depend on.

## What taudit is not

- Not a secret scanner (use [gitleaks](https://github.com/gitleaks/gitleaks))
- Not a CVE scanner (use [trivy](https://github.com/aquasecurity/trivy))
- Not a policy engine (use [checkov](https://github.com/bridgecrewio/checkov))
- Not a runtime monitor — taudit reads pipeline YAML, offline, always

taudit models a finite set of authority primitives. When every primitive is captured and every failure class has invariants, the model is complete. Unlike CVE databases, this problem has an end. See [`docs/positioning.md`](docs/positioning.md) for why this matters and how taudit fits into a wider stack.

## License

MIT OR Apache-2.0

## Release trust

Release archives ship with SHA-256 checksum files and an SPDX dependency SBOM.
See `docs/release-trust.md` for verification steps.
