# taudit

[![SLSA-aligned supply chain](https://slsa.dev/images/gh-badge-level3.svg)](https://github.com/0ryant/taudit/blob/main/docs/release-trust.md#verifying-build-attestations-github)

> **CI/CD is an untyped authority system. taudit makes it explicit, inspectable, and enforceable.**

**What taudit is:** a **CI/CD authority graph analyzer**. It models how **credentials, tokens, identities, and artifacts** propagate across **GitHub Actions, Azure DevOps, and GitLab CI** so you can surface **implicit trust-boundary violations** and **non-obvious privilege-escalation paths** that line-by-line YAML review rarely catches.

**What taudit is not:** a general-purpose **workflow YAML linter** (keep using e.g. **actionlint** for schema and expression shape), a **CVE-style vulnerability scanner**, or a standalone **policy engine**. The **typed authority graph** is the product. Findings, SARIF, merge gates, and optional YAML invariants are **consumers** of that graph—not the other way around.

Release archives and SBOMs use **GitHub Artifact Attestations** ([`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance) in [`.github/workflows/release.yml`](.github/workflows/release.yml)) — aligned with [SLSA](https://slsa.dev)-style *build provenance* goals, not a third-party “SLSA certified” audit. Verify downloads with **`gh attestation verify`** ([Install](#install), [Release trust](docs/release-trust.md#verifying-build-attestations-github)).

taudit models how authority — secrets, identities, tokens, image trust — propagates through a CI/CD pipeline as a deterministic, typed graph. The graph is the product. Findings, SARIF, terminal output, and PR-gate enforcement are all consumers of that graph.

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
2. **Evaluates built-in graph predicates** (rules) across GitHub Actions, Azure DevOps, and GitLab CI — each one is a query over nodes and edges, not a style or schema lint over raw YAML.
3. **Optionally expresses org-specific expectations** as declarative YAML invariants (`--rules-dir`) and, when you want merge discipline, runs `taudit verify` against a chosen invariant set — still grounded in the graph, not a separate policy runtime.

### Built-in rules

> This table shows a representative subset. Run `taudit explain` to list the current built-in rules with severity, or `taudit explain <rule-id>` for full description and remediation guidance. The full catalogue is in [`docs/rules/index.md`](docs/rules/index.md).

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

Custom YAML invariants are loaded from `--rules-dir <path>` and participate in the same propagation engine — see [`docs/custom-rules.md`](docs/custom-rules.md).

Severity is graduated from real-world signal: constrained identity to SHA-pinned action = Medium. Broad identity to unpinned action = Critical. The tool handles unknowns honestly — if it can't fully resolve the authority graph, it marks it `Partial`, records why with a typed severity (`expression` / `structural` / `opaque`), and caps findings at High until the graph is complete.

## Adopting on existing repos: per-pipeline baselines

Rolling taudit onto a repo with hundreds of historical findings shouldn't mean "fix 200 things before your first PR turns green." Capture a baseline once, and `verify` only fails on **NEW** findings from that point forward:

```bash
taudit baseline init .github/workflows/   # one-time snapshot
git add .taudit/baselines/                # commit the contract
taudit verify --policy invariants/ .github/workflows/   # exits 0 unless a NEW finding lands
```

Baselines are opt-in (no `.taudit/` directory ⇒ today's behaviour, byte-identical), per-pipeline (one file per workflow keyed by content hash, so merge conflicts touch at most one file), and the fingerprint is the same as in SARIF/JSON/CloudEvents output. **Critical findings always count toward exit 1** unless explicitly waived with a 90-day-bounded justification — a security analyst's non-negotiable. See [`docs/baselines.md`](docs/baselines.md).

## Stack positioning

taudit is **the graph layer** of a small, composable stack. It is meant to be combined with sibling projects, not extended into them:

- **taudit** — generates the typed authority graph and checks invariants over it.
- **tsign** — attestation layer (sibling project). Consumes the graph to attach signed claims about which authority paths existed at build time.
- **axiom** — enforcement brain (sibling project). Consumes graphs and attestations to make merge / deploy decisions across many repos.
- **CI providers** (GitHub Actions, Azure DevOps, GitLab CI) — substrate. taudit reads their YAML; it does not replace them.

The graph is the contract between these layers. Keeping it stable, versioned, and inspectable is a higher priority than adding new rules. See [`docs/positioning.md`](docs/positioning.md) for the full framing.

For **workflow YAML shape and platform contexts**, keep using your platform linter (e.g. **[actionlint](https://github.com/rhysd/actionlint)** for GitHub Actions) alongside taudit — taudit models **authority propagation**, not full expression evaluation or every schema knob.

## Operator surfaces

The CLI is the authority surface. Three thin operator adapters are maintained
around it:

- **GitHub Action**: [`docs/integrations/github-marketplace-action-contract.md`](docs/integrations/github-marketplace-action-contract.md)
  — `0ryant/taudit-action` for typed verify, scan, and graph execution in
  GitHub Actions.

- **VS Code extension**: [`integrations/vscode-extension/README.md`](integrations/vscode-extension/README.md)
  — install [`Algol.taudit-vscode`](https://marketplace.visualstudio.com/items?itemName=Algol.taudit-vscode)
  from Visual Studio Marketplace for local verify, scan, and graph commands
  over a locally installed `taudit` binary.
- **Azure DevOps task**: [`integrations/azure-devops-extension/README.md`](integrations/azure-devops-extension/README.md)
  — install [`Algol.taudit-azure-pipelines`](https://marketplace.visualstudio.com/items?itemName=Algol.taudit-azure-pipelines)
  from Visual Studio Marketplace for `Taudit@1` in Azure Pipelines with typed
  task inputs and version-pinned release-asset execution.

These wrappers do not embed a separate taudit engine. If a pipeline or editor
surface runs `taudit`, that execution surface is still auditable by `taudit`
itself.

## Golden path (docs + CI)

Blessed copy-paste flows (graph → scan → verify, exit codes, stdout vs `-o`): **[`docs/golden-paths.md`](docs/golden-paths.md)**. Example workflow with pinned `taudit` + SARIF upload: **[`docs/examples/ci-gate-taudit-verify.yml`](docs/examples/ci-gate-taudit-verify.yml)**. Adoption checklist: **[`docs/adr/0003-strategic-spine-adoption-phased.md`](docs/adr/0003-strategic-spine-adoption-phased.md)**. Day 0–1 operator runbook (verify, baselines, suppressions, CI per platform): **[`docs/adoption-day0-day1.md`](docs/adoption-day0-day1.md)**. **Stable vs edge releases** (crates.io trust, GitHub velocity, semver for detection): **[`docs/release-strategy.md`](docs/release-strategy.md)**.

**Research (reproducible demos):** public workflow fixtures + rule IDs — [`docs/research/case-study-live-demo.md`](docs/research/case-study-live-demo.md). CVE → rule mapping — [`docs/research/cve-to-taudit-rules.md`](docs/research/cve-to-taudit-rules.md). `pull_request_target` corpus sample (`n=80`) — [`docs/research/pull-request-target-sample-study.md`](docs/research/pull-request-target-sample-study.md). Competitive scorecard evidence pass — [`docs/research/2026-06-01-competitive-scorecard.md`](docs/research/2026-06-01-competitive-scorecard.md).

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
| **Dedicated graph command** | `taudit graph` *(v1.0)* | First-class graph generator separate from scan/map (writes to **stdout** only — use `>` for a file; no `-o` on `graph`) |

## Install

```bash
cargo install taudit
```

Or download a pre-built binary from [GitHub Releases](https://github.com/0ryant/taudit/releases).
Every release archive and SBOM is attested in CI (**GitHub Artifact Attestations** / [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)). Verify the **local file** after download (GitHub CLI 2.49+; `gh auth login` if needed):

```bash
curl -fsSL -O "https://github.com/0ryant/taudit/releases/download/<tag>/taudit-x86_64-linux.tar.gz"
gh attestation verify taudit-x86_64-linux.tar.gz --repo 0ryant/taudit
```

Replace `<tag>` with the release (for example `v1.0.8`). The same `gh attestation verify <path> --repo 0ryant/taudit` command applies to downloaded SPDX or CycloneDX SBOM files. Details: [docs/release-trust.md#verifying-build-attestations-github](docs/release-trust.md#verifying-build-attestations-github).

Or build from source:

```bash
git clone https://github.com/0ryant/taudit.git
cd taudit
cargo install --path crates/taudit-cli
```

## Quickstart

Lead with the graph. Everything else is downstream.

```bash
# 1. Generate the authority graph as DOT and render with Graphviz (optional install).
taudit graph --format dot .github/workflows/release.yml | dot -Tsvg > release.svg
#    Per-job subgraph when the full workflow graph is too dense:
#    taudit graph --format dot --job build .github/workflows/release.yml | dot -Tsvg > build.svg

# 2. Inspect the same graph as a human-readable access table.
taudit map .github/workflows/release.yml

# 3. Apply the built-in rules and emit findings.
taudit scan .github/workflows/

# 4. Same scan, machine-readable, with the full graph included in the JSON.
taudit scan .github/workflows/ --format json > taudit.json

# 5. Load custom invariants from a directory of YAML rule files.
taudit scan .github/workflows/ --rules-dir .taudit/rules/

# 6. Gate PR merges against a policy directory (exit 0 / 1 / 2 — see docs/verify.md).
#    Starter rules are strict; on many repos this exits 1 until policies are tuned.
taudit verify .github/workflows/ --policy invariants/starter/ --platform github-actions

# 7. Propagation rollup JSON (same dense-graph guard as scan) — triage / dashboards.
taudit graph .github/workflows/release.yml --format summary | jq '.totals'
```

## Self-audit semantics

`taudit` audits the pipeline that runs it. There is no built-in self-exemption.

If a workflow contains a `taudit` step or extension task, that step is part of
the authority graph and may appear in findings when it matches normal rules.
This is expected:

- a GitHub Actions job that runs `taudit` can still be flagged for broad
  `GITHUB_TOKEN`, unpinned third-party actions, or risky authority flow
- an Azure DevOps pipeline that uses `Taudit@1` can still be flagged for
  external task trust, variable-group authority, or artifact movement

What matters is the trust model of the execution surface, not the brand of the
tool running there.

Platform pinning is different across CI systems:

- **GitHub Actions**: pin third-party actions by full commit SHA
- **Azure DevOps Marketplace tasks**: there is no SHA-pin equivalent; pin the
  task major version (`Taudit@1`), pin the downloaded `taudit` binary version,
  and verify the asset integrity

`Taudit@1` downloads a version-pinned release asset and verifies its SHA-256
checksum before execution. If you want taudit findings in a repo dogfood lane
to be non-blocking, do that explicitly in policy, baseline, or suppressions —
not through a hidden product exemption.

## Support

- Product support: open a GitHub issue in this repository.
- Security issues: follow the process in `SECURITY.md`.
- **Phased & laned jobs** (multi-agent / parallel workstreams): [`docs/jobs-phased-lanes.md`](docs/jobs-phased-lanes.md).
- **Golden paths** (blessed copy-paste flows on committed fixtures): [`docs/golden-paths.md`](docs/golden-paths.md); smoke them with **`just golden-paths`**.
- Large-directory / corpus methodology and **citing upstream workflow examples** (licensing, fingerprints, JSON vs SARIF): [`docs/corpus-research.md`](docs/corpus-research.md).
- Council synthesis on **docs, golden paths, and screenshots** as first-class: [`docs/research/2026-04-27-council-docs-golden-paths-screenshots.md`](docs/research/2026-04-27-council-docs-golden-paths-screenshots.md).

## Usage

### Help and man page

- **`taudit --help`** — all subcommands, plus a long section on authority graph exports (`json` / `dot` / `mermaid` / `summary`), `--job`, stdout/pipes (EPIPE), and pointers to `docs/`.
- **`taudit <command> --help`** — per-command flags (e.g. `taudit graph --help`, `taudit explain --help`).
- **Troff manual** for packagers and local preview: [`man/taudit.1`](man/taudit.1) (e.g. `man man/taudit.1` from the repo if your OS supports a path, or install the file into your man path).

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

### Authority Graph export (machine-readable)

```bash
# Emit the canonical authority graph as versioned JSON (default format)
taudit graph .github/workflows/release.yml

# Graphviz DOT for visualization
taudit graph .github/workflows/release.yml --format dot | dot -Tsvg -o graph.svg

# Mermaid flowchart (paste into a Markdown code fence with language `mermaid` — no Graphviz)
taudit graph .github/workflows/release.yml --format mermaid

# Restrict diagram output to a single job's reachable subgraph (see USERGUIDE for all job IDs)
taudit graph .github/workflows/release.yml --format dot --job build
taudit graph .github/workflows/release.yml --format mermaid --job build
taudit graph .github/workflows/security.yml --format mermaid --job taudit-self-scan
```

The JSON document conforms to [`schemas/authority-graph.v1.json`](schemas/authority-graph.v1.json)
and includes a top-level `schema_version` (`"1.0.0"`) and `schema_uri`
so downstream consumers (tsign, axiom, runtime cells, custom auditors)
can pin to a major version. See [docs/authority-graph.md](docs/authority-graph.md)
for the data model, the semver guarantee, and the integration playbook.

`taudit map` (the human-readable table above) is unchanged — `taudit graph`
is the machine-readable counterpart.

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
# List the current built-in rules with severity
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

### Authority invariants (custom checks)

taudit's built-in rules are **authority invariants** — declarative
properties the authority graph must satisfy. You can add your own as YAML
files and load them with `--invariants-dir`:

```bash
# Run the starter library of 5 example invariants alongside the built-ins
taudit scan --invariants-dir invariants/starter .github/workflows/

# Print every invariant that will run on the next scan
taudit invariants list --invariants-dir invariants/starter
```

The starter library lives in [`invariants/starter/`](./invariants/starter/);
the schema, predicate reference, and semver guarantee are documented in
[`docs/authority-invariants.md`](./docs/authority-invariants.md).
`--rules-dir` is accepted as an alias for backward compatibility.

### Remediate (safe hardening + rollback)

```bash
# Read-only suggestions

taudit remediate suggest .github/workflows/

# Read-only patch preview
taudit remediate diff .github/workflows/

# Apply conservative remediations with backup + validation (write-path opt-in)
taudit remediate --unstable apply .github/workflows/ --policy invariants/starter/

# List backups and roll back by id
taudit remediate list-backups
taudit remediate --unstable rollback --backup-id <id>
```

Backups and manifests are written under `.taudit/backups/` by default. See [docs/remediation.md](docs/remediation.md) for safety guarantees, failure modes, and rollback playbook.

`suggest` may also report review-only guidance for unpinned third-party actions
or broad workflow permissions. Those cases intentionally do not get automatic
patches until taudit can prove the replacement SHA or reduced scope.

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

1. **Parse** — GitHub Actions, Azure DevOps, or GitLab CI YAML into typed nodes (steps, secrets, identities, images) with trust zone classification (FirstParty, ThirdParty, Untrusted). Platform is auto-detected by default (`--platform auto`); override with `--platform github-actions`, `--platform azure-devops`, or `--platform gitlab`.
2. **Build graph** — Directed edges model authority flow: `HasAccessTo`, `Produces`, `Consumes`, `UsesImage`, `DelegatesTo`, `PersistsTo`.
3. **Propagate** — BFS from authority-bearing sources (secrets, identities) through edges, flagging trust boundary crossings.
4. **Apply invariants** — built-in rules (plus any custom YAML rules) pattern-match against the graph, producing findings with severity, evidence paths, and remediation routing.

Trust zones are explicit on every node:
- **FirstParty** — code you own (`run:` steps, local actions)
- **ThirdParty** — SHA-pinned external actions (immutable code)
- **Untrusted** — tag-pinned actions, fork PRs, user input

The graph is the artifact; steps 3 and 4 are consumers of it. See [`docs/authority-graph.md`](docs/authority-graph.md) for the typed schema.

## Outputs

taudit emits four kinds of output, all backed by stable, versioned contracts:

| Output             | Command                            | Schema / contract                                                              | Purpose |
| ------------------ | ---------------------------------- | ------------------------------------------------------------------------------ | ------- |
| **Findings (terminal)** | `taudit scan ... --format terminal` | colored, human-readable                                                        | day-to-day reading in shells and CI logs |
| **Findings (JSON)**     | `taudit scan ... --format json`     | [`contracts/schemas/taudit-report.schema.json`](contracts/schemas/taudit-report.schema.json) (`schema_version: "1.0.0"`) | full report: graph + findings + summary |
| **Findings (SARIF)**    | `taudit scan ... --format sarif`    | SARIF 2.1.0                                                                    | code-scanning ingestion (GitHub, Azure DevOps, IDE plugins) |
| **Findings (CloudEvents)** | `taudit scan ... --format cloudevents` | [`contracts/schemas/taudit-cloudevent-finding-v1.schema.json`](contracts/schemas/taudit-cloudevent-finding-v1.schema.json) | one CloudEvent JSONL per finding for event-driven sinks |
| **Authority graph (JSON)** | `taudit graph ... --format json`   | [`schemas/authority-graph.v1.json`](schemas/authority-graph.v1.json) (`schema_version: "1.0.0"`) | the canonical authority graph as a first-class artifact for downstream tools (tsign, axiom, runtime cells) — see [docs/authority-graph.md](docs/authority-graph.md) |
| **Authority graph (DOT)**  | `taudit graph ... --format dot`    | Graphviz DOT                                                                   | render to SVG/PNG for docs, slides, and incident reports |
| **Authority graph (Mermaid)** | `taudit graph ... --format mermaid` | Mermaid `flowchart`                                                         | paste into Markdown / wikis without installing Graphviz |
| **Authority map (text)**   | `taudit map ...`                   | human-readable table                                                           | quick "which step touches which secret" view |
| **Diff (terminal/JSON)**   | `taudit diff before after`         | n/a (terminal) / inline JSON shape                                             | compare two pipeline revisions |

Every JSON-shaped output carries a top-level `schema_version` (and, for
new outputs, `schema_uri`) so consumers can pin to a major version and
fail loudly on a breaking change.

Every finding emitted by taudit carries a stable cross-run **fingerprint**
that is byte-identical across SARIF (`partialFingerprints["taudit/v1"]`
and `partialFingerprints["primaryLocationLineHash"]`), JSON
(`findings[].fingerprint`), and CloudEvents
(extension attribute `tauditfindingfingerprint`). SIEM and code-scanning
consumers join on this value to deduplicate findings across re-runs and
to preserve user-managed state (suppressions, dismissals). See
[`docs/finding-fingerprint.md`](docs/finding-fingerprint.md) for the
contract, the formula, and the SARIF baseline-mapping integration with
GitHub Code Scanning.

## Architecture

```
taudit-api               stable wire types for JSON / SARIF / CloudEvents / authority graph output
taudit-core              graph, propagation engine, rules, baselines, suppressions, custom rules (no I/O)
taudit-parse-gha         GitHub Actions YAML → AuthorityGraph
taudit-parse-ado         Azure DevOps YAML → AuthorityGraph
taudit-parse-gitlab      GitLab CI YAML → AuthorityGraph
taudit-parse-bitbucket   Bitbucket Pipelines YAML → AuthorityGraph
taudit-report-terminal   colored terminal reporter
taudit-report-json       JSON report adapter
taudit-report-sarif      SARIF 2.1.0 adapter for code scanning platforms
taudit-sink-cloudevents  findings → CloudEvents JSONL event stream
taudit-cli               composition root (clap, file I/O, wiring)
```

Ports and adapters — `taudit-core` has zero I/O dependencies, so the graph is reproducible from YAML in isolation.

### Crate READMEs

| Crate | Crates.io role | README |
|---|---|---|
| `taudit` | CLI product: installable authority graph scanner and CI/CD security gate | This README |
| `taudit-api` | Stable Rust wire types for JSON, SARIF, CloudEvents, and authority graph output | [`crates/taudit-api/README.md`](crates/taudit-api/README.md) |
| `taudit-core` | In-process authority graph engine, propagation analysis, rules, baselines, suppressions, custom rules | [`crates/taudit-core/README.md`](crates/taudit-core/README.md) |
| `taudit-parse-gha` | GitHub Actions YAML parser for authority graphs | [`crates/taudit-parse-gha/README.md`](crates/taudit-parse-gha/README.md) |
| `taudit-parse-ado` | Azure DevOps YAML parser for authority graphs | [`crates/taudit-parse-ado/README.md`](crates/taudit-parse-ado/README.md) |
| `taudit-parse-gitlab` | GitLab CI YAML parser for authority graphs | [`crates/taudit-parse-gitlab/README.md`](crates/taudit-parse-gitlab/README.md) |
| `taudit-parse-bitbucket` | Bitbucket Pipelines YAML parser for authority graphs | [`crates/taudit-parse-bitbucket/README.md`](crates/taudit-parse-bitbucket/README.md) |
| `taudit-report-terminal` | Human-readable terminal and CI log renderer | [`crates/taudit-report-terminal/README.md`](crates/taudit-report-terminal/README.md) |
| `taudit-report-json` | Versioned JSON report and authority graph export adapter | [`crates/taudit-report-json/README.md`](crates/taudit-report-json/README.md) |
| `taudit-report-sarif` | SARIF 2.1.0 adapter for code scanning ingestion | [`crates/taudit-report-sarif/README.md`](crates/taudit-report-sarif/README.md) |
| `taudit-sink-cloudevents` | CloudEvents JSONL event stream for findings | [`crates/taudit-sink-cloudevents/README.md`](crates/taudit-sink-cloudevents/README.md) |

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

The full output catalogue is in [Outputs](#outputs) above. The stable JSON report contract is currently `schema_version: "1.0.0"` and lives at [`contracts/schemas/taudit-report.schema.json`](contracts/schemas/taudit-report.schema.json). A versioned graph schema (separate from the report contract) lands in v1.0 and will be the contract that downstream tools — tsign, axiom, anything else — depend on.

## What taudit is not

- Not a secret scanner (use [gitleaks](https://github.com/gitleaks/gitleaks))
- Not a CVE scanner (use [trivy](https://github.com/aquasecurity/trivy))
- Not a policy engine (use [checkov](https://github.com/bridgecrewio/checkov))
- Not a runtime monitor — taudit reads pipeline YAML, offline, always

taudit models a finite set of authority primitives. When every primitive is captured and every failure class has invariants, the model is complete. Unlike CVE databases, this problem has an end. See [`docs/positioning.md`](docs/positioning.md) for why this matters and how taudit fits into a wider stack.

## License

This repository is licensed under **AGPL-3.0-or-later** (see [LICENSE](LICENSE)). You may use, copy, modify, and redistribute the code **subject to the license** — including the AGPL network-use / source-disclosure obligations if you make a modified version available to users over a network. This is not legal advice; confirm with your counsel for regulated or commercial deployments.

**Why AGPL-3.0-or-later:** taudit is the OSS wedge of a larger ecosystem (see council D6 / `release-surfaces/public-vs-gated.md`). AGPL keeps the analyzer genuinely open and copyleft-protected: improvements made by downstream redistributors stay accessible to the community, while permissive embed in proprietary CI gateways requires a separate commercial arrangement.

**Pre-v0.5.0 (taudit-api) / pre-v3.1.0 (engines) / pre-v1.3.0 (CLI) caveat:** Versions of this repository released before the relicense were under their original license (MIT OR Apache-2.0; preserved as [LICENSE-MIT.old](LICENSE-MIT.old) and [LICENSE-APACHE.old](LICENSE-APACHE.old)). The AGPL-3.0-or-later relicense applies from the next minor of each published crate forward. Pre-relicense versions remain available under their original terms.

## Release trust

Release archives ship with SHA-256 checksum files and SPDX + CycloneDX dependency SBOMs, each covered by **GitHub build attestations** (verify with **`gh attestation verify`** on the downloaded file). See [docs/release-trust.md#verifying-build-attestations-github](docs/release-trust.md#verifying-build-attestations-github) for the full checklist (checksums, SBOMs, attestations, and future minisign-on-assets work).
