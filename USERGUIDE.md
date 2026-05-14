# taudit User Guide

taudit is a **CI/CD authority graph** tool: it parses pipeline YAML into a deterministic model of how **credentials, tokens, identities, and artifacts** propagate, then surfaces **implicit trust-boundary breaks** and **non-obvious privilege-escalation paths**. It is **not** a workflow YAML linter, a CVE scanner, or a standalone policy engine — those concerns stay in other tools; here the **graph** comes first. It understands **GitHub Actions**, **Azure DevOps**, and **GitLab CI**. Built-in checks and optional YAML invariants are **predicates over that graph**.

---

## Table of Contents

1. [Installation](#1-installation)
2. [First scan](#2-first-scan)
3. [Reading findings](#3-reading-findings)
4. [The authority graph — the real product](#4-the-authority-graph--the-real-product)
5. [CI gate with `taudit verify`](#5-ci-gate-with-taudit-verify)
6. [Adopting incrementally with baselines](#6-adopting-incrementally-with-baselines)
7. [Per-finding waivers with suppressions](#7-per-finding-waivers-with-suppressions)
8. [Custom authority invariants](#8-custom-authority-invariants)
9. [Explaining rules](#9-explaining-rules)
10. [Output formats](#10-output-formats)
11. [Corpus research & citing upstream examples](#11-corpus-research--citing-upstream-examples)
12. [Day 0–1 adoption runbook (CI + baselines)](docs/adoption-day0-day1.md)

---

## 1. Installation

```bash
cargo install taudit --locked
```

Requires Rust ≥ 1.76. Verify the install:

```bash
taudit --version
# taudit 1.1.0
```

`taudit --help` appends a long reference (graph formats `json`/`dot`/`mermaid`/`summary`, `--job`, stdout/pipes, doc paths). Use `taudit graph --help`, `taudit scan --help`, etc. for subcommand flags. A Troff manual is in the repo: [`man/taudit.1`](../man/taudit.1). **Blessed CLI flows** on committed fixtures: [`docs/golden-paths.md`](docs/golden-paths.md); run **`just golden-paths`** from a clone to smoke them.

---

## 2. First scan

Point `taudit scan` at any pipeline file or directory. taudit auto-detects the
platform (GHA / ADO / GitLab) from the YAML content.

```bash
# Scan a single workflow
taudit scan .github/workflows/release.yml

# Scan every pipeline in a directory (recursive)
taudit scan .github/workflows/

# Scan a GitLab project
taudit scan .gitlab-ci.yml

# Scan an Azure DevOps pipeline
taudit scan azure-pipelines.yml
```

### Sample output

```
taudit 1.1.0 — 1 file
────────────────────────────────────────────────────────────
Authority Graph: .github/workflows/quality.yml
  Steps: 18 | Secrets: 0 | Actions: 4 | Identities: 1

[CRITICAL] GITHUB_TOKEN reaches 5 sinks via authority propagation:
  [actions/checkout@11bd71..., dtolnay/rust-toolchain@98e1b8...,
   Swatinem/rust-cache@9d47c6..., actions/upload-artifact@65c4c4...,
   taudit-self-scan-sarif]
  Path: GITHUB_TOKEN (identity) → taudit-self-scan-sarif (artifact)
  Recommendation: tsafe exec --ns <scoped-namespace> -- <command>

[HIGH] Step 'Install governance tooling' writes to the environment gate
  while holding authority (GITHUB_TOKEN) — secrets may leak into pipeline
  environment
  Nodes: Install governance tooling (step) → GITHUB_TOKEN (identity)
  Recommendation: Avoid writing secrets or attacker-controlled values to
  $GITHUB_ENV / $GITHUB_PATH. Use explicit step outputs with narrow scoping.

────────────────────────────────────────────────────────────
Summary  1 critical  1 high
  Files with findings: 1 / 1
```

---

## 3. Reading findings

Each finding has:

| Field | Meaning |
|-------|---------|
| **Severity** | `CRITICAL / HIGH / MEDIUM / LOW / INFO` |
| **Rule** | Which of the 61 built-in rules fired |
| **Message** | What taudit found — node names are verbatim from your YAML |
| **Path** | The authority propagation chain (source → sink) |
| **Recommendation** | Concrete fix action |

Severity meanings:

| Severity | Action |
|----------|--------|
| `CRITICAL` | Active exploitation path — fix immediately |
| `HIGH` | Significant risk — fix within the sprint |
| `MEDIUM` | Real risk but requires additional conditions |
| `LOW` | Hygiene — low direct exploit potential |
| `INFO` | Best-practice gap — no immediate risk |

To understand a specific rule:

```bash
taudit explain unpinned_action
```

```
unpinned_action (UnpinnedAction)  high

  A third-party action is referenced by mutable tag instead of SHA digest.

  A third-party action is referenced by a mutable tag or branch instead of
  an immutable SHA digest. The action's code can change under the workflow
  without any local change, enabling supply-chain attacks.

  Tags: security, supply-chain
  See: https://github.com/0ryant/taudit/blob/main/docs/rules/unpinned_action.md
```

List all 61 rules:

```bash
taudit explain
```

---

## 4. The authority graph — the real product

The authority graph is the core model. Every step, secret, identity, image, and
artifact is a node; edges represent "has access to", "uses image", "produces",
"consumes", and "delegates to". Rules are predicates over this graph.

### View the authority table

```bash
taudit map .github/workflows/quality.yml
```

```
Authority Map: .github/workflows/quality.yml

Step                             Zone  GITHUB_TOKEN
-------------------------------  ----  ------------
quality[0]                       3P         ✓
Rust toolchain                   3P         ✓
quality[2]                       3P         ✓
fmt                              1P         ✓
clippy                           1P         ✓
test                             1P         ✓
Install cargo-deny               1P         ✓
cargo deny                       1P         ✓
Install cargo-audit              1P         ✓
cargo audit                      1P         ✓
Install governance tooling       1P         ✓
Governance quality gate          1P         ✓
Build taudit (release)           1P         ✓
taudit self-scan (SARIF)         1P         ✓
Upload self-scan SARIF           3P         ✓
taudit verify (starter)          1P         ✓
```

**Zone key:**
- `1P` — First-party (your own inline `run:` steps)
- `3P` — Third-party (pinned SHA actions)
- `UT` — Untrusted (floating tags, PR fork code, downloaded artifacts)

`✓` in the `GITHUB_TOKEN` column means the step has access to the repository
identity. Any `UT` row with `✓` is a `untrusted_with_authority` finding.

### Export as Graphviz DOT

```bash
taudit map --format dot .github/workflows/release.yml > graph.dot
# Same DOT from the canonical graph export:
# taudit graph --format dot .github/workflows/release.yml > graph.dot

# Render with Graphviz (install `dot` first — it is not bundled with taudit)
# macOS: brew install graphviz   Debian/Ubuntu: apt install graphviz
dot -Tsvg graph.dot -o graph.svg

# Or use the online renderer: paste the DOT output at https://dreampuf.github.io/GraphvizOnline/
```

### Export as Mermaid (no Graphviz)

```bash
# Full workflow (all jobs)
taudit graph --format mermaid .github/workflows/release.yml

# Same Mermaid text from `taudit map` (diagram only — no table header)
taudit map --format mermaid .github/workflows/release.yml

# Per-job subgraph — smaller diagram, same semantics for `dot` / `mermaid` / `map`
taudit graph --format mermaid --job build .github/workflows/release.yml
```

The output is a Mermaid `flowchart LR` — paste it into a Markdown fenced code block with the `mermaid` language tag (GitHub, GitLab, or any Mermaid-capable preview). You do **not** need the `dot` binary. The **canonical** machine interchange remains `taudit graph --format json` (see [ADR 0001](docs/adr/0001-graph-native-exports-and-leverage.md)). An ASCII picture of how JSON / DOT / Mermaid / summary relate to one `AuthorityGraph` is in [docs/authority-graph.md](docs/authority-graph.md#at-a-glance-one-graph-several-exports). When the parser marks the graph as incomplete, a leading `%%` comment notes that the diagram may omit authority edges; use JSON for `completeness` and `completeness_gaps`.

#### JSON = contract; diagrams = views (`--rich-labels`)

**`taudit graph --format json`** is the full, schema-backed interchange. **DOT**
and **Mermaid** are **diagram views** of the same authority graph: default node
labels stay short (name only). Add **`--rich-labels`** with **`taudit graph`**
or **`taudit map`** when using **`--format dot`** or **`--format mermaid`** to
inline trust zone and key node metadata the parser already attached (for
example identity scope and permissions text on `GITHUB_TOKEN`) — useful for
small graphs and documentation; skip it for very large workflows. JSON is
unchanged by this flag. On **`has_access_to`** edges to **identity** nodes, the
JSON graph also carries an optional **`authority_summary`** (trust zone,
identity scope, truncated permissions) for tools that prefer edge-shaped data;
see [docs/authority-graph.md](docs/authority-graph.md#edge-authority_summary-adr-0002-phase-2).

#### Propagation summary (`--format summary`)

**`taudit graph --format summary`** emits a **separate** JSON document (not the graph envelope) with rollups over **boundary-crossing** propagation paths — sinks in a **strictly lower** trust zone than the authority source — plus top sinks/sources by path count. It uses the same **`--max-hops`** and **dense-graph** guard as **`taudit scan`** (override with **`--force-scan-dense`** when you accept the cost). **`--job`** and **`--rich-labels`** do not apply (summary is always the full parsed graph). Schema: [`schemas/authority-propagation-summary.v1.json`](../schemas/authority-propagation-summary.v1.json); details in [docs/authority-graph.md](docs/authority-graph.md#propagation-summary-format-summary).

```bash
taudit graph --format summary .github/workflows/release.yml | jq '.totals'
```

The DOT output encodes trust zones as node colors:
- **green** — `FirstParty`
- **yellow** — `ThirdParty`
- **red** — `Untrusted`

Node shapes:
- **ellipse** — Step
- **diamond** — Identity (GITHUB_TOKEN, assumed cloud identity)
- **box** — Secret
- **cylinder** — Image / Action
- **hexagon** — Artifact

### Focus on a single job (`--job`)

Large workflows produce crowded graphs. Pass **`--job <job_id>`** to restrict
`taudit map`, **`taudit graph --format dot`**, and **`taudit graph --format mermaid`**
to the subgraph reachable from that job’s steps (BFS across edge kinds).
**`taudit graph --format json`**, **`--format summary`**, and JSON from **`taudit scan`**
always use the **full** graph (job filter does not apply). If the job name is wrong,
taudit lists the job IDs it parsed from the file.

**Jobs in this repository (copy/paste examples):**

| Workflow | Job IDs |
|----------|---------|
| `.github/workflows/release.yml` | `quality`, `create-release`, `sbom`, `build`, `publish` |
| `.github/workflows/quality.yml` | `test-matrix`, `quality` |
| `.github/workflows/security.yml` | `cargo-deny`, `taudit-self-scan` |
| `.github/workflows/taudit-pr-diff.yml` | `authority-diff` |

```bash
# Table: one job only
taudit map --job build .github/workflows/release.yml

# Mermaid for a README (no Graphviz) — authority for the build job only
taudit graph --format mermaid --job build .github/workflows/release.yml

# DOT → SVG for the same subgraph (requires `dot` on PATH)
taudit graph --format dot --job build .github/workflows/release.yml | dot -Tsvg -o build-subgraph.svg

# CI / security workflow slice
taudit graph --format mermaid --job taudit-self-scan .github/workflows/security.yml
```

---

## 5. CI gate with `taudit verify`

`scan` *describes* what taudit found. `verify` *decides* whether the world
is acceptable and exits with a deterministic code:

| Exit code | Meaning |
|-----------|---------|
| `0` | **Pass** — no policy violations; merge allowed on policy grounds |
| `1` | **Fail** — at least one violation; block the merge |
| `2` | **Could not decide** — usage/config error (missing policy, unreadable file, parse failure on explicit paths, empty policy dir without `--include-builtin`, or `--strict` directory scan errors) |

`verify` runs only your `--policy` invariants (not the 61 built-ins by default).
This lets you gate on exactly the properties you care about.

Every successful run also summarizes **authority graph modeling** (how completely
each pipeline was parsed): see the `verify: authority graph modeling:` line in
text output, or the `pipelines` array in `--format json`. When graphs are
`partial` or `unknown`, treat coverage as a first-class signal. Each gap is
classified with a typed kind — `expression` (template noise, structure intact),
`structural` (a composite action, reusable workflow, `extends:`, or `include:`
broke the authority chain), or `opaque` (the graph couldn't be built at all).
Pull the typed `completeness_gap_kinds` array from `taudit graph --format json`
and gate on kind, not just count — see
[`docs/policies/cookbook-partial-graphs.md`](docs/policies/cookbook-partial-graphs.md)
Pattern D for a `jq` recipe.

By default, `taudit scan` suppresses per-finding `[partial]` inline tags
to reduce output noise. The per-file header warning and run summary are
always shown. Gaps with kind `opaque` always emit `[partial:opaque]` inline
regardless of verbosity — a total graph failure is never silently suppressed.

Use `--verbose` / `-v` to restore inline `[partial]` tags on every finding
from a partial graph.

### GitHub Actions — required check

```yaml
name: Pipeline policy
on: [pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - name: Install taudit
        run: cargo install taudit --version 1.1.2 --locked
      - name: Verify pipeline policy
        run: taudit verify --policy .taudit/policy/ .github/workflows/
```

Mark this job as a **required check** in branch protection. Exit `1` (violations)
and exit `2` (config error) both block the merge.

### Azure DevOps

```yaml
- task: Bash@3
  displayName: Verify pipeline policy
  inputs:
    targetType: inline
    script: |
      cargo install taudit --version 1.1.2 --locked
      taudit verify --policy .taudit/policy/ azure-pipelines.yml
```

### GitLab CI

```yaml
verify-pipeline-policy:
  stage: test
  script:
    - cargo install taudit --version 1.1.2 --locked
    - taudit verify --policy .taudit/policy/ .gitlab-ci.yml
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

### SARIF for GitHub Code Scanning

Emit violations as code-scanning annotations from a trusted branch or scheduled
workflow. Keep the required PR scanner job at `contents: read`; do not combine
untrusted PR workflow parsing with a same-job `security-events: write` token.

```yaml
- name: Verify and emit SARIF
  run: taudit verify --policy .taudit/policy/ --format sarif -o results.sarif .github/workflows/
  continue-on-error: true   # let the upload step run even on violations

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@<sha>
  with:
    sarif_file: results.sarif

- name: Re-fail if violations
  run: taudit verify --policy .taudit/policy/ .github/workflows/
```

The double-invocation is intentional: the first run emits SARIF for the UI,
the second enforces the exit-code gate. Use that pattern only in workflows whose
trigger and checkout are trusted for `security-events: write`.

### Using the built-in rules as a gate

To gate on any of the 61 built-in rules in addition to your policy:

```bash
taudit verify --policy .taudit/policy/ --include-builtin \
  --severity-threshold high .github/workflows/
```

`--include-builtin` folds built-in findings into the violation count.
`--severity-threshold high` ignores `MEDIUM / LOW / INFO` built-in findings.

---

## 6. Adopting incrementally with baselines

If you drop taudit into a repo with pre-existing findings, baselines let you
gate on **new** findings only — without spending a sprint triaging history.

```bash
# Step 1: snapshot the current state
taudit baseline init .github/workflows/

# This writes .taudit/baselines/<content-hash>.json
# Commit the .taudit/ directory.
```

After that, `taudit scan` and `taudit verify` automatically diff against the
baseline, reporting:

```
.github/workflows/release.yml: 1 NEW, 0 FIXED, 3 PRE-EXISTING
```

Pre-existing findings no longer drive `verify` exit `1` — **except** criticals
that have not been explicitly waived (see below).

### Explicitly waiving a pre-existing critical

```bash
taudit baseline accept \
  --pipeline .github/workflows/release.yml \
  --fingerprint abc123def456 \
  --rule-id authority_propagation \
  --severity critical \
  --reason "Remediation scheduled for sprint 42; tracked in JIRA-1234" \
  --expires-at 2026-06-01
```

The waiver is recorded in the baseline JSON. After `--expires-at` passes, the
finding re-surfaces in `verify` output.

---

## 7. Per-finding waivers with suppressions

Suppressions are `.taudit-suppressions.yml` entries that permanently waive
specific findings with an audit trail. Unlike baselines (per-pipeline adoption),
suppressions are for findings that will never be fixed (e.g., a known accepted
risk with a compensating control).

```yaml
# .taudit-suppressions.yml
suppressions:
  - rule_id: over_privileged_identity
    path: .github/workflows/release.yml
    reason: "GITHUB_TOKEN scope is narrowed per-job; broad token is structural"
    approved_by: security-team
    expires_at: "2027-01-01"
```

Pass it to any taudit command:

```bash
taudit scan --suppressions .taudit-suppressions.yml .github/workflows/
```

Suppressed findings are downgraded one severity tier by default
(`--suppression-mode downgrade`). Use `--suppression-mode suppress` to hide
them from output entirely.

---

## 8. Custom authority invariants

You can encode org-specific policy as YAML invariant files and load them
alongside the 61 built-ins:

```bash
taudit scan --invariants-dir .taudit/policy/ .github/workflows/
```

### Minimum viable invariant

```yaml
# .taudit/policy/no-prod-secret-to-untrusted.yml
id: no_prod_secret_to_untrusted
name: Production secrets must not reach untrusted code
severity: critical
category: authority_propagation
match:
  source:
    node_type: secret
    name_pattern: "PROD_*"
  sink:
    trust_zone: untrusted
```

### List all active invariants (built-in + custom)

```bash
taudit invariants list --invariants-dir .taudit/policy/
```

### Starter library

Five ready-to-use invariants ship in `invariants/starter/`:

| File | What it enforces |
|------|-----------------|
| `no-untrusted-with-secret.yml` | No untrusted step may hold any secret |
| `no-broad-identity-to-untrusted.yml` | Broad identity (full GITHUB_TOKEN) must not reach untrusted nodes |
| `no-third-party-step-with-identity.yml` | Third-party actions must not hold an identity |
| `prefer-oidc-over-static-secrets.yml` | Warn when static cloud credentials are present (OIDC preferred) |
| `no-write-permissions-on-pr.yml` | Workflows triggered by PRs must not have write permissions |

Copy, edit the predicates to match your naming scheme, and load them with
`--invariants-dir`.

Full invariant schema reference: [`docs/authority-invariants.md`](docs/authority-invariants.md)

---

## 9. Explaining rules

```bash
# Describe one rule
taudit explain script_injection_via_untrusted_context

# List all 61 rules with descriptions
taudit explain
```

Each rule links to its full documentation in `docs/rules/<rule-id>.md`.

Rule index with severity, category, and platform columns:
[`docs/rules/index.md`](docs/rules/index.md)

---

## 10. Output formats

### Terminal (default)

Colour-coded, human-readable. Use `--no-color` or set `NO_COLOR=1` for
plain text (e.g., in CI logs where ANSI renders as garbage).

### JSON

```bash
taudit scan --format json .github/workflows/ | jq '.findings[].severity' | sort | uniq -c
```

Stable schema, versioned. Use `jq`, `duckdb`, or any JSON tooling to slice
findings.

### SARIF

```bash
taudit scan --format sarif -o results.sarif .github/workflows/
```

SARIF 2.1.0. Upload to GitHub Code Scanning, use with VS Code SARIF Viewer,
or feed into any SARIF-aware tool.

### CloudEvents

```bash
taudit scan --format cloudevents .github/workflows/
```

Emits one CloudEvent per finding. Pipe to a SIEM or event stream.

---

## 11. Corpus research & citing upstream examples

Large-directory scans, mirrored corpora, and “zero-finding” workflows need a
bit of context so results are not over-interpreted. For **aggregated JSON
vs SARIF**, **fingerprint path semantics**, **licensing/attribution** when
citing public repos, and the difference between a **minimal clean workflow**
and a **commented-out or empty file**, read:

- [`docs/corpus-research.md`](docs/corpus-research.md)

---

## Quick reference

```text
taudit scan   <path>                   # describe all findings
taudit verify --policy <dir> <path>    # enforce, exit 0/1/2
taudit map    <path>                   # authority table (or --format dot)
taudit explain [rule-id]               # describe one rule (or all 61)
taudit baseline init   <path>          # snapshot current state
taudit baseline diff   <path>          # new vs pre-existing findings
taudit invariants list [--invariants-dir <dir>]  # list active invariants
```

See `taudit --help` or `taudit <subcommand> --help` for all flags.
