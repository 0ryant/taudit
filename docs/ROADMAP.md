# taudit Roadmap

Three horizons. Each is a superset of the previous.

**Current state:** 6 crates, 36 tests, 2,469 LOC, 6 analysis rules, 1 parser (GitHub Actions), 3 output formats (terminal, JSON, CloudEvents JSONL), 2 commands (scan, map).

**Effort key:** S = hours, M = days, L = week+

---

## Roadmap 1: MVP — Ship It

> Gate: a security engineer at your employer can run `taudit scan` on every repo and get actionable findings with zero false positives.

Almost everything is shipped. The remaining items are about confidence, not features.

| # | Item | Effort | Status |
|---|------|--------|--------|
| 1 | Authority graph with typed nodes, edges, trust zones | S | Done |
| 2 | BFS propagation engine with configurable depth | S | Done |
| 3 | 5 core analysis rules with severity graduation | S | Done |
| 4 | Finding model with path evidence and remediation routing | S | Done |
| 5 | GitHub Actions parser with trust zone classification | S | Done |
| 6 | Terminal report with propagation path visualization | S | Done |
| 7 | JSON report with JSON Schema contract | S | Done |
| 8 | CloudEvents JSONL sink with schema | S | Done |
| 9 | Authority map command | S | Done |
| 10 | LongLivedCredential rule | S | Done |
| 11 | CI pipeline (fmt, clippy, test, deny) | S | Done |
| 12 | 36 tests (unit + integration + sink) | S | Done |
| | | | |
| **13** | **Finding suppression (`.tauditignore`)** | **M** | **TODO** |
| **14** | **`--severity-threshold` flag (exit 1 only above threshold)** | **S** | **TODO** |
| **15** | **README with install + quickstart + example output** | **S** | **TODO** |
| **16** | **`cargo install taudit` works (publish to crates.io)** | **S** | **TODO** |

### MVP ship gate

- [ ] Zero false positives on employer's production workflows
- [ ] `.tauditignore` suppresses known-accepted risks (GITHUB_TOKEN in SHA-pinned actions)
- [ ] `--severity-threshold critical` lets CI pass on medium/low findings
- [ ] README exists with copy-paste install command
- [ ] Available via `cargo install`

**Remaining effort: ~1-2 days.** The product is built. These are packaging and noise reduction.

---

## Roadmap 2: AAA — Competitive with Commercial Tools

> Gate: a platform engineering team adopts taudit as their standard pipeline security tool, replacing manual review.

Organized by impact tier, not feature list. Each tier unlocks a class of adoption.

### Tier 1: Noise Elimination (S each, do first)

These determine whether teams keep using taudit past day 1.

- [ ] `.tauditignore` with glob + category matching
- [ ] `--severity-threshold` flag
- [ ] `--exclude` glob patterns for generated/vendored workflows
- [ ] `--baseline` file (suppress findings from a known-good scan)
- [ ] `--quiet` mode (summary counts only, for CI logs)

### Tier 2: Platform Integration (M each, highest leverage)

These put findings where engineers already look.

- [ ] **SARIF output adapter** — findings appear in GitHub code scanning tab
- [ ] **`taudit diff`** — before/after authority graph diff between pipeline versions
- [ ] **PR comment bot** — `taudit diff base..head` posts authority changes to PR
- [ ] **GitHub Action** — `uses: taudit-dev/taudit-action@sha` with configurable severity gate

### Tier 3: Parser Depth (M-L each, unlocks real-world coverage)

Real GHA workflows use features the current parser doesn't handle.

- [ ] **Reusable workflow support** (`workflow_call` inputs/secrets passthrough)
- [ ] **Composite action parsing** (action.yml with `using: composite`)
- [ ] **Matrix strategy awareness** (trust zones may differ per matrix entry)
- [ ] **Expression evaluation** (`${{ github.event_name == 'pull_request_target' }}`)
- [ ] **Trigger-based trust classification** (pull_request_target = untrusted source)

### Tier 4: Second Platform (L, unlocks enterprise)

- [ ] **Azure DevOps parser** (`taudit-parse-ado`) — stages, jobs, steps, service connections, variable groups
- [ ] Environment approvals as isolation boundaries

### Tier 5: Rule Depth (S-M each, deeper analysis)

- [ ] **EgressBlindspot** — steps with secrets + network access + no egress constraint
- [ ] **MissingAuditTrail** — authority-bearing steps with no logging
- [ ] **FloatingImage** — container images without digest pinning
- [ ] **Confidence scoring** — severity modulated by context (e.g., internal-only repo = lower risk)
- [ ] **Custom rule loading** — user-defined rules via YAML policy files

### Tier 6: Enterprise Polish (M each)

- [ ] **`--no-color` flag** + automatic tty detection
- [ ] **`--verbose` mode** (full node metadata in terminal report)
- [ ] **Stable schema versioning** (v1/v2 contract evolution)
- [ ] **JSON Schema CI validation** in quality.yml (examples validate against schemas)
- [ ] **Release workflow** with multi-platform binaries (linux-x64, linux-arm64, darwin-x64, darwin-arm64)
- [ ] **`cargo-audit`** in CI
- [ ] **Homebrew formula** / **nix package**
- [ ] **Shell completions** (bash, zsh, fish)

### Tier 7: Graph Power (M-L each, differentiation)

- [ ] **Isolation boundary support** — explicit breaks in propagation (CellOS containment = boundary)
- [ ] **Subgraph extraction** per job (focus view)
- [ ] **Graphviz DOT export** from `taudit map`
- [ ] **Adjacency index** for large graphs (currently O(n) scan — fine for pipeline scale, not for mono-repo with 200 workflows)

### AAA completion gate

- [ ] Two CI platforms supported (GHA + ADO)
- [ ] Findings appear in GitHub code scanning (SARIF)
- [ ] PR bot posts authority changes
- [ ] `.tauditignore` + `--baseline` eliminate all noise
- [ ] Reusable workflows and composite actions parsed correctly
- [ ] All 9 finding categories implemented
- [ ] Available via Homebrew + cargo install + GitHub Action
- [ ] Release binaries for 4 targets

**Estimated effort: 4-8 weeks solo.** Tier 1-2 are the highest leverage. Tier 4 (ADO) is the gate for enterprise.

---

## Roadmap 3: Done — Feature Complete

> Gate: taudit models every authority primitive in the three major CI/CD platforms, covers every failure class from the doctrine, integrates with the operator's existing toolchain, and scans itself.

"Done" is reachable because taudit's scope is bounded by the authority model, not the security landscape. Unlike CVE scanners (infinite new CVEs) or policy engines (infinite policies), taudit models a finite set of authority primitives. When every primitive is captured and every failure class has rules, the model is complete.

### What "Done" adds beyond AAA

**Third parser:**

- [ ] **GitLab CI parser** (`taudit-parse-gitlab`) — stages, jobs, secrets, images
- [ ] `include:` template resolution (remote + local)
- [ ] Protected branch rules as trust boundaries
- [ ] GitLab CI/CD variables with scope (environment, group)

**Governance loop completion:**

- [ ] **Governance correlation schema** — shared CloudEvents extension attribute linking taudit findings → tsafe remediation → CellOS execution events (`governance_pipeline_file`, `governance_step_ref`, `governance_secret_ref`)
- [ ] **tsafe recommendation validation** — `taudit verify` confirms tsafe namespace scoping matches finding recommendations
- [ ] **CellOS spec generation** — `taudit emit-spec` generates CellOS cell specs from isolation findings (network deny, secret brokering)
- [ ] **Feedback loop** — `taudit scan` consumes CellOS execution events to verify containment was applied

**Self-hosting:**

- [ ] **taudit scans taudit** — quality.yml includes `taudit scan .github/workflows/` as a CI step with zero findings
- [ ] **taudit scans tsafe** — zero findings on tsafe's quality.yml
- [ ] **taudit scans CellOS** — zero findings on CellOS's quality.yml (already tested informally)

**Complete rule coverage:**

- [ ] All 9 finding categories implemented (5 MVP + 4 stretch) with tests
- [ ] **Policy-as-code** — YAML rule definitions loaded at runtime (beyond hardcoded rules)
- [ ] **Rule documentation** — each rule has a doc page explaining what it detects, why, and how to fix

**Complete output coverage:**

- [ ] Terminal, JSON, CloudEvents JSONL, SARIF — all four formats
- [ ] **JetStream publish adapter** — optional direct NATS publish for CellOS-integrated deployments
- [ ] **Governance correlation ID** in CloudEvents extension attributes

**Operational maturity:**

- [ ] **SBOM generation** per release
- [ ] **Signed releases** (cosign or minisign)
- [ ] **Fuzzing** (cargo-fuzz on parser inputs)
- [ ] **Property-based tests** (proptest on graph invariants)
- [ ] **Benchmark suite** (criterion on propagation engine scaling)
- [ ] **Interactive TUI** for `taudit map` (ratatui)
- [ ] **Watch mode** — `taudit scan --watch` re-runs on file change

### Done completion gate

- [ ] Three CI platforms parsed (GHA + ADO + GitLab)
- [ ] All 5 failure classes from doctrine have rules
- [ ] All 9 finding categories implemented
- [ ] Governance loop has correlation IDs across taudit/tsafe/CellOS
- [ ] taudit scans all three sister projects with zero findings
- [ ] Policy-as-code supports user-defined rules
- [ ] Four output formats (terminal, JSON, CloudEvents, SARIF)
- [ ] Fuzzed, property-tested, benchmarked
- [ ] Signed releases with SBOM

**Estimated effort: 3-6 months solo.** The long poles are the GitLab parser (L), policy-as-code engine (L), and governance loop integration (L).

---

## What "Done" Does NOT Include

Per doctrine anti-goals — these are out of scope permanently:

| Not building | Why |
|---|---|
| Secret pattern scanning | That's gitleaks |
| CVE scanning | That's trivy |
| IaC policy engine | That's checkov |
| Web dashboard | CLI-first + SARIF + PR bot is the UX |
| Cloud API dependency | Core analysis is offline, always |
| Kubernetes/runtime scanning | taudit reads pipeline YAML, not runtime state |
| AI/ML-based detection | Rules are deterministic and auditable |
| Multi-tenant SaaS | Single binary, runs in CI |

---

## Visual Summary

```
                    YOU ARE HERE
                         |
MVP ═══════════════════[~]══ ship gate
  .tauditignore            |
  --severity-threshold     |
  README                   |
  crates.io publish        |
                           |
AAA ═══════════════════════╪════════════════════════ competitive
  T1: noise elimination    |
  T2: SARIF + PR bot       |
  T3: reusable workflows   |
  T4: Azure DevOps         |
  T5: all 9 rules          |
  T6: release binaries     |
  T7: graph power          |
                           |
DONE ══════════════════════╪════════════════════════════════ complete
  GitLab parser            |
  governance correlation   |
  self-hosting             |
  policy-as-code           |
  JetStream adapter        |
  fuzzing + SBOM           |
```
