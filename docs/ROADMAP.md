# taudit Roadmap

Three horizons. Each is a superset of the previous.

**Current state:** 7 crates, 91 tests, ~5,300 LOC, 7 analysis rules, 1 parser (GitHub Actions), 4 output formats (terminal, JSON, CloudEvents JSONL, SARIF), 4 commands (scan, map, diff, completions). MVP complete. Deep into AAA: Tier 1 done, Tier 2 partial, Tier 3 mostly done, Tier 4 partial, Tier 6 partial, Tier 7 partial.

**Effort key:** S = hours, M = days, L = week+

**Core thesis (from external review):** taudit's credibility depends on how it handles ambiguity and incompleteness. If it overclaims certainty, it will get dismissed. If it handles unknowns honestly, it will gain trust. The next iteration is not more features — it's precision under uncertainty.

---

## Roadmap 1: MVP — Credible on Real Pipelines

> Gate: a security engineer at your employer can run `taudit scan` on every repo, trust the output, and understand what the tool does and doesn't know.

### Already shipped

| # | Item | Status |
|---|------|--------|
| 1 | Authority graph with typed nodes, edges, trust zones | Done |
| 2 | BFS propagation engine with configurable depth | Done |
| 3 | 7 analysis rules with severity graduation and deduplication | Done |
| 4 | Finding model with path evidence and remediation routing | Done |
| 5 | GitHub Actions parser with trust zone classification | Done |
| 6 | Terminal report with propagation path visualization | Done |
| 7 | JSON report with JSON Schema contract | Done |
| 8 | CloudEvents JSONL sink with schema | Done |
| 9 | Authority map command | Done |
| 10 | CI pipeline (fmt, clippy, test, deny, dependabot) | Done |
| 11 | 91 tests (unit + integration + sink) | Done |

### Precision (do first — the credibility layer)

| # | Item | Effort | Status |
|---|------|--------|--------|
| **12** | `AuthorityCompleteness` enum on `AuthorityGraph` | S | Done |
| **13** | `IdentityScope` classification on Identity nodes | S | Done |
| **14** | Inferred secret detection in `run:` blocks | S | Done |
| **15** | `env:` inheritance (workflow → job → step) | S | Done |

### Noise reduction

| # | Item | Effort | Status |
|---|------|--------|--------|
| **16** | `.tauditignore` | M | Done |
| **17** | `--severity-threshold` flag | S | Done |

### Real-world validation

| # | Item | Effort | Status |
|---|------|--------|--------|
| **18** | Run on production workflows | M | Done — 10 workflows across taudit/tsafe/CellOS |
| **19** | Tune findings from real-world signal | S | Done — constrained+pinned graduated to Medium |

### Packaging

| # | Item | Effort | Status |
|---|------|--------|--------|
| **20** | README with install + quickstart + example output | S | Done |
| **21** | `cargo install taudit` (publish to crates.io) | S | Ready — metadata set, `cargo publish` when ready |

### MVP ship gate

- [x] `AuthorityCompleteness` marks graphs as Complete/Partial — no silent incompleteness
- [x] `IdentityScope` classifies identity breadth — Unknown treated as risky
- [x] Inferred secrets in `run:` blocks detected and marked
- [x] Workflow/job-level `env:` inheritance parsed
- [x] Zero false positives on production workflows (10 workflows, 3 projects)
- [x] `.tauditignore` suppresses known-accepted risks
- [x] `--severity-threshold` lets CI pass on medium/low
- [x] README with sharp narrative
- [ ] Available via `cargo install` (metadata ready, publish pending)

**Status: MVP complete.** `cargo publish` is the only remaining step.

---

## Roadmap 2: AAA — Competitive with Commercial Tools

> Gate: a platform engineering team adopts taudit as their standard pipeline security tool, replacing manual review.

Organized by impact tier. Each tier unlocks a class of adoption.

### Tier 1: Noise Elimination ✅ Complete

- [x] `.tauditignore` with glob + category matching
- [x] `--severity-threshold` flag
- [x] `--exclude` glob patterns for generated/vendored workflows
- [x] `--baseline` file (suppress findings from a known-good scan)
- [x] `--quiet` mode (summary counts only, for CI logs)

### Tier 2: Platform Integration (M each, highest leverage)

Put findings where engineers already look.

- [x] **SARIF output adapter** — findings appear in GitHub code scanning tab
- [x] **`taudit diff`** — before/after authority graph diff between pipeline versions
- [x] **Stdin pipe support** — `cat workflow.yml | taudit scan -`
- [ ] **PR comment bot** — `taudit diff base..head` posts authority changes to PR
- [ ] **GitHub Action** — `uses: taudit-dev/taudit-action@sha` with configurable severity gate

### Tier 3: Parser Precision (M-L each, real-world correctness)

Real GHA workflows use features that affect the completeness of the authority graph.

- [x] **Reusable workflow detection** — `job.uses` creates DelegatesTo edge, marks graph Partial
- [x] **Trigger-based trust classification** — `pull_request_target` marks `run:` steps Untrusted
- [x] **Matrix strategy** — jobs with `strategy.matrix` mark graph Partial
- [x] **Workflow-level `env:` inheritance** — secrets defined at workflow root visible to all steps
- [x] **Job container images** — `job.container` parsed, `FloatingImage` rule applies
- [ ] **Composite action parsing** — action.yml with `using: composite` (steps hidden from graph)
- [ ] **Expression evaluation** — `${{ github.event_name }}` in conditionals not resolved

### Tier 4: Identity Depth (M each, the dangerous gap)

Identity modelling is the biggest long-term risk. Modern pipelines use OIDC tokens, service principals, and cloud identities with massive over-scope by default.

- [x] **OIDC token detection** — `id-token: write` tags identity as OIDC-capable (`META_OIDC`)
- [ ] **Cloud identity inference** — detect `aws-actions/configure-aws-credentials`, `google-github-actions/auth`, `azure/login` from step `uses:` + `with:` inputs; create Identity or Secret nodes
- [ ] **Scope propagation escalation** — Broad identity → Untrusted step should escalate to Critical regardless of sink pinning
- [ ] **Container authority modeling** — steps running inside a floating container should inherit its trust zone; currently a modeling gap (container Image node is disconnected from its steps)
- [ ] **FederateIdentity recommendation refinement** — OIDC-tagged identities suggest specific provider (`actions/oidc-federation` vs. cloud-native)

### Tier 5: Second Platform (L, unlocks enterprise)

Don't rush this. Depth + correctness on GHA first.

- [ ] **Azure DevOps parser** (`taudit-parse-ado`) — stages, jobs, steps, service connections, variable groups
- [ ] Environment approvals as isolation boundaries

### Tier 6: Rule Depth (S-M each, deeper analysis)

- [x] **FloatingImage** — container images without digest pinning (Medium severity)
- [ ] **EgressBlindspot** — steps with secrets + network access + no egress constraint
- [ ] **MissingAuditTrail** — authority-bearing steps with no logging
- [ ] **Confidence scoring** — severity modulated by `AuthorityCompleteness` (Partial graph → cap max severity)
- [ ] **Custom rule loading** — user-defined rules via YAML policy files

### Tier 7: Enterprise Polish (M each)

- [x] `--no-color` flag + automatic tty detection
- [x] `--verbose` mode (full node metadata in terminal report)
- [x] Shell completions (bash, zsh, fish) — `taudit completions <shell>`
- [x] Release workflow — 5-platform binaries (linux-x64, linux-arm64, macos-x64, macos-arm64, windows-x64)
- [ ] Stable schema versioning (v1/v2 contract evolution)
- [ ] JSON Schema CI validation in quality.yml
- [ ] `cargo-audit` in CI
- [ ] Homebrew formula / nix package

### Tier 8: Graph Power (M-L each, differentiation)

- [ ] **Isolation boundary support** — explicit breaks in propagation (CellOS containment = graph boundary)
- [ ] **Subgraph extraction** per job (focus view)
- [ ] **Graphviz DOT export** from `taudit map`
- [ ] **Adjacency index** for large graphs (O(n) scan → O(1) lookup for mono-repo scale)

### AAA completion gate

- [ ] Two CI platforms supported (GHA + ADO)
- [x] `AuthorityCompleteness` propagated — parser marks Partial for reusable workflows, matrix, inferred secrets
- [ ] Identity scope modelled with OIDC/cloud identity awareness
- [x] Findings appear in GitHub code scanning (SARIF)
- [ ] PR bot posts authority changes
- [x] `.tauditignore` + `--baseline` eliminate known noise
- [ ] Composite actions parsed correctly
- [ ] All 9 finding categories implemented (7/9 done)
- [ ] Available via Homebrew + cargo install + GitHub Action
- [x] Release binaries for 5 targets (linux-x64, linux-arm64, macos-x64, macos-arm64, windows-x64)

**Estimated effort: 4-7 weeks remaining to full AAA.** Tier 4 cloud identity inference and Tier 2 PR bot are the highest remaining leverage.

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

- [ ] **Governance correlation schema** — shared CloudEvents extension attribute linking taudit findings → tsafe remediation → CellOS execution events
- [ ] **tsafe recommendation validation** — `taudit verify` confirms tsafe namespace scoping matches finding recommendations
- [ ] **CellOS spec generation** — `taudit emit-spec` generates CellOS cell specs from isolation findings
- [ ] **Feedback loop** — `taudit scan` consumes CellOS execution events to verify containment was applied

**Self-hosting:**

- [ ] **taudit scans taudit** — quality.yml includes `taudit scan` as a CI step with zero findings
- [ ] **taudit scans tsafe** — zero findings
- [ ] **taudit scans CellOS** — zero findings

**Complete rule coverage:**

- [ ] All 9 finding categories implemented with tests
- [ ] **Policy-as-code** — YAML rule definitions loaded at runtime
- [ ] **Rule documentation** — each rule has a doc page explaining what it detects, why, and how to fix

**Complete output coverage:**

- [x] Terminal, JSON, CloudEvents JSONL, SARIF — all four formats done
- [ ] **JetStream publish adapter** — optional direct NATS publish for CellOS-integrated deployments
- [ ] **Governance correlation ID** in CloudEvents extension attributes

**Operational maturity:**

- [ ] SBOM generation per release
- [ ] Signed releases (cosign or minisign)
- [ ] Fuzzing (cargo-fuzz on parser inputs)
- [ ] Property-based tests (proptest on graph invariants)
- [ ] Benchmark suite (criterion on propagation engine scaling)
- [ ] Interactive TUI for `taudit map` (ratatui)
- [ ] Watch mode — `taudit scan --watch` re-runs on file change

### Done completion gate

- [ ] Three CI platforms parsed (GHA + ADO + GitLab)
- [ ] All 5 failure classes from doctrine have rules
- [ ] All 9 finding categories implemented
- [ ] `AuthorityCompleteness` is `Complete` for all three parsers (every authority primitive modelled)
- [ ] Identity scope modelled for OIDC, service principals, cloud identities
- [ ] Governance loop has correlation IDs across taudit/tsafe/CellOS
- [ ] taudit scans all three sister projects with zero findings
- [ ] Policy-as-code supports user-defined rules
- [x] Four output formats (terminal, JSON, CloudEvents, SARIF)
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
| Full IAM resolution | taudit classifies scope (broad/constrained/unknown), not what each permission means |
| Shell script evaluation | Inferred secret detection via pattern matching, not execution |

---

## Known Modeling Gaps

Documented incompleteness — not bugs, but places where the graph underapproximates reality.

| Gap | Impact | Fix direction |
|-----|--------|---------------|
| Container → step authority | Steps inside a floating container inherit its supply chain risk, but no `UsesImage` edge connects them. `FloatingImage` flags the image; propagation doesn't escalate steps running in it. | Add `UsesImage` edge from each step to its job's container Image node in the parser |
| Composite actions | `uses: ./.github/actions/foo` with `using: composite` hides sub-steps from the graph entirely | Parse `action.yml` and inline steps; mark Partial if action.yml is unavailable |
| Expression conditionals | `if: ${{ github.event_name == 'push' }}` — steps with conditionals are modelled as always-executing | Mark steps with `if:` as Partial-contributing (low priority — this is conservative, not dangerous) |
| Reusable workflow authority | `job.uses` marks the graph Partial but doesn't model what secrets/identities the called workflow uses | Would require fetching and parsing the called workflow's YAML |

---

## Pressure Points

### 1. Parser Fidelity → Authority Truth

**Resolved:**
- ✅ Inferred secrets in `run:` blocks
- ✅ Workflow/job-level `env:` inheritance
- ✅ Reusable workflow detection (`job.uses`)
- ✅ Matrix strategy marking graph Partial
- ✅ `pull_request_target` trust zone classification
- ✅ Job container images

**Still open:**
- Composite actions (steps hidden behind `action.yml`)
- Expression evaluation in conditionals

### 2. Identity Modelling Depth

**Resolved:**
- ✅ `IdentityScope` classification (Broad/Constrained/Unknown)
- ✅ OIDC-capable identity tagged (`META_OIDC`)

**Still open:**
- Cloud identity inference (AWS/GCP/Azure action detection)
- Scope propagation escalation (Broad → Untrusted = always Critical)
- Container trust zone not propagated to steps running inside it

---

## Visual Summary

```
MVP ═══════════════════════════════════════════════════════════ ✅ SHIPPED
  AuthorityCompleteness · IdentityScope · inferred secrets
  env inheritance · .tauditignore · --threshold
  real-world validation · README

                              ↓
AAA ══════════════════════════╪══════════════════════ YOU ARE HERE
  T1: noise elimination    ✅ DONE
  T2: platform integration ◑ SARIF+diff+stdin done; PR bot+GHA pending
  T3: parser precision     ◑ reusable/matrix/container/PRT done; composite pending
  T4: identity depth       ◑ OIDC tagging done; cloud inference pending
  T5: Azure DevOps         ○ not started
  T6: rule depth           ◑ FloatingImage done; Egress/Audit pending
  T7: enterprise polish    ◑ completions+release+color+verbose done
  T8: graph power          ○ not started
                              |
DONE ═════════════════════════╪═════════════════════════════════ future
  GitLab parser               |
  governance correlation      |
  self-hosting                |
  policy-as-code              |
  JetStream adapter           |
  fuzzing + SBOM              |
```
