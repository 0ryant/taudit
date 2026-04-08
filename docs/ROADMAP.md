# taudit Roadmap

Three horizons. Each is a superset of the previous.

**Current state:** 6 crates, 36 tests, 2,469 LOC, 6 analysis rules, 1 parser (GitHub Actions), 3 output formats (terminal, JSON, CloudEvents JSONL), 2 commands (scan, map).

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
| 3 | 6 analysis rules with severity graduation and deduplication | Done |
| 4 | Finding model with path evidence and remediation routing | Done |
| 5 | GitHub Actions parser with trust zone classification | Done |
| 6 | Terminal report with propagation path visualization | Done |
| 7 | JSON report with JSON Schema contract | Done |
| 8 | CloudEvents JSONL sink with schema | Done |
| 9 | Authority map command | Done |
| 10 | CI pipeline (fmt, clippy, test, deny, dependabot) | Done |
| 11 | 36 tests (unit + integration + sink) | Done |

### Precision (do first — the credibility layer)

The graph is only as good as the parser. If taudit can't parse something, it must say so — not silently produce an incomplete graph.

| # | Item | Effort | Why |
|---|------|--------|-----|
| **12** | **`AuthorityCompleteness` enum on `AuthorityGraph`** | **S** | Marks the graph as `Complete`, `Partial`, or `Unknown`. If a step uses `${{ secrets.X }}` inside a shell `run:` block and the parser can't precisely map it, the graph is `Partial` — not silently incomplete. Propagated to terminal/JSON/CloudEvents output. |
| **13** | **`IdentityScope` classification on Identity nodes** | **S** | Classifies identity scope as `Broad` (write-all, admin), `Constrained` (contents:read), or `Unknown`. `Unknown` treated as risky. Prevents shallow identity modelling from missing over-scoped cloud identities (OIDC, service principals). |
| **14** | **Inferred secret detection in `run:` blocks** | **S** | Scan shell script strings for `${{ secrets.* }}` patterns. Mark these as `inferred` (not precisely mapped) in graph metadata. Today the parser only catches `env:` and `with:` blocks. |
| **15** | **`env:` inheritance (job-level → step-level)** | **S** | Job-level `env:` with secret references propagate to all steps. Currently missed — only step-level `env:` and `with:` are parsed. |

### Noise reduction (do second — the adoption layer)

| # | Item | Effort | Why |
|---|------|--------|-----|
| **16** | **`.tauditignore`** | **M** | Suppress known-accepted findings. Glob + category matching. Without this, every repo with GITHUB_TOKEN in SHA-pinned actions generates noise. |
| **17** | **`--severity-threshold` flag** | **S** | Exit 1 only above threshold. Lets CI pass on medium/low findings while still reporting them. |

### Real-world validation (do third — the truth layer)

| # | Item | Effort | Why |
|---|------|--------|-----|
| **18** | **Run on employer's production workflows** | **M** | The harsh test. Looking for: false positives, missed propagation, confusing output. This is where most tools die. |
| **19** | **Tune findings from real-world signal** | **S** | Adjust severity graduation, deduplication, and message clarity based on what real pipelines surface. Better modelling > better filtering. |

### Packaging (do last — the distribution layer)

| # | Item | Effort | Why |
|---|------|--------|-----|
| **20** | **README with install + quickstart + example output** | **S** | Sharp narrative: "show exactly how secrets and permissions move through your pipeline — and where they cross trust boundaries." |
| **21** | **`cargo install taudit` (publish to crates.io)** | **S** | Frictionless install path. |

### MVP ship gate

- [ ] `AuthorityCompleteness` marks graphs as Complete/Partial — no silent incompleteness
- [ ] `IdentityScope` classifies identity breadth — Unknown treated as risky
- [ ] Inferred secrets in `run:` blocks detected and marked
- [ ] Job-level `env:` inheritance parsed
- [ ] Zero false positives on employer's production workflows
- [ ] `.tauditignore` suppresses known-accepted risks
- [ ] `--severity-threshold` lets CI pass on medium/low
- [ ] README with sharp narrative
- [ ] Available via `cargo install`

**Remaining effort: ~3-5 days.** Precision items are S each but gate everything else.

---

## Roadmap 2: AAA — Competitive with Commercial Tools

> Gate: a platform engineering team adopts taudit as their standard pipeline security tool, replacing manual review.

Organized by impact tier. Each tier unlocks a class of adoption.

### Tier 1: Noise Elimination (S each)

These determine whether teams keep using taudit past day 1.

- [ ] `.tauditignore` with glob + category matching (from MVP)
- [ ] `--severity-threshold` flag (from MVP)
- [ ] `--exclude` glob patterns for generated/vendored workflows
- [ ] `--baseline` file (suppress findings from a known-good scan)
- [ ] `--quiet` mode (summary counts only, for CI logs)

### Tier 2: Platform Integration (M each, highest leverage)

Put findings where engineers already look.

- [ ] **SARIF output adapter** — findings appear in GitHub code scanning tab
- [ ] **`taudit diff`** — before/after authority graph diff between pipeline versions
- [ ] **PR comment bot** — `taudit diff base..head` posts authority changes to PR
- [ ] **GitHub Action** — `uses: taudit-dev/taudit-action@sha` with configurable severity gate

### Tier 3: Parser Precision (M-L each, real-world correctness)

Real GHA workflows use features the current parser doesn't handle. Priority order by likelihood of encountering in real repos.

- [ ] **Reusable workflow support** (`workflow_call` inputs/secrets passthrough)
- [ ] **Composite action parsing** (action.yml with `using: composite`)
- [ ] **Trigger-based trust classification** (pull_request_target = untrusted source)
- [ ] **Expression evaluation** (`${{ github.event_name }}` in conditionals)
- [ ] **Matrix strategy awareness** (trust zones may differ per matrix entry)
- [ ] **`AuthorityCompleteness::Partial` propagation** for unsupported YAML constructs — flag what the parser skipped, not just what it found

### Tier 4: Identity Depth (M each, the dangerous gap)

Identity modelling is the biggest long-term risk. Modern pipelines use OIDC tokens, service principals, and cloud identities with massive over-scope by default.

- [ ] **OIDC token detection** — `permissions: id-token: write` → identity with federated scope
- [ ] **Cloud identity inference** — AWS role assumption, Azure federated credentials detected from action inputs
- [ ] **Scope propagation** — if an identity is `Broad` and propagates to an `Untrusted` step, escalate severity
- [ ] **Identity recommendation refinement** — `FederateIdentity` recommendations carry specific OIDC provider suggestions

### Tier 5: Second Platform (L, unlocks enterprise)

Don't rush this. Depth + correctness on GHA first. ADO only when GHA is fully proven.

- [ ] **Azure DevOps parser** (`taudit-parse-ado`) — stages, jobs, steps, service connections, variable groups
- [ ] Environment approvals as isolation boundaries

### Tier 6: Rule Depth (S-M each, deeper analysis)

Don't over-expand rules before identity depth. Authority propagation is the core narrative — keep it sharp.

- [ ] **EgressBlindspot** — steps with secrets + network access + no egress constraint
- [ ] **MissingAuditTrail** — authority-bearing steps with no logging
- [ ] **FloatingImage** — container images without digest pinning
- [ ] **Confidence scoring** — severity modulated by context + `AuthorityCompleteness`
- [ ] **Custom rule loading** — user-defined rules via YAML policy files

### Tier 7: Enterprise Polish (M each)

- [ ] `--no-color` flag + automatic tty detection
- [ ] `--verbose` mode (full node metadata in terminal report)
- [ ] Stable schema versioning (v1/v2 contract evolution)
- [ ] JSON Schema CI validation in quality.yml
- [ ] Release workflow with multi-platform binaries (linux-x64, linux-arm64, darwin-x64, darwin-arm64)
- [ ] `cargo-audit` in CI
- [ ] Homebrew formula / nix package
- [ ] Shell completions (bash, zsh, fish)

### Tier 8: Graph Power (M-L each, differentiation)

- [ ] **Isolation boundary support** — explicit breaks in propagation (CellOS containment = graph boundary)
- [ ] **Subgraph extraction** per job (focus view)
- [ ] **Graphviz DOT export** from `taudit map`
- [ ] **Adjacency index** for large graphs (O(n) scan → O(1) lookup for mono-repo scale)

### AAA completion gate

- [ ] Two CI platforms supported (GHA + ADO)
- [ ] `AuthorityCompleteness` propagated through all outputs
- [ ] Identity scope modelled with OIDC/cloud identity awareness
- [ ] Findings appear in GitHub code scanning (SARIF)
- [ ] PR bot posts authority changes
- [ ] `.tauditignore` + `--baseline` eliminate all noise
- [ ] Reusable workflows and composite actions parsed correctly
- [ ] All 9 finding categories implemented
- [ ] Available via Homebrew + cargo install + GitHub Action
- [ ] Release binaries for 4 targets

**Estimated effort: 6-10 weeks solo.** Tier 1-3 are the highest leverage. Tier 4 (identity depth) is the long-term credibility play.

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

- [ ] Terminal, JSON, CloudEvents JSONL, SARIF — all four formats
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
| Full IAM resolution | taudit classifies scope (broad/constrained/unknown), not what each permission means |
| Shell script evaluation | Inferred secret detection via pattern matching, not execution |

---

## Pressure Points (from external review)

Two structural weak points that gate credibility:

### 1. Parser Fidelity → Authority Truth

The graph is only as good as the parser. GitHub Actions is not declarative in the way the model assumes.

**Not yet handled:**
- `${{ secrets.X }}` inside `run:` shell scripts (inferred, not precise)
- Composite actions hiding steps
- Reusable workflows (`workflow_call`)
- Matrix expansions changing authority shape
- `env:` inheritance (job → step)

**Fix direction:** Don't try to evaluate everything. Mark unknown authority with `AuthorityCompleteness::Partial` and propagate it. False confidence in incomplete graphs is worse than being noisy.

### 2. Identity Modelling Depth

Identity nodes capture `write-all` / `contents:read` permission strings. But the real risk is *what the identity can actually do* — OIDC tokens, service principals, and cloud identities carry massive implicit scope.

**Fix direction:** Add `IdentityScope` classification (`Broad` / `Constrained` / `Unknown`). Treat `Unknown` as risky. Don't try to resolve full IAM — classify the breadth.

### What NOT to do yet (even though it's tempting)

| Skip | Why |
|---|---|
| Rush ADO parser | Don't need platform breadth to prove the thesis. Need depth + correctness on GHA first. |
| Over-expand rules | 6 rules clustered around authority misuse / trust boundaries / supply chain risk. That's the correct bias. Adding network modelling or audit trail gaps too early dilutes the core narrative. |
| Build dashboards | The propagation path in output is the strongest feature. Don't dilute it with summary-heavy views. |
| Automate the governance loop | Manual `tsafe exec` from recommendation text is the right UX at 1 customer. |

---

## Visual Summary

```
                         YOU ARE HERE
                              |
                              v
MVP ═══════════════════[precision]═══[noise]═══[validate]═══[package]══ ship gate
  AuthorityCompleteness    .tauditignore    real repos       README
  IdentityScope            --threshold      tune findings    crates.io
  inferred secrets
  env inheritance
                              |
AAA ══════════════════════════╪═════════════════════════════════════ competitive
  T1: noise elimination       |
  T2: SARIF + PR bot          |
  T3: parser precision        |
  T4: identity depth          |
  T5: Azure DevOps            |
  T6: all 9 rules             |
  T7: enterprise polish       |
  T8: graph power             |
                              |
DONE ═════════════════════════╪═════════════════════════════════════════ complete
  GitLab parser               |
  governance correlation      |
  self-hosting                |
  policy-as-code              |
  JetStream adapter           |
  fuzzing + SBOM              |
```
