# taudit Roadmap

Three horizons. Each is a superset of the previous.

**Current state (post-v0.9.2):** 9 crates, 487 tests, 38 built-in authority invariants + custom YAML invariant DSL (negation, typed metadata predicates, multi-value selectors, `graph_metadata:`, `standalone:`, multi-doc YAML), 3 parsers (GHA + ADO + GitLab CI), 11 commands (scan, verify, graph, map, diff, invariants, explain, version, completions, **baseline**, **suppressions**), 4 output formats (terminal, JSON, CloudEvents JSONL, SARIF) + Graphviz DOT. Stable finding fingerprint (SHA-256) parity across all output formats AND per-pipeline baselines (`baseline_fingerprint_matches_sarif_fingerprint` test enforces byte-equality). Per-pipeline baselines (`.taudit/baselines/<hash>.json`) ship as the v0.10 adoption mechanism — opt-in (no `.taudit/` => today's behaviour), content-hash-keyed, with the council-mandated "criticals always exit 1 unless waived with severity_override + reason + expires_at <= 90d" contract. New subcommands: `taudit baseline {init, accept, diff, review}` plus `taudit suppressions {list, add, review}`. Reference consumers in Python/Go/TypeScript at `examples/consumers/`. Stack integration specs at `docs/integrations/`. v0.9.x ships as the v1.0 release candidate line — CLI contract, graph schema (`schemas/authority-graph.v1.json`), baseline schema (`schemas/baseline.v1.json`), and invariant DSL are intended to be stable. Published to crates.io.

**Effort key:** S = hours, M = days, L = week+

**Core thesis (from external review):** taudit's credibility depends on how it handles ambiguity and incompleteness. If it overclaims certainty, it will get dismissed. If it handles unknowns honestly, it will gain trust. The next iteration is not more features — it's precision under uncertainty.

---

## Strategic framing

taudit's category is not "pipeline security scanner." Its category is **authority modelling for CI/CD**. Most security tools scan configs and pattern-match. taudit treats a pipeline as a typed graph of authority propagation — `NodeKinds` × `TrustZones` × `EdgeKinds` — and lets every other behaviour (scan, map, SARIF, custom invariants, PR-gate verify) be a consumer of that graph.

The frame: **CI/CD is an untyped authority system. taudit makes it explicit, inspectable, and enforceable.** That puts taudit alongside type systems, policy engines, and trust systems — not alongside linters.

**Stack positioning.** taudit is the graph layer of a small composable stack. **tsign** (sibling project) is the attestation layer that signs claims about which authority paths existed at build time. **axiom** (sibling project) is the enforcement brain that consumes graphs and attestations across many repos to make merge / deploy decisions. The CI providers (GHA, ADO, GitLab) are substrate. Keeping the graph stable, versioned, and inspectable is therefore a higher-priority deliverable than any individual new invariant.

**What "Done" actually means now.** A re-publishable contract. An authoritative authority-graph specification, a reference implementation that is `Complete` (not `Partial`) across three platforms, a stable invariant DSL, and `taudit verify` with semver-stable semantics. A downstream tool should be able to depend on taudit's graph schema the same way you depend on a programming language's grammar — versioned, breaking changes only on a major bump.

See [`positioning.md`](positioning.md) for the long-form framing and [`authority-graph.md`](authority-graph.md) for the specification.

---

## Near term: the v1.0 charter

Before chasing more invariants or platforms, v1.0 turns the existing authority model into a contract. No date — this is a quality bar, not a release calendar.

| # | Item | Effort | Status |
|---|------|--------|--------|
| **V1-1** | **Versioned graph schema** — JSON Schema for the `AuthorityGraph` (`NodeKinds`, `TrustZones`, `EdgeKinds`, completeness flags, metadata keys), published under `contracts/schemas/`, validated in CI. Becomes the contract downstream tools depend on. | M | Not started |
| **V1-2** | **Stable invariant DSL** — promote the v0.4.0 custom-rule YAML loader to a v1 schema with documented predicate vocabulary; semver-stable; future fields are additive. | M | Not started |
| **V1-3** | **`taudit verify` command** — explicit invariant-set gate for PRs. Inputs: graph + invariant set (built-ins + custom). Output: pass / fail per invariant, machine-readable. Semver-stable exit-code semantics. | M | Not started |
| **V1-4** | **`taudit graph` command** — first-class graph generator separate from `scan` and `map`. Default emits the v1 graph schema as JSON; `--format dot` for Graphviz. The graph artifact stops being a side effect of other commands. | S | Not started |
| **V1-5** | **Three-platform parity at `Complete`** — every parser (GHA, ADO, GitLab) reaches `AuthorityCompleteness::Complete` on its supported feature surface, with every gap explicitly modelled rather than silently approximated. | L | In progress |
| **V1-6** | **Re-publishable contract docs** — `docs/authority-graph.md` (specification), `docs/positioning.md` (framing), versioned changelog for the graph schema separate from product CHANGELOG. | S | In progress |

When all six land, taudit is no longer "a pipeline scanner with extra structure" — it is the authority graph layer of the broader stack, and tsign / axiom / future consumers can build on a stable surface.

---

## Roadmap 1: MVP — Credible on Real Pipelines

> Frame: the authority graph is real, deterministic, and trustworthy on the workflows engineers actually run. Gate: a security engineer at your employer can run `taudit scan` on every repo, trust the output, and understand what the model does and doesn't know.

### Already shipped

| # | Item | Status |
|---|------|--------|
| 1 | Authority graph with typed nodes, edges, trust zones | Done |
| 2 | BFS propagation engine with configurable depth | Done |
| 3 | 16 analysis rules with severity graduation and deduplication | Done |
| 4 | Finding model with path evidence and remediation routing | Done |
| 5 | GitHub Actions parser with trust zone classification | Done |
| 5b | Azure DevOps parser (stages/jobs/steps, service connections, variable groups, template references) | Done — v0.2.0 |
| 6 | Terminal report with propagation path visualization | Done |
| 7 | JSON report with JSON Schema contract | Done |
| 8 | CloudEvents JSONL sink with schema | Done |
| 9 | Authority map command | Done |
| 10 | CI pipeline (fmt, clippy, test, deny, dependabot) | Done |
| 11 | 181 tests (unit + integration + sink) | Done |

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
| **18** | Run on production workflows | M | Done — 10 workflows across taudit/tsafe/runtime-isolation repos |
| **19** | Tune findings from real-world signal | S | Done — constrained+pinned graduated to Medium |

### Packaging

| # | Item | Effort | Status |
|---|------|--------|--------|
| **20** | README with install + quickstart + example output | S | Done |
| **21** | `cargo install taudit` (publish to crates.io) | S | Done — v0.3.0 live on crates.io |

### MVP ship gate

- [x] `AuthorityCompleteness` marks graphs as Complete/Partial — no silent incompleteness
- [x] `IdentityScope` classifies identity breadth — Unknown treated as risky
- [x] Inferred secrets in `run:` blocks detected and marked
- [x] Workflow/job-level `env:` inheritance parsed
- [x] Zero false positives on production workflows (10 workflows, 3 projects)
- [x] `.tauditignore` suppresses known-accepted risks
- [x] `--severity-threshold` lets CI pass on medium/low
- [x] README with sharp narrative
- [x] Available via `cargo install` — v0.3.0 published to crates.io

**Status: MVP complete.** v0.3.0 published to crates.io.

---

## Roadmap 2: AAA — Competitive with Commercial Tools

> Frame: the authority graph is consumable from where engineers already work — code-scanning tabs, PRs, CI logs, custom rules — and is rich enough across two platforms to displace manual review. Gate: a platform engineering team adopts taudit as their standard pipeline authority tool, replacing manual review.

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
- [x] **SARIF fingerprint collapse** — `partialFingerprints` keys on `rule_id + root authority node name` so per-hop findings group into single alerts (v0.2.4)
- [x] **`taudit diff`** — before/after authority graph diff between pipeline versions
- [x] **`taudit explain`** — list all 16 rules with severity, or get full description and remediation for one rule (v0.2.3)
- [x] **`--omit-empty`** — `--quiet` mode silently skips files with zero findings (v0.2.4)
- [x] **`--collapse-template-instances`** — groups findings sharing `(category, root authority node)` into one summary finding per file (v0.2.4)
- [x] **Stdin pipe support** — `cat workflow.yml | taudit scan -`
- [x] **PR comment bot** — `.github/workflows/taudit-pr-diff.yml` diffs authority graph on every PR touching pipeline files and posts a comment (v0.2.6)
- [x] **GitHub Action** — `.github/actions/taudit-scan/` composite action, `uses: ./.github/actions/taudit-scan` with 7 inputs and `findings-count` output (v0.2.6)

### Tier 3: Parser Precision (M-L each, real-world correctness)

Real GHA workflows use features that affect the completeness of the authority graph.

- [x] **Reusable workflow detection** — `job.uses` creates DelegatesTo edge, marks graph Partial
- [x] **Trigger-based trust classification** — `pull_request_target` marks `run:` steps Untrusted
- [x] **Matrix strategy** — jobs with `strategy.matrix` mark graph Partial
- [x] **Workflow-level `env:` inheritance** — secrets defined at workflow root visible to all steps
- [x] **Job container images** — `job.container` parsed, `FloatingImage` rule applies
- [x] **Composite action parsing** — action.yml with `using: composite` inlined as Step nodes with DelegatesTo edges; missing/non-composite marks graph Partial (v0.3.0)
- [ ] **Expression evaluation** — `${{ github.event_name }}` in conditionals not resolved

### Tier 4: Identity Depth (M each, the dangerous gap)

Identity modelling is the biggest long-term risk. Modern pipelines use OIDC tokens, service principals, and cloud identities with massive over-scope by default.

- [x] **OIDC token detection** — `id-token: write` tags identity as OIDC-capable (`META_OIDC`)
- [x] **Cloud identity inference** — `aws-actions/configure-aws-credentials` (role-to-assume), `google-github-actions/auth` (workload_identity_provider), `azure/login` (client-id without client-secret) each create a Broad OIDC Identity node; static credential paths fall through to existing `with:` secret scanning
- [x] **Container authority modeling** — steps inside a job container now have `UsesImage` edges to the container Image node; authority propagates through it (floating container = Untrusted sink)
- [x] **Scope propagation escalation** — OIDC identity reaching any ThirdParty sink (pinned or not) is Critical; cloud blast radius means SHA pinning doesn't bound impact (v0.3.0)
- [ ] **FederateIdentity recommendation refinement** — OIDC-tagged identities suggest specific provider (`actions/oidc-federation` vs. cloud-native)

### Tier 5: Second Platform ✅ Done — v0.2.0

- [x] **Azure DevOps parser** (`taudit-parse-ado`) — stages, jobs, steps, `System.AccessToken`, service connections, variable groups, template references, pool tagging (`self_hosted`), `checkout: self`, `META_IMPLICIT` for platform-injected identities (v0.2.0)
- [x] **`--platform azure-devops` CLI flag** — selects parser per scan (v0.2.0)
- [x] **`--platform auto` (default)** — sniffs each file's YAML structure independently; `on:` → GHA, `trigger:`/`pr:`/`stages:`/`jobs:` → ADO (v0.2.6)
- [x] **Three ADO PR-boundary rules** — `variable_group_in_pr_job`, `self_hosted_pool_pr_hijack`, `service_connection_scope_mismatch` (v0.2.3)
- [x] **Environment approvals as isolation boundaries** — ADO `environment:` with required approvals tags job steps with `META_ENV_APPROVAL`; findings crossing the gate are downgraded one severity step (v0.3.0)

### Tier 6: Rule Depth (S-M each, deeper analysis)

- [x] **FloatingImage** — container images without digest pinning (Medium severity)
- [x] **PersistedCredential** — `persistCredentials: true` writes token to disk (v0.2.0)
- [x] **TriggerContextMismatch** — `pull_request_target` / ADO `pr:` with authority-bearing steps
- [x] **CrossWorkflowAuthorityChain** — authority-bearing step delegates to external/untrusted workflow
- [x] **AuthorityCycle** — workflow delegation graph contains a cycle
- [x] **UpliftWithoutAttestation** — OIDC-privileged build produces no signed provenance
- [x] **SelfMutatingPipeline** — step writes `GITHUB_ENV` / `GITHUB_PATH` to inject into later steps
- [x] **CheckoutSelfPrExposure** — PR-triggered pipeline checks out repo; attacker-controlled code lands on runner (v0.2.6)
- [x] **VariableGroupInPrJob** (ADO) — variable-group secrets reachable from PR-triggered job
- [x] **SelfHostedPoolPrHijack** (ADO) — PR pipeline runs on self-hosted agent and checks out repo
- [x] **ServiceConnectionScopeMismatch** (ADO) — broad-scope service connection reachable from PR job
- [ ] **EgressBlindspot** — steps with secrets + network access + no egress constraint
- [ ] **MissingAuditTrail** — authority-bearing steps with no logging
- [x] **Confidence scoring** — severity modulated by `AuthorityCompleteness` (Partial graph → cap max severity at High)
- [x] **Custom rule loading** — `--rules-dir <path>` loads YAML rule files at runtime; declarative source/sink/path predicates; SARIF dynamic registration (v0.4.0)

### Tier 7: Enterprise Polish (M each)

- [x] `--no-color` flag + automatic tty detection
- [x] `--verbose` mode (full node metadata in terminal report)
- [x] Shell completions (bash, zsh, fish) — `taudit completions <shell>`
- [x] Release workflow — 5-platform binaries (linux-x64, linux-arm64, macos-x64, macos-arm64, windows-x64)
- [x] Stable schema versioning (v1/v2 contract evolution)
- [x] JSON Schema CI validation in quality.yml
- [x] `cargo-audit` in CI
- [x] Homebrew formula / nix package
- [x] **`taudit map` layout** — terminal-width-aware column pagination, zone abbreviation (`1P` / `3P` / `?`), `✓` / `·` access markers, step/authority name capping

### Tier 8: Graph Power (M-L each, differentiation)

- [ ] **Isolation boundary support** — explicit breaks in propagation (runtime containment = graph boundary)
- [x] **Subgraph extraction** per job — `taudit map --job <name>` filters to BFS-reachable subgraph; unknown job name lists available jobs (v0.4.0)
- [x] **Graphviz DOT export** — `taudit map --format dot`; node shape=kind, color=trust zone, edge label=kind; combine with `--job` for focused diagrams (v0.4.0)
- [ ] **Adjacency index** for large graphs (O(n) scan → O(1) lookup for mono-repo scale)

### AAA completion gate

- [x] Two CI platforms supported (GHA + ADO)
- [x] `AuthorityCompleteness` propagated — parser marks Partial for reusable workflows, matrix, inferred secrets
- [x] Identity scope modelled with OIDC/cloud identity awareness — OIDC identity reaching ThirdParty sink escalates to Critical (v0.3.0)
- [x] Findings appear in GitHub code scanning (SARIF)
- [x] PR bot posts authority changes (v0.2.6)
- [x] `.tauditignore` + `--baseline` eliminate known noise
- [x] Composite actions parsed correctly — action.yml inlined as Step nodes with DelegatesTo edges (v0.3.0)
- [x] 17 analysis rules covering propagation, identity, supply chain, artifact, trigger, delegation, attestation, mutation, ADO PR boundaries, and PR checkout exposure
- [x] Available via Homebrew + cargo install + GitHub Action (v0.2.6)
- [x] Release binaries for 5 targets (linux-x64, linux-arm64, macos-x64, macos-arm64, windows-x64)

**AAA gate: ✅ CLOSED as of v0.3.0.** All gate criteria met. Remaining work (T8 graph power, custom rule loading) advances toward Roadmap 3: Done.

---

## Roadmap 3: Done — Feature Complete

> Frame: the authority model is a re-publishable contract. Three platforms reach `AuthorityCompleteness::Complete`, the invariant DSL is stable, `taudit verify` is semver-stable, and downstream tools (tsign, axiom) can depend on the graph schema the way you depend on a language grammar. Gate: taudit models every authority primitive in the three major CI/CD platforms, covers every failure class from the doctrine, integrates with the operator's existing toolchain, and scans itself.

"Done" is reachable because taudit's scope is bounded by the authority model, not the security landscape. Unlike CVE scanners (infinite new CVEs) or policy engines (infinite policies), taudit models a finite set of authority primitives. When every primitive is captured and every failure class has invariants, the model is complete.

### What "Done" adds beyond AAA

**Third parser:**

- [x] **GitLab CI parser** (`taudit-parse-gitlab`) — stages, jobs, secrets, images — v0.5.0
- [ ] `include:` template resolution (remote + local)
- [ ] Protected branch rules as trust boundaries
- [ ] GitLab CI/CD variables with scope (environment, group)

**Governance loop completion:**

- [ ] **Governance correlation schema** — shared CloudEvents extension attribute linking taudit findings → tsafe remediation → runtime execution events
- [ ] **tsafe recommendation validation** — `taudit verify` confirms tsafe namespace scoping matches finding recommendations
- [ ] **Runtime spec generation** — `taudit emit-spec` generates execution-cell specs from isolation findings
- [ ] **Feedback loop** — `taudit scan` consumes runtime execution events to verify containment was applied

**Self-hosting:**

- [x] **taudit scans taudit** — quality.yml includes `taudit scan .github/workflows/` as a CI step (v0.2.6)
- [ ] **taudit scans tsafe** — zero findings
- [ ] **taudit scans runtime isolation harness** — zero findings

**Complete authority invariant coverage:**

- [ ] All 9 finding categories implemented with tests
- [ ] **First-class invariant DSL** — declarative invariants over the typed graph (`source` / `sink` / `path` predicates over `NodeKinds` × `TrustZones` × `EdgeKinds`), loaded from YAML at runtime, with semver-stable schema. The v0.4.0 custom-rule loader is the prototype; v1.0 makes the surface a contract.
- [ ] **Invariant documentation** — each built-in and custom invariant has a doc page explaining what it detects, why, and how to fix

**Complete output coverage:**

- [x] Terminal, JSON, CloudEvents JSONL, SARIF — all four formats done
- [ ] **JetStream publish adapter** — optional direct NATS publish for runtime-integrated deployments
- [ ] **Governance correlation ID** in CloudEvents extension attributes

**Operational maturity:**

- [x] SBOM generation per release
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
- [ ] Governance loop has correlation IDs across taudit/tsafe/runtime-executor
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
| ~~Container → step authority~~ | ~~Steps inside a floating container inherit its supply chain risk, but no `UsesImage` edge connects them.~~ | ✅ Fixed — `UsesImage` edges now connect each step to its job container |
| Composite actions | `uses: ./.github/actions/foo` with `using: composite` hides sub-steps from the graph entirely | Parse `action.yml` and inline steps; mark Partial if action.yml is unavailable |
| Expression conditionals | `if: ${{ github.event_name == 'push' }}` — steps with conditionals are modelled as always-executing | Low priority — conservative (over-reports), not dangerous |
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
- ✅ Job container images with `UsesImage` edges to all steps in the job

**Still open:**
- Composite actions (steps hidden behind `action.yml`)
- Expression evaluation in conditionals

### 2. Identity Modelling Depth

**Resolved:**
- ✅ `IdentityScope` classification (Broad/Constrained/Unknown)
- ✅ OIDC-capable identity tagged (`META_OIDC`)
- ✅ Cloud identity inference (AWS/GCP/Azure OIDC action detection)
- ✅ Container authority propagation to steps

**Still open:**
- Scope propagation escalation nuance (cloud OIDC identity to pinned ThirdParty sink)

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
  T2: platform integration ✅ DONE — SARIF+fingerprint+diff+explain+stdin+omit-empty+collapse+PR-bot+GHA-action
  T3: parser precision     ◑ reusable/matrix/container/PRT done; composite pending
  T4: identity depth       ◑ OIDC tagging + cloud inference + container auth done; escalation nuance pending
  T5: Azure DevOps         ✅ DONE — v0.2.0 + v0.2.3 PR-boundary rules + v0.2.6 auto-detect
  T6: rule depth           ◑ 11 rules done (FloatingImage, PersistedCredential, TriggerCtx, CrossWorkflow, Cycle, Uplift, SelfMutating, 3 ADO PR rules, CheckoutSelfPrExposure); Egress/Audit/custom pending
  T7: enterprise polish    ◑ completions+release+color+verbose+map-layout done
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
