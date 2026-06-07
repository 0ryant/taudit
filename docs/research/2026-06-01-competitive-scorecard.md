# taudit competitive scorecard evidence pass

Date: 2026-06-01
Status: point-in-time research and tasking
Decision basis:

- Ecosystem ADR 0005: AXIOM is agentic authority infrastructure, not another
  coding agent.
- Ecosystem ADR 0006: market leadership, release-ready, production-ready, and
  best-in-class claims require current proof gates.
- taudit ADR 0013: evidence rendering and output ceilings.
- taudit ADR 0014: parser completeness and platform promise.
- taudit ADR 0015: real-input corpus provenance and runner.
- taudit ADR 0025: Marketplace install path and operator hardening.

## Scope

This file normalizes an external competitive scorecard into bounded evidence,
corrections, and task lanes. It is not launch copy.

Any public reuse must re-check volatile package, GitHub, benchmark, Marketplace,
and competitor facts on the day of publication.

## Evidence ceiling

Current safe claim:

> taudit is a graph-native CI/CD authority analyzer that models credentials,
> identities, tokens, images, artifacts, trust zones, and propagation edges, then
> evaluates findings and verify gates over that graph.

Current unsafe claims without more proof:

- market-leading
- best in class
- production-ready beyond the release gates already documented
- fastest
- broadest rule coverage
- externally benchmarked
- third-party audited

## Point-in-time observations

| Surface | Observation | Evidence |
|---------|-------------|----------|
| Published package | crates.io reports `taudit` newest/max version `1.1.5`, 760 downloads, `MIT OR Apache-2.0`, created `2026-04-09`, updated `2026-05-18`. | `CMD(Invoke-RestMethod https://crates.io/api/v1/crates/taudit, exit=0)` |
| Current repository | GitHub reports `0ryant/taudit` at 1 star, 0 forks, 0 watchers/subscribers, 385 commits, latest release `taudit v1.1.5` on 2026-05-18. | `SEARCH(github.com/0ryant/taudit, scope=public repo page/API, result=observed 2026-06-01)` |
| License transition | Published `1.1.5` remains pre-relicense `MIT OR Apache-2.0`; current repo `LICENSE` and workspace metadata are `AGPL-3.0-or-later`; README explains the pre-release license caveat. | `FILE(LICENSE)`, `FILE(Cargo.toml)`, `SEARCH(github.com/0ryant/taudit, scope=repo README, result=license caveat observed)` |
| Local main version | `crates/taudit-cli/Cargo.toml` is `1.3.0-pre`; `target/debug/taudit.exe --version` prints `taudit 1.3.0-pre`. | `FILE(crates/taudit-cli/Cargo.toml)`, `CMD(target\debug\taudit.exe --version, exit=0)` |
| Local main rule count | Current local debug binary reports `taudit - 129 rules`; `docs/rules` contains 135 rule docs excluding `index.md` alignment still needs a drift check. | `CMD(target\debug\taudit.exe explain, exit=0)`, `CMD(Get-ChildItem docs\rules -Filter *.md, exit=0)` |
| Third-party benchmark | arXiv 2601.14455v2 compares 9 GitHub Actions workflow scanners over 2,722 workflows and does not include taudit in its curated set. | `SEARCH(arxiv.org/html/2601.14455v2, scope=paper, result=curated scanner list observed)` |
| zizmor | GitHub page/API reports 5.4k stars, MIT license, latest release `v1.25.2` on 2026-05-16; the arXiv paper reports 23 rules, all 10 weakness classes, and 0.26s median per workflow for the benchmarked commit. | `SEARCH(github.com/zizmorcore/zizmor, scope=public repo, result=observed 2026-06-01)`, `SEARCH(arxiv.org/html/2601.14455v2, scope=paper, result=observed)` |
| poutine | GitHub page/API reports 468 stars and Apache-2.0; README lists GitHub Actions, GitLab, Azure DevOps, and Tekton support; README documents custom Rego and MCP integration; arXiv reports 13 rules and 0.39s median per workflow for the benchmarked commit. | `SEARCH(github.com/boostsecurityio/poutine, scope=public repo, result=observed 2026-06-01)`, `SEARCH(arxiv.org/html/2601.14455v2, scope=paper, result=observed)` |
| actionlint | GitHub page/API reports about 3.9k stars and MIT license; README positions it as a static checker for GitHub Actions workflow files with syntax, expression, action-usage, reusable-workflow, shellcheck/pyflakes, and security checks. | `SEARCH(github.com/rhysd/actionlint, scope=public repo, result=observed 2026-06-01)` |
| StepSecurity Harden-Runner | GitHub page/API reports about 1.2k stars and Apache-2.0; README positions it as a runtime CI/CD security agent for GitHub Actions runners; the arXiv paper excluded runner/runtime tools from the static-scanner benchmark. | `SEARCH(github.com/step-security/harden-runner, scope=public repo, result=observed 2026-06-01)`, `SEARCH(arxiv.org/html/2601.14455v2, scope=paper, result=observed)` |

External references:

- <https://crates.io/crates/taudit>
- <https://github.com/0ryant/taudit>
- <https://arxiv.org/html/2601.14455v2>
- <https://github.com/zizmorcore/zizmor>
- <https://docs.zizmor.sh/>
- <https://github.com/boostsecurityio/poutine>
- <https://github.com/rhysd/actionlint>
- <https://github.com/step-security/harden-runner>

## Corrections to the pasted scorecard

| Pasted claim | Status | Replacement |
|--------------|--------|-------------|
| `30 commits by 0ryant + 15 dependabot` | Stale against current GitHub page. | Use `385 commits` as a 2026-06-01 point-in-time repo metric, or omit commit counts from public copy. |
| `~17 built-in rules` | Incomplete for local `main`; likely derived from a representative README table. | Local `1.3.0-pre` debug binary reports 129 rules. Do not attribute 129 rules to crates.io `1.1.5` unless the published binary is measured separately. |
| `License ambiguity` | Directionally useful but needs sharper wording. | Call it a license-transition/due-diligence gap: crates.io `1.1.5` is pre-relicense MIT/Apache, current repo/main is AGPL-3.0-or-later, and the next published minor needs especially clear release notes. |
| `No Homebrew tap` | Not fully verified. | Local packaging includes a Homebrew formula and Nix derivation, but a live public tap/install path was not verified in this pass. |
| `zizmor 1.24+ auto-fixes` | Version detail not verified here. | zizmor docs/release notes document `--fix` for a subset of findings, including template-injection; quote current docs before using a version threshold. |
| `Harden-Runner 600+ stars` | Stale against current GitHub page/API. | Current point-in-time value is about 1.2k stars. |

## Bounded competitive read

Use taudit when the adoption question is:

- Which identity, secret, token, image, or artifact can reach which step?
- Did authority cross a trust boundary?
- Can the finding be expressed as graph evidence and gated with stable verify
  semantics?
- Is cross-provider CI/CD modeling required?

Use actionlint alongside taudit for GitHub Actions syntax, expression, runner,
and authoring correctness. taudit should not claim to replace it.

Use zizmor as the default comparison point for GitHub Actions-only security
scanning, especially where community adoption, speed evidence, and auto-fix
support matter more than cross-provider authority modeling.

Use poutine as the closest multi-platform static-scanner comparison, especially
where supply-chain heuristics, Rego policy extension, organization scanning, and
MCP integration are the evaluator's priorities.

Use Harden-Runner as complementary runtime evidence, not a static-scanner
replacement.

## Decision pass

| Decision | Outcome | Reason |
|----------|---------|--------|
| Lead with typed authority graph, not scanner-count marketing. | Take | Matches taudit positioning and ecosystem ADR 0005. |
| Treat the arXiv paper as a benchmark gap, not as evidence against taudit. | Take | The paper predates/omits taudit and provides the right comparison protocol. |
| Claim market leadership from graph novelty. | Reject | Violates ecosystem ADR 0006 without external benchmark and FP/FN evidence. |
| Rush broad auto-fix parity claims. | Reject | `taudit remediate` is still explicitly unstable and low-scope. |
| Create a new ADR today. | Defer | Existing ADRs already cover claim ceilings, parser evidence, real-input corpus, and install hardening. Add an ADR only if license strategy, benchmark methodology, or remediation scope changes product policy. |

## Task lanes

### C1: License transition clarity

Objective: make the crates.io/package/repo license story unambiguous for
adopters.

Owned files or surfaces:

- `README.md`
- `CHANGELOG.md`
- `Cargo.toml`
- `docs/release-strategy.md`
- next crates.io release metadata

Acceptance criteria:

- Next published `taudit` CLI minor has license metadata that matches the
  intended current license.
- Release notes explain that `1.1.5` remains pre-relicense MIT/Apache and the
  new line is AGPL-3.0-or-later.
- README install section points commercial/procurement evaluators to the license
  caveat and does not imply permissive embedding for current main.

Verification evidence:

- `CMD(cargo metadata --no-deps, exit=0)`
- `SEARCH(crates.io/api/v1/crates/taudit, scope=published package, result=license/version observed)`
- `FILE(README.md)`
- `FILE(CHANGELOG.md)`

Stop conditions:

- Legal/business decision about AGPL vs commercial exceptions is not final.

### B1: Benchmark and coverage map

Objective: turn the arXiv scanner benchmark gap into a reproducible taudit
evaluation plan.

Owned files or surfaces:

- `docs/research/`
- `scripts/research/`
- `docs/dogfood-corpus.md`
- `docs/perf-baseline.md`
- `docs/rc/v1.2.0/`

Acceptance criteria:

- Map taudit rules to the arXiv 10-weakness taxonomy, with explicit "not in
  scope" rows.
- Run taudit on a pinned public corpus comparable to the arXiv setup.
- Record runtime median, crash/hang count, schema-valid output count, and
  supported parser completeness.
- Do not claim FP/FN superiority without ground-truth or manual triage protocol.

Verification evidence:

- `FILE(docs/research/<benchmark-plan>.md)`
- `CMD(taudit scan <corpus> --format json, exit=<0|1 with valid output>)`
- `CMD(<schema validation>, exit=0)`

Stop conditions:

- Corpus cannot be redistributed or source URLs/SHAs cannot be pinned.
- Comparison would mix local `main` with published competitor releases without
  stating that asymmetry.

### I1: Frictionless install proof

Objective: make first-run adoption evidence stronger than "cargo install
works".

Owned files or surfaces:

- `docs/integrations/github-marketplace-action-contract.md`
- `docs/research/2026-05-23-marketplace-install-and-hardening-subtasks.md`
- `packaging/`
- `docs/release-trust.md`
- `README.md`

Acceptance criteria:

- GitHub Action hosted smoke is recorded against an immutable action ref.
- VS Code and Azure DevOps Marketplace install smoke receipts are current.
- Homebrew/Nix public install path is either verified or clearly marked as a
  local packaging asset, not a published distribution channel.
- README gives the shortest safe install path for each audience.

Verification evidence:

- `TOOL(GitHub Actions hosted smoke, result=pass)`
- `TOOL(Marketplace install smoke, result=pass)`
- `CMD(brew install <tap>/taudit, exit=0)` if a public tap is claimed
- `FILE(docs/release-trust.md)`

Stop conditions:

- Marketplace, GitHub billing, or package-publisher state blocks hosted proof.

### R1: Conservative remediation/autofix lane

Objective: make auto-remediation useful without claiming broad auto-fix parity.

Owned files or surfaces:

- `crates/taudit-cli/src/remediate.rs`
- `docs/remediation.md`
- `tests/fixtures/`
- `docs/rules/`

Acceptance criteria:

- `remediate suggest` and `remediate diff` cover at least unpinned-action and
  broad-permissions candidates as read-only guidance.
- Any `apply` transform remains opt-in, backs up files, validates YAML, and
  re-runs `verify` after rewrite.
- Public copy says "conservative remediation" until transforms cover a measured
  set of findings with rollback proof.

Verification evidence:

- `CMD(cargo test -p taudit -- remediate, exit=0)`
- `CMD(taudit remediate diff tests/fixtures/<fixture>, exit=0)`
- `FILE(docs/remediation.md)`

Stop conditions:

- A transform can alter workflow semantics without a deterministic validation
  path.

### P1: Public competitive copy ceiling

Objective: make public positioning confident but evidence-bound.

Owned files or surfaces:

- `README.md`
- `docs/positioning.md`
- `docs/marketing/`
- `docs/release-notes/`
- ecosystem catalog release surfaces

Acceptance criteria:

- Public copy says taudit is graph-native authority modeling for CI/CD, not
  "the best scanner".
- Competitor comparisons say "complementary" or "use when" rather than
  universal wins.
- Any numerical competitor comparison has a date and source.
- Any benchmark claim links to a reproducible artifact or is labelled as a gap.

Verification evidence:

- `CMD(rg "best in class|market-leading|production-ready|release-ready|fastest|broadest" README.md docs -g "*.md", result=only ceiling/negative/contextual mentions or current artifacts)`
- `FILE(docs/positioning.md)`

Stop conditions:

- A copy request asks for a stronger claim than the current evidence ceiling.

## Metrics to track

| Metric | Why it matters |
|--------|----------------|
| Time from fresh user to first valid `taudit verify` result | Install friction and adoption. |
| Runtime median per workflow on pinned public corpus | Direct comparison with scanner benchmark methodology. |
| Schema-valid output rate on public corpus | Contract reliability. |
| Parser completeness distribution by platform | Honesty around graph certainty. |
| Findings reviewed vs findings suppressed/waived | Noise and triage quality. |
| Remediation diff acceptance rate | Whether conservative fixes are useful. |
| External stars/downloads/installs over time | Distribution health, not product truth. |

## Residual risks

- GitHub stars, crates downloads, and Marketplace installs are weak adoption
  proxies and can drift daily.
- The arXiv benchmark has no ground-truth labels for correctness; it compares
  behavior, scope, and runtime.
- Current local main is ahead of crates.io `1.1.5`; all public claims must name
  which artifact they describe.
- Rule count alone is a poor quality measure. It should be paired with coverage,
  corpus behavior, false-positive review, and parser completeness.
- License interpretation is legal/procurement-sensitive. This document is not
  legal advice.
