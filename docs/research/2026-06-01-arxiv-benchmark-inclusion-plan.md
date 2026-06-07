# arXiv benchmark inclusion and reproduction path

Date: 2026-06-01
Status: execution artifact, not public claim copy

## Scope

This note answers one question: how can taudit become comparable with, or
candidate material for, the GitHub Actions workflow scanner benchmark in
arXiv:2601.14455v2?

It does not claim that taudit is benchmarked, accepted into a future rerun, or
validated by the paper authors.

Evidence ceiling:

- Safe: taudit has a plan to reproduce a comparable benchmark locally.
- Safe after execution: taudit has local benchmark evidence for the exact tag,
  corpus, command, and hardware named in the report.
- Unsafe today: taudit is included in the arXiv benchmark, externally
  benchmarked, faster, broader, more accurate, or accepted for a rerun.

## Verified public facts

| Fact | Evidence | Implication for taudit |
| --- | --- | --- |
| arXiv:2601.14455v2 is "Unpacking Security Scanners for GitHub Actions Workflows", last revised 2026-03-17, by Madjda Fares, Yogya Gamage, and Benoit Baudry. | arXiv abstract page and HTML paper. | Treat it as a current external benchmark gap, not proof for or against taudit. |
| The paper compares 9 GitHub Actions workflow scanners over scope, detection behavior, and performance. | arXiv HTML abstract and methodology. | taudit must present a GitHub Actions-only benchmark profile even though its product scope is broader. |
| The curated scanner set is: actionlint, frizbee, ggshield, pinny, poutine, scharf, scorecard, semgrep, and zizmor. | Table I in the paper. | taudit is absent and must not be described as included. |
| The paper starts from open-source workflow scanners, then filters for workflow focus, local reproducible execution, recent activity, static analyzer posture, and an operational smoke on 10 workflows. | Paper Section III. | The inclusion package must prove local execution and a stable command, not only link to crates.io. |
| The dataset is 2,722 workflows from 388 repos across verified GitHub orgs for 9 large technology companies, collected around 2026-02-27/28. | Paper Section IV-B and Table II. | taudit's dogfood corpus is not a substitute; a comparable run should use the paper dataset where license/use permits. |
| The taxonomy has 10 weakness classes: AIW, CFW, EPW, GRCW, HGW, IW, KVCW, PTW, SEW, and UDW. | Paper Table III and Section V. | taudit needs a rule-to-taxonomy map before any comparison is interpretable. |
| The public repo result CSVs currently use `TMW` in some headers where the paper Table III uses `PTW` for Privileged Trigger Weakness. | Raw `results/coverage_matrix.csv` and `results/detection_volume_matrix.csv` observed on 2026-06-01. | The taudit normalizer must canonicalize to the paper taxonomy and record the upstream raw label so no class is silently renamed. |
| Runtime is measured per workflow file with Unix `time`, repeated 3 times, using median elapsed wall-clock time, on a stated laptop. | Paper RQ3 methodology. | taudit must record full command, version, hardware, timeout policy, and cold-start behavior. |
| The paper explicitly states there is no verified ground-truth labeled dataset for correctness. | Paper threats-to-validity section. | FP/FN claims require a separate taudit labeling protocol; the paper's detection-volume tables do not prove correctness. |
| Data/code are published at `sparkrew/github-actions-security`; the repo documents dataset, weakness mapping, results, scripts, tools, and command records. | Paper Data Availability section and GitHub repo README. | The practical route is a fork/PR/issue plus direct author contact with a reproducible taudit package. |
| The paper lists author emails on the arXiv HTML page. The public repo has GitHub issues enabled. | arXiv HTML author line and GitHub API `has_issues=true` observed 2026-06-01. | Contact path exists; no public "submit a scanner" program or rerun schedule was found. |
| The observed public repo `main` head on 2026-06-01 was `09c9e167f740e32d5f5d77a785b5056bff8b7fe6`. | GitHub branches API. | Use this only as a starting pin. Re-check and pin the exact commit used when the benchmark run starts. |
| arXiv itself is a scholarly preprint host. New submissions require a registered author, may require endorsement, and are moderated. | arXiv submission and endorsement help. | Publishing our own reproduction paper is separate from being added to the original authors' benchmark. |
| arXiv submissions should be topical, refereeable scientific contributions; moderation is not peer review and may decline out-of-scope, non-scientific, insufficiently novel, or poorly prepared work. | arXiv submission guidelines and moderation help. | A taudit paper needs a research contribution and reproducible method, not product launch copy. |
| arXiv prefers TeX/LaTeX source; PDF-only submission is allowed in limited cases, but PDFs created from TeX/LaTeX source are typically rejected unless an exception applies. | arXiv submission format and PDF help. | Prepare a clean LaTeX source bundle, figures, bibliography, and ancillary artifact links rather than only a rendered PDF. |

Sources checked:

- <https://arxiv.org/abs/2601.14455>
- <https://arxiv.org/html/2601.14455v2>
- <https://github.com/sparkrew/github-actions-security>
- <https://api.github.com/repos/sparkrew/github-actions-security>
- <https://api.github.com/repos/sparkrew/github-actions-security/branches/main>
- <https://raw.githubusercontent.com/sparkrew/github-actions-security/main/tools_output/commands.md>
- <https://raw.githubusercontent.com/sparkrew/github-actions-security/main/tools.csv>
- <https://raw.githubusercontent.com/sparkrew/github-actions-security/main/results/coverage_matrix.csv>
- <https://raw.githubusercontent.com/sparkrew/github-actions-security/main/results/detection_volume_matrix.csv>
- <https://raw.githubusercontent.com/sparkrew/github-actions-security/main/results/execution_time.csv>
- <https://raw.githubusercontent.com/sparkrew/github-actions-security/main/weakness/rules_mapping.csv>
- <https://github.com/sparkrew/github-actions-security/issues>
- <https://info.arxiv.org/help/submit/index.html>
- <https://info.arxiv.org/help/endorsement.html>
- <https://info.arxiv.org/help/moderation/index.html>
- <https://info.arxiv.org/help/submit_tex.html>
- <https://info.arxiv.org/help/submit_pdf.html>
- Local: `docs/research/2026-06-01-competitive-scorecard.md`
- Local: `docs/dogfood-corpus.md`
- Local: `docs/perf-baseline.md`
- Local: `docs/rc/v1.2.0/corpus-runner.md`
- Local: `docs/rc/v1.2.0/workstreams/parser-completeness-corpus.md`
- Local: `docs/parser-feature-matrix.md`
- Local: `docs/rules/index.md`

## Evidence log

Observed source-local evidence:

- `CMD(target\debug\taudit.exe --version, exit=0)` printed
  `taudit 1.3.0-pre`.
- `CMD(target\debug\taudit.exe explain, exit=0)` printed
  `taudit - 129 rules`.
- `CMD(Get-ChildItem docs\rules -Filter *.md, exit=0)` counted 135 rule docs
  excluding `index.md`; exact rule/doc drift still needs a dedicated mapping
  pass.
- `CMD(target\debug\taudit.exe scan --help, exit=0)` showed
  `scan [OPTIONS] <PATHS>...`, `--format` values including `json`, and
  `--no-color`.
- `CMD(target\debug\taudit.exe scan tests\fixtures\clean.yml --format json --no-color, exit=0)`
  emitted parseable JSON starting with `schema_version`.
- `FILE(docs/rc/v1.2.0/corpus-runner.md)` shows the existing runner is
  deterministic/offline and does not fetch remote files.

Observed external evidence:

- `SEARCH(arxiv.org/abs/2601.14455, result=observed 2026-06-01)` confirmed
  the title, authors, v2 revision date, 9-scanner comparison, and 2,722-workflow
  corpus summary.
- `SEARCH(arxiv.org/html/2601.14455v2, result=observed 2026-06-01)` confirmed
  author contact line, taxonomy, runtime method, threats-to-validity language,
  and data availability link.
- `CMD(Invoke-RestMethod https://api.github.com/repos/sparkrew/github-actions-security, exit=0)`
  observed `has_issues=true`, `default_branch=main`, and
  `pushed_at=2026-02-04T14:08:13Z`.
- `CMD(Invoke-RestMethod https://api.github.com/repos/sparkrew/github-actions-security/branches/main, exit=0)`
  observed `main` at
  `09c9e167f740e32d5f5d77a785b5056bff8b7fe6`.
- `CMD(Invoke-RestMethod .../tools_output/commands.md, exit=0)` observed the
  per-tool command record, including per-workflow commands for actionlint,
  semgrep, and zizmor plus temporary-repo/repository-scope commands for other
  tools.
- `CMD(Invoke-RestMethod .../results/*.csv, exit=0)` observed summary CSVs for
  coverage, detection volume, and execution time.

This proves current document inputs and command feasibility in this checkout.
It does not prove taudit benchmark performance, correctness, upstream inclusion,
or author review.

## Bottom line

There is no verified public application form for adding taudit to the existing
paper. The realistic path has two tracks:

1. Prepare a reproduction package that lets the original authors, or anyone
   else, run taudit through the same style of benchmark.
2. Ask for inclusion in a future rerun through a GitHub issue/PR and a short
   email to the authors, while making no acceptance claim.

If no rerun is available, the fallback is an independent taudit benchmark
report or arXiv preprint that cites the original benchmark, uses a comparable
method, and clearly labels any methodological differences.

## Implemented readiness assets

The repo now has the source-local assets needed to produce a benchmark package:

- Rule taxonomy map:
  `docs/research/arxiv-taudit-rule-map.csv`
- Fail-closed normalizer:
  `scripts/research/normalize_taudit_arxiv_findings.py`
- Repeated per-workflow runner:
  `scripts/research/run_arxiv_taudit_benchmark.py`
- Corpus manifest protocol:
  `docs/research/arxiv-corpus-manifest.md`
- Runtime ledger:
  `docs/research/arxiv-taudit-runtime-ledger.md`
- Detection ledger:
  `docs/research/arxiv-taudit-detection-ledger.md`
- FP/FN labeling protocol:
  `docs/research/arxiv-taudit-labeling-protocol.md`
- Contact payload:
  `docs/research/arxiv-contact-package.md`
- arXiv submission preflight:
  `docs/research/arxiv-submission-preflight.md`

Current safe state: taudit has a reproducible source-local path to generate
arXiv-comparable benchmark evidence. It still does not have full-corpus runtime
evidence, full-corpus detection evidence, FP/FN evidence, or external inclusion.

## arXiv submission gates for an independent paper

Submitting a taudit-owned paper is not the same as getting taudit added to the
existing benchmark. It is useful only if the artifact is a self-contained
research contribution.

Minimum gates before drafting submission copy:

1. A registered arXiv author can submit the work and can satisfy endorsement if
   arXiv requires endorsement for the selected category.
2. The paper is framed as empirical software-engineering/security research,
   likely `cs.SE` with `cs.CR` cross-list if the content supports it, not as a
   vendor comparison sheet.
3. The contribution includes a reproducible method: pinned taudit source,
   pinned corpus, exact commands, raw output retention, normalizer scripts,
   taxonomy mapping, runtime method, and explicit validity threats.
4. The submission source is prepared as a clean TeX/LaTeX bundle with figures,
   bibliography, and only files needed to build the paper; ancillary data/code
   are linked or attached according to arXiv guidance.
5. Any use of generative AI in preparing the paper is disclosed according to
   subject norms and arXiv moderation guidance.

Stop condition: if the artifact is mainly "taudit exists and is better", do not
submit it to arXiv. Publish a repo-local research note instead and keep the
claim ceiling at source-local evidence.

## Inclusion-readiness gaps

| Gap | Current state | Required before contact |
| --- | --- | --- |
| Stable benchmark artifact | Local `target/debug/taudit.exe explain` reports 129 rules, but that is a local checkout artifact, not a pinned benchmark release. | Pick one exact tag/commit and publish or attach install instructions, binary provenance, `taudit --version`, and source SHA. |
| GitHub Actions-only profile | taudit is multi-provider, while the paper is GHA-only. | Define the benchmark command over `.github/workflows/*.yml` and ensure ADO/GitLab rules do not pollute the mapping. |
| Command contract | Paper records exact per-tool commands. | Add a command wrapper equivalent to `taudit scan .github/workflows/<file> --format json --no-color` and document exit-code interpretation. |
| Output normalizer | Paper post-processes raw outputs to weakness classes, line numbers, and counts. | Add `scripts/research/normalize_taudit_arxiv_findings.py` or equivalent, with tests on fixture JSON. |
| Rule taxonomy mapping | `docs/rules/index.md` has rule categories, but not arXiv weakness classes. | Produce a machine-readable `taudit_rule_id -> arXiv weakness` map and a human-readable mapping rationale. |
| Corpus access | Paper dataset is public in the repo, but local license/use basis and exact fetch state still need checking. | Pin upstream repo commit, record dataset path/digests, and avoid redistributing copied workflows unless license/use basis is reviewed. Initial observed `main` candidate on 2026-06-01: `09c9e167f740e32d5f5d77a785b5056bff8b7fe6`; re-check before use. |
| Runtime evidence | `docs/perf-baseline.md` is criterion microbench evidence on old v0.9 and different hardware. | Run per-workflow wall-clock timing over the benchmark corpus using the paper's repeated-median method. |
| Detection evidence | Existing dogfood and corpus notes are not the paper's detection-volume method. | Emit per-workflow findings, mapped weakness classes, line numbers where available, parser completeness, and failure status. |
| FP/FN evidence | Paper says no ground-truth dataset exists. | Do not claim precision/recall unless we add a labeled sample or seeded ground-truth fixture set with reviewer adjudication. |
| Maintainer validation | Paper validated rule mapping with scanner maintainers. | Provide taudit maintainer-signed mapping rationale and invite author review; do not call it validated until reviewed. |

## Contact and submission path

### Track A: Ask for future rerun or inclusion

1. Fork or clone `sparkrew/github-actions-security` at a pinned commit.
   - Starting candidate observed 2026-06-01:
     `09c9e167f740e32d5f5d77a785b5056bff8b7fe6`.
   - Do not use floating `main` in any result table.
2. Add a taudit runner package in the style of their existing `tools/` and
   `tools_output/commands.md` assets:
   - install command or binary path;
   - exact command for one workflow file and for a temporary repo with one
     workflow;
   - taudit version and source commit;
   - timeout and expected exit code rules;
   - JSON output schema notes.
3. Add a rule mapping artifact:
   - one row per taudit rule that can fire on GitHub Actions;
   - arXiv weakness class or `out_of_scope`;
   - rationale and source doc link;
   - whether the rule is enabled by default.
4. Run the operational validation first: the paper used a random sample of 10
   real workflows before the full benchmark. Record command, exit code,
   runtime, JSON validity, parser completeness, and failures.
5. If the 10-workflow smoke passes, run the full dataset and publish a concise
   reproduction ledger.
6. Open a GitHub issue or PR against `sparkrew/github-actions-security` asking
   whether a future rerun accepts additional scanners. Link the taudit package,
   not marketing copy.
7. Email the authors using the public arXiv contact line with the same link and
   the narrow ask: "Would you consider taudit for a future rerun or accept a
   reproduction PR?"

Stop condition: if the authors decline, do not imply external inclusion. Keep
the local reproduction as taudit-owned evidence only.

### Track B: Independent comparable report

If there is no upstream rerun:

1. Publish a taudit-owned benchmark report under `docs/research/`.
2. Cite the arXiv paper as the reference method.
3. State every deviation: taudit version, corpus commit, hardware, operating
   system, command, timeout, parser settings, and mapping choices.
4. Release the runner and normalizer scripts under `scripts/research/`.
5. Consider an arXiv preprint only after the report has scientific content:
   comparable methodology, reproducible data/code, defensible taxonomy mapping,
   and clearly bounded claims.

Stop condition: if the work is only product marketing, do not submit it to
arXiv. arXiv submission guidance expects a topical, refereeable scientific
contribution.

## Reproducibility assets to prepare

| Asset | Proposed path | Purpose | Acceptance check |
| --- | --- | --- | --- |
| Benchmark lane brief | `docs/research/2026-06-01-arxiv-benchmark-inclusion-plan.md` | This plan. | Markdown sanity and source links present. |
| Rule taxonomy map | `docs/research/arxiv-taudit-rule-map.csv` | Maps taudit GHA rule IDs to AIW/CFW/EPW/GRCW/HGW/IW/KVCW/PTW/SEW/UDW/out_of_scope, with an `upstream_raw_weakness` column where repo CSVs use labels such as `TMW`. | Every GHA-enabled rule in `taudit explain` is mapped exactly once, and PTW/TMW handling is explicit. |
| Output normalizer | `scripts/research/normalize_taudit_arxiv_findings.py` | Converts taudit JSON to the paper-style per-workflow weakness rows. | Fixture JSON produces deterministic CSV/JSONL and fails closed on unknown taxonomy labels. |
| Runner wrapper | `scripts/research/run_arxiv_taudit_benchmark.py` | Runs taudit per workflow, repeats timings, applies timeouts, writes raw and normalized outputs. | 10-workflow smoke exits with recorded pass/fail rows, not hidden errors. |
| Dataset manifest | `docs/research/arxiv-corpus-manifest.md` or JSON under a later corpus lane | Pins upstream dataset commit, paths, digests, license/use notes. | All referenced files exist at the pinned upstream commit. |
| Runtime ledger | `docs/research/arxiv-taudit-runtime-ledger.md` | Records hardware, OS, binary, command, repetitions, medians, outliers. | Includes failure count, timeout count, and median elapsed time. |
| Detection ledger | `docs/research/arxiv-taudit-detection-ledger.md` | Records mapped findings by workflow and weakness class. | Includes raw-output pointer, line number availability, and parser completeness. |
| FP/FN protocol | `docs/research/arxiv-taudit-labeling-protocol.md` | Separates detection volume from correctness evidence. | Defines sample size, reviewer roles, adjudication, and stop conditions. |

## Starter taxonomy mapping

This is a planning map, not a final maintainer-validated mapping. Each row must
be expanded to exact rule IDs before any upstream contact.

| arXiv class | taudit fit | Representative taudit rules | Evidence needed |
| --- | --- | --- | --- |
| AIW: Artifact Integrity Weakness | Strong for artifact authority flow; partial for checksum/signature absence. | `artifact_boundary_crossing`, `unsafe_pr_artifact_in_workflow_run_consumer`, `gha_workflow_run_artifact_poisoning_to_privileged_consumer`, `gha_workflow_run_artifact_metadata_to_privileged_api`, `gha_workflow_run_artifact_to_build_scan_publish`, `pr_specific_cache_key_in_default_branch_consumer`, attestation subject/gate rules. | Decide whether cache and attestation rules map to AIW or out_of_scope; verify line mapping. |
| CFW: Control Flow Weakness | Gap or narrow partial. taudit has trigger/fork-guard reasoning, but no observed dedicated folded-scalar/always-true `if:` rule in current rule index. | `pull_request_workflow_inconsistent_fork_check`, possibly trigger/fork guard rules. | Add or explicitly mark missing for always-true/folded `if:` and skipped-security control-flow patterns. |
| EPW: Excessive Permission Weakness | Strong. | `over_privileged_identity`, `no_workflow_level_permissions_block`, `risky_trigger_with_authority`, `gh_cli_with_default_token_escalating`, OIDC/identity authority rules. | Define how authority propagation findings differ from permission-scope findings so EPW does not absorb every authority rule. |
| GRCW: GitHub Runner Compatibility Weakness | Gap today. | Possible future rule for deprecated action runtime or unsupported runner constructs. | Add rule or mark not covered; do not stretch parser partiality into GRCW without author review. |
| HGW: Hardening Gap Weakness | Gap for GHA. | No current GHA rule for absence of security scanning observed in `docs/rules/index.md`; GitLab has `security_job_silently_skipped` but paper scope is GHA. | Add a GHA hardening-gap rule or mark not covered. |
| IW: Injection Weakness | Strong. | `script_injection_via_untrusted_context`, `manual_dispatch_input_to_url_or_command`, `self_mutating_pipeline`, `untrusted_api_response_to_env_sink`, `gha_script_injection_to_privileged_shell`, env/path/helper injection family, manifest-as-code rules. | Split pure injection from credential handoff rules where the sink is helper resolution rather than shell execution. |
| KVCW: Known Vulnerable Component Weakness | Narrow partial. | `known_compromised_action_ref` and possibly future advisory-backed action version checks. | Generalize beyond compromise families if claiming KVCW coverage; pin advisory source and update cadence. |
| PTW: Privileged Trigger Weakness | Strong. | `trigger_context_mismatch`, `pr_trigger_with_floating_action_ref`, `secrets_inherit_overscoped_passthrough`, `gha_issue_comment_command_to_write_token`, `gha_manual_dispatch_ref_to_privileged_checkout`, workflow_run artifact rules. | Separate trigger-only rules from trigger plus exploit-chain rules in the mapping rationale. |
| SEW: Secrets Exposure Weakness | Strong. | `long_lived_credential`, `persisted_credential`, `sensitive_value_in_job_output`, `secret_via_env_gate_to_untrusted_consumer`, `interactive_debug_action_in_authority_workflow`, `gha_token_remote_url_with_trace_or_process_exposure`, `gha_pat_remote_url_write`, secrets-inherit rules. | Decide whether taudit's secret-name heuristics are SEW or hardening/hygiene for the paper taxonomy. |
| UDW: Unpinned Dependency Weakness | Strong for action/image/script pinning. | `unpinned_action`, `action_major_version_pin_without_sha`, `floating_image`, `runtime_script_fetched_from_floating_url`, `gha_remote_script_in_authority_job`, `gha_floating_remote_script_before_publish_sink`, cross-repo floating ref rules. | Keep remote scripts/images separate if authors treat UDW as only action refs. |

## Runtime evidence requirements

Minimum comparable run:

1. Pin taudit source commit, binary checksum, and `taudit --version`.
2. Pin the benchmark dataset commit from `sparkrew/github-actions-security`.
3. Run one workflow file per invocation.
4. Use default taudit rules only unless the config deviation is documented.
5. Use JSON output with no color.
6. Repeat each workflow 3 times.
7. Record elapsed wall-clock time and median per workflow.
8. Record stdout parse result, schema validation result if a schema is used,
   stderr, exit code, timeout, and panic/crash status.
9. Record parser completeness: complete, partial, unknown, failure.
10. Report medians and outliers without claiming speed parity until the
    hardware and command differences are normalized.

Recommended command shape:

```powershell
target\release\taudit.exe scan <workflow.yml> --format json --no-color
```

For a repo-scoped variant, create a temporary repository containing exactly one
workflow under `.github/workflows/`, matching the paper's per-workflow setup for
tools that require repository context.

## FP/FN evidence requirements

The original paper does not provide a correctness ground truth. Therefore:

- Detection-volume reproduction can report counts by weakness class.
- It cannot prove false-positive or false-negative rates.
- Precision/recall claims need an additional labeled dataset.

Minimum FP/FN protocol:

1. Select a stratified sample from the 2,722 workflows plus a seeded fixture set
   for rare weakness classes.
2. Label each workflow/weakness pair independently by two reviewers.
3. Adjudicate disagreements and publish the rubric.
4. Track parser partiality separately from true negatives.
5. Treat unknown provider/runtime state as "unjudgeable", not negative.
6. Report confidence intervals and sample coverage.

Stop condition: if labels are unavailable or reviewer agreement is poor, report
"detection volume only" and do not publish FP/FN numbers.

## Concrete task lanes

| Lane | Objective | Owned paths | Acceptance |
| --- | --- | --- | --- |
| A1 contact package | Prepare the upstream issue/PR/email payload. | `docs/research/**` | Includes exact ask, source links, and no acceptance claim. |
| A2 runner | Build repeatable per-workflow timing runner. | `scripts/research/**` | 10-workflow smoke records pass/fail/timing rows. |
| A3 normalizer | Convert taudit JSON to arXiv weakness rows. | `scripts/research/**` | Fixture tests cover every weakness class and out_of_scope. |
| A4 taxonomy | Finish exact GHA rule mapping. | `docs/research/**` | Every GHA-enabled rule maps exactly once with rationale. |
| A5 corpus manifest | Pin dataset commit and workflow paths. | `docs/research/**` initially | Manifest has URL, commit, path, digest/use note. |
| A6 detection run | Run taudit over the full paper corpus. | `docs/research/**`, generated outputs under a later agreed artifact path | Summary reports failures, parser completeness, and counts by weakness. |
| A7 FP/FN protocol | Define correctness study separate from detection volume. | `docs/research/**` | Reviewer rubric and stop conditions exist before claims. |

## Stop conditions

Stop and report a gap instead of inventing if any of these occur:

- The upstream benchmark dataset cannot be pinned or used under a documented
  license/use basis.
- taudit cannot run locally on a 10-workflow smoke with deterministic command
  and parseable output.
- A rule cannot be mapped to exactly one arXiv weakness or `out_of_scope`.
- Runtime measurements mix debug and release binaries without labeling.
- Parser partiality hides enough GHA surface that "no finding" would be
  misleading.
- Any request asks for "included", "accepted", "externally benchmarked",
  "best", "fastest", or FP/FN claims before the corresponding evidence exists.

## Residual risks

- The paper's selection includes a "production ready" filter. That is the
  paper authors' curation language, not a taudit claim we can reuse without
  release proof.
- The benchmark is GitHub Actions-only; it does not test taudit's ADO/GitLab
  advantage.
- The paper's raw GitHub HTML and repo files are public, but local reproduction
  still needs a pinned repo commit and generated artifact digests.
- The taxonomy mapping will involve judgment. The paper used maintainer
  validation; taudit should expect author review to change some mappings.
- Even a successful local reproduction is source-local evidence unless the
  authors or another independent party rerun it.
