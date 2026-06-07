# arXiv taudit smoke ledger

Date: 2026-06-01
Status: release-binary 10-workflow smoke recorded; shareable package pending

## Claim boundary

This ledger is a required pre-contact receipt for a 10-workflow smoke run. The
source-local smoke fields below are filled from a main-thread verification
result. They are not a public/shareable package until the `%TEMP%` artifacts are
copied to a durable reviewed location.

Do not use this file for speed, coverage, correctness, upstream participation,
or third-party review claims.

## Smoke run identity

| Field | Required value or link | Current status |
| --- | --- | --- |
| Smoke run id | Stable local run id or artifact directory name | `taudit-arxiv-upstream-10-smoke-release` |
| Main-thread verification result | Link to final verification note or receipt | `CMD(run_arxiv_taudit_benchmark.py, exit=0)` on 2026-06-01 |
| Run date/time | ISO-like local timestamp with timezone | Summary generated `2026-06-01T17:55:54.627647+00:00` |
| Operator | Person or automation that ran the smoke | Codex main thread |
| taudit source commit | Commit SHA or release tag used to build the binary | `7bd9d56d860165cb3041ed339c13661466f5b52f` |
| taudit version | `taudit --version` output | `taudit 1.3.0-pre` |
| Binary mode | `release` for publishable evidence; `debug` only if labeled as smoke-only | `release` |
| Build command | Exact command used to produce the binary | `cargo build --release` |
| Binary SHA-256 | `Get-FileHash ... -Algorithm SHA256` output | `8296FBCC5CA0BB6B175B9B7C446544B272629706CE4CD6FE9AE2CB6BB17429BE` |
| Corpus repository | Upstream corpus URL | `https://github.com/sparkrew/github-actions-security` |
| Corpus commit | Pinned corpus commit SHA | `09c9e167f740e32d5f5d77a785b5056bff8b7fe6` |
| Workflow sample manifest | Link to selected 10-workflow manifest and selection notes | `%TEMP%\taudit-arxiv-upstream-10-workflows.txt`; digest manifest `%TEMP%\taudit-arxiv-upstream-10-smoke-release\corpus-manifest-smoke-git-tree.json` |
| Full corpus manifest | Link to full pinned workflow manifest | `%TEMP%\taudit-arxiv-upstream-10-smoke-release\corpus-manifest-full.json` |
| Dataset license/use note | Link to license/use review note if redistribution is involved | Pending operator review |

## Execution contract

| Field | Required value or link | Current status |
| --- | --- | --- |
| Runner command | Exact `run_arxiv_taudit_benchmark.py` command | `python scripts\research\run_arxiv_taudit_benchmark.py --workflow-list %TEMP%\taudit-arxiv-upstream-10-workflows.txt --taudit target\release\taudit.exe --rule-map docs\research\arxiv-taudit-rule-map.csv --output-dir %TEMP%\taudit-arxiv-upstream-10-smoke-release --repeat 3 --timeout 20` |
| Repeat count | Expected `3` unless deviation is documented | `3` |
| Timeout seconds | Per-invocation timeout | `20` |
| OS | Operating system and version | Windows local Codex environment |
| CPU/RAM | Hardware summary relevant to timing claims | Not recorded beyond local environment; do not publish timing comparison from this smoke |
| Output directory | Root artifact directory for the smoke run | `%TEMP%\taudit-arxiv-upstream-10-smoke-release` |
| Raw stdout/stderr directory | Directory containing retained raw files for every attempt | `%TEMP%\taudit-arxiv-upstream-10-smoke-release\raw` |
| Timing CSV | Link to timing CSV artifact | `%TEMP%\taudit-arxiv-upstream-10-smoke-release\timings.csv` |
| Runner summary JSON | Link to runner summary JSON artifact | `%TEMP%\taudit-arxiv-upstream-10-smoke-release\summary.json` |
| Runtime ledger | Link to filled runtime ledger section or copy | `docs/research/arxiv-taudit-runtime-ledger.md` |
| Detection ledger | Link to filled detection ledger section or copy | `docs/research/arxiv-taudit-detection-ledger.md` |

## Normalization contract

| Field | Required value or link | Current status |
| --- | --- | --- |
| Rule map | `docs/research/arxiv-taudit-rule-map.csv` at the verified commit | Used from local worktree |
| Normalizer command | Exact `normalize_taudit_arxiv_findings.py` command | Integrated runner normalization |
| Findings CSV | Link to normalized findings CSV | `%TEMP%\taudit-arxiv-upstream-10-smoke-release\findings.csv` |
| Findings JSONL | Link to normalized findings JSONL | `%TEMP%\taudit-arxiv-upstream-10-smoke-release\findings.jsonl` |
| Detection summary JSON | Link to detection summary JSON | `%TEMP%\taudit-arxiv-upstream-10-smoke-release\summary.json` |
| Unmapped rule count | Must be `0` for contact-package send gate | `0` |
| Normalization error count | Must be `0` for contact-package send gate | `0` |
| `needs_author_review` rows | Count and review status for mappings touched by emitted findings | See `docs/research/arxiv-taxonomy-review.md`; emitted smoke rows include review-needed mappings, so use method notes before public claims |

## Workflow outcome table

Fill one row per workflow selected for the smoke. Successful invocations must
have parseable JSON and retained raw stdout/stderr. Failed invocations must be
counted rather than omitted.

| # | Workflow path | Workflow SHA-256 | Repeat statuses | Raw stdout/stderr links | Timing row link | Normalized finding count | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `dataset/workflows/AUTOMATIC1111_stable-diffusion-webui__on_pull_request.yaml` | `2b97d99e78ef5b0d1045db77c38ac83e6f11d52712f8705953d4c6c63c465400` | `ok,ok,ok` | Retained under raw dir | `timings.csv` | Included in 97 total | Median 64 ms |
| 2 | `dataset/workflows/AUTOMATIC1111_stable-diffusion-webui__run_tests.yaml` | `054414879e0d483bef3aa8aec80c32fd9e008d0b71f15acb6fcffdc2a0615661` | `ok,ok,ok` | Retained under raw dir | `timings.csv` | Included in 97 total | Median 106 ms |
| 3 | `dataset/workflows/AUTOMATIC1111_stable-diffusion-webui__warns_merge_master.yml` | `739f866945b42363a8895a8d4a9a6b88c0b946e8c7e4fd6a2796d7605096fc49` | `ok,ok,ok` | Retained under raw dir | `timings.csv` | Included in 97 total | Median 44 ms |
| 4 | `dataset/workflows/Chalarangelo_30-seconds-of-code__deploy-production.yml` | `2fc6c68f97e68bbe727acf328180e69b0ae9725cef5fc78ec15ec5f32c6a6752` | `ok,ok,ok` | Retained under raw dir | `timings.csv` | Included in 97 total | Median 21 ms |
| 5 | `dataset/workflows/Chalarangelo_30-seconds-of-code__label.yml` | `071048f136942a70d914adcb7a25a7ac8780cee966082ce54240386a641e8b98` | `ok,ok,ok` | Retained under raw dir | `timings.csv` | Included in 97 total | Median 22 ms |
| 6 | `dataset/workflows/Chalarangelo_30-seconds-of-code__stale.yml` | `793479a754217c0dbe18c66f39b205f6c419609a100e554dc88c5766bda00c51` | `ok,ok,ok` | Retained under raw dir | `timings.csv` | Included in 97 total | Median 26 ms |
| 7 | `dataset/workflows/Chalarangelo_30-seconds-of-code__test.yml` | `52ff57fd0bb194ae6bb60d4444bc872cc8b6dc86737439f4ad0ad2bee3780d6c` | `ok,ok,ok` | Retained under raw dir | `timings.csv` | Included in 97 total | Median 27 ms |
| 8 | `dataset/workflows/EbookFoundation_free-programming-books__check-urls.yml` | `27ccbc8f32f0e7724350383c047addf3d7f612886d2123c805504494bd04e44e` | `ok,ok,ok` | Retained under raw dir | `timings.csv` | Included in 97 total | Median 31 ms |
| 9 | `dataset/workflows/EbookFoundation_free-programming-books__comment-pr.yml` | `46fd952b6614fe1367413be98a4c875d4fc510a12ae3558d5e4c23785f04d1ef` | `ok,ok,ok` | Retained under raw dir | `timings.csv` | Included in 97 total | Median 24 ms |
| 10 | `dataset/workflows/EbookFoundation_free-programming-books__detect-conflicting-prs.yml` | `ff04ce1412630122111e50225918d15cfc34f848a96e25bc17cb26ec47e9741c` | `ok,ok,ok` | Retained under raw dir | `timings.csv` | Included in 97 total | Median 24 ms |

## Send-gate checklist

| Gate | Required evidence | Current status |
| --- | --- | --- |
| All 10 workflows attempted | Runner summary names 10 workflows | Pass |
| Raw output retained | Raw stdout/stderr exists for every repeat, including failures | Pass |
| JSON parseability | Successful repeats produce parseable JSON | Pass: `ok=30` |
| Failure accounting | Nonzero exits, invalid JSON, timeouts, and launch errors are counted | Pass: none observed |
| Timing artifacts | Timing CSV and summary JSON are written | Pass |
| Normalization | No unmapped emitted rule ids and no normalization errors | Pass: normalization error count `0` |
| Contact package links | `docs/research/arxiv-contact-package.md` links this ledger and artifacts | Partial: source-local docs updated; external/shareable URLs still pending |

## Update rule

When the main thread provides a verification result, replace the pending entries
with exact artifact links, commands, counts, and hashes. Preserve failed or
partial rows as evidence; do not rewrite them into a pass narrative.
