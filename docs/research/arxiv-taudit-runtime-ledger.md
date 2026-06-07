# arXiv taudit runtime ledger

Date: 2026-06-01
Status: ledger template; no full arXiv corpus runtime claim yet

## Command contract

Default command shape:

```powershell
python scripts\research\run_arxiv_taudit_benchmark.py `
  --workflows-root <pinned-upstream-dataset-path> `
  --taudit target\release\taudit.exe `
  --rule-map docs\research\arxiv-taudit-rule-map.csv `
  --output-dir <artifact-output-dir> `
  --repeat 3 `
  --timeout 30
```

Per workflow invocation performed by the runner:

```powershell
target\release\taudit.exe scan <workflow.yml> --platform github-actions --format json --no-color
```

## 2026-06-01 release-binary 10-workflow smoke

| Field | Value |
| --- | --- |
| Run id | `taudit-arxiv-upstream-10-smoke-release` |
| Run date | 2026-06-01 |
| taudit source commit | `7bd9d56d860165cb3041ed339c13661466f5b52f` |
| taudit version | `taudit 1.3.0-pre` |
| Build command | `cargo build --release` |
| Build result | `CMD(cargo build --release, exit=0)` |
| taudit binary checksum | SHA-256 `8296FBCC5CA0BB6B175B9B7C446544B272629706CE4CD6FE9AE2CB6BB17429BE` |
| Benchmark corpus repository | `https://github.com/sparkrew/github-actions-security` |
| Benchmark corpus commit | `09c9e167f740e32d5f5d77a785b5056bff8b7fe6` |
| Full corpus manifest | `%TEMP%\taudit-arxiv-upstream-10-smoke-release\corpus-manifest-full.json` |
| Smoke sample manifest | `%TEMP%\taudit-arxiv-upstream-10-smoke-release\corpus-manifest-smoke-git-tree.json` |
| Workflow count | 10 |
| Repeat count | 3 |
| Timeout | 20 seconds |
| Runner command | `python scripts\research\run_arxiv_taudit_benchmark.py --workflow-list %TEMP%\taudit-arxiv-upstream-10-workflows.txt --taudit target\release\taudit.exe --rule-map docs\research\arxiv-taudit-rule-map.csv --output-dir %TEMP%\taudit-arxiv-upstream-10-smoke-release --repeat 3 --timeout 20` |
| Status counts | `ok=30` |
| Median elapsed time across workflow medians | 26.5 ms |
| Timeout count | 0 |
| Nonzero exit count | 0 |
| Invalid JSON count | 0 |
| Normalization errors | 0 |
| Output directory | `%TEMP%\taudit-arxiv-upstream-10-smoke-release` |
| Raw output directory | `%TEMP%\taudit-arxiv-upstream-10-smoke-release\raw` |
| Timing CSV | `%TEMP%\taudit-arxiv-upstream-10-smoke-release\timings.csv` |
| Summary JSON | `%TEMP%\taudit-arxiv-upstream-10-smoke-release\summary.json` |

Smoke workflow sample:

1. `dataset/workflows/AUTOMATIC1111_stable-diffusion-webui__on_pull_request.yaml`
2. `dataset/workflows/AUTOMATIC1111_stable-diffusion-webui__run_tests.yaml`
3. `dataset/workflows/AUTOMATIC1111_stable-diffusion-webui__warns_merge_master.yml`
4. `dataset/workflows/Chalarangelo_30-seconds-of-code__deploy-production.yml`
5. `dataset/workflows/Chalarangelo_30-seconds-of-code__label.yml`
6. `dataset/workflows/Chalarangelo_30-seconds-of-code__stale.yml`
7. `dataset/workflows/Chalarangelo_30-seconds-of-code__test.yml`
8. `dataset/workflows/EbookFoundation_free-programming-books__check-urls.yml`
9. `dataset/workflows/EbookFoundation_free-programming-books__comment-pr.yml`
10. `dataset/workflows/EbookFoundation_free-programming-books__detect-conflicting-prs.yml`

Important caveat: this is a 10-workflow smoke, not a full-corpus benchmark.
It proves command feasibility, raw output retention, timing artifact creation,
and normalization over a pinned upstream sample. It does not prove performance,
coverage, precision, recall, external validation, or arXiv inclusion.

## Required fields for full run

| Field | Value |
| --- | --- |
| Run id | TBD |
| Run date | TBD |
| Operator | TBD |
| taudit source commit | TBD |
| taudit version | TBD |
| taudit binary checksum | TBD |
| Benchmark corpus repository | `https://github.com/sparkrew/github-actions-security` |
| Benchmark corpus commit | TBD |
| Workflow count | TBD |
| Repeat count | `3` unless deviation is documented |
| Timeout | TBD |
| OS | TBD |
| CPU/RAM | TBD |
| Raw output directory | TBD |
| Timing CSV | TBD |
| Summary JSON | TBD |

## Reporting rule

Report median wall-clock time per workflow using successful repeats only. Also
report timeout count, nonzero exit count, invalid JSON count, and workflow count
with no successful repeat. Do not compare speed against the paper unless the
hardware, command shape, and corpus commit are stated beside the number.
