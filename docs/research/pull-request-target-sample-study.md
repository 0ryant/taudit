# `pull_request_target` sample study (taudit engine)

This validates **prevalence of static findings** on a random sample of public workflows that match GitHub code search for `pull_request_target` under `.github/workflows`.

## Method

1. Query (GitHub code search API, max **1,000** hits per query):  
   `pull_request_target path:.github/workflows extension:yml`
2. For each hit, download the file via the Contents API (`Accept: application/vnd.github.raw`).
3. Run `taudit scan <file> --format json` locally (no repo clone).

**Script:** `scripts/research/prt_repo_sample_scan.py`

```bash
export GITHUB_TOKEN=$(gh auth token)   # or gh auth login
python3 scripts/research/prt_repo_sample_scan.py --limit 80 \
  --json-out docs/research/prt-sample-scan-2026-04-29.json
```

## Snapshot (2026-04-29, n = 80)

| Metric | Value |
|--------|------:|
| Workflows fetched | 80 |
| `taudit` JSON scan succeeded | 80 |
| Workflows with **≥ 1** finding | 80 (100%) |
| Workflows with **≥ 1 critical** | 77 (96.2%) |
| Workflows with **≥ 1 high** | 71 (88.8%) |

Raw rows: `docs/research/prt-sample-scan-2026-04-29.json`.

## How to compare to vendor “~1%” claims

External percentages (e.g. “only 1% of repos are exploitable”) usually measure **exploitable chains** or **manual triage**, not “any static finding.”

taudit is intentionally **strict**: third-party actions, reusable workflows, and token scope produce many **high/critical** graph findings that are **true positives for risk** but not always **drop-everything CVEs**.

**Apples-to-apples protocol:**

1. Fix `n` and the search query (public vs org scope).
2. Define the outcome: e.g. `critical > 0` **and** rule in `{ checkout_self_pr_exposure, trigger_context_mismatch }`.
3. Re-run the script; post-process JSON with `jq` for that definition.

Scaling to **1,000** repos: set `--limit 1000` (expect ~15–25 minutes depending on API + CPU; respect GitHub secondary rate limits).

## Limitations

- Search results skew toward indexed public repos; forks and renamed paths appear.
- Deleted or moved files between index and fetch show as fetch errors (the script records `ok_fetch: false`).
