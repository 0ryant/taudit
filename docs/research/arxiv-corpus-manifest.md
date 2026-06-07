# arXiv corpus manifest

Date: 2026-06-01
Status: manifest protocol; no benchmark corpus is vendored in this repository

## Corpus source

Reference paper: arXiv:2601.14455v2, "Unpacking Security Scanners for GitHub
Actions Workflows".

Reference code/data repository:

- URL: <https://github.com/sparkrew/github-actions-security>
- Starting commit observed in the planning pass:
  `09c9e167f740e32d5f5d77a785b5056bff8b7fe6`
- Required before a real run: re-check `main`, pin the exact commit used, and
  record the dataset file list and digests.

## Local use rule

Do not copy the benchmark workflows into this repository unless the license and
redistribution basis is reviewed. The default local route is:

1. Clone or download the upstream benchmark repository outside the taudit source
   tree.
2. Check out the pinned commit.
3. Run `scripts/research/run_arxiv_taudit_benchmark.py` against the workflow
   dataset path.
4. Store generated run outputs under an agreed artifact path or release asset,
   not as ad hoc committed bulk data.

## Required run manifest fields

Each benchmark run must retain:

- upstream repository URL
- upstream commit SHA
- workflow path list
- SHA-256 digest for each workflow file
- taudit source commit
- taudit binary checksum
- `taudit --version`
- command line
- OS and hardware notes
- timeout policy
- repeat count
- raw stdout/stderr output paths
- normalized finding output paths

## Evidence ceiling

This manifest protocol does not prove performance, coverage, false positives,
false negatives, or external inclusion. Those claims require a completed run
ledger and, for correctness claims, the separate labeling protocol.
