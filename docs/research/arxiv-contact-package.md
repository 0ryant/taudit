# arXiv benchmark contact package

Date: 2026-06-01
Status: draft payload; source-local smoke passed; send only after shareable
artifact and license/use review

## Required artifact links before sending

Fill this table before copying any issue, PR, or email text. Keep pending rows
out of sent correspondence.

| ID | Field | Required value or link | Current status |
| --- | --- | --- | --- |
| A1 | Reproduction package | Public or shareable package URL containing command contract, rule map, runner/normalizer versions, and retained smoke artifacts | Pending durable package URL |
| S1 | 10-workflow smoke ledger | Link to `docs/research/arxiv-smoke-ledger.md` with completed smoke evidence | Source-local: `docs/research/arxiv-smoke-ledger.md` |
| R1 | Runtime ledger | Link to completed runtime ledger entries for the smoke run | Source-local: `docs/research/arxiv-taudit-runtime-ledger.md` |
| D1 | Detection ledger | Link to completed detection ledger entries or smoke-normalized output summary | Source-local: `docs/research/arxiv-taudit-detection-ledger.md` |
| M1 | Rule map | Link to pinned `docs/research/arxiv-taudit-rule-map.csv` at the benchmark commit | Source-local: `docs/research/arxiv-taudit-rule-map.csv` |
| C1 | Corpus manifest | Link to pinned corpus commit, selected workflow manifest, and workflow SHA-256 digest list | Source-local temp artifacts: `%TEMP%\taudit-arxiv-upstream-10-smoke-release\corpus-manifest-smoke-git-tree.json` and `%TEMP%\taudit-arxiv-upstream-10-smoke-release\corpus-manifest-full.json` |
| B1 | Binary receipt | Link to taudit source commit, build command, version output, and binary SHA-256 | Source-local: `docs/research/arxiv-taudit-runtime-ledger.md` |
| L1 | License/use note | Link to dataset license/use note if workflow files or outputs are copied outside the local repo | Pending operator review |

## GitHub issue or PR draft

Title:

```text
Candidate reproduction package for taudit scanner inclusion in a future rerun
```

Body:

```text
Hello. We maintain taudit, a static CI/CD authority graph analyzer with GitHub
Actions support. We noticed arXiv:2601.14455v2 and the companion benchmark
repository, and we would like to ask whether you would consider an additional
scanner in a future rerun or accept a reproduction PR.

We are not claiming inclusion in the current paper. We have prepared a local
reproduction package with:

- exact taudit version and source commit;
- one-workflow-per-invocation command contract;
- JSON raw output retention;
- 3-repeat wall-clock timing;
- a proposed taudit-rule to 10-class taxonomy map;
- explicit out-of-scope rows and mapping-review notes;
- detection-volume output separate from FP/FN claims.

Package link:
[fill from required artifact table: A1]

Smoke evidence:
[fill from required artifact table: S1]

Question:
Would a small PR adding the taudit command/mapping artifacts be useful for a
future rerun, or would you prefer an issue with our reproduction artifacts only?
```

## Author email draft

Subject:

```text
taudit reproduction package for GitHub Actions scanner benchmark
```

Body:

```text
Hello Madjda, Yogya, and Benoit,

Thank you for publishing "Unpacking Security Scanners for GitHub Actions
Workflows" and the companion data/code repository.

I maintain taudit, a static CI/CD authority graph analyzer. We have prepared a
reproduction package that runs taudit in the same general shape as the paper:
one workflow per invocation, JSON output, raw output retention, three timing
repeats, and a proposed mapping from taudit rules to your ten weakness classes.

We are not claiming taudit is included in the current paper or externally
validated. The narrow ask is whether you would consider taudit for a future
rerun or prefer a PR/issue that documents the candidate scanner package.

Package:
[fill from required artifact table: A1]

10-workflow smoke ledger:
[fill from required artifact table: S1]

Full-corpus run ledger, if complete:
[optional; include only after full-corpus verification exists]

Best,
Ryan
```

## Send gate

Do not send until:

- the rule map loads without duplicate or unknown classes;
- the normalizer passes tests;
- the runner passes a 10-workflow smoke with raw output and timing CSV;
- all claims link to source-local artifacts;
- the payload does not say accepted, included, fastest, broadest, or most
  accurate.
