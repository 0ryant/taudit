# arXiv readiness checklist

Date: 2026-06-01
Status: operator runbook; not a submission receipt

## Claim ceiling

Safe today:

- taudit has source-local arXiv-comparable benchmark tooling and runbook
  material.
- taudit has a proposed rule-to-taxonomy map, runner, normalizer, corpus
  manifest protocol, runtime ledger template, detection ledger template,
  labeling protocol, contact package, and arXiv submission preflight.

Unsafe until the named gate is completed:

- Do not claim taudit is included in arXiv:2601.14455 or accepted for a future
  rerun until the paper authors or benchmark maintainers say so.
- Do not claim external validation until an independent party reruns or reviews
  the package.
- Do not claim benchmark performance, coverage, precision, recall, false
  positive rate, or false negative rate until the corresponding ledger and, for
  correctness, labeling protocol are complete.
- Do not submit product launch copy to arXiv. A taudit-owned arXiv paper must be
  a self-contained, topical, refereeable research contribution.

## Source-local engineering done

- [x] Benchmark inclusion plan exists:
  `docs/research/2026-06-01-arxiv-benchmark-inclusion-plan.md`.
- [x] Proposed taudit rule mapping exists:
  `docs/research/arxiv-taudit-rule-map.csv`.
- [x] Fail-closed normalizer exists:
  `scripts/research/normalize_taudit_arxiv_findings.py`.
- [x] Repeated per-workflow runner exists:
  `scripts/research/run_arxiv_taudit_benchmark.py`.
- [x] Source-local readiness checker exists:
  `scripts/research/check_arxiv_readiness.py`.
- [x] Corpus manifest protocol exists:
  `docs/research/arxiv-corpus-manifest.md`.
- [x] Runtime ledger template exists:
  `docs/research/arxiv-taudit-runtime-ledger.md`.
- [x] Detection ledger contract exists:
  `docs/research/arxiv-taudit-detection-ledger.md`.
- [x] FP/FN labeling protocol exists:
  `docs/research/arxiv-taudit-labeling-protocol.md`.
- [x] Upstream contact package exists:
  `docs/research/arxiv-contact-package.md`.
- [x] arXiv submission preflight exists:
  `docs/research/arxiv-submission-preflight.md`.
- [x] Current operator checklist exists:
  `docs/research/arxiv-readiness-checklist.md`.

## Operator and external gates not done

- [ ] Pick the exact benchmark route:
  upstream rerun request, taudit-owned comparable report, arXiv paper, or a
  staged combination of those tracks.
- [ ] Select one taudit source commit or release tag for the benchmark.
- [ ] Build a release-mode taudit binary from that commit.
- [ ] Record `taudit --version`, source commit, build command, and binary
  SHA-256.
- [ ] Re-check and pin the exact
  `https://github.com/sparkrew/github-actions-security` commit used for the
  corpus.
- [ ] Confirm the dataset license/use basis before copying or redistributing
  workflow files.
- [ ] Generate a workflow path manifest and SHA-256 digest list for every
  workflow scanned.
- [ ] Run the 10-workflow smoke before contacting upstream.
- [ ] Run the full corpus only after the smoke has parseable JSON, retained raw
  output, timing rows, and no hidden runner failures.
- [ ] Fill the runtime ledger with OS, hardware, timeout, repeat count, command,
  binary checksum, source commit, corpus commit, failure counts, timeout counts,
  and median timings.
- [ ] Fill the detection ledger with raw output pointers, normalized rows,
  weakness counts, line availability, parser completeness, and mapping status.
- [ ] Review every `needs_author_review` rule-map row before sending upstream
  contact.
- [ ] Execute the FP/FN labeling protocol before any correctness metric is
  published.
- [ ] Replace all `TBD` placeholders in the contact package with artifact links
  and smoke evidence.
- [ ] Send upstream issue/PR/email only after the send gate in
  `docs/research/arxiv-contact-package.md` passes.
- [ ] For an independent arXiv paper, prepare a clean TeX/LaTeX source bundle,
  figures, bibliography, metadata, license selection, and ancillary material
  plan.
- [ ] Confirm the submitting author account, endorsement status, category
  choice, and cross-listing rationale.
- [ ] Run arXiv package checks locally enough to catch missing files, case
  mismatches, nonportable file names, JavaScript-bearing PDFs, and accidental
  generated/intermediate files.
- [ ] Submit only after the processed PDF, title, abstract, author list,
  references, figures, and artifact links are manually reviewed.

## Source-local gates completed after tranche R

- [x] Release binary built with `cargo build --release`.
- [x] Release binary version recorded: `taudit 1.3.0-pre`.
- [x] Release binary SHA-256 recorded:
  `8296FBCC5CA0BB6B175B9B7C446544B272629706CE4CD6FE9AE2CB6BB17429BE`.
- [x] Local source commit recorded:
  `7bd9d56d860165cb3041ed339c13661466f5b52f`.
- [x] Upstream benchmark repository head checked:
  `09c9e167f740e32d5f5d77a785b5056bff8b7fe6`.
- [x] Windows checkout hazard recorded: full upstream checkout fails on
  `tools/actionlint/LICENSE.txt:Zone.Identifier`; dataset workflow blobs were
  extracted by exact Git path instead.
- [x] Full pinned corpus manifest generated:
  `%TEMP%\taudit-arxiv-upstream-10-smoke-release\corpus-manifest-full.json`
  with 596 workflows.
- [x] Smoke sample digest manifest generated:
  `%TEMP%\taudit-arxiv-upstream-10-smoke-release\corpus-manifest-smoke-git-tree.json`.
- [x] 10-workflow upstream smoke passed with release binary:
  10 workflows, 3 repeats each, `ok=30`, no normalization errors.
- [x] Runtime smoke evidence added to
  `docs/research/arxiv-taudit-runtime-ledger.md`.
- [x] Detection smoke evidence added to
  `docs/research/arxiv-taudit-detection-ledger.md`.
- [x] Smoke ledger updated in `docs/research/arxiv-smoke-ledger.md`.
- [x] Taxonomy review artifact added:
  `docs/research/arxiv-taxonomy-review.md`.
- [x] Rule-map drift bounded: 100 current-default GHA rows and 11
  non-current candidate rows.

## Remaining gates after tranche R

- [ ] Move source-local artifacts out of `%TEMP%` into a durable shareable
  package location before contacting upstream.
- [ ] Confirm the dataset license/use basis before copying workflow files,
  raw scanner output, or manifests outside the local machine.
- [ ] Run the full 596-workflow corpus benchmark with the release binary and
  retain raw output, timing CSV, summary JSON, findings CSV/JSONL, and the
  corpus manifest beside the run.
- [ ] Execute the FP/FN labeling protocol before publishing correctness metrics.
- [ ] Complete operator review of the contact package and replace public-link
  placeholders with durable artifact URLs.
- [ ] Obtain upstream maintainer or paper-author response before claiming
  benchmark inclusion or external validation.
- [ ] For a taudit-owned arXiv paper, prepare and verify the TeX/PDF source
  bundle, figures, bibliography, metadata, license, category, and endorsement.

## Benchmark command path

Use release binaries for publishable results. Debug binaries are acceptable only
for tool smoke and must be labeled as such.

Before spending full-corpus time, run the source-local gate:

```powershell
python scripts\research\check_arxiv_readiness.py
```

```powershell
cargo build --release
```

```powershell
target\release\taudit.exe --version
```

```powershell
Get-FileHash target\release\taudit.exe -Algorithm SHA256
```

```powershell
python scripts\research\run_arxiv_taudit_benchmark.py `
  --workflows-root <pinned-upstream-dataset-path> `
  --taudit target\release\taudit.exe `
  --rule-map docs\research\arxiv-taudit-rule-map.csv `
  --output-dir <artifact-output-dir> `
  --repeat 3 `
  --timeout 30
```

```powershell
python scripts\research\normalize_taudit_arxiv_findings.py `
  <artifact-output-dir>\raw `
  --rule-map docs\research\arxiv-taudit-rule-map.csv `
  --output-csv <artifact-output-dir>\findings.csv `
  --output-jsonl <artifact-output-dir>\findings.jsonl `
  --summary-json <artifact-output-dir>\detection-summary.json
```

## Smoke acceptance

The 10-workflow smoke is acceptable only when all of these are true:

- every workflow attempt has a retained raw stdout/stderr file;
- every successful invocation emits parseable JSON;
- every emitted taudit rule id is present in the rule map;
- timing CSV and summary JSON are written;
- nonzero exits, invalid JSON, timeouts, and parser failures are counted rather
  than hidden;
- the smoke ledger is linked from the contact package.

## Full-corpus acceptance

The full corpus run is acceptable only when all of these are true:

- the corpus commit and workflow digests are pinned;
- the taudit source commit and binary checksum are pinned;
- repeat count, timeout, OS, CPU/RAM, command, and platform are recorded;
- raw output, normalized output, timing CSV, and summary JSON are retained;
- failures are reported as failures, not omitted rows;
- detection volume is labeled as detection volume only;
- any comparison to the paper names hardware, command, corpus, and method
  differences beside the number.

## arXiv paper acceptance

Before submitting a taudit-owned arXiv preprint:

- [ ] Paper contribution is research, not marketing.
- [ ] Likely category is justified, for example `cs.SE` with `cs.CR` cross-list
  only if the security contribution supports it.
- [ ] Method section names corpus, commit, commands, repeat count, timeout,
  hardware, mapping process, normalizer, and raw artifact retention.
- [ ] Results distinguish detection volume from correctness.
- [ ] Threats to validity include taxonomy judgment, lack of paper-provided
  ground truth, static-analysis limits, parser partiality, hardware/runtime
  differences, and source-local execution.
- [ ] Any significant use of generative AI language tools is disclosed according
  to subject standards and author policy.
- [ ] TeX/LaTeX is submitted when TeX/LaTeX source exists.
- [ ] Ancillary material is included only to support the research article and is
  packaged under `anc/` if uploaded with the arXiv source bundle.
- [ ] Final upload uses portable file names:
  `a-z A-Z 0-9 _ + - . , =`.
- [ ] The processed PDF is manually checked before final submission.

## Stop conditions

Stop and report a gap instead of continuing if any of these occur:

- the upstream corpus cannot be pinned or legally used for the intended
  artifact;
- the smoke run cannot produce parseable JSON and retained raw output;
- the normalizer encounters an unmapped emitted taudit rule id;
- the benchmark mixes debug and release binaries without labeling;
- parser partiality makes "no finding" misleading;
- the paper draft is mostly a product comparison or unsupported superiority
  claim;
- the arXiv submitter lacks required registration or endorsement.

## Official guidance sources

- arXiv submission overview:
  <https://info.arxiv.org/help/submit/index.html>
- arXiv TeX/LaTeX submission help:
  <https://info.arxiv.org/help/submit_tex.html>
- arXiv PDF submission help:
  <https://info.arxiv.org/help/submit_pdf.html>
- arXiv endorsement help:
  <https://info.arxiv.org/help/endorsement.html>
- arXiv moderation help:
  <https://info.arxiv.org/help/moderation/index.html>
- arXiv ancillary files help:
  <https://info.arxiv.org/help/ancillary_files.html>
- arXiv category taxonomy:
  <https://arxiv.org/category_taxonomy>
