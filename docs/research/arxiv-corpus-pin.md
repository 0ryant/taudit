# arXiv corpus pin

Date: 2026-06-01
Status: upstream pin and manifest-generation instructions; corpus is not vendored

## Observed upstream state

Observed with read-only git commands against
`https://github.com/sparkrew/github-actions-security.git`.

- Default branch: `main`
- Observed `main` commit: `09c9e167f740e32d5f5d77a785b5056bff8b7fe6`
- Workflow dataset path: `dataset/workflows/`
- Workflow files at observed commit: 596 total, 553 `.yml` and 43 `.yaml`
- Current tree shape: flat files under `dataset/workflows/`, for example
  `dataset/workflows/AUTOMATIC1111_stable-diffusion-webui__on_pull_request.yaml`
- Dataset metadata files also present:
  `dataset/workflow_list.csv`, `dataset/workflow_metadata.csv`,
  `dataset/workflow_metadata_no-content.csv`, `dataset/fetched_workflows.pkl`

## Exact observed commands

```bash
git ls-remote --symref https://github.com/sparkrew/github-actions-security.git HEAD
git ls-remote https://github.com/sparkrew/github-actions-security.git refs/heads/main refs/heads/master
git clone --bare --depth=1 --filter=blob:none https://github.com/sparkrew/github-actions-security.git /tmp/github-actions-security-09c9e167.git
git -C /tmp/github-actions-security-09c9e167.git rev-parse HEAD
git -C /tmp/github-actions-security-09c9e167.git ls-tree -r --name-only HEAD -- dataset/workflows
```

## Manifest generation

Preferred local route from the taudit repository root:

```bash
UPSTREAM_URL=https://github.com/sparkrew/github-actions-security.git
UPSTREAM_COMMIT=09c9e167f740e32d5f5d77a785b5056bff8b7fe6
CORPUS_GIT=/tmp/github-actions-security-${UPSTREAM_COMMIT}.git

git clone --bare --depth=1 --filter=blob:none "$UPSTREAM_URL" "$CORPUS_GIT"
git -C "$CORPUS_GIT" rev-parse HEAD
python scripts/research/generate_arxiv_corpus_manifest.py "$CORPUS_GIT" \
  --mode git-tree \
  --workflow-dir dataset/workflows \
  --upstream-url "$UPSTREAM_URL" \
  --commit "$UPSTREAM_COMMIT" \
  --output artifacts/arxiv/corpus-manifest.json
```

The same tool also accepts a normal checkout or extracted `dataset/workflows`
directory:

```bash
git clone "$UPSTREAM_URL" /tmp/github-actions-security
git -C /tmp/github-actions-security checkout "$UPSTREAM_COMMIT"
python scripts/research/generate_arxiv_corpus_manifest.py /tmp/github-actions-security \
  --output artifacts/arxiv/corpus-manifest.json
```

For a smoke manifest, add `--limit 10`.

## Windows note

The observed upstream tree contains NTFS-invalid paths under `tools/`, including
literal `:Zone.Identifier` suffixes. On Windows, prefer the bare-clone
`--mode git-tree` route above, or run the normal checkout in Linux/WSL storage.
Do not copy `dataset/workflows/` into this repository unless the license and
redistribution basis has been reviewed.

## Claim ceiling

This pin and manifest tooling only establishes source-local corpus identity:
upstream URL, commit, workflow relative paths, byte sizes, and SHA-256 digests.
It does not prove benchmark performance, external inclusion, FP/FN rates, or
permission to redistribute the upstream corpus.
