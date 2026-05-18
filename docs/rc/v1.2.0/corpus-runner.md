# Corpus Manifest And Runner

Status: v1.2.0-rc.1 runner skeleton.

This document covers L3-02/L3-03: the tracked corpus manifest schema and the
offline-friendly runner used to measure parser completeness from pinned local
inputs.

## Manifest Contract

Tracked manifest files validate against
`schemas/corpus-manifest.v1.json`. Each entry records:

- `id`: stable manifest-local identifier.
- `provider`: `github_actions`, `azure_pipelines`, `gitlab_ci`, or
  `bitbucket_pipelines`.
- `source`: public source URL plus upstream path and either `commit` or
  `digest`.
- `license`: license or use basis, including a short basis label.
- `expected`: parser crate, expected completeness, and expected typed gap
  classes.
- `local`: local file path plus cache metadata.
- `tags`: search and tranche labels.

The schema intentionally separates source provenance from local
materialization. A manifest can point at an ignored fetch cache, a tracked copy,
or an external reference, but the runner does not fetch or refresh remote files.

## Runner Modes

Validate the manifest and emit deterministic expectation histograms:

```powershell
python scripts/corpus_runner.py --manifest path\to\manifest.json validate
```

Run local files through taudit with a per-entry timeout:

```powershell
python scripts/corpus_runner.py --manifest path\to\manifest.json run --timeout-seconds 30 --taudit target\debug\taudit.exe
```

Optional report-schema validation can be enabled when `jsonschema` is installed:

```powershell
python scripts/corpus_runner.py --manifest path\to\manifest.json run --report-schema contracts\schemas\taudit-report.schema.json
```

## Output Shape

Both modes write sorted JSON to stdout. The top-level histograms include:

- `completeness`: counts for `complete`, `partial`, `unknown`, and `failure`.
- `gap_kinds`: counts for `expression`, `structural`, `opaque`, and `unknown`.
- `providers`: per-provider completeness counts.
- `failure_kinds`: timeout, missing local path, parser panic, invalid JSON, or
  schema validation failures when present.

`validate` uses manifest expectations only. `run` uses observed scan JSON and
records scan failures as `status: "failure"` entries instead of hiding them.

## Exit Codes

- `0`: manifest validation succeeded, and in `run` mode no entry failed.
- `1`: `run` mode completed but at least one entry recorded `failure`.
- `2`: manifest/configuration validation failed before the corpus run.

## Explicit Non-Implementation

Network fetch, cache refresh, remote license discovery, and source checkout are
not implemented in this skeleton. Future population work should add those as a
separate fetch/cache command with its own safety gates and tests. The current
runner is deterministic and offline except for whatever local `taudit` binary
the operator chooses to execute.
