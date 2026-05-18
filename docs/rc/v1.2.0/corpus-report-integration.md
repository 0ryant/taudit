# Corpus Report Integration

Status: v1.2.0-rc.1 L3-10 implementation note.

This lane turns `scripts/corpus_runner.py` output into a release-evidence-ready
JSON summary. The report is intentionally counts-only: it can support parser
completeness and typed-gap claims, but it is not a safety verdict, exploit
claim, or proof that a corpus file is vulnerability-free.

## Report Contract

Both runner modes now emit `report_kind: "taudit.corpus.summary"` and a
`release_evidence` block:

- `contract`: `taudit-corpus-report.v1`
- `claim_ceiling`: `parser-completeness-counts-only`
- `network_mode`: `offline`
- `fetch_performed`: `false`

The summary keeps the existing deterministic histograms:

- `histograms.completeness`: `complete`, `partial`, `unknown`, and `failure`.
- `histograms.gap_kinds`: `expression`, `structural`, `opaque`, and
  `unknown`.
- `histograms.providers`: per-provider completeness histograms.
- `histograms.failure_kinds`: timeout, missing local file, invalid JSON,
  schema validation, exit-code, or other runner failure classes observed.

The runner validates this report shape before emitting `validate` or `run`
output. Validation also checks that `entry_count` matches `entries`, provider
histograms match entry status counts, failure histograms match failure entries,
and gap-kind histograms match the entry gap-kind arrays.

## Commands

Emit expected histograms from the manifest without scanning local files:

```powershell
python scripts/corpus_runner.py --manifest path\to\manifest.json validate
```

Run local corpus files and validate each observed summary before emission:

```powershell
python scripts/corpus_runner.py --manifest path\to\manifest.json run --timeout-seconds 30 --taudit target\debug\taudit.exe
```

Validate a saved corpus report before attaching it to release evidence:

```powershell
python scripts/corpus_runner.py check-report --report docs\proof\v1.2.0-rc.1\corpus-report.json
```

## Offline Boundary

The runner still does not fetch, refresh, or license-discover remote corpus
material. `validate` reads only the manifest. `run` reads local files and invokes
only the operator-supplied local `taudit` binary. `check-report` reads only a
previously emitted JSON report.

## Next Dependency Unblocked

L6 release/operator docs can now cite a saved corpus report as structured
release evidence once L3-04 to L3-08 provide the populated corpus and provider
lanes. The report remains bounded to measured parser completeness and typed
gap distributions.
