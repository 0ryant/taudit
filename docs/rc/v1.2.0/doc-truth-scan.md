# v1.2.0-rc.1 Doc Truth Scan

Status: L6-02/L6-12 offline scanner. The scanner reports stale RC wording and
unqualified adoption or completeness claims. It does not edit documentation,
fetch network state, or treat prose as proof.

## Command

```powershell
python scripts/doc_truth_scan.py --format json
```

Use explicit paths to narrow a lane review:

```powershell
python scripts/doc_truth_scan.py --format text README.md USERGUIDE.md docs/golden-paths.md
```

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | No issues were reported. |
| 1 | At least one issue was reported. |
| 2 | Argument parsing or Python execution failed before a scan report. |

## Default Scope

The default scan includes root operator surfaces and maintained Markdown under
`docs/**`:

- `README.md`
- `USERGUIDE.md`
- `TODOS.md`
- `CHANGELOG.md`
- `docs/**/*.md`

The default scan excludes historical or receipt material that is not a current
operator promise:

- `docs/adr/**`
- `docs/research/**`
- `docs/proof/**`

Fenced code blocks are ignored so docs can show bad examples without creating a
self-failing report.

## Rule Ceilings

The scanner flags these claim classes unless nearby wording makes the claim
proof-gated, planned, historical, or evidence-bound:

| Rule | Claim ceiling |
| --- | --- |
| `marketplace-proof-overclaim` | Marketplace, hosted-smoke, listing, installability, backlink, and moving-tag claims need receipt-gated wording until receipts exist. |
| `stable-rc-overclaim` | `v1.2.0` must not be presented as stable or production-ready while stable promotion is blocked. |
| `parser-completeness-overclaim` | Provider/parser completeness language needs matrix, corpus, fixture, partiality, or gap evidence. |
| `conformance-overclaim` | Full ADR 0020 conformance language must name the harness or pending gate state. |
| `stale-install-version` | Old `cargo install taudit --version 1.0.12` pins need refresh or explicit historical framing. |
| `stale-current-cycle-version` | `v1.1.0` current-cycle language is stale for this RC lane unless explicitly historical. |
| `witness-disclosure-overclaim` | CVE, disclosure, witness, and observed-exploit wording must stay inside the documented output ceiling. |

## Report Shape

JSON output is a deterministic release-evidence receipt shape:

```json
{
  "files_scanned": 1,
  "issue_count": 1,
  "issues": [
    {
      "code": "stable-rc-overclaim",
      "column": 1,
      "line": 1,
      "match": "v1.2.0 is stable",
      "message": "v1.2.0 stable or production-ready claims must be framed as gated/pending until promotion.",
      "path": "README.md",
      "severity": "error",
      "text": "v1.2.0 is stable today."
    }
  ],
  "status": "issues"
}
```

Downstream lanes can archive the JSON report with other L6 proof material, or
use it as a blocking local check before docs are promoted out of the RC branch.

## Residual Risk

This is a heuristic truth scan, not a semantic reviewer. It catches known
release-risk terms and applies bounded allow contexts; it cannot prove every
sentence is correct, validate external marketplace state, or replace human
review of final release notes.

## Dependency Unblocked

L6-02 can now run an offline wording scan before editing operator docs, and
L6-12 can require the same scan as a final doc drift gate before release review.
