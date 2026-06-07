# arXiv taudit detection ledger

Date: 2026-06-01
Status: detection-output contract; no full arXiv corpus detection claim yet

## Normalization contract

Use:

```powershell
python scripts\research\normalize_taudit_arxiv_findings.py `
  <taudit-json-report-or-directory> `
  --rule-map docs\research\arxiv-taudit-rule-map.csv `
  --output-csv <artifact-output-dir>\findings.csv `
  --output-jsonl <artifact-output-dir>\findings.jsonl `
  --summary-json <artifact-output-dir>\detection-summary.json
```

The normalizer fails closed if a `taudit` finding rule id is absent from
`docs/research/arxiv-taudit-rule-map.csv`.

## Output fields

| Field | Meaning |
| --- | --- |
| `workflow_path` | Workflow file scanned. |
| `rule_id` | `taudit` finding rule id. |
| `arxiv_weakness` | Canonical class: `AIW`, `CFW`, `EPW`, `GRCW`, `HGW`, `IW`, `KVCW`, `PTW`, `SEW`, `UDW`, or `out_of_scope`. |
| `upstream_raw_weakness` | Raw upstream label when a paper/repo mismatch exists, such as `TMW` for canonical `PTW`. |
| `severity` | taudit severity for the finding. |
| `fingerprint` | taudit stable finding fingerprint. |
| `line` | Source line when available, otherwise `unknown`. |
| `mapping_status` | Whether the taxonomy mapping is proposed or requires author review. |

## Claim boundary

Detection-volume rows count scanner behavior after taxonomy mapping. They do
not prove correctness. False-positive and false-negative claims require the
labeling protocol in `docs/research/arxiv-taudit-labeling-protocol.md`.

## 2026-06-01 release-binary 10-workflow smoke

Source-local smoke evidence:

- Run id: `taudit-arxiv-upstream-10-smoke-release`
- Corpus repository: `https://github.com/sparkrew/github-actions-security`
- Corpus commit: `09c9e167f740e32d5f5d77a785b5056bff8b7fe6`
- taudit source commit: `7bd9d56d860165cb3041ed339c13661466f5b52f`
- taudit version: `taudit 1.3.0-pre`
- Binary SHA-256:
  `8296FBCC5CA0BB6B175B9B7C446544B272629706CE4CD6FE9AE2CB6BB17429BE`
- Output directory: `%TEMP%\taudit-arxiv-upstream-10-smoke-release`
- Finding count: 97
- Normalization status: `ok`
- Normalization error count: 0

Detection-volume counts by mapped weakness class:

| Weakness | Findings |
| --- | ---: |
| `EPW` | 12 |
| `KVCW` | 1 |
| `PTW` | 5 |
| `SEW` | 41 |
| `UDW` | 38 |

Detection-volume counts by taudit rule:

| Rule | Findings |
| --- | ---: |
| `action_major_version_pin_without_sha` | 18 |
| `authority_propagation` | 12 |
| `known_compromised_action_ref` | 1 |
| `no_workflow_level_permissions_block` | 4 |
| `over_privileged_identity` | 8 |
| `pr_trigger_with_floating_action_ref` | 3 |
| `risky_trigger_with_authority` | 1 |
| `trigger_context_mismatch` | 1 |
| `unpinned_action` | 20 |
| `untrusted_with_authority` | 29 |

This smoke detected no unmapped emitted rule IDs. The table is detection volume
only and must not be used as FP/FN or precision/recall evidence.
