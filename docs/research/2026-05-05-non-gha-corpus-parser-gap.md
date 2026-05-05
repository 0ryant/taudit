# Non-GHA corpus parser-gap check

Observed: 2026-05-05.

Binary: `target/debug/taudit` (`taudit 1.1.0-rc.5`).

Command:

```bash
python3 scripts/research/analyze_workflow_corpus.py \
  --root corpus/workflow-yaml-testbed \
  --binary target/debug/taudit \
  --platform ado \
  --platform gl \
  --platform bb \
  --jobs 8 \
  --timeout 10 \
  --auto-reclassify-failures
```

## Result

| Bucket | Files |
|---|---:|
| Total non-GHA corpus files | 12,692 |
| Scanned with requested platform | 12,570 |
| Reclassified by `--platform auto` | 7 |
| Remaining failed | 115 |

By requested platform:

| Platform bucket | Files | Requested-platform OK | Reclassified | Remaining failed |
|---|---:|---:|---:|---:|
| ADO | 5,000 | 4,940 | 6 | 54 |
| GitLab | 5,000 | 4,977 | 0 | 23 |
| Bitbucket | 2,692 | 2,653 | 1 | 38 |

Remaining failure kinds:

| Failure kind | Count | Interpretation |
|---|---:|---|
| `yaml_parse` | 113 | Invalid YAML or unrendered template material; not a taudit rule crash. |
| `root_not_mapping` | 2 | Bitbucket bucket files whose YAML root is not a pipeline mapping. |

Reclassified platforms:

| Resolved platform | Count |
|---|---:|
| `github-actions` | 6 |
| `gitlab` | 1 |

## Reclassified files

- `corpus/workflow-yaml-testbed/ado/Bhoomika-06_SVITCSEMavenApp__azure-pipelines.yml__1a21072e05ab.yml` -> `github-actions`
- `corpus/workflow-yaml-testbed/ado/ChrisKelter_Superchat__azure-pipelines.yml__f35842a41464.yml` -> `gitlab`
- `corpus/workflow-yaml-testbed/ado/daniloiamreal_Agent-Orchestrator__workspace_azure-pipelines.yml__6a197d3fdd02.yml` -> `github-actions`
- `corpus/workflow-yaml-testbed/ado/karlospn_MyTechRamblings.Templates__src_WebApiNet5Template_pipelines_azure-pipelines.yml__2b8beff7c7df.yml` -> `github-actions`
- `corpus/workflow-yaml-testbed/ado/manishalankala_tasks__VC_1_dev-azure-pipelines.yaml__2699bbf02997.yaml` -> `github-actions`
- `corpus/workflow-yaml-testbed/ado/manishalankala_terraform__azure_8_azure-pipelines.yaml__2bb7c0c5b01a.yaml` -> `github-actions`
- `corpus/workflow-yaml-testbed/bb/ktomk_pipelines__test_data_yml_bitbucket-pipelines.yml__9959262a45f7.yml` -> `github-actions`

## Decision

The production parsers should continue rejecting the 115 remaining failures.
They are invalid YAML, unrendered templates, or non-pipeline root shapes.

The closed gap is in the research harness: explicit-platform corpus failures
can now be retried with `--platform auto`, counted as `scan_reclassified`, and
written to `analysis/reclassified.jsonl` instead of being mixed into true parse
failures.

