# taudit for Azure Pipelines

`taudit` brings authority-graph scanning and verify-mode policy gates into
Azure DevOps pipelines as a first-class pipeline task.

## What it does

- Runs `taudit verify`, `taudit scan`, or `taudit graph`
- Preserves the same typed contract as the GitHub Marketplace action
- Downloads a pinned `taudit` release asset for the current runner platform
- Keeps Azure DevOps PAT material out of argv and injects it through process
  environment only when ADO enrichment is configured

## Minimal step

```yaml
steps:
  - task: Taudit@1
    inputs:
      mode: verify
      policy: .taudit/policy/
      paths: |
        azure-pipelines.yml
```

## Key controls

- `includeBuiltin`
- `ignoreFile`
- `suppressions`
- `suppressionMode`
- `baselineRoot`
- `gateOnAll`
- `ignorePartial`
- `graphView`

## Outputs

The task writes output variables such as:

- `taudit.exitCode`
- `taudit.outcome`
- `taudit.reportPath`
- `taudit.findingsCount`
- `taudit.tauditVersion`

These can be consumed by later steps in the same job or downstream jobs using
Azure DevOps output-variable syntax.
