# taudit Azure DevOps extension

Azure DevOps extension packaging for the `Taudit@1` pipeline task.

This is the pipeline-step surface for Azure DevOps. It complements the VS Code
extension in `integrations/vscode-extension/`; it does not replace it.

## Golden path

1. Package the extension:

```bash
npm ci
npm run preflight
```

2. Publish the VSIX to Visual Studio Marketplace as an Azure DevOps extension.
3. Share the extension with your Azure DevOps organization if it remains private.
4. Install it into the organization.
5. Use `Taudit@1` in pipeline YAML.

The packaged artifact is:

```text
dist/algol.taudit-azure-pipelines-0.1.1.vsix
```

This repo also carries a dedicated smoke lane:

```text
../../azure-pipelines.taudit-task-smoke.yml
```

It exercises `Taudit@1` in `scan`, `graph authority`, `graph exploit`, and
`verify` modes against this repository.

## YAML

```yaml
steps:
  - task: Taudit@1
    inputs:
      mode: verify
      policy: .taudit/policy/
      paths: |
        azure-pipelines.yml
```

## Verify-first example

```yaml
steps:
  - task: Taudit@1
    displayName: Verify pipeline policy
    inputs:
      mode: verify
      policy: .taudit/policy/
      paths: |
        azure-pipelines.yml
      includeBuiltin: true
      severityThreshold: high
```

## Graph example

```yaml
steps:
  - task: Taudit@1
    displayName: Export exploit-candidate graph
    inputs:
      mode: graph
      paths: |
        azure-pipelines.yml
      graphView: exploit
      format: dot
      output: .artifacts/taudit-exploit.dot
```

## Task outputs

The task sets Azure DevOps output variables:

- `taudit.exitCode`
- `taudit.outcome`
- `taudit.reportPath`
- `taudit.findingsCount`
- `taudit.tauditVersion`

Use them by naming the step:

```yaml
steps:
  - task: Taudit@1
    name: tauditGate
    inputs:
      mode: verify
      policy: .taudit/policy/
      paths: |
        azure-pipelines.yml

  - script: echo "taudit outcome: $(tauditGate.taudit.outcome)"
```

## Contract

`Taudit@1` is a thin typed adapter over the `taudit` CLI.

- Default mode: `verify`
- Default platform: `auto`
- Default paths: `azure-pipelines.yml`
- No raw args or shell passthrough
- `verify` requires `policy`
- `graph` writes to a file only when `output` is set; the task captures stdout
  because `taudit graph` itself does not support `--output`

See also:

- [`../../docs/integrations/azure-devops-marketplace-extension-contract.md`](../../docs/integrations/azure-devops-marketplace-extension-contract.md)

## Packaging

```bash
npm ci
npm run preflight
```

This emits a VSIX under `dist/` that can be published as an Azure DevOps
extension and then installed into an Azure DevOps organization.
