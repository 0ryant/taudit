# taudit Azure DevOps extension

Azure DevOps Marketplace packaging for `Taudit@1`, a pipeline task that runs
taudit policy gates, advisory CI/CD scans, and authority graph exports without
raw shell passthrough.

Use it to make taudit visible in Azure Pipelines as an installable task:

- `verify` blocks unsafe authority paths with repo-local policy
- `scan` gives teams advisory findings during adoption and migration
- `graph` writes authority or exploit-candidate artifacts for review
- typed inputs keep policy, ignore files, suppressions, baselines, and ADO
  enrichment separate

Operator pitfalls worth knowing up front:

- `baselineRoot` must be workspace-relative, for example `.` or `.taudit`.
  Do not pass `$(System.DefaultWorkingDirectory)` or any absolute path.
- On Windows, release-asset extraction depends on PowerShell archive support or
  `tar`. If that path is unavailable on the runner, set `fallbackCargo=true`
  and the task will install `taudit` into a workspace-local Cargo cache.

This is the pipeline-step surface for Azure DevOps. It complements the VS Code
extension in `integrations/vscode-extension/`; it does not replace it.

## Operator golden path

1. Install the extension into your Azure DevOps organization.
2. Add `Taudit@1` to your pipeline YAML.
3. Start with `mode: verify` and `policy: .taudit/policy/`.
4. Add `mode: graph` and `graphView: authority` or `exploit` when you want
   saved graph artifacts.

## Maintainer packaging path

1. Package the extension:

```bash
npm ci
npm run preflight
```

2. Publish the VSIX to Visual Studio Marketplace as an Azure DevOps extension.
3. Share the extension with your Azure DevOps organization if it remains private.
4. Install it into the organization.

The packaged artifact is:

```text
dist/algol.taudit-azure-pipelines-0.1.7.vsix
```

This repo also carries a dedicated smoke lane:

```text
../../azure-pipelines.taudit-task-smoke.yml
```

It exercises `Taudit@1` in `scan`, `graph authority`, `graph exploit`, and
`verify` modes against this repository.

Binary behavior:

- Default: download a pinned GitHub release asset for the current runner
  platform into `.taudit-tools/bin/<version>/`.
- Optional fallback: if `fallbackCargo=true`, install `taudit` with
  `cargo install --locked --root <workspace-local-cache>` and execute that
  binary directly.

Windows note:

- The task first tries explicit PowerShell `Expand-Archive` extraction with
  `Microsoft.PowerShell.Archive` imported directly, then falls back to `tar`.
- If both extraction paths are unavailable on the runner, the task now points
  directly at `fallbackCargo=true` as the supported recovery path.

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
- [`../../docs/demos/corpus-expo-docs-authority-exploit-story.md`](../../docs/demos/corpus-expo-docs-authority-exploit-story.md)
- [`../../docs/golden-paths.md`](../../docs/golden-paths.md)

## Packaging

```bash
npm ci
npm run preflight
```

This emits a VSIX under `dist/` that can be published as an Azure DevOps
extension and then installed into an Azure DevOps organization.
