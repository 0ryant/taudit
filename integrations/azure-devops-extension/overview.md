# taudit for Azure Pipelines

Fail unsafe Azure Pipelines before merge with repo-local taudit policy gates,
reviewable workflow findings, and saved authority or exploit graph artifacts.

Use `Taudit@1` when you need to:

- fail a pipeline when a PR introduces broad service connections, risky mutable
  state, or secret-bearing helper flows
- review advisory findings during migration, audit, or hardening work
- export authority and exploit-candidate graphs as pipeline artifacts for
  security review
- keep policy, ignore files, suppressions, and baselines as explicit pipeline
  controls instead of shell-script arguments

## 60-second quick start

1. Install the extension into your Azure DevOps organization.
2. Add `Taudit@1` to a pipeline with `mode: verify` and a repo-local policy
   path such as `.taudit/policy/`.
3. Run the pipeline and inspect the `taudit.outcome` and `taudit.reportPath`
   outputs.

```yaml
steps:
  - task: Taudit@1
    displayName: Verify pipeline policy
    inputs:
      mode: verify
      policy: .taudit/policy/
      paths: |
        azure-pipelines.yml
```

## Requirements and limitations

- `policy` is required in `verify` mode.
- `baselineRoot` is workspace-relative only. Use `.` or another repo-relative
  path, not `$(System.DefaultWorkingDirectory)` and not an absolute path.
- On Windows runners, release extraction depends on PowerShell archive support
  or `tar`; if those are missing, use `fallbackCargo=true`.
- ADO variable-group enrichment is optional and requires `adoOrg`,
  `adoProject`, and a secret `adoPat` or `TAUDIT_ADO_PAT`.
- The task is Azure DevOps-first. Cross-CI scanning is supported, but the main
  merge-gating story is Azure Pipelines.

## Review artifact example

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

## What lands in the run

- `taudit.exitCode`
- `taudit.outcome`
- `taudit.reportPath`
- `taudit.findingsCount`
- `taudit.tauditVersion`
- saved graph or report artifacts when `output` is set
- config errors surfaced directly in the task log before taudit starts

## Trust signals

- typed task contract with no raw shell passthrough
- pinned GitHub release assets by taudit version and runner platform
- ADO PAT material stays in process environment and out of taudit argv
- open-source implementation and documented security disclosure path

## Key controls

- `includeBuiltin`
- `ignoreFile`
- `suppressions`
- `suppressionMode`
- `baselineRoot`
- `gateOnAll`
- `ignorePartial`
- `graphView`

## Demo and docs

- Demo story: `https://github.com/0ryant/taudit/blob/main/docs/demos/corpus-expo-docs-authority-exploit-story.md`
- CLI golden paths: `https://github.com/0ryant/taudit/blob/main/docs/golden-paths.md`
- Azure DevOps contract: `https://github.com/0ryant/taudit/blob/main/docs/integrations/azure-devops-marketplace-extension-contract.md`
