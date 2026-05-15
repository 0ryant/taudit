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
      version: 1.1.4
      policy: .taudit/policy/
      paths: |
        azure-pipelines.yml
```

## Requirements and limitations

- Azure DevOps Marketplace tasks do not have a GitHub-style SHA pin surface.
  The closest equivalent is `Taudit@1` plus an explicit `version` input for the
  downloaded `taudit` binary.
- `policy` is required in `verify` mode.
- `baselineRoot` is workspace-relative only. Use `.` or another repo-relative
  path, not `$(System.DefaultWorkingDirectory)` and not an absolute path.
- On Windows runners, release extraction depends on PowerShell archive support
  or `tar`; if those are missing, use `fallbackCargo=true`.
- `adoOrg`, `adoProject`, and `adoPat` are forwarded to the taudit CLI for
  ADO-aware analysis. Current taudit versions may treat that path as reserved
  scaffolding rather than active variable-group enrichment.
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
- version-pinned GitHub release assets by runner platform, with SHA-256
  verification before execution
- ADO PAT material stays in process environment and out of taudit argv
- open-source implementation and documented security disclosure path

## What the task executes

`Taudit@1` downloads the requested taudit release asset for the runner platform,
verifies its SHA-256 checksum, extracts it into a workspace-local tool cache,
and executes that binary locally on the agent. If `fallbackCargo=true` is set,
the task may instead install the pinned taudit crate version into a
workspace-local Cargo cache and run that binary. The task logs the resolved
taudit version and report path so the execution surface is inspectable in the
pipeline run.

## When taudit finds taudit

`Taudit@1` stays inside the authority graph. If your pipeline gives the task
broad authority or routes it through risky boundaries, `taudit` can report that
step in findings. That is expected behavior, not a hidden self-attack mode.

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
