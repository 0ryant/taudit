# taudit for Azure Pipelines

Gate Azure Pipelines with the same taudit controls operators use from the CLI:
policy verification, advisory CI/CD scans, and reviewable authority or exploit
graph artifacts.

Use `Taudit@1` when you need to:

- fail a pipeline when workflow authority violates a repo-local policy
- scan Azure Pipelines YAML, GitHub Actions, GitLab CI, or Bitbucket pipeline
  files during migration and audit work
- export authority and exploit-candidate graphs for security review
- keep policy, ignore files, suppressions, and baselines as explicit pipeline
  controls instead of shell-script arguments

## Golden path

1. Install the extension into your Azure DevOps organization.
2. Add `Taudit@1` to a pipeline.
3. Start with `mode: verify` and a repo-local policy directory such as
   `.taudit/policy/`.
4. Add `mode: graph` with `graphView: authority` or `graphView: exploit` when
   you want a saved graph artifact for review.

## What it does

- Runs `taudit verify`, `taudit scan`, or `taudit graph`.
- Preserves a typed task contract with no raw shell or arbitrary argument
  passthrough.
- Downloads a pinned `taudit` release asset for the current runner platform.
- Keeps Azure DevOps PAT material out of argv and injects it through process
  environment only when ADO enrichment is configured
- Falls back to a locked, workspace-local Cargo install only when explicitly
  enabled through `fallbackCargo`

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

## Graph artifact example

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

## Demo and docs

- Demo story: `https://github.com/0ryant/taudit/blob/main/docs/demos/corpus-expo-docs-authority-exploit-story.md`
- CLI golden paths: `https://github.com/0ryant/taudit/blob/main/docs/golden-paths.md`
- Azure DevOps contract: `https://github.com/0ryant/taudit/blob/main/docs/integrations/azure-devops-marketplace-extension-contract.md`
