# taudit Marketplace Proof Media Shot List

This is the execution plan for the first proof-media pack used by the taudit
VS Code and Azure DevOps Marketplace listings.

The goal is not generic product art. The goal is operator proof:

- show one clean first-use path
- show one verify result
- show one authority graph
- show one exploit-candidate graph
- show one Azure Pipelines task result

Use the same repo, policy path, and corpus workflow across shots where
possible so the listings feel consistent and reproducible.

Primary source story:

- [Demo: Authority And Exploit Path In One Corpus Pipeline](/Users/rytilcock/prj/taudit/docs/demos/corpus-expo-docs-authority-exploit-story.md)

## Global capture rules

- Use direct screenshots, not phone photos.
- Use the same taudit version and the same corpus workflow across the graph
  shots.
- Prefer a light editor theme and a readable monospace font for screenshots.
- Crop tightly around the proof surface: command result, graph, artifact, or
  task output.
- Do not show secret material, personal notifications, shell history, or
  unrelated tabs.
- Keep filenames stable so Marketplace copy can reference them without churn.

## Capture environment

Use these fixed inputs for the first pack unless a shot says otherwise:

- Repo root: `/Users/rytilcock/prj/taudit`
- Demo workflow:
  `/Users/rytilcock/prj/taudit/corpus/workflow-yaml-testbed/gha/expo_expo__.github_workflows_docs.yml__fca5ee05f1a8.yml`
- Demo story:
  `/Users/rytilcock/prj/taudit/docs/demos/corpus-expo-docs-authority-exploit-story.md`
- Verify policy path:
  `.taudit/policy/`
- VS Code extension installed locally
- Azure DevOps extension installed in the target org
- Graphviz `dot` available locally for DOT-to-PNG renders

## Shared prep

Do this once before capturing any media:

1. Build or install a current `taudit` binary:
   `cargo install taudit --locked`
2. Open `/Users/rytilcock/prj/taudit` in VS Code.
3. Set `taudit.verify.policyPath` to `.taudit/policy/`.
4. Run `taudit: Initialize Workspace Policy`.
5. Confirm `taudit: Verify Workspace` runs without a configuration error.
6. Generate the demo graph artifacts:

```bash
PIPE=/Users/rytilcock/prj/taudit/corpus/workflow-yaml-testbed/gha/expo_expo__.github_workflows_docs.yml__fca5ee05f1a8.yml

taudit graph --platform github-actions --format dot --view authority --rich-labels "$PIPE" \
  > /Users/rytilcock/prj/taudit/docs/demos/assets/expo-docs-authority.dot

taudit graph --platform github-actions --format dot --view exploit "$PIPE" \
  > /Users/rytilcock/prj/taudit/docs/demos/assets/expo-docs-exploit.dot

dot -Tpng /Users/rytilcock/prj/taudit/docs/demos/assets/expo-docs-authority.dot \
  -o /Users/rytilcock/prj/taudit/docs/demos/assets/expo-docs-authority.png

dot -Tpng /Users/rytilcock/prj/taudit/docs/demos/assets/expo-docs-exploit.dot \
  -o /Users/rytilcock/prj/taudit/docs/demos/assets/expo-docs-exploit.png
```

7. Confirm the Azure DevOps demo pipeline includes a `Taudit@1` step with an
   explicit `version`.

## VS Code Marketplace media

### VS-01 — Quick start success

- Filename: `vscode-verify-workspace-success.png`
- Use in:
  - VS Code Marketplace hero screenshot
  - VS Code README quick-start section
- Show:
  - VS Code editor open on a pipeline file
  - command palette result or output channel showing a successful
    `taudit: Verify Workspace`
  - enough surrounding UI to prove this is a VS Code workflow
- Prerequisites:
  - `taudit.verify.policyPath` configured
  - initialized workspace policy exists
  - successful verify run already executed
- Capture note:
  - keep the output channel open with the passing result and artifact path visible

### VS-02 — Authority graph in editor workflow

- Filename: `vscode-authority-graph.png`
- Use in:
  - VS Code Marketplace screenshot slot
  - README result-surfaces section
- Show:
  - rendered authority graph PNG or DOT preview from the Expo docs demo
  - visible filename or tab title containing `authority`
- Prerequisites:
  - `expo-docs-authority.png` already generated
  - graph opened from the workspace, not from a detached image viewer
- Capture note:
  - crop so the graph remains readable; do not show a tiny thumbnail

### VS-03 — Exploit-candidate graph in editor workflow

- Filename: `vscode-exploit-graph.png`
- Use in:
  - VS Code Marketplace screenshot slot
  - README exploit-graph explanation
- Show:
  - rendered exploit graph PNG or DOT preview from the Expo docs demo
  - visible filename or tab title containing `exploit`
- Prerequisites:
  - `expo-docs-exploit.png` already generated
- Capture note:
  - prefer the rendered PNG if the DOT text is too dense on screen

### VS-04 — Config error fails early

- Filename: `vscode-config-error-policy-missing.png`
- Use in:
  - README limitations or troubleshooting section
  - optional fourth VS Code Marketplace screenshot
- Show:
  - output channel or VS Code error surface for a missing or invalid
    `taudit.verify.policyPath`
- Prerequisites:
  - temporarily point `taudit.verify.policyPath` at a missing path
- Capture note:
  - only capture this if the first three proof surfaces are already strong

### VS-GIF — Initialize policy to verify

- Filename: `vscode-initialize-policy-verify.gif`
- Use in:
  - VS Code Marketplace media
  - repo docs and launch posts
- Flow:
  1. open command palette
  2. run `taudit: Initialize Workspace Policy`
  3. open seeded policy file
  4. run `taudit: Verify Workspace`
  5. open `taudit: Show Output`
- Duration:
  - target 12–20 seconds
- Prerequisites:
  - fresh or freshly reset workspace settings
  - `.taudit/policy/` absent before recording
- Capture note:
  - do one clean pass at normal speed; no cursor circling or zoom effects

## Azure DevOps Marketplace media

### ADO-01 — Minimal verify task in YAML

- Filename: `ado-task-verify-yaml.png`
- Use in:
  - Azure DevOps listing overview near quick start
  - Azure DevOps README quick-start section
- Show:
  - Azure pipeline YAML editor with a minimal `Taudit@1` verify step
  - explicit `version`
  - repo-local `policy`
- Prerequisites:
  - pipeline file contains the documented quick-start block
- Capture note:
  - keep the shot tight; the step contract should be readable

### ADO-02 — Successful task run summary

- Filename: `ado-task-run-success.png`
- Use in:
  - Azure DevOps Marketplace hero screenshot
  - README “What lands in the run” section
- Show:
  - Azure DevOps run summary for a successful `Taudit@1` step
  - visible task name and success state
- Prerequisites:
  - one real pipeline run with `Taudit@1` completed successfully
- Capture note:
  - this is the highest-value Azure proof shot; do not substitute a YAML-only shot

### ADO-03 — Task outputs and artifact path

- Filename: `ado-task-outputs-and-report-path.png`
- Use in:
  - Azure DevOps listing secondary screenshot
  - docs explaining task outputs
- Show:
  - task log lines or summary proving `taudit.outcome`, `taudit.reportPath`,
    and `taudit.tauditVersion`
- Prerequisites:
  - successful run with visible outputs
- Capture note:
  - crop to the output values; do not include unrelated job logs

### ADO-04 — Exploit graph artifact from pipeline

- Filename: `ado-exploit-graph-artifact.png`
- Use in:
  - Azure DevOps listing screenshot slot
  - overview “review artifact example”
- Show:
  - artifact browser or downloaded artifact view for an exploit graph generated
    by `Taudit@1`
- Prerequisites:
  - pipeline run executed with:

```yaml
steps:
  - task: Taudit@1
    displayName: Export exploit-candidate graph
    inputs:
      mode: graph
      version: 1.1.4
      paths: |
        azure-pipelines.yml
      graphView: exploit
      format: dot
      output: .artifacts/taudit-exploit.dot
```

- Capture note:
  - if the Azure artifact browser is too cramped, use the downloaded rendered
    PNG alongside the artifact filename in the pipeline UI

### ADO-05 — Trust model and self-audit proof

- Filename: `ado-task-version-pinned-self-audit.png`
- Use in:
  - Azure DevOps listing trust-signals section
  - docs explaining “When taudit finds taudit”
- Show:
  - YAML with `Taudit@1`, explicit `version`, and repo-local `policy`
  - optionally a nearby finding or note proving the taudit step remains in scope
- Prerequisites:
  - demo pipeline or example pipeline where taudit can appear in findings
- Capture note:
  - this is optional for Marketplace, but useful for launch collateral and docs

## Asset slot mapping

Use this default mapping unless Marketplace slot limits force consolidation.

### VS Code listing

1. `vscode-verify-workspace-success.png`
2. `vscode-authority-graph.png`
3. `vscode-exploit-graph.png`
4. `vscode-initialize-policy-verify.gif`

### Azure DevOps listing

1. `ado-task-run-success.png`
2. `ado-task-verify-yaml.png`
3. `ado-task-outputs-and-report-path.png`
4. `ado-exploit-graph-artifact.png`

## Storage plan

Store captured assets under a dedicated repo path so the README, overview, and
launch posts all reference the same files.

Recommended target folder:

- `/Users/rytilcock/prj/taudit/docs/integrations/assets/marketplace/`

Recommended filenames:

- `vscode-verify-workspace-success.png`
- `vscode-authority-graph.png`
- `vscode-exploit-graph.png`
- `vscode-config-error-policy-missing.png`
- `vscode-initialize-policy-verify.gif`
- `ado-task-verify-yaml.png`
- `ado-task-run-success.png`
- `ado-task-outputs-and-report-path.png`
- `ado-exploit-graph-artifact.png`
- `ado-task-version-pinned-self-audit.png`

## Execution order

Capture in this order so later shots can reuse earlier setup:

1. VS-01 quick start success
2. VS-GIF initialize policy to verify
3. VS-02 authority graph
4. VS-03 exploit graph
5. ADO-01 minimal verify YAML
6. ADO-02 successful task run summary
7. ADO-03 task outputs and artifact path
8. ADO-04 exploit graph artifact
9. ADO-05 trust/self-audit proof if needed

## Done criteria

The pack is ready when all of these are true:

- one VS Code screenshot proves first success
- one VS Code screenshot proves authority graph output
- one VS Code screenshot proves exploit graph output
- one GIF shows policy bootstrap to verify result
- one Azure screenshot proves a successful `Taudit@1` run
- one Azure screenshot proves task outputs or saved artifact behavior
- every asset filename and listing slot is stable enough to reference from docs
