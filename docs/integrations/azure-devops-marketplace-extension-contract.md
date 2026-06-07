# Azure DevOps Marketplace Task Contract

Status: implemented v1 contract for the `algol.taudit-azure-pipelines` Azure
DevOps extension.

Live listing:
<https://marketplace.visualstudio.com/items?itemName=Algol.taudit-azure-pipelines>

## Release state

Observed on 2026-06-01:

| Surface | State |
|---|---|
| Source-local extension manifest | `integrations/azure-devops-extension/vss-extension.json` version `0.1.10` |
| Source-local package manifest | `integrations/azure-devops-extension/package.json` version `0.1.10` |
| Source-local task metadata | `Taudit@1` task version `1.0.6`; default downloaded `taudit` version `1.1.5` |
| GitHub release witness | `0ryant/taudit` latest release `v1.1.5` with platform archives and `.sha256` files |
| crates.io witness | `taudit` latest stable crate `1.1.5` |
| Visual Studio Marketplace witness | live `Algol.taudit-azure-pipelines` extension version `0.1.9`; rendered quick start still shows `version: 1.1.4` |
| Task runtime dependency audit | Source-local `npm audit --omit=dev` reports 2 moderate advisories through `azure-pipelines-task-lib` -> `uuid`; npm reports `fixAvailable: false` while `azure-pipelines-task-lib` is already at the latest observed `5.2.10` |

The source-local `0.1.10` package is the next publish candidate. Publishing is
blocked on an operator-owned Marketplace action: run local preflight, publish
`dist/algol.taudit-azure-pipelines-0.1.10.vsix`, then record the Marketplace
response and a live `Taudit@1` smoke receipt in
[`azure-devops-live-proof-checklist.md`](azure-devops-live-proof-checklist.md).
Treat the `uuid` advisory as an explicit residual until the upstream task
library ships a compatible fix or a tested override is proven.

This document defines the first-class Azure Pipelines task surface for taudit.
It is the Azure DevOps pipeline-step counterpart to the GitHub Marketplace
action and the VS Code extension.

## Contract identity

| Field | Value |
|---|---|
| Publishable unit | Azure DevOps extension |
| Extension ID | `algol.taudit-azure-pipelines` |
| Task name | `Taudit@1` |
| Contract id | `dev.taudit.azure-pipelines-task.v1` |
| Contract version | `1.0.0` |
| Primary files | `vss-extension.json`, `Taudit/task.json`, `Taudit/index.js` |
| Execution model | Thin typed adapter over `taudit` CLI |
| Default mode | `verify` |
| Install scope | Azure DevOps organization |
| Out of scope | Raw CLI passthrough, automatic SARIF upload, third-party storage upload |

## Minimal YAML

```yaml
steps:
  - task: Taudit@1
    inputs:
      mode: verify
      policy: .taudit/policy/
      paths: |
        azure-pipelines.yml
```

## Input surface

The task exposes only typed inputs. It must not expose a free-form command,
shell, or extra-args passthrough in v1.

| Input | Type | Default | Applies to | CLI mapping |
|---|---|---|---|---|
| `mode` | enum `verify`, `scan`, `graph` | `verify` | all | subcommand |
| `version` | SemVer string | `1.1.5` | all | installer only |
| `paths` | multiline string | `azure-pipelines.yml` | all | positional paths |
| `platform` | enum `auto`, `github-actions`, `azure-devops`, `gitlab`, `bitbucket` | `auto` | all | `--platform` |
| `adoOrg` | string | none | all | `--ado-org` (forwarded; may be reserved scaffolding on current taudit versions) |
| `adoProject` | string | none | all | `--ado-project` (forwarded; may be reserved scaffolding on current taudit versions) |
| `adoPat` | secret string | none | all | `TAUDIT_ADO_PAT` env (forwarded; may be reserved scaffolding on current taudit versions) |
| `policy` | workspace-relative file or directory | none | `verify` | `--policy` |
| `includeBuiltin` | boolean | `false` | `verify` | `--include-builtin` |
| `ignoreFile` | workspace-relative file | none | `scan`, `verify` | `--ignore-file` |
| `suppressions` | workspace-relative file | none | `scan`, `verify` | `--suppressions` |
| `suppressionMode` | enum `downgrade`, `tag-only` | `downgrade` | `scan`, `verify` | `--suppression-mode` |
| `baselineRoot` | workspace-relative directory | none | `scan`, `verify` | `--baseline-root` |
| `gateOnAll` | boolean | `false` | `verify` | `--gate-on-all` |
| `strict` | boolean | `false` | `verify` | `--strict` |
| `ignorePartial` | boolean | `false` | `verify` | `--ignore-partial` |
| `format` | mode-scoped string | mode default | all | `--format` |
| `output` | workspace-relative file | none | all | `--output` for scan/verify; captured stdout for graph |
| `graphView` | enum `authority`, `exploit` | `authority` | `graph` | `--view` |
| `severityThreshold` | enum `critical`, `high`, `medium`, `low`, `info` | none | `scan`, `verify` | `--severity-threshold` |
| `maxHops` | positive integer | CLI default | all | `--max-hops` |
| `noColor` | boolean | `true` | `scan`, `verify` | `--no-color` |
| `fallbackCargo` | boolean | `false` | installer | installer only |

Notes:

- `policy`, `ignoreFile`, `suppressions`, and `baselineRoot` are modeled as
  plain string inputs in the Azure DevOps task contract. They are not
  `filePath` inputs because the Azure Pipelines agent can canonicalize
  `filePath` values into absolute workspace paths before the task runs.
- For compatibility with older task materialization behavior, workspace-absolute
  values inside the checked-out repo are relativized internally before CLI
  argument construction.
- `policy` is validated only in `verify` mode. `graph` does not require it.

## Output variables

The task sets these output variables:

- `taudit.exitCode`
- `taudit.outcome`
- `taudit.reportPath`
- `taudit.findingsCount`
- `taudit.tauditVersion`

The step should usually be named so later steps can reference them:

```yaml
steps:
  - task: Taudit@1
    name: tauditGate
    inputs:
      mode: verify
      policy: .taudit/policy/
      paths: |
        azure-pipelines.yml

  - script: echo "$(tauditGate.taudit.outcome)"
```

## Packaging constraints

- The VSIX must include the full task runtime under `Taudit/`.
- The task runtime dependency tree must be included under
  `Taudit/node_modules/`.
- The package must include discovery assets: `overview.md` and icon.
- The extension can be published private and shared org-by-org, or made public
  later without changing the task contract.
- Cargo fallback, when enabled, must install into a workspace-local tool cache
  and execute the resolved binary path directly rather than relying on PATH
  mutation.

## Publish and install model

Azure DevOps tasks are installed at the organization level after the extension
is published and shared.

High-level operator flow:

1. Build VSIX.
2. Publish Azure DevOps extension to Visual Studio Marketplace.
3. Share the private extension with the Azure DevOps organization.
4. Install it into the organization.
5. Reference `Taudit@1` in pipeline YAML.

The repository smoke definition for this contract lives at:

```text
../../azure-pipelines.taudit-task-smoke.yml
```
