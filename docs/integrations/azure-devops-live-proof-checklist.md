# Azure DevOps Live Proof Checklist

Use this checklist to get one real `Taudit@1` pipeline receipt in Azure
Pipelines and to verify that the run produced the expected task outputs and
artifacts.

## Success definition

A live proof receipt is complete when all of these are true:

1. The pipeline queues on a real Azure DevOps agent.
2. `Taudit@1` runs in `scan`, `graph authority`, `graph exploit`, and `verify`
   modes.
3. The task sets the expected output variables.
4. The run publishes the `.artifacts/` directory as a pipeline artifact.
5. The artifact contains the expected scan, graph, and verify files.

The repository smoke lane for this is:

```text
/Users/rytilcock/prj/taudit/azure-pipelines.taudit-task-smoke.yml
```

## Preconditions

- The Azure DevOps extension is installed into the target organization.
- The pipeline YAML points at this repository and branch.
- The repository contains:
  - `invariants/policies/example-enterprise-ado.yml`
  - `tests/fixtures/clean.yml`
- The agent can reach GitHub release assets for `taudit`.
- For hosted pools: the organization has available hosted minutes.
- For self-hosted pools: the target agent is online and can run `bash`.

Recommended pinned task inputs for the first live receipt:

- `task: Taudit@1`
- `version: 1.1.4`
- `platform: azure-devops`

## Queue and agent preflight

Before queueing the run, confirm:

1. The pipeline definition uses `azure-pipelines.taudit-task-smoke.yml`.
2. The selected pool is available.
3. If using `ubuntu-latest`, the organization still has hosted capacity.
4. If using a self-hosted pool, the agent is online and not paused.
5. The extension is installed in the same Azure DevOps organization as the
   pipeline.

If the run fails before any step starts, check these first:

- `no free minutes remaining`
- self-hosted queue offline
- extension not installed in the org

## Run procedure

1. Queue the smoke pipeline.
2. Watch the first `Taudit@1` step resolve the pinned `taudit` version.
3. Confirm the scan step writes:
   - `.artifacts/taudit-scan.json`
4. Confirm the authority graph step writes:
   - `.artifacts/taudit-authority.dot`
5. Confirm the exploit graph step writes:
   - `.artifacts/taudit-exploit.dot`
6. Confirm the verify step writes:
   - `.artifacts/taudit-verify.json`
7. Confirm the final artifact publish step runs.

## Expected task outputs

Each named `Taudit@1` step should set Azure DevOps output variables:

- `taudit.exitCode`
- `taudit.outcome`
- `taudit.reportPath`
- `taudit.findingsCount`
- `taudit.tauditVersion`

Expected `taudit.outcome` values:

- `pass` for exit code `0`
- `violations` for exit code `1`
- `config-error` for any other non-zero exit

For the current smoke lane:

- `tauditVerify.taudit.outcome` should be `pass` if the clean fixture and
  example policy still match.
- `tauditScan.taudit.outcome` may be `pass` or `violations` depending on the
  current repository pipeline findings; this is not the primary gate for the
  live receipt.

## Artifact verification

After the run completes, download or inspect the published pipeline artifact:

- artifact name: `taudit-task-smoke`

Verify that it contains:

- `taudit-scan.json`
- `taudit-authority.dot`
- `taudit-exploit.dot`
- `taudit-verify.json`

Minimum receipt checks inside the artifact:

- `taudit-scan.json` is valid JSON and contains a top-level findings payload.
- `taudit-verify.json` is valid JSON.
- both `.dot` files are non-empty text files.

## Common failure branches

### Extension resolution failure

Symptoms:

- Azure DevOps cannot find `Taudit@1`
- job fails before task execution

Checks:

- extension is installed into the org
- pipeline is running in the same org where the extension was installed

### Hosted pool capacity failure

Symptoms:

- run fails before agent allocation
- Azure reports no free minutes remaining

Checks:

- add hosted capacity, or
- switch to an online self-hosted agent

### Self-hosted queue unavailable

Symptoms:

- job remains queued
- Azure shows offline agent state

Checks:

- agent is online
- agent accepts the target pool demands

### Verify-mode configuration failure

Symptoms:

- `Taudit@1` exits with `config-error`

Checks:

- `policy` exists and is workspace-relative
- do not pass `$(System.DefaultWorkingDirectory)` for `policy`,
  `baselineRoot`, `paths`, or other path-like inputs
- `baselineRoot` stays repo-relative, for example `.` or `.taudit`

### Windows extraction failure

Symptoms:

- release asset downloads but extraction fails

Checks:

- PowerShell archive support is available, or
- `tar` is available, or
- rerun with `fallbackCargo=true`

### Artifact missing after a taudit failure

Symptoms:

- `Taudit@1` ran, but `.artifacts/` was not published

Checks:

- confirm the smoke lane still uses `condition: always()` on the artifact
  publish step
- inspect the job log for earlier workspace or output-path errors

## What to record as the live receipt

Capture these anchors for the final proof:

- Azure DevOps run URL
- pool and agent used
- resolved `taudit` version
- `tauditVerify.taudit.outcome`
- artifact name `taudit-task-smoke`
- artifact file list

That is enough to show one real `Taudit@1` execution receipt without mixing it
with broader marketplace or policy claims.
