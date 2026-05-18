# Dogfood self-audit patterns

Use these patterns when a repo runs taudit against the same CI surface that
executes taudit. The taudit step is part of the authority graph and is not
self-exempt. If a dogfood lane should be visible but non-blocking, make that
choice explicit with policy, baselines, suppressions, and CI wiring.

## Shared controls

Commit these controls before adding an advisory dogfood lane:

```bash
# 1. Keep policy separate from waivers and baselines.
mkdir -p .taudit/policy

# 2. Snapshot known findings once per pipeline.
taudit baseline init .github/workflows/ --root .
taudit baseline init azure-pipelines.yml --platform azure-devops --root .

# 3. Add reviewed waivers by fingerprint or suppression_key.
taudit suppressions add \
  --fingerprint 5edb30f4db3b5fa3d7fe7289374b7155 \
  --rule-id untrusted_with_authority \
  --reason "Dogfood taudit lane reviewed by platform security; advisory only." \
  --accepted-by platform-security@example.com \
  --expires-at 2026-08-01

git add .taudit/policy/ .taudit/baselines/ .taudit-suppressions.yml
```

Do not put dogfood exceptions in the policy directory. Policy says what must be
true. Baselines and suppressions say which known findings are accepted and who
accepted them.

## GitHub Actions advisory dogfood

This job records findings from `.github/workflows/`, applies the committed
baseline and suppression file, uploads the SARIF/JSON evidence, and does not
block merges. Keep it out of branch-protection required checks unless the
intent changes from advisory to gate.

```yaml
name: taudit dogfood advisory

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  self-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<FULL_SHA>

      - name: Prepare taudit evidence directory
        run: mkdir -p .artifacts

      - name: Run taudit dogfood verify
        id: taudit
        uses: 0ryant/taudit-action@v1
        continue-on-error: true
        with:
          mode: verify
          version: 1.1.5
          paths: |
            .github/workflows/
          policy: .taudit/policy/
          include-builtin: true
          baseline-root: .
          suppressions: .taudit-suppressions.yml
          suppression-mode: downgrade
          severity-threshold: high
          format: sarif
          output: .artifacts/taudit-dogfood.sarif

      - name: Keep machine-readable evidence
        if: always()
        uses: actions/upload-artifact@<FULL_SHA>
        with:
          name: taudit-dogfood
          path: .artifacts/taudit-dogfood.sarif
          if-no-files-found: warn

      - name: Show advisory outcome
        if: always()
        run: |
          echo "taudit outcome: ${{ steps.taudit.outputs.outcome }}"
          echo "taudit exit code: ${{ steps.taudit.outputs['exit-code'] }}"
```

Use `suppression-mode: downgrade` when a reviewed waiver should affect
`severity-threshold`. Use `suppression-mode: tag-only` when dashboards should
see the waiver metadata but the finding should retain its original severity.

## Azure DevOps advisory dogfood

`Taudit@1` is also part of the ADO pipeline graph. This pattern runs `verify`
with the same explicit controls, marks the task non-blocking with
`continueOnError`, and publishes the JSON report for review.

```yaml
trigger:
  branches:
    include:
      - main

pr:
  branches:
    include:
      - main

pool:
  vmImage: ubuntu-latest

steps:
  - checkout: self
    fetchDepth: 0

  - bash: mkdir -p .artifacts
    displayName: Prepare taudit evidence directory

  - task: Taudit@1
    name: tauditDogfood
    displayName: Taudit dogfood advisory verify
    continueOnError: true
    inputs:
      mode: verify
      version: 1.1.5
      platform: azure-devops
      paths: |
        azure-pipelines.yml
      policy: .taudit/policy/
      includeBuiltin: true
      baselineRoot: .
      suppressions: .taudit-suppressions.yml
      suppressionMode: downgrade
      severityThreshold: high
      format: json
      output: .artifacts/taudit-dogfood.json

  - bash: |
      set -euo pipefail
      echo "taudit outcome: $(tauditDogfood.taudit.outcome)"
      echo "taudit exit code: $(tauditDogfood.taudit.exitCode)"
      echo "taudit findings: $(tauditDogfood.taudit.findingsCount)"
      ls -la .artifacts
    displayName: Show taudit advisory outcome
    condition: always()

  - task: PublishPipelineArtifact@1
    displayName: Publish taudit dogfood report
    condition: always()
    inputs:
      targetPath: .artifacts
      artifact: taudit-dogfood
```

For ADO-aware scans that use `adoOrg`, `adoProject`, and `adoPat`, treat the
baseline as a snapshot of both YAML and live variable-group state. Re-run
`taudit baseline init azure-pipelines.yml --platform azure-devops --root .`
after intentional variable-group membership changes.

## Operator checks

Run these before marking a dogfood lane healthy:

```bash
taudit baseline review --root .
taudit suppressions review
taudit verify \
  --policy .taudit/policy/ \
  --include-builtin \
  --baseline-root . \
  --suppressions .taudit-suppressions.yml \
  --suppression-mode downgrade \
  --severity-threshold high \
  .github/workflows/
```

Expected result: known accepted findings remain visible in JSON/SARIF with
baseline or suppression metadata; new High/Critical findings still appear in
the advisory report; the CI lane remains non-blocking only because the workflow
or pipeline explicitly marks it that way.
