# VS Code Extension Operator Guide

Status: implementation guide for the in-repo `taudit` VS Code extension under
`integrations/vscode-extension/`. This guide documents the current operator
surface and release-preflight path. It does not claim that the extension has
already been published to Visual Studio Marketplace.

## What The Extension Is

The extension is a typed VS Code adapter over the local `taudit` CLI.

It does three things:

- runs `taudit verify` for policy gates
- runs `taudit scan` for advisory findings
- runs `taudit graph` for authority and exploit-candidate views

It does not embed taudit, does not edit your pipelines, and does not expose
raw argument passthrough.

## Operator Secret Posture

Local operator flows for Marketplace publish or share must use `tsafe`.

- Use `tsafe exec` for local `vsce` / `tfx-cli` publish or share commands.
- Do not paste PATs into shell history.
- Do not pass PATs on command lines.
- For hosted CI lanes, a CI secret variable is the allowed exception because
  `tsafe` is a local operator tool, not a hosted runner dependency.

## Commands

The current command surface is:

- `taudit: Verify Workspace`
- `taudit: Scan Workspace`
- `taudit: Scan Active File`
- `taudit: Graph Authority View`
- `taudit: Graph Exploit View`
- `taudit: Show Output`

## Default Posture

Recommended workspace posture:

```json
{
  "taudit.binaryPath": "taudit",
  "taudit.platform": "auto",
  "taudit.workflowPaths": [".github/workflows/"],
  "taudit.verify.policyPath": ".taudit/policy/",
  "taudit.verify.includeBuiltin": false,
  "taudit.verify.ignorePartial": false,
  "taudit.verify.format": "json",
  "taudit.scan.format": "json",
  "taudit.graph.format": "mermaid",
  "taudit.controls.suppressionMode": "downgrade",
  "taudit.runOnSave": false
}
```

For GitHub Actions-heavy repos, that keeps `verify` policy-first and keeps
`scan` advisory.

## Control Mapping

The extension keeps these controls separate on purpose.

### Policy

`taudit.verify.policyPath`

- Required for `taudit: Verify Workspace`
- Maps to `taudit verify --policy <path>`
- Defines invariant bundles used for gate decisions

If the configured policy path does not exist, the extension fails before it
starts `taudit`.

### Ignore File

`taudit.controls.ignoreFile`

- Optional
- Maps to `--ignore-file`
- Removes paths or findings before rule evaluation

Ignore rules are not suppressions.

### Suppressions

`taudit.controls.suppressionsFile`
`taudit.controls.suppressionMode`

- Optional
- Map to `--suppressions` and `--suppression-mode`
- Used to waive or tag specific findings

`downgrade` changes how matched findings affect severity and gating.

`tag-only` preserves the finding and adds suppression metadata without using
that suppression to clear the result by itself.

### Baselines

`taudit.controls.baselineRoot`

- Optional
- Maps to `--baseline-root`
- Points at the root containing `.taudit/baselines/`

Baselines are not policy and not suppressions. They are used to distinguish
new findings from accepted pre-existing ones where the CLI supports that mode.

## Verify vs Scan vs Graph

### Verify

Use `taudit: Verify Workspace` when you want a policy gate.

- exit `0`: pass
- exit `1`: policy violations
- exit `2` or startup failure: configuration/runtime error

This is the merge-gate/editor-gate mode.

### Scan

Use `taudit: Scan Workspace` or `taudit: Scan Active File` when you want
advisory findings without policy gating.

This is the discovery/triage mode.

### Graph

Use graph views when you need structure, not just findings.

- `Graph Authority View`: where authority materializes and crosses boundaries
- `Graph Exploit View`: where mutable state can influence later
  authority-bearing execution

The extension stores the graph artifact and opens it in the editor.

## Local Release Preflight

From `integrations/vscode-extension/`:

```bash
npm ci
cargo build -p taudit
npm run preflight
```

`npm run preflight` runs:

- unit checks
- extension-host integration tests
- VSIX packaging
- isolated VSIX install/uninstall smoke against a downloaded stable VS Code
  runtime

## Azure Hosted Preflight

The hosted lane is:

- [`azure-pipelines.vscode-extension.yml`](../../azure-pipelines.vscode-extension.yml)

It currently:

- installs Node
- installs Rust
- builds `taudit`
- runs `npm ci`
- runs `npm run check`
- runs `xvfb-run -a npm run test:integration`
- runs `npm run package:vsix`
- runs `npm run smoke:vsix`
- publishes the VSIX and checksum as pipeline artifacts
- exposes a gated publish stage that requires `VSCE_PAT`

For local manual publish, use `tsafe` rather than exporting `VSCE_PAT`
directly in the shell.

## What Is Still CLI-Only

Current extension scope does not replace the full CLI surface.

Still CLI-first:

- ad hoc taudit subcommands not covered by the command palette
- custom output routing beyond the extension artifact/result path
- any future provider-specific auth/enrichment flags not yet modeled in the
  settings contract
- direct automation of SARIF upload or CI mutation

## Release Blockers

The remaining blockers are operational, not product-shape:

- the Marketplace PAT principal currently lacks publish rights on publisher
  `Algol`
- no successful Azure hosted preflight run is recorded yet

## Related

- [`visual-studio-marketplace-extension-contract.md`](visual-studio-marketplace-extension-contract.md)
- [`../research/2026-05-15-visual-studio-marketplace-publish-track.md`](../research/2026-05-15-visual-studio-marketplace-publish-track.md)
- [`../research/2026-05-15-visual-studio-marketplace-release-lane.md`](../research/2026-05-15-visual-studio-marketplace-release-lane.md)
