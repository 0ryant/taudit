# taudit VS Code Extension

Audit GitHub Actions, Azure Pipelines, GitLab CI, and Bitbucket pipelines from
VS Code with policy gates, advisory findings, and authority or exploit graphs.

Use it when you want a local workflow for CI/CD policy review without writing
ad hoc shell commands.

What you get first:

- `Verify Workspace` to fail unsafe GitHub Actions or Azure Pipelines policy
  paths before merge.
- `Scan Workspace` and `Scan Active File` for advisory workflow findings and
  SARIF-ready output.
- Authority and exploit graph commands for local review of risky helper,
  secret, and mutable-state paths.
- Output and artifact views inside VS Code so you can inspect command results,
  graph files, and config errors without leaving the editor.

## Before you install

- Install `taudit` locally with `cargo install taudit --locked`.
- Prefer a known taudit release version in team docs and support runbooks; by
  default `cargo install` tracks the latest published crate.
- Keep `taudit` on `PATH`, or set `taudit.binaryPath`.
- `Verify Workspace` requires a repo-local policy path.
- Supported workflow platforms are GitHub Actions, Azure DevOps, GitLab CI, and
  Bitbucket Pipelines.

## Quick start

1. Install `taudit` locally with `cargo install taudit --locked`.
2. Open the repository you want to inspect in VS Code.
3. Set `taudit.verify.policyPath` to `.taudit/policy/`.
4. Run `taudit: Initialize Workspace Policy`.
5. Run `taudit: Verify Workspace`.
6. Open `taudit: Show Output` to inspect the result and any generated artifact.

If your repo uses a different pipeline root, also set `taudit.workflowPaths`
before running the workspace commands.

If the configured verify policy path does not exist yet, `Initialize Workspace
Policy` seeds it with a starter `bundled-strict-policy.yml` so `Verify
Workspace` can run immediately.

## Result surfaces

- `taudit` output channel for command results and validation errors
- workspace artifact files for graph output and JSON/SARIF exports
- config validation that fails early when the binary, policy, ignore file,
  suppressions file, or baseline root are misconfigured

## Trust model

- the extension runs a local `taudit` binary on your machine or dev container
- it does not expose raw shell or arbitrary argument passthrough
- it writes artifacts into the workspace so you can inspect graph and report output
- it does not embed its own taudit engine; local binary behavior controls the result
- if you need a fully pinned operator flow, install and manage a specific taudit
  CLI version in your team environment

## Required settings

- `taudit.verify.policyPath`
  Required policy file or directory for `taudit: Verify Workspace`.
- `taudit.binaryPath`
  Explicit path to the local `taudit` binary when it is not on `PATH`.
- `taudit.workflowPaths`
  Workspace-relative roots used by the workspace commands.

## Optional controls

- `taudit.platform`
  Default CI/CD platform for `scan`, `verify`, and `graph`.
- `taudit.controls.ignoreFile`
- `taudit.controls.suppressionsFile`
- `taudit.controls.suppressionMode`
- `taudit.controls.baselineRoot`

The extension validates explicit paths before it starts `taudit`. Missing
binary, missing policy, missing ignore file, missing suppressions file, or
missing baseline root are reported as configuration errors.

## Commands

- `taudit: Initialize Workspace Policy`
- `taudit: Verify Workspace`
- `taudit: Scan Workspace`
- `taudit: Scan Active File`
- `taudit: Graph Authority View`
- `taudit: Graph Exploit View`
- `taudit: Show Output`

## Scope

This extension is a workspace-side operator surface over a local `taudit`
binary for:

- `taudit verify`
- `taudit scan`
- `taudit graph --view authority`
- `taudit graph --view exploit`

It is not a vulnerability scanner, a generic YAML linter, or a shell wrapper
for arbitrary taudit flags.

## Local release preflight

From `integrations/vscode-extension/`:

```bash
npm ci
cargo build -p taudit
npm run preflight
```

`npm run preflight` runs unit checks, extension-host integration tests, VSIX
packaging, and isolated VSIX install/uninstall smoke against a downloaded
stable VS Code runtime.
