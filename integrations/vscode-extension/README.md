# taudit VS Code Extension

This extension runs the local `taudit` CLI from VS Code with an explicit,
typed command surface.

Current commands:

- `taudit: Verify Workspace`
- `taudit: Scan Workspace`
- `taudit: Scan Active File`
- `taudit: Graph Authority View`
- `taudit: Graph Exploit View`
- `taudit: Show Output`

The extension does not embed taudit and does not expose raw argument
passthrough. It invokes a locally available `taudit` binary and maps VS Code
settings onto the supported CLI surface.

## Minimum setup

1. Install `taudit` locally and make it available on `PATH`, or set
   `taudit.binaryPath`.
2. Set `taudit.verify.policyPath` to a valid policy file or directory.
3. Optionally configure ignore, suppressions, and baseline controls through the
   `taudit.controls.*` settings.

## Settings that matter

- `taudit.binaryPath`
  Explicit path to the local `taudit` binary when it is not on `PATH`.
- `taudit.platform`
  Default CI/CD platform for `scan`, `verify`, and `graph`.
- `taudit.workflowPaths`
  Workspace-relative roots used by the workspace commands.
- `taudit.verify.policyPath`
  Required policy file or directory for `taudit: Verify Workspace`.
- `taudit.controls.ignoreFile`
- `taudit.controls.suppressionsFile`
- `taudit.controls.suppressionMode`
- `taudit.controls.baselineRoot`

The extension validates explicit paths before it starts `taudit`. Missing
binary, missing policy, missing ignore file, missing suppressions file, or
missing baseline root are reported as configuration errors.

## Scope

This extension is a workspace-side operator surface for:

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
