# taudit VS Code Extension

Verify CI/CD pipeline authority from VS Code. The taudit extension runs your
local `taudit` CLI through typed commands for `verify`, `scan`, and
authority/exploit graph generation.

Use it when you want editor-side checks for GitHub Actions, Azure DevOps,
GitLab CI, or Bitbucket Pipelines without writing ad hoc shell commands.

What it gives you:

- `Verify Workspace` for policy-backed CI/CD authority checks.
- `Scan Workspace` and `Scan Active File` for advisory findings.
- Authority and exploit graph commands for local graph inspection.
- Explicit settings for policy, ignore files, suppressions, baselines,
  platform, graph format, and severity threshold.

The extension does not embed taudit. Install `taudit` locally, keep it on
`PATH`, or set `taudit.binaryPath`.

Current commands:

- `taudit: Initialize Workspace Policy`
- `taudit: Verify Workspace`
- `taudit: Scan Workspace`
- `taudit: Scan Active File`
- `taudit: Graph Authority View`
- `taudit: Graph Exploit View`
- `taudit: Show Output`

The extension does not embed taudit and does not expose raw argument
passthrough. It invokes a locally available `taudit` binary and maps VS Code
settings onto the supported CLI surface.

## Golden path

1. Install `taudit` locally with `cargo install taudit --locked`, then make it
   available on `PATH`, or set `taudit.binaryPath`.
2. Open the repository you want to inspect in VS Code.
3. Set `taudit.verify.policyPath` to `.taudit/policy/`.
4. Open the Command Palette and run `taudit: Initialize Workspace Policy`.
5. Review or edit the generated
   `.taudit/policy/bundled-strict-policy.yml`.
6. Run `taudit: Verify Workspace`.
7. Open `taudit: Show Output` to inspect the artifact and command output.

If your repo uses a different pipeline root, also set `taudit.workflowPaths`
before running the workspace commands.

## Minimum setup

1. Install `taudit` locally with `cargo install taudit --locked`, then make it
   available on `PATH`, or set `taudit.binaryPath`.
2. Set `taudit.verify.policyPath` to a valid policy file or directory.
3. Optionally configure ignore, suppressions, and baseline controls through the
   `taudit.controls.*` settings.

If the configured verify policy path does not exist yet, run
`taudit: Initialize Workspace Policy`. The extension seeds the configured path
with a starter `bundled-strict-policy.yml` file so `Verify Workspace` can run
immediately.

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
