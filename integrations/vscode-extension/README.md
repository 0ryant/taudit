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

## Scope

This extension is a workspace-side operator surface for:

- `taudit verify`
- `taudit scan`
- `taudit graph --view authority`
- `taudit graph --view exploit`

It is not a vulnerability scanner, a generic YAML linter, or a shell wrapper
for arbitrary taudit flags.
