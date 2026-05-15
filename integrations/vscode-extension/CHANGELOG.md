# Changelog

## 0.1.6

- Hardened request validation so workspace scans, verify policy paths, ignore
  files, suppressions files, and baseline roots cannot escape the active
  workspace via `..` or other out-of-workspace paths.
- Tightened settings validation at the extension boundary: `maxHops` must be a
  positive integer and `severityThreshold` must be one of the supported taudit
  severities before the CLI starts.
- In multi-root workspaces, workspace commands now prefer the active editor's
  workspace folder instead of blindly using the first root.
- Hardened artifact handling so failed runs do not leave `Show Output` pointing
  at a missing file; the extension now only opens artifacts that actually
  exist and tells the user when no artifact has been produced yet.

## 0.1.5

- Tightened Marketplace description, categories, keywords, and README first
  screen for CI/CD authority, graph, SARIF, and policy-search discoverability.
- Kept the extension positioning precise: a typed VS Code surface over a local
  `taudit` binary, not a bundled scanner or arbitrary shell wrapper.

## 0.1.2

- Added `taudit: Initialize Workspace Policy` to bootstrap a starter verify
  policy into the configured workspace path.
- Added a verify-time quick action to initialize the policy path when it does
  not exist.
- Documented a README golden path for first use.

## 0.1.1

- Replaced the Marketplace extension icon with the updated taudit icon asset.

## 0.1.0

- First Marketplace release of the taudit VS Code extension.
- Added explicit commands for workspace verify, workspace scan, active-file
  scan, authority graph, exploit graph, and output reveal.
- Added typed settings for policy, ignore, suppressions, baselines, platform,
  graph format, severity threshold, and run-on-save behavior.
- Added explicit config-error handling for missing taudit binary and missing
  verify policy paths.
- Added local extension-host integration smoke, deterministic VSIX install
  smoke, and an Azure hosted preflight/publish lane.
