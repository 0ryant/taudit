# Changelog

## 0.1.11

- Updated the bundled task runtime: `azure-pipelines-task-lib` 5.2.1 -> 5.279.0,
  which moves `adm-zip` to 0.6.0 and clears two HIGH advisories (crafted-ZIP
  memory exhaustion, and symlink-following extraction allowing arbitrary file
  overwrite) that were bundled inside the published 0.1.10 VSIX.
  `brace-expansion` 1.1.14 -> 1.1.18 clears three more. Both were in-range
  updates; the task's 16 unit tests pass unchanged.
- Bumped the task contract version to 1.0.7.

## 0.1.10

- Moved the default pinned `version` from taudit 1.1.4 to 1.3.3 so a task
  without an explicit `version` input downloads the current stable CLI
  (BLAKE3 fingerprints, signed receipts, platform-native remediations).
  Pin `version` explicitly if you need to stay on 1.1.4 while re-baselining.
- Bumped the task contract version to 1.0.6.

## 0.1.9

- Refreshed the Azure DevOps README and Marketplace overview to match the
  current task contract, especially the workspace-absolute compatibility
  normalization for `policy`, `ignoreFile`, `suppressions`, and
  `baselineRoot`.
- Added the in-repo Azure DevOps extension changelog so package history is
  inspectable alongside the task source.

## 0.1.8

- Fixed the Azure DevOps relative-path coercion bug by treating `policy`,
  `ignoreFile`, `suppressions`, and `baselineRoot` as string inputs instead of
  `filePath` inputs, then normalizing workspace-absolute compatibility values
  back to repo-relative paths inside the checked-out workspace.
- Stopped `graph` mode from validating or being poisoned by stray `policy`
  values.
- Preserved explicit repo-relative values such as `baselineRoot: "."` while
  still rejecting absolute paths outside the checked-out workspace.

## 0.1.7

- Hardened Windows release extraction by trying explicit PowerShell archive
  import, then `tar`, and pointing operators directly at `fallbackCargo=true`
  when both extraction paths are unavailable.
- Added early validation for Azure DevOps macro and absolute path misuse on
  workspace-relative controls such as `baselineRoot`.

## 0.1.6

- Tightened Marketplace listing copy, tags, and overview positioning for Azure
  Pipelines adoption and CI/CD policy-search discoverability.

## 0.1.5

- Corrected Marketplace-facing repository and documentation links to
  `https://github.com/0ryant/taudit`.
- Repackaged the extension icon and overview asset paths for a stable public
  listing.

## 0.1.0

- First Azure DevOps Marketplace release of `Taudit@1`.
- Added typed `verify`, `scan`, and `graph` task modes with explicit policy,
  suppressions, baseline, and graph controls.
- Added local packaging, smoke, and task-runtime verification.
