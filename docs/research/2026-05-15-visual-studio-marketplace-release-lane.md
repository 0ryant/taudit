# Visual Studio Marketplace Release/Test Lane

Date: 2026-05-15
Scope: release and test sequence for a future `taudit` VS Code extension
published to Visual Studio Marketplace under publisher `algol`.

Status: lane definition plus initial local evidence. The repository now
contains an in-tree extension scaffold at `integrations/vscode-extension/`,
local `npm run check` passed, `npm run test:integration` passed,
`vsce package` passed, `npm run smoke:vsix` passed, and `npm run preflight`
passed.
Marketplace PAT evidence and hosted smoke are still missing.

## Inputs

- Product track:
  [`2026-05-15-visual-studio-marketplace-publish-track.md`](2026-05-15-visual-studio-marketplace-publish-track.md)
- Prior Marketplace tranche:
  [`2026-05-14-marketplace-publish-supervised-tranche.md`](2026-05-14-marketplace-publish-supervised-tranche.md)
- Contract pattern:
  [`../integrations/github-marketplace-action-contract.md`](../integrations/github-marketplace-action-contract.md)

## Release Principle

The VS Code extension is a separate Marketplace product. Do not publish it from
taudit CLI metadata alone. A release is eligible only when the extension
manifest, packaged VSIX, local install smoke, hosted smoke, PAT handling, and
rollback path all have direct evidence.

## Required Evidence Gates

Each gate must pass in order. If a gate fails, stop the lane, record the failed
command or hosted run, and do not publish.

1. **Repository shape gate**
   - Confirm the extension artifact exists in the intended in-repo location.
   - Confirm the extension root has `package.json`, `README.md`,
     `CHANGELOG.md`, `LICENSE`, icon asset, `.vscodeignore`, extension
     entrypoint, and tests.
   - Confirm `package.json` includes `name`, `displayName`,
     `publisher: "algol"`, `version`, `engines.vscode`, `description`,
     `categories`, `license`, contributed commands, contributed settings, and
     activation events.
   - Confirm no v1 setting exposes raw `extraArgs`, `shell`, command
     passthrough, or ambiguous config-path shortcuts.

2. **Local dependency/build gate**
   - From the extension root, install dependencies with the locked package
     manager command selected by the extension scaffold.
   - Run the extension build script.
   - Run static checks for manifest/settings schema and command contribution
     registration.
   - Run unit tests for argv construction, workspace path normalization, secret
     redaction, missing binary errors, and missing policy/control-path errors.

3. **Local VS Code integration gate**
   - Run `@vscode/test-electron` or the selected equivalent against the
     packaged extension code.
   - Cover activation plus these commands:
     `taudit.verifyWorkspace`, `taudit.scanWorkspace`, `taudit.scanFile`,
     `taudit.graphAuthority`, `taudit.graphExploit`, and `taudit.showOutput`.
   - Cover missing `taudit` binary failure behavior.
   - Cover missing verify policy failure behavior before any `taudit verify`
     child process is launched.

4. **Local package gate**
   - Run `npx @vscode/vsce package` or the pinned equivalent.
   - Inspect the produced `.vsix` file contents.
   - Confirm `.vscodeignore` excludes source-only, test-only, secret, and
     temporary files while retaining runtime dependencies.
   - Confirm Marketplace metadata hygiene:
     no user-provided SVG icon, no non-HTTPS images, no untrusted SVG images in
     README or CHANGELOG, and no secret-like values in packaged files.

5. **Local install smoke gate**
  - Install the produced `.vsix` into a supported local VS Code client with
    the repository smoke path (`npm run smoke:vsix`) or an equivalent
    `code --install-extension <vsix> --force` flow.
   - Open a fixture workspace containing representative GitHub Actions workflow
     files and taudit controls.
   - Run command activation and at least one advisory `scan`, one `verify`
     config-error case, and one `graph` generation case.
   - Capture the extension identifier, installed version, command results, and
     uninstall command evidence.

6. **PAT handling gate**
   - Create or rotate an Azure DevOps PAT scoped only to Marketplace `Manage`
     for publisher `algol`.
   - Store it as `VSCE_PAT` in the selected CI secret store or local secret
     manager; do not commit it, echo it, or place it in command arguments.
   - Verify auth with `vsce login algol` for interactive local setup or
     noninteractive `VSCE_PAT` execution in CI.
   - Confirm normal and failed publish-preflight logs do not contain the PAT or
     token-like substrings.
   - If a broader PAT scope is proposed, stop and record the exception before
     proceeding.

7. **Hosted preflight gate**
   - Prefer Azure Pipelines for the first hosted lane while GitHub-hosted runner
     capacity is blocked by billing/spending-limit state.
   - Use the dedicated Azure YAML lane at
     [`../../azure-pipelines.vscode-extension.yml`](../../azure-pipelines.vscode-extension.yml)
     for hosted preflight and gated `VSCE_PAT` publish.
   - Hosted preflight must run on a clean checkout and perform:
     dependency install, build, unit tests, extension integration tests, VSIX
     packaging, package content inspection, and install/activation smoke.
   - Publish jobs must require the hosted preflight artifact digest or run id.
   - A hosted job that fails before runner execution does not satisfy this gate.

8. **Version/tag gate**
   - Decide whether the extension version mirrors the taudit CLI version or
     follows independent SemVer before tagging.
   - Confirm the manifest version equals the intended Marketplace version.
   - Create the release tag only after local and hosted evidence gates pass.
   - Do not reuse a failed published Marketplace version. If publish partially
     succeeds and then fails, recover with a new extension version.

9. **Publish gate**
   - Publish either with `vsce publish` using `VSCE_PAT` or by uploading the
     already-inspected `.vsix` through the Marketplace UI.
   - Use the exact VSIX artifact that passed hosted preflight, or rerun all
     package and smoke gates if a new artifact is generated.
   - Record command, artifact path, artifact digest, version, publisher,
     extension identifier, and Marketplace response.

10. **Post-publish verification gate**
    - Verify the Marketplace page renders under publisher `algol`.
    - Verify README assets load and do not violate Marketplace image rules.
    - Install from Marketplace into a fresh VS Code profile.
    - Run activation, one command smoke, upgrade behavior if replacing a prior
      version, and uninstall behavior.
    - Record listing URL, installed extension identifier, installed version,
      command result, and uninstall result.

## Deterministic Command Skeleton

Current scaffold values:

- extension root: `integrations/vscode-extension`
- extension identifier: `algol.taudit-vscode`
- current manifest version: `0.0.1`
- current VSIX name: `taudit-vscode.vsix`

```bash
cd /Users/rytilcock/prj/taudit/integrations/vscode-extension
git status --short --branch
npm ci
npm run check
cargo build -p taudit
npm run test:integration
npx @vscode/vsce package
npm run smoke:vsix
# or the one-shot local lane:
npm run preflight
```

For CI publish, prefer a two-job shape:

1. `preflight`: build, test, package, inspect, install smoke, upload VSIX
   artifact and digest.
2. `publish`: requires `preflight`, downloads the exact artifact, verifies the
   digest, then runs `npx @vscode/vsce publish --packagePath <vsix>` with
   `VSCE_PAT` provided only as a secret environment variable.

## Smoke Fixture Matrix

Use fixtures that make each result deterministic:

- `clean-workspace`: valid workflow plus policy that produces `verify` exit
  `0`.
- `violating-workspace`: workflow/policy pair that produces `verify` exit `1`.
- `missing-policy`: `verify` configured without policy; extension fails before
  invoking taudit.
- `missing-binary`: configured `taudit.binaryPath` does not exist; extension
  reports missing binary.
- `graph-workspace`: authority and exploit graph commands both produce files.
- `secret-redaction`: settings or output fixture with token-like values;
  output channel, notifications, logs, and artifacts must not reveal them.

## Rollback And Recovery

- If local or hosted preflight fails, do not tag or publish. Fix forward and
  rerun the full lane.
- If publish fails before the Marketplace accepts the version, keep the same
  version only if Marketplace confirms no release object was created.
- If Marketplace accepts the version but post-publish verification fails, do
  not overwrite that version. Prepare a new patch version with the fix.
- If the published extension is unsafe or materially broken, unpublish or hide
  the extension version through Marketplace controls if available, revoke or
  rotate `VSCE_PAT`, and publish a fixed new version after the full lane passes.
- Always record the failed version, failed artifact digest, Marketplace state,
  and the exact recovery decision.

## Stop Conditions

- No extension artifact exists in-tree.
- Manifest publisher is not `algol`.
- Required Marketplace PAT is missing, over-scoped without exception, or appears
  in logs.
- Local VSIX install smoke has not run.
- Hosted preflight has not reached runner execution and completed.
- Package inspection finds secret-like values or Marketplace-disallowed assets.
- Post-publish Marketplace install cannot be verified.

## Current Blockers

- No Marketplace PAT evidence is recorded.
- No hosted VSIX install/activation smoke path is recorded.
- GitHub-hosted runner smoke is currently not a reliable first lane because the
  prior Marketplace tranche observed a billing/spending-limit blocker before
  runner execution.
