# Visual Studio Marketplace Publish Track

Date: 2026-05-15
Scope: first publish path for a future `taudit` VS Code extension under the
Visual Studio Marketplace publisher `algol`.

## Source Of Truth

- Official publish flow: VS Code extensions are packaged and published with
  `@vscode/vsce`; publishing requires a Visual Studio Marketplace publisher and
  an Azure DevOps PAT with Marketplace `Manage` scope.
- Required manifest contract: every extension needs a root `package.json` with
  at least `name`, `version`, `publisher`, and `engines.vscode`.
- Packaging/publish hygiene: Marketplace rejects user-provided SVG icons and
  non-HTTPS / untrusted SVG images in `README.md` / `CHANGELOG.md`.
- CI guidance: `VSCE_PAT` is the expected secret for automated publish; Azure
  Pipelines is the reference multi-OS extension test runner and GitHub Actions
  is also supported when runner capacity exists.
- Canonical references:
  - <https://code.visualstudio.com/api/working-with-extensions/publishing-extension>
  - <https://code.visualstudio.com/api/working-with-extensions/continuous-integration>
  - <https://code.visualstudio.com/api/references/extension-manifest>

## Current State

- [x] V1: Publisher exists: `algol`.
- [x] V2: Extension package exists in this repo at
  `integrations/vscode-extension/`.
- [x] V4: Extension release automation exists.
- [x] V5: Hosted smoke path exists for packaged VSIX install and activation.
- [ ] V3: Marketplace auth token is provisioned and verified.

## Observed Evidence

- `integrations/vscode-extension/` now exists with:
  `package.json`, `README.md`, `CHANGELOG.md`, `LICENSE`,
  `.vscodeignore`, `.gitignore`, `tsconfig.json`, `assets/icon.png`,
  extension source, tests, and `package-lock.json`.
- Hosted lane exists at:
  `azure-pipelines.vscode-extension.yml`
- Local extension checks passed:
  `npm run check`
- Local extension-host smoke passed:
  `npm run test:integration`
- Local VSIX package passed:
  `npm run package:vsix`
- Local VSIX install smoke passed:
  `npm run smoke:vsix`
- Local full extension preflight passed:
  `npm run preflight`

## Non-Negotiable Constraints

- Do not claim a Marketplace publish path is ready until a real VS Code
  extension artifact exists in-tree.
- Do not publish directly from taudit CLI metadata; the Marketplace object is a
  separate extension product with its own manifest, versioning, and UX.
- Do not create a publisher PAT with broader Azure DevOps scope than
  Marketplace `Manage` unless a documented exception is accepted.
- Do not ship README / CHANGELOG / icon assets that violate VS Marketplace
  image rules.
- Do not publish the first extension release without at least one real VSIX
  install smoke on a supported VS Code client.

## Proposed v1 Product Contract

This should not start as a generic shell wrapper with arbitrary args. The
extension should expose the stable taudit operator surface directly.

### Commands

- `taudit.verifyWorkspace`
  Run `taudit verify` against the configured workflow roots and policy path.
- `taudit.scanWorkspace`
  Run `taudit scan` for advisory findings and open the result.
- `taudit.scanFile`
  Run taudit against the active pipeline file when the current editor target is
  a supported CI/CD file.
- `taudit.graphAuthority`
  Generate the authority graph for the active workspace selection.
- `taudit.graphExploit`
  Generate the exploit-candidate graph for the active workspace selection.
- `taudit.showOutput`
  Focus the taudit output channel and the most recent JSON / SARIF / graph
  artifact produced by the extension.

### Settings contract

- `taudit.binaryPath`
- `taudit.platform`
- `taudit.workflowPaths`
- `taudit.verify.policyPath`
- `taudit.verify.includeBuiltin`
- `taudit.verify.ignorePartial`
- `taudit.verify.format`
- `taudit.scan.format`
- `taudit.controls.ignoreFile`
- `taudit.controls.suppressionsFile`
- `taudit.controls.suppressionMode`
- `taudit.controls.baselineRoot`
- `taudit.graph.format`
- `taudit.maxHops`
- `taudit.severityThreshold`
- `taudit.runOnSave`

Rules:

- No raw `extraArgs`, `shell`, or arbitrary command passthrough in v1.
- Paths must resolve inside the workspace unless an explicit exception is
  designed and documented.
- The extension must distinguish policy, ignore-file, suppressions, and
  baselines as separate controls; one path must not ambiguously stand in for
  the others.

### v1 result surfaces

- Command success/failure with preserved taudit exit semantics.
- Machine-readable artifacts written to the workspace or extension storage:
  JSON, SARIF, DOT, Mermaid, or summary output as selected.
- Clear error states for missing `taudit` binary, missing policy, invalid
  suppressions path, and unsupported platform/mode combinations.

## Tasks

- [ ] V10: Ratify the extension product contract.
  Required decision:
  first-class command/settings surface for `scan`, `verify`, `graph`,
  controls (`policy`, ignore, suppressions, baselines), and result rendering.

- [ ] V11: Define the extension runtime boundary.
  Required decision:
  `extensionKind`, activation model, local binary invocation model, settings
  surface, and whether the extension must support remote workspaces or web.

- [x] V12: Create the extension scaffold in-repo.
  Required files:
  root `package.json`, `README.md`, `CHANGELOG.md`, extension entrypoint,
  `LICENSE`, icon asset, and `.vscodeignore`.

- [x] V13: Populate the manifest with required Marketplace fields.
  Required fields:
  `name`, `displayName`, `publisher=algol`, `version`, `engines.vscode`,
  `description`, `categories`, `license`, and extension entrypoint fields.

- [x] V14: Encode the extension settings schema and command registrations.
  Required:
  `package.json` contributes commands, settings, activation events, and any
  view/webview points for the v1 product contract.

- [x] V15: Add package/build scripts.
  Minimum scripts:
  local build, local test, `vscode:prepublish`, `vsce package`, and
  deterministic packaging verification.

- [x] V16: Implement the minimum user-visible feature set for v1.
  Required floor:
  run `taudit verify`, `scan`, and `graph`; support both authority and exploit
  graph views; surface JSON/SARIF results; and expose clear error states when
  the `taudit` binary or required control paths are missing.

- [x] V17: Add extension tests.
  Minimum:
  manifest/schema checks, command activation tests, and at least one
  `@vscode/test-electron` integration smoke covering each contributed command
  plus missing-binary failure behavior.

- [x] V18: Add local VSIX packaging smoke.
  Required checks:
  `vsce package`, inspect produced `.vsix`, and install smoke with
  `code --install-extension` or equivalent supported client.
  Also review package contents, dependency inclusion, and Marketplace metadata
  hygiene before publish.

- [ ] V19: Provision Marketplace auth for publisher `algol`.
  Required:
  Azure DevOps PAT with Marketplace `Manage` scope, stored in secret
  management, and verified with `vsce login algol` or equivalent noninteractive
  `VSCE_PAT` flow.

- [x] V20: Decide release versioning semantics.
  Required decision:
  whether the extension version mirrors `taudit` CLI versions or follows its
  own cadence, plus pre-release policy.

- [x] V21: Add release automation.
  Preferred path:
  Azure Pipelines publish lane using `VSCE_PAT`, because the current GitHub
  Actions account is blocked on billing/runners.

- [ ] V22: Add hosted publish-preflight smoke.
  Minimum:
  hosted package build, hosted extension test, and hosted VSIX install / basic
  activation before first publish.

- [ ] V23: Publish the first private or stable extension release.
  Choose one:
  `vsce publish` directly or `vsce package` plus manual Marketplace upload.

- [ ] V24: Verify the Marketplace listing after publish.
  Required checks:
  extension page renders correctly, README assets load, install succeeds from
  Marketplace, extension identifier is stable, and uninstall/upgrade behavior
  is sane.

- [ ] V25: Document the operator path in taudit docs.
  Required docs:
  local development, packaging, publish flow, secrets handling, and rollback /
  unpublish rules.

- [ ] V26: Add an operator adoption guide specific to the extension UX.
  Required docs:
  how `policy`, `.tauditignore`, suppressions, and baselines map into the
  extension settings and commands; what `verify` vs `scan` vs `graph` mean in
  the editor; and what is still CLI-only.

## Recommended Order

1. V10-V16: ratify the product contract and make the extension real.
2. V17-V18: make tests, packaging, and local install reliable.
3. V19-V22: add auth and hosted release validation.
4. V23-V26: publish and document the operational path.

## Known Blockers

- Marketplace PAT transport now exists via tsafe, but the PAT principal lacks
  publish rights on publisher `Algol`.
- The Azure hosted preflight lane exists, but no successful hosted run is
  recorded yet.
- GitHub-hosted smoke is currently blocked on account billing / spending-limit
  issues, so the publish lane should prefer Azure Pipelines or another working
  hosted environment for the first real smoke.

## Versioning Decision

- The extension follows independent SemVer from the `taudit` CLI.
- First publish target: `0.1.0`.
- Minor versions can add typed commands/settings.
- Patch versions are for packaging, docs, and bug fixes that preserve the
  public command/settings contract.
