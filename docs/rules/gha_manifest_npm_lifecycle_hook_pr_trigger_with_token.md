# GHA Manifest npm-Family Lifecycle Hook On PR Trigger With Token

**Rule ID:** `gha_manifest_npm_lifecycle_hook_pr_trigger_with_token`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, supply-chain, manifest-as-code, github-actions

## Detection

Fires when a workflow's `on:` block includes `pull_request` or `pull_request_target`, AND a step in any job runs `npm install`, `npm ci`, `pnpm install`, `yarn install`, `yarn`, or any other package-manager invocation that triggers lifecycle hooks (without `--ignore-scripts`), AND the same job has any of:

- `${{ secrets.* }}` references in env or `with:`;
- the default `GITHUB_TOKEN` with write scope (no `permissions:` strip to read-only);
- `id-token: write` permission;
- registry tokens (`NPM_TOKEN`, `NODE_AUTH_TOKEN`);
- cloud or OIDC credentials.

## Risk

`package.json` defines `scripts.preinstall`, `scripts.install`, `scripts.postinstall`, `scripts.prepare`, `scripts.prepublish`, `scripts.prepublishOnly`, `scripts.prepack`, `scripts.postpack` — every one of these runs as shell when the package manager is invoked. `npm ci` runs scripts by default. `pnpm install` and `yarn install` likewise.

The `package.json` (and `package-lock.json`/`pnpm-lock.yaml`/`yarn.lock` for transitive deps) is whatever the PR head says. A PR that adds a `postinstall: "node ./pwn.js"` field — or modifies a transitive dep in the lockfile to a new version that has a malicious `postinstall` — runs PR-author code with the CI step's full env, including any secrets, the `GITHUB_TOKEN`, and any minted OIDC ready for cloud use.

Empirically, in the public corpus only ~2.2% of npm-family install invocations pass `--ignore-scripts`. The default is unsafe.

## Remediation

Pass `--ignore-scripts` to every package-manager install in workflows reachable from PR triggers. For npm and pnpm, also set `script-shell` to a controlled value. If lifecycle hooks are required for the build, run them in a separate, sandboxed job with no secrets, no `id-token: write`, no PAT, and no mutation steps; promote the build artifact to the privileged job only after content verification.
