# GHA NODE_OPTIONS Code Injection Before Node Authority

**Rule ID:** `gha_env_node_options_code_injection_before_node_authority`
**Severity:** High
**Category:** Credentials
**Tags:** security, credentials, authority-confusion, github-actions, code-injection

## Detection

Fires when a same-job earlier step writes `NODE_OPTIONS` (via `env:`, matrix value, or `>> $GITHUB_ENV`) and the value contains any of the following injection-capable flags:

- `--require <module>` / `-r <module>`
- `--import <module>`
- `--experimental-loader <loader>`
- `--experimental-vm-modules`
- `--experimental-policy <file>`
- `--inspect[-brk]` (debugging surface)

A later step in the same job either uses a node-based third-party action (any action implemented in JavaScript/TypeScript, which is most GHA actions) or invokes `node`, `npm`, `npx`, `pnpm`, or `yarn` while a credential-bearing secret, registry token, OIDC `id-token: write` permission, or publish authority is in scope.

## Risk

`NODE_OPTIONS` is honored by every Node.js process started after it is set. `--require` and `--import` execute arbitrary JS at interpreter startup. If an earlier step sets a malicious or attacker-influenceable `NODE_OPTIONS`, every subsequent Node.js action — including the GHA runner's action host process — runs that attacker code with full access to step inputs, env (including secrets), `GITHUB_TOKEN`, and the credential file paths the action would otherwise materialize. PATH hardening does not mitigate this, because the attacker code runs inside the legitimate, absolute-path `node` binary.

## Remediation

Restrict `NODE_OPTIONS` to memory-tuning flags (`--max-old-space-size=*`, `--max-semi-space-size=*`). Treat any other `NODE_OPTIONS` value as a sensitive privileged operation: confine it to the single step that needs it via inline `env:` and never via `>> $GITHUB_ENV`. Where possible, pass the flag as part of the command being invoked rather than persisting it.
