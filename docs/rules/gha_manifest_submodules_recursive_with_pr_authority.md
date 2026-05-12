# GHA Manifest Submodules Recursive With PR-Mutable .gitmodules And Credentials

**Rule ID:** `gha_manifest_submodules_recursive_with_pr_authority`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, supply-chain, manifest-as-code, github-actions

## Detection

Fires when `actions/checkout` is invoked with `submodules: recursive` or `submodules: true` in a workflow whose triggers include `pull_request`, `pull_request_target`, or `workflow_run`, AND the same job has credential-bearing env in scope, AND the `.gitmodules` file is in a PR-mutable directory (i.e., not protected by CODEOWNERS in a way the workflow can verify).

## Risk

`.gitmodules` defines submodule URLs. `actions/checkout` with `submodules: recursive` clones every submodule URL into the working tree. A PR that edits `.gitmodules` to point at an attacker-controlled repository pulls that repo's bytes into the workspace under the workflow's credential surface. Subsequent steps that build, compile, install, or run code from the working tree (`cargo build` for vendored crates, `npm install` for vendored packages, `make` for vendored shell) execute attacker code with the CI step's env in scope.

This combines with MAC-3 (cargo `build.rs` runs for any vendored Rust crate) and MAC-1 (npm lifecycle hooks run for any vendored Node package) and MAC-5 (Makefile recipes run for any vendored shell).

## Remediation

Pin `.gitmodules` URLs to a hardcoded allowlist enforced at workflow start (compare against a CODEOWNERS-protected snapshot before clone). Prefer `submodules: false` (the default) and explicit per-submodule cloning at known SHAs. Where recursive cloning is required, run the cloning step in a sandboxed job with no credentials and re-validate submodule URLs in the privileged job before any build invocation.
