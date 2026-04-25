# Checkout Self PR Exposure

**Rule ID:** `checkout_self_pr_exposure`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, supply-chain, pull-request

## Detection

taudit fires this rule when two conditions are simultaneously true:
1. The graph has a PR-class trigger: `pull_request_target` (GHA) or `pr` (ADO).
2. At least one Step node has `META_CHECKOUT_SELF = "true"` — set by the parser when the step performs a checkout of the repository (`actions/checkout` with no explicit ref override on a PR context, or `checkout: self` in ADO).

This rule is distinct from [trigger_context_mismatch](trigger_context_mismatch.md). `trigger_context_mismatch` fires when a PR-triggered workflow holds authority (secrets, identities). `checkout_self_pr_exposure` fires whenever attacker-controlled fork code lands on the runner, regardless of whether explicit secrets are present — because workspace files themselves can be vectors.

## Risk

When a PR-triggered workflow checks out the PR head branch, the code of the PR author physically lands on the CI runner's filesystem. Every step that runs after the checkout can access this code:

- **Script injection:** A later step runs `./scripts/test.sh` from the workspace. The attacker's PR has modified `test.sh` to include a curl exfiltration command.
- **Config file injection:** A step runs a tool that reads configuration from the workspace (e.g., `.eslintrc`, `pytest.ini`, `Makefile`). The attacker modifies the config to inject shell commands.
- **Makefile / build system hijack:** `make build` runs `$(shell malicious-command)` injected into the Makefile.
- **Test fixture injection:** A test runner executes files from the workspace including attacker-controlled fixtures. If those fixtures contain shell escape sequences processed by the test framework, they can execute arbitrary code.

Even without any explicit secret access, if a later step in the same job has credentials (e.g., a deploy step that runs after tests), the attacker's code can exfiltrate them by poisoning the workspace before the deploy step runs.

## Remediation

1. **The simplest fix — use `pull_request` instead of `pull_request_target`:**
   ```yaml
   on:
     pull_request:  # safe — no base repo access, fork code is expected here
   ```
   `pull_request` is designed for exactly this use case: running CI on untrusted PR code.

2. **If you must use `pull_request_target` — don't check out the PR head:**
   ```yaml
   on:
     pull_request_target:
   
   jobs:
     # Never do: ref: ${{ github.event.pull_request.head.sha }}
     # Just omit the checkout, or check out the base ref
     label:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/labeler@<sha>
           with:
             repo-token: ${{ secrets.GITHUB_TOKEN }}
             # No checkout needed — works on event metadata only
   ```

3. **If tests must run on PR code:** Use the `pull_request` trigger for the CI job (no secrets). Use `workflow_run` to trigger a privileged deploy job only after CI passes — and the deploy job should not check out PR code.

4. **For ADO PR pipelines:** Use `checkout: none` on jobs that don't need source code:
   ```yaml
   steps:
     - checkout: none  # explicit — no workspace contamination
     - task: SomeTask@1
   ```

5. **Verify:** Re-run `taudit scan`. The finding resolves when either the trigger changes to `pull_request` or the checkout step is removed from the PR-triggered workflow. If both `checkout_self_pr_exposure` and `trigger_context_mismatch` are firing, resolve both.

## See also

- [trigger_context_mismatch](trigger_context_mismatch.md) — fires when the PR-triggered workflow also holds authority
- [GitHub Actions — `pull_request_target` security advisory](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [GitHub Actions — safe patterns for PR workflows](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request_target)
