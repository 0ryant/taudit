# Cross-Workflow Authority Chain

**Rule ID:** `cross_workflow_authority_chain`
**Severity:** Critical (Untrusted target) / High (ThirdParty target)
**Category:** Propagation
**Tags:** security, supply-chain

## Detection

taudit looks for Step nodes that: (a) have `HasAccessTo` a Secret or Identity, and (b) have a `DelegatesTo` edge to an Image node in a trust zone other than FirstParty. The Image node represents the called workflow or reusable action. The rule fires once per (step, target) pair, listing all authority held by the calling step.

Severity: Critical when the called workflow is in the Untrusted zone, High when it is ThirdParty.

## Risk

Reusable workflows and composite actions in GitHub Actions, and template references in ADO, allow one pipeline to call another. When the calling pipeline holds secrets and delegates to an external workflow, it is effectively handing those credentials to code it does not control.

The attack path:

1. Your workflow calls `secrets: inherit` on a reusable workflow hosted in another organization's repository.
2. The called workflow receives all of your caller's secrets in its environment.
3. The other organization's repository is compromised, or they intentionally add malicious steps to the reusable workflow.
4. The malicious steps exfiltrate every secret inherited from your workflow.

Even without `secrets: inherit`, individual secrets passed via `with:` or `secrets:` parameters are accessible to the called workflow. If you call an unpinned external workflow, you're passing credentials to code that can change at any time.

This is a transitive authority delegation problem — the called workflow may in turn call other workflows, extending the chain further (see also [authority_cycle](authority_cycle.md) for the circular version).

## Remediation

1. **Immediate — check what you're calling and why:**
   Find the flagged `uses:` reference in your workflow:
   ```yaml
   jobs:
     deploy:
       uses: external-org/shared-workflows/.github/workflows/deploy.yml@main
       secrets: inherit  # hands all your secrets to external-org's code
   ```

2. **Pin the called workflow to a SHA:**
   ```yaml
   jobs:
     deploy:
       uses: external-org/shared-workflows/.github/workflows/deploy.yml@a1b2c3d4e5f6...  # v2.1.0
       secrets:
         DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}  # explicit, not inherit
   ```
   SHA-pinning prevents the external repository from silently changing the code that receives your credentials.

3. **Prefer calling workflows within your own org:**
   ```yaml
   jobs:
     deploy:
       uses: your-org/shared-workflows/.github/workflows/deploy.yml@<sha>
   ```
   First-party workflows (same organization) are not flagged by this rule.

4. **Use `secrets:` instead of `secrets: inherit`:**
   Pass only the specific secrets the called workflow needs, not all of them:
   ```yaml
   secrets:
     DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
   # not: secrets: inherit
   ```

5. **Audit the called workflow:** Before granting it any credentials, review what it does with them. Check that the external repository has appropriate security practices (dependency pinning, branch protection, CODEOWNERS for the workflow file).

6. **Verify:** Re-run `taudit scan`. If the finding persists after SHA-pinning, it means the called workflow is still not FirstParty — that is expected and reflects the real-world trust boundary.

## See also

- [authority_cycle](authority_cycle.md) — circular delegation
- [unpinned_action](unpinned_action.md) — the called workflow is often also unpinned
- [GitHub Actions — reusable workflows security](https://docs.github.com/en/actions/using-workflows/reusing-workflows#access-and-permissions)
- [SLSA — trusted builders](https://slsa.dev/spec/v1.0/requirements#build-as-code)
