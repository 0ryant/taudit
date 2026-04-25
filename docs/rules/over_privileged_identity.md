# Over-Privileged Identity

**Rule ID:** `over_privileged_identity`
**Severity:** High (Broad scope) / Medium (Unknown scope)
**Category:** Privilege
**Tags:** security, privilege-escalation

## Detection

taudit inspects every Identity node (GITHUB_TOKEN, ADO service principal) in the authority graph and classifies its scope as Broad, Constrained, or Unknown. The rule fires when scope is Broad or Unknown and at least one Step has `HasAccessTo` the identity.

Broad scope means the permissions block grants write-level access beyond what the workflow's actual operations require (e.g. `contents: write` on a workflow that only reads). Unknown scope means taudit could not determine the permissions — often because no `permissions:` block is present, which defaults to the repository's ambient token scope (frequently write-all in legacy repos).

## Risk

An over-privileged token is safe right up until it isn't. The scenarios:

- **Secret exfiltration via supply chain:** A third-party action you depend on gets compromised. They now have your token. If your token has `contents: write`, they can push commits. If it has `packages: write`, they can publish malicious packages. The token's scope defines what an attacker can do.
- **Mistake amplification:** A misconfigured step accidentally calls `gh repo delete` or pushes to the default branch. With a constrained token this fails — with a broad token it succeeds.
- **Lateral movement in ADO:** An Azure DevOps service connection scoped to a subscription rather than a resource group gives an attacker access to every resource in that subscription if the pipeline is compromised.

The blast radius is exactly the permissions of the token. Minimising scope minimises the blast radius.

## Remediation

1. **Immediate — add an explicit permissions block:**
   ```yaml
   permissions:
     contents: read
   ```
   GitHub's default when no `permissions:` block is present depends on the repository's "Default permissions" setting. Adding an explicit block locks the token to exactly what you specify.

2. **Better — start from zero and add only what's needed:**
   ```yaml
   permissions: {}  # deny all by default
   
   jobs:
     build:
       permissions:
         contents: read
         packages: write  # only if this job publishes packages
   ```

3. **Identify minimum permissions:** Check what API calls your workflow makes:
   - `gh release create` → `contents: write`
   - `gh pr comment` → `pull-requests: write`
   - `gh attestation` → `attestations: write`, `id-token: write`
   - Reading repository → `contents: read`

4. **For ADO service connections:** Scope the connection to a specific resource group rather than the subscription:
   - Go to Project Settings → Service connections → [connection] → Edit
   - Change scope from Subscription to Resource Group

5. **Verify:** Run `taudit scan --verbose` to see the permissions string taudit extracted. Confirm `IdentityScope` is now `constrained`.

## See also

- [GitHub Actions permissions reference](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token)
- [GitHub Actions default permissions](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#setting-the-permissions-of-the-github_token-for-your-repository)
- [authority_propagation](authority_propagation.md) — an over-privileged token propagating to untrusted code is a separate Critical finding
