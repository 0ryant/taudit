# Long-Lived Credential

**Rule ID:** `long_lived_credential`
**Severity:** High
**Category:** Credentials
**Tags:** security, credentials

## Detection

taudit checks every Secret node in the authority graph against a list of name patterns associated with static, long-lived credentials:

- `AWS_ACCESS_KEY`, `AWS_SECRET_ACCESS_KEY`
- `_API_KEY`, `_APIKEY`
- `_PASSWORD`, `_PASSWD`
- `_PRIVATE_KEY`
- `_SECRET_KEY`
- `_SERVICE_ACCOUNT`
- `_SIGNING_KEY`

The match is case-insensitive and substring-based — `MY_SERVICE_APIKEY` fires just as `API_KEY` does. This is a heuristic: taudit detects the name, not the value.

## Risk

Long-lived credentials don't expire on their own. If one leaks — through a log line, a compromised runner, a supply-chain attack, or a misconfigured artifact — it remains valid until manually rotated. The window of exposure is unbounded.

The specific scenarios:

- **Log leakage:** A step accidentally prints the value (e.g., `echo "Connecting with $AWS_SECRET_ACCESS_KEY"` or a tool that logs its environment on startup). Pipeline logs may be retained for months.
- **Runner compromise:** An attacker who gains code execution in your CI job reads the environment. The credential is usable from that point forward.
- **Rotation lag:** When a compromise is detected, rotating a static credential requires updating every pipeline that uses it. OIDC tokens expire automatically — there is nothing to rotate.

AWS access keys in particular carry significant blast radius: they can be used to call any AWS API the associated IAM user or role has access to, often including cross-account operations.

## Remediation

1. **Best — replace with OIDC federation:**

   **AWS:**
   ```yaml
   permissions:
     id-token: write
     contents: read
   
   steps:
     - uses: aws-actions/configure-aws-credentials@<sha>
       with:
         role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
         aws-region: us-east-1
   ```
   Delete `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` from your secrets store after migration.

   **GCP:**
   ```yaml
   permissions:
     id-token: write
   
   steps:
     - uses: google-github-actions/auth@<sha>
       with:
         workload_identity_provider: projects/123/locations/global/workloadIdentityPools/...
         service_account: my-service-account@my-project.iam.gserviceaccount.com
   ```

   **Azure:**
   ```yaml
   permissions:
     id-token: write
   
   steps:
     - uses: azure/login@<sha>
       with:
         client-id: ${{ secrets.AZURE_CLIENT_ID }}
         tenant-id: ${{ secrets.AZURE_TENANT_ID }}
         subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
   ```
   (Federated credential — no static client secret stored.)

2. **If OIDC is not available for the target service:** Set the shortest possible expiry on the credential and rotate it on a schedule. Store it in a secrets manager (not directly in the pipeline secret store) and inject at runtime.

3. **Verify:** After migrating to OIDC, remove the old secret from the repository secrets store. Re-run `taudit scan` — the finding should be gone because the secret node no longer exists in the parsed graph.

## See also

- [authority_propagation](authority_propagation.md) — if this long-lived credential is also propagating to untrusted code
- [AWS IAM OIDC for GitHub Actions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)
- [GitHub Actions OIDC configuration](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#using-the-github_token-in-a-workflow)
