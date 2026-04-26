# Long-Lived Secret Without OIDC Recommendation

**Rule ID:** `long_lived_secret_without_oidc_recommendation`
**Severity:** Info (advisory)
**Category:** Credentials
**Tags:** security, credentials
**Platform:** GitHub Actions, Azure DevOps, GitLab CI

## Detection

Advisory uplift on top of [long_lived_credential](long_lived_credential.md). Fires when both of these hold:

1. The graph contains a Secret node whose name suggests an AWS / GCP / Azure long-lived credential (`AWS_*`, `AWS_ACCESS_KEY*`, `AWS_SECRET*`, `GCP_*`, `GCLOUD_*`, `GOOGLE_*`, `GCP_SERVICE_ACCOUNT*`, `GOOGLE_CREDENTIALS*`, `AZURE_*`, `ARM_*`, `AZURE_CLIENT_SECRET*`).
2. No Identity node in the graph carries `META_OIDC = "true"` (no OIDC federation is currently in use anywhere in this pipeline).

Fires once per matching Secret. Does not double-flag the underlying credential — `long_lived_credential` already covers the existence of the static secret. This rule's contribution is the actionable migration recommendation.

The recommendation it emits is `Recommendation::FederateIdentity { static_secret, oidc_provider }`. This enum variant has shipped in `finding.rs` for two releases without any rule emitting it; this rule wires it.

## Risk

The risk this rule highlights is opportunity-cost rather than direct exploit. The underlying static credential is already flagged by `long_lived_credential`. This rule's purpose is to put a concrete remediation path in front of the pipeline owner: "AWS supports OIDC, so this credential can be replaced with a short-lived token issued at runtime."

The rule only fires when no OIDC identity exists anywhere in the graph. If even one job already uses OIDC, the team is presumably aware of federation — this rule then no-ops to avoid pestering them. The correct framing in that case is "extend OIDC to the remaining static-credential paths," which is a different conversation than "you should consider OIDC."

## Remediation

The recommendation field gives the cloud-specific migration target:

| Cloud  | Recommendation source |
|--------|-----------------------|
| AWS    | `id-token: write` permission + `aws-actions/configure-aws-credentials` with `role-to-assume` |
| GCP    | `google-github-actions/auth` with `workload_identity_provider` |
| Azure  | `azure/login` with `client-id` (no `client-secret`) |

Concrete AWS example replacing `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` secrets:

```yaml
permissions:
  id-token: write          # required for OIDC
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - uses: aws-actions/configure-aws-credentials@<sha>
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-actions-deploy
          aws-region: us-east-1
      - run: aws s3 sync ./dist s3://my-bucket/
```

The role itself must have a trust policy allowing the GitHub OIDC provider:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
      "StringLike": { "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:*" }
    }
  }]
}
```

Once the OIDC role is in use, the static `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` secrets can be deleted from the repository's Actions secrets. The `long_lived_credential` finding then disappears on its own.

## See also

- [long_lived_credential](long_lived_credential.md) — the underlying static-credential finding this rule annotates.
- [GitHub Docs — About security hardening with OpenID Connect](https://docs.github.com/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [aws-actions/configure-aws-credentials](https://github.com/aws-actions/configure-aws-credentials)
- [google-github-actions/auth](https://github.com/google-github-actions/auth)
- [azure/login](https://github.com/azure/login)
