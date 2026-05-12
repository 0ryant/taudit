# GHA Cross-Repo Secrets Inherit To Unreviewed Callee

**Rule ID:** `gha_crossrepo_secrets_inherit_unreviewed_callee`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, supply-chain, manifest-as-code, cross-repo, github-actions

## Detection

Fires when a workflow uses `uses: <org>/<repo>/.github/workflows/<X>.yml@<ref>` AND declares `secrets: inherit`, AND the callee repo is not the same as the caller repo. Severity rises further when the ref is also a floating ref (`@main`/`@master`/floating major).

## Risk

`secrets: inherit` forwards the entire caller secret surface to the callee. When the callee lives in a different repository, the security boundary collapses across repo boundaries: any secret named in the caller — registry tokens, cloud credentials, signing keys, deploy keys, PATs, OIDC trust — becomes visible to any code that runs inside the callee.

When the callee ref is floating, this collapse is dynamic: whoever can push to the producer's branch can read the consumer's secrets on the next consumer trigger. When the callee ref is a SHA, the collapse is static but still a contract violation: the workflow author cannot opt out of secrets they don't even know exist.

In the public corpus this shape compounds: `bridgecrewio/checkov/build.yml` declares `secrets: inherit` for `bridgecrewio/gha-reusable-workflows/.github/workflows/publish-image.yaml@main`, cascading at least seven distinct secrets (`PRISMA_KEY_API2`, `PRISMA_API_URL_2`, `DOCKERHUB_USERNAME_2`, `DOCKERHUB_PASSWORD_2`, `BC_JENKINS_TOKEN`, `GH_PAT_SECRET_2`, `GPG_PRIVATE_KEY_2`) to a separate repo at a mutable branch. `chef/chef/ci-main-pull-request-stub.yml` cascades to `chef/common-github-actions@main` for 8+ stub workflows.

## Remediation

Replace `secrets: inherit` with explicit `secrets: {<name>: ${{ secrets.<name> }}}` blocks naming only the secrets the callee actually needs. Pin the callee ref to a SHA. Where the callee is in a different repo, audit that repo's branch protection and CODEOWNERS to ensure they meet or exceed the caller's, and document the audit in a comment next to the `uses:` line.
