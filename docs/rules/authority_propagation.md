# Authority Propagation

**Rule ID:** `authority_propagation`
**Severity:** Critical / High / Medium (graduated — see below)
**Category:** Propagation
**Tags:** security, privilege-escalation

## Detection

taudit performs BFS from every Secret and Identity node in the authority graph. When that traversal reaches a Step node in a lower trust zone (ThirdParty or Untrusted), this rule fires. The severity graduates based on two factors: whether the sink is SHA-pinned, and whether the source identity is OIDC-federated or constrained.

Graduation:
- **Critical** — sink is in the Untrusted zone, OR the source is an OIDC/federated cloud identity (regardless of pinning)
- **High** — sink is SHA-pinned ThirdParty, but the source has broad or unknown permissions
- **Medium** — sink is SHA-pinned ThirdParty, source has constrained (read-only) permissions, and source is not OIDC

If the propagation path crosses an ADO environment approval gate, severity is downgraded one step (Critical → High, High → Medium, Medium → Low).

## Risk

A secret or identity that reaches untrusted code is effectively compromised. The attack scenario:

1. You have `AWS_ACCESS_KEY_ID` or a `GITHUB_TOKEN` with write permissions.
2. Your workflow passes it (via `env:` or implicit scoping) to a third-party action or step.
3. That action is controlled by an external party — either directly or via a supply-chain attack against their repository.
4. The external code reads the credential from the environment and exfiltrates it to an attacker-controlled endpoint.
5. The attacker now has a working credential with the full scope of what you granted.

OIDC cloud credentials are particularly dangerous here: even a short-lived AWS role token can be used to enumerate S3 buckets, read Secrets Manager, or deploy infrastructure before it expires.

The blast radius depends on the credential's scope. A `contents: write` GitHub token can push commits to the default branch. An AWS role with `sts:AssumeRole` can pivot to other accounts.

## Remediation

1. **Immediate:** Identify which step is the sink. Check whether that action's `@ref` is a mutable tag (e.g. `@v4`). If it is, also fix `unpinned_action`.

2. **Pin the sink:** Replace the mutable tag with a full 40-character SHA digest:
   ```yaml
   # Before
   - uses: some-org/some-action@v2

   # After
   - uses: some-org/some-action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  # v2.3.1
   ```
   Get the SHA: `gh api /repos/some-org/some-action/commits/v2 --jq '.sha'`

3. **Scope secrets to minimum blast radius:** Move the secret from job-level `env:` to step-level `env:` on only the step that actually needs it:
   ```yaml
   steps:
     - name: deploy
       env:
         AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}  # only here
       run: ./deploy.sh
   ```

4. **Better — replace with OIDC:** For AWS, GCP, and Azure, eliminate the long-lived credential entirely:
   ```yaml
   permissions:
     id-token: write
   steps:
     - uses: aws-actions/configure-aws-credentials@<sha>
       with:
         role-to-assume: arn:aws:iam::123456789:role/my-role
         aws-region: us-east-1
   ```

5. **Verify:** Re-run `taudit scan` — the finding should be gone. If it persists, check whether the secret is still present at a job-level `env:` block that flows into the flagged step.

## See also

- [untrusted_with_authority](untrusted_with_authority.md) — fires when the access is direct rather than propagated
- [unpinned_action](unpinned_action.md) — the sink is often also an unpinned action
- [long_lived_credential](long_lived_credential.md) — the source credential may also be flagged
- [GitHub Actions security hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [SLSA provenance levels](https://slsa.dev/spec/v1.0/levels)
