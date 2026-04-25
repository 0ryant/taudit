# Persisted Credential

**Rule ID:** `persisted_credential`
**Severity:** High
**Category:** Credentials
**Tags:** security, supply-chain

## Detection

taudit looks for `PersistsTo` edges in the authority graph — these are created by the parser when a checkout step has `persist-credentials: true` (GHA) or the equivalent ADO option enabled. When such an edge exists, the credential is written to `.git/config` on the runner filesystem and remains there for the duration of the job (and potentially across jobs on a shared runner).

## Risk

When `persist-credentials: true` is set on `actions/checkout`, the GITHUB_TOKEN (or a PAT if configured) is embedded in the repository's `.git/config` as a credential helper. This file lives on the runner's filesystem for the rest of the job.

The specific threats:

1. **Subsequent step access:** Every step that runs after the checkout can read `.git/config`. A third-party action running later in the same job can extract the token with:
   ```bash
   git config --get http.https://github.com/.extraheader
   ```
   This extracts the base64-encoded token from the git credential helper configuration.

2. **Shared runner persistence:** On self-hosted runners, the checkout directory may persist between jobs. A later, unrelated job running on the same agent can potentially access the credentials from a previous job's workspace.

3. **Blast radius equals token scope:** The persisted token has whatever permissions the workflow's GITHUB_TOKEN was granted. If the workflow runs with `contents: write`, the extracted token can push commits.

The key distinction from `authority_propagation`: this rule fires on disk persistence specifically. The credential is accessible to any code with filesystem access, not just code that receives the environment variable.

## Remediation

1. **Immediate — disable credential persistence:**
   ```yaml
   - uses: actions/checkout@<sha>
     with:
       persist-credentials: false
   ```
   This is a one-line fix. After this change, git will not have stored credentials and subsequent steps cannot extract them via `.git/config`.

2. **If subsequent steps need git authentication:** Pass the token explicitly only to the step that needs it, rather than persisting it globally:
   ```yaml
   - uses: actions/checkout@<sha>
     with:
       persist-credentials: false
   
   - name: Push changes
     env:
       GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
     run: |
       git remote set-url origin https://x-access-token:${GITHUB_TOKEN}@github.com/${{ github.repository }}
       git push
   ```

3. **Verify:** Re-run `taudit scan`. The finding should be gone. Confirm by checking your checkout step for `persist-credentials: false`. You can also verify at runtime: after checkout, `cat .git/config` should not contain `extraheader` entries.

## See also

- [authority_propagation](authority_propagation.md) — the persisted token may also propagate to subsequent untrusted steps
- [untrusted_with_authority](untrusted_with_authority.md) — if a step after the checkout is untrusted
- [GitHub Actions — `actions/checkout` persist-credentials](https://github.com/actions/checkout#usage)
