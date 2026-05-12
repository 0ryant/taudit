# GHA Cross-Forge Mirror Checkout With Token Push

**Rule ID:** `gha_crossforge_mirror_checkout_with_token_push`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, cross-forge, mirror-bot, github-actions

## Detection

Fires when:

- `actions/checkout` is invoked with `repository:` set to a value
  other than the running repo (i.e., `${{ env.* }}`,
  `${{ inputs.* }}`, an interpolated repo name, or a different
  hardcoded `<org>/<repo>`); AND
- a later step in the same job runs `git push`, `gh api -X PUT/POST`
  with credentials, or pushes to the checked-out repo via a token-in-URL
  (`https://x-access-token:${TOKEN}@github.com/...`).

Severity rises when the token is a PAT or App token with broader scope
than the running repo.

## Risk

The checked-out repository is a different trust boundary from the
running repo. The running workflow's CODEOWNERS, branch protection,
and reviewer requirements do NOT apply to the checked-out repo. Any
mutation pushed to the checked-out repo bypasses the running repo's
review chain.

Common vulnerable shapes:

- **Wiki-sync workflows**: a workflow in `<org>/<repo>` updates
  `<org>/<repo>.wiki` using `$GITHUB_TOKEN`. PRs to `<repo>` that
  modify the sync logic mutate the wiki contents without wiki-side
  review.
- **Fork-bot autosolvers**: a workflow pushes commits to a fork
  (`<org>-bot/<repo>`) using a separate PAT. The fork's branch
  protection differs from the canonical repo's; PRs from the fork
  back to canonical may be auto-approved.
- **Mirror sync**: a workflow pushes from GitHub to a GitLab mirror
  using a PAT, divorcing the mirror's CI from the canonical repo's
  review chain.

The trust gap: reviewers of the running repo audit the workflow YAML
but not the cross-repo target's branch protection.

## Remediation

Pin the cross-repo target's branch protection at least as strict as
the running repo's. Document the cross-repo dependency inline in the
workflow comment. Where possible, replace the cross-repo push with a
reusable workflow or a coordinated release process that mediates the
cross-repo authority through CODEOWNERS-protected commits.

Avoid embedding tokens in URLs (`https://x-access-token:${TOKEN}@...`)
because this leaks the token to git's process tree; prefer
`actions/checkout`'s `token:` input or `git-credential-helper`.
