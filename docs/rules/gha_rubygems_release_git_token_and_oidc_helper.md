# gha_rubygems_release_git_token_and_oidc_helper

Flags `rubygems/release-gem` when an earlier same-job step mutates
`GITHUB_PATH` and the later release action has RubyGems token, GitHub token, or
OIDC release authority before delegating to `gem`, `bundle`, or `git` helpers.

This is an action-boundary source lead for package release authority.

## Remediation

Run RubyGems release before mutable PATH setup, or ensure `gem`, `bundle`, and
`git` resolve to trusted absolute paths before release authority is present.
