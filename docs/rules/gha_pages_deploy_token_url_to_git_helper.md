# gha_pages_deploy_token_url_to_git_helper

Flags Pages deploy actions such as `peaceiris/actions-gh-pages` and
`JamesIves/github-pages-deploy-action` when an earlier same-job step mutates
`GITHUB_PATH` and the later action receives GitHub token, PAT, or deploy-key
authority before delegating to `git`.

This is a source-lead classifier for helper-resolution authority confusion,
not an action disclosure.

## Remediation

Deploy Pages before mutable PATH setup, prefer least-privileged deploy keys or
tokens, and ensure `git` resolves to a trusted absolute path before token URLs
or deploy-key Git authority are composed.
