# gha_create_pr_git_token_path_handoff

Flags `peter-evans/create-pull-request` when an earlier same-job step mutates
`GITHUB_PATH` and the later action has token or write-scoped repository
authority before delegating repository mutation to `git`.

This is a source-lead classifier. It does not claim exploitability or same-job
isolation.

## Remediation

Run pull-request automation before mutable PATH setup, split PATH-mutating work
into an authority-free job, or resolve `git` through a trusted absolute path
before token authority is available.
