# GitLab Deploy Job Missing Protected-Branch Restriction

**Rule ID:** `gitlab_deploy_job_missing_protected_branch_only`
**Severity:** Medium
**Category:** Configuration
**Tags:** security, configuration, gitlab
**Platform:** GitLab CI only

## Detection

Positive-invariant rule for GitLab CI. Fires once per Step (job) when ALL of the following hold:

1. The graph platform is GitLab (`META_PLATFORM == "gitlab"`).
2. The Step carries an `environment_name` metadata value matching a production token (`prod`, `production`, `prd`).
3. The Step does NOT carry `META_RULES_PROTECTED_ONLY = "true"`.

The parser stamps `META_RULES_PROTECTED_ONLY` when the job's `rules:` or `only:` clause demonstrably restricts execution to a protected ref. Recognised patterns:

- `rules: - if: '$CI_COMMIT_REF_PROTECTED == "true"'`
- `rules: - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'` (default branch is GitLab-protected by default)
- `rules: - if: '$CI_COMMIT_TAG'` (tags are protected by default)
- `only: [main]` / `only: [master]` / `only: tags`
- `only: { refs: [main, /^release/.*/] }`

The recogniser is intentionally generous: the goal is to *credit* defensive intent, not to audit-grade verify that every protection actually exists in the project's branch-protection settings (which lives outside the YAML).

## Risk

GitLab's protected-branch model means CI/CD variables marked as "protected" are only injected on protected refs. But the CI YAML itself must still be written defensively — without a `rules:` / `only:` clause restricting the job, two things happen:

1. The job runs (or attempts to run) on every pipeline trigger, including MRs. If the secrets are protected, the job fails noisily with missing-credential errors. If the secrets are NOT protected, the deploy actually executes from an MR — the secret-side protection becomes the only gate, and it's a single-point-of-failure.
2. If the project's branch protection is later relaxed (a common operational mistake when adding a new release branch), the deploy job silently becomes runnable from unprotected branches without any code change.

The blue-team corpus showed multiple deployment jobs in public GitLab projects with `script: kubectl apply -f k8s/` and no branch restriction whatsoever — the deploy ran on every commit to every branch, and the only thing stopping it from rewriting prod was that the kubeconfig variable happened to be protected.

## Remediation

Add a `rules:` clause restricting the job to protected refs. The safest two patterns:

```yaml
deploy-prod:
  stage: deploy
  environment:
    name: production
  script:
    - kubectl apply -f k8s/
  rules:
    - if: '$CI_COMMIT_REF_PROTECTED == "true"'   # any protected branch or tag
```

Or restrict to the default branch only:

```yaml
deploy-prod:
  stage: deploy
  environment:
    name: production
  script:
    - kubectl apply -f k8s/
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
```

Both forms survive future relaxation of branch-protection settings — the YAML itself enforces the restriction independently of the project's protection configuration.

For tag-driven release flows, the `$CI_COMMIT_TAG` form is the direct equivalent:

```yaml
release-prod:
  stage: release
  environment:
    name: production
  script:
    - ./scripts/release.sh
  rules:
    - if: '$CI_COMMIT_TAG =~ /^v[0-9]+\.[0-9]+\.[0-9]+$/'
```

## See also

- [trigger_context_mismatch](trigger_context_mismatch.md) — companion rule on MR-triggered jobs with secret access.
- [authority_propagation](authority_propagation.md) — fires on the propagation chain that this restriction is meant to gate.
- [GitLab Docs — Protected branches](https://docs.gitlab.com/ee/user/project/protected_branches.html)
- [GitLab Docs — Restrict CI/CD variables to protected refs](https://docs.gitlab.com/ee/ci/variables/#protect-a-cicd-variable)
- [GitLab Docs — `rules:` keyword](https://docs.gitlab.com/ee/ci/yaml/#rules)
