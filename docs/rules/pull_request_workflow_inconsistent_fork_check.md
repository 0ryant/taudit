# PR Workflow Inconsistent Fork Check

**Rule ID:** `pull_request_workflow_inconsistent_fork_check`
**Severity:** High (or Medium when only one job is unguarded)
**Category:** Privilege Escalation
**Tags:** security, privilege-escalation, github-actions
**Platform:** GitHub Actions only

## Detection

Detects intra-file inconsistency in fork-check application. Fires once per workflow when ALL of the following hold:

1. The graph platform is GitHub Actions (`META_PLATFORM == "github-actions"`).
2. The trigger list (`META_TRIGGER`) contains `pull_request` or `pull_request_target`.
3. Multiple distinct jobs hold authority (each has at least one Step with `HasAccessTo` to a Secret or Identity).
4. At least one job's privileged steps ALL carry `META_FORK_CHECK = "true"` — meaning every privileged step in that job is gated by a fork-check `if:`.
5. At least one OTHER privileged job has at least one privileged step that does NOT carry that marker.

The parser stamps `META_FORK_CHECK` when the step's own `if:` (or its enclosing job's `if:`) matches one of:

- `github.event.pull_request.head.repo.fork == false`
- `github.event.pull_request.head.repo.fork != true`
- `github.event.pull_request.head.repo.full_name == github.repository`
- `github.repository == github.event.pull_request.head.repo.full_name`

Match is case-insensitive and tolerant of whitespace normalisation.

Severity floors at Medium when the inconsistency is limited to a single unguarded job (one-off oversight) and steps up to High when multiple privileged jobs are unguarded (systemic gap).

## Risk

The interesting signal isn't "the workflow has unguarded privileged jobs" — that's covered by [trigger_context_mismatch](trigger_context_mismatch.md), [checkout_self_pr_exposure](checkout_self_pr_exposure.md), and [pr_build_pushes_image_with_floating_credentials](pr_build_pushes_image_with_floating_credentials.md). The interesting signal is **the org has the right defensive instinct but applied it inconsistently**.

When some jobs in the same workflow have the standard fork-check `if:` and others don't, the unguarded jobs are almost certainly an oversight rather than a deliberate design choice. The fix is mechanical (copy the `if:` from the guarded job to the unguarded one), the diff is one line per job, and the team is already familiar with the pattern. This is the highest-velocity hardening change a reviewer can request on a single PR.

The blue-team corpus showed Grafana's `pr-e2e-tests.yml` consistently applying the fork-check while the same repo's `pr-build-grafana.yml` did not — an exact fit for this rule.

## Remediation

Add the same fork-check `if:` to every privileged step (or job) in the workflow. The recommended canonical form:

```yaml
jobs:
  build-grafana:
    if: github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: make build

  push-docker-image:
    if: github.event.pull_request.head.repo.full_name == github.repository   # match the build-grafana guard
    needs: build-grafana
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: docker/login-action@<sha>
      - run: docker push ...
```

Use job-level `if:` rather than step-level when the entire job should be fork-guarded — that way every step in the job inherits the guard without per-step duplication.

If a job genuinely needs to run for fork PRs (e.g. a lint check that consumes no secrets), the right fix is to drop the secret/identity access from that job rather than to skip the fork-check.

## See also

- [trigger_context_mismatch](trigger_context_mismatch.md) — fires on the underlying trigger combination; the suppression layer downgrades it when fork-check is universal.
- [checkout_self_pr_exposure](checkout_self_pr_exposure.md) — companion rule on PR checkouts.
- [pr_build_pushes_image_with_floating_credentials](pr_build_pushes_image_with_floating_credentials.md) — related compound vector.
- [GitHub Docs — Keeping your GitHub Actions and workflows secure: Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
