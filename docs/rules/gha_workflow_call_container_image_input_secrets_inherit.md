# GHA Reusable Callee Container Image From Caller Input With Inherited Secrets

**Rule ID:** `gha_workflow_call_container_image_input_secrets_inherit`
**Severity:** High
**Category:** Credentials
**Tags:** security, credentials, authority-confusion, github-actions, supply-chain

## Detection

Fires when a workflow with `on: workflow_call` defines an input named `image`, `docker`, `container`, or `container_image` (or any input typed as a container image), and a job sets `container.image: ${{ inputs.<that> }}`, and the workflow declares `secrets: inherit` (or names credential-bearing secrets as `workflow_call.secrets` inputs).

## Risk

A reusable workflow that runs each job inside a caller-named image while inheriting all caller secrets gives the caller full authority over what code executes with the credentials. Anyone who can trigger the caller — directly or by chaining through `pull_request_target`, `workflow_run`, `issue_comment`, or another reusable hop — can substitute an arbitrary image (a public registry tag they control, a digest under their account) and the job will run inside it with the caller's `GITHUB_TOKEN`, OIDC token, registry tokens, and any cloud credentials.

This is authority confusion at the callable-workflow boundary: the apparent trust contract is "the callee is privileged but the callers are gated" — but the input collapses that gating because the callee's runtime is no longer the callee's source.

## Remediation

Either (a) hardcode `container.image` to a digest-pinned, repo-owned image; (b) restrict the input to a closed enum of validated digests and gate the container job behind an `if:` that proves the input is in the enum; or (c) drop `secrets: inherit` and forward only the secrets the callable needs explicitly. Combining all three is preferable when callers can include `pull_request_target` or `workflow_run` triggers in their chain.
