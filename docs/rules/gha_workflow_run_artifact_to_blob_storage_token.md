# GHA Workflow-Run Artifact To Blob Storage Under Token

**Rule ID:** `gha_workflow_run_artifact_to_blob_storage_token`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, artifact-replay, exfiltration, github-actions

## Detection

Fires when a `workflow_run` consumer downloads an artifact produced by an upstream workflow that was triggered by `pull_request`, AND the consumer writes that artifact (or its bytes) to a blob/object-storage destination under a token-bearing action or shell command — `vercel/blob`, `aws s3 cp`/`aws s3 sync`, `gcloud storage cp`, `az storage blob upload`, Cloudflare R2 / Wrangler bucket put, custom signed-URL upload, or a release-asset upload.

## Risk

The cache/artifact channel is not signed end-to-end. The PR-triggered upstream produces bytes the PR author controlled; the privileged consumer treats them as its own build output. With a privileged write token, those bytes land in production blob storage where downstream services (CDN, preview environments, customer-facing assets) consume them as if they came from the protected branch's CI.

This is a replace-and-publish channel: the attacker does not need to compromise the consumer's secrets; they only need to upload a maliciously-named artifact in the upstream PR.

## Remediation

Verify the artifact's provenance before consuming it: require the upstream workflow to attach an `actions/attest-build-provenance` artifact with a cert pinned to the protected ref, then validate the cert in the consumer. Alternatively, gate the consumer on `github.event.workflow_run.head_branch == 'main'` (or equivalent protected-ref check) and confirm the upstream's HEAD is the same branch — not the PR head. Where preview-environment publish from PRs is intentional, isolate the storage destination so production consumers never read PR-origin bytes.
