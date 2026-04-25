# Floating Image

**Rule ID:** `floating_image`
**Severity:** Medium
**Category:** Supply Chain
**Tags:** security, supply-chain

## Detection

taudit checks Image nodes that are marked as job containers (`META_CONTAINER = "true"`) — these are `container:` fields on a job or service, not action `uses:` references (which are handled by [unpinned_action](unpinned_action.md)). The rule fires when the image reference does not match `image@sha256:<64 hex chars>`. Tags like `:latest`, `:v1`, or `:stable` all fail the check. The same image used in multiple jobs is deduplicated and fires once.

## Risk

A mutable image tag means the container pulled during your next workflow run may differ from the one used in the last run. The consequences:

- **Silent supply-chain attack:** A compromised registry account pushes malicious code under the same tag. Your next CI run executes it with whatever permissions the job has — network access, secret environment variables, and mounted volumes.
- **Broken reproducibility:** An upstream image update changes system libraries, breaking your build in ways that are hard to attribute. Even if there's no security angle, debugging a build that "worked yesterday" is expensive.
- **`:latest` has no semantics:** Nothing about `:latest` guarantees recency or stability. Registries can point it at anything.

The Medium severity reflects that this requires a registry compromise or deliberate upstream action to exploit — it is not self-contained like a secret exposure. But the blast radius when it fires is the full job execution context.

## Remediation

1. **Get the digest for your image:**
   ```bash
   docker pull my-registry/my-image:stable
   docker inspect --format='{{index .RepoDigests 0}}' my-registry/my-image:stable
   # → my-registry/my-image@sha256:abc123...64hex...
   ```
   Or via the registry API:
   ```bash
   crane digest my-registry/my-image:stable
   ```

2. **Pin to the digest in your workflow:**
   ```yaml
   jobs:
     build:
       container:
         image: my-registry/my-image@sha256:abc123def456...  # full 64-char hex
   ```
   Keep the original tag in a comment for human readability:
   ```yaml
         image: my-registry/my-image@sha256:abc123...  # stable as of 2024-01-15
   ```

3. **Automate digest updates with Renovate:**
   ```json
   {
     "extends": ["config:base"],
     "docker-compose": {
       "enabled": true
     }
   }
   ```
   Renovate understands `image@sha256:` references and opens PRs to update them.

4. **Verify:** Re-run `taudit scan`. The finding should be gone. Use `docker image inspect` to confirm the digest matches what you pinned.

## See also

- [unpinned_action](unpinned_action.md) — same concept for action `uses:` references
- [Renovate Docker digest pinning](https://docs.renovatebot.com/docker/)
- [crane](https://github.com/google/go-containerregistry/blob/main/cmd/crane/README.md) — lightweight tool to inspect registry digests without pulling
