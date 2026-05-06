# gha_floating_remote_script_before_publish_sink

Flags a mutable remote script execution step that runs before a
publish/deploy/release sink in the same authority-bearing GitHub Actions job.

This is the publish-boundary subset of mutable remote script execution.

## Remediation

Pin remote installers to immutable commits and verify checksums before
execution, or run remote script installation in an authority-free job before
any publish, deploy, release, or push credentials are present.
