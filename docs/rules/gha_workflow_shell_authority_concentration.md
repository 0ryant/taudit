# gha_workflow_shell_authority_concentration

Flags workflow-authored shell steps that concentrate publish, deploy, registry,
release, signing, or package authority. Examples include `docker push`, `npm
publish`, `twine upload`, `terraform apply`, `helm push`, `kubectl apply -f
https://...`, `cosign sign`, `gh release`, `cargo publish`, `sentry-cli`, and
`sonar-scanner`.

This is a corpus and workflow-hardening classifier, not an action disclosure or
vulnerability claim.

## Remediation

Keep publish/deploy/sign/release helpers on trusted paths, use explicit env
allowlists around the sink step, and split preparatory PATH mutations from
authority-bearing shell sinks where practical.
