# gha_pr_build_pushes_publishable_image

Flags PR-triggered workflows that build and push a container image while
registry or cloud publish authority is present.

This is the publishable-image subset of PR image build leads.

## Remediation

Do not push publishable images from PR-context builds. Split PR build/test from
protected-branch publish and require fork checks before registry credentials
are available.
