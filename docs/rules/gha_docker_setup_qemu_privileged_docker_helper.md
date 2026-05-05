# gha_docker_setup_qemu_privileged_docker_helper

Flags `docker/setup-qemu-action` when it runs after registry authentication or
with a private/non-default image, and an earlier same-job step mutates
`GITHUB_PATH`. The action delegates to Docker helper operations including
privileged container execution.

The action alone is not enough; the rule requires the registry/private-image
context and prior mutable PATH shape.

## Remediation

Run QEMU setup before registry login or private image pulls, resolve Docker
through a trusted absolute path, and keep privileged Docker helper execution out
of mutable PATH contexts.

