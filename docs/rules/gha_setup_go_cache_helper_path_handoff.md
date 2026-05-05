# gha_setup_go_cache_helper_path_handoff

Flags `actions/setup-go` when explicit cache mode is configured and an earlier
same-job step mutates `GITHUB_PATH` before setup-go resolves Go helper commands
for cache discovery.

This is a source-lead cache classifier. It deliberately does not fire for an
action reference alone or for absent/default cache metadata.

## Remediation

Run setup-go cache discovery before mutable PATH setup, disable setup-go cache
discovery when it is not required, or keep Go helper resolution on trusted
runner paths.
