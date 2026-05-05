# gha_setup_node_cache_helper_path_handoff

Flags `actions/setup-node` cache discovery when an earlier same-job step mutates
`GITHUB_PATH`. Setup-node cache modes resolve package-manager helpers such as
`npm`, `pnpm`, and `yarn` through PATH to discover cache directories.

This is a source-lead and hardening rule, not a vulnerability claim.

## Remediation

Run setup-node cache discovery before mutable PATH setup, disable package
manager cache discovery where it is not needed, or pin package-manager helper
resolution to trusted toolcache paths.

