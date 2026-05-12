# gha_changesets_publish_command_with_authority

Flags `changesets/action` when it is configured with a publish command and has
package or GitHub token authority after an earlier same-job `GITHUB_PATH`
mutation.

The rule models the publish command as a package-manager helper boundary, not as
a vulnerability claim.

## Remediation

Run Changesets publish before mutable PATH setup, pin package-manager helper
resolution, and keep npm registry tokens out of ambient helper environments.
