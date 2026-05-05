# gha_tool_installer_then_shell_helper_authority

Flags installer-followed-by-use patterns for helpers such as Helm, kubectl, and
cosign. The rule looks for a setup/install action followed by workflow-authored
shell use while deploy, signing, Kubernetes, registry, token, or cloud authority
is in scope.

This is an advisory workflow-shell classifier unless source or witness evidence
identifies an action-owned helper boundary.

## Remediation

Call the installed helper through the installer-owned absolute path when
possible, avoid mutable PATH setup between install and privileged use, and keep
the sink step's environment allowlisted.

