# gha_macos_codesign_cert_security_path

Flags `apple-actions/import-codesign-certs` when an earlier same-job step
mutates `GITHUB_PATH` and the later action receives P12, certificate password,
or keychain authority before invoking the macOS `security` helper.

This rule is most relevant on macOS runners. It remains a classifier unless a
separate internal witness proves runtime helper selection.

## Remediation

Import codesigning material before mutable PATH setup, and resolve `security`
through a trusted absolute path before certificate or keychain material is
available.
