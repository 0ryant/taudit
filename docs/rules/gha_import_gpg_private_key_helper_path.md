# gha_import_gpg_private_key_helper_path

Flags `crazy-max/ghaction-import-gpg` when an earlier same-job step mutates
`GITHUB_PATH` and the later action receives GPG private-key or passphrase
material before invoking GPG helpers.

This is a source-lead classifier. It does not emit witness, disclosure, or CVE
metadata.

## Remediation

Import signing keys before mutable PATH setup, or force `gpg` and
`gpg-connect-agent` resolution to trusted runner paths before private key
material is present.
