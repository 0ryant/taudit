# gha_setup_python_pip_install_authority_env

Flags `actions/setup-python` `pip-install` mode when the job has token,
package-index, cloud, or identity authority in scope. The action invokes
`python -m pip install` while inheriting the job environment.

This is a hardening classifier for ambient authority around package
installation.

## Remediation

Prefer a dedicated install step with an explicit environment allowlist and
trusted Python/pip paths. Keep private index and cloud credentials out of
ambient env during setup-python install mode.

