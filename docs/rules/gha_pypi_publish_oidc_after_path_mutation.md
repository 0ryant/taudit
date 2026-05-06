# gha_pypi_publish_oidc_after_path_mutation

Flags `pypa/gh-action-pypi-publish` when an earlier same-job step mutates
`GITHUB_PATH` and the later publish action has PyPI token or OIDC publishing
authority before Python packaging helper resolution.

This is an action-boundary source lead for package publishing authority.

## Remediation

Publish to PyPI before mutable PATH setup, use trusted absolute helper paths,
and keep OIDC or token publishing authority scoped to the publish boundary.
