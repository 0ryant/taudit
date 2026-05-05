# gha_setup_python_cache_helper_path_handoff

Flags `actions/setup-python` cache modes that invoke `pip` or `poetry` helper
commands after an earlier same-job `GITHUB_PATH` mutation.

The rule intentionally excludes pipenv cache mode unless stronger source
evidence exists, because the current Algol handoff identifies helper execution
for pip and poetry.

## Remediation

Run cache discovery before mutable PATH setup, or use a cache mode that does
not resolve package-manager helpers from mutable PATH.

