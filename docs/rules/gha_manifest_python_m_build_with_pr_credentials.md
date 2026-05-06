# GHA Manifest python -m build / setup.py On PR With Publish Credentials

**Rule ID:** `gha_manifest_python_m_build_with_pr_credentials`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, supply-chain, manifest-as-code, python, github-actions

## Detection

Fires when a workflow runs `python -m build`, `python setup.py *`, `pip install -e .`, `pip install .[<extras>]`, `pip wheel .`, `cibuildwheel`, `maturin build`, `pdm build`, or `poetry build` against a checkout that includes PR-author bytes (PR head, merged HEAD before re-build, or a tag created by automation that consumes PR content), AND the workflow file (or a workflow it dispatches/triggers) runs `pypa/gh-action-pypi-publish`, `twine upload`, `maturin publish`, OR has `id-token: write` granting OIDC for trusted publishing.

## Risk

`setup.py` is Python that runs at install/build time. `pyproject.toml [build-system].requires` and `build-backend` together declare a build backend that pip downloads from PyPI and runs in a virtualenv to produce the wheel/sdist. `[tool.poetry.scripts]` and `entry_points` declare scripts that run on install. `conftest.py` is auto-imported by `pytest` from the cwd.

A PR that modifies `setup.py`, `pyproject.toml`, or any module the build-backend imports during the build process can execute arbitrary Python with the CI step's env in scope. If a downstream job inherits the produced wheel/sdist as the publish artifact and uploads it under PyPI OIDC or a Twine token, PR-author code controls what is published as the project's authentic release.

Trusted-publishing OIDC tokens are scoped to the project and the workflow filename. A verifier that confirms only those two facts accepts the artifact. The cert/identity correctly binds to the workflow path; what's wrong is the bytes the workflow built from PR-author manifests.

## Remediation

Build wheels/sdists in a sandboxed job that has no PyPI publish credentials and no `id-token: write`. Sign and publish only after a CODEOWNERS-gated re-checkout of the protected ref re-runs the build with the same arguments and verifies the artifact's content hash matches. Where wheel-build matrices on PR are intentional (preview wheels), publish them under a clearly distinguished cert identity so production verifiers cannot accept them.
