# GHA Env Credential-Helper Config Redirect Before Authority

**Rule ID:** `gha_env_credential_helper_config_redirect_before_authority`
**Severity:** High
**Category:** Credentials
**Tags:** security, credentials, authority-confusion, github-actions

## Detection

Fires when a same-job earlier step assigns one of the following environment variables (via `env:`, matrix, or `>> $GITHUB_ENV`) and a later step is a known credential-materializing action or invokes a matching helper under token, cloud, or registry authority:

- AWS: `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE`, `AWS_PROFILE`, `AWS_WEB_IDENTITY_TOKEN_FILE`
- Azure: `AZURE_CONFIG_DIR`
- GCP: `CLOUDSDK_CONFIG`, `GOOGLE_APPLICATION_CREDENTIALS`
- Kubernetes: `KUBECONFIG`, `KUBE_CONFIG_PATH`
- Docker: `DOCKER_CONFIG`, `DOCKER_HOST`, `DOCKER_CERT_PATH`
- npm/pip/Helm/Terraform: `NPM_CONFIG_USERCONFIG`, `NPMRC`, `PIP_CONFIG_FILE`, `HELM_REPOSITORY_CONFIG`, `HELM_REGISTRY_CONFIG`, `TF_CLI_CONFIG_FILE`
- GPG: `GNUPGHOME`
- Generic: `XDG_CONFIG_HOME`

## Risk

The credential-materializing helper writes or reads its config in the redirected location, breaking the trust contract between the action's apparent input boundary and the file the helper actually consults. Whoever can influence the earlier env write controls where credentials are persisted, what registry/index a publish step trusts, or which kubeconfig a later helper applies. This is authority confusion via config-file resolution rather than via PATH.

## Remediation

Set credential-helper config-file env vars only in the same step that consumes them, or pin them to action-owned absolute paths the action itself rewrites before use. Avoid writing these env vars to `$GITHUB_ENV` from a step that runs on user-influenced data. Where possible, prefer action inputs and explicit file paths over env redirection.
