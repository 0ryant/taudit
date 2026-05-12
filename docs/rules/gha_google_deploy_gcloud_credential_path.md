# gha_google_deploy_gcloud_credential_path

Flags Google App Engine or Cloud Run deploy actions when an earlier same-job
step mutates `GITHUB_PATH` and later deploy authority reaches `gcloud`.

The authority may come from action inputs, a prior `google-github-actions/auth`
step, ADC, OIDC, or service-account material visible in the parsed workflow.

## Remediation

Run Google deploy actions before mutable PATH setup, or resolve `gcloud` through
trusted absolute paths before ADC, OIDC, or service-account authority is
present.
