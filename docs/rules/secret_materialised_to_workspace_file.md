# Secret Materialised To Workspace File

**Rule ID:** `secret_materialised_to_workspace_file`
**Severity:** High
**Category:** Credentials
**Tags:** security, credentials, azure-devops

## Detection

The ADO parser stamps every Step's inline script body as `META_SCRIPT_BODY`. The rule walks every Step that holds at least one Secret via `HasAccessTo` and looks for a script line (or sequence of lines) where:

1. A `$(SECRET)` reference is present, **and**
2. The line contains a "write to file" sink:
   - bash: `>`, `>>`, `tee`, `cat << EOF >`
   - PowerShell: `Out-File`, `Set-Content`, `Add-Content`, `[IO.File]::WriteAllText`/`WriteAllLines`
3. The target path either references the agent workspace (`$(System.DefaultWorkingDirectory)`, `$(Build.SourcesDirectory)`, `$(Pipeline.Workspace)`, `$(Agent.BuildDirectory)`, `$(Agent.TempDirectory)`) or carries a credential-bearing extension (`.tfvars`, `.env`, `.hcl`, `.pfx`, `.key`, `.pem`, `.crt`, `.p12`, `.kubeconfig`, `.jks`, `.keystore`).

The rule also detects the multi-line PowerShell idiom where a secret is first bound to a `$variable` and then a later line in the same script writes that variable via `Out-File` to a workspace path.

## Risk

A file written under the agent workspace is fundamentally different from a runtime-only environment variable:

- **Persistence** — the file lives until the job ends, not until the step ends. Every subsequent step in the same job can `cat`, `Get-Content`, or `cp` it freely. ADO's `HasAccessTo` model does not protect files that one step writes for another step to read.
- **Artifact upload** — `PublishPipelineArtifact` and `PublishBuildArtifacts` happily upload anything under the working directory by default. A `.tfvars` containing a Key Vault password ends up in the pipeline's artifact storage, accessible to anyone with `Read` on the pipeline (often the entire engineering org).
- **Self-hosted agent contamination** — on persistent self-hosted agents the workspace is **not** wiped between jobs by default. A secret-bearing file from the previous job's PR pipeline is readable by the next job's main-branch pipeline.
- **Image/container leakage** — `docker build` with the working directory as context will copy the file into the image layer.

The pattern most commonly fires on Terraform pipelines that template `.tfvars` from Key Vault — the file persists to the workspace, gets consumed by `terraform apply`, and is then either uploaded as an artifact for `terraform plan` review or left on a self-hosted agent.

## Remediation

1. **Use the `secureFile` task** for genuine file-shaped secrets (`.pfx`, `.kubeconfig`, signing keys):
   ```yaml
   - task: DownloadSecureFile@1
     name: signingCert
     inputs:
       secureFile: signing.pfx
   - script: signtool sign /f $(signingCert.secureFilePath) /p $(SIGN_PASS) app.exe
   ```
   The file is downloaded to `$(Agent.TempDirectory)` with mode 0600 and is auto-deleted at job end.

2. **Stream the secret over stdin or an env var** to the consuming tool:
   ```yaml
   # bad
   - bash: |
       echo "token = \"$(TF_TOKEN)\"" > $(Build.SourcesDirectory)/secrets.tfvars
       terraform apply -var-file=secrets.tfvars

   # good
   - bash: terraform apply -var "token=$(TF_TOKEN)"   # still bad — see secret_to_inline_script_env_export
   - bash: terraform apply                            # better — pass via env
     env:
       TF_VAR_token: $(TF_TOKEN)
   ```

3. **If a workspace file is unavoidable**, write it under `$(Agent.TempDirectory)` (which is wiped between jobs even on self-hosted agents), `chmod 600` immediately, and `rm -f` it before the step exits — wrap the body in a `trap` (bash) or `try/finally` (PowerShell) so failures still trigger cleanup.

4. **For Terraform** — link the variable group to Key Vault and use `TF_VAR_<name>` env vars instead of templating `.tfvars`. The Terraform provider reads the env var directly; no file is created.

5. **Verify:** Re-run `taudit scan`. The finding clears once the script no longer combines a `$(SECRET)` reference with a file-write sink to a workspace path.

## See also

- [secret_to_inline_script_env_export](secret_to_inline_script_env_export.md) — companion rule for secrets bound to shell variables (in-memory exposure rather than on-disk)
- [persisted_credential](persisted_credential.md) — checkout-step credential persistence (`.git/config`)
- [artifact_boundary_crossing](artifact_boundary_crossing.md) — fires when an artifact crosses a trust zone, including artifacts that may contain materialised secrets
- [Azure DevOps — secureFile task](https://learn.microsoft.com/en-us/azure/devops/pipelines/library/secure-files)
