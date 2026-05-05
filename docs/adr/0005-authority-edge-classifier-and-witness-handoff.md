# ADR 0005: Authority-edge classifier and witness handoff

- **Status:** Accepted
- **Date:** 2026-05-05
- **Context:** Hosted-runner helper-resolution witnesses, first-pass GHA helper-authority rules, [ADR 0002](0002-authority-signal-roadmap-phased.md), [ADR 0003](0003-strategic-spine-adoption-phased.md).

## Context

taudit already models pipeline authority as a deterministic graph: secrets, permissions, identities, trust zones, propagation, rules, and schema'd reports. Recent helper-resolution work added first-pass rules for same-job `GITHUB_PATH` mutation followed by later sensitive helper use.

The product risk is over-broad linting. A finding that only says "this workflow mutates PATH" is noisy. The useful signal is narrower:

1. an earlier step can mutate helper resolution state;
2. a later action or step materializes sensitive authority;
3. that later action or step invokes a helper through PATH or equivalent ambient resolution;
4. the helper receives the authority by argv, stdin, env, credential/config file path, workspace file, or OIDC request env.

The hosted-runner witness results also clarify the product boundary. taudit should identify and rank candidate authority paths. It should not become the proof engine that runs exploit witnesses.

## Decision

taudit is the **authority-edge classifier and prioritizer** for CI/CD pipelines.

The split is:

| Component | Responsibility |
|-----------|----------------|
| **taudit** | Find candidate authority paths, classify helper-resolution authority edges, rank technical priority, emit customer-safe reports, and optionally emit internal witness specs. |
| **Algol / enforcement layer** | Enforce or deny undeclared authority according to policy. |
| **witness harness** | Prove a candidate on a real hosted runner or runner-faithful execution path. |

Disclosure and CVE-oriented tooling is **feature-gated internal signal**. Default downstream/customer output must not expose private disclosure ranking, CVE workflow hints, exploit language, or witness canary details. Customers get authority classification, evidence, remediation, and hardening labels. Internal operators can opt into disclosure prioritization and witness handoff explicitly.

taudit will model helper-resolution authority confusion as a first-class rule family, centered on the umbrella condition:

```text
GHA_HELPER_PATH_LATER_AUTHORITY:
  earlier step can mutate PATH or equivalent helper resolution
  AND later action/step materializes sensitive authority
  AND later action/step invokes a helper resolved from PATH or ambient mode
  AND helper receives that authority
```

The rule family does **not** fire merely because a workflow writes `GITHUB_PATH`. Ordering and authority transport are required:

```text
PathMutation.step_index < SecretMaterialized.step_index <= HelperExecution.step_index
```

This lets taudit report:

```text
Earlier mutable PATH state reaches later secret-bearing helper execution.
```

rather than:

```text
This workflow uses PATH.
```

## Model Additions

Add an explicit authority timing model, either as a compact event stream or equivalent graph metadata:

```rust
enum AuthorityPhase {
    PriorMutableState,
    LaterSecretMaterialization,
    HelperExecution,
    PostActionCleanup,
}

struct AuthorityEvent {
    step_index: usize,
    phase: AuthorityPhase,
    kind: AuthorityEventKind,
}
```

Important event kinds:

```rust
enum AuthorityEventKind {
    PathMutation { channel: MutableChannel, source: TrustZone },
    SecretMaterialized { name: String, source: SecretSource },
    CredentialMinted { provider: Provider, credential_type: CredentialType },
    HelperResolved { command: String, resolution: HelperResolution },
    HelperReceivesAuthority {
        command: String,
        transport: AuthorityTransport,
        authority: SensitiveAuthority,
    },
}
```

Helper resolution is classified explicitly:

```rust
enum HelperResolution {
    BareCommand,
    ShellString,
    ToolkitWhich,
    AbsolutePath,
    ToolcachePath,
    ActionOwnedPath,
    UserSuppliedAbsolutePath,
    AmbientPathByExplicitMode,
    Unknown,
}
```

Severity and confidence depend heavily on resolution:

| Resolution | Default treatment |
|------------|-------------------|
| `BareCommand`, `ShellString`, `ToolkitWhich` | high signal |
| `AbsolutePath`, `ToolcachePath`, `ActionOwnedPath` | downgrade or suppress when path is trusted |
| `AmbientPathByExplicitMode` | mode-specific downgrade |
| `Unknown` | confidence-limited |

Authority transport is split by sink:

```rust
enum AuthorityTransport {
    Argv,
    Stdin,
    Env,
    CredentialFilePath,
    ConfigFilePath,
    WorkspaceFile,
    OidcRequestEnv,
}
```

Authority origin is surfaced for triage:

```rust
enum AuthorityOrigin {
    CallerProvidedSecret,
    ActionInputSecret,
    GitHubToken,
    OidcRequestCapability,
    CloudCredentialMintedByAction,
    RegistryCredentialMintedByAction,
    GeneratedCredentialFile,
    DerivedSecretPayload,
}
```

Reports must distinguish action-minted or derived authority from direct caller-provided secret forwarding.

## Rule Families

High-priority rule family:

| Rule | Purpose |
|------|---------|
| `GHA_HELPER_PATH_LATER_AUTHORITY` | Umbrella timing edge: prior mutable helper resolution reaches later authority-bearing helper execution. |
| `GHA_HELPER_ARGV_SECRET` | Sensitive value passed in argv to a PATH-resolved helper. |
| `GHA_HELPER_STDIN_SECRET` | Sensitive value passed on stdin to a PATH-resolved helper. |
| `GHA_HELPER_CREDENTIAL_FILE` | Credential file path reaches a PATH-resolved helper. |
| `GHA_ACTION_MINTED_CREDENTIAL_TO_HELPER` | Action derives or mints credential and sends it to helper. |
| `GHA_OIDC_ENV_TO_HELPER` | Helper inherits GitHub OIDC request variables. |

Medium-priority refinements:

| Rule | Purpose |
|------|---------|
| `GHA_SECRET_ENV_INHERITED_BY_HELPER` | Broad child env inheritance carries sensitive authority to helper. |
| `GHA_PACKAGE_MANAGER_HELPER_WITH_DEPLOY_SECRET` | `npx`, `npm`, `pnpm`, `yarn`, `bunx`, `pip`, or similar receives deploy/publish authority. |
| `GHA_CLI_LOGIN_HELPER_WITH_CREDENTIAL` | `az`, `gcloud`, `aws`, `docker`, `firebase`, `wrangler`, `tbot`, or similar receives login/deploy authority. |

Downgrade and suppressor rules:

| Rule | Purpose |
|------|---------|
| `GHA_HELPER_ABSOLUTE_TOOLCACHE_PATH` | Downgrade canonical trusted toolcache helper execution. |
| `GHA_HELPER_ACTION_OWNED_INSTALL_PATH` | Downgrade action-owned helper install paths not writable by untrusted workflow state. |
| `GHA_HELPER_AMBIENT_BY_EXPLICIT_MODE` | Downgrade explicit "use system binary" modes such as `skip_install` or `use_pypi`. |
| `GHA_ONLY_CALLER_PROVIDED_SECRET_TO_GENERIC_CLI` | Downgrade simple caller-provided secret forwarding to expected CLI wrappers. |

Post-cleanup stays separate:

```text
GHA_POST_AMBIENT_ENV_CLEANUP_PATH:
  action has post hook
  AND post reads non-STATE env
  AND env-derived path reaches delete/remove/rm/rimraf
```

This family may have subrules such as `GHA_POST_ENV_RECURSIVE_DELETE`, `GHA_POST_ENV_CREDENTIAL_CLEANUP`, `GHA_POST_ENV_CACHE_CLEANUP`, and `GHA_POST_ENV_HOME_CACHE_RETARGET`. It must not be merged with helper-PATH authority findings.

## Action Intelligence Catalog

taudit's workflow scanner should not clone and inspect every action on every run. Add an offline action intelligence catalog generated from source scans and witness results.

Minimum catalog shape:

```json
{
  "action": "FirebaseExtended/action-hosting-deploy",
  "versions": ["v0", "main", "500ac625ca2dd40cbd15f7659af953801858032a"],
  "helper_invocations": [
    {
      "helper": "npx",
      "resolution": "BareCommand",
      "argv_pattern": "firebase-tools@* hosting:channel:deploy",
      "authority_transports": ["CredentialFilePath", "Env"],
      "authority_names": ["GOOGLE_APPLICATION_CREDENTIALS", "FIREBASE_DEPLOY_AGENT"],
      "credential_file_created_by_action": true
    }
  ],
  "witness_status": "hosted",
  "severity_bias": "high",
  "notes": "Deploy action writes firebaseServiceAccount into a credential file before invoking npx."
}
```

Initial entries should cover:

- `FirebaseExtended/action-hosting-deploy`
- `azure/login`
- `cloudflare/wrangler-action`
- `docker/login-action`
- `JS-DevTools/npm-publish`
- `aws-actions/amazon-ecr-login`
- `google-github-actions/setup-gcloud`
- `goreleaser/goreleaser-action`
- `codecov/codecov-action`
- `teleport-actions/*` or the pinned Teleport action witnessed in research

Catalog entries carry witness status:

```text
none | local | runner_faithful | hosted
```

and internal-only witness metadata where available:

```text
run_id
pinned_sha
observed_helper
observed_authority_transport
canary_only
```

Public/customer output may use `witness_status` as an evidence strength label. It must not expose canary values, private run artifacts, or disclosure workflow details unless an explicit internal feature gate is enabled.

## Witness Spec Handoff

taudit emits witness specs; it does not execute them. This command is internal disclosure infrastructure and must be hidden behind an explicit feature gate or internal build flag.

Command shape:

```bash
taudit scan .github/workflows/deploy.yml --format json > taudit.json
taudit witness-spec taudit.json --finding TAU-GHA-HELPER-PATH-LATER-AUTH > witness.json
```

Minimum witness spec:

```json
{
  "finding_id": "TAU-GHA-HELPER-PATH-LATER-AUTH",
  "platform": "github-actions",
  "candidate_action": "FirebaseExtended/action-hosting-deploy",
  "helper": "npx",
  "mutation_step": {
    "channel": "GITHUB_PATH",
    "fake_helper_name": "npx"
  },
  "expected_observations": [
    "fake helper invoked",
    "GOOGLE_APPLICATION_CREDENTIALS present",
    "credential file contains canary"
  ],
  "canaries": {
    "firebaseServiceAccount": "algol-canary-service-account-json",
    "projectId": "firebase-project-canary"
  }
}
```

## Reporting Contract

Helper-resolution findings include:

- earlier mutable channel and step;
- later authority source and materialization point;
- helper, helper resolution, and authority transport;
- authority origin;
- confidence level;
- witness status;
- same-job objection analysis;
- technical score;
- product label.

Internal feature-gated output may additionally include disclosure score, witness-spec next action, disclosure-candidate routing, private source anchors, and CVE/disclosure workflow metadata.

Same-job objection analysis is explicit:

```rust
struct SameJobObjection {
    earlier_step_already_has_secret: bool,
    authority_materialized_later: bool,
    action_mints_credential: bool,
    helper_selected_by_prior_mutation: bool,
    likely_vendor_pushback: PushbackLevel,
}
```

Report text should make the caveat visible:

```text
Same-job caveat:
This finding does not assume isolation between arbitrary same-job steps.
The relevant edge is that the earlier step mutates helper resolution before
the later action materializes deploy credentials.
```

Use labels to avoid mixing product vulnerabilities, workflow misconfigurations, and hardening recommendations:

```text
PRODUCT_ACTION_CANDIDATE
WORKFLOW_MISCONFIGURATION
HARDENING_RECOMMENDATION
MOAT_DEMO
SUPPRESSED_EXPECTED_BEHAVIOR
```

## Scoring

Default output carries `technical_score`: did the authority edge happen?

Internal feature-gated output may carry `disclosure_score`: will a vendor likely accept this as a vulnerability or meaningful hardening issue? This signal is for internal triage and should not be included in downstream/customer output.

Suggested internal scoring inputs:

```text
technical_score:
  +3 hosted-runner witness
  +3 helper receives secret
  +2 helper receives credential file path
  +2 action mints/derives credential
  +2 OIDC request env present
  +1 source anchors confirmed

disclosure_score:
  +3 deploy/auth/publish/security action
  +3 action-minted or generated credential
  +2 official docs recommend secret input
  +2 fix is local and compatible
  +1 family issue

penalties:
  -4 earlier step already has same secret
  -3 helper-from-PATH is explicit product contract
  -3 mode-specific ambient helper
  -2 only caller-provided token
  -2 no hosted witness
  -2 same-user filesystem-only impact
```

## Non-Goals

- taudit does not run hosted-runner exploit proofs.
- taudit does not claim CVEs.
- taudit does not expose disclosure scoring or CVE workflow hints in default downstream/customer output.
- taudit does not treat every PATH mutation as a finding.
- taudit does not make every helper-PATH finding critical.
- taudit does not merge post-cleanup path issues into helper-authority issues.
- taudit does not hide whether evidence is catalog-backed, source-scan-backed, or witness-backed.

## Consequences

### Positive

- Keeps taudit credible as a classifier rather than a noisy workflow linter.
- Preserves composability with Algol and witness harnesses.
- Lets reports explain why Firebase/Azure/Cloudflare-like candidates outrank ambient or caller-provided-only cases.
- Creates a stable bridge from static scan to private disclosure evidence work without exposing that workflow to customers by default.

### Negative / costs

- Requires new schema surface for timing events, helper metadata, transport, origin, confidence, scores, and internal witness specs.
- Catalog maintenance becomes a real product surface with versioning and tests.
- Some current helper rules will need migration or aliasing to canonical rule IDs.
- Disclosure scoring is partly judgment-based and must remain feature-gated internal signal.

## Compliance

- Additive schemas only on 1.x unless a future ADR approves a v2 break.
- Catalog entries must have fixtures and at least one source anchor or witness-status explanation.
- Rule output must distinguish `candidate`, `known hosted witness`, and `suppressed expected behavior`.
- Tests must cover timing order, transport split, mode-specific downgrades, same-job caveat text, feature-gated disclosure output, and witness-spec emission.

## References

- [ADR 0002 - Authority signal roadmap](0002-authority-signal-roadmap-phased.md)
- [ADR 0003 - Strategic spine, merge gate, and adoption](0003-strategic-spine-adoption-phased.md)
- [Helper-resolution authority-edge backlog](../research/BACKLOG-helper-resolution-authority-edges-adr0005.md)
- [Rule docs index](../rules/index.md)
