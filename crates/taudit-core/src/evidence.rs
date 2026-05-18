//! Shared ordered authority evidence skeleton for v1.2 core rules.
//!
//! This module mirrors the frozen public field names in
//! `docs/rc/v1.2.0/ordered-evidence-wire-fields.md`, but remains a bounded
//! core API until parser stamps and sink projections are wired.

use crate::graph::TrustZone;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Current ordered authority evidence schema label.
pub const ORDERED_AUTHORITY_EVIDENCE_SCHEMA: &str = "taudit.ordered_authority_evidence.v1";

/// Public ordering invariant label for helper-resolution authority evidence.
pub const ORDERED_AUTHORITY_ORDERING_INVARIANT: &str =
    "path_mutation_before_authority_materialization_before_or_at_helper_execution";

/// Public scope boundary for one ordered authority evidence object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderedEvidenceScope {
    /// CI/CD platform label, for example `github-actions`.
    pub platform: String,
    /// Workflow or pipeline identity within the scanned source.
    pub workflow_id: String,
    /// Job identity used as the default ordering scope.
    pub job_id: String,
}

/// Static source location safe for public rendering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderedEvidenceSourceLocation {
    /// Source file path.
    pub path: String,
    /// One-based source line when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// One-based source column when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

/// Common fields present on every ordered evidence event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderedEvidenceEventCommon {
    /// Stable id within one finding, path, or evidence object.
    pub event_id: String,
    /// Job identity used for ordering scope.
    pub job_id: String,
    /// Zero-based step execution order within `job_id`.
    pub step_index: u32,
    /// Source step id when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_id: Option<String>,
    /// Source step display name when safe to render.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_name: Option<String>,
    /// Static source location. This is explanatory, not an ordering coordinate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_location: Option<OrderedEvidenceSourceLocation>,
    /// Evidence strength label for this event.
    pub evidence_strength: EvidenceStrength,
}

/// Evidence strength values allowed on ordered evidence events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStrength {
    /// Static facts parsed from source.
    Static,
    /// Inferred facts derived from source or graph shape.
    Inferred,
    /// Catalog-backed facts.
    Catalog,
    /// Witness status rendered only as a label.
    WitnessLabel,
    /// Observed evidence from an explicit observed-evidence input.
    Observed,
}

/// Event-kind discriminator values for ordered authority evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderedEvidenceEventKind {
    /// Mutable helper-resolution state was changed.
    PathMutation,
    /// A secret specifically became available.
    SecretMaterialized,
    /// Broader authority became available.
    AuthorityMaterialized,
    /// A helper was invoked.
    HelperExecution,
    /// Authority reaches a helper execution.
    HelperReceivesAuthority,
}

/// Mutable helper-resolution channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutableChannel {
    /// GitHub Actions `$GITHUB_PATH`.
    GithubPath,
    /// Process `PATH`.
    PathEnv,
    /// Workspace path material.
    WorkspacePath,
    /// Runner temp directory.
    RunnerTemp,
    /// Toolcache path.
    ToolcachePath,
    /// Shell environment mutation.
    ShellEnv,
    /// Unknown or platform-specific mutable channel.
    Unknown,
}

/// Scope affected by a path mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationScope {
    /// Job-scoped mutation.
    Job,
    /// Step-scoped mutation.
    Step,
    /// Workspace-scoped mutation.
    Workspace,
    /// Runner-scoped mutation.
    Runner,
    /// Unknown mutation scope.
    Unknown,
}

/// Class of materialized authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityClass {
    /// Secret value or secret handle.
    Secret,
    /// Token authority.
    Token,
    /// OIDC request capability.
    OidcRequest,
    /// Cloud credential.
    CloudCredential,
    /// Registry credential.
    RegistryCredential,
    /// Generated credential file.
    CredentialFile,
    /// Authority derived from another secret payload.
    DerivedSecret,
}

/// Origin of materialized authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityOrigin {
    /// Caller-provided secret.
    CallerProvidedSecret,
    /// Secret passed through an action input.
    ActionInputSecret,
    /// Platform-provided GitHub token.
    GithubToken,
    /// OIDC request capability.
    OidcRequestCapability,
    /// Cloud credential minted by an action.
    #[serde(rename = "cloud_credential_minted_by_action")]
    ActionMintedCloudCredential,
    /// Registry credential minted by an action.
    #[serde(rename = "registry_credential_minted_by_action")]
    ActionMintedRegistryCredential,
    /// Generated credential file.
    GeneratedCredentialFile,
    /// Derived secret payload.
    DerivedSecretPayload,
}

/// How a helper execution was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperResolution {
    /// Bare command resolved by ambient lookup.
    BareCommand,
    /// Shell string resolved by shell semantics.
    ShellString,
    /// Toolkit `which` style lookup.
    ToolkitWhich,
    /// Absolute path.
    AbsolutePath,
    /// Toolcache path.
    ToolcachePath,
    /// Path owned by the action.
    ActionOwnedPath,
    /// Caller-provided absolute path.
    UserSuppliedAbsolutePath,
    /// Ambient path allowed by explicit mode.
    AmbientPathByExplicitMode,
    /// Unknown helper resolution mode.
    Unknown,
}

/// Public call-site descriptor for a helper execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperCallSite {
    /// Human-safe label, for example an action name or script key path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Source location for the call site when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_location: Option<OrderedEvidenceSourceLocation>,
}

/// How authority is transported to a helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityTransport {
    /// Command-line argument transport.
    Argv,
    /// Standard input transport.
    Stdin,
    /// Environment variable transport.
    Env,
    /// Credential file path transport.
    CredentialFilePath,
    /// Config file path transport.
    ConfigFilePath,
    /// Workspace file transport.
    WorkspaceFile,
    /// OIDC request environment transport.
    OidcRequestEnv,
}

/// Confidence assigned to an ordered authority predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceConfidence {
    /// High confidence.
    High,
    /// Medium confidence.
    Medium,
    /// Low confidence.
    Low,
}

/// One ordered authority evidence event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event_kind", rename_all = "snake_case")]
pub enum OrderedEvidenceEvent {
    /// Mutable helper-resolution state changed before later authority.
    PathMutation {
        /// Common event fields.
        #[serde(flatten)]
        common: OrderedEvidenceEventCommon,
        /// Mutable channel affected by the event.
        mutable_channel: MutableChannel,
        /// Trust zone of the source that can write the mutable channel.
        source_trust_zone: TrustZone,
        /// Scope affected by the mutation.
        mutation_scope: MutationScope,
    },
    /// A secret specifically became available.
    SecretMaterialized {
        /// Common event fields.
        #[serde(flatten)]
        common: OrderedEvidenceEventCommon,
        /// Class of materialized authority.
        authority_class: AuthorityClass,
        /// Origin of materialized authority.
        authority_origin: AuthorityOrigin,
        /// Sanitized source-level label.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authority_label: Option<String>,
    },
    /// Broader authority became available.
    AuthorityMaterialized {
        /// Common event fields.
        #[serde(flatten)]
        common: OrderedEvidenceEventCommon,
        /// Class of materialized authority.
        authority_class: AuthorityClass,
        /// Origin of materialized authority.
        authority_origin: AuthorityOrigin,
        /// Sanitized source-level label.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authority_label: Option<String>,
    },
    /// A helper was invoked.
    HelperExecution {
        /// Common event fields.
        #[serde(flatten)]
        common: OrderedEvidenceEventCommon,
        /// Normalized helper name.
        helper: String,
        /// Sanitized command display.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command: Option<String>,
        /// Helper resolution mode.
        helper_resolution: HelperResolution,
        /// Public call-site descriptor.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        call_site: Option<HelperCallSite>,
    },
    /// Authority reaches a helper execution.
    HelperReceivesAuthority {
        /// Common event fields.
        #[serde(flatten)]
        common: OrderedEvidenceEventCommon,
        /// Event id of the helper execution that receives authority.
        helper_execution_event_id: String,
        /// Event id of the materialized authority.
        authority_materialization_event_id: String,
        /// Authority transport mode.
        authority_transport: AuthorityTransport,
        /// Predicate confidence.
        confidence: EvidenceConfidence,
    },
}

impl OrderedEvidenceEvent {
    /// Return the event-kind discriminator.
    pub fn event_kind(&self) -> OrderedEvidenceEventKind {
        match self {
            Self::PathMutation { .. } => OrderedEvidenceEventKind::PathMutation,
            Self::SecretMaterialized { .. } => OrderedEvidenceEventKind::SecretMaterialized,
            Self::AuthorityMaterialized { .. } => OrderedEvidenceEventKind::AuthorityMaterialized,
            Self::HelperExecution { .. } => OrderedEvidenceEventKind::HelperExecution,
            Self::HelperReceivesAuthority { .. } => {
                OrderedEvidenceEventKind::HelperReceivesAuthority
            }
        }
    }

    /// Return common event fields.
    pub fn common(&self) -> &OrderedEvidenceEventCommon {
        match self {
            Self::PathMutation { common, .. }
            | Self::SecretMaterialized { common, .. }
            | Self::AuthorityMaterialized { common, .. }
            | Self::HelperExecution { common, .. }
            | Self::HelperReceivesAuthority { common, .. } => common,
        }
    }

    /// Return the event id.
    pub fn event_id(&self) -> &str {
        &self.common().event_id
    }

    /// Return the event job id.
    pub fn job_id(&self) -> &str {
        &self.common().job_id
    }

    /// Return the event step index.
    pub fn step_index(&self) -> u32 {
        self.common().step_index
    }

    fn is_authority_materialization(&self) -> bool {
        matches!(
            self,
            Self::SecretMaterialized { .. } | Self::AuthorityMaterialized { .. }
        )
    }

    fn is_helper_execution(&self) -> bool {
        matches!(self, Self::HelperExecution { .. })
    }

    fn as_helper_receives_authority(
        &self,
    ) -> Option<(&str, &str, EvidenceConfidence, &OrderedEvidenceEventCommon)> {
        match self {
            Self::HelperReceivesAuthority {
                common,
                helper_execution_event_id,
                authority_materialization_event_id,
                confidence,
                ..
            } => Some((
                helper_execution_event_id,
                authority_materialization_event_id,
                *confidence,
                common,
            )),
            _ => None,
        }
    }
}

/// Public predicate over the event ids that satisfy the ordering invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderedAuthorityEvidencePredicate {
    /// Path mutation event id.
    pub path_mutation_event_id: String,
    /// Authority materialization event id.
    pub authority_materialization_event_id: String,
    /// Helper execution event id.
    pub helper_execution_event_id: String,
    /// Helper receives authority event id.
    pub helper_receives_authority_event_id: String,
    /// Predicate confidence.
    pub confidence: EvidenceConfidence,
    /// True because the current skeleton only proves same-job chains.
    pub same_job_caveat: bool,
}

/// Public ordered authority evidence object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderedAuthorityEvidence {
    /// Evidence schema label.
    pub schema: String,
    /// Scope for this evidence object.
    pub scope: OrderedEvidenceScope,
    /// Ordering invariant label.
    pub ordering_invariant: String,
    /// Ordered evidence events.
    pub events: Vec<OrderedEvidenceEvent>,
    /// Predicate event ids satisfying the invariant.
    pub predicate: OrderedAuthorityEvidencePredicate,
}

/// Errors returned while building an ordered authority predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OrderedEvidenceBuildError {
    /// Duplicate event ids are not stable within one evidence object.
    #[error("duplicate ordered evidence event id")]
    DuplicateEventId,
    /// A path mutation event is required.
    #[error("ordered authority evidence requires a path mutation event")]
    MissingPathMutation,
    /// A secret or authority materialization event is required.
    #[error("ordered authority evidence requires an authority materialization event")]
    MissingAuthorityMaterialization,
    /// A helper execution event is required.
    #[error("ordered authority evidence requires a helper execution event")]
    MissingHelperExecution,
    /// A helper-receives-authority event is required.
    #[error("ordered authority evidence requires a helper_receives_authority event")]
    MissingHelperReceivesAuthority,
    /// Events do not share the same default job scope.
    #[error("ordered authority evidence crosses job scope without an execution relationship")]
    CrossJobScope,
    /// The path/auth/helper ordering invariant is not satisfied.
    #[error("ordered authority evidence does not satisfy the ordering invariant")]
    OrderingInvariantNotSatisfied,
}

/// Builder for the bounded same-job ordered authority evidence skeleton.
#[derive(Debug, Clone)]
pub struct OrderedAuthorityEvidenceBuilder {
    scope: OrderedEvidenceScope,
    events: Vec<OrderedEvidenceEvent>,
}

impl OrderedAuthorityEvidenceBuilder {
    /// Start an evidence object for one default job scope.
    pub fn new(scope: OrderedEvidenceScope) -> Self {
        Self {
            scope,
            events: Vec::new(),
        }
    }

    /// Append one event and return the builder.
    pub fn event(mut self, event: OrderedEvidenceEvent) -> Self {
        self.events.push(event);
        self
    }

    /// Append one event by mutable reference.
    pub fn push_event(&mut self, event: OrderedEvidenceEvent) -> &mut Self {
        self.events.push(event);
        self
    }

    /// Validate the same-job ordering invariant and build the evidence object.
    pub fn build(self) -> Result<OrderedAuthorityEvidence, OrderedEvidenceBuildError> {
        let predicate = build_predicate(&self.scope, &self.events)?;
        Ok(OrderedAuthorityEvidence {
            schema: ORDERED_AUTHORITY_EVIDENCE_SCHEMA.into(),
            scope: self.scope,
            ordering_invariant: ORDERED_AUTHORITY_ORDERING_INVARIANT.into(),
            events: self.events,
            predicate,
        })
    }
}

fn build_predicate(
    scope: &OrderedEvidenceScope,
    events: &[OrderedEvidenceEvent],
) -> Result<OrderedAuthorityEvidencePredicate, OrderedEvidenceBuildError> {
    let mut index = HashMap::with_capacity(events.len());
    for (idx, event) in events.iter().enumerate() {
        if index.insert(event.event_id(), idx).is_some() {
            return Err(OrderedEvidenceBuildError::DuplicateEventId);
        }
        if event.job_id() != scope.job_id {
            return Err(OrderedEvidenceBuildError::CrossJobScope);
        }
    }

    let has_path = events
        .iter()
        .any(|event| matches!(event, OrderedEvidenceEvent::PathMutation { .. }));
    let has_authority = events
        .iter()
        .any(OrderedEvidenceEvent::is_authority_materialization);
    let has_helper = events.iter().any(OrderedEvidenceEvent::is_helper_execution);
    let has_transport = events
        .iter()
        .any(|event| event.as_helper_receives_authority().is_some());

    if !has_path {
        return Err(OrderedEvidenceBuildError::MissingPathMutation);
    }
    if !has_authority {
        return Err(OrderedEvidenceBuildError::MissingAuthorityMaterialization);
    }
    if !has_helper {
        return Err(OrderedEvidenceBuildError::MissingHelperExecution);
    }
    if !has_transport {
        return Err(OrderedEvidenceBuildError::MissingHelperReceivesAuthority);
    }

    let mut saw_cross_job_path = false;
    let mut saw_ordering_failure = false;

    for receive_event in events {
        let Some((helper_id, authority_id, confidence, receive_common)) =
            receive_event.as_helper_receives_authority()
        else {
            continue;
        };

        let helper = index
            .get(helper_id)
            .and_then(|idx| events.get(*idx))
            .filter(|event| event.is_helper_execution())
            .ok_or(OrderedEvidenceBuildError::MissingHelperExecution)?;
        let authority = index
            .get(authority_id)
            .and_then(|idx| events.get(*idx))
            .filter(|event| event.is_authority_materialization())
            .ok_or(OrderedEvidenceBuildError::MissingAuthorityMaterialization)?;

        if receive_common.job_id != scope.job_id
            || helper.job_id() != scope.job_id
            || authority.job_id() != scope.job_id
            || receive_common.job_id != helper.job_id()
            || helper.job_id() != authority.job_id()
        {
            return Err(OrderedEvidenceBuildError::CrossJobScope);
        }

        if authority.step_index() > helper.step_index() {
            saw_ordering_failure = true;
            continue;
        }

        if receive_common.step_index != helper.step_index() {
            saw_ordering_failure = true;
            continue;
        }

        let mut same_job_path_without_order = false;
        for path_event in events
            .iter()
            .filter(|event| matches!(event, OrderedEvidenceEvent::PathMutation { .. }))
        {
            if path_event.job_id() != scope.job_id {
                saw_cross_job_path = true;
                continue;
            }

            if path_event.step_index() < authority.step_index() {
                return Ok(OrderedAuthorityEvidencePredicate {
                    path_mutation_event_id: path_event.event_id().to_string(),
                    authority_materialization_event_id: authority.event_id().to_string(),
                    helper_execution_event_id: helper.event_id().to_string(),
                    helper_receives_authority_event_id: receive_event.event_id().to_string(),
                    confidence,
                    same_job_caveat: true,
                });
            }

            same_job_path_without_order = true;
        }

        if same_job_path_without_order {
            saw_ordering_failure = true;
        }
    }

    if saw_cross_job_path {
        Err(OrderedEvidenceBuildError::CrossJobScope)
    } else if saw_ordering_failure {
        Err(OrderedEvidenceBuildError::OrderingInvariantNotSatisfied)
    } else {
        Err(OrderedEvidenceBuildError::OrderingInvariantNotSatisfied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::TrustZone;

    fn scope(job_id: &str) -> OrderedEvidenceScope {
        OrderedEvidenceScope {
            platform: "github-actions".into(),
            workflow_id: "release.yml".into(),
            job_id: job_id.into(),
        }
    }

    fn common(event_id: &str, job_id: &str, step_index: u32) -> OrderedEvidenceEventCommon {
        OrderedEvidenceEventCommon {
            event_id: event_id.into(),
            job_id: job_id.into(),
            step_index,
            step_id: None,
            step_name: None,
            source_location: None,
            evidence_strength: EvidenceStrength::Static,
        }
    }

    fn path(event_id: &str, job_id: &str, step_index: u32) -> OrderedEvidenceEvent {
        OrderedEvidenceEvent::PathMutation {
            common: common(event_id, job_id, step_index),
            mutable_channel: MutableChannel::GithubPath,
            source_trust_zone: TrustZone::Untrusted,
            mutation_scope: MutationScope::Job,
        }
    }

    fn auth(event_id: &str, job_id: &str, step_index: u32) -> OrderedEvidenceEvent {
        OrderedEvidenceEvent::AuthorityMaterialized {
            common: common(event_id, job_id, step_index),
            authority_class: AuthorityClass::Token,
            authority_origin: AuthorityOrigin::GithubToken,
            authority_label: Some("github_token".into()),
        }
    }

    fn helper(event_id: &str, job_id: &str, step_index: u32) -> OrderedEvidenceEvent {
        OrderedEvidenceEvent::HelperExecution {
            common: common(event_id, job_id, step_index),
            helper: "gh".into(),
            command: Some("gh release upload".into()),
            helper_resolution: HelperResolution::BareCommand,
            call_site: None,
        }
    }

    fn transport(
        event_id: &str,
        job_id: &str,
        step_index: u32,
        helper_id: &str,
        authority_id: &str,
    ) -> OrderedEvidenceEvent {
        OrderedEvidenceEvent::HelperReceivesAuthority {
            common: common(event_id, job_id, step_index),
            helper_execution_event_id: helper_id.into(),
            authority_materialization_event_id: authority_id.into(),
            authority_transport: AuthorityTransport::Env,
            confidence: EvidenceConfidence::High,
        }
    }

    #[test]
    fn builder_accepts_positive_order() {
        let evidence = OrderedAuthorityEvidenceBuilder::new(scope("publish"))
            .event(path("event-path-1", "publish", 1))
            .event(auth("event-auth-1", "publish", 2))
            .event(helper("event-helper-1", "publish", 3))
            .event(transport(
                "event-transport-1",
                "publish",
                3,
                "event-helper-1",
                "event-auth-1",
            ))
            .build()
            .expect("ordered predicate should build");

        assert_eq!(evidence.schema, ORDERED_AUTHORITY_EVIDENCE_SCHEMA);
        assert_eq!(
            evidence.ordering_invariant,
            ORDERED_AUTHORITY_ORDERING_INVARIANT
        );
        assert_eq!(evidence.events.len(), 4);
        assert_eq!(evidence.predicate.path_mutation_event_id, "event-path-1");
        assert_eq!(
            evidence.predicate.authority_materialization_event_id,
            "event-auth-1"
        );
        assert_eq!(
            evidence.predicate.helper_execution_event_id,
            "event-helper-1"
        );
        assert_eq!(
            evidence.predicate.helper_receives_authority_event_id,
            "event-transport-1"
        );
        assert!(evidence.predicate.same_job_caveat);
    }

    #[test]
    fn builder_rejects_reversed_path_and_authority_order() {
        let err = OrderedAuthorityEvidenceBuilder::new(scope("publish"))
            .event(path("event-path-1", "publish", 3))
            .event(auth("event-auth-1", "publish", 2))
            .event(helper("event-helper-1", "publish", 4))
            .event(transport(
                "event-transport-1",
                "publish",
                4,
                "event-helper-1",
                "event-auth-1",
            ))
            .build()
            .expect_err("path mutation after authority must not build");

        assert_eq!(
            err,
            OrderedEvidenceBuildError::OrderingInvariantNotSatisfied
        );
    }

    #[test]
    fn builder_allows_same_step_materialization_and_execution() {
        let evidence = OrderedAuthorityEvidenceBuilder::new(scope("publish"))
            .event(path("event-path-1", "publish", 1))
            .event(auth("event-auth-1", "publish", 2))
            .event(helper("event-helper-1", "publish", 2))
            .event(transport(
                "event-transport-1",
                "publish",
                2,
                "event-helper-1",
                "event-auth-1",
            ))
            .build()
            .expect("authority and helper may share a step");

        assert_eq!(
            evidence.predicate.helper_execution_event_id,
            "event-helper-1"
        );
    }

    #[test]
    fn builder_rejects_cross_job_chain() {
        let err = OrderedAuthorityEvidenceBuilder::new(scope("publish"))
            .event(path("event-path-1", "prepare", 1))
            .event(auth("event-auth-1", "publish", 2))
            .event(helper("event-helper-1", "publish", 3))
            .event(transport(
                "event-transport-1",
                "publish",
                3,
                "event-helper-1",
                "event-auth-1",
            ))
            .build()
            .expect_err("cross-job evidence must not build");

        assert_eq!(err, OrderedEvidenceBuildError::CrossJobScope);
    }

    #[test]
    fn builder_rejects_extra_out_of_scope_events() {
        let err = OrderedAuthorityEvidenceBuilder::new(scope("publish"))
            .event(path("event-path-1", "publish", 1))
            .event(auth("event-auth-1", "publish", 2))
            .event(helper("event-helper-1", "publish", 3))
            .event(transport(
                "event-transport-1",
                "publish",
                3,
                "event-helper-1",
                "event-auth-1",
            ))
            .event(path("event-path-other", "other-job", 1))
            .build()
            .expect_err("out-of-scope extra events must not ride along");

        assert_eq!(err, OrderedEvidenceBuildError::CrossJobScope);
    }

    #[test]
    fn builder_rejects_missing_materialization() {
        let err = OrderedAuthorityEvidenceBuilder::new(scope("publish"))
            .event(path("event-path-1", "publish", 1))
            .event(helper("event-helper-1", "publish", 3))
            .event(transport(
                "event-transport-1",
                "publish",
                3,
                "event-helper-1",
                "event-auth-1",
            ))
            .build()
            .expect_err("transport without authority materialization must not build");

        assert_eq!(
            err,
            OrderedEvidenceBuildError::MissingAuthorityMaterialization
        );
    }

    #[test]
    fn builder_rejects_transport_event_before_helper_execution() {
        let err = OrderedAuthorityEvidenceBuilder::new(scope("publish"))
            .event(path("event-path-1", "publish", 1))
            .event(auth("event-auth-1", "publish", 2))
            .event(helper("event-helper-1", "publish", 4))
            .event(transport(
                "event-transport-1",
                "publish",
                3,
                "event-helper-1",
                "event-auth-1",
            ))
            .build()
            .expect_err("authority transport must occur with the helper execution");

        assert_eq!(
            err,
            OrderedEvidenceBuildError::OrderingInvariantNotSatisfied
        );
    }

    #[test]
    fn authority_origin_serializes_with_public_contract_names() {
        assert_eq!(
            serde_json::to_value(AuthorityOrigin::ActionMintedCloudCredential).unwrap(),
            serde_json::json!("cloud_credential_minted_by_action")
        );
        assert_eq!(
            serde_json::to_value(AuthorityOrigin::ActionMintedRegistryCredential).unwrap(),
            serde_json::json!("registry_credential_minted_by_action")
        );
    }
}
