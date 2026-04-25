use crate::graph::NodeId;
use crate::propagation::PropagationPath;
use serde::{Deserialize, Serialize};

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
}
