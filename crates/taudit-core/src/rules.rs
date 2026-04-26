use crate::finding::{Finding, FindingCategory, Recommendation, Severity};
use crate::graph::{
    is_docker_digest_pinned, is_sha_pinned, AuthorityCompleteness, AuthorityGraph, EdgeKind,
    IdentityScope, NodeId, NodeKind, TrustZone, META_ADD_SPN_TO_ENV, META_ATTESTS,
    META_CHECKOUT_SELF, META_CLI_FLAG_EXPOSED, META_CONTAINER, META_DIGEST, META_ENV_APPROVAL,
    META_IDENTITY_SCOPE, META_IMPLICIT, META_OIDC, META_PERMISSIONS, META_REPOSITORIES,
    META_SCRIPT_BODY, META_SELF_HOSTED, META_SERVICE_CONNECTION, META_SERVICE_CONNECTION_NAME,
    META_TERRAFORM_AUTO_APPROVE, META_TRIGGER, META_VARIABLE_GROUP, META_WRITES_ENV_GATE,
};
use crate::propagation;

fn cap_severity(severity: Severity, max_severity: Severity) -> Severity {
    if severity < max_severity {
        max_severity
    } else {
        severity
    }
}

fn apply_confidence_cap(graph: &AuthorityGraph, findings: &mut [Finding]) {
    if graph.completeness != AuthorityCompleteness::Partial {
        return;
    }

    for finding in findings {
        finding.severity = cap_severity(finding.severity, Severity::High);
    }
}

/// MVP Rule 1: Authority (secret/identity) propagated across a trust boundary.
///
/// Severity graduation (tuned from real-world signal on 10 production workflows):
/// - Untrusted sink: Critical (real risk — unpinned code with authority)
/// - SHA-pinned ThirdParty sink: High (immutable code, but still cross-boundary)
/// - SHA-pinned sink + constrained identity: Medium (lowest-risk form — read-only
///   token to immutable third-party code, e.g. `contents:read` → `actions/checkout@sha`)
pub fn authority_propagation(graph: &AuthorityGraph, max_hops: usize) -> Vec<Finding> {
    let paths = propagation::propagation_analysis(graph, max_hops);

    paths
        .into_iter()
        .filter(|p| p.crossed_boundary)
        .map(|path| {
            let source_name = graph
                .node(path.source)
                .map(|n| n.name.as_str())
                .unwrap_or("?");
            let sink_name = graph
                .node(path.sink)
                .map(|n| n.name.as_str())
                .unwrap_or("?");

            // Graduate severity based on sink trust + source scope
            let sink_is_pinned = graph
                .node(path.sink)
                .map(|n| {
                    n.trust_zone == TrustZone::ThirdParty && n.metadata.contains_key(META_DIGEST)
                })
                .unwrap_or(false);

            let source_is_constrained = graph
                .node(path.source)
                .and_then(|n| n.metadata.get(META_IDENTITY_SCOPE))
                .map(|s| s == "constrained")
                .unwrap_or(false);

            let source_is_oidc = graph
                .node(path.source)
                .and_then(|n| n.metadata.get(META_OIDC))
                .map(|v| v == "true")
                .unwrap_or(false);

            // OIDC cloud identities (AWS/GCP/Azure federated creds) carry direct
            // cloud blast radius — even SHA-pinned third-party code reaching them
            // can exfiltrate credentials. The token itself is the threat, not the
            // sink's trust zone, so OIDC sources are Critical regardless of pinning.
            let base_severity = if sink_is_pinned && source_is_constrained && !source_is_oidc {
                Severity::Medium
            } else if sink_is_pinned && !source_is_oidc {
                Severity::High
            } else {
                // Untrusted sink OR OIDC source — Critical regardless of pinning
                Severity::Critical
            };

            // ADO environment approvals are a manual gate — authority cannot
            // propagate past one without human intervention. If any node on the
            // propagation path carries META_ENV_APPROVAL, downgrade severity by
            // one step and annotate the message so the operator can see why.
            let crosses_approval_gate = path_crosses_env_approval(graph, &path);
            let (severity, message_suffix) = if crosses_approval_gate {
                (
                    downgrade_one_step(base_severity),
                    " (mitigated: environment approval gate)",
                )
            } else {
                (base_severity, "")
            };

            Finding {
                severity,
                category: FindingCategory::AuthorityPropagation,
                nodes_involved: vec![path.source, path.sink],
                message: format!(
                    "{source_name} propagated to {sink_name} across trust boundary{message_suffix}"
                ),
                recommendation: Recommendation::TsafeRemediation {
                    command: "tsafe exec --ns <scoped-namespace> -- <command>".to_string(),
                    explanation: format!("Scope {source_name} to only the steps that need it"),
                },
                path: Some(path),
            }
        })
        .collect()
}

/// Returns true if any node touched by `path` (source, sink, or any edge
/// endpoint along the way) carries META_ENV_APPROVAL = "true".
fn path_crosses_env_approval(graph: &AuthorityGraph, path: &propagation::PropagationPath) -> bool {
    let has_marker = |id: NodeId| {
        graph
            .node(id)
            .and_then(|n| n.metadata.get(META_ENV_APPROVAL))
            .map(|v| v == "true")
            .unwrap_or(false)
    };

    if has_marker(path.source) || has_marker(path.sink) {
        return true;
    }

    for &edge_id in &path.edges {
        if let Some(edge) = graph.edge(edge_id) {
            if has_marker(edge.from) || has_marker(edge.to) {
                return true;
            }
        }
    }
    false
}

/// Reduce a severity by one step. Critical→High, High→Medium, Medium→Low.
/// Low and Info are already at the floor of meaningful reduction and are
/// returned unchanged.
fn downgrade_one_step(severity: Severity) -> Severity {
    match severity {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low => Severity::Low,
        Severity::Info => Severity::Info,
    }
}

/// MVP Rule 2: Identity scope broader than actual usage.
///
/// Uses `IdentityScope` classification from the precision layer. Broad and
/// Unknown scopes are flagged — Unknown is treated as risky because if we
/// can't determine the scope, we shouldn't assume it's safe.
pub fn over_privileged_identity(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for identity in graph.nodes_of_kind(NodeKind::Identity) {
        let granted_scope = identity
            .metadata
            .get(META_PERMISSIONS)
            .cloned()
            .unwrap_or_default();

        // Use IdentityScope from metadata if set by parser, otherwise classify from permissions
        let scope = identity
            .metadata
            .get(META_IDENTITY_SCOPE)
            .and_then(|s| match s.as_str() {
                "broad" => Some(IdentityScope::Broad),
                "constrained" => Some(IdentityScope::Constrained),
                "unknown" => Some(IdentityScope::Unknown),
                _ => None,
            })
            .unwrap_or_else(|| IdentityScope::from_permissions(&granted_scope));

        // Broad or Unknown scope — flag it. Unknown is treated as risky.
        let (should_flag, severity) = match scope {
            IdentityScope::Broad => (true, Severity::High),
            IdentityScope::Unknown => (true, Severity::Medium),
            IdentityScope::Constrained => (false, Severity::Info),
        };

        if !should_flag {
            continue;
        }

        let accessor_steps: Vec<_> = graph
            .edges_to(identity.id)
            .filter(|e| e.kind == EdgeKind::HasAccessTo)
            .filter_map(|e| graph.node(e.from))
            .collect();

        if !accessor_steps.is_empty() {
            let scope_label = match scope {
                IdentityScope::Broad => "broad",
                IdentityScope::Unknown => "unknown (treat as risky)",
                IdentityScope::Constrained => "constrained",
            };

            findings.push(Finding {
                severity,
                category: FindingCategory::OverPrivilegedIdentity,
                path: None,
                nodes_involved: std::iter::once(identity.id)
                    .chain(accessor_steps.iter().map(|n| n.id))
                    .collect(),
                message: format!(
                    "{} has {} scope (permissions: '{}') — likely broader than needed",
                    identity.name, scope_label, granted_scope
                ),
                recommendation: Recommendation::ReducePermissions {
                    current: granted_scope.clone(),
                    minimum: "{ contents: read }".into(),
                },
            });
        }
    }

    findings
}

/// MVP Rule 3: Third-party action/image without SHA pin.
///
/// Deduplicates by action reference — the same action used in multiple jobs
/// produces multiple Image nodes but should only be flagged once.
pub fn unpinned_action(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for image in graph.nodes_of_kind(NodeKind::Image) {
        if image.trust_zone == TrustZone::FirstParty {
            continue;
        }

        // Container images are handled by floating_image — skip here to avoid
        // double-flagging the same node as both UnpinnedAction and FloatingImage.
        if image
            .metadata
            .get(META_CONTAINER)
            .map(|v| v == "true")
            .unwrap_or(false)
        {
            continue;
        }

        // Deduplicate: same action reference flagged once
        if !seen.insert(&image.name) {
            continue;
        }

        let has_digest = image.metadata.contains_key(META_DIGEST);

        if !has_digest && !is_sha_pinned(&image.name) {
            findings.push(Finding {
                severity: Severity::Medium,
                category: FindingCategory::UnpinnedAction,
                path: None,
                nodes_involved: vec![image.id],
                message: format!("{} is not pinned to a SHA digest", image.name),
                recommendation: Recommendation::PinAction {
                    current: image.name.clone(),
                    pinned: format!(
                        "{}@<sha256-digest>",
                        image.name.split('@').next().unwrap_or(&image.name)
                    ),
                },
            });
        }
    }

    findings
}

/// MVP Rule 4: Untrusted step has direct access to secret/identity.
pub fn untrusted_with_authority(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for step in graph.nodes_in_zone(TrustZone::Untrusted) {
        if step.kind != NodeKind::Step {
            continue;
        }

        // Check if this untrusted step directly accesses any authority source
        for edge in graph.edges_from(step.id) {
            if edge.kind != EdgeKind::HasAccessTo {
                continue;
            }

            if let Some(target) = graph.node(edge.to) {
                if matches!(target.kind, NodeKind::Secret | NodeKind::Identity) {
                    let cli_flag_exposed = target
                        .metadata
                        .get(META_CLI_FLAG_EXPOSED)
                        .map(|v| v == "true")
                        .unwrap_or(false);

                    // Platform-implicit tokens (e.g. ADO System.AccessToken) are structurally
                    // accessible to all tasks by design. Flag at Info — real but not actionable
                    // as a misconfiguration. Explicit secrets/service connections stay Critical.
                    let is_implicit = target
                        .metadata
                        .get(META_IMPLICIT)
                        .map(|v| v == "true")
                        .unwrap_or(false);

                    let recommendation = if target.kind == NodeKind::Secret {
                        if cli_flag_exposed {
                            Recommendation::Manual {
                                action: format!(
                                    "Move '{}' from -var flag to TF_VAR_{} env var — \
                                     -var values appear in pipeline logs and Terraform plan output",
                                    target.name, target.name
                                ),
                            }
                        } else {
                            Recommendation::CellosRemediation {
                                reason: format!(
                                    "Untrusted step '{}' has direct access to secret '{}'",
                                    step.name, target.name
                                ),
                                spec_hint: format!(
                                    "cellos run --network deny-all --broker env:{}",
                                    target.name
                                ),
                            }
                        }
                    } else {
                        // Identity branch — for implicit platform tokens, add a CellOS
                        // compensating-control note since the token cannot be un-injected
                        // at the platform layer.
                        let minimum = if is_implicit {
                            "minimal required scope — or use CellOS deny-all egress as a compensating control to limit exfiltration of the injected token".into()
                        } else {
                            "minimal required scope".into()
                        };
                        Recommendation::ReducePermissions {
                            current: target
                                .metadata
                                .get(META_PERMISSIONS)
                                .cloned()
                                .unwrap_or_else(|| "unknown".into()),
                            minimum,
                        }
                    };

                    let log_exposure_note = if cli_flag_exposed {
                        " (passed as -var flag — value visible in pipeline logs)"
                    } else {
                        ""
                    };

                    let (severity, message) =
                        if is_implicit {
                            (
                                Severity::Info,
                                format!(
                                "Untrusted step '{}' has structural access to implicit {} '{}' \
                                 (platform-injected — all tasks receive this token by design){}",
                                step.name,
                                if target.kind == NodeKind::Secret { "secret" } else { "identity" },
                                target.name,
                                log_exposure_note,
                            ),
                            )
                        } else {
                            (
                                Severity::Critical,
                                format!(
                                    "Untrusted step '{}' has direct access to {} '{}'{}",
                                    step.name,
                                    if target.kind == NodeKind::Secret {
                                        "secret"
                                    } else {
                                        "identity"
                                    },
                                    target.name,
                                    log_exposure_note,
                                ),
                            )
                        };

                    findings.push(Finding {
                        severity,
                        category: FindingCategory::UntrustedWithAuthority,
                        path: None,
                        nodes_involved: vec![step.id, target.id],
                        message,
                        recommendation,
                    });
                }
            }
        }
    }

    findings
}

/// MVP Rule 5: Artifact produced by privileged step consumed across trust boundary.
pub fn artifact_boundary_crossing(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for artifact in graph.nodes_of_kind(NodeKind::Artifact) {
        // Find producer(s)
        let producers: Vec<_> = graph
            .edges_to(artifact.id)
            .filter(|e| e.kind == EdgeKind::Produces)
            .filter_map(|e| graph.node(e.from))
            .collect();

        // Find consumer(s) — Consumes edges go artifact -> step
        let consumers: Vec<_> = graph
            .edges_from(artifact.id)
            .filter(|e| e.kind == EdgeKind::Consumes)
            .filter_map(|e| graph.node(e.to))
            .collect();

        for producer in &producers {
            // Only care if the producer is privileged (has access to secrets/identities)
            let producer_has_authority = graph.edges_from(producer.id).any(|e| {
                e.kind == EdgeKind::HasAccessTo
                    && graph
                        .node(e.to)
                        .map(|n| matches!(n.kind, NodeKind::Secret | NodeKind::Identity))
                        .unwrap_or(false)
            });

            if !producer_has_authority {
                continue;
            }

            for consumer in &consumers {
                if consumer.trust_zone.is_lower_than(&producer.trust_zone) {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: FindingCategory::ArtifactBoundaryCrossing,
                        path: None,
                        nodes_involved: vec![producer.id, artifact.id, consumer.id],
                        message: format!(
                            "Artifact '{}' produced by privileged step '{}' consumed by '{}' ({:?} -> {:?})",
                            artifact.name,
                            producer.name,
                            consumer.name,
                            producer.trust_zone,
                            consumer.trust_zone
                        ),
                        recommendation: Recommendation::TsafeRemediation {
                            command: format!(
                                "tsafe exec --ns {} -- <build-command>",
                                producer.name
                            ),
                            explanation: format!(
                                "Scope secrets to '{}' only; artifact '{}' should not carry authority",
                                producer.name, artifact.name
                            ),
                        },
                    });
                }
            }
        }
    }

    findings
}

/// Stretch Rule 9: Secret name matches known long-lived/static credential pattern.
///
/// Heuristic: secrets named like AWS keys, API keys, passwords, or private keys
/// are likely static credentials that should be replaced with OIDC federation.
pub fn long_lived_credential(graph: &AuthorityGraph) -> Vec<Finding> {
    const STATIC_PATTERNS: &[&str] = &[
        "AWS_ACCESS_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "_API_KEY",
        "_APIKEY",
        "_PASSWORD",
        "_PASSWD",
        "_PRIVATE_KEY",
        "_SECRET_KEY",
        "_SERVICE_ACCOUNT",
        "_SIGNING_KEY",
    ];

    let mut findings = Vec::new();

    for secret in graph.nodes_of_kind(NodeKind::Secret) {
        let upper = secret.name.to_uppercase();
        let is_static = STATIC_PATTERNS.iter().any(|p| upper.contains(p));

        if is_static {
            findings.push(Finding {
                severity: Severity::Low,
                category: FindingCategory::LongLivedCredential,
                path: None,
                nodes_involved: vec![secret.id],
                message: format!(
                    "'{}' looks like a long-lived static credential",
                    secret.name
                ),
                recommendation: Recommendation::FederateIdentity {
                    static_secret: secret.name.clone(),
                    oidc_provider: "GitHub Actions OIDC (id-token: write)".into(),
                },
            });
        }
    }

    findings
}

/// Tier 6 Rule: Container image without Docker digest pinning.
///
/// Job-level containers marked with `META_CONTAINER` that aren't pinned to
/// `image@sha256:<64hex>` can be silently mutated between runs. Deduplicates
/// by image name (same image in multiple jobs flags once).
pub fn floating_image(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for image in graph.nodes_of_kind(NodeKind::Image) {
        let is_container = image
            .metadata
            .get(META_CONTAINER)
            .map(|v| v == "true")
            .unwrap_or(false);

        if !is_container {
            continue;
        }

        if !seen.insert(image.name.as_str()) {
            continue;
        }

        if !is_docker_digest_pinned(&image.name) {
            findings.push(Finding {
                severity: Severity::Medium,
                category: FindingCategory::FloatingImage,
                path: None,
                nodes_involved: vec![image.id],
                message: format!("Container image '{}' is not pinned to a digest", image.name),
                recommendation: Recommendation::PinAction {
                    current: image.name.clone(),
                    pinned: format!(
                        "{}@sha256:<digest>",
                        image.name.split(':').next().unwrap_or(&image.name)
                    ),
                },
            });
        }
    }

    findings
}

/// Stretch Rule: checkout step with `persistCredentials: true` writes credentials to disk.
///
/// The PersistsTo edge connects a checkout step to the token it persists. Disk-resident
/// credentials are accessible to all subsequent steps (and to any process with filesystem
/// access), unlike runtime-only HasAccessTo authority which expires when the step exits.
pub fn persisted_credential(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for edge in &graph.edges {
        if edge.kind != EdgeKind::PersistsTo {
            continue;
        }

        let Some(step) = graph.node(edge.from) else {
            continue;
        };
        let Some(target) = graph.node(edge.to) else {
            continue;
        };

        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::PersistedCredential,
            path: None,
            nodes_involved: vec![step.id, target.id],
            message: format!(
                "'{}' persists '{}' to disk via persistCredentials: true — \
                 credential remains in .git/config and is accessible to all subsequent steps",
                step.name, target.name
            ),
            recommendation: Recommendation::Manual {
                action: "Remove persistCredentials: true from the checkout step. \
                         Pass credentials explicitly only to steps that need them."
                    .into(),
            },
        });
    }

    findings
}

/// Rule: dangerous trigger type (pull_request_target / pr) combined with secret/identity access.
///
/// Fires once per workflow when the graph-level `META_TRIGGER` indicates a high-risk
/// trigger and at least one step holds authority. Aggregates all involved nodes.
pub fn trigger_context_mismatch(graph: &AuthorityGraph) -> Vec<Finding> {
    let trigger = match graph.metadata.get(META_TRIGGER) {
        Some(t) => t.clone(),
        None => return Vec::new(),
    };

    let severity = match trigger.as_str() {
        "pull_request_target" => Severity::Critical,
        "pr" => Severity::High,
        _ => return Vec::new(),
    };

    // Collect steps that hold authority (HasAccessTo a Secret or Identity)
    let mut steps_with_authority: Vec<NodeId> = Vec::new();
    let mut authority_targets: Vec<NodeId> = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let mut step_holds_authority = false;
        for edge in graph.edges_from(step.id) {
            if edge.kind != EdgeKind::HasAccessTo {
                continue;
            }
            if let Some(target) = graph.node(edge.to) {
                if matches!(target.kind, NodeKind::Secret | NodeKind::Identity) {
                    step_holds_authority = true;
                    if !authority_targets.contains(&target.id) {
                        authority_targets.push(target.id);
                    }
                }
            }
        }
        if step_holds_authority {
            steps_with_authority.push(step.id);
        }
    }

    if steps_with_authority.is_empty() {
        return Vec::new();
    }

    let n = steps_with_authority.len();
    let mut nodes_involved = steps_with_authority.clone();
    nodes_involved.extend(authority_targets);

    vec![Finding {
        severity,
        category: FindingCategory::TriggerContextMismatch,
        path: None,
        nodes_involved,
        message: format!(
            "Workflow triggered by {trigger} with secret/identity access — {n} step(s) hold authority that attacker-controlled code could reach"
        ),
        recommendation: Recommendation::Manual {
            action: "Use a separate workflow triggered by workflow_run (not pull_request_target) for privileged operations, or ensure no checkout of the PR head ref occurs before secret use".into(),
        },
    }]
}

/// Rule: authority (secret/identity) flows into an opaque external workflow via DelegatesTo.
///
/// For each Step node: find all `DelegatesTo` edges to Image nodes where the trust zone
/// is not FirstParty. If the same step also has `HasAccessTo` any Secret or Identity,
/// emit one finding per delegation edge.
pub fn cross_workflow_authority_chain(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        // Collect authority sources this step holds
        let authority_nodes: Vec<&_> = graph
            .edges_from(step.id)
            .filter(|e| e.kind == EdgeKind::HasAccessTo)
            .filter_map(|e| graph.node(e.to))
            .filter(|n| matches!(n.kind, NodeKind::Secret | NodeKind::Identity))
            .collect();

        if authority_nodes.is_empty() {
            continue;
        }

        // Find each DelegatesTo edge to a non-FirstParty Image
        for edge in graph.edges_from(step.id) {
            if edge.kind != EdgeKind::DelegatesTo {
                continue;
            }
            let Some(target) = graph.node(edge.to) else {
                continue;
            };
            if target.kind != NodeKind::Image {
                continue;
            }
            if target.trust_zone == TrustZone::FirstParty {
                continue;
            }

            let severity = match target.trust_zone {
                TrustZone::Untrusted => Severity::Critical,
                TrustZone::ThirdParty => Severity::High,
                TrustZone::FirstParty => continue,
            };

            let authority_names: Vec<String> =
                authority_nodes.iter().map(|n| n.name.clone()).collect();
            let authority_label = authority_names.join(", ");

            let mut nodes_involved = vec![step.id, target.id];
            nodes_involved.extend(authority_nodes.iter().map(|n| n.id));

            findings.push(Finding {
                severity,
                category: FindingCategory::CrossWorkflowAuthorityChain,
                path: None,
                nodes_involved,
                message: format!(
                    "'{}' delegates to '{}' ({:?}) while holding authority ({}) — authority chain extends into opaque external workflow",
                    step.name, target.name, target.trust_zone, authority_label
                ),
                recommendation: Recommendation::Manual {
                    action: format!(
                        "Pin '{}' to a full SHA digest; audit what authority the called workflow receives",
                        target.name
                    ),
                },
            });
        }
    }

    findings
}

/// Rule: circular DelegatesTo chain — workflow calls itself transitively.
///
/// Iterative DFS over `DelegatesTo` edges. Detects back edges (gray → gray) and
/// collects all nodes that participate in any cycle. If any cycles exist, emits
/// a single High-severity finding listing all cycle members.
pub fn authority_cycle(graph: &AuthorityGraph) -> Vec<Finding> {
    let n = graph.nodes.len();
    if n == 0 {
        return Vec::new();
    }

    // Pre-build adjacency list for DelegatesTo edges only.
    let mut delegates_to: Vec<Vec<NodeId>> = vec![Vec::new(); n];
    for edge in &graph.edges {
        if edge.kind == EdgeKind::DelegatesTo && edge.from < n && edge.to < n {
            delegates_to[edge.from].push(edge.to);
        }
    }

    let mut color: Vec<u8> = vec![0u8; n]; // 0=white, 1=gray, 2=black
    let mut cycle_nodes: std::collections::BTreeSet<NodeId> = std::collections::BTreeSet::new();

    for start in 0..n {
        if color[start] != 0 {
            continue;
        }
        color[start] = 1;
        let mut stack: Vec<(NodeId, usize)> = vec![(start, 0)];

        loop {
            let len = stack.len();
            if len == 0 {
                break;
            }
            let (node_id, edge_idx) = stack[len - 1];
            if edge_idx < delegates_to[node_id].len() {
                stack[len - 1].1 += 1;
                let neighbor = delegates_to[node_id][edge_idx];
                if color[neighbor] == 1 {
                    // Back edge: cycle found. Collect every node between `neighbor`
                    // (the cycle start) and `node_id` (the cycle end) along the
                    // current DFS stack. All stack entries are gray by construction,
                    // so we walk the stack from `neighbor` to the top.
                    let cycle_start_idx =
                        stack.iter().position(|&(n, _)| n == neighbor).unwrap_or(0);
                    for &(n, _) in &stack[cycle_start_idx..] {
                        cycle_nodes.insert(n);
                    }
                } else if color[neighbor] == 0 {
                    color[neighbor] = 1;
                    stack.push((neighbor, 0));
                }
            } else {
                color[node_id] = 2;
                stack.pop();
            }
        }
    }

    if cycle_nodes.is_empty() {
        return Vec::new();
    }

    vec![Finding {
        severity: Severity::High,
        category: FindingCategory::AuthorityCycle,
        path: None,
        nodes_involved: cycle_nodes.into_iter().collect(),
        message:
            "Circular delegation detected — workflow calls itself transitively, creating unbounded privilege escalation paths"
                .into(),
        recommendation: Recommendation::Manual {
            action: "Break the delegation cycle — a workflow must not directly or transitively call itself".into(),
        },
    }]
}

/// Rule: privileged workflow (OIDC/federated identity) with no provenance attestation step.
///
/// Scoped to workflows that actually use OIDC/federated identity (an Identity node with
/// `META_OIDC = "true"` is present). If no node in the graph has `META_ATTESTS = "true"`,
/// emit one Info-severity finding listing the steps with HasAccessTo an OIDC identity.
pub fn uplift_without_attestation(graph: &AuthorityGraph) -> Vec<Finding> {
    // Scope: only fire when the graph has at least one OIDC-capable Identity
    let oidc_identity_ids: Vec<NodeId> = graph
        .nodes_of_kind(NodeKind::Identity)
        .filter(|n| {
            n.metadata
                .get(META_OIDC)
                .map(|v| v == "true")
                .unwrap_or(false)
        })
        .map(|n| n.id)
        .collect();

    if oidc_identity_ids.is_empty() {
        return Vec::new();
    }

    // Bail if any node already has META_ATTESTS = true
    let has_attestation = graph.nodes.iter().any(|n| {
        n.metadata
            .get(META_ATTESTS)
            .map(|v| v == "true")
            .unwrap_or(false)
    });
    if has_attestation {
        return Vec::new();
    }

    // Collect steps that have HasAccessTo an OIDC identity
    let mut steps_using_oidc: Vec<NodeId> = Vec::new();
    for edge in &graph.edges {
        if edge.kind != EdgeKind::HasAccessTo {
            continue;
        }
        if oidc_identity_ids.contains(&edge.to) && !steps_using_oidc.contains(&edge.from) {
            steps_using_oidc.push(edge.from);
        }
    }

    if steps_using_oidc.is_empty() {
        return Vec::new();
    }

    let n = steps_using_oidc.len();
    let mut nodes_involved = steps_using_oidc.clone();
    nodes_involved.extend(oidc_identity_ids);

    vec![Finding {
        severity: Severity::Info,
        category: FindingCategory::UpliftWithoutAttestation,
        path: None,
        nodes_involved,
        message: format!(
            "{n} step(s) use OIDC/federated identity but no provenance attestation step was detected — artifact integrity cannot be verified"
        ),
        recommendation: Recommendation::Manual {
            action: "Add 'actions/attest-build-provenance' after your build step (GHA) to provide SLSA provenance. See https://docs.github.com/en/actions/security-guides/using-artifact-attestations".into(),
        },
    }]
}

/// Rule: step writes to the environment gate ($GITHUB_ENV / ##vso[task.setvariable]).
///
/// Authority leaking through the environment gate propagates to subsequent steps
/// outside the explicit graph edges. Severity:
/// - Untrusted step: Critical (attacker-controlled values inject into pipeline env)
/// - Step with secret/identity access: High (secrets may leak into env)
/// - Otherwise: Medium (still a propagation risk)
pub fn self_mutating_pipeline(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let writes_gate = step
            .metadata
            .get(META_WRITES_ENV_GATE)
            .map(|v| v == "true")
            .unwrap_or(false);
        if !writes_gate {
            continue;
        }

        // Collect authority targets the step has HasAccessTo
        let authority_nodes: Vec<&_> = graph
            .edges_from(step.id)
            .filter(|e| e.kind == EdgeKind::HasAccessTo)
            .filter_map(|e| graph.node(e.to))
            .filter(|n| matches!(n.kind, NodeKind::Secret | NodeKind::Identity))
            .collect();

        let is_untrusted = step.trust_zone == TrustZone::Untrusted;
        let has_authority = !authority_nodes.is_empty();

        let severity = if is_untrusted {
            Severity::Critical
        } else if has_authority {
            Severity::High
        } else {
            Severity::Medium
        };

        let mut nodes_involved = vec![step.id];
        nodes_involved.extend(authority_nodes.iter().map(|n| n.id));

        let message = if is_untrusted {
            format!(
                "Untrusted step '{}' writes to the environment gate — attacker-controlled values can inject into subsequent steps' environment",
                step.name
            )
        } else if has_authority {
            let authority_label: Vec<String> =
                authority_nodes.iter().map(|n| n.name.clone()).collect();
            format!(
                "Step '{}' writes to the environment gate while holding authority ({}) — secrets may leak into pipeline environment",
                step.name,
                authority_label.join(", ")
            )
        } else {
            format!(
                "Step '{}' writes to the environment gate — values can propagate into subsequent steps' environment",
                step.name
            )
        };

        findings.push(Finding {
            severity,
            category: FindingCategory::SelfMutatingPipeline,
            path: None,
            nodes_involved,
            message,
            recommendation: Recommendation::Manual {
                action: "Avoid writing secrets or attacker-controlled values to $GITHUB_ENV / $GITHUB_PATH / pipeline variables. Use explicit step outputs with narrow scoping instead.".into(),
            },
        });
    }

    findings
}

/// Rule: PR-triggered pipeline performs a self checkout.
///
/// When a PR/PRT-triggered pipeline checks out the repository, attacker-controlled
/// code from the fork lands on the runner. Any subsequent step that reads workspace
/// files (which is almost all of them) can exfiltrate secrets or tamper with build
/// artifacts. Fires only when the graph has a PR-class trigger.
pub fn checkout_self_pr_exposure(graph: &AuthorityGraph) -> Vec<Finding> {
    // Only fires when the graph has a PR/PRT trigger
    let trigger = graph.metadata.get(META_TRIGGER).map(|s| s.as_str());
    let is_pr_context = matches!(trigger, Some("pr") | Some("pull_request_target"));
    if !is_pr_context {
        return vec![];
    }

    let mut findings = Vec::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        let is_checkout_self = step
            .metadata
            .get(META_CHECKOUT_SELF)
            .map(|v| v == "true")
            .unwrap_or(false);
        if !is_checkout_self {
            continue;
        }
        findings.push(Finding {
            category: FindingCategory::CheckoutSelfPrExposure,
            severity: Severity::High,
            message: format!(
                "PR-triggered pipeline checks out the repository at step '{}' — \
                 attacker-controlled code from the fork lands on the runner and is \
                 readable by all subsequent steps",
                step.name
            ),
            path: None,
            nodes_involved: vec![step.id],
            recommendation: Recommendation::Manual {
                action: "Use `persist-credentials: false` and avoid reading workspace \
                         files in subsequent privileged steps. Consider `checkout: none` \
                         for jobs that only need pipeline config, not source code."
                    .into(),
            },
        });
    }
    findings
}

/// Rule: ADO variable group consumed by a PR-triggered job.
///
/// Variable groups hold secrets scoped to pipelines. When a PR-triggered job has
/// `HasAccessTo` a Secret/Identity carrying `META_VARIABLE_GROUP = "true"`, those
/// secrets cross into an untrusted-contributor execution context.
pub fn variable_group_in_pr_job(graph: &AuthorityGraph) -> Vec<Finding> {
    // Only fires when the pipeline has a PR trigger
    let trigger = graph
        .metadata
        .get(META_TRIGGER)
        .map(|s| s.as_str())
        .unwrap_or("");
    if trigger != "pull_request_target" && trigger != "pr" {
        return Vec::new();
    }

    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let accessed_var_groups: Vec<&_> = graph
            .edges_from(step.id)
            .filter(|e| e.kind == EdgeKind::HasAccessTo)
            .filter_map(|e| graph.node(e.to))
            .filter(|n| {
                (n.kind == NodeKind::Secret || n.kind == NodeKind::Identity)
                    && n.metadata
                        .get(META_VARIABLE_GROUP)
                        .map(|v| v == "true")
                        .unwrap_or(false)
            })
            .collect();

        if !accessed_var_groups.is_empty() {
            let group_names: Vec<_> = accessed_var_groups
                .iter()
                .map(|n| n.name.as_str())
                .collect();
            findings.push(Finding {
                severity: Severity::Critical,
                category: FindingCategory::VariableGroupInPrJob,
                path: None,
                nodes_involved: std::iter::once(step.id)
                    .chain(accessed_var_groups.iter().map(|n| n.id))
                    .collect(),
                message: format!(
                    "PR-triggered step '{}' accesses variable group(s) [{}] — secrets cross into untrusted PR execution context",
                    step.name,
                    group_names.join(", ")
                ),
                recommendation: Recommendation::CellosRemediation {
                    reason: format!(
                        "PR-triggered step '{}' can exfiltrate variable group secrets via untrusted code",
                        step.name
                    ),
                    spec_hint: "cellos run --network deny-all --policy requireEgressDeclared,requireRuntimeSecretDelivery".into(),
                },
            });
        }
    }

    findings
}

/// Rule: self-hosted agent pool used by a PR-triggered pipeline that also checks out the repo.
///
/// All three factors present — self-hosted pool + PR trigger + `checkout:self` — combine to
/// allow an attacker to land malicious git hooks on the shared runner via a PR. Those hooks
/// persist across pipeline runs and execute with full pipeline authority.
pub fn self_hosted_pool_pr_hijack(graph: &AuthorityGraph) -> Vec<Finding> {
    let trigger = graph
        .metadata
        .get(META_TRIGGER)
        .map(|s| s.as_str())
        .unwrap_or("");
    if trigger != "pull_request_target" && trigger != "pr" {
        return Vec::new();
    }

    // Check if any Image node is self-hosted
    let has_self_hosted_pool = graph.nodes_of_kind(NodeKind::Image).any(|n| {
        n.metadata
            .get(META_SELF_HOSTED)
            .map(|v| v == "true")
            .unwrap_or(false)
    });

    if !has_self_hosted_pool {
        return Vec::new();
    }

    // Check if any Step does checkout:self
    let checkout_steps: Vec<&_> = graph
        .nodes_of_kind(NodeKind::Step)
        .filter(|n| {
            n.metadata
                .get(META_CHECKOUT_SELF)
                .map(|v| v == "true")
                .unwrap_or(false)
        })
        .collect();

    if checkout_steps.is_empty() {
        return Vec::new();
    }

    // All three factors present: self-hosted + PR trigger + checkout:self.
    // Collect self-hosted pool nodes for the finding.
    let pool_nodes: Vec<&_> = graph
        .nodes_of_kind(NodeKind::Image)
        .filter(|n| {
            n.metadata
                .get(META_SELF_HOSTED)
                .map(|v| v == "true")
                .unwrap_or(false)
        })
        .collect();

    let mut nodes_involved: Vec<NodeId> = pool_nodes.iter().map(|n| n.id).collect();
    nodes_involved.extend(checkout_steps.iter().map(|n| n.id));

    vec![Finding {
        severity: Severity::Critical,
        category: FindingCategory::SelfHostedPoolPrHijack,
        path: None,
        nodes_involved,
        message:
            "PR-triggered pipeline uses self-hosted agent pool with checkout:self — enables git hook injection persisting across pipeline runs on the shared runner"
                .into(),
        recommendation: Recommendation::Manual {
            action: "Run PR pipelines on Microsoft-hosted (ephemeral) agents, or disable checkout:self for PR-triggered jobs on self-hosted pools".into(),
        },
    }]
}

/// Rule: ADO service connection with broad/unknown scope and no OIDC federation,
/// reachable from a PR-triggered job.
///
/// Static credentials backing broad-scope service connections can carry
/// subscription-wide Azure RBAC. When a PR-triggered step has `HasAccessTo` one of
/// these, PR-author-controlled code can move laterally into the Azure tenant.
pub fn service_connection_scope_mismatch(graph: &AuthorityGraph) -> Vec<Finding> {
    let trigger = graph
        .metadata
        .get(META_TRIGGER)
        .map(|s| s.as_str())
        .unwrap_or("");
    if trigger != "pull_request_target" && trigger != "pr" {
        return Vec::new();
    }

    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let broad_scs: Vec<&_> = graph
            .edges_from(step.id)
            .filter(|e| e.kind == EdgeKind::HasAccessTo)
            .filter_map(|e| graph.node(e.to))
            .filter(|n| {
                n.kind == NodeKind::Identity
                    && n.metadata
                        .get(META_SERVICE_CONNECTION)
                        .map(|v| v == "true")
                        .unwrap_or(false)
                    && n.metadata
                        .get(META_OIDC)
                        .map(|v| v != "true")
                        .unwrap_or(true) // not OIDC-federated
                    && matches!(
                        n.metadata.get(META_IDENTITY_SCOPE).map(|s| s.as_str()),
                        Some("broad") | Some("Broad") | None // unknown scope is also a risk
                    )
            })
            .collect();

        for sc in &broad_scs {
            findings.push(Finding {
                severity: Severity::High,
                category: FindingCategory::ServiceConnectionScopeMismatch,
                path: None,
                nodes_involved: vec![step.id, sc.id],
                message: format!(
                    "PR-triggered step '{}' accesses service connection '{}' with broad/unknown scope and no OIDC federation — static credential may have subscription-wide Azure RBAC",
                    step.name, sc.name
                ),
                recommendation: Recommendation::CellosRemediation {
                    reason: "Broad-scope service connection reachable from PR code — CellOS egress isolation limits lateral movement even when connection cannot be immediately rescoped".into(),
                    spec_hint: "cellos run --network deny-all --policy requireEgressDeclared".into(),
                },
            });
        }
    }

    findings
}

/// ADO-only rule: a `resources.repositories[]` entry resolves against a
/// mutable target — no `ref:` field (default branch) or `refs/heads/<x>`
/// without a SHA. Whoever owns that branch can inject steps into every
/// consuming pipeline at the next run.
///
/// Pinned forms that do NOT fire:
///   - `refs/tags/<x>` — git tags (treated as immutable in practice)
///   - bare 40-char hex SHA — explicit commit pin
///   - `refs/heads/<sha>` where the trailing segment is a 40-char hex SHA
///
/// Mutable forms that DO fire:
///   - field absent — defaults to the repo's default branch
///   - `refs/heads/<branch>` with a normal branch name
///   - bare branch name (`main`, `master`, `develop`, ...)
///
/// Suppression: a repository entry declared with NO `ref:` field AND no
/// in-file consumer (`extends:`, `template: x@alias`, or `checkout: alias`)
/// is skipped. This catches purely vestigial declarations — a leftover
/// `resources.repositories[]` entry that no one references is not an active
/// attack surface. An entry with an explicit `ref: refs/heads/<x>` always
/// fires regardless of in-file usage, because the explicit branch ref
/// signals an intent to consume (the consumer is typically in an included
/// template file outside the per-file scan boundary).
pub fn template_extends_unpinned_branch(graph: &AuthorityGraph) -> Vec<Finding> {
    let raw = match graph.metadata.get(META_REPOSITORIES) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let entries: Vec<serde_json::Value> = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut findings = Vec::new();
    for entry in entries {
        let alias = match entry.get("alias").and_then(|v| v.as_str()) {
            Some(a) => a,
            None => continue,
        };
        let name = entry.get("name").and_then(|v| v.as_str()).unwrap_or(alias);
        let repo_type = entry
            .get("repo_type")
            .and_then(|v| v.as_str())
            .unwrap_or("git");
        let ref_value = entry.get("ref").and_then(|v| v.as_str());
        let used = entry.get("used").and_then(|v| v.as_bool()).unwrap_or(false);

        let classification = classify_repository_ref(ref_value);
        let resolved = match classification {
            RepositoryRefClass::Pinned => continue,
            RepositoryRefClass::DefaultBranch => {
                // Default-branch entries are only flagged when an in-file
                // consumer actually references the alias. Without an explicit
                // `ref:` and without a consumer there's no evidence the
                // declaration is active — likely vestigial.
                if !used {
                    continue;
                }
                "default branch (no ref:)".to_string()
            }
            RepositoryRefClass::MutableBranch(b) => format!("mutable branch '{b}'"),
        };

        let pinned_example = format!("ref: <40-char-sha>  # commit on {name}");
        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::TemplateExtendsUnpinnedBranch,
            path: None,
            nodes_involved: Vec::new(),
            message: format!(
                "ADO resources.repositories alias '{alias}' (type: {repo_type}, name: {name}) resolves to {resolved} — \
                 whoever owns that branch can inject steps at the next pipeline run"
            ),
            recommendation: Recommendation::PinAction {
                current: ref_value.unwrap_or("(default branch)").to_string(),
                pinned: pinned_example,
            },
        });
    }

    findings
}

/// ADO-only rule: a `resources.repositories[]` entry pins to a *feature-class*
/// branch — anything outside the platform-blessed set
/// (`main`, `master`, `release/*`, `hotfix/*`).
///
/// Strictly stronger signal than [`template_extends_unpinned_branch`]:
///
/// * `template_extends_unpinned_branch` fires on *any* mutable branch ref
///   (including `main` and `master`) — the abstract "ref isn't pinned to a
///   SHA or tag" finding.
/// * This rule fires only on the subset that's *worse than main*: a developer
///   feature branch (`feature/*`, `topic/*`, `dev/*`, `wip/*`, `users/*`,
///   `develop`, …) where push protection is typically weaker than the trunk.
///
/// The two findings co-fire intentionally — they describe different angles of
/// the same risk class. `template_extends_unpinned_branch` says "this isn't
/// pinned"; this rule adds "and the branch it points to is one any developer
/// can push to without a code review gate".
///
/// Detection inputs are identical to `template_extends_unpinned_branch`:
/// `META_REPOSITORIES` JSON array, with the same `used` suppression for
/// `ref`-absent entries.
///
/// Pinned forms (40-char SHA, `refs/tags/<x>`, `refs/heads/<sha>`) do not
/// fire — same classification helper as the parent rule.
///
/// Default-branch (no-`ref:`) entries do not fire from this rule. The default
/// branch is conventionally `main`/`master`, and even when it's something
/// else the *implicit* default-branch contract carries less risk than an
/// explicit feature-branch pin (the default branch usually has the strongest
/// protection in the org). The plain "this isn't pinned" surface is left to
/// `template_extends_unpinned_branch`.
pub fn template_repo_ref_is_feature_branch(graph: &AuthorityGraph) -> Vec<Finding> {
    let raw = match graph.metadata.get(META_REPOSITORIES) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let entries: Vec<serde_json::Value> = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut findings = Vec::new();
    for entry in entries {
        let alias = match entry.get("alias").and_then(|v| v.as_str()) {
            Some(a) => a,
            None => continue,
        };
        let name = entry.get("name").and_then(|v| v.as_str()).unwrap_or(alias);
        let repo_type = entry
            .get("repo_type")
            .and_then(|v| v.as_str())
            .unwrap_or("git");
        let ref_value = entry.get("ref").and_then(|v| v.as_str());

        // Only explicit refs are candidates here — the parent rule covers the
        // ref-absent case via the default-branch path.
        let branch = match classify_repository_ref(ref_value) {
            RepositoryRefClass::MutableBranch(b) => b,
            RepositoryRefClass::Pinned | RepositoryRefClass::DefaultBranch => continue,
        };

        if !is_feature_class_branch(&branch) {
            continue;
        }

        let pinned_example = format!("ref: <40-char-sha>  # commit on {name}");
        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::TemplateRepoRefIsFeatureBranch,
            path: None,
            nodes_involved: Vec::new(),
            message: format!(
                "ADO resources.repositories alias '{alias}' (type: {repo_type}, name: {name}) is pinned to feature-class branch '{branch}' — \
                 weaker than even an unpinned trunk pin: any developer with write access to that branch can inject pipeline steps without a code review on main"
            ),
            recommendation: Recommendation::PinAction {
                current: ref_value.unwrap_or("(default branch)").to_string(),
                pinned: pinned_example,
            },
        });
    }

    findings
}

/// Returns `true` for ADO branch names that are *not* part of the
/// platform-blessed trunk/release set. The blessed set:
///
///   - `main`, `master`
///   - `release/*`, `releases/*`
///   - `hotfix/*`, `hotfixes/*`
///
/// Everything else — `feature/*`, `topic/*`, `dev/*`, `wip/*`, `users/*`,
/// `develop`, ad-hoc names — is treated as feature-class.
///
/// Comparison is case-insensitive and prefix-stripped of any leading
/// `refs/heads/` (the [`classify_repository_ref`] caller already strips it,
/// but defensive normalisation keeps this helper standalone-testable).
fn is_feature_class_branch(branch: &str) -> bool {
    let normalised = branch
        .trim()
        .trim_start_matches("refs/heads/")
        .to_ascii_lowercase();

    if normalised.is_empty() {
        return false;
    }

    // Exact-match trunk names.
    if matches!(normalised.as_str(), "main" | "master") {
        return false;
    }

    // Prefix-match release / hotfix branches (with or without trailing slash).
    const TRUNK_PREFIXES: &[&str] = &["release/", "releases/", "hotfix/", "hotfixes/"];
    for p in TRUNK_PREFIXES {
        if normalised == p.trim_end_matches('/') || normalised.starts_with(p) {
            return false;
        }
    }

    true
}

// ── Command-line credential leakage helpers ─────────────
//
// These two rules (`vm_remote_exec_via_pipeline_secret`,
// `short_lived_sas_in_command_line`) inspect inline script bodies stamped on
// Step nodes by the parser as `META_SCRIPT_BODY`. They are intentionally
// heuristic — the goal is reliable detection of the corpus pattern, not 100%
// false-positive cleanliness. They're allowed to co-fire on the same step:
// each describes a different angle of the same risk class.

/// Names of the Azure VM remote-execution primitives we care about.
/// Match is case-insensitive on the script body.
const VM_REMOTE_EXEC_TOKENS: &[&str] = &[
    "set-azvmextension",
    "invoke-azvmruncommand",
    "az vm run-command",
    "az vm extension set",
];

/// Substrings that indicate a SAS token has just been minted in this script.
/// Match is case-insensitive on the script body.
const SAS_MINT_TOKENS: &[&str] = &[
    "new-azstoragecontainersastoken",
    "new-azstorageblobsastoken",
    "new-azstorageaccountsastoken",
    "az storage container generate-sas",
    "az storage blob generate-sas",
    "az storage account generate-sas",
];

/// Argument-passing keywords that put a value on the process command line and
/// thus into ARM extension status / OS process logs.
const COMMAND_LINE_SINK_TOKENS: &[&str] = &[
    "commandtoexecute",
    "scriptarguments",
    "--arguments",
    "-argumentlist",
    "--scripts",
    "-scriptstring",
];

/// Returns the names of pipeline secret/SAS variables (`$(NAME)`) that the
/// step references via `HasAccessTo` a Secret. Used to spot interpolation of
/// pipeline secrets into command-line strings.
fn step_secret_var_names(graph: &AuthorityGraph, step_id: NodeId) -> Vec<&str> {
    graph
        .edges_from(step_id)
        .filter(|e| e.kind == EdgeKind::HasAccessTo)
        .filter_map(|e| graph.node(e.to))
        .filter(|n| n.kind == NodeKind::Secret)
        .map(|n| n.name.as_str())
        .collect()
}

/// Returns the names of all Secret nodes a step has `HasAccessTo`.
/// Used by the script-aware ADO rules to constrain pattern matches to
/// `$(VAR)` references that actually resolve to secrets in this graph.
fn step_secret_names(graph: &AuthorityGraph, step_id: NodeId) -> Vec<String> {
    graph
        .edges_from(step_id)
        .filter(|e| e.kind == EdgeKind::HasAccessTo)
        .filter_map(|e| graph.node(e.to))
        .filter(|n| n.kind == NodeKind::Secret)
        .map(|n| n.name.clone())
        .collect()
}

/// Heuristic: returns true if a value-bearing variable named `var_name` appears
/// to be interpolated into `script_body` (PowerShell `$var` / `"$var"` /
/// `` `"$var`" `` form, or ADO `$(var)` form). Case-insensitive.
fn body_interpolates_var(script_body: &str, var_name: &str) -> bool {
    if var_name.is_empty() {
        return false;
    }
    let body = script_body.to_lowercase();
    let name = var_name.to_lowercase();
    // ADO macro form
    let dollar_paren = format!("$({name})");
    if body.contains(&dollar_paren) {
        return true;
    }
    // PowerShell variable form: must be followed by a non-identifier char to
    // avoid matching `$varSomething` as `$var`.
    let needle = format!("${name}");
    let mut search_from = 0usize;
    while let Some(pos) = body[search_from..].find(&needle) {
        let abs = search_from + pos;
        let end = abs + needle.len();
        let next = body.as_bytes().get(end).copied();
        let is_word = matches!(next, Some(c) if c.is_ascii_alphanumeric() || c == b'_');
        if !is_word {
            return true;
        }
        search_from = end;
    }
    false
}

/// Returns true if `script` contains `$(secret)` and that occurrence sits on
/// a line whose left-hand side looks like a shell-variable assignment:
///   - `export FOO=$(SECRET)`
///   - `FOO="$(SECRET)"`
///   - `$X = "$(SECRET)"` / `$env:X = "$(SECRET)"`
///   - `set -a` followed by an assignment is a softer signal but still flagged
///
/// Returns false when `$(secret)` is part of a command-line argument
/// (e.g. `terraform plan -var "k=$(SECRET)"`) — that's covered by other rules.
fn script_assigns_secret_to_shell_var(script: &str, secret: &str) -> bool {
    let needle = format!("$({secret})");
    for line in script.lines() {
        if !line.contains(&needle) {
            continue;
        }
        // Strip everything from `$(secret)` rightward — we only inspect what
        // comes before it on this line.
        let lhs = match line.find(&needle) {
            Some(pos) => &line[..pos],
            None => continue,
        };
        let trimmed = lhs.trim_start();

        // bash/sh: `export VAR=`, `VAR=`, `set VAR=`, `declare VAR=`
        // Look for `<word>=` (no space allowed before `=`) and no leading
        // command pipe / non-assignment indicator.
        if matches_bash_assignment(trimmed) {
            return true;
        }

        // PowerShell: `$VAR = "..."`, `$env:VAR = "..."`, `${VAR} = "..."`,
        // `Set-Variable -Name X -Value "$(SECRET)"`.
        if matches_powershell_assignment(trimmed) {
            return true;
        }
    }
    false
}

/// Returns true if `body` contains any of the SAS-mint token substrings.
fn body_mints_sas(body_lower: &str) -> bool {
    SAS_MINT_TOKENS.iter().any(|t| body_lower.contains(t))
}

/// Returns true if `body` contains any of the VM remote-exec tool substrings.
fn body_uses_vm_remote_exec(body_lower: &str) -> bool {
    VM_REMOTE_EXEC_TOKENS.iter().any(|t| body_lower.contains(t))
}

/// Returns true if `body` contains any command-line sink keyword.
fn body_has_cmdline_sink(body_lower: &str) -> bool {
    COMMAND_LINE_SINK_TOKENS
        .iter()
        .any(|t| body_lower.contains(t))
}

/// Extract names of PowerShell variables that are bound to a SAS-mint result.
/// Pattern: `$<name> = New-AzStorage...SASToken ...` (case-insensitive).
/// Returns the variable names without the leading `$`.
fn powershell_sas_assignments(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = body.to_lowercase();
    let bytes = lower.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            i += 1;
            continue;
        }
        // Read identifier
        let name_start = i + 1;
        let mut j = name_start;
        while j < bytes.len() {
            let c = bytes[j];
            if c.is_ascii_alphanumeric() || c == b'_' {
                j += 1;
            } else {
                break;
            }
        }
        if j == name_start {
            i += 1;
            continue;
        }
        // Skip whitespace, then expect `=`
        let mut k = j;
        while k < bytes.len() && (bytes[k] == b' ' || bytes[k] == b'\t') {
            k += 1;
        }
        if k >= bytes.len() || bytes[k] != b'=' {
            i = j;
            continue;
        }
        // Skip `=` and whitespace
        k += 1;
        while k < bytes.len() && (bytes[k] == b' ' || bytes[k] == b'\t') {
            k += 1;
        }
        // Look at the rest of this logical line (until `\n`).
        let line_end = lower[k..].find('\n').map(|p| k + p).unwrap_or(bytes.len());
        let rhs = &lower[k..line_end];
        if SAS_MINT_TOKENS.iter().any(|t| rhs.contains(t)) {
            // Recover original-case variable name from `body` at the same byte
            // offsets — `lower` and `body` share UTF-8 byte layout for ASCII,
            // and identifiers in PowerShell are ASCII in the corpus.
            let name = body
                .get(name_start..j)
                .unwrap_or(&lower[name_start..j])
                .to_string();
            if !out.iter().any(|n: &String| n.eq_ignore_ascii_case(&name)) {
                out.push(name);
            }
        }
        i = j;
    }
    out
}

/// Rule: pipeline step uses an Azure VM remote-execution primitive
/// (Set-AzVMExtension/CustomScriptExtension, Invoke-AzVMRunCommand,
/// `az vm run-command invoke`, `az vm extension set`) where the executed
/// command line is constructed from a pipeline secret or a freshly-minted
/// SAS token.
///
/// Pipeline-to-VM lateral movement primitive: every pipeline run can RCE every
/// VM in scope, and the SAS/secret embedded in the command line is logged in
/// plaintext on the VM and in the ARM extension status JSON.
///
/// Detection: read each Step's `META_SCRIPT_BODY`. If the body contains a
/// remote-exec tool name AND (it interpolates a known pipeline secret variable
/// OR it mints a SAS token in the same body), fire one finding per step.
pub fn vm_remote_exec_via_pipeline_secret(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let body = match step.metadata.get(META_SCRIPT_BODY) {
            Some(b) if !b.is_empty() => b,
            _ => continue,
        };
        let body_lower = body.to_lowercase();
        if !body_uses_vm_remote_exec(&body_lower) {
            continue;
        }

        let secret_names = step_secret_var_names(graph, step.id);
        let secret_interpolated = secret_names
            .iter()
            .any(|name| body_interpolates_var(body, name));
        let mints_sas = body_mints_sas(&body_lower);

        if !secret_interpolated && !mints_sas {
            continue;
        }

        // Pick a single tool name for the message.
        let tool = VM_REMOTE_EXEC_TOKENS
            .iter()
            .find(|t| body_lower.contains(*t))
            .copied()
            .unwrap_or("Set-AzVMExtension");

        let trigger = if secret_interpolated {
            "interpolating a pipeline secret into the executed command line"
        } else {
            "embedding a freshly-minted SAS token into the executed command line"
        };

        let mut nodes_involved = vec![step.id];
        // Include the secret nodes the step has access to so consumers can
        // attribute the finding to the leaked credential.
        for edge in graph.edges_from(step.id) {
            if edge.kind == EdgeKind::HasAccessTo {
                if let Some(n) = graph.node(edge.to) {
                    if n.kind == NodeKind::Secret {
                        nodes_involved.push(n.id);
                    }
                }
            }
        }

        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::VmRemoteExecViaPipelineSecret,
            path: None,
            nodes_involved,
            message: format!(
                "Step '{}' uses {} {} — pipeline-to-VM RCE primitive; credential is logged on the VM and in ARM extension status",
                step.name, tool, trigger
            ),
            recommendation: Recommendation::Manual {
                action: "Stage the script on the VM and pass the SAS via env var or protectedSettings (encrypted, not logged); avoid embedding secrets in commandToExecute".into(),
            },
        });
    }

    findings
}

/// Heuristic: line prefix looks like a bash/sh assignment to an env var.
/// Conservative — only matches when the LHS contains `<keyword>? IDENT=` and
/// nothing after the `=` other than optional opening quote characters.
fn matches_bash_assignment(lhs: &str) -> bool {
    // `export FOO=`, `declare FOO=`, `local FOO=`, `readonly FOO=`, plain `FOO=`
    let after_keyword = strip_one_of(lhs, &["export ", "declare ", "local ", "readonly "])
        .unwrap_or(lhs)
        .trim_start();
    // Allow trailing opening-quote characters between `=` and the secret ref.
    let trimmed = after_keyword.trim_end_matches(['"', '\'']);
    let Some(ident) = trimmed.strip_suffix('=') else {
        return false;
    };
    !ident.is_empty()
        && ident.chars().all(is_shell_var_char)
        && !ident.starts_with(|c: char| c.is_ascii_digit())
}

/// Heuristic: line prefix looks like a PowerShell assignment.
fn matches_powershell_assignment(lhs: &str) -> bool {
    // Strip trailing opening quote and whitespace so `$x = "$(SECRET)` matches.
    let trimmed = lhs.trim_end().trim_end_matches(['"', '\'']).trim_end();
    if let Some(before_eq) = trimmed.strip_suffix('=') {
        let before_eq = before_eq.trim_end();
        if before_eq.starts_with('$') {
            return true;
        }
    }
    // `Set-Variable ... -Value`
    if trimmed.contains("Set-Variable") && trimmed.contains("-Value") {
        return true;
    }
    false
}

fn is_shell_var_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn strip_one_of<'a>(s: &'a str, prefixes: &[&str]) -> Option<&'a str> {
    for p in prefixes {
        if let Some(rest) = s.strip_prefix(p) {
            return Some(rest);
        }
    }
    None
}

/// Rule: pipeline secret exported via shell variable inside an inline script.
///
/// Severity: High. ADO masks the literal token `$(SECRET)` when it appears in
/// log output, but masking happens on the rendered command string before the
/// shell runs. Once the value is bound to a shell variable, downstream
/// transcripts (`Start-Transcript`, `bash -x`, terraform `TF_LOG=DEBUG`,
/// `az --debug`) print the cleartext.
pub fn secret_to_inline_script_env_export(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let Some(script) = step.metadata.get(META_SCRIPT_BODY) else {
            continue;
        };
        if script.is_empty() {
            continue;
        }
        let secrets = step_secret_names(graph, step.id);
        let exposed: Vec<String> = secrets
            .into_iter()
            .filter(|s| script_assigns_secret_to_shell_var(script, s))
            .collect();

        if exposed.is_empty() {
            continue;
        }

        let n = exposed.len();
        let preview: String = exposed
            .iter()
            .take(3)
            .map(|s| format!("$({s})"))
            .collect::<Vec<_>>()
            .join(", ");
        let suffix = if n > 3 {
            format!(", and {} more", n - 3)
        } else {
            String::new()
        };
        let secret_node_ids: Vec<NodeId> = graph
            .edges_from(step.id)
            .filter(|e| e.kind == EdgeKind::HasAccessTo)
            .filter_map(|e| graph.node(e.to))
            .filter(|n| n.kind == NodeKind::Secret && exposed.contains(&n.name))
            .map(|n| n.id)
            .collect();

        let mut nodes_involved = vec![step.id];
        nodes_involved.extend(secret_node_ids);

        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::SecretToInlineScriptEnvExport,
            path: None,
            nodes_involved,
            message: format!(
                "Step '{}' assigns pipeline secret(s) {preview}{suffix} to shell variables inside an inline script — once bound to a variable the value bypasses ADO's $(SECRET) log mask and will appear in any transcript (Start-Transcript, bash -x, terraform/az --debug)",
                step.name
            ),
            recommendation: Recommendation::TsafeRemediation {
                command: "tsafe exec --ns <scoped-namespace> -- <command>".to_string(),
                explanation: "Inject the secret as an env var on the step itself (ADO `env:` block) instead of materialising it inside the script body. The value still reaches the process but never travels through a shell variable assignment that transcripts can capture.".to_string(),
            },
        });
    }

    findings
}

/// How a `resources.repositories[].ref` value resolves for the purposes of
/// the `template_extends_unpinned_branch` rule.
enum RepositoryRefClass {
    /// SHA-pinned, tag-pinned — code at the consumer is immutable.
    Pinned,
    /// No `ref:` field — resolves to the repo's default branch.
    DefaultBranch,
    /// `refs/heads/<name>` or bare branch — mutable.
    MutableBranch(String),
}

fn classify_repository_ref(ref_value: Option<&str>) -> RepositoryRefClass {
    let raw = match ref_value {
        None => return RepositoryRefClass::DefaultBranch,
        Some(s) if s.trim().is_empty() => return RepositoryRefClass::DefaultBranch,
        Some(s) => s.trim(),
    };

    // Bare 40+ hex SHA — pinned.
    if is_hex_sha(raw) {
        return RepositoryRefClass::Pinned;
    }

    // refs/tags/<x> — pinned.
    if let Some(tag) = raw.strip_prefix("refs/tags/") {
        if !tag.is_empty() {
            return RepositoryRefClass::Pinned;
        }
    }

    // refs/heads/<x> — mutable, unless trailing segment is a SHA.
    if let Some(branch) = raw.strip_prefix("refs/heads/") {
        if is_hex_sha(branch) {
            return RepositoryRefClass::Pinned;
        }
        return RepositoryRefClass::MutableBranch(branch.to_string());
    }

    // Bare value — treat as a branch name.
    RepositoryRefClass::MutableBranch(raw.to_string())
}

fn is_hex_sha(s: &str) -> bool {
    s.len() >= 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Rule: a SAS token minted in-pipeline is passed as a CLI argument or
/// interpolated into `commandToExecute` / `scriptArguments` / `--arguments` /
/// `-ArgumentList` rather than via env var or stdin.
///
/// Even short-lived SAS tokens in argv hit Linux `/proc/*/cmdline`, Windows
/// ETW process-create events, and ARM extension status — logged for the
/// SAS lifetime.
///
/// Detection: read each Step's `META_SCRIPT_BODY`. Body must (a) mint a SAS
/// token AND (b) reference a command-line sink keyword. Heuristic acceptable:
/// the goal is to catch the corpus pattern, not perfect specificity.
pub fn short_lived_sas_in_command_line(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let body = match step.metadata.get(META_SCRIPT_BODY) {
            Some(b) if !b.is_empty() => b,
            _ => continue,
        };
        let body_lower = body.to_lowercase();

        if !body_mints_sas(&body_lower) {
            continue;
        }
        if !body_has_cmdline_sink(&body_lower) {
            continue;
        }

        // Tighten precision: at least one minted-SAS variable must actually
        // appear interpolated somewhere in the script body. This filters out
        // scripts that mint a SAS purely for upload-to-blob and never put it
        // on argv.
        let sas_vars = powershell_sas_assignments(body);
        let mut interpolated_var: Option<String> = None;
        for v in &sas_vars {
            if body_interpolates_var(body, v) {
                interpolated_var = Some(v.clone());
                break;
            }
        }
        // If we couldn't bind a SAS var (e.g. inline `az`-CLI subshell), fall
        // back to "mint+sink in same script" — still better than no signal.
        let evidence = interpolated_var
            .as_deref()
            .map(|v| format!("$ {v} interpolated into argv"))
            .unwrap_or_else(|| "SAS-mint and command-line sink in same script".to_string());

        findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::ShortLivedSasInCommandLine,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Step '{}' mints a SAS token and passes it on the command line ({}) — argv lands in /proc, ETW, and ARM extension status for the token's lifetime",
                step.name, evidence
            ),
            recommendation: Recommendation::Manual {
                action: "Pass the SAS via env var, stdin, or VM-extension protectedSettings; never put SAS tokens in commandToExecute / --arguments / -ArgumentList".into(),
            },
        });
    }

    findings
}

/// Returns true if `line` contains a sink that writes its left-hand-side
/// content to a file path. Recognises the common bash and PowerShell
/// "write to file" idioms.
fn line_writes_to_file(line: &str) -> bool {
    // bash: `>`, `>>`, `tee`, `cat <<`/`<<-` heredoc redirected with `>`
    if line.contains(" > ")
        || line.contains(" >> ")
        || line.contains(">/")
        || line.contains(">>/")
        || line.contains("| tee ")
        || line.contains("| tee -")
        || line.starts_with("tee ")
    {
        return true;
    }
    // PowerShell: Out-File, Set-Content, Add-Content, [IO.File]::WriteAllText
    let lower = line.to_lowercase();
    if lower.contains("out-file")
        || lower.contains("set-content")
        || lower.contains("add-content")
        || lower.contains("writealltext")
        || lower.contains("writealllines")
    {
        return true;
    }
    false
}

/// Returns true if `line` references a workspace path or a config-file
/// extension we consider risky for secret materialisation.
fn line_references_workspace_path(line: &str) -> bool {
    let lower = line.to_lowercase();
    if lower.contains("$(system.defaultworkingdirectory)")
        || lower.contains("$(build.sourcesdirectory)")
        || lower.contains("$(pipeline.workspace)")
        || lower.contains("$(agent.builddirectory)")
        || lower.contains("$(agent.tempdirectory)")
    {
        return true;
    }
    // Common credential / config file extensions
    const RISKY_EXT: &[&str] = &[
        ".tfvars",
        ".env",
        ".hcl",
        ".pfx",
        ".key",
        ".pem",
        ".crt",
        ".p12",
        ".kubeconfig",
        ".jks",
        ".keystore",
    ];
    RISKY_EXT.iter().any(|ext| lower.contains(ext))
}

/// Heuristic: returns true if `script` materialises `secret` to a workspace
/// file. Looks for a single line that contains the secret reference AND a
/// "write to file" sink AND a workspace/credfile path target.
///
/// Also detects the heredoc + Out-File pattern across multiple lines:
/// the secret appears inside a `@" ... "@` block whose final pipe is
/// `Out-File <workspace-path>`.
fn script_materialises_secret_to_file(script: &str, secret: &str) -> bool {
    let needle = format!("$({secret})");

    // Pass 1: single-line write. Catches `echo $(SECRET) > /tmp/x.env`,
    // `Out-File ... $(SECRET) ...`, etc.
    for line in script.lines() {
        if line.contains(&needle)
            && line_writes_to_file(line)
            && line_references_workspace_path(line)
        {
            return true;
        }
    }

    // Pass 2: PowerShell pattern `$X = "$(SECRET)"` followed by the variable
    // being piped into Out-File / Set-Content with a workspace path. We
    // detect this conservatively: if any line assigns `$x = "$(SECRET)"`
    // AND any *later* line both writes-to-file and references a workspace
    // path, we flag it. False-positive risk is low because the ASLR-style
    // `$x` typically won't be reused for unrelated content within the same
    // inline block.
    let mut secret_bound_to_var = false;
    for line in script.lines() {
        let trimmed = line.trim();
        if !secret_bound_to_var
            && trimmed.contains(&needle)
            && trimmed.starts_with('$')
            && trimmed.contains('=')
        {
            secret_bound_to_var = true;
            continue;
        }
        if secret_bound_to_var && line_writes_to_file(line) && line_references_workspace_path(line)
        {
            return true;
        }
    }

    false
}

/// Rule: pipeline secret materialised to a file under the agent workspace.
///
/// Severity: High. Files written under `$(System.DefaultWorkingDirectory)` /
/// `$(Build.SourcesDirectory)` survive the writing step's lifetime, are
/// uploaded by `PublishPipelineArtifact` tasks (sometimes accidentally), and
/// remain readable by every subsequent step in the same job.
pub fn secret_materialised_to_workspace_file(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let Some(script) = step.metadata.get(META_SCRIPT_BODY) else {
            continue;
        };
        if script.is_empty() {
            continue;
        }
        let secrets = step_secret_names(graph, step.id);
        let materialised: Vec<String> = secrets
            .into_iter()
            .filter(|s| script_materialises_secret_to_file(script, s))
            .collect();

        if materialised.is_empty() {
            continue;
        }

        let n = materialised.len();
        let preview: String = materialised
            .iter()
            .take(3)
            .map(|s| format!("$({s})"))
            .collect::<Vec<_>>()
            .join(", ");
        let suffix = if n > 3 {
            format!(", and {} more", n - 3)
        } else {
            String::new()
        };

        let secret_node_ids: Vec<NodeId> = graph
            .edges_from(step.id)
            .filter(|e| e.kind == EdgeKind::HasAccessTo)
            .filter_map(|e| graph.node(e.to))
            .filter(|n| n.kind == NodeKind::Secret && materialised.contains(&n.name))
            .map(|n| n.id)
            .collect();

        let mut nodes_involved = vec![step.id];
        nodes_involved.extend(secret_node_ids);

        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::SecretMaterialisedToWorkspaceFile,
            path: None,
            nodes_involved,
            message: format!(
                "Step '{}' writes pipeline secret(s) {preview}{suffix} to a file under the agent workspace — the file persists for the rest of the job, is readable by every subsequent step, and may be uploaded by PublishPipelineArtifact",
                step.name
            ),
            recommendation: Recommendation::Manual {
                action: "Replace inline secret materialisation with the `secureFile` task (downloaded to a temp dir with 0600 perms and auto-deleted), or pass the secret to the consuming tool over stdin / an env var instead of via a workspace file. If a file is unavoidable, write under `$(Agent.TempDirectory)` and `chmod 600` immediately.".into(),
            },
        });
    }

    findings
}

/// Returns true if `script` contains a Key Vault → plaintext extraction
/// pattern that lands the secret in a non-`SecureString` variable.
fn script_extracts_keyvault_to_plaintext(script: &str) -> bool {
    let lower = script.to_lowercase();
    // New syntax: Get-AzKeyVaultSecret ... -AsPlainText
    if lower.contains("get-azkeyvaultsecret") && lower.contains("-asplaintext") {
        return true;
    }
    // ConvertFrom-SecureString ... -AsPlainText (PS 7+) — flat plaintext extraction
    if lower.contains("convertfrom-securestring") && lower.contains("-asplaintext") {
        return true;
    }
    // Old syntax: ($x = (Get-AzKeyVaultSecret ...).SecretValueText)
    if lower.contains("get-azkeyvaultsecret") && lower.contains(".secretvaluetext") {
        return true;
    }
    // Even older: BSTR pattern — ConvertToString on PtrToStringAuto
    if lower.contains("get-azkeyvaultsecret") && lower.contains("ptrtostringauto") {
        return true;
    }
    false
}

/// Rule: PowerShell pulls a Key Vault secret as plaintext inside an inline
/// script. The value never crosses the ADO variable-group boundary so
/// pipeline log masking does not apply — verbose `Az` / PowerShell logging
/// (`Set-PSDebug -Trace`, `$VerbosePreference = "Continue"`, error stack
/// traces) will print the cleartext credential.
///
/// Severity: Medium. Lower than the materialisation rules because the value
/// is at least kept in process memory (vs. on disk), but still a real
/// exposure path that pipeline-level secret rotation alone does not fix.
pub fn keyvault_secret_to_plaintext(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let Some(script) = step.metadata.get(META_SCRIPT_BODY) else {
            continue;
        };
        if script.is_empty() {
            continue;
        }
        if !script_extracts_keyvault_to_plaintext(script) {
            continue;
        }

        findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::KeyVaultSecretToPlaintext,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Step '{}' extracts a Key Vault secret as plaintext inside an inline script (-AsPlainText / .SecretValueText) — value bypasses ADO variable-group masking and is printed by Az verbose logging or any error stack trace",
                step.name
            ),
            recommendation: Recommendation::Manual {
                action: "Keep the secret as a `SecureString`: drop `-AsPlainText`, pass the SecureString directly to cmdlets that accept it (e.g. `New-PSCredential`, `Connect-AzAccount -ServicePrincipal -Credential ...`), and only convert to plaintext at the moment of consumption, scoped to a single expression. For values that must be plaintext (REST calls, env vars) prefer ADO variable groups linked to Key Vault — the value then participates in pipeline log masking.".into(),
            },
        });
    }

    findings
}

/// Returns true when `name` (case-insensitive) looks like a production
/// service-connection name. Matches `prod` / `production` / `prd` either as
/// the entire name, a token surrounded by `-`/`_`, or a leading/trailing
/// segment (`prod-foo`, `foo-prd`). Conservative: avoids matching
/// substrings like "approver" or "reproduce".
fn looks_like_prod_connection(name: &str) -> bool {
    let lower = name.to_lowercase();
    let token_match = |s: &str| {
        lower == s
            || lower.contains(&format!("-{s}-"))
            || lower.contains(&format!("_{s}_"))
            || lower.ends_with(&format!("-{s}"))
            || lower.ends_with(&format!("_{s}"))
            || lower.starts_with(&format!("{s}-"))
            || lower.starts_with(&format!("{s}_"))
    };
    token_match("prod") || token_match("production") || token_match("prd")
}

/// Returns true when an inline script body looks like it laundering federated
/// SPN/OIDC token material into a pipeline variable via
/// `##vso[task.setvariable]`. Used to escalate addspn_with_inline_script's
/// message wording when explicit laundering is detected.
fn script_launders_spn_token(s: &str) -> bool {
    let lower = s.to_lowercase();
    if !lower.contains("##vso[task.setvariable") {
        return false;
    }
    let token_markers = [
        "$env:idtoken",
        "$env:serviceprincipalkey",
        "$env:serviceprincipalid",
        "$env:tenantid",
        "arm_oidc_token",
        "arm_client_id",
        "arm_client_secret",
        "arm_tenant_id",
    ];
    token_markers.iter().any(|m| lower.contains(m))
}

/// Rule: `terraform apply -auto-approve` against a production service
/// connection without an environment approval gate.
///
/// Combines three signals on a Step node:
///   1. `META_TERRAFORM_AUTO_APPROVE` = "true" (set by the parser when an
///      inline script runs `terraform apply --auto-approve`, or a
///      `TerraformCLI@N` task has `command: apply` + commandOptions
///      containing `auto-approve`).
///   2. `META_SERVICE_CONNECTION_NAME` matches a production-named pattern
///      (`prod`, `production`, `prd`), OR the step is linked via
///      `HasAccessTo` to an Identity service-connection node whose name
///      matches that pattern.
///   3. The step is NOT inside an `environment:`-bound deployment job
///      (parser sets `META_ENV_APPROVAL` for those steps).
///
/// Severity: Critical. Bypasses the only ADO-side change-control on
/// infra rewrites.
pub fn terraform_auto_approve_in_prod(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let auto_approve = step
            .metadata
            .get(META_TERRAFORM_AUTO_APPROVE)
            .map(|v| v == "true")
            .unwrap_or(false);
        if !auto_approve {
            continue;
        }

        // Step's own service-connection name (set by parser from
        // azureSubscription / connectedServiceName / etc).
        let direct_conn = step.metadata.get(META_SERVICE_CONNECTION_NAME).cloned();

        // Walk HasAccessTo edges to find a service-connection Identity. This
        // catches steps that don't carry the name on themselves but inherit
        // an Identity node via the parser's edge.
        let edge_conn = graph
            .edges_from(step.id)
            .filter(|e| e.kind == EdgeKind::HasAccessTo)
            .filter_map(|e| graph.node(e.to))
            .find(|n| {
                n.kind == NodeKind::Identity
                    && n.metadata
                        .get(META_SERVICE_CONNECTION)
                        .map(|v| v == "true")
                        .unwrap_or(false)
            })
            .map(|n| n.name.clone());

        let conn_name = match direct_conn.or(edge_conn) {
            Some(n) if looks_like_prod_connection(&n) => n,
            _ => continue,
        };

        // Skip when the step is in an environment-gated job — the manual
        // approval is the change-control we're worried about being missing.
        let env_gated = step
            .metadata
            .get(META_ENV_APPROVAL)
            .map(|v| v == "true")
            .unwrap_or(false);
        if env_gated {
            continue;
        }

        findings.push(Finding {
            severity: Severity::Critical,
            category: FindingCategory::TerraformAutoApproveInProd,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Step '{}' runs `terraform apply -auto-approve` against production service connection '{}' with no environment approval gate — any committer can rewrite prod infrastructure",
                step.name, conn_name
            ),
            recommendation: Recommendation::Manual {
                action: "Move the apply step into a deployment job whose `environment:` is configured with required approvers in ADO, OR remove `-auto-approve` and run apply behind a manual checkpoint task. Combine with a non-shared agent pool so committers cannot pre-stage payloads.".into(),
            },
        });
    }

    findings
}

/// Rule: `AzureCLI@2` task with `addSpnToEnvironment: true` AND an inline
/// script body. The inline script can launder federated SPN material
/// (`$env:idToken`, `$env:servicePrincipalKey`, `$env:tenantId`) into normal
/// pipeline variables via `##vso[task.setvariable]`, leaking OIDC tokens to
/// downstream tasks/artifacts un-masked.
///
/// Severity: High. Escalates message wording when the script body contains
/// explicit laundering patterns (`##vso[task.setvariable ...]` writing one
/// of the well-known token env vars or `ARM_OIDC_TOKEN`).
pub fn addspn_with_inline_script(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let add_spn = step
            .metadata
            .get(META_ADD_SPN_TO_ENV)
            .map(|v| v == "true")
            .unwrap_or(false);
        if !add_spn {
            continue;
        }

        let body = match step.metadata.get(META_SCRIPT_BODY) {
            Some(b) if !b.trim().is_empty() => b,
            _ => continue,
        };

        let launders = script_launders_spn_token(body);
        let suffix = if launders {
            " — explicit token laundering detected (##vso[task.setvariable] writes federated token material)"
        } else {
            ""
        };

        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::AddSpnWithInlineScript,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Step '{}' runs an inline script with addSpnToEnvironment:true — the federated SPN (idToken/servicePrincipalKey/tenantId) is exposed to script-controlled code and can be exfiltrated via setvariable{}",
                step.name, suffix
            ),
            recommendation: Recommendation::Manual {
                action: "Replace the inline script with `scriptPath:` pointing to a reviewed file in-repo, OR drop `addSpnToEnvironment: true` and use the task's first-class auth surface. Never emit federated token material via `##vso[task.setvariable]` — those values are inherited by every downstream task and may appear in logs.".into(),
            },
        });
    }

    findings
}

/// Rule: free-form `type: string` parameter (no `values:` allowlist)
/// interpolated via `${{ parameters.<name> }}` directly into an inline
/// shell/PowerShell script body. ADO does not escape parameter values in
/// YAML emission, so any user with "queue build" can inject shell.
///
/// Detection requires the parser to populate
/// `AuthorityGraph::parameters` (currently ADO only) and to stamp Step
/// nodes with `META_SCRIPT_BODY`.
///
/// Severity: Medium.
pub fn parameter_interpolation_into_shell(graph: &AuthorityGraph) -> Vec<Finding> {
    if graph.parameters.is_empty() {
        return Vec::new();
    }

    // Free-form string parameters: type is `string` (or unspecified — ADO's
    // default) AND no `values:` allowlist.
    let free_form: Vec<&str> = graph
        .parameters
        .iter()
        .filter(|(_, spec)| {
            !spec.has_values_allowlist
                && (spec.param_type.is_empty() || spec.param_type.eq_ignore_ascii_case("string"))
        })
        .map(|(name, _)| name.as_str())
        .collect();

    if free_form.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let body = match step.metadata.get(META_SCRIPT_BODY) {
            Some(b) if !b.is_empty() => b,
            _ => continue,
        };

        // Find every free-form parameter that appears interpolated in the
        // script body. Match both `${{ parameters.X }}` and `${{parameters.X}}`.
        let mut hits: Vec<&str> = Vec::new();
        for &name in &free_form {
            let needle_a = format!("${{{{ parameters.{name} }}}}");
            let needle_b = format!("${{{{parameters.{name}}}}}");
            if body.contains(&needle_a) || body.contains(&needle_b) {
                hits.push(name);
            }
        }

        if hits.is_empty() {
            continue;
        }

        hits.sort();
        hits.dedup();
        let names = hits.join(", ");

        findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::ParameterInterpolationIntoShell,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Step '{}' interpolates free-form string parameter(s) [{}] into an inline script — anyone with 'queue build' permission can inject shell commands",
                step.name, names
            ),
            recommendation: Recommendation::Manual {
                action: "Add a `values:` allowlist to the parameter declaration to constrain accepted inputs, OR pass the parameter through the step's `env:` block so the runtime quotes it as a shell variable instead of YAML-interpolating raw text.".into(),
            },
        });
    }

    findings
}

/// Run all rules against a graph.
pub fn run_all_rules(graph: &AuthorityGraph, max_hops: usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    // MVP rules
    findings.extend(authority_propagation(graph, max_hops));
    findings.extend(over_privileged_identity(graph));
    findings.extend(unpinned_action(graph));
    findings.extend(untrusted_with_authority(graph));
    findings.extend(artifact_boundary_crossing(graph));
    // Stretch rules
    findings.extend(long_lived_credential(graph));
    findings.extend(floating_image(graph));
    findings.extend(persisted_credential(graph));
    findings.extend(trigger_context_mismatch(graph));
    findings.extend(cross_workflow_authority_chain(graph));
    findings.extend(authority_cycle(graph));
    findings.extend(uplift_without_attestation(graph));
    findings.extend(self_mutating_pipeline(graph));
    findings.extend(checkout_self_pr_exposure(graph));
    findings.extend(variable_group_in_pr_job(graph));
    findings.extend(self_hosted_pool_pr_hijack(graph));
    findings.extend(service_connection_scope_mismatch(graph));
    findings.extend(template_extends_unpinned_branch(graph));
    findings.extend(template_repo_ref_is_feature_branch(graph));
    findings.extend(vm_remote_exec_via_pipeline_secret(graph));
    findings.extend(short_lived_sas_in_command_line(graph));
    // ADO inline-script secret-leak rules
    findings.extend(secret_to_inline_script_env_export(graph));
    findings.extend(secret_materialised_to_workspace_file(graph));
    findings.extend(keyvault_secret_to_plaintext(graph));
    findings.extend(terraform_auto_approve_in_prod(graph));
    findings.extend(addspn_with_inline_script(graph));
    findings.extend(parameter_interpolation_into_shell(graph));

    apply_confidence_cap(graph, &mut findings);

    findings.sort_by_key(|f| f.severity);

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::*;

    fn source(file: &str) -> PipelineSource {
        PipelineSource {
            file: file.into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        }
    }

    #[test]
    fn unpinned_third_party_action_flagged() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.add_node(
            NodeKind::Image,
            "actions/checkout@v4",
            TrustZone::ThirdParty,
        );

        let findings = unpinned_action(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::UnpinnedAction);
    }

    #[test]
    fn pinned_action_not_flagged() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.add_node(
            NodeKind::Image,
            "actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29",
            TrustZone::ThirdParty,
        );

        let findings = unpinned_action(&g);
        assert!(findings.is_empty());
    }

    #[test]
    fn untrusted_step_with_secret_is_critical() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let step = g.add_node(NodeKind::Step, "evil-action", TrustZone::Untrusted);
        let secret = g.add_node(NodeKind::Secret, "DEPLOY_KEY", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let findings = untrusted_with_authority(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn implicit_identity_downgrades_to_info() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let step = g.add_node(NodeKind::Step, "AzureCLI@2", TrustZone::Untrusted);
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_IMPLICIT.into(), "true".into());
        meta.insert(META_IDENTITY_SCOPE.into(), "broad".into());
        let token = g.add_node_with_metadata(
            NodeKind::Identity,
            "System.AccessToken",
            TrustZone::FirstParty,
            meta,
        );
        g.add_edge(step, token, EdgeKind::HasAccessTo);

        let findings = untrusted_with_authority(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].severity,
            Severity::Info,
            "implicit token must be Info not Critical"
        );
        assert!(findings[0].message.contains("platform-injected"));
    }

    #[test]
    fn explicit_secret_remains_critical_despite_implicit_token() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let step = g.add_node(NodeKind::Step, "AzureCLI@2", TrustZone::Untrusted);
        // implicit token → Info
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_IMPLICIT.into(), "true".into());
        let token = g.add_node_with_metadata(
            NodeKind::Identity,
            "System.AccessToken",
            TrustZone::FirstParty,
            meta,
        );
        // explicit secret → Critical
        let secret = g.add_node(NodeKind::Secret, "ARM_CLIENT_SECRET", TrustZone::FirstParty);
        g.add_edge(step, token, EdgeKind::HasAccessTo);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let findings = untrusted_with_authority(&g);
        assert_eq!(findings.len(), 2);
        let info = findings
            .iter()
            .find(|f| f.severity == Severity::Info)
            .unwrap();
        let crit = findings
            .iter()
            .find(|f| f.severity == Severity::Critical)
            .unwrap();
        assert!(info.message.contains("platform-injected"));
        assert!(crit.message.contains("ARM_CLIENT_SECRET"));
    }

    #[test]
    fn artifact_crossing_detected() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let secret = g.add_node(NodeKind::Secret, "KEY", TrustZone::FirstParty);
        let build = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        let artifact = g.add_node(NodeKind::Artifact, "dist.zip", TrustZone::FirstParty);
        let deploy = g.add_node(NodeKind::Step, "deploy", TrustZone::ThirdParty);

        g.add_edge(build, secret, EdgeKind::HasAccessTo);
        g.add_edge(build, artifact, EdgeKind::Produces);
        g.add_edge(artifact, deploy, EdgeKind::Consumes);

        let findings = artifact_boundary_crossing(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].category,
            FindingCategory::ArtifactBoundaryCrossing
        );
    }

    #[test]
    fn propagation_to_sha_pinned_is_high_not_critical() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(
            "digest".into(),
            "a5ac7e51b41094c92402da3b24376905380afc29".into(),
        );
        let identity = g.add_node(NodeKind::Identity, "GITHUB_TOKEN", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "checkout", TrustZone::ThirdParty);
        let image = g.add_node_with_metadata(
            NodeKind::Image,
            "actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29",
            TrustZone::ThirdParty,
            meta,
        );

        g.add_edge(step, identity, EdgeKind::HasAccessTo);
        g.add_edge(step, image, EdgeKind::UsesImage);

        let findings = authority_propagation(&g, 4);
        // Should find propagation to the SHA-pinned image
        let image_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.nodes_involved.contains(&image))
            .collect();
        assert!(!image_findings.is_empty());
        // SHA-pinned targets get High, not Critical (non-OIDC source)
        assert_eq!(image_findings[0].severity, Severity::High);
    }

    #[test]
    fn oidc_identity_to_pinned_third_party_is_critical() {
        let mut g = AuthorityGraph::new(source("ci.yml"));

        // OIDC-federated cloud identity — token itself is the threat
        let mut id_meta = std::collections::HashMap::new();
        id_meta.insert(META_OIDC.into(), "true".into());
        let identity = g.add_node_with_metadata(
            NodeKind::Identity,
            "AWS_OIDC_ROLE",
            TrustZone::FirstParty,
            id_meta,
        );

        // SHA-pinned ThirdParty image — would normally be High without OIDC
        let mut img_meta = std::collections::HashMap::new();
        img_meta.insert(
            META_DIGEST.into(),
            "a5ac7e51b41094c92402da3b24376905380afc29".into(),
        );
        let image = g.add_node_with_metadata(
            NodeKind::Image,
            "aws-actions/configure-aws-credentials@a5ac7e51b41094c92402da3b24376905380afc29",
            TrustZone::ThirdParty,
            img_meta,
        );

        // Step in ThirdParty zone holds the OIDC identity and uses the pinned image
        let step = g.add_node(
            NodeKind::Step,
            "configure-aws-credentials",
            TrustZone::ThirdParty,
        );
        g.add_edge(step, identity, EdgeKind::HasAccessTo);
        g.add_edge(step, image, EdgeKind::UsesImage);

        let findings = authority_propagation(&g, 4);
        let image_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.nodes_involved.contains(&image))
            .collect();
        assert!(
            !image_findings.is_empty(),
            "expected OIDC→pinned propagation finding"
        );
        // OIDC source escalates pinned ThirdParty from High → Critical
        assert_eq!(image_findings[0].severity, Severity::Critical);
    }

    #[test]
    fn propagation_to_untrusted_is_critical() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let identity = g.add_node(NodeKind::Identity, "GITHUB_TOKEN", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "deploy", TrustZone::Untrusted);
        let image = g.add_node(NodeKind::Image, "evil/action@main", TrustZone::Untrusted);

        g.add_edge(step, identity, EdgeKind::HasAccessTo);
        g.add_edge(step, image, EdgeKind::UsesImage);

        let findings = authority_propagation(&g, 4);
        let image_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.nodes_involved.contains(&image))
            .collect();
        assert!(!image_findings.is_empty());
        assert_eq!(image_findings[0].severity, Severity::Critical);
    }

    #[test]
    fn long_lived_credential_detected() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.add_node(NodeKind::Secret, "AWS_ACCESS_KEY_ID", TrustZone::FirstParty);
        g.add_node(NodeKind::Secret, "NPM_TOKEN", TrustZone::FirstParty);
        g.add_node(NodeKind::Secret, "DEPLOY_API_KEY", TrustZone::FirstParty);
        // Non-matching names
        g.add_node(NodeKind::Secret, "CACHE_TTL", TrustZone::FirstParty);

        let findings = long_lived_credential(&g);
        assert_eq!(findings.len(), 2); // AWS_ACCESS_KEY_ID + DEPLOY_API_KEY
        assert!(findings
            .iter()
            .all(|f| f.category == FindingCategory::LongLivedCredential));
    }

    #[test]
    fn duplicate_unpinned_actions_deduplicated() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        // Same action used in two jobs — two Image nodes, same name
        g.add_node(NodeKind::Image, "actions/checkout@v4", TrustZone::Untrusted);
        g.add_node(NodeKind::Image, "actions/checkout@v4", TrustZone::Untrusted);
        g.add_node(
            NodeKind::Image,
            "actions/setup-node@v3",
            TrustZone::Untrusted,
        );

        let findings = unpinned_action(&g);
        // Should get 2 findings (checkout + setup-node), not 3
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn broad_identity_scope_flagged_as_high() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_PERMISSIONS.into(), "write-all".into());
        meta.insert(META_IDENTITY_SCOPE.into(), "broad".into());
        let identity = g.add_node_with_metadata(
            NodeKind::Identity,
            "GITHUB_TOKEN",
            TrustZone::FirstParty,
            meta,
        );
        let step = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        g.add_edge(step, identity, EdgeKind::HasAccessTo);

        let findings = over_privileged_identity(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("broad"));
    }

    #[test]
    fn unknown_identity_scope_flagged_as_medium() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_PERMISSIONS.into(), "custom-scope".into());
        meta.insert(META_IDENTITY_SCOPE.into(), "unknown".into());
        let identity = g.add_node_with_metadata(
            NodeKind::Identity,
            "GITHUB_TOKEN",
            TrustZone::FirstParty,
            meta,
        );
        let step = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        g.add_edge(step, identity, EdgeKind::HasAccessTo);

        let findings = over_privileged_identity(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains("unknown"));
    }

    #[test]
    fn floating_image_unpinned_container_flagged() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_CONTAINER.into(), "true".into());
        g.add_node_with_metadata(NodeKind::Image, "ubuntu:22.04", TrustZone::Untrusted, meta);

        let findings = floating_image(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::FloatingImage);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn partial_graph_caps_critical_findings_at_high() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.mark_partial("matrix strategy hides some authority paths");

        let identity = g.add_node(NodeKind::Identity, "GITHUB_TOKEN", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "deploy", TrustZone::Untrusted);
        let image = g.add_node(NodeKind::Image, "evil/action@main", TrustZone::Untrusted);

        g.add_edge(step, identity, EdgeKind::HasAccessTo);
        g.add_edge(step, image, EdgeKind::UsesImage);

        let findings = run_all_rules(&g, 4);
        assert!(findings
            .iter()
            .any(|f| f.category == FindingCategory::AuthorityPropagation));
        assert!(findings
            .iter()
            .any(|f| f.category == FindingCategory::UntrustedWithAuthority));
        assert!(findings.iter().all(|f| f.severity >= Severity::High));
        assert!(!findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn complete_graph_keeps_critical_findings() {
        let mut g = AuthorityGraph::new(source("ci.yml"));

        let identity = g.add_node(NodeKind::Identity, "GITHUB_TOKEN", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "deploy", TrustZone::Untrusted);
        let image = g.add_node(NodeKind::Image, "evil/action@main", TrustZone::Untrusted);

        g.add_edge(step, identity, EdgeKind::HasAccessTo);
        g.add_edge(step, image, EdgeKind::UsesImage);

        let findings = run_all_rules(&g, 4);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn floating_image_digest_pinned_container_not_flagged() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_CONTAINER.into(), "true".into());
        g.add_node_with_metadata(
            NodeKind::Image,
            "ubuntu@sha256:a5ac7e51b41094c92402da3b24376905380afc29a5ac7e51b41094c92402da3b",
            TrustZone::ThirdParty,
            meta,
        );

        let findings = floating_image(&g);
        assert!(
            findings.is_empty(),
            "digest-pinned container should not be flagged"
        );
    }

    #[test]
    fn unpinned_action_does_not_flag_container_images() {
        // Regression: container Image nodes are handled by floating_image, not unpinned_action.
        // The same node must not generate findings from both rules.
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_CONTAINER.into(), "true".into());
        g.add_node_with_metadata(NodeKind::Image, "ubuntu:22.04", TrustZone::Untrusted, meta);

        let findings = unpinned_action(&g);
        assert!(
            findings.is_empty(),
            "unpinned_action must skip container images to avoid double-flagging"
        );
    }

    #[test]
    fn floating_image_ignores_action_images() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        // Image node without META_CONTAINER — this is a step uses: action, not a container
        g.add_node(NodeKind::Image, "actions/checkout@v4", TrustZone::Untrusted);

        let findings = floating_image(&g);
        assert!(
            findings.is_empty(),
            "floating_image should not flag step actions"
        );
    }

    #[test]
    fn persisted_credential_rule_fires_on_persists_to_edge() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let token = g.add_node(
            NodeKind::Identity,
            "System.AccessToken",
            TrustZone::FirstParty,
        );
        let checkout = g.add_node(NodeKind::Step, "checkout", TrustZone::FirstParty);
        g.add_edge(checkout, token, EdgeKind::PersistsTo);

        let findings = persisted_credential(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::PersistedCredential);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("persistCredentials"));
    }

    #[test]
    fn untrusted_with_cli_flag_exposed_secret_notes_log_exposure() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let step = g.add_node(NodeKind::Step, "TerraformCLI@0", TrustZone::Untrusted);
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_CLI_FLAG_EXPOSED.into(), "true".into());
        let secret =
            g.add_node_with_metadata(NodeKind::Secret, "db_password", TrustZone::FirstParty, meta);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let findings = untrusted_with_authority(&g);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.contains("-var flag"),
            "message should note -var flag log exposure"
        );
        assert!(matches!(
            findings[0].recommendation,
            Recommendation::Manual { .. }
        ));
    }

    #[test]
    fn constrained_identity_scope_not_flagged() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_PERMISSIONS.into(), "{ contents: read }".into());
        meta.insert(META_IDENTITY_SCOPE.into(), "constrained".into());
        let identity = g.add_node_with_metadata(
            NodeKind::Identity,
            "GITHUB_TOKEN",
            TrustZone::FirstParty,
            meta,
        );
        let step = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        g.add_edge(step, identity, EdgeKind::HasAccessTo);

        let findings = over_privileged_identity(&g);
        assert!(
            findings.is_empty(),
            "constrained scope should not be flagged"
        );
    }

    #[test]
    fn trigger_context_mismatch_fires_on_pull_request_target_with_secret() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.metadata
            .insert(META_TRIGGER.into(), "pull_request_target".into());
        let secret = g.add_node(NodeKind::Secret, "DEPLOY_KEY", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let findings = trigger_context_mismatch(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(
            findings[0].category,
            FindingCategory::TriggerContextMismatch
        );
    }

    #[test]
    fn trigger_context_mismatch_no_fire_without_trigger_metadata() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let secret = g.add_node(NodeKind::Secret, "DEPLOY_KEY", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let findings = trigger_context_mismatch(&g);
        assert!(findings.is_empty(), "no trigger metadata → no finding");
    }

    #[test]
    fn cross_workflow_authority_chain_detected() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let step = g.add_node(NodeKind::Step, "deploy", TrustZone::FirstParty);
        let secret = g.add_node(NodeKind::Secret, "DEPLOY_KEY", TrustZone::FirstParty);
        let external = g.add_node(
            NodeKind::Image,
            "evil/workflow.yml@main",
            TrustZone::Untrusted,
        );
        g.add_edge(step, secret, EdgeKind::HasAccessTo);
        g.add_edge(step, external, EdgeKind::DelegatesTo);

        let findings = cross_workflow_authority_chain(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(
            findings[0].category,
            FindingCategory::CrossWorkflowAuthorityChain
        );
    }

    #[test]
    fn cross_workflow_authority_chain_no_fire_if_local_delegation() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let step = g.add_node(NodeKind::Step, "deploy", TrustZone::FirstParty);
        let secret = g.add_node(NodeKind::Secret, "DEPLOY_KEY", TrustZone::FirstParty);
        let local = g.add_node(NodeKind::Image, "./local-action", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);
        g.add_edge(step, local, EdgeKind::DelegatesTo);

        let findings = cross_workflow_authority_chain(&g);
        assert!(
            findings.is_empty(),
            "FirstParty delegation should not be flagged"
        );
    }

    #[test]
    fn authority_cycle_detected() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let a = g.add_node(NodeKind::Step, "A", TrustZone::FirstParty);
        let b = g.add_node(NodeKind::Step, "B", TrustZone::FirstParty);
        g.add_edge(a, b, EdgeKind::DelegatesTo);
        g.add_edge(b, a, EdgeKind::DelegatesTo);

        let findings = authority_cycle(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::AuthorityCycle);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn authority_cycle_no_fire_for_acyclic_graph() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let a = g.add_node(NodeKind::Step, "A", TrustZone::FirstParty);
        let b = g.add_node(NodeKind::Step, "B", TrustZone::FirstParty);
        let c = g.add_node(NodeKind::Step, "C", TrustZone::FirstParty);
        g.add_edge(a, b, EdgeKind::DelegatesTo);
        g.add_edge(b, c, EdgeKind::DelegatesTo);

        let findings = authority_cycle(&g);
        assert!(findings.is_empty(), "acyclic graph must not fire");
    }

    #[test]
    fn uplift_without_attestation_fires_when_oidc_no_attests() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_OIDC.into(), "true".into());
        let identity = g.add_node_with_metadata(
            NodeKind::Identity,
            "AWS/deploy-role",
            TrustZone::FirstParty,
            meta,
        );
        let step = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        g.add_edge(step, identity, EdgeKind::HasAccessTo);

        let findings = uplift_without_attestation(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(
            findings[0].category,
            FindingCategory::UpliftWithoutAttestation
        );
    }

    #[test]
    fn uplift_without_attestation_no_fire_when_attests_present() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut id_meta = std::collections::HashMap::new();
        id_meta.insert(META_OIDC.into(), "true".into());
        let identity = g.add_node_with_metadata(
            NodeKind::Identity,
            "AWS/deploy-role",
            TrustZone::FirstParty,
            id_meta,
        );
        let mut step_meta = std::collections::HashMap::new();
        step_meta.insert(META_ATTESTS.into(), "true".into());
        let attest_step =
            g.add_node_with_metadata(NodeKind::Step, "attest", TrustZone::FirstParty, step_meta);
        let build_step = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        g.add_edge(build_step, identity, EdgeKind::HasAccessTo);
        // Touch attest_step so the variable is used (avoid unused warning)
        let _ = attest_step;

        let findings = uplift_without_attestation(&g);
        assert!(findings.is_empty(), "attestation present → no finding");
    }

    #[test]
    fn uplift_without_attestation_no_fire_without_oidc() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_PERMISSIONS.into(), "write-all".into());
        meta.insert(META_IDENTITY_SCOPE.into(), "broad".into());
        // Note: no META_OIDC
        let identity = g.add_node_with_metadata(
            NodeKind::Identity,
            "GITHUB_TOKEN",
            TrustZone::FirstParty,
            meta,
        );
        let step = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        g.add_edge(step, identity, EdgeKind::HasAccessTo);

        let findings = uplift_without_attestation(&g);
        assert!(
            findings.is_empty(),
            "broad identity without OIDC must not fire"
        );
    }

    #[test]
    fn self_mutating_pipeline_untrusted_is_critical() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_WRITES_ENV_GATE.into(), "true".into());
        g.add_node_with_metadata(NodeKind::Step, "fork-step", TrustZone::Untrusted, meta);

        let findings = self_mutating_pipeline(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].category, FindingCategory::SelfMutatingPipeline);
    }

    #[test]
    fn self_mutating_pipeline_privileged_step_is_high() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_WRITES_ENV_GATE.into(), "true".into());
        let step = g.add_node_with_metadata(NodeKind::Step, "build", TrustZone::FirstParty, meta);
        let secret = g.add_node(NodeKind::Secret, "DEPLOY_KEY", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let findings = self_mutating_pipeline(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn trigger_context_mismatch_fires_on_ado_pr_with_secret_as_high() {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        g.metadata.insert(META_TRIGGER.into(), "pr".into());
        let secret = g.add_node(NodeKind::Secret, "DEPLOY_KEY", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let findings = trigger_context_mismatch(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(
            findings[0].category,
            FindingCategory::TriggerContextMismatch
        );
    }

    #[test]
    fn cross_workflow_authority_chain_third_party_is_high() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let step = g.add_node(NodeKind::Step, "deploy", TrustZone::FirstParty);
        let secret = g.add_node(NodeKind::Secret, "DEPLOY_KEY", TrustZone::FirstParty);
        // ThirdParty target (SHA-pinned external workflow)
        let external = g.add_node(
            NodeKind::Image,
            "org/repo/.github/workflows/deploy.yml@a5ac7e51b41094c92402da3b24376905380afc29",
            TrustZone::ThirdParty,
        );
        g.add_edge(step, secret, EdgeKind::HasAccessTo);
        g.add_edge(step, external, EdgeKind::DelegatesTo);

        let findings = cross_workflow_authority_chain(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].severity,
            Severity::High,
            "ThirdParty delegation target should be High (Critical reserved for Untrusted)"
        );
        assert_eq!(
            findings[0].category,
            FindingCategory::CrossWorkflowAuthorityChain
        );
    }

    #[test]
    fn self_mutating_pipeline_first_party_no_authority_is_medium() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_WRITES_ENV_GATE.into(), "true".into());
        // FirstParty step writes the gate but holds no secret/identity access.
        g.add_node_with_metadata(NodeKind::Step, "set-version", TrustZone::FirstParty, meta);

        let findings = self_mutating_pipeline(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].category, FindingCategory::SelfMutatingPipeline);
    }

    #[test]
    fn authority_cycle_3node_cycle_includes_all_members() {
        // A → B → C → A should produce one finding whose nodes_involved
        // contains all three node IDs, not just the back-edge endpoints.
        let mut g = AuthorityGraph::new(source("test.yml"));
        let a = g.add_node(NodeKind::Step, "A", TrustZone::FirstParty);
        let b = g.add_node(NodeKind::Step, "B", TrustZone::FirstParty);
        let c = g.add_node(NodeKind::Step, "C", TrustZone::FirstParty);
        g.add_edge(a, b, EdgeKind::DelegatesTo);
        g.add_edge(b, c, EdgeKind::DelegatesTo);
        g.add_edge(c, a, EdgeKind::DelegatesTo);

        let findings = authority_cycle(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::AuthorityCycle);
        assert!(
            findings[0].nodes_involved.contains(&a),
            "A must be in nodes_involved"
        );
        assert!(
            findings[0].nodes_involved.contains(&b),
            "B must be in nodes_involved — middle of A→B→C→A cycle"
        );
        assert!(
            findings[0].nodes_involved.contains(&c),
            "C must be in nodes_involved"
        );
    }

    #[test]
    fn variable_group_in_pr_job_fires_on_pr_trigger_with_var_group() {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        g.metadata.insert(META_TRIGGER.into(), "pr".into());
        let mut secret_meta = std::collections::HashMap::new();
        secret_meta.insert(META_VARIABLE_GROUP.into(), "true".into());
        let secret = g.add_node_with_metadata(
            NodeKind::Secret,
            "prod-deploy-secrets",
            TrustZone::FirstParty,
            secret_meta,
        );
        let step = g.add_node(NodeKind::Step, "deploy", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let findings = variable_group_in_pr_job(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].category, FindingCategory::VariableGroupInPrJob);
        assert!(findings[0].message.contains("prod-deploy-secrets"));
    }

    #[test]
    fn variable_group_in_pr_job_no_fire_without_pr_trigger() {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        // No trigger metadata — should not fire
        let mut secret_meta = std::collections::HashMap::new();
        secret_meta.insert(META_VARIABLE_GROUP.into(), "true".into());
        let secret = g.add_node_with_metadata(
            NodeKind::Secret,
            "prod-deploy-secrets",
            TrustZone::FirstParty,
            secret_meta,
        );
        let step = g.add_node(NodeKind::Step, "deploy", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let findings = variable_group_in_pr_job(&g);
        assert!(
            findings.is_empty(),
            "no PR trigger → variable_group_in_pr_job must not fire"
        );
    }

    #[test]
    fn self_hosted_pool_pr_hijack_fires_when_all_three_factors_present() {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        g.metadata.insert(META_TRIGGER.into(), "pr".into());

        let mut pool_meta = std::collections::HashMap::new();
        pool_meta.insert(META_SELF_HOSTED.into(), "true".into());
        g.add_node_with_metadata(
            NodeKind::Image,
            "self-hosted-pool",
            TrustZone::FirstParty,
            pool_meta,
        );

        let mut step_meta = std::collections::HashMap::new();
        step_meta.insert(META_CHECKOUT_SELF.into(), "true".into());
        g.add_node_with_metadata(NodeKind::Step, "checkout", TrustZone::FirstParty, step_meta);

        let findings = self_hosted_pool_pr_hijack(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(
            findings[0].category,
            FindingCategory::SelfHostedPoolPrHijack
        );
        assert!(findings[0].message.contains("self-hosted"));
    }

    #[test]
    fn self_hosted_pool_pr_hijack_no_fire_without_pr_trigger() {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        // No trigger metadata

        let mut pool_meta = std::collections::HashMap::new();
        pool_meta.insert(META_SELF_HOSTED.into(), "true".into());
        g.add_node_with_metadata(
            NodeKind::Image,
            "self-hosted-pool",
            TrustZone::FirstParty,
            pool_meta,
        );

        let mut step_meta = std::collections::HashMap::new();
        step_meta.insert(META_CHECKOUT_SELF.into(), "true".into());
        g.add_node_with_metadata(NodeKind::Step, "checkout", TrustZone::FirstParty, step_meta);

        let findings = self_hosted_pool_pr_hijack(&g);
        assert!(
            findings.is_empty(),
            "no PR trigger → self_hosted_pool_pr_hijack must not fire"
        );
    }

    #[test]
    fn service_connection_scope_mismatch_fires_on_pr_broad_non_oidc() {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        g.metadata.insert(META_TRIGGER.into(), "pr".into());

        let mut sc_meta = std::collections::HashMap::new();
        sc_meta.insert(META_SERVICE_CONNECTION.into(), "true".into());
        sc_meta.insert(META_IDENTITY_SCOPE.into(), "broad".into());
        // No META_OIDC → treated as not OIDC-federated
        let sc = g.add_node_with_metadata(
            NodeKind::Identity,
            "prod-azure-sc",
            TrustZone::FirstParty,
            sc_meta,
        );
        let step = g.add_node(NodeKind::Step, "deploy", TrustZone::FirstParty);
        g.add_edge(step, sc, EdgeKind::HasAccessTo);

        let findings = service_connection_scope_mismatch(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(
            findings[0].category,
            FindingCategory::ServiceConnectionScopeMismatch
        );
        assert!(findings[0].message.contains("prod-azure-sc"));
    }

    #[test]
    fn service_connection_scope_mismatch_no_fire_without_pr_trigger() {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        // No trigger metadata
        let mut sc_meta = std::collections::HashMap::new();
        sc_meta.insert(META_SERVICE_CONNECTION.into(), "true".into());
        sc_meta.insert(META_IDENTITY_SCOPE.into(), "broad".into());
        let sc = g.add_node_with_metadata(
            NodeKind::Identity,
            "prod-azure-sc",
            TrustZone::FirstParty,
            sc_meta,
        );
        let step = g.add_node(NodeKind::Step, "deploy", TrustZone::FirstParty);
        g.add_edge(step, sc, EdgeKind::HasAccessTo);

        let findings = service_connection_scope_mismatch(&g);
        assert!(
            findings.is_empty(),
            "no PR trigger → service_connection_scope_mismatch must not fire"
        );
    }

    #[test]
    fn checkout_self_pr_exposure_fires_on_pr_trigger() {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        g.metadata.insert(META_TRIGGER.into(), "pr".into());
        let mut step_meta = std::collections::HashMap::new();
        step_meta.insert(META_CHECKOUT_SELF.into(), "true".into());
        g.add_node_with_metadata(NodeKind::Step, "checkout", TrustZone::FirstParty, step_meta);

        let findings = checkout_self_pr_exposure(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].category,
            FindingCategory::CheckoutSelfPrExposure
        );
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn checkout_self_pr_exposure_no_fire_without_pr_trigger() {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        // No META_TRIGGER set
        let mut step_meta = std::collections::HashMap::new();
        step_meta.insert(META_CHECKOUT_SELF.into(), "true".into());
        g.add_node_with_metadata(NodeKind::Step, "checkout", TrustZone::FirstParty, step_meta);

        let findings = checkout_self_pr_exposure(&g);
        assert!(
            findings.is_empty(),
            "no PR trigger → checkout_self_pr_exposure must not fire"
        );
    }

    #[test]
    fn variable_group_in_pr_job_uses_cellos_remediation() {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        g.metadata.insert(META_TRIGGER.into(), "pr".into());

        let mut secret_meta = std::collections::HashMap::new();
        secret_meta.insert(META_VARIABLE_GROUP.into(), "true".into());
        let secret = g.add_node_with_metadata(
            NodeKind::Secret,
            "prod-secret",
            TrustZone::FirstParty,
            secret_meta,
        );
        let step = g.add_node(NodeKind::Step, "deploy step", TrustZone::Untrusted);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let findings = variable_group_in_pr_job(&g);
        assert!(!findings.is_empty());
        assert!(
            matches!(
                findings[0].recommendation,
                Recommendation::CellosRemediation { .. }
            ),
            "variable_group_in_pr_job must recommend CellosRemediation"
        );
    }

    #[test]
    fn service_connection_scope_mismatch_uses_cellos_remediation() {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        g.metadata.insert(META_TRIGGER.into(), "pr".into());

        let mut id_meta = std::collections::HashMap::new();
        id_meta.insert(META_SERVICE_CONNECTION.into(), "true".into());
        id_meta.insert(META_IDENTITY_SCOPE.into(), "broad".into());
        // No META_OIDC → treated as not OIDC-federated
        let identity = g.add_node_with_metadata(
            NodeKind::Identity,
            "sub-conn",
            TrustZone::FirstParty,
            id_meta,
        );
        let step = g.add_node(NodeKind::Step, "azure deploy", TrustZone::Untrusted);
        g.add_edge(step, identity, EdgeKind::HasAccessTo);

        let findings = service_connection_scope_mismatch(&g);
        assert!(!findings.is_empty());
        assert!(
            matches!(
                findings[0].recommendation,
                Recommendation::CellosRemediation { .. }
            ),
            "service_connection_scope_mismatch must recommend CellosRemediation"
        );
    }

    /// Build a propagation graph with an optional approval-gated middle step:
    ///   Secret → middle Step (FirstParty) → Artifact → ThirdParty Step.
    /// When `gated` is true the middle step carries META_ENV_APPROVAL.
    fn build_env_approval_graph(gated: bool) -> AuthorityGraph {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));

        let secret = g.add_node(NodeKind::Secret, "DEPLOY_KEY", TrustZone::FirstParty);
        let mut middle_meta = std::collections::HashMap::new();
        if gated {
            middle_meta.insert(META_ENV_APPROVAL.into(), "true".into());
        }
        let middle = g.add_node_with_metadata(
            NodeKind::Step,
            "deploy-prod",
            TrustZone::FirstParty,
            middle_meta,
        );
        let artifact = g.add_node(NodeKind::Artifact, "release.tar", TrustZone::FirstParty);
        let third = g.add_node(
            NodeKind::Step,
            "third-party/uploader",
            TrustZone::ThirdParty,
        );

        g.add_edge(middle, secret, EdgeKind::HasAccessTo);
        g.add_edge(middle, artifact, EdgeKind::Produces);
        g.add_edge(artifact, third, EdgeKind::Consumes);

        g
    }

    #[test]
    fn env_approval_gate_reduces_propagation_severity() {
        // Baseline: no gate → Critical (third-party sink, not SHA-pinned)
        let baseline = authority_propagation(&build_env_approval_graph(false), 4);
        let baseline_finding = baseline
            .iter()
            .find(|f| f.category == FindingCategory::AuthorityPropagation)
            .expect("baseline must produce an AuthorityPropagation finding");
        assert_eq!(baseline_finding.severity, Severity::Critical);
        assert!(!baseline_finding
            .message
            .contains("environment approval gate"));

        // Gated: same shape, middle step tagged → severity drops one step to High
        let gated = authority_propagation(&build_env_approval_graph(true), 4);
        let gated_finding = gated
            .iter()
            .find(|f| f.category == FindingCategory::AuthorityPropagation)
            .expect("gated must produce an AuthorityPropagation finding");
        assert_eq!(
            gated_finding.severity,
            Severity::High,
            "Critical must downgrade to High when path crosses an env-approval gate"
        );
        assert!(
            gated_finding
                .message
                .contains("(mitigated: environment approval gate)"),
            "gated finding must annotate the mitigation in its message"
        );
    }

    #[test]
    fn downgrade_one_step_table() {
        assert_eq!(downgrade_one_step(Severity::Critical), Severity::High);
        assert_eq!(downgrade_one_step(Severity::High), Severity::Medium);
        assert_eq!(downgrade_one_step(Severity::Medium), Severity::Low);
        assert_eq!(downgrade_one_step(Severity::Low), Severity::Low);
        assert_eq!(downgrade_one_step(Severity::Info), Severity::Info);
    }

    // ── template_extends_unpinned_branch ──────────────────────

    /// Build a graph whose META_REPOSITORIES carries a single repo descriptor.
    /// `git_ref` of `None` encodes the "no `ref:` field" case (default branch).
    fn graph_with_repo(
        alias: &str,
        repo_type: &str,
        name: &str,
        git_ref: Option<&str>,
        used: bool,
    ) -> AuthorityGraph {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        let mut obj = serde_json::Map::new();
        obj.insert("alias".into(), serde_json::Value::String(alias.into()));
        obj.insert(
            "repo_type".into(),
            serde_json::Value::String(repo_type.into()),
        );
        obj.insert("name".into(), serde_json::Value::String(name.into()));
        if let Some(r) = git_ref {
            obj.insert("ref".into(), serde_json::Value::String(r.into()));
        }
        obj.insert("used".into(), serde_json::Value::Bool(used));
        let arr = serde_json::Value::Array(vec![serde_json::Value::Object(obj)]);
        g.metadata.insert(
            META_REPOSITORIES.into(),
            serde_json::to_string(&arr).unwrap(),
        );
        g
    }

    // ── vm_remote_exec_via_pipeline_secret ──────────────

    /// Helper: build a graph with one Step that has the given inline script
    /// body and (optionally) a HasAccessTo edge to a Secret named `sas_var`.
    fn graph_with_script_step(body: &str, secret_name: Option<&str>) -> AuthorityGraph {
        let mut g = AuthorityGraph::new(source("ado.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_SCRIPT_BODY.into(), body.into());
        let step_id =
            g.add_node_with_metadata(NodeKind::Step, "deploy-vm", TrustZone::FirstParty, meta);
        if let Some(name) = secret_name {
            let sec = g.add_node(NodeKind::Secret, name, TrustZone::FirstParty);
            g.add_edge(step_id, sec, EdgeKind::HasAccessTo);
        }
        g
    }

    // ── secret_to_inline_script_env_export ────────────────────

    /// Build a graph with one Step that has access to `secret_name` and
    /// stamps `script` as the META_SCRIPT_BODY.
    fn build_step_with_script(secret_name: &str, script: &str) -> AuthorityGraph {
        let mut g = AuthorityGraph::new(source("ado.yml"));
        let secret = g.add_node(NodeKind::Secret, secret_name, TrustZone::FirstParty);
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_SCRIPT_BODY.into(), script.into());
        let step = g.add_node_with_metadata(NodeKind::Step, "deploy", TrustZone::FirstParty, meta);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);
        g
    }

    #[test]
    fn template_extends_unpinned_branch_fires_on_missing_ref() {
        let g = graph_with_repo(
            "template-library",
            "git",
            "Template Library/Library",
            None,
            true,
        );
        let findings = template_extends_unpinned_branch(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].category,
            FindingCategory::TemplateExtendsUnpinnedBranch
        );
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("default branch"));
    }

    #[test]
    fn template_extends_unpinned_branch_fires_on_refs_heads_main() {
        let g = graph_with_repo(
            "templates",
            "git",
            "org/templates",
            Some("refs/heads/main"),
            true,
        );
        let findings = template_extends_unpinned_branch(&g);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("mutable branch 'main'"));
    }

    #[test]
    fn template_extends_unpinned_branch_skips_tag_pinned() {
        let g = graph_with_repo(
            "templates",
            "github",
            "org/templates",
            Some("refs/tags/v1.0.0"),
            true,
        );
        let findings = template_extends_unpinned_branch(&g);
        assert!(
            findings.is_empty(),
            "refs/tags/v1.0.0 must be treated as pinned"
        );
    }

    #[test]
    fn template_extends_unpinned_branch_skips_sha_pinned() {
        let sha = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";
        assert_eq!(sha.len(), 40);
        let g = graph_with_repo("templates", "git", "org/templates", Some(sha), true);
        let findings = template_extends_unpinned_branch(&g);
        assert!(
            findings.is_empty(),
            "40-char hex SHA must be treated as pinned"
        );
    }

    #[test]
    fn template_extends_unpinned_branch_skips_unreferenced_repo_with_no_ref() {
        // Spec edge: "repo declared but not referenced anywhere → does not fire
        // (no consumer = no risk)". Applies when the declaration carries no
        // explicit `ref:` field — the entry is purely vestigial in that case.
        let g = graph_with_repo(
            "templates",
            "git",
            "org/templates",
            None,  // no explicit ref
            false, // and no consumer
        );
        let findings = template_extends_unpinned_branch(&g);
        assert!(
            findings.is_empty(),
            "repo declared with no ref and no consumer must not fire"
        );
    }

    #[test]
    fn template_extends_unpinned_branch_fires_on_explicit_branch_even_without_in_file_consumer() {
        // An explicit `ref: refs/heads/<branch>` signals intent to consume —
        // the consumer is typically inside an included template file outside
        // the per-file scan boundary (mirrors the msigeurope corpus shape).
        let g = graph_with_repo(
            "adf_publish",
            "git",
            "org/finance-reporting",
            Some("refs/heads/adf_publish"),
            false, // no in-file consumer
        );
        let findings = template_extends_unpinned_branch(&g);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("mutable branch 'adf_publish'"));
    }

    #[test]
    fn template_extends_unpinned_branch_skips_when_metadata_absent() {
        let g = AuthorityGraph::new(source("ci.yml"));
        assert!(template_extends_unpinned_branch(&g).is_empty());
    }

    #[test]
    fn template_extends_unpinned_branch_handles_bare_branch_name() {
        // `ref: main` (no `refs/heads/` prefix) is a valid ADO shorthand for a branch.
        let g = graph_with_repo(
            "template-library",
            "git",
            "Template Library/Library",
            Some("main"),
            true,
        );
        let findings = template_extends_unpinned_branch(&g);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("mutable branch 'main'"));
    }

    // ── template_repo_ref_is_feature_branch ───────────────────

    #[test]
    fn template_repo_ref_is_feature_branch_fires_on_bare_feature_branch() {
        // Mirrors the corpus shape: `ref: feature/maps-network` (no
        // `refs/heads/` prefix) on the Template Library checkout.
        let g = graph_with_repo(
            "templateLibRepo",
            "git",
            "Template Library/Template Library",
            Some("feature/maps-network"),
            true,
        );
        let findings = template_repo_ref_is_feature_branch(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].category,
            FindingCategory::TemplateRepoRefIsFeatureBranch
        );
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("feature/maps-network"));
        assert!(findings[0].message.contains("feature-class"));
    }

    #[test]
    fn template_repo_ref_is_feature_branch_fires_on_refs_heads_feature() {
        // Same attack via the fully-qualified `refs/heads/feature/...` form.
        let g = graph_with_repo(
            "templates",
            "git",
            "org/templates",
            Some("refs/heads/feature/wip"),
            true,
        );
        let findings = template_repo_ref_is_feature_branch(&g);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("feature/wip"));
    }

    #[test]
    fn template_repo_ref_is_feature_branch_fires_on_develop_branch() {
        // `develop` is not in the trunk set — it's a feature-class branch.
        let g = graph_with_repo(
            "templates",
            "git",
            "org/templates",
            Some("refs/heads/develop"),
            true,
        );
        let findings = template_repo_ref_is_feature_branch(&g);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn template_repo_ref_is_feature_branch_skips_main_branch() {
        // `template_extends_unpinned_branch` still fires on this — but the
        // feature-branch refinement does not, because main is the trunk.
        let g = graph_with_repo(
            "templates",
            "git",
            "org/templates",
            Some("refs/heads/main"),
            true,
        );
        assert!(template_repo_ref_is_feature_branch(&g).is_empty());
        // Sanity: the parent rule still fires on the same input.
        assert_eq!(template_extends_unpinned_branch(&g).len(), 1);
    }

    #[test]
    fn template_repo_ref_is_feature_branch_skips_master_release_hotfix() {
        for ref_value in [
            "master",
            "refs/heads/master",
            "release/v1.4",
            "refs/heads/release/2026-q2",
            "releases/2026-04",
            "hotfix/CVE-2026-0001",
            "refs/heads/hotfix/CVE-2026-0002",
        ] {
            let g = graph_with_repo("t", "git", "org/t", Some(ref_value), true);
            assert!(
                template_repo_ref_is_feature_branch(&g).is_empty(),
                "ref {ref_value:?} must not fire as feature-class"
            );
        }
    }

    #[test]
    fn template_repo_ref_is_feature_branch_skips_pinned_refs() {
        // SHA, tag, and refs/heads/<sha> are all pinned — the feature-branch
        // rule must not fire on any of them, regardless of the alias name.
        let sha = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";
        for ref_value in [
            sha.to_string(),
            "refs/tags/v1.4.2".to_string(),
            format!("refs/heads/{sha}"),
        ] {
            let g = graph_with_repo("templates", "git", "org/t", Some(&ref_value), true);
            assert!(
                template_repo_ref_is_feature_branch(&g).is_empty(),
                "pinned ref {ref_value:?} must not fire"
            );
        }
    }

    #[test]
    fn template_repo_ref_is_feature_branch_skips_when_ref_absent() {
        // The "no ref:" (default-branch) case is left to
        // `template_extends_unpinned_branch`. The feature-branch rule only
        // fires on explicit feature-class refs.
        let g = graph_with_repo("templates", "git", "org/templates", None, true);
        assert!(template_repo_ref_is_feature_branch(&g).is_empty());
    }

    #[test]
    fn template_repo_ref_is_feature_branch_cofires_with_parent_rule() {
        // Both rules should fire together on the corpus shape — the parent
        // says "not pinned", the refinement says "and it's a feature branch".
        let g = graph_with_repo(
            "templateLibRepo",
            "git",
            "Template Library/Template Library",
            Some("feature/maps-network"),
            true,
        );
        let parent = template_extends_unpinned_branch(&g);
        let refinement = template_repo_ref_is_feature_branch(&g);
        assert_eq!(parent.len(), 1, "parent rule must still fire");
        assert_eq!(refinement.len(), 1, "refinement must fire alongside");
        assert_ne!(parent[0].category, refinement[0].category);
    }

    #[test]
    fn is_feature_class_branch_classification() {
        // Trunk-class — must return false.
        for b in [
            "main",
            "MAIN",
            "master",
            "refs/heads/main",
            "release/v1",
            "release/",
            "release",
            "releases/2026",
            "hotfix/x",
            "hotfix",
            "hotfixes/y",
            "  refs/heads/main  ",
        ] {
            assert!(!is_feature_class_branch(b), "{b:?} must be trunk");
        }
        // Feature-class — must return true.
        for b in [
            "feature/foo",
            "topic/bar",
            "dev/wip",
            "wip/x",
            "develop",
            "users/alice/spike",
            "personal-branch",
            "refs/heads/feature/x",
            "main-staging", // not exact main, prefix-only — feature-class
        ] {
            assert!(is_feature_class_branch(b), "{b:?} must be feature-class");
        }
        // Empty / whitespace.
        assert!(!is_feature_class_branch(""));
        assert!(!is_feature_class_branch("   "));
    }

    #[test]
    fn template_extends_unpinned_branch_skips_refs_heads_with_sha() {
        // ADO accepts `ref: refs/heads/<sha>` to lock onto a commit on a branch.
        // The trailing segment is what determines mutability.
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let g = graph_with_repo(
            "templates",
            "git",
            "org/templates",
            Some(&format!("refs/heads/{sha}")),
            true,
        );
        let findings = template_extends_unpinned_branch(&g);
        assert!(findings.is_empty());
    }

    // ── vm_remote_exec_via_pipeline_secret ──────────────

    #[test]
    fn vm_remote_exec_fires_on_set_azvmextension_with_minted_sas() {
        let body = r#"
            $sastokenpackages = New-AzStorageContainerSASToken -Container $packagecontainer -Context $ctx -Permission r -ExpiryTime (Get-Date).AddHours(3)
            Set-AzVMExtension -ResourceGroupName $vmRG -VMName $vm.name -Name 'customScript' `
                -Publisher 'Microsoft.Compute' -ExtensionType 'CustomScriptExtension' `
                -Settings @{ "commandToExecute" = "powershell -File install.ps1 -saskey `"$sastokenpackages`"" }
        "#;
        let g = graph_with_script_step(body, None);
        let findings = vm_remote_exec_via_pipeline_secret(&g);
        assert_eq!(findings.len(), 1, "should fire once");
        assert_eq!(
            findings[0].category,
            FindingCategory::VmRemoteExecViaPipelineSecret
        );
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn vm_remote_exec_fires_on_invoke_azvmruncommand_with_pipeline_secret() {
        let body = r#"
            Invoke-AzVMRunCommand -ResourceGroupName rg -VMName vm `
                -CommandId RunPowerShellScript -ScriptString "Add-LocalGroupMember -Member admin -Password $(DOMAIN_JOIN_PASSWORD)"
        "#;
        let g = graph_with_script_step(body, Some("DOMAIN_JOIN_PASSWORD"));
        let findings = vm_remote_exec_via_pipeline_secret(&g);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .message
            .contains("interpolating a pipeline secret"));
    }

    #[test]
    fn vm_remote_exec_does_not_fire_without_remote_exec_call() {
        // Has a SAS mint, but no VM remote-exec primitive — should not fire.
        let body = r#"
            $sas = New-AzStorageContainerSASToken -Container c -Context $ctx -Permission r -ExpiryTime (Get-Date).AddHours(1)
            Write-Host "sas length is $($sas.Length)"
        "#;
        let g = graph_with_script_step(body, None);
        let findings = vm_remote_exec_via_pipeline_secret(&g);
        assert!(findings.is_empty());
    }

    #[test]
    fn vm_remote_exec_does_not_fire_when_remote_exec_has_no_secret_or_sas() {
        // Set-AzVMExtension with a static command line, no SAS, no secret —
        // should not fire (no exposed credential).
        let body = r#"
            Set-AzVMExtension -ResourceGroupName rg -VMName vm -Name diag `
                -Publisher Microsoft.Azure.Diagnostics -ExtensionType IaaSDiagnostics `
                -Settings @{ "xmlCfg" = "<wadcfg/>" }
        "#;
        let g = graph_with_script_step(body, None);
        let findings = vm_remote_exec_via_pipeline_secret(&g);
        assert!(
            findings.is_empty(),
            "no SAS-mint and no secret interpolation → no finding"
        );
    }

    #[test]
    fn vm_remote_exec_fires_on_az_cli_run_command() {
        let body = r#"
            az vm run-command invoke --resource-group rg --name vm `
                --command-id RunShellScript --scripts "echo $(DB_PASSWORD) > /tmp/x"
        "#;
        let g = graph_with_script_step(body, Some("DB_PASSWORD"));
        let findings = vm_remote_exec_via_pipeline_secret(&g);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("az vm run-command"));
    }

    // ── short_lived_sas_in_command_line ─────────────────

    #[test]
    fn sas_in_cmdline_fires_on_minted_sas_interpolated_into_command_to_execute() {
        let body = r#"
            $sastokenpackages = New-AzStorageContainerSASToken -Container c -Context $ctx -Permission r -ExpiryTime (Get-Date).AddHours(3)
            $settings = @{ "commandToExecute" = "powershell install.ps1 -sas `"$sastokenpackages`"" }
        "#;
        let g = graph_with_script_step(body, None);
        let findings = short_lived_sas_in_command_line(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].category,
            FindingCategory::ShortLivedSasInCommandLine
        );
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains("sastokenpackages"));
    }

    #[test]
    fn sas_in_cmdline_does_not_fire_when_sas_is_only_uploaded_to_blob() {
        // SAS minted but never put on argv — only used to build a URL.
        let body = r#"
            $sas = New-AzStorageContainerSASToken -Container c -Context $ctx -Permission r -ExpiryTime (Get-Date).AddHours(1)
            $url = "https://acct.blob.core.windows.net/c/?" + $sas
            Invoke-WebRequest -Uri $url -OutFile foo.zip
        "#;
        let g = graph_with_script_step(body, None);
        let findings = short_lived_sas_in_command_line(&g);
        assert!(findings.is_empty(), "no command-line sink → no finding");
    }

    #[test]
    fn sas_in_cmdline_does_not_fire_without_sas_mint() {
        let body = r#"
            $settings = @{ "commandToExecute" = "powershell -File foo.ps1" }
        "#;
        let g = graph_with_script_step(body, None);
        let findings = short_lived_sas_in_command_line(&g);
        assert!(findings.is_empty());
    }

    #[test]
    fn sas_in_cmdline_fires_on_az_cli_generate_sas_with_arguments() {
        let body = r#"
            sas=$(az storage container generate-sas --name c --account-name acct --permissions r --expiry 2099-01-01 -o tsv)
            az vm extension set --vm-name vm --resource-group rg --name CustomScript --publisher Microsoft.Compute \
                --settings "{ \"commandToExecute\": \"curl https://acct.blob.core.windows.net/c/foo?$sas\" }"
        "#;
        let g = graph_with_script_step(body, None);
        let findings = short_lived_sas_in_command_line(&g);
        // mint + sink in same script → fires (fallback evidence path).
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn co_fire_on_solarwinds_pattern() {
        // Mirrors the corpus solarwinds shape: SAS minted, embedded in
        // CustomScriptExtension commandToExecute. Both rules must fire.
        let body = r#"
            $sastokenpackages = New-AzStorageContainerSASToken -Container $pc -Context $ctx -Permission r -ExpiryTime (Get-Date).AddHours(3)
            Set-AzVMExtension -ResourceGroupName $rg -VMName $vm `
                -Publisher 'Microsoft.Compute' -ExtensionType 'CustomScriptExtension' `
                -Settings @{ "commandToExecute" = "powershell -File install.ps1 -sas `"$sastokenpackages`"" }
        "#;
        let g = graph_with_script_step(body, None);
        let r6 = vm_remote_exec_via_pipeline_secret(&g);
        let r7 = short_lived_sas_in_command_line(&g);
        assert_eq!(r6.len(), 1, "rule 6 must fire on solarwinds shape");
        assert_eq!(r7.len(), 1, "rule 7 must fire on solarwinds shape");
    }

    #[test]
    fn body_interpolates_var_does_not_match_prefix() {
        // `$sas` should not match `$sastokenpackages`.
        assert!(!body_interpolates_var(
            "Write-Host $sastokenpackages",
            "sas"
        ));
        assert!(body_interpolates_var(
            "Write-Host $sastokenpackages",
            "sastokenpackages"
        ));
        assert!(body_interpolates_var("echo $(SECRET)", "SECRET"));
    }

    #[test]
    fn powershell_sas_assignments_extracts_var_names() {
        let body = r#"
            $a = New-AzStorageContainerSASToken -Container c -Context $ctx -Permission r
            $b = Get-Date
            $sasBlob = New-AzStorageBlobSASToken -Container c -Blob foo -Context $ctx -Permission r
        "#;
        let names = powershell_sas_assignments(body);
        assert!(names.iter().any(|n| n.eq_ignore_ascii_case("a")));
        assert!(names.iter().any(|n| n.eq_ignore_ascii_case("sasBlob")));
        assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("b")));
    }

    #[test]
    fn bash_export_of_pipeline_secret_flagged() {
        let g = build_step_with_script(
            "TF_TOKEN",
            "echo init\nexport TF_TOKEN_app_terraform_io=\"$(TF_TOKEN)\"\nterraform init",
        );
        let findings = secret_to_inline_script_env_export(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("$(TF_TOKEN)"));
    }

    #[test]
    fn powershell_assignment_of_pipeline_secret_flagged() {
        let g = build_step_with_script(
            "AppContainerDBPassword",
            "$AppContainerDBPassword = \"$(AppContainerDBPassword)\"\n$x = 1",
        );
        let findings = secret_to_inline_script_env_export(&g);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("$(AppContainerDBPassword)"));
    }

    #[test]
    fn secret_passed_as_command_argument_not_flagged() {
        // Secret used as a CLI argument, not assigned to a variable. This is
        // covered by the separate META_CLI_FLAG_EXPOSED detection — env_export
        // should NOT also fire here.
        let g = build_step_with_script("TF_TOKEN", "terraform plan -var \"token=$(TF_TOKEN)\"");
        let findings = secret_to_inline_script_env_export(&g);
        assert!(
            findings.is_empty(),
            "command-arg use of $(SECRET) must not trip env-export rule"
        );
    }

    #[test]
    fn step_without_script_body_not_flagged() {
        let mut g = AuthorityGraph::new(source("ado.yml"));
        let secret = g.add_node(NodeKind::Secret, "TF_TOKEN", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "task", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);
        let findings = secret_to_inline_script_env_export(&g);
        assert!(findings.is_empty());
    }

    // ── secret_materialised_to_workspace_file ────────────────

    #[test]
    fn powershell_outfile_of_secret_to_workspace_flagged() {
        // Mirrors Azure_Landing_Zone/userapp-n8nx pattern: secret bound to
        // $var, then $var written via Out-File to $(System.DefaultWorkingDirectory).
        let script = "$AppContainerDBPassword = \"$(AppContainerDBPassword)\"\n\
                      $TFfile = Get-Content $(System.DefaultWorkingDirectory)/in.tfvars\n\
                      $TFfile = $TFfile.Replace(\"x\", $AppContainerDBPassword)\n\
                      $TFfile | Out-File $(System.DefaultWorkingDirectory)/envVars/tffile.tfvars";
        let g = build_step_with_script("AppContainerDBPassword", script);
        let findings = secret_materialised_to_workspace_file(&g);
        assert_eq!(
            findings.len(),
            1,
            "Out-File of bound secret to workspace must fire"
        );
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn bash_redirect_of_secret_to_tfvars_flagged() {
        let script =
            "echo \"token = \\\"$(TF_TOKEN)\\\"\" > $(Build.SourcesDirectory)/secrets.tfvars";
        let g = build_step_with_script("TF_TOKEN", script);
        let findings = secret_materialised_to_workspace_file(&g);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn echoing_secret_to_stdout_not_flagged_by_materialisation_rule() {
        let g = build_step_with_script("TF_TOKEN", "echo using $(TF_TOKEN)\nterraform init");
        let findings = secret_materialised_to_workspace_file(&g);
        assert!(
            findings.is_empty(),
            "stdout echo (no file sink) must not trip materialisation rule"
        );
    }

    #[test]
    fn write_to_unrelated_path_not_flagged() {
        // No workspace-path keyword, no risky extension — should not fire.
        let script = "echo $(MY_SECRET) > /var/tmp/ignore.log";
        let g = build_step_with_script("MY_SECRET", script);
        let findings = secret_materialised_to_workspace_file(&g);
        assert!(findings.is_empty());
    }

    // ── keyvault_secret_to_plaintext ─────────────────────────

    #[test]
    fn keyvault_asplaintext_flagged() {
        let script = "$pass = Get-AzKeyVaultSecret -VaultName foo -Name bar -AsPlainText\n\
                      Write-Host done";
        let g = build_step_with_script("UNUSED", script);
        let findings = keyvault_secret_to_plaintext(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn keyvault_secretvaluetext_legacy_pattern_flagged() {
        let script = "$pwd = (Get-AzKeyVaultSecret -VaultName foo -Name bar).SecretValueText";
        let g = build_step_with_script("UNUSED", script);
        let findings = keyvault_secret_to_plaintext(&g);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn convertfrom_securestring_asplaintext_flagged() {
        let script = "$plain = ConvertFrom-SecureString $sec -AsPlainText";
        let g = build_step_with_script("UNUSED", script);
        let findings = keyvault_secret_to_plaintext(&g);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn keyvault_securestring_handling_not_flagged() {
        // Using the secret as SecureString (no -AsPlainText) is the safe pattern.
        let script = "$sec = Get-AzKeyVaultSecret -VaultName foo -Name bar\n\
                      $cred = New-Object PSCredential 'svc', $sec.SecretValue";
        let g = build_step_with_script("UNUSED", script);
        let findings = keyvault_secret_to_plaintext(&g);
        assert!(
            findings.is_empty(),
            "SecureString-only handling is the recommended pattern and must not fire"
        );
    }

    // ── terraform_auto_approve_in_prod ──────────────────────

    fn step_with_meta(g: &mut AuthorityGraph, name: &str, meta: &[(&str, &str)]) -> NodeId {
        let mut m = std::collections::HashMap::new();
        for (k, v) in meta {
            m.insert((*k).to_string(), (*v).to_string());
        }
        g.add_node_with_metadata(NodeKind::Step, name, TrustZone::FirstParty, m)
    }

    #[test]
    fn terraform_auto_approve_against_prod_connection_fires() {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        step_with_meta(
            &mut g,
            "Terraform : Apply",
            &[
                (META_TERRAFORM_AUTO_APPROVE, "true"),
                (META_SERVICE_CONNECTION_NAME, "sharedservice-w365-prod-sc"),
            ],
        );

        let findings = terraform_auto_approve_in_prod(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(
            findings[0].category,
            FindingCategory::TerraformAutoApproveInProd
        );
        assert!(
            findings[0].message.contains("sharedservice-w365-prod-sc"),
            "message should name the connection, got: {}",
            findings[0].message
        );
    }

    #[test]
    fn terraform_auto_approve_via_edge_to_service_connection_identity() {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        let step = step_with_meta(
            &mut g,
            "Terraform : Apply",
            &[(META_TERRAFORM_AUTO_APPROVE, "true")],
        );
        let mut id_meta = std::collections::HashMap::new();
        id_meta.insert(META_SERVICE_CONNECTION.into(), "true".into());
        let conn = g.add_node_with_metadata(
            NodeKind::Identity,
            "alz-infra-sc-prd-uks",
            TrustZone::FirstParty,
            id_meta,
        );
        g.add_edge(step, conn, EdgeKind::HasAccessTo);

        let findings = terraform_auto_approve_in_prod(&g);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("alz-infra-sc-prd-uks"));
    }

    #[test]
    fn terraform_auto_approve_with_env_gate_does_not_fire() {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        step_with_meta(
            &mut g,
            "Terraform : Apply",
            &[
                (META_TERRAFORM_AUTO_APPROVE, "true"),
                (META_SERVICE_CONNECTION_NAME, "platform-prod-sc"),
                (META_ENV_APPROVAL, "true"),
            ],
        );

        let findings = terraform_auto_approve_in_prod(&g);
        assert!(
            findings.is_empty(),
            "env-gated apply must not fire — gate is the change-control"
        );
    }

    #[test]
    fn terraform_auto_approve_against_non_prod_does_not_fire() {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        step_with_meta(
            &mut g,
            "Terraform : Apply",
            &[
                (META_TERRAFORM_AUTO_APPROVE, "true"),
                (META_SERVICE_CONNECTION_NAME, "platform-dev-sc"),
            ],
        );

        let findings = terraform_auto_approve_in_prod(&g);
        assert!(findings.is_empty(), "dev connection must not match prod");
    }

    #[test]
    fn terraform_apply_without_auto_approve_does_not_fire() {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        step_with_meta(
            &mut g,
            "Terraform : Apply",
            &[(META_SERVICE_CONNECTION_NAME, "platform-prod-sc")],
        );

        let findings = terraform_auto_approve_in_prod(&g);
        assert!(findings.is_empty());
    }

    #[test]
    fn looks_like_prod_connection_matches_real_world_names() {
        assert!(looks_like_prod_connection("sharedservice-w365-prod-sc"));
        assert!(looks_like_prod_connection("alz-infra-sc-prd"));
        assert!(looks_like_prod_connection("prod-tenant-arm"));
        assert!(looks_like_prod_connection("PROD"));
        assert!(looks_like_prod_connection("my_prod_arm"));
        // Negatives — substrings inside other words must not match
        assert!(!looks_like_prod_connection("approver-sc"));
        assert!(!looks_like_prod_connection("reproducer-sc"));
        assert!(!looks_like_prod_connection("dev-sc"));
        assert!(!looks_like_prod_connection("staging"));
    }

    // ── addspn_with_inline_script ───────────────────────────

    #[test]
    fn addspn_with_inline_script_fires_with_basic_body() {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        step_with_meta(
            &mut g,
            "ado : azure : login (federated)",
            &[
                (META_ADD_SPN_TO_ENV, "true"),
                (META_SCRIPT_BODY, "az account show --query id -o tsv"),
            ],
        );

        let findings = addspn_with_inline_script(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(!findings[0]
            .message
            .contains("explicit token laundering detected"));
    }

    #[test]
    fn addspn_with_inline_script_escalates_message_on_token_laundering() {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        step_with_meta(
            &mut g,
            "ado : azure : login (federated)",
            &[
                (META_ADD_SPN_TO_ENV, "true"),
                (
                    META_SCRIPT_BODY,
                    "Write-Output \"##vso[task.setvariable variable=ARM_OIDC_TOKEN]$env:idToken\"",
                ),
            ],
        );

        let findings = addspn_with_inline_script(&g);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0]
                .message
                .contains("explicit token laundering detected"),
            "message should escalate, got: {}",
            findings[0].message
        );
    }

    #[test]
    fn addspn_without_inline_script_does_not_fire() {
        // No META_SCRIPT_BODY → scriptPath form, not inline
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        step_with_meta(
            &mut g,
            "AzureCLI scriptPath",
            &[(META_ADD_SPN_TO_ENV, "true")],
        );

        let findings = addspn_with_inline_script(&g);
        assert!(findings.is_empty());
    }

    #[test]
    fn inline_script_without_addspn_does_not_fire() {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        step_with_meta(
            &mut g,
            "az account show",
            &[(META_SCRIPT_BODY, "az account show")],
        );

        let findings = addspn_with_inline_script(&g);
        assert!(findings.is_empty());
    }

    #[test]
    fn script_launders_spn_token_recognises_known_markers() {
        assert!(script_launders_spn_token(
            "Write-Output \"##vso[task.setvariable variable=ARM_OIDC_TOKEN]$env:idToken\""
        ));
        assert!(script_launders_spn_token(
            "echo \"##vso[task.setvariable variable=X]$env:servicePrincipalKey\""
        ));
        // setvariable without token material → not laundering, just env mutation
        assert!(!script_launders_spn_token(
            "echo \"##vso[task.setvariable variable=X]hello\""
        ));
        // No setvariable at all
        assert!(!script_launders_spn_token("$env:idToken"));
    }

    // ── parameter_interpolation_into_shell ──────────────────

    fn graph_with_param(spec: ParamSpec, name: &str) -> AuthorityGraph {
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        g.parameters.insert(name.to_string(), spec);
        g
    }

    #[test]
    fn parameter_interpolation_fires_on_free_form_string_in_inline_script() {
        let mut g = graph_with_param(
            ParamSpec {
                param_type: "string".into(),
                has_values_allowlist: false,
            },
            "appName",
        );
        step_with_meta(
            &mut g,
            "terraform workspace",
            &[(
                META_SCRIPT_BODY,
                "terraform workspace select -or-create ${{ parameters.appName }}",
            )],
        );

        let findings = parameter_interpolation_into_shell(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains("appName"));
    }

    #[test]
    fn parameter_interpolation_with_values_allowlist_does_not_fire() {
        let mut g = graph_with_param(
            ParamSpec {
                param_type: "string".into(),
                has_values_allowlist: true,
            },
            "location",
        );
        step_with_meta(
            &mut g,
            "Terraform Plan",
            &[(
                META_SCRIPT_BODY,
                "terraform plan -var=\"location=${{ parameters.location }}\"",
            )],
        );

        let findings = parameter_interpolation_into_shell(&g);
        assert!(
            findings.is_empty(),
            "values: allowlist must suppress the finding"
        );
    }

    #[test]
    fn parameter_interpolation_default_type_is_treated_as_string() {
        let mut g = graph_with_param(
            ParamSpec {
                // ADO defaults missing `type:` to string — same risk
                param_type: "".into(),
                has_values_allowlist: false,
            },
            "appName",
        );
        step_with_meta(
            &mut g,
            "Terraform : Plan",
            &[(
                META_SCRIPT_BODY,
                "terraform plan -var \"appName=${{ parameters.appName }}\"",
            )],
        );

        let findings = parameter_interpolation_into_shell(&g);
        assert_eq!(findings.len(), 1, "missing type: must default to string");
    }

    #[test]
    fn parameter_interpolation_skips_non_string_params() {
        let mut g = graph_with_param(
            ParamSpec {
                param_type: "boolean".into(),
                has_values_allowlist: false,
            },
            "enabled",
        );
        step_with_meta(
            &mut g,
            "step",
            &[(META_SCRIPT_BODY, "echo ${{ parameters.enabled }}")],
        );

        let findings = parameter_interpolation_into_shell(&g);
        assert!(findings.is_empty(), "boolean params can't carry shell");
    }

    #[test]
    fn parameter_interpolation_no_spaces_form_also_matches() {
        let mut g = graph_with_param(
            ParamSpec {
                param_type: "string".into(),
                has_values_allowlist: false,
            },
            "x",
        );
        step_with_meta(
            &mut g,
            "step",
            &[(META_SCRIPT_BODY, "echo ${{parameters.x}}")],
        );

        let findings = parameter_interpolation_into_shell(&g);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn parameter_interpolation_skips_step_without_script_body() {
        let mut g = graph_with_param(
            ParamSpec {
                param_type: "string".into(),
                has_values_allowlist: false,
            },
            "appName",
        );
        // Step has no META_SCRIPT_BODY (e.g. a typed task without an inline script)
        g.add_node(NodeKind::Step, "task-step", TrustZone::Untrusted);

        let findings = parameter_interpolation_into_shell(&g);
        assert!(findings.is_empty());
    }
}
