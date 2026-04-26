use crate::finding::{Finding, FindingCategory, Recommendation, Severity};
use crate::graph::{
    is_docker_digest_pinned, is_sha_pinned, AuthorityCompleteness, AuthorityGraph, EdgeKind,
    IdentityScope, NodeId, NodeKind, TrustZone, META_ATTESTS, META_CHECKOUT_SELF,
    META_CLI_FLAG_EXPOSED, META_CONTAINER, META_DIGEST, META_ENV_APPROVAL, META_IDENTITY_SCOPE,
    META_IMPLICIT, META_OIDC, META_PERMISSIONS, META_REPOSITORIES, META_SELF_HOSTED,
    META_SERVICE_CONNECTION, META_TRIGGER, META_VARIABLE_GROUP, META_WRITES_ENV_GATE,
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
}
