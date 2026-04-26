use crate::finding::{Finding, FindingCategory, Recommendation, Severity};
use crate::graph::{
    is_docker_digest_pinned, is_sha_pinned, AuthorityCompleteness, AuthorityGraph, EdgeKind,
    IdentityScope, NodeId, NodeKind, TrustZone, META_ATTESTS, META_CHECKOUT_SELF,
    META_CLI_FLAG_EXPOSED, META_CONTAINER, META_DIGEST, META_ENV_APPROVAL, META_IDENTITY_SCOPE,
    META_IMPLICIT, META_OIDC, META_PERMISSIONS, META_SCRIPT_BODY, META_SELF_HOSTED,
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
    // ADO inline-script secret-leak rules
    findings.extend(secret_to_inline_script_env_export(graph));
    findings.extend(secret_materialised_to_workspace_file(graph));
    findings.extend(keyvault_secret_to_plaintext(graph));

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
}
