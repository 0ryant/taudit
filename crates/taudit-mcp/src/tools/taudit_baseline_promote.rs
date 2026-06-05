//! Generated tool `taudit_baseline_promote`.

use crate::server_config;
use async_trait::async_trait;
use mcpact_audit::AuditSink;
use mcpact_mcp::{McpTool, ToolCallResult, ToolDefinition};
use mcpact_runtime::{ExecutionPlan, Executor};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TauditBaselinePromoteArgs {
    pub pipeline: String,
    pub fingerprint: String,
    pub rule_id: String,
    pub severity: String,
    pub reason: String,
    #[serde(default)]
    pub severity_override: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub root: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Tool;

impl Tool {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl McpTool for Tool {
    fn definition(&self) -> ToolDefinition {
        let schema = schemars::schema_for!(TauditBaselinePromoteArgs);
        ToolDefinition {
            name: "taudit_baseline_promote".into(),
            title: Some("Promote finding into baseline".into()),
            description: "Append a finding to a baseline as an accepted waiver (taudit's `baseline accept`). Requires --reason >= 10 chars; critical waivers require --severity-override + --expires-at.".into(),
            input_schema: serde_json::to_value(&schema).unwrap_or_else(|_| json!({"type":"object"})),
            output_schema: None,
            annotations: Some(mcpact_mcp::ToolDefinition::mcpact_annotations(mcpact_core::AuthorityClass::Mutate, server_config::TRUST)),
        }
    }

    async fn call(&self, arguments: serde_json::Value) -> ToolCallResult {
        let args: TauditBaselinePromoteArgs = match serde_json::from_value(arguments) {
            Ok(args) => args,
            Err(err) => return ToolCallResult::error(format!("invalid arguments: {err}")),
        };

        let tool_spec: mcpact_manifest::ToolSpec = match serde_json::from_str(include_str!(
            concat!("../../.mcpact/tools/taudit_baseline_promote.json")
        )) {
            Ok(spec) => spec,
            Err(err) => return ToolCallResult::error(format!("tool spec load failed: {err}")),
        };
        let args_json = match serde_json::to_value(&args) {
            Ok(value) => value,
            Err(err) => {
                return ToolCallResult::error(format!("argument serialization failed: {err}"))
            }
        };
        let workspace = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let ctx = mcpact_policy::PolicyContext {
            workspace_root: workspace,
            trust_ceiling: server_config::TRUST,
            approved: std::env::var("MCPACT_APPROVED").is_ok_and(|value| value == "1"),
            allow_network: tool_spec.policy.network,
            allowed_secrets: BTreeSet::new(),
        };
        match mcpact_policy::evaluate_invocation(&ctx, &tool_spec, &args_json) {
            Ok(decision) if decision.allowed => {}
            Ok(decision) => {
                let reason = decision.reason.clone();
                let event = mcpact_audit::EvidenceEvent::tool_denied(
                    "taudit_baseline_promote",
                    mcpact_core::AuthorityClass::Mutate,
                    &reason,
                );
                let sink = server_config::audit_sink();
                let _ = sink.emit(&event).await;
                return ToolCallResult::error(reason);
            }
            Err(err) => {
                let event = mcpact_audit::EvidenceEvent::tool_denied(
                    "taudit_baseline_promote",
                    mcpact_core::AuthorityClass::Mutate,
                    err.to_string(),
                );
                let sink = server_config::audit_sink();
                let _ = sink.emit(&event).await;
                return ToolCallResult::error(err.to_string());
            }
        }

        let mut plan =
            ExecutionPlan::new(server_config::binary_path().to_string_lossy().to_string());
        plan.argv = Vec::new();
        plan.argv.push("baseline".into());
        plan.argv.push("accept".into());
        if args.expires_at.is_some() {
            plan.argv.push("--expires-at".into());
            plan.argv.push(args.expires_at.unwrap_or_default());
        }
        plan.argv.push("--fingerprint".into());
        plan.argv.push(args.fingerprint.to_string());
        plan.argv.push("--pipeline".into());
        plan.argv.push(args.pipeline.to_string());
        plan.argv.push("--reason".into());
        plan.argv.push(args.reason.to_string());
        if args.root.is_some() {
            plan.argv.push("--root".into());
            plan.argv.push(args.root.unwrap_or_default());
        }
        plan.argv.push("--rule-id".into());
        plan.argv.push(args.rule_id.to_string());
        plan.argv.push("--severity".into());
        plan.argv.push(args.severity.to_string());
        if args.severity_override.is_some() {
            plan.argv.push("--severity-override".into());
            plan.argv.push(args.severity_override.unwrap_or_default());
        }
        let redacted = Vec::new();
        plan.redacted_arg_indexes = redacted;
        plan.env.inherit = false;

        plan.timeout = std::time::Duration::from_secs(60);
        plan.max_output_bytes = 524288;
        plan.output_mode = mcpact_runtime::OutputMode::Json;
        plan.authority = mcpact_core::AuthorityClass::Mutate;

        let plan_for_audit = plan.clone();
        match Executor.execute(plan).await {
            Ok(result) => {
                let event = mcpact_audit::EvidenceEvent::tool_executed(
                    "taudit_baseline_promote",
                    &plan_for_audit,
                    &result,
                );
                let sink = server_config::audit_sink();
                let _ = sink.emit(&event).await;
                if let Some(value) = result.structured {
                    ToolCallResult::structured(value)
                } else if result.stderr.is_empty() {
                    ToolCallResult::text(result.stdout)
                } else {
                    ToolCallResult::text(format!("{}\n{}", result.stdout, result.stderr))
                }
            }
            Err(err) => {
                let event = mcpact_audit::EvidenceEvent::tool_failed(
                    "taudit_baseline_promote",
                    &plan_for_audit,
                    err.to_string(),
                );
                let sink = server_config::audit_sink();
                let _ = sink.emit(&event).await;
                ToolCallResult::error(format!("execution failed: {err}"))
            }
        }
    }
}
