//! Generated tool `taudit_invariants_list`.

use crate::server_config;
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use mcpact_mcp::{McpTool, ToolCallResult, ToolDefinition};
use mcpact_runtime::{ExecutionPlan, Executor};
use mcpact_audit::AuditSink;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TauditInvariantsListArgs {
    #[serde(default)]
    pub invariants_dir: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Tool;

impl Tool {
    pub fn new() -> Self { Self }
}

#[async_trait]
impl McpTool for Tool {
    fn definition(&self) -> ToolDefinition {
        let schema = schemars::schema_for!(TauditInvariantsListArgs);
        ToolDefinition {
            name: "taudit_invariants_list".into(),
            title: Some("List invariants".into()),
            description: "List every loaded invariant (built-in plus any custom).".into(),
            input_schema: serde_json::to_value(&schema).unwrap_or_else(|_| json!({"type":"object"})),
            output_schema: None,
            annotations: Some(mcpact_mcp::ToolDefinition::mcpact_annotations(mcpact_core::AuthorityClass::Observe, server_config::TRUST)),
        }
    }

    async fn call(&self, arguments: serde_json::Value) -> ToolCallResult {
        let args: TauditInvariantsListArgs = match serde_json::from_value(arguments) {
            Ok(args) => args,
            Err(err) => return ToolCallResult::error(format!("invalid arguments: {err}")),
        };

        let tool_spec: mcpact_manifest::ToolSpec = match serde_json::from_str(include_str!(concat!("../../.mcpact/tools/taudit_invariants_list.json"))) {
            Ok(spec) => spec,
            Err(err) => return ToolCallResult::error(format!("tool spec load failed: {err}")),
        };
        let args_json = match serde_json::to_value(&args) {
            Ok(value) => value,
            Err(err) => return ToolCallResult::error(format!("argument serialization failed: {err}")),
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
                    "taudit_invariants_list",
                    mcpact_core::AuthorityClass::Observe,
                    &reason,
                );
                let sink = server_config::audit_sink();
                let _ = sink.emit(&event).await;
                return ToolCallResult::error(reason);
            }
            Err(err) => {
                let event = mcpact_audit::EvidenceEvent::tool_denied(
                    "taudit_invariants_list",
                    mcpact_core::AuthorityClass::Observe,
                    err.to_string(),
                );
                let sink = server_config::audit_sink();
                let _ = sink.emit(&event).await;
                return ToolCallResult::error(err.to_string());
            }
        }

        let mut plan = ExecutionPlan::new(server_config::binary_path().to_string_lossy().to_string());
        plan.argv = Vec::new();
        plan.argv.push("invariants".into());
        plan.argv.push("list".into());
        if args.invariants_dir.is_some() {
        plan.argv.push("--invariants-dir".into());
        plan.argv.push(match args.invariants_dir { Some(v) => v, None => String::new() });
        }
        let redacted = Vec::new();
        plan.redacted_arg_indexes = redacted;
        plan.env.inherit = false;
        plan.env.allow = vec!["NO_COLOR".into()];

        plan.timeout = std::time::Duration::from_secs(30);
        plan.max_output_bytes = 524288;
        plan.output_mode = mcpact_runtime::OutputMode::Text;
        plan.authority = mcpact_core::AuthorityClass::Observe;

        let plan_for_audit = plan.clone();
        match Executor::default().execute(plan).await {
            Ok(result) => {
                let event = mcpact_audit::EvidenceEvent::tool_executed("taudit_invariants_list", &plan_for_audit, &result);
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
                    "taudit_invariants_list",
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
