//! Generated tool `taudit_remediate_apply`.

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
pub struct TauditRemediateApplyArgs {
    /// One or more pipeline file paths. Multiple paths may be supplied as a
    /// single whitespace-separated string; each token is forwarded to the CLI
    /// as its own argv element (a space-separated list is NOT treated as one
    /// filename). Paths containing spaces are not supported via this field.
    pub paths: String,
    pub policy: String,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub allow_risky: bool,
    #[serde(default)]
    pub min_confidence: Option<f64>,
    #[serde(default)]
    pub backup_root: Option<String>,
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
        let schema = schemars::schema_for!(TauditRemediateApplyArgs);
        ToolDefinition {
            name: "taudit_remediate_apply".into(),
            title: Some("Apply remediations".into()),
            description: "Apply low-risk remediations with backup + validation + auto-restore. Mutates pipeline files.".into(),
            input_schema: serde_json::to_value(&schema).unwrap_or_else(|_| json!({"type":"object"})),
            output_schema: None,
            annotations: Some(mcpact_mcp::ToolDefinition::mcpact_annotations(mcpact_core::AuthorityClass::Mutate, server_config::TRUST)),
        }
    }

    async fn call(&self, arguments: serde_json::Value) -> ToolCallResult {
        let args: TauditRemediateApplyArgs = match serde_json::from_value(arguments) {
            Ok(args) => args,
            Err(err) => return ToolCallResult::error(format!("invalid arguments: {err}")),
        };

        let tool_spec: mcpact_manifest::ToolSpec = match serde_json::from_str(include_str!(
            concat!("../../.mcpact/tools/taudit_remediate_apply.json")
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
                    "taudit_remediate_apply",
                    mcpact_core::AuthorityClass::Mutate,
                    &reason,
                );
                let sink = server_config::audit_sink();
                let _ = sink.emit(&event).await;
                return ToolCallResult::error(reason);
            }
            Err(err) => {
                let event = mcpact_audit::EvidenceEvent::tool_denied(
                    "taudit_remediate_apply",
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
        plan.argv.push("remediate".into());
        plan.argv.push("--unstable".into());
        plan.argv.push("apply".into());
        // Split the whitespace-separated path list and push each token as its
        // own argv element, so a multi-path string is not handed to the CLI as
        // a single (non-existent) filename.
        for path in args.paths.split_whitespace() {
            plan.argv.push(path.to_string());
        }
        if args.allow_risky {
            plan.argv.push("--allow-risky".into());
        }
        if args.backup_root.is_some() {
            plan.argv.push("--backup-root".into());
            plan.argv.push(args.backup_root.unwrap_or_default());
        }
        if args.format.is_some() {
            plan.argv.push("--format".into());
            plan.argv.push(args.format.unwrap_or_default());
        }
        if args.min_confidence.is_some() {
            plan.argv.push("--min-confidence".into());
            plan.argv.push(match args.min_confidence {
                Some(v) => v.to_string(),
                None => String::new(),
            });
        }
        plan.argv.push("--policy".into());
        plan.argv.push(args.policy.to_string());
        let redacted = Vec::new();
        plan.redacted_arg_indexes = redacted;
        plan.env.inherit = false;

        plan.timeout = std::time::Duration::from_secs(600);
        plan.max_output_bytes = 2097152;
        plan.output_mode = mcpact_runtime::OutputMode::Json;
        plan.authority = mcpact_core::AuthorityClass::Mutate;

        let plan_for_audit = plan.clone();
        match Executor.execute(plan).await {
            Ok(result) => {
                let event = mcpact_audit::EvidenceEvent::tool_executed(
                    "taudit_remediate_apply",
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
                    "taudit_remediate_apply",
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
