//! Generated McPact MCP server crate. Do not edit generated code directly.

mod server_config;
mod tools;

use mcpact_mcp::ToolRegistry;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    server_config::init("taudit")?;
    let _ = std::process::Command::new(server_config::binary_path()).args(["--version".to_string()]).status();

    let mut registry = ToolRegistry::new();
    registry.register(tools::taudit_baseline_init::Tool::new());
    registry.register(tools::taudit_baseline_list::Tool::new());
    registry.register(tools::taudit_baseline_promote::Tool::new());
    registry.register(tools::taudit_baseline_rollback::Tool::new());
    registry.register(tools::taudit_diff::Tool::new());
    registry.register(tools::taudit_emit_spec::Tool::new());
    registry.register(tools::taudit_explain::Tool::new());
    registry.register(tools::taudit_graph::Tool::new());
    registry.register(tools::taudit_invariants_explain::Tool::new());
    registry.register(tools::taudit_invariants_list::Tool::new());
    registry.register(tools::taudit_map::Tool::new());
    registry.register(tools::taudit_remediate_apply::Tool::new());
    registry.register(tools::taudit_remediate_suggest::Tool::new());
    registry.register(tools::taudit_scan::Tool::new());
    registry.register(tools::taudit_verify::Tool::new());
    mcpact_mcp::serve_stdio(registry).await?;
    Ok(())
}
