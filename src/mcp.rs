//! MCP server exposing the remote shell as one `exec` tool.

use anyhow::Result;
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::{
    client::{self, RunReport},
    config,
    ipc::ExecRequest,
};

/// Default per-call timeout for MCP-driven executions.
const DEFAULT_TIMEOUT_MS: u64 = 600_000;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ExecParams {
    command: String,
    #[serde(default)]
    cwd: Option<String>,
    /// 0 disables the timeout.
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(Clone, Default)]
struct SpMcp;

#[tool_router]
impl SpMcp {
    #[tool(
        description = "Execute a bash command on the remote Linux host. cwd persists across calls."
    )]
    async fn exec(&self, params: Parameters<ExecParams>) -> Result<CallToolResult, McpError> {
        let host =
            config::resolve_host(None).map_err(|e| McpError::internal_error(e.brief(), None))?;
        let req = ExecRequest {
            host,
            command: params.0.command,
            args: Vec::new(),
            cwd: params.0.cwd,
            timeout_ms: Some(params.0.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
        };
        let (signals_tx, signals_rx) = mpsc::channel(1);
        drop(signals_tx);
        let (report, stdout, stderr) = client::run_captured(req, Vec::new(), signals_rx)
            .await
            .map_err(|e| McpError::internal_error(e.brief(), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(
            format_report(&report, &stdout, &stderr),
        )]))
    }
}

#[tool_handler]
impl ServerHandler for SpMcp {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        let mut imp = rmcp::model::Implementation::default();
        imp.name = env!("CARGO_PKG_NAME").into();
        imp.version = env!("CARGO_PKG_VERSION").into();
        info.server_info = imp;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.instructions = Some("Run shell commands on the remote Linux host.".into());
        info
    }
}

fn format_report(report: &RunReport, stdout: &[u8], stderr: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "exit_code: {}", report.code);
    if let Some(cwd) = &report.cwd {
        let _ = writeln!(out, "cwd: {cwd}");
    }
    if report.timed_out {
        let _ = writeln!(out, "timed_out: true");
    }
    let _ = writeln!(out, "--- stdout ---");
    out.push_str(&String::from_utf8_lossy(stdout));
    if !stdout.is_empty() && !stdout.ends_with(b"\n") {
        out.push('\n');
    }
    let _ = writeln!(out, "--- stderr ---");
    out.push_str(&String::from_utf8_lossy(stderr));
    if !stderr.is_empty() && !stderr.ends_with(b"\n") {
        out.push('\n');
    }
    out
}

/// Serve MCP over stdio until the client disconnects.
pub async fn run() -> Result<()> {
    let server = SpMcp
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|e| anyhow::anyhow!("serve stdio: {e}"))?;
    server
        .waiting()
        .await
        .map_err(|e| anyhow::anyhow!("mcp server ended: {e}"))?;
    Ok(())
}
