//! MCP server exposing the remote shell as `exec`, `read_file` and
//! `write_file` tools.

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
    proto::ExecRequest,
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReadFileParams {
    /// Remote path; relative paths resolve against the persisted cwd.
    path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct WriteFileParams {
    /// Remote path; relative paths resolve against the persisted cwd.
    path: String,
    /// UTF-8 file content, written verbatim (truncates).
    content: String,
}

#[derive(Clone, Default)]
struct SpMcp;

#[tool_router]
impl SpMcp {
    #[tool(
        description = "Execute a bash command on the remote Linux host. cwd and shell state \
                       (exported vars, shell vars, functions, aliases, umask) persist across \
                       calls."
    )]
    async fn exec(&self, params: Parameters<ExecParams>) -> Result<CallToolResult, McpError> {
        let host = resolve_host()?;
        let req = ExecRequest {
            host,
            command: params.0.command,
            args: Vec::new(),
            cwd: params.0.cwd,
            state: None,
            timeout_ms: Some(params.0.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
        };
        let (report, stdout, stderr) = call(req, Vec::new()).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(
            format_report(&report, &stdout, &stderr),
        )]))
    }

    #[tool(description = "Read a remote file (UTF-8 text).")]
    async fn read_file(
        &self,
        params: Parameters<ReadFileParams>,
    ) -> Result<CallToolResult, McpError> {
        let host = resolve_host()?;
        let req = client::download_request(host, &params.0.path, None, Some(DEFAULT_TIMEOUT_MS));
        let (report, stdout, stderr) = call(req, Vec::new()).await?;
        match file_result(&report, &stdout, &stderr) {
            Some(err) => Ok(CallToolResult::error(vec![ContentBlock::text(err)])),
            None => Ok(CallToolResult::success(vec![ContentBlock::text(clip(
                &stdout,
            ))])),
        }
    }

    #[tool(description = "Write UTF-8 text to a remote file (truncates).")]
    async fn write_file(
        &self,
        params: Parameters<WriteFileParams>,
    ) -> Result<CallToolResult, McpError> {
        let host = resolve_host()?;
        let req = client::upload_request(host, &params.0.path, None, Some(DEFAULT_TIMEOUT_MS));
        let content = params.0.content;
        let len = content.len();
        let (report, _, stderr) = call(req, content.into_bytes()).await?;
        match file_result(&report, b"", &stderr) {
            Some(err) => Ok(CallToolResult::error(vec![ContentBlock::text(err)])),
            None => Ok(CallToolResult::success(vec![ContentBlock::text(format!(
                "wrote {} ({len} bytes)",
                params.0.path
            ))])),
        }
    }
}

fn resolve_host() -> Result<String, McpError> {
    config::resolve_host(None).map_err(|e| McpError::internal_error(e.brief(), None))
}

/// Run one request with captured streams; no signal forwarding (MCP has no
/// console to interrupt from).
async fn call(req: ExecRequest, stdin: Vec<u8>) -> Result<(RunReport, Vec<u8>, Vec<u8>), McpError> {
    let (signals_tx, signals_rx) = mpsc::channel(1);
    drop(signals_tx);
    client::run_captured(req, stdin, signals_rx)
        .await
        .map_err(|e| McpError::internal_error(e.brief(), None))
}

/// Failure rendering shared by the file tools: `None` means success.
fn file_result(report: &RunReport, stdout: &[u8], stderr: &[u8]) -> Option<String> {
    if let Some(e) = &report.error {
        return Some(format!("error: {e}"));
    }
    (report.code != 0).then(|| {
        format!(
            "exit_code: {}\n--- stdout ---\n{}--- stderr ---\n{}",
            report.code,
            clip(stdout),
            clip(stderr)
        )
    })
}

// The `tool_handler` macro generates an async `call` without awaits.
#[allow(clippy::unused_async_trait_impl)]
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

/// Each captured stream is capped at this size in the tool result; the MCP
/// client is not the place to relay gigabytes.
const MAX_TOOL_OUTPUT: usize = 64 * 1024;

/// Render one stream, truncating with a notice beyond the cap. Cutting inside
/// a UTF-8 sequence only costs one replacement character at the boundary.
fn clip(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    if bytes.len() <= MAX_TOOL_OUTPUT {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let mut s = String::from_utf8_lossy(&bytes[..MAX_TOOL_OUTPUT]).into_owned();
    if !s.ends_with('\n') {
        s.push('\n');
    }
    let _ = writeln!(s, "...[truncated, {} bytes total]", bytes.len());
    s
}

fn format_report(report: &RunReport, stdout: &[u8], stderr: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "exit_code: {}", report.code);
    if let Some(e) = &report.error {
        let _ = writeln!(out, "error: {e}");
    }
    if report.timed_out {
        let _ = writeln!(out, "timed_out: true");
    }
    let _ = writeln!(out, "--- stdout ---");
    out.push_str(&clip(stdout));
    if !stdout.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    let _ = writeln!(out, "--- stderr ---");
    out.push_str(&clip(stderr));
    if !stderr.is_empty() && !out.ends_with('\n') {
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
