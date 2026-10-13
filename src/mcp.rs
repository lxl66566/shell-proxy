//! MCP server exposing the remote shell as `exec`, `read_file`/`write_file`
//! and their base64 twins for binary content.

use anyhow::Result;
use base64::{
    Engine as _,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::{
    check_timeout_ms,
    client::{self, DroppedBytes, RunReport},
    config,
    proto::ExecRequest,
    session::SessionId,
};

/// Default per-call timeout for MCP-driven executions.
const DEFAULT_TIMEOUT_MS: u64 = 600_000;

/// Standard base64 alphabet; decoding also accepts unpadded input, which
/// callers frequently emit.
const BASE64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ExecParams {
    command: String,
    #[serde(default)]
    cwd: Option<String>,
    /// 0 disables the timeout; values above 24 h are rejected as invalid.
    #[serde(default)]
    timeout_ms: Option<u64>,
    /// Target host alias (resolved through the system ssh config); defaults to
    /// the configured host.
    #[serde(default)]
    host: Option<String>,
    /// Session name: independent cwd/state per session on the same host.
    #[serde(default)]
    session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReadFileParams {
    /// Remote path; relative paths resolve against the session's persisted cwd.
    path: String,
    /// Target host alias (resolved through the system ssh config); defaults to
    /// the configured host.
    #[serde(default)]
    host: Option<String>,
    /// Session name: independent cwd/state per session on the same host.
    #[serde(default)]
    session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct WriteFileParams {
    /// Remote path; relative paths resolve against the session's persisted cwd.
    path: String,
    /// UTF-8 file content, written verbatim (truncates).
    content: String,
    /// Target host alias (resolved through the system ssh config); defaults to
    /// the configured host.
    #[serde(default)]
    host: Option<String>,
    /// Session name: independent cwd/state per session on the same host.
    #[serde(default)]
    session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReadFileBinaryParams {
    /// Remote path; relative paths resolve against the session's persisted cwd.
    path: String,
    /// Target host alias (resolved through the system ssh config); defaults to
    /// the configured host.
    #[serde(default)]
    host: Option<String>,
    /// Session name: independent cwd/state per session on the same host.
    #[serde(default)]
    session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct WriteFileBinaryParams {
    /// Remote path; relative paths resolve against the session's persisted cwd.
    path: String,
    /// Base64-encoded file content, decoded before writing (truncates).
    content_b64: String,
    /// Target host alias (resolved through the system ssh config); defaults to
    /// the configured host.
    #[serde(default)]
    host: Option<String>,
    /// Session name: independent cwd/state per session on the same host.
    #[serde(default)]
    session: Option<String>,
}

#[derive(Clone, Default)]
struct SpMcp;

#[tool_router]
impl SpMcp {
    #[tool(
        description = "Execute a bash command on the remote Linux host. cwd and shell state \
                       (exported vars, shell vars, functions, aliases, umask) persist across \
                       calls within one session; pass `session` to keep parallel agents \
                       independent."
    )]
    async fn exec(&self, params: Parameters<ExecParams>) -> Result<CallToolResult, McpError> {
        let host = resolve_host(params.0.host.as_deref())?;
        let session = resolve_session(params.0.session.as_deref())?;
        // Model-controlled input: an oversized value is a caller error, the
        // command must not run.
        let timeout_ms = params.0.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
        check_timeout_ms(timeout_ms).map_err(|e| McpError::invalid_params(e, None))?;
        let req = ExecRequest {
            host,
            command: params.0.command,
            args: Vec::new(),
            cwd: params.0.cwd,
            state: None,
            timeout_ms: Some(timeout_ms),
            session: Some(session.as_str().to_owned()),
        };
        let (report, stdout, stderr, dropped) = call(req, Vec::new()).await?;
        let text = format_report(&report, &stdout, &stderr, &dropped);
        // MCP hosts key retry and correction off isError: a non-zero exit
        // (including 254 internal and 124 timeout) or a reported error is a
        // failed call, not a success carrying error text.
        if report.code != 0 || report.error.is_some() {
            Ok(CallToolResult::error(vec![ContentBlock::text(text)]))
        } else {
            Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
        }
    }

    #[tool(description = "Read a remote file (UTF-8 text).")]
    async fn read_file(
        &self,
        params: Parameters<ReadFileParams>,
    ) -> Result<CallToolResult, McpError> {
        let host = resolve_host(params.0.host.as_deref())?;
        let session = resolve_session(params.0.session.as_deref())?;
        let req = client::download_request(
            host,
            session.as_str().to_owned(),
            &params.0.path,
            None,
            Some(DEFAULT_TIMEOUT_MS),
        );
        read_remote(req, OutputEncoding::Text).await
    }

    #[tool(description = "Read a remote file as base64 (binary-safe).")]
    async fn read_file_binary(
        &self,
        params: Parameters<ReadFileBinaryParams>,
    ) -> Result<CallToolResult, McpError> {
        let host = resolve_host(params.0.host.as_deref())?;
        let session = resolve_session(params.0.session.as_deref())?;
        let req = client::download_request(
            host,
            session.as_str().to_owned(),
            &params.0.path,
            None,
            Some(DEFAULT_TIMEOUT_MS),
        );
        read_remote(req, OutputEncoding::Base64).await
    }

    #[tool(description = "Write UTF-8 text to a remote file (truncates).")]
    async fn write_file(
        &self,
        params: Parameters<WriteFileParams>,
    ) -> Result<CallToolResult, McpError> {
        let host = resolve_host(params.0.host.as_deref())?;
        let session = resolve_session(params.0.session.as_deref())?;
        let req = client::upload_request(
            host,
            session.as_str().to_owned(),
            &params.0.path,
            None,
            Some(DEFAULT_TIMEOUT_MS),
        );
        write_remote(req, params.0.content.into_bytes(), &params.0.path).await
    }

    #[tool(description = "Write base64-decoded bytes to a remote file (truncates).")]
    async fn write_file_binary(
        &self,
        params: Parameters<WriteFileBinaryParams>,
    ) -> Result<CallToolResult, McpError> {
        let host = resolve_host(params.0.host.as_deref())?;
        let session = resolve_session(params.0.session.as_deref())?;
        let content = BASE64
            .decode(params.0.content_b64.as_bytes())
            .map_err(|e| McpError::invalid_params(format!("content_b64: {e}"), None))?;
        let req = client::upload_request(
            host,
            session.as_str().to_owned(),
            &params.0.path,
            None,
            Some(DEFAULT_TIMEOUT_MS),
        );
        write_remote(req, content, &params.0.path).await
    }
}

/// Tool arg > `SP_HOST` env > config file. An empty arg or a missing default
/// host is a caller error.
fn resolve_host(cli: Option<&str>) -> Result<String, McpError> {
    if cli.is_some_and(str::is_empty) {
        return Err(McpError::invalid_params("host must not be empty", None));
    }
    config::resolve_host(cli).map_err(|e| McpError::invalid_params(e.brief(), None))
}

/// Tool arg > `SP_SESSION` env > default; an invalid name from either source
/// is a caller error.
fn resolve_session(cli: Option<&str>) -> Result<SessionId, McpError> {
    config::resolve_session(cli).map_err(|e| McpError::invalid_params(e.brief(), None))
}

/// Run one request with capped captured streams; no signal forwarding (MCP
/// has no console to interrupt from).
async fn call(
    req: ExecRequest,
    stdin: Vec<u8>,
) -> Result<(RunReport, Vec<u8>, Vec<u8>, DroppedBytes), McpError> {
    let (signals_tx, signals_rx) = mpsc::channel(1);
    drop(signals_tx);
    client::run_captured_capped(req, stdin, signals_rx)
        .await
        .map_err(|e| McpError::internal_error(e.brief(), None))
}

/// How the captured file bytes appear in a read tool result.
enum OutputEncoding {
    Text,
    Base64,
}

/// Shared body of the read tools: failures render as an error result,
/// success returns the captured stdout, optionally base64-encoded, clipped to
/// the tool cap.
async fn read_remote(
    req: ExecRequest,
    encoding: OutputEncoding,
) -> Result<CallToolResult, McpError> {
    let (report, stdout, stderr, dropped) = call(req, Vec::new()).await?;
    if let Some(err) = file_result(&report, &stdout, &stderr, &dropped) {
        return Ok(CallToolResult::error(vec![ContentBlock::text(err)]));
    }
    let mut text = match encoding {
        OutputEncoding::Text => clip(&stdout),
        // base64 is ASCII, so clipping its bytes never splits a character.
        OutputEncoding::Base64 => clip(BASE64.encode(&stdout).as_bytes()),
    };
    push_dropped(&mut text, &dropped);
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}

/// Shared body of the write tools: upload `content`, failures render as an
/// error result, success returns a one-line confirmation.
async fn write_remote(
    req: ExecRequest,
    content: Vec<u8>,
    path: &str,
) -> Result<CallToolResult, McpError> {
    let len = content.len();
    let (report, _, stderr, dropped) = call(req, content).await?;
    if let Some(err) = file_result(&report, b"", &stderr, &dropped) {
        return Ok(CallToolResult::error(vec![ContentBlock::text(err)]));
    }
    let mut text = format!("wrote {path} ({len} bytes)");
    push_dropped(&mut text, &dropped);
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}

/// Failure rendering shared by the file tools: `None` means success.
fn file_result(
    report: &RunReport,
    stdout: &[u8],
    stderr: &[u8],
    dropped: &DroppedBytes,
) -> Option<String> {
    if let Some(e) = &report.error {
        return Some(format!("error: {e}"));
    }
    (report.code != 0).then(|| {
        let mut s = format!(
            "exit_code: {}\n--- stdout ---\n{}--- stderr ---\n{}",
            report.code,
            clip(stdout),
            clip(stderr)
        );
        push_dropped(&mut s, dropped);
        s
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

/// Append capture-drop notices at the very end of a tool text, after every
/// clipped section, so [`clip`] can never cut them off: the caller must
/// always learn that output was dropped.
fn push_dropped(out: &mut String, dropped: &DroppedBytes) {
    use std::fmt::Write as _;
    if dropped.stdout == 0 && dropped.stderr == 0 {
        return;
    }
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if dropped.stdout > 0 {
        let _ = writeln!(out, "[dropped {} bytes of stdout]", dropped.stdout);
    }
    if dropped.stderr > 0 {
        let _ = writeln!(out, "[dropped {} bytes of stderr]", dropped.stderr);
    }
}

fn format_report(
    report: &RunReport,
    stdout: &[u8],
    stderr: &[u8],
    dropped: &DroppedBytes,
) -> String {
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
    // The reported cwd saves the caller a follow-up `pwd` to track the session.
    if let Some(cwd) = &report.cwd {
        let _ = writeln!(out, "cwd: {cwd}");
    }
    push_dropped(&mut out, dropped);
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
