//! shell-proxy: run local commands on a remote Linux host with persistent
//! shell state (cwd), as if typed into an interactive bash there.
//!
//! Layout: a resident [`daemon`] owns persistent SSH connections per host and
//! deploys the remote `sp-serve` binary ([`remote`]); each command runs in a
//! fresh `sp-serve` process speaking sp-proto frames over one SSH exec
//! channel. The `sp` CLI and the MCP server are thin clients talking to the
//! daemon over IPC ([`transport`]).

pub mod client;
pub mod config;
pub mod console;
pub mod daemon;
pub mod embed;
pub mod error;
pub mod mcp;
pub mod remote;
pub mod session;
pub mod ssh;
pub mod ssh_config;
pub mod transport;

pub use error::{Error, Result};
pub use sp_proto as proto;

/// Upper bound for caller-supplied execution timeouts, in milliseconds
/// (24 h).
///
/// Deadlines are computed as `tokio::time::Instant + Duration`, which panics
/// on overflow because the instant representation covers a limited range;
/// with `panic = "abort"` in the release profile a single oversized value
/// would kill the resident daemon (or serve) with every live session. Entry
/// points (CLI `--timeout`, MCP `timeout_ms`) reject larger values instead
/// of forwarding them.
pub const MAX_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;

/// Reject a timeout above [`MAX_TIMEOUT_MS`]; `0` (no timeout) is always
/// valid because no deadline is ever built from it. Every entry point
/// funnels caller-supplied timeouts through this check so the bound is
/// enforced identically.
pub fn check_timeout_ms(ms: u64) -> std::result::Result<(), String> {
    if ms > MAX_TIMEOUT_MS {
        Err(format!(
            "timeout of {ms} ms exceeds the maximum of {MAX_TIMEOUT_MS} ms (24 h)"
        ))
    } else {
        Ok(())
    }
}
