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
