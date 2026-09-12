//! shell-proxy: run local commands on a remote Linux host with persistent
//! shell state (cwd), as if typed into an interactive bash there.
//!
//! Layout: a resident [`daemon`] owns persistent SSH connections and per-host
//! cwd state; the `sp` CLI and the MCP server are thin clients talking to it
//! over IPC. Each command is a generated bash script ([`script`]) uploaded and
//! executed through two SSH channels ([`exec`]); stdout carries a trailing cwd
//! marker stripped by [`marker`].

pub mod client;
pub mod config;
pub mod console;
pub mod daemon;
pub mod error;
pub mod exec;
pub mod ipc;
pub mod marker;
pub mod mcp;
pub mod script;
pub mod ssh;
pub mod ssh_config;
pub mod transport;

pub use error::{Error, Result};
