//! User configuration and well-known paths.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Env var overriding the daemon socket path (mainly for tests).
pub const ENV_SOCK: &str = "SP_SOCK";
/// Env var overriding the default host.
pub const ENV_HOST: &str = "SP_HOST";

/// User configuration loaded from `config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Default remote host alias (resolved through the system ssh config).
    pub host: Option<String>,
    /// Daemon log level: trace/debug/info/warn/error.
    pub log_level: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: None,
            log_level: "info".into(),
        }
    }
}

/// Per-user application directory (`%APPDATA%/shell-proxy` or `~/.config/shell-proxy`).
#[must_use]
pub fn app_dir() -> PathBuf {
    let base =
        dirs::config_dir().map_or_else(|| PathBuf::from(".shell-proxy"), |d| d.join("shell-proxy"));
    let _ = std::fs::create_dir_all(&base);
    base
}

/// Path of the daemon IPC endpoint.
///
/// Windows uses a named pipe, other platforms a unix socket inside the app dir.
#[must_use]
pub fn sock_path() -> String {
    if let Ok(p) = std::env::var(ENV_SOCK)
        && !p.is_empty()
    {
        return p;
    }
    if cfg!(windows) {
        let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".into());
        let sane: String = user
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        format!(r"\\.\pipe\shell-proxy-{sane}")
    } else {
        app_dir().join("daemon.sock").to_string_lossy().into_owned()
    }
}

/// Load `config.toml` from the app dir. Missing file yields defaults.
pub fn load_config() -> Result<Config> {
    let path = app_dir().join("config.toml");
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(e) => return Err(Error::Config(format!("read {}: {e}", path.display()))),
    };
    toml::from_str(&text).map_err(|e| Error::Config(format!("parse {}: {e}", path.display())))
}

/// Resolve the effective host: CLI arg > env > config file.
pub fn resolve_host(cli: Option<&str>) -> Result<String> {
    if let Some(h) = cli {
        return Ok(h.to_owned());
    }
    if let Ok(h) = std::env::var(ENV_HOST)
        && !h.is_empty()
    {
        return Ok(h);
    }
    load_config()?
        .host
        .filter(|h| !h.is_empty())
        .ok_or_else(|| {
            Error::Config(format!(
                "no host configured; pass --host, set {ENV_HOST}, or set `host` in {}",
                app_dir().join("config.toml").display()
            ))
        })
}
