//! User configuration and well-known paths.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    session::SessionId,
};

/// Env var overriding the daemon socket path (mainly for tests).
pub const ENV_SOCK: &str = "SP_SOCK";
/// Env var overriding the binary spawned as the daemon (mainly for tests:
/// the test binary must not respawn itself, libtest would parse "daemon" as a
/// test-name filter and recurse).
pub const ENV_DAEMON_EXE: &str = "SP_DAEMON_EXE";
/// Env var overriding the default host.
pub const ENV_HOST: &str = "SP_HOST";
/// Env var overriding the default session.
pub const ENV_SESSION: &str = "SP_SESSION";

/// Daemon log level; invalid values fail config parsing instead of silently
/// falling back.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

/// User configuration loaded from `config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Default remote host alias (resolved through the system ssh config).
    pub host: Option<String>,
    /// Daemon log level.
    pub log_level: LogLevel,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: None,
            log_level: LogLevel::Info,
        }
    }
}

/// Per-user application directory.
///
/// `$XDG_CONFIG_HOME/shell-proxy` when `XDG_CONFIG_HOME` is set to an
/// absolute path (honored on all platforms); otherwise `dirs::config_dir()`
/// (`%APPDATA%` on Windows, `~/.config` on Unix).
#[must_use]
pub fn app_dir() -> PathBuf {
    let xdg = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        // XDG spec: relative values must be ignored
        .filter(|p| p.is_absolute());
    let base = xdg
        .or_else(dirs::config_dir)
        .unwrap_or_else(|| PathBuf::from(".shell-proxy"));
    let dir = base.join("shell-proxy");
    let _ = std::fs::create_dir_all(&dir);
    dir
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

/// Resolve the effective session: CLI/tool arg > env > default.
///
/// Sessions are daemon-lifetime state, not persisted configuration, so there
/// is no config.toml knob. An invalid value from any source is an error, not
/// a silent fallback: a typo would silently split one session in two.
pub fn resolve_session(cli: Option<&str>) -> Result<SessionId> {
    if let Some(s) = cli {
        return SessionId::parse(s).map_err(|e| Error::Config(format!("invalid session name: {e}")));
    }
    if let Ok(s) = std::env::var(ENV_SESSION)
        && !s.is_empty()
    {
        return SessionId::parse(&s).map_err(|e| Error::Config(format!("{ENV_SESSION}: {e}")));
    }
    Ok(SessionId::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::DEFAULT_NAME;

    #[test]
    fn app_dir_prefers_absolute_xdg() {
        let tmp = tempfile::tempdir().unwrap();
        let old = std::env::var_os("XDG_CONFIG_HOME");
        // SAFETY: no other test in this binary touches XDG_CONFIG_HOME
        unsafe { std::env::set_var("XDG_CONFIG_HOME", tmp.path()) };
        assert_eq!(app_dir(), tmp.path().join("shell-proxy"));
        // relative value is ignored per XDG spec
        unsafe { std::env::set_var("XDG_CONFIG_HOME", "rel/path") };
        assert_ne!(app_dir(), PathBuf::from("rel/path").join("shell-proxy"));
        match old {
            Some(v) => unsafe { std::env::set_var("XDG_CONFIG_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_CONFIG_HOME") },
        }
    }

    #[test]
    fn resolve_session_precedence() {
        // SAFETY: no other test in this binary touches SP_SESSION
        unsafe { std::env::set_var(ENV_SESSION, "from-env") };
        // CLI arg wins over env
        assert_eq!(
            resolve_session(Some("from-cli")).unwrap().as_str(),
            "from-cli"
        );
        // env used when no CLI arg
        assert_eq!(resolve_session(None).unwrap().as_str(), "from-env");
        unsafe { std::env::remove_var(ENV_SESSION) };
        // default when neither
        assert_eq!(resolve_session(None).unwrap().as_str(), DEFAULT_NAME);
    }

    #[test]
    fn resolve_session_rejects_invalid_input() {
        assert!(resolve_session(Some("no spaces")).is_err());
        // SAFETY: no other test in this binary touches SP_SESSION
        unsafe { std::env::set_var(ENV_SESSION, "no/slashes") };
        assert!(resolve_session(None).is_err());
        unsafe { std::env::remove_var(ENV_SESSION) };
    }
}
