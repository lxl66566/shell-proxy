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
    /// Default command timeout in seconds for CLI runs without `--timeout`
    /// (0 = unlimited). An explicit `--timeout` always wins. The MCP server
    /// keeps its own fixed default.
    pub default_timeout_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: None,
            log_level: LogLevel::Info,
            default_timeout_secs: 0,
        }
    }
}

/// Per-user application directory.
///
/// `$XDG_CONFIG_HOME/shell-proxy` when `XDG_CONFIG_HOME` is set to an
/// absolute path (honored on all platforms); otherwise `dirs::config_dir()`
/// (`%APPDATA%` on Windows, `~/.config` on Unix). Pure read: use
/// [`ensure_app_dir`] when the directory must exist.
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
    base.join("shell-proxy")
}

/// Create the app directory if missing and return its path. Callers that
/// write inside the app dir surface creation failures here instead of at a
/// distant write site.
pub fn ensure_app_dir() -> Result<PathBuf> {
    let dir = app_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| Error::Config(format!("create {}: {e}", dir.display())))?;
    Ok(dir)
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
    #[cfg(windows)]
    {
        windows_pipe_name()
    }
    #[cfg(not(windows))]
    {
        app_dir().join("daemon.sock").to_string_lossy().into_owned()
    }
}

/// Named pipe path on Windows. Sanitizing the username can collide across
/// accounts (`a-b` and `a_b` both map to `a_b`); a short hash of the account
/// SID keeps the name stable per user yet distinct per account. Falls back to
/// hashing the username when the SID is unavailable.
#[cfg(windows)]
fn windows_pipe_name() -> String {
    use sha2::{Digest, Sha256};

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
    let bytes = crate::transport::current_user_sid().unwrap_or_else(|_| user.into_bytes());
    let digest = Sha256::digest(&bytes);
    let suffix = &hex_simd::encode_to_string(&digest[..4], hex_simd::AsciiCase::Lower);
    format!(r"\\.\pipe\shell-proxy-{sane}-{suffix}")
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
    use std::sync::{Mutex, OnceLock};

    use super::*;
    use crate::session::DEFAULT_NAME;

    /// Tests in one binary run on parallel threads and the env is process
    /// global; every test that mutates env vars must hold this lock.
    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn app_dir_prefers_absolute_xdg() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let old = std::env::var_os("XDG_CONFIG_HOME");
        // SAFETY: serialized against every other env-mutating test
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
    fn ensure_app_dir_creates_directory() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let old = std::env::var_os("XDG_CONFIG_HOME");
        // SAFETY: serialized against every other env-mutating test
        unsafe { std::env::set_var("XDG_CONFIG_HOME", tmp.path()) };
        let dir = ensure_app_dir().unwrap();
        assert!(dir.is_dir());
        assert_eq!(dir, tmp.path().join("shell-proxy"));
        match old {
            Some(v) => unsafe { std::env::set_var("XDG_CONFIG_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_CONFIG_HOME") },
        }
    }

    /// The SID-derived suffix is stable across calls and independent of the
    /// sanitized username; distinct accounts get distinct SIDs, hence distinct
    /// pipe names even when their sanitized names collide.
    #[cfg(windows)]
    #[test]
    fn sock_path_suffix_is_stable_per_user() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let old_sock = std::env::var_os(ENV_SOCK);
        let old_user = std::env::var_os("USERNAME");
        // SAFETY: serialized against every other env-mutating test
        unsafe { std::env::remove_var(ENV_SOCK) };

        let name = sock_path();
        assert!(name.starts_with(r"\\.\pipe\shell-proxy-"));
        let suffix = name.rsplit('-').next().unwrap_or_default();
        assert_eq!(suffix.len(), 8);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));

        // Same account, colliding sanitized names: the suffix part is unchanged.
        unsafe { std::env::set_var("USERNAME", "a-b") };
        let with_dash = sock_path();
        unsafe { std::env::set_var("USERNAME", "a_b") };
        let with_underscore = sock_path();
        assert!(with_dash.starts_with(r"\\.\pipe\shell-proxy-a_b-"));
        assert!(with_underscore.starts_with(r"\\.\pipe\shell-proxy-a_b-"));
        assert_eq!(
            with_dash.rsplit('-').next(),
            with_underscore.rsplit('-').next()
        );
        assert_eq!(sock_path(), with_underscore);

        match old_sock {
            Some(v) => unsafe { std::env::set_var(ENV_SOCK, v) },
            None => unsafe { std::env::remove_var(ENV_SOCK) },
        }
        match old_user {
            Some(v) => unsafe { std::env::set_var("USERNAME", v) },
            None => unsafe { std::env::remove_var("USERNAME") },
        }
    }

    #[test]
    fn load_config_reads_default_timeout_secs() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("shell-proxy");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let old = std::env::var_os("XDG_CONFIG_HOME");
        // SAFETY: serialized against every other env-mutating test
        unsafe { std::env::set_var("XDG_CONFIG_HOME", tmp.path()) };

        std::fs::write(&path, "default_timeout_secs = 120\n").unwrap();
        assert_eq!(load_config().unwrap().default_timeout_secs, 120);

        // Absent key keeps the zero default (unlimited).
        std::fs::write(&path, "log_level = \"warn\"\n").unwrap();
        assert_eq!(load_config().unwrap().default_timeout_secs, 0);

        match old {
            Some(v) => unsafe { std::env::set_var("XDG_CONFIG_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_CONFIG_HOME") },
        }
    }

    #[test]
    fn resolve_session_precedence() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: serialized against every other env-mutating test
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
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(resolve_session(Some("no spaces")).is_err());
        // SAFETY: serialized against every other env-mutating test
        unsafe { std::env::set_var(ENV_SESSION, "no/slashes") };
        assert!(resolve_session(None).is_err());
        unsafe { std::env::remove_var(ENV_SESSION) };
    }
}
