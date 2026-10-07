//! Host resolution through the system `ssh -G` output.
//!
//! We reuse the OpenSSH client to parse `~/.ssh/config` (aliases, ProxyCommand,
//! ProxyJump, IdentityFile, UserKnownHostsFile) instead of reimplementing it.

use std::{path::PathBuf, time::Duration};

use spdlog::prelude::*;
use tokio::process::Command;

use crate::error::{Error, Result};

/// Fully resolved connection parameters for one host alias.
#[derive(Debug, Clone)]
pub struct ResolvedHost {
    /// Real hostname or IP after alias expansion.
    pub hostname: String,
    pub port: u16,
    pub user: String,
    /// Identity files, in ssh config order (already includes ssh defaults).
    pub identity_files: Vec<PathBuf>,
    /// known_hosts files to check against.
    pub known_hosts_files: Vec<PathBuf>,
    /// ProxyCommand with %h/%p already expanded; None for direct connections.
    pub proxy_command: Option<String>,
    /// `connecttimeout` seconds (0/unset = library default); bounds the TCP
    /// connect and the shared handshake + authentication budget.
    pub connect_timeout: Option<Duration>,
    /// `stricthostkeychecking` value: unknown keys are rejected unless this
    /// is `no`/`off`/`accept-new`.
    pub strict_host_keys: bool,
    /// `hostkeyalias`: known_hosts entries are recorded under this name
    /// instead of the hostname.
    pub host_key_alias: Option<String>,
}

/// Resolve `host` by running `ssh -G host` and parsing the key/value output.
///
/// Fails when `ssh -G` is unusable and the local user cannot be determined.
pub async fn resolve(host: &str) -> Result<ResolvedHost> {
    match run_ssh_g(host).await {
        Ok(r) => Ok(r),
        Err(e) => {
            // Masking this would surface as a confusing "connect to <alias>
            // failed" later; the reason belongs in the daemon log.
            warn!("ssh -G failed, falling back to a direct connection: {e}");
            fallback(host)
        },
    }
}

/// Local username (ssh `%u`); None when the environment has neither USER nor
/// USERNAME.
fn local_user() -> Option<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
}

/// Direct connection fallback used when `ssh -G` cannot run at all.
fn fallback(host: &str) -> Result<ResolvedHost> {
    let user = local_user().ok_or_else(|| Error::Resolve {
        host: host.to_owned(),
        reason: "cannot determine the local user: neither USER nor USERNAME is set".into(),
    })?;
    Ok(ResolvedHost {
        hostname: host.to_owned(),
        port: 22,
        user,
        identity_files: default_identity_files(),
        known_hosts_files: vec![home_ssh().join("known_hosts")],
        proxy_command: None,
        connect_timeout: None,
        strict_host_keys: true,
        host_key_alias: None,
    })
}

fn default_identity_files() -> Vec<PathBuf> {
    [
        "id_ed25519",
        "id_ecdsa",
        "id_rsa",
        "id_ed25519_sk",
        "id_ecdsa_sk",
    ]
    .into_iter()
    .map(|n| home_ssh().join(n))
    .collect()
}

fn home_ssh() -> PathBuf {
    dirs::home_dir().unwrap_or_default().join(".ssh")
}

async fn run_ssh_g(host: &str) -> Result<ResolvedHost> {
    let out = tokio::time::timeout(
        Duration::from_secs(10),
        Command::new("ssh").arg("-G").arg(host).output(),
    )
    .await
    .map_err(|_| Error::Resolve {
        host: host.to_owned(),
        reason: "ssh -G timed out".into(),
    })?
    .map_err(|e| Error::Resolve {
        host: host.to_owned(),
        reason: format!("cannot run ssh: {e}"),
    })?;

    if !out.status.success() {
        return Err(Error::Resolve {
            host: host.to_owned(),
            reason: format!(
                "ssh -G exited with {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            ),
        });
    }

    let text = String::from_utf8_lossy(&out.stdout);
    parse_ssh_g_output(host, &text)
}

/// Parse `ssh -G` output: one `key value...` per line, values may be quoted.
fn parse_ssh_g_output(host: &str, text: &str) -> Result<ResolvedHost> {
    let mut hostname = None;
    let mut port = 22u16;
    let mut user = None;
    let mut identity_files = Vec::new();
    let mut known_hosts_files = Vec::new();
    let mut proxy_command = None;
    let mut proxy_jump = None;
    let mut connect_timeout = None;
    let mut host_key_alias = None;

    let mut strict_host_keys = true;

    for line in text.lines() {
        let Some((key, value)) = line.split_once(' ') else {
            continue
        };
        match key {
            "hostname" => hostname = Some(unquote(value)),
            "port" => port = value.parse().unwrap_or(22),
            "user" => user = Some(unquote(value)),
            // 0 means "system default" in ssh, which we map to our own default
            "connecttimeout" => {
                connect_timeout = unquote(value)
                    .parse()
                    .ok()
                    .filter(|secs: &u64| *secs > 0)
                    .map(Duration::from_secs);
            },
            "identityfile" => identity_files.push(PathBuf::from(expand_tilde(&unquote(value)))),
            // userknownhostsfile carries several paths on one line
            "userknownhostsfile" => known_hosts_files.extend(
                split_values(value)
                    .into_iter()
                    .map(|v| expand_tilde(&v))
                    .map(PathBuf::from),
            ),
            // system-wide known_hosts (/etc/ssh/ssh_known_hosts, Windows
            // ProgramData); consulted after the per-user files
            "globalknownhostsfile" => known_hosts_files.extend(
                split_values(value)
                    .into_iter()
                    .map(|v| expand_tilde(&v))
                    .map(PathBuf::from),
            ),
            "stricthostkeychecking" => {
                strict_host_keys = !matches!(unquote(value).as_str(), "no" | "off" | "accept-new");
            },
            "proxycommand" => {
                let v = unquote(value);
                if v != "none" {
                    proxy_command = Some(v);
                }
            },
            "proxyjump" => {
                let v = unquote(value);
                if v != "none" {
                    proxy_jump = Some(v);
                }
            },
            // `none` when unset; ssh -G lowercases the sentinel
            "hostkeyalias" => {
                let v = unquote(value);
                if !v.eq_ignore_ascii_case("none") {
                    host_key_alias = Some(v);
                }
            },
            _ => {},
        }
    }

    let hostname = hostname.ok_or_else(|| Error::Resolve {
        host: host.to_owned(),
        reason: "ssh -G output has no hostname".into(),
    })?;

    // ssh resolves the user itself when the config sets none; the local user
    // is the fallback, and a missing one is an error rather than a guess.
    let user = user.or_else(local_user).ok_or_else(|| Error::Resolve {
        host: host.to_owned(),
        reason: "ssh -G output has no user and neither USER nor USERNAME is set".into(),
    })?;

    // ProxyJump is materialized by OpenSSH into a ProxyCommand; build one ourselves
    // in case only the jump field is set. Tokens in the jump spec are expanded
    // with the target's hostname/port/user, like OpenSSH does; inserted values
    // are percent-escaped for `cmd /C` on Windows.
    let escape = cfg!(windows);
    let proxy_command = proxy_command.or_else(|| {
        proxy_jump.map(|jump| {
            let jump = expand_tokens(
                &jump,
                &hostname,
                port,
                &user,
                local_user().as_deref(),
                escape,
            );
            format!("ssh -W [{}]:{port} {jump}", insert_value(&hostname, escape))
        })
    });

    if identity_files.is_empty() {
        identity_files = default_identity_files();
    }
    if known_hosts_files.is_empty() {
        known_hosts_files = vec![home_ssh().join("known_hosts")];
    }

    Ok(ResolvedHost {
        hostname,
        port,
        user,
        identity_files,
        known_hosts_files,
        proxy_command,
        connect_timeout,
        strict_host_keys,
        host_key_alias,
    })
}

/// Value inserted into a ProxyCommand string. On Windows the command runs
/// through `cmd /C`, which expands `%VAR%` references: a literal `%` in a
/// hostname, port or user must be doubled so it survives verbatim.
fn insert_value(v: &str, escape: bool) -> String {
    if escape {
        v.replace('%', "%%")
    } else {
        v.to_owned()
    }
}

/// Expand ProxyCommand tokens in a single left-to-right pass: `%%`, `%h`,
/// `%n`, `%p`, `%r`, `%u`. Tokens sp cannot expand (`%C`, `%d`, `%f`, ...) are
/// left verbatim for the command to interpret.
fn expand_tokens(
    cmd: &str,
    hostname: &str,
    port: u16,
    user: &str,
    local_user: Option<&str>,
    escape: bool,
) -> String {
    // %n is the pre-canonicalization hostname, which sp does not keep; the
    // resolved hostname is the closest equivalent.
    let hostname = insert_value(hostname, escape);
    let user = insert_value(user, escape);
    let mut out = String::with_capacity(cmd.len());
    let mut chars = cmd.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            // Trailing or doubled percent: a literal percent.
            Some('%') | None => out.push('%'),
            Some('h' | 'n') => out.push_str(&hostname),
            Some('p') => out.push_str(&port.to_string()),
            Some('r') => out.push_str(&user),
            // %u is the local username; kept verbatim when it is unknown.
            Some('u') => match local_user {
                Some(u) => out.push_str(&insert_value(u, escape)),
                None => out.push_str("%u"),
            },
            // Unknown token: keep verbatim.
            Some(other) => {
                out.push('%');
                out.push(other);
            },
        }
    }
    out
}

/// Expand %h/%p/%n/%r/%u tokens in a ProxyCommand.
#[must_use]
pub fn expand_proxy_command(cmd: &str, hostname: &str, port: u16, user: &str) -> String {
    expand_tokens(
        cmd,
        hostname,
        port,
        user,
        local_user().as_deref(),
        cfg!(windows),
    )
}

/// Expand a leading `~` to the user's home directory (`ssh -G` emits `~/...`).
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest).to_string_lossy().into_owned();
    }
    path.to_owned()
}

fn unquote(v: &str) -> String {
    let v = v.trim();
    if v.len() >= 2
        && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\'')))
    {
        v[1..v.len() - 1].to_owned()
    } else {
        v.to_owned()
    }
}

/// Split a value list on spaces, keeping quoted segments intact.
fn split_values(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for ch in value.chars() {
        match quote {
            Some(q) if ch == q => {
                quote = None;
                cur.push(ch);
            },
            None if ch == '"' || ch == '\'' => {
                quote = Some(ch);
                cur.push(ch);
            },
            None if ch.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            },
            Some(_) | None => cur.push(ch),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out.into_iter().map(|v| unquote(&v)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let text = "\
host ls
hostname 192.168.10.171
user root
port 22
proxycommand none
identityfile C:\\Users\\x\\.ssh\\id_rsa
identityfile C:\\Users\\x\\.ssh\\id_ed25519
userknownhostsfile C:\\Users\\x\\.ssh\\known_hosts
globalknownhostsfile C:\\ProgramData\\ssh\\ssh_known_hosts
";
        let r = parse_ssh_g_output("ls", text).unwrap();
        assert_eq!(r.hostname, "192.168.10.171");
        assert_eq!(r.user, "root");
        assert_eq!(r.port, 22);
        assert!(r.proxy_command.is_none());
        assert_eq!(r.identity_files.len(), 2);
        assert_eq!(r.known_hosts_files.len(), 2);
    }

    #[test]
    fn parse_quoted_and_jump() {
        let text = "\
host j
hostname \"ex ample.com\"
port 2222
user u1
proxyjump bastion
identityfile \"C:/a b/id_ed25519\"
";
        let r = parse_ssh_g_output("j", text).unwrap();
        assert_eq!(r.hostname, "ex ample.com");
        assert_eq!(r.port, 2222);
        assert_eq!(
            r.proxy_command.as_deref(),
            Some("ssh -W [ex ample.com]:2222 bastion")
        );
        assert_eq!(r.identity_files[0], PathBuf::from("C:/a b/id_ed25519"));
    }

    #[test]
    fn parse_connecttimeout() {
        let mk = |text: &str| format!("host x\nhostname h\nconnecttimeout {text}\n");
        assert_eq!(
            parse_ssh_g_output("x", &mk("10")).unwrap().connect_timeout,
            Some(Duration::from_secs(10))
        );
        // Quoted values are unquoted before parsing.
        assert_eq!(
            parse_ssh_g_output("x", &mk("\"10\""))
                .unwrap()
                .connect_timeout,
            Some(Duration::from_secs(10))
        );
        // 0 = system default in ssh, mapped to our own default
        assert_eq!(
            parse_ssh_g_output("x", &mk("0")).unwrap().connect_timeout,
            None
        );
        assert_eq!(
            parse_ssh_g_output("x", &mk("junk"))
                .unwrap()
                .connect_timeout,
            None
        );
    }

    #[test]
    fn parse_hostkeyalias() {
        let mk = |v: &str| format!("host x\nhostname h\nhostkeyalias {v}\n");
        assert_eq!(
            parse_ssh_g_output("x", &mk("myalias"))
                .unwrap()
                .host_key_alias,
            Some("myalias".into())
        );
        assert_eq!(
            parse_ssh_g_output("x", &mk("NONE")).unwrap().host_key_alias,
            None
        );
        assert_eq!(
            parse_ssh_g_output("x", &mk("none")).unwrap().host_key_alias,
            None
        );
    }

    #[test]
    fn default_identities_include_security_keys() {
        let files = default_identity_files();
        assert!(files.iter().any(|p| p.ends_with("id_ed25519_sk")));
        assert!(files.iter().any(|p| p.ends_with("id_ecdsa_sk")));
    }

    #[test]
    fn proxyjump_tokens_expand() {
        let text = "\
host j
hostname ex.org
port 2200
user u1
proxyjump u2@jump%h:2222
";
        let r = parse_ssh_g_output("j", text).unwrap();
        assert_eq!(
            r.proxy_command.as_deref(),
            Some("ssh -W [ex.org]:2200 u2@jumpex.org:2222")
        );
    }

    #[test]
    fn expand_proxy_command_tokens() {
        assert_eq!(
            expand_tokens("nc %h %p %%", "h1", 22, "r1", Some("lu"), false),
            "nc h1 22 %"
        );
        assert_eq!(
            expand_tokens(
                "ssh -l %r -o User=%u %n:%p",
                "h1",
                2200,
                "r1",
                Some("lu"),
                false
            ),
            "ssh -l r1 -o User=lu h1:2200"
        );
        // %u stays verbatim when the local user is unknown; unknown tokens
        // and a trailing percent are preserved.
        assert_eq!(
            expand_tokens("x %u %d %", "h", 22, "r", None, false),
            "x %u %d %"
        );
    }

    #[test]
    fn inserted_values_are_percent_escaped_for_cmd() {
        assert_eq!(insert_value("a%b", true), "a%%b");
        assert_eq!(insert_value("a%b", false), "a%b");
        // With escaping, a hostname containing % survives `cmd /C` expansion.
        assert_eq!(
            expand_tokens("nc %h %p", "h%1", 22, "r%2", None, true),
            "nc h%%1 22"
        );
        assert_eq!(
            expand_tokens("nc %h %r", "h%1", 22, "r%2", Some("u%3"), true),
            "nc h%%1 r%%2"
        );
        // The public entry point escapes only on Windows.
        let expanded = expand_proxy_command("nc %h", "h%1", 22, "r");
        if cfg!(windows) {
            assert_eq!(expanded, "nc h%%1");
        } else {
            assert_eq!(expanded, "nc h%1");
        }
    }

    #[test]
    fn expand_proxy_command_basic() {
        assert_eq!(
            expand_proxy_command("connect -H 1 %h %p", "h1", 22, "u"),
            "connect -H 1 h1 22"
        );
    }
}
