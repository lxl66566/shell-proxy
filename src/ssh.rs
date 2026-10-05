//! SSH connection: transport (direct or ProxyCommand), host key verification,
//! authentication (agent first, then identity files) and keepalives.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use russh::{
    client::{self, Handle},
    keys::{
        self, HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate, agent::client::AgentClient,
        known_hosts::check_known_hosts_path, ssh_key,
    },
};
use tokio::{
    net::TcpStream,
    process::{Child, ChildStdin, ChildStdout, Command},
};

use crate::{
    error::Error,
    ssh_config::{ResolvedHost, expand_proxy_command},
};

type Result<T> = std::result::Result<T, Error>;

/// russh client callback implementation doing strict known_hosts checking.
pub struct ClientHandler {
    resolved: ResolvedHost,
    /// Detailed rejection reason; shared with [`connect`] because russh
    /// consumes the handler and only reports a generic error on rejection.
    hostkey_reason: Arc<Mutex<Option<String>>>,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    // Signature is dictated by the russh trait; the future shape is not ours to choose.
    #[allow(clippy::unused_async_trait_impl)]
    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let server_public_key: ssh_key::PublicKey = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            PublicKeyOrCertificate::Certificate(cert) => {
                ssh_key::PublicKey::new(cert.public_key().clone(), "")
            },
        };
        let host = &self.resolved.hostname;
        let port = self.resolved.port;
        // Real files only: `ssh -G` emits /dev/null and platform placeholders
        // (e.g. __PROGRAMDATA__) that must be skipped, plus missing defaults.
        let files: Vec<&Path> = self
            .resolved
            .known_hosts_files
            .iter()
            .filter(|p| p.as_os_str() != "/dev/null" && p.is_file())
            .map(PathBuf::as_path)
            .collect();
        match decide_host_key(host, port, self.resolved.strict_host_keys, &files, |path| {
            KnownHostCheck::from_result(check_known_hosts_path(
                host,
                port,
                &server_public_key,
                path,
            ))
        }) {
            HostKeyDecision::Accept => Ok(true),
            HostKeyDecision::Reject(reason) => {
                *self.hostkey_reason.lock().expect("hostkey lock") = Some(reason);
                Ok(false)
            },
        }
    }
}

/// Outcome of checking one known_hosts file for the server key.
enum KnownHostCheck {
    /// The file records this exact key for the host.
    Matched,
    /// The file has no entry for the host.
    Absent,
    /// The file records a different key for the host, or cannot be parsed;
    /// both fail closed as a changed key.
    Changed { line: String },
}

impl KnownHostCheck {
    fn from_result(r: std::result::Result<bool, keys::Error>) -> Self {
        match r {
            Ok(true) => Self::Matched,
            Ok(false) => Self::Absent,
            Err(e) => Self::Changed {
                line: match &e {
                    keys::Error::KeyChanged { line } => line.to_string(),
                    _ => "?".to_string(),
                },
            },
        }
    }
}

/// Verdict for a server key: accept, or reject with a user-facing reason.
enum HostKeyDecision {
    Accept,
    Reject(String),
}

/// Decide whether the server key of `host`:`port` may be trusted.
///
/// `files` are the existing known_hosts files in ssh config order; `check` is
/// invoked lazily per file and evaluation stops at the first match or change,
/// so an earlier match never sees a later file's failure.
fn decide_host_key<F>(
    host: &str,
    port: u16,
    strict: bool,
    files: &[&Path],
    mut check: F,
) -> HostKeyDecision
where
    F: FnMut(&Path) -> KnownHostCheck,
{
    let mut checked: Vec<&Path> = Vec::new();
    for path in files {
        match check(path) {
            KnownHostCheck::Matched => return HostKeyDecision::Accept,
            KnownHostCheck::Absent => checked.push(path),
            KnownHostCheck::Changed { line } => {
                return HostKeyDecision::Reject(format!(
                    "host key of {host}:{port} changed ({} line {line}); remove the stale entry \
                     or verify the server",
                    path.display()
                ));
            },
        }
    }
    if !strict {
        // Matches `StrictHostKeyChecking no/off/accept-new`: first sight of
        // a host is accepted.
        return HostKeyDecision::Accept;
    }
    if checked.is_empty() {
        // sp never writes known_hosts, so an empty file set is not first-use
        // trust but a permanent skip of key verification; refuse instead.
        return HostKeyDecision::Reject(format!(
            "no readable known_hosts file to verify the host key of {host}:{port}; sp does not \
             write known_hosts, run `ssh {host} true` once on this machine so OpenSSH records the \
             key"
        ));
    }
    let names = checked
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    HostKeyDecision::Reject(format!(
        "host key of {host}:{port} not found in {names}; connect once with `ssh {host} true` to \
         record it"
    ))
}

/// Handle alias used across the crate.
pub type SshHandle = Handle<ClientHandler>;

/// An established, authenticated SSH connection.
pub struct SshConnection {
    handle: SshHandle,
    /// Keeps the ProxyCommand child alive while the connection lives.
    _proxy_child: Option<Child>,
}

impl SshConnection {
    #[must_use]
    pub fn handle(&self) -> &SshHandle {
        &self.handle
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }
}

/// Connect and authenticate to `resolved`.
pub async fn connect(resolved: ResolvedHost) -> Result<SshConnection> {
    let config = Arc::new(client::Config {
        keepalive_interval: Some(std::time::Duration::from_secs(30)),
        keepalive_max: 3,
        nodelay: true,
        ..Default::default()
    });

    let handler = ClientHandler {
        resolved: resolved.clone(),
        hostkey_reason: Arc::new(Mutex::new(None)),
    };
    let hostkey_reason = Arc::clone(&handler.hostkey_reason);

    let map_connect_err =
        |e: russh::Error| match hostkey_reason.lock().expect("hostkey lock").take() {
            Some(reason) => Error::HostKey(reason),
            None => Error::Connect(e.to_string()),
        };

    let mut proxy_child = None;
    let mut handle = if let Some(pc) = resolved.proxy_command.as_deref() {
        let cmd = expand_proxy_command(pc, &resolved.hostname, resolved.port);
        let (stream, child) =
            spawn_proxy(&cmd).map_err(|e| Error::Connect(format!("proxycommand {cmd:?}: {e}")))?;
        proxy_child = Some(child);
        client::connect_stream(config, stream, handler)
            .await
            .map_err(map_connect_err)?
    } else {
        let addr = (resolved.hostname.as_str(), resolved.port);
        // ssh config ConnectTimeout when set, otherwise a library default.
        let timeout = resolved
            .connect_timeout
            .unwrap_or(std::time::Duration::from_secs(15));
        let tcp = tokio::time::timeout(timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| Error::Connect(format!("connect to {addr:?} timed out")))?
            .map_err(|e| Error::Connect(format!("connect to {addr:?}: {e}")))?;
        client::connect_stream(config, tcp, handler)
            .await
            .map_err(map_connect_err)?
    };

    authenticate(&mut handle, &resolved).await?;

    Ok(SshConnection {
        handle,
        _proxy_child: proxy_child,
    })
}

/// Duplex over a ProxyCommand child's pipes.
type ProxyStream = tokio::io::Join<ChildStdout, ChildStdin>;

/// Spawn a ProxyCommand, wiring its stdout->russh read side and stdin->write side.
fn spawn_proxy(cmd: &str) -> std::io::Result<(ProxyStream, Child)> {
    let mut command = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(cmd);
        c
    } else {
        let mut c = Command::new("sh");
        c.arg("-c").arg(cmd);
        c
    };
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    // Taken handles keep the pipes open; they are the russh transport.
    let stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    let stream = tokio::io::join(stdout, stdin);
    Ok((stream, child))
}

async fn authenticate(handle: &mut SshHandle, resolved: &ResolvedHost) -> Result<()> {
    let user = resolved.user.clone();

    // 1. ssh-agent
    if let Ok(mut agent) = connect_agent().await
        && let Ok(identities) = agent.request_identities().await
    {
        for identity in identities {
            let pubkey = identity.public_key().into_owned();
            if matches!(
                handle
                    .authenticate_publickey_with(&user, pubkey, None, &mut agent)
                    .await,
                Ok(client::AuthResult::Success)
            ) {
                return Ok(());
            }
        }
    }

    // 2. identity files
    let mut attempts: Vec<String> = Vec::new();
    for path in &resolved.identity_files {
        let key = match keys::load_secret_key(path, None) {
            Ok(k) => k,
            Err(keys::Error::KeyIsEncrypted) => {
                attempts.push(format!(
                    "{}: encrypted, add it to ssh-agent",
                    path.display()
                ));
                continue;
            },
            Err(_) => continue, // missing/unreadable is normal, ssh skips too
        };
        let hash = if key.algorithm().is_rsa() {
            Some(HashAlg::Sha512)
        } else {
            None
        };
        let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
        match handle.authenticate_publickey(&user, key_with_hash).await {
            Ok(client::AuthResult::Success) => return Ok(()),
            _ => attempts.push(format!("{}: rejected", path.display())),
        }
    }

    Err(Error::Auth(format!(
        "no auth method succeeded for {}@{}; agent tried, keys: {}",
        resolved.user,
        resolved.hostname,
        if attempts.is_empty() {
            "none usable".to_string()
        } else {
            attempts.join("; ")
        }
    )))
}

/// Connect to the ssh-agent; Windows uses the OpenSSH named pipe, others $SSH_AUTH_SOCK.
#[cfg(windows)]
async fn connect_agent()
-> std::result::Result<AgentClient<tokio::net::windows::named_pipe::NamedPipeClient>, keys::Error> {
    AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await
}

#[cfg(unix)]
async fn connect_agent() -> std::result::Result<AgentClient<tokio::net::UnixStream>, keys::Error> {
    AgentClient::connect_env().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_files_strict_rejects_with_guidance() {
        match decide_host_key("h", 22, true, &[], |_| unreachable!()) {
            HostKeyDecision::Reject(reason) => {
                assert!(reason.contains("no readable known_hosts file"));
                assert!(reason.contains("sp does not write known_hosts"));
                assert!(reason.contains("`ssh h true`"));
            },
            HostKeyDecision::Accept => panic!("strict mode must reject without known_hosts"),
        }
    }

    #[test]
    fn no_files_non_strict_accepts() {
        assert!(matches!(
            decide_host_key("h", 22, false, &[], |_| unreachable!()),
            HostKeyDecision::Accept
        ));
    }

    #[test]
    fn unrecorded_host() {
        let files = [
            Path::new("/u/.ssh/known_hosts"),
            Path::new("/etc/ssh/ssh_known_hosts"),
        ];
        match decide_host_key("h", 2222, true, &files, |_| KnownHostCheck::Absent) {
            HostKeyDecision::Reject(reason) => {
                assert!(reason.contains("h:2222"));
                assert!(reason.contains("/u/.ssh/known_hosts, /etc/ssh/ssh_known_hosts"));
                assert!(reason.contains("`ssh h true`"));
            },
            HostKeyDecision::Accept => panic!("strict mode must reject an unrecorded host"),
        }
        assert!(matches!(
            decide_host_key("h", 22, false, &files, |_| KnownHostCheck::Absent),
            HostKeyDecision::Accept
        ));
    }

    #[test]
    fn matched_accepts_and_stops_checking() {
        let files = [Path::new("/a"), Path::new("/b")];
        let mut calls = 0;
        let decision = decide_host_key("h", 22, true, &files, |_| {
            calls += 1;
            KnownHostCheck::Matched
        });
        assert!(matches!(decision, HostKeyDecision::Accept));
        assert_eq!(calls, 1);
    }

    #[test]
    fn changed_key_is_a_hard_failure_even_non_strict() {
        let files = [Path::new("/a"), Path::new("/b")];
        let mut calls = 0;
        let decision = decide_host_key("h", 22, false, &files, |path| {
            calls += 1;
            if path == Path::new("/a") {
                KnownHostCheck::Changed { line: "3".into() }
            } else {
                KnownHostCheck::Matched
            }
        });
        match decision {
            HostKeyDecision::Reject(reason) => {
                assert!(reason.contains("changed (/a line 3)"));
            },
            HostKeyDecision::Accept => panic!("a changed key must fail even in non-strict mode"),
        }
        assert_eq!(calls, 1);
    }
}
