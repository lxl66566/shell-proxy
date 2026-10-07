//! SSH connection: transport (direct or ProxyCommand), host key verification,
//! authentication (agent first, then identity files) and keepalives.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use russh::{
    MethodKind,
    client::{self, Handle},
    keys::{
        self, HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate,
        agent::client::AgentClient,
        check_known_hosts_path, ssh_key,
        ssh_key::known_hosts::{Entry, HostPatterns, Marker},
    },
};
use tokio::{
    net::TcpStream,
    process::{Child, ChildStdin, ChildStdout, Command},
    time::Instant,
};

use crate::{
    error::Error,
    ssh_config::{ResolvedHost, expand_proxy_command},
};

type Result<T> = std::result::Result<T, Error>;

/// TCP connect timeout when the config sets no `connecttimeout`.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Shared handshake + authentication budget when the config sets no
/// `connecttimeout`.
const SSH_SETUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Ceiling for config-derived timeouts. `Instant + Duration` panics on
/// overflow, so an absurd `connecttimeout` must be capped before any
/// deadline arithmetic.
const CONNECT_TIMEOUT_CAP: Duration = Duration::from_secs(86_400);

fn clamp_timeout(d: Duration) -> Duration {
    d.min(CONNECT_TIMEOUT_CAP)
}

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
        match self.decide_server_key(key) {
            HostKeyDecision::Accept => Ok(true),
            HostKeyDecision::Reject(reason) => {
                *self.hostkey_reason.lock().expect("hostkey lock") = Some(reason);
                Ok(false)
            },
        }
    }
}

impl ClientHandler {
    fn decide_server_key(&self, key: &PublicKeyOrCertificate) -> HostKeyDecision {
        // HostKeyAlias replaces the hostname in every known_hosts form; the
        // resolved hostname must not be used for lookup when it is set.
        let record_host = self
            .resolved
            .host_key_alias
            .as_deref()
            .unwrap_or(&self.resolved.hostname);
        let endpoint = format!("{}:{}", self.resolved.hostname, self.resolved.port);
        // Real files only: `ssh -G` emits /dev/null and platform placeholders
        // (e.g. __PROGRAMDATA__) that must be skipped, plus missing defaults.
        let files: Vec<&Path> = self
            .resolved
            .known_hosts_files
            .iter()
            .filter(|p| p.as_os_str() != "/dev/null" && p.is_file())
            .map(PathBuf::as_path)
            .collect();

        match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => decide_host_key(
                &endpoint,
                record_host,
                self.resolved.strict_host_keys,
                &files,
                |path| check_known_host_file(path, record_host, self.resolved.port, key, false),
            ),
            PublicKeyOrCertificate::Certificate(cert) => decide_certificate(
                &endpoint,
                record_host,
                self.resolved.port,
                self.resolved.strict_host_keys,
                &files,
                &ssh_key::PublicKey::new(cert.public_key().clone(), ""),
            ),
        }
    }
}

/// Decide a certificate presentation: plain entries never authorize a
/// certificate and sp does not implement host-certificate (CA) verification,
/// so only revocation can decide; anything else fails closed in strict mode.
/// Non-strict keeps accepting unseen keys, certificates included.
fn decide_certificate(
    endpoint: &str,
    record_host: &str,
    port: u16,
    strict: bool,
    files: &[&Path],
    cert_key: &ssh_key::PublicKey,
) -> HostKeyDecision {
    for path in files {
        if let KnownHostCheck::Revoked { line } =
            check_known_host_file(path, record_host, port, cert_key, true)
        {
            return HostKeyDecision::Reject(format!(
                "host key presented by {endpoint} is revoked ({} line {line})",
                path.display()
            ));
        }
    }
    if strict {
        HostKeyDecision::Reject(format!(
            "server presented a host key certificate for {endpoint}; sp does not verify host \
             certificates"
        ))
    } else {
        HostKeyDecision::Accept
    }
}

/// Outcome of checking one known_hosts file for the server key.
#[derive(Debug)]
enum KnownHostCheck {
    /// The file records this exact key for the host.
    Matched,
    /// The file has no entry for the host.
    Absent,
    /// The file records a different key of the same algorithm for the host.
    Changed { line: String },
    /// The file revokes this key.
    Revoked { line: String },
    /// A host-matching line cannot be parsed, so the file cannot decide.
    Malformed { detail: String },
}

impl KnownHostCheck {
    /// Map the russh path result, used only as the fallback for hashed
    /// (`|1|`) entries; non-hashed entries were already decided by
    /// [`scan_known_hosts`], so only a hashed entry can produce a verdict.
    fn from_hashed_fallback(r: std::result::Result<bool, keys::Error>) -> Self {
        match r {
            Ok(true) => Self::Matched,
            Ok(false) => Self::Absent,
            Err(keys::Error::KeyChanged { line }) => Self::Changed {
                line: line.to_string(),
            },
            Err(e) => Self::Malformed {
                detail: e.to_string(),
            },
        }
    }
}

/// Verdict for a server key: accept, or reject with a user-facing reason.
enum HostKeyDecision {
    Accept,
    Reject(String),
}

/// Decide whether the server key of `endpoint` may be trusted.
///
/// `endpoint` names the real `host:port` for messages; `record_host` is the
/// name keys are recorded under (hostname or HostKeyAlias) and is used in the
/// `ssh ... true` guidance. `files` are the existing known_hosts files in ssh
/// config order; `check` is invoked lazily per file and evaluation stops at
/// the first match or change, so an earlier match never sees a later file's
/// failure.
fn decide_host_key<F>(
    endpoint: &str,
    record_host: &str,
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
            KnownHostCheck::Revoked { line } => {
                return HostKeyDecision::Reject(format!(
                    "host key of {endpoint} is revoked ({} line {line})",
                    path.display()
                ));
            },
            KnownHostCheck::Changed { line } => {
                return HostKeyDecision::Reject(format!(
                    "host key of {endpoint} changed ({} line {line}); remove the stale entry or \
                     verify the server",
                    path.display()
                ));
            },
            KnownHostCheck::Malformed { detail } => {
                return HostKeyDecision::Reject(format!(
                    "malformed known_hosts entry ({} {detail}) blocks verification of the host \
                     key of {endpoint}; fix or remove the line",
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
            "no readable known_hosts file to verify the host key of {endpoint}; sp does not write \
             known_hosts, run `ssh {record_host} true` once on this machine so OpenSSH records \
             the key"
        ));
    }
    let names = checked
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    HostKeyDecision::Reject(format!(
        "host key of {endpoint} not found in {names}; connect once with `ssh {record_host} true` \
         to record it"
    ))
}

/// Check one known_hosts file for `server_key` of `record_host`:`port`.
///
/// Non-hashed entries are matched by our OpenSSH-compatible scanner; hashed
/// (`|1|`) entries are delegated to russh's HMAC-SHA1 checker as a fallback.
/// `cert` is set when the server presented a certificate, for which only
/// revocation can decide.
fn check_known_host_file(
    path: &Path,
    record_host: &str,
    port: u16,
    server_key: &ssh_key::PublicKey,
    cert: bool,
) -> KnownHostCheck {
    let lookup = host_key_lookup_name(record_host, port);
    let scan = match std::fs::read(path) {
        Ok(bytes) => scan_known_hosts(&String::from_utf8_lossy(&bytes), &lookup, server_key, cert),
        Err(_) => KnownHostCheck::Absent,
    };
    match scan {
        KnownHostCheck::Absent => KnownHostCheck::from_hashed_fallback(check_known_hosts_path(
            record_host,
            port,
            server_key,
            path,
        )),
        other => other,
    }
}

/// The name a host key is recorded under in known_hosts: `host` on the
/// default port, `[host]:port` otherwise (OpenSSH behavior, also applied to
/// a HostKeyAlias).
fn host_key_lookup_name(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    }
}

/// Scan known_hosts text for `lookup` (already lowercased form of the record
/// name). OpenSSH matching semantics:
///
/// - comma-separated patterns with `*`/`?` wildcards and `!` negation, case-insensitive;
/// - `@revoked` entries reject the named key itself (checked for every line so revocation wins over
///   a match found earlier);
/// - `@cert-authority` entries authorize certificates only and never match a host key;
/// - a matching entry with the same algorithm but a different key is a change; a different
///   algorithm is no signal.
///
/// Hashed entries are left to the russh fallback, and for `cert` only
/// revocation can produce a verdict.
fn scan_known_hosts(
    text: &str,
    lookup: &str,
    server_key: &ssh_key::PublicKey,
    cert: bool,
) -> KnownHostCheck {
    let mut verdict = KnownHostCheck::Absent;
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Ok(entry) = line.parse::<Entry>() else {
            // A line the parser rejects that still names our host must not be
            // ignored (it could be the entry that would match); lines for
            // other hosts are skipped, like OpenSSH does.
            if !matches!(verdict, KnownHostCheck::Matched) && raw_entry_targets_host(line, lookup) {
                return KnownHostCheck::Malformed {
                    detail: format!("line {line_no}"),
                };
            }
            continue;
        };
        match entry.marker() {
            // Revocation names the key itself, regardless of the host list.
            Some(Marker::Revoked) => {
                if entry.public_key() == server_key {
                    return KnownHostCheck::Revoked {
                        line: line_no.to_string(),
                    };
                }
            },
            // CA entries authorize certificates only, which sp does not
            // verify; they must not be treated as host keys.
            Some(Marker::CertAuthority) => {},
            None => {
                if cert {
                    // Plain entries never authorize a certificate.
                    continue;
                }
                let matched = match entry.host_patterns() {
                    HostPatterns::Patterns(patterns) => {
                        match_pattern_list(lookup, patterns.iter().map(String::as_str))
                    },
                    // Hashed entries are the russh fallback's domain.
                    HostPatterns::HashedName { .. } => false,
                };
                if !matched {
                    continue;
                }
                let recorded = entry.public_key();
                if recorded == server_key {
                    // Keep scanning: a later @revoked entry for this key wins.
                    verdict = KnownHostCheck::Matched;
                } else if recorded.algorithm() == server_key.algorithm()
                    && matches!(verdict, KnownHostCheck::Absent)
                {
                    verdict = KnownHostCheck::Changed {
                        line: line_no.to_string(),
                    };
                }
            },
        }
    }
    verdict
}

/// Host-field test for lines the full parser rejects: a malformed line that
/// still names our host blocks verification, others are ignored.
fn raw_entry_targets_host(line: &str, lookup: &str) -> bool {
    let mut fields = line.split_whitespace();
    let first = fields.next().unwrap_or_default();
    let host_field = if first.starts_with('@') {
        fields.next()
    } else {
        Some(first)
    };
    match host_field {
        // Hashed fields cannot be evaluated here; the russh fallback sees
        // them too.
        Some(h) if !h.starts_with("|1|") => match_pattern_list(lookup, h.split(',')),
        _ => false,
    }
}

/// OpenSSH `match_pattern_list` semantics: comma-separated patterns with
/// `*`/`?` wildcards, case-insensitive; a matching `!` negation vetoes the
/// whole list immediately.
fn match_pattern_list<'a>(host: &str, patterns: impl IntoIterator<Item = &'a str>) -> bool {
    let host = host.to_ascii_lowercase();
    let mut got_positive = false;
    for pattern in patterns {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, pattern),
        };
        if match_pattern(&host, &pattern.to_ascii_lowercase()) {
            if negated {
                return false;
            }
            got_positive = true;
        }
    }
    got_positive
}

/// OpenSSH `match_pattern`: `*` matches any sequence (including empty), `?`
/// any single character. Iterative backtracking matcher.
fn match_pattern(mut s: &str, mut pattern: &str) -> bool {
    // Last `*`: (pattern after it, subject position when it was seen).
    let mut star: Option<(&str, &str)> = None;
    loop {
        let mut p = pattern.chars();
        match p.next() {
            Some('*') => {
                pattern = p.as_str();
                star = Some((pattern, s));
            },
            expected => {
                let mut c = s.chars();
                let actual = c.next();
                let matched = match expected {
                    Some('?') => actual.is_some(),
                    Some(ch) => actual == Some(ch),
                    // Pattern and subject exhausted together: full match.
                    None if actual.is_none() => return true,
                    // Pattern done but subject remains: only a star can absorb.
                    None => false,
                };
                if matched {
                    pattern = p.as_str();
                    s = c.as_str();
                    continue;
                }
                // Mismatch: backtrack to the last `*` and let it absorb one
                // more character of the subject.
                let Some((pattern_after, s_at_star)) = star else {
                    return false;
                };
                let mut it = s_at_star.chars();
                if it.next().is_none() {
                    return false;
                }
                s = it.as_str();
                pattern = pattern_after;
                star = Some((pattern_after, s));
            },
        }
    }
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
///
/// The establishment is bounded: TCP by `connecttimeout` (15s default),
/// handshake and authentication by one shared deadline (`connecttimeout`,
/// 30s default). A wedged peer or a hung ProxyCommand child fails with a
/// stage-named timeout error instead of hanging the caller forever.
pub async fn connect(resolved: ResolvedHost) -> Result<SshConnection> {
    let config = Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(30)),
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

    let setup_timeout = clamp_timeout(resolved.connect_timeout.unwrap_or(SSH_SETUP_TIMEOUT));
    let setup_secs = setup_timeout.as_secs();
    // Set by both transport branches; the setup budget starts once the
    // transport exists, because the TCP connect carries its own timeout.
    let setup_deadline: Instant;

    let mut proxy_child = None;
    let mut handle = if let Some(pc) = resolved.proxy_command.as_deref() {
        let cmd = expand_proxy_command(pc, &resolved.hostname, resolved.port, &resolved.user);
        let (stream, mut child) =
            spawn_proxy(&cmd).map_err(|e| Error::Connect(format!("proxycommand {cmd:?}: {e}")))?;
        setup_deadline = Instant::now() + setup_timeout;
        match tokio::time::timeout_at(
            setup_deadline,
            client::connect_stream(config, stream, handler),
        )
        .await
        {
            Ok(Ok(h)) => {
                // The connection owns the child from here on.
                proxy_child = Some(child);
                h
            },
            Ok(Err(e)) => return Err(map_connect_err(e)),
            Err(_) => {
                // The child's pipes are the transport; kill it now instead
                // of relying on kill_on_drop along the error return.
                let _ = child.start_kill();
                return Err(Error::Connect(format!(
                    "ssh handshake via proxycommand {cmd:?} timed out after {setup_secs}s"
                )));
            },
        }
    } else {
        let addr = (resolved.hostname.as_str(), resolved.port);
        // ssh config ConnectTimeout when set, otherwise a library default.
        let timeout = clamp_timeout(resolved.connect_timeout.unwrap_or(TCP_CONNECT_TIMEOUT));
        let tcp = tokio::time::timeout(timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| Error::Connect(format!("connect to {addr:?} timed out")))?
            .map_err(|e| Error::Connect(format!("connect to {addr:?}: {e}")))?;
        setup_deadline = Instant::now() + setup_timeout;
        tokio::time::timeout_at(setup_deadline, client::connect_stream(config, tcp, handler))
            .await
            .map_err(|_| {
                Error::Connect(format!(
                    "ssh handshake with {addr:?} timed out after {setup_secs}s"
                ))
            })?
            .map_err(map_connect_err)?
    };

    // Handshake and authentication share one deadline, so a slow handshake
    // leaves less room for auth.
    match tokio::time::timeout_at(setup_deadline, authenticate(&mut handle, &resolved)).await {
        Ok(result) => result?,
        Err(_) => {
            return Err(Error::Auth(format!(
                "timed out after {setup_secs}s authenticating as {user}@{host}:{port}",
                user = resolved.user,
                host = resolved.hostname,
                port = resolved.port
            )));
        },
    }

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

/// Servers count every authentication request (including the unsigned
/// publickey probes russh sends first) toward `MaxAuthTries` (OpenSSH
/// default 6) and disconnect once it is exceeded.
const MAX_PUBLICKEY_ATTEMPTS: usize = 6;

/// Shared publickey attempt state across the agent and identity-file paths.
struct PublickeyBudget {
    attempts: usize,
    /// False once a failure reply no longer offers publickey.
    offered: bool,
}

impl PublickeyBudget {
    fn new() -> Self {
        Self {
            attempts: 0,
            offered: true,
        }
    }

    /// True when no further publickey attempt should be made.
    fn exhausted(&self) -> bool {
        !self.offered || self.attempts >= MAX_PUBLICKEY_ATTEMPTS
    }

    /// Record one attempt result.
    fn record<E>(&mut self, result: std::result::Result<client::AuthResult, E>) -> AuthAttempt {
        self.attempts += 1;
        match result {
            Ok(client::AuthResult::Success) => AuthAttempt::Success,
            Ok(client::AuthResult::Failure {
                remaining_methods, ..
            }) => {
                if !remaining_methods.contains(&MethodKind::PublicKey) {
                    self.offered = false;
                }
                AuthAttempt::Rejected
            },
            // Whether this is a transport failure or, on the agent path, a
            // per-identity agent error, the attempt did not succeed.
            Err(_) => AuthAttempt::Failed,
        }
    }
}

/// Outcome of a single authentication attempt.
#[derive(Debug, PartialEq, Eq)]
enum AuthAttempt {
    Success,
    /// The server rejected the attempt; further tries may still work.
    Rejected,
    /// Transport or signer error.
    Failed,
}

/// RSA signature hash selection for identity files.
enum RsaHashPlan {
    /// The server advertised its algorithms: one attempt with this hash
    /// (`None` means the server only accepts ssh-rsa/SHA-1).
    Fixed(Option<HashAlg>),
    /// The server did not advertise (no EXT_INFO): start at Sha512 and
    /// downgrade for pre-rsa-sha2 servers.
    Downgrade,
}

async fn authenticate(handle: &mut SshHandle, resolved: &ResolvedHost) -> Result<()> {
    let user = resolved.user.clone();
    let mut attempts: Vec<String> = Vec::new();
    let mut budget = PublickeyBudget::new();

    // 1. ssh-agent: a large keyring must not exhaust the server's auth
    // budget before the identity files get their turn.
    if let Ok(mut agent) = connect_agent().await
        && let Ok(identities) = agent.request_identities().await
    {
        for identity in identities {
            if budget.exhausted() {
                break;
            }
            let pubkey = identity.public_key().into_owned();
            let result = handle
                .authenticate_publickey_with(&user, pubkey, None, &mut agent)
                .await;
            if budget.record(result) == AuthAttempt::Success {
                return Ok(());
            }
        }
    }

    // 2. identity files
    // Queried once, at the first RSA identity: the server's advertised
    // RSA hash algorithm, when it sends the server-sig-algs extension.
    let mut rsa_plan: Option<RsaHashPlan> = None;
    for path in &resolved.identity_files {
        if budget.exhausted() {
            break;
        }
        let key = match keys::load_secret_key(path, None) {
            Ok(k) => Arc::new(k),
            Err(keys::Error::KeyIsEncrypted) => {
                attempts.push(format!(
                    "{}: encrypted, add it to ssh-agent",
                    path.display()
                ));
                continue;
            },
            Err(_) => continue, // missing/unreadable is normal, ssh skips too
        };
        let hashes: &[Option<HashAlg>] = if key.algorithm().is_rsa() {
            if rsa_plan.is_none() {
                // `Ok(Some(alg))`: the server advertised its algorithms.
                // `Ok(None)`: no server-sig-algs extension was sent, so the
                // hash is probed with a downgrade chain instead.
                rsa_plan = Some(match handle.best_supported_rsa_hash().await {
                    Ok(Some(alg)) => RsaHashPlan::Fixed(alg),
                    Ok(None) | Err(_) => RsaHashPlan::Downgrade,
                });
            }
            match rsa_plan.as_ref() {
                Some(RsaHashPlan::Fixed(hash)) => std::slice::from_ref(hash),
                _ => &[Some(HashAlg::Sha512), Some(HashAlg::Sha256), None],
            }
        } else {
            &[None]
        };
        let mut rejected = false;
        for hash in hashes {
            if budget.exhausted() {
                break;
            }
            let key_with_hash = PrivateKeyWithHashAlg::new(Arc::clone(&key), *hash);
            let result = handle.authenticate_publickey(&user, key_with_hash).await;
            match budget.record(result) {
                AuthAttempt::Success => return Ok(()),
                // Only a server rejection justifies a downgrade retry.
                AuthAttempt::Rejected => rejected = true,
                AuthAttempt::Failed => break,
            }
        }
        if rejected {
            attempts.push(format!("{}: rejected", path.display()));
        }
    }

    if !budget.offered {
        attempts.push("server stopped offering publickey authentication".into());
    }
    if budget.attempts >= MAX_PUBLICKEY_ATTEMPTS && budget.offered {
        attempts.push(format!(
            "publickey attempt budget of {MAX_PUBLICKEY_ATTEMPTS} exhausted"
        ));
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
    use russh::MethodSet;

    use super::*;

    #[test]
    fn no_files_strict_rejects_with_guidance() {
        match decide_host_key("h:22", "h", true, &[], |_| unreachable!()) {
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
            decide_host_key("h:22", "h", false, &[], |_| unreachable!()),
            HostKeyDecision::Accept
        ));
    }

    #[test]
    fn unrecorded_host() {
        let files = [
            Path::new("/u/.ssh/known_hosts"),
            Path::new("/etc/ssh/ssh_known_hosts"),
        ];
        match decide_host_key("h:2222", "h", true, &files, |_| KnownHostCheck::Absent) {
            HostKeyDecision::Reject(reason) => {
                assert!(reason.contains("h:2222"));
                assert!(reason.contains("/u/.ssh/known_hosts, /etc/ssh/ssh_known_hosts"));
                assert!(reason.contains("`ssh h true`"));
            },
            HostKeyDecision::Accept => panic!("strict mode must reject an unrecorded host"),
        }
        assert!(matches!(
            decide_host_key("h:22", "h", false, &files, |_| KnownHostCheck::Absent),
            HostKeyDecision::Accept
        ));
    }

    #[test]
    fn matched_accepts_and_stops_checking() {
        let files = [Path::new("/a"), Path::new("/b")];
        let mut calls = 0;
        let decision = decide_host_key("h:22", "h", true, &files, |_| {
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
        let decision = decide_host_key("h:22", "h", false, &files, |path| {
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

    #[test]
    fn revoked_and_malformed_have_distinct_reasons() {
        let files = [Path::new("/a")];
        match decide_host_key("h:22", "h", false, &files, |_| KnownHostCheck::Revoked {
            line: "7".into(),
        }) {
            HostKeyDecision::Reject(reason) => {
                assert!(reason.contains("revoked (/a line 7)"));
            },
            HostKeyDecision::Accept => panic!("a revoked key must fail even in non-strict mode"),
        }
        match decide_host_key("h:22", "h", false, &files, |_| KnownHostCheck::Malformed {
            detail: "line 9".into(),
        }) {
            HostKeyDecision::Reject(reason) => {
                assert!(reason.contains("malformed known_hosts entry (/a line 9)"));
                assert!(!reason.contains("changed"));
            },
            HostKeyDecision::Accept => panic!("a malformed entry must fail closed"),
        }
    }

    #[test]
    fn glob_match_pattern() {
        assert!(match_pattern("host.example.com", "host.example.com"));
        assert!(match_pattern("host.example.com", "*.example.com"));
        assert!(match_pattern("host.example.com", "host.*"));
        assert!(match_pattern("host.example.com", "h???.example.com"));
        assert!(match_pattern("host", "*"));
        assert!(match_pattern("", "*"));
        assert!(match_pattern("", ""));
        assert!(!match_pattern("host.example.com", "*.example.org"));
        assert!(!match_pattern("host", "???"));
        assert!(match_pattern("host", "????"));
        assert!(!match_pattern("host.example.com", "host"));
        assert!(!match_pattern("host", "host.example.com"));
        // Multiple stars and star at both ends.
        assert!(match_pattern("a.b.c", "*.*.*"));
        assert!(match_pattern("xhosty", "*host*"));
        assert!(!match_pattern("xhosp", "*host"));
    }

    #[test]
    fn glob_match_pattern_list() {
        let m = |host: &str, list: &str| match_pattern_list(host, list.split(','));
        assert!(m("a.example.com", "b.org,*.example.com"));
        assert!(!m("a.example.com", "b.org,*.example.org"));
        // Negation matching vetoes the whole list, even after a positive.
        assert!(!m("bad.example.com", "*.example.com,!bad.example.com"));
        assert!(m("good.example.com", "*.example.com,!bad.example.com"));
        // A non-matching negation has no effect.
        assert!(m("a.example.com", "!b.example.com,a.example.com"));
        // Case-insensitive comparison.
        assert!(m("A.EXAMPLE.COM", "a.example.com"));
        assert!(m("a.example.com", "*.EXAMPLE.com"));
        // Empty list never matches.
        assert!(!m("a", ""));
    }

    #[test]
    fn lookup_name_brackets_nondefault_port() {
        assert_eq!(host_key_lookup_name("h", 22), "h");
        assert_eq!(host_key_lookup_name("h", 2222), "[h]:2222");
    }

    /// Two distinct ed25519 keys and one ecdsa key for the scan tests.
    fn test_keys() -> (ssh_key::PublicKey, ssh_key::PublicKey, ssh_key::PublicKey) {
        let k1 = keys::parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti",
        )
        .expect("key1");
        let k2 = keys::parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXX9OIeZJ",
        )
        .expect("key2");
        let ke = keys::parse_public_key_base64(
            "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHwf2HMM5TRXvo2SQJjsNkiDD5KqiiNjrGVv3UUh+mMT5RHxiRtOnlqvjhQtBq0VpmpCV/PwUdhOig4vkbqAcEc=",
        )
        .expect("ecdsa key");
        (k1, k2, ke)
    }

    const K1_B64: &str = "AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti";
    const K2_B64: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXX9OIeZJ";

    fn scan(text: &str, lookup: &str, key: &ssh_key::PublicKey) -> KnownHostCheck {
        scan_known_hosts(text, lookup, key, false)
    }

    #[test]
    fn scan_wildcard_and_negated_entries() {
        let (k1, _k2, _ke) = test_keys();
        let text = format!("*.example.com,!bad.example.com ssh-ed25519 {K1_B64}\n");
        assert!(matches!(
            scan(&text, "good.example.com", &k1),
            KnownHostCheck::Matched
        ));
        assert!(matches!(
            scan(&text, "bad.example.com", &k1),
            KnownHostCheck::Absent
        ));
        assert!(matches!(
            scan(&text, "good.example.org", &k1),
            KnownHostCheck::Absent
        ));
    }

    #[test]
    fn scan_bracketed_port_entries() {
        let (k1, _k2, _ke) = test_keys();
        let text = format!("[h]:2222 ssh-ed25519 {K1_B64}\n");
        assert!(matches!(
            scan(&text, "[h]:2222", &k1),
            KnownHostCheck::Matched
        ));
        // A bracketed entry does not authorize the default-port name.
        assert!(matches!(scan(&text, "h", &k1), KnownHostCheck::Absent));
        let plain = format!("h ssh-ed25519 {K1_B64}\n");
        assert!(matches!(scan(&plain, "h", &k1), KnownHostCheck::Matched));
        assert!(matches!(
            scan(&plain, "[h]:2222", &k1),
            KnownHostCheck::Absent
        ));
    }

    #[test]
    fn scan_case_insensitive_host() {
        let (k1, _k2, _ke) = test_keys();
        let text = format!("EXAMPLE.COM ssh-ed25519 {K1_B64}\n");
        assert!(matches!(
            scan(&text, "example.com", &k1),
            KnownHostCheck::Matched
        ));
    }

    #[test]
    fn scan_same_algorithm_different_key_is_changed() {
        let (_k1, k2, _ke) = test_keys();
        let text = format!("h ssh-ed25519 {K1_B64}\n");
        match scan(&text, "h", &k2) {
            KnownHostCheck::Changed { line } => assert_eq!(line, "1"),
            other => panic!("expected change, got {other:?}"),
        }
    }

    #[test]
    fn scan_different_algorithm_is_no_signal() {
        let (_k1, _k2, ke) = test_keys();
        let text = format!("h ssh-ed25519 {K1_B64}\n");
        assert!(matches!(scan(&text, "h", &ke), KnownHostCheck::Absent));
    }

    #[test]
    fn scan_revoked_wins_over_earlier_match() {
        let (k1, _k2, _ke) = test_keys();
        // Matching plain entry first, revocation later: revocation wins.
        let text = format!("h ssh-ed25519 {K1_B64}\n@revoked h ssh-ed25519 {K1_B64}\n");
        match scan(&text, "h", &k1) {
            KnownHostCheck::Revoked { line } => assert_eq!(line, "2"),
            other => panic!("expected revocation, got {other:?}"),
        }
        // A revoked entry naming a different key is only a revocation record.
        let text = format!("@revoked h ssh-ed25519 {K2_B64}\nh ssh-ed25519 {K1_B64}\n");
        assert!(matches!(scan(&text, "h", &k1), KnownHostCheck::Matched));
    }

    #[test]
    fn scan_revoked_applies_regardless_of_host_list() {
        let (k1, _k2, _ke) = test_keys();
        let text = format!("@revoked other.host ssh-ed25519 {K1_B64}\n");
        assert!(matches!(scan(&text, "h", &k1), KnownHostCheck::Revoked {
            line: _
        }));
    }

    #[test]
    fn scan_cert_authority_lines_never_match_host_keys() {
        let (k1, _k2, _ke) = test_keys();
        let text = format!("@cert-authority *.example.com ssh-ed25519 {K1_B64}\n");
        // Neither as a match candidate nor as a change.
        assert!(matches!(
            scan(&text, "a.example.com", &k1),
            KnownHostCheck::Absent
        ));
        let (_k1, k2, _ke) = test_keys();
        assert!(matches!(
            scan(&text, "a.example.com", &k2),
            KnownHostCheck::Absent
        ));
    }

    #[test]
    fn scan_hashed_entries_left_to_fallback() {
        let (k1, _k2, _ke) = test_keys();
        let text = format!(
            "|1|JfKTdBh7rNbXkVAQCRp4OQoPfmI=|USECr3SWf1JUPsms5AqfD5QfxkM= ssh-ed25519 {K1_B64}\n"
        );
        assert!(matches!(
            scan(&text, "example.com", &k1),
            KnownHostCheck::Absent
        ));
    }

    #[test]
    fn scan_malformed_line_for_our_host_blocks() {
        let (k1, _k2, _ke) = test_keys();
        let text = "h ssh-ed25519 !!!not-base64!!!\n";
        match scan(text, "h", &k1) {
            KnownHostCheck::Malformed { detail } => assert_eq!(detail, "line 1"),
            other => panic!("expected malformed, got {other:?}"),
        }
        // Malformed lines for other hosts are ignored.
        let text = format!("other ssh-ed25519 !!!not-base64!!!\nh ssh-ed25519 {K1_B64}\n");
        assert!(matches!(scan(&text, "h", &k1), KnownHostCheck::Matched));
        // A malformed line after a match does not override it.
        let text = format!("h ssh-ed25519 {K1_B64}\nh ssh-ed25519 !!!\n");
        assert!(matches!(scan(&text, "h", &k1), KnownHostCheck::Matched));
    }

    #[test]
    fn scan_comments_and_blank_lines_skipped() {
        let (k1, _k2, _ke) = test_keys();
        let text = format!("\n# comment: h ssh-ed25519 AAAA\n  \nh ssh-ed25519 {K1_B64}\n");
        assert!(matches!(scan(&text, "h", &k1), KnownHostCheck::Matched));
    }

    #[test]
    fn scan_certificate_presentation_ignores_plain_entries() {
        let (k1, _k2, _ke) = test_keys();
        let text = format!("h ssh-ed25519 {K1_B64}\n");
        assert!(matches!(
            scan_known_hosts(&text, "h", &k1, true),
            KnownHostCheck::Absent
        ));
        // Revocation still applies to certificates.
        let text = format!("@revoked h ssh-ed25519 {K1_B64}\n");
        assert!(matches!(
            scan_known_hosts(&text, "h", &k1, true),
            KnownHostCheck::Revoked { line: _ }
        ));
    }

    #[test]
    fn certificate_decisions() {
        let (k1, _k2, _ke) = test_keys();
        // Strict mode rejects with a certificate-specific reason; non-strict
        // accepts the unseen key.
        match decide_certificate("h:22", "h", 22, true, &[], &k1) {
            HostKeyDecision::Reject(reason) => assert!(reason.contains("certificate")),
            HostKeyDecision::Accept => panic!("strict mode must reject certificates"),
        }
        assert!(matches!(
            decide_certificate("h:22", "h", 22, false, &[], &k1),
            HostKeyDecision::Accept
        ));
    }

    #[test]
    fn publickey_budget_bounds_attempts() {
        let failure = |offered: bool| {
            let methods: &[MethodKind] = if offered {
                &[MethodKind::PublicKey, MethodKind::Password]
            } else {
                &[MethodKind::Password]
            };
            client::AuthResult::Failure {
                remaining_methods: MethodSet::from(methods),
                partial_success: false,
            }
        };
        // Repeated rejections stop at the attempt cap.
        let mut budget = PublickeyBudget::new();
        for _ in 0..(MAX_PUBLICKEY_ATTEMPTS - 1) {
            assert_eq!(
                budget.record::<std::convert::Infallible>(Ok(failure(true))),
                AuthAttempt::Rejected
            );
            assert!(!budget.exhausted());
        }
        assert_eq!(
            budget.record::<std::convert::Infallible>(Ok(failure(true))),
            AuthAttempt::Rejected
        );
        assert!(budget.exhausted());
        assert!(budget.offered);

        // A reply that stops offering publickey ends the method immediately.
        let mut budget = PublickeyBudget::new();
        assert_eq!(
            budget.record::<std::convert::Infallible>(Ok(failure(false))),
            AuthAttempt::Rejected
        );
        assert!(budget.exhausted());
        assert!(!budget.offered);

        // Success and transport failure are told apart.
        let mut budget = PublickeyBudget::new();
        assert_eq!(
            budget.record::<std::convert::Infallible>(Ok(client::AuthResult::Success)),
            AuthAttempt::Success
        );
        assert_eq!(
            budget.record::<russh::Error>(Err(russh::Error::SendError)),
            AuthAttempt::Failed
        );
    }
}
