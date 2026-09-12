//! The resident daemon: owns persistent SSH connections per host, serializes
//! commands per host (cwd is shared state), streams output back over IPC and
//! logs every execution.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, mpsc},
};

use crate::{
    config,
    error::{Error, Result},
    exec::{self, ExecOutcome, InputEvent, OutputEvent},
    ipc,
    ipc::{DaemonFrame, ExecRequest, ExitReport, Pong},
    script::{self, ScriptSpec},
    ssh::{self, SshConnection},
    ssh_config,
};

/// Log files above this size are rotated to `.old` at daemon startup.
const ROTATE_BYTES: u64 = 10 * 1024 * 1024;

/// One host alias with its connection and persisted shell state.
struct HostState {
    conn: SshConnection,
    cwd: std::sync::Mutex<Option<String>>,
    /// Serializes executions so cwd updates apply in order.
    lock: Mutex<()>,
}

#[derive(Default)]
struct Shared {
    hosts: Mutex<HashMap<String, Arc<HostState>>>,
}

/// Run the daemon until killed. Binds the IPC endpoint exclusively.
///
/// With `SP_IDLE_SECS` set, exits after that many idle seconds (test helper).
pub async fn run() -> Result<()> {
    init_logger().map_err(|e| Error::Daemon(format!("init logging: {e}")))?;
    let sock_path = config::sock_path();
    let listener = crate::transport::bind(&sock_path)
        .map_err(|e| Error::Daemon(format!("bind {sock_path}: {e}")))?;

    info!("daemon started pid={} sock={sock_path}", std::process::id());

    let shared = Arc::new(Shared::default());
    let mut listener = listener;
    let idle = std::env::var("SP_IDLE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs);
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let idle_now = Arc::new(tokio::sync::Notify::new());
    let far = tokio::time::Instant::now() + Duration::from_secs(86_400 * 365);

    loop {
        let deadline = if active.load(Ordering::SeqCst) == 0 {
            idle.map(|d| tokio::time::Instant::now() + d)
        } else {
            None
        };
        let deadline = deadline.unwrap_or(far);
        tokio::select! {
            res = listener.accept() => {
                let stream = res
                    .map_err(|e| Error::Daemon(format!("accept on {sock_path}: {e}")))?;
                let shared = Arc::clone(&shared);
                let guard = ActiveGuard {
                    active: Arc::clone(&active),
                    idle_now: Arc::clone(&idle_now),
                };
                tokio::spawn(async move {
                    let _guard = guard;
                    if let Err(e) = handle_conn(stream, shared).await {
                        info!("connection ended: {e}");
                    }
                });
            }
            () = tokio::time::sleep_until(deadline), if idle.is_some() && deadline != far => {
                info!("idle timeout reached, exiting");
                return Ok(());
            }
            () = idle_now.notified(), if deadline == far => {
                // Last connection finished; loop again to re-arm the timer.
            }
        }
    }
}

/// Decrements the active-connection counter; wakes the accept loop when idle.
struct ActiveGuard {
    active: Arc<std::sync::atomic::AtomicUsize>,
    idle_now: Arc<tokio::sync::Notify>,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        if self.active.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.idle_now.notify_one();
        }
    }
}

async fn handle_conn<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    shared: Arc<Shared>,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    // Single writer task keeps frame writes ordered.
    let (out_tx, mut out_rx) = mpsc::channel::<DaemonFrame>(256);
    tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            if ipc::write_daemon_frame(&mut writer, &frame).await.is_err() {
                break;
            }
        }
    });

    while let Some(frame) = ipc::read_client_frame(&mut reader).await? {
        match frame {
            ipc::ClientFrame::Ping => {
                let _ = out_tx
                    .send(DaemonFrame::Pong(Pong {
                        pid: std::process::id(),
                    }))
                    .await;
            },
            // One exec per connection: stdin forwarding interleaves with the
            // engine, so the connection is closed after it finishes.
            ipc::ClientFrame::Exec(req) => {
                handle_exec(&shared, req, reader, &out_tx).await;
                return Ok(());
            },
            // Stdin/signal frames outside an execution are meaningless.
            _ => {},
        }
    }
    Ok(())
}

/// Execute one request: forwards subsequent stdin/signal frames to the engine
/// until it finishes, then reports the exit frame. Consumes the reader.
async fn handle_exec<S: AsyncRead + Unpin + Send>(
    shared: &Arc<Shared>,
    req: ExecRequest,
    mut reader: S,
    out_tx: &mpsc::Sender<DaemonFrame>,
) {
    let started = Instant::now();
    let state = match get_or_connect(shared, &req.host).await {
        Ok(s) => s,
        Err(e) => {
            warn!("connect host={} failed: {e}", req.host);
            let _ = out_tx
                .send(DaemonFrame::Exit(ExitReport {
                    code: 254,
                    cwd: None,
                    error: Some(e.brief()),
                    timed_out: false,
                }))
                .await;
            return;
        },
    };
    let _guard = state.lock.lock().await;
    let start_cwd = req
        .cwd
        .clone()
        .or_else(|| state.cwd.lock().expect("cwd lock").clone());

    let nonce_hex = new_nonce();
    let spec = ScriptSpec {
        command: &req.command,
        args: &req.args,
        cwd: start_cwd.as_deref(),
        nonce_hex: &nonce_hex,
    };
    let script_text = script::build(&spec);
    let timeout = req
        .timeout_ms
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis);

    let (input_tx, input_rx) = mpsc::channel::<InputEvent>(64);
    let (event_tx, mut event_rx) = mpsc::channel::<OutputEvent>(256);
    let stdout_bytes = Arc::new(AtomicU64::new(0));
    let stderr_bytes = Arc::new(AtomicU64::new(0));
    let bridge_tx = out_tx.clone();
    let (out_ctr, err_ctr) = (Arc::clone(&stdout_bytes), Arc::clone(&stderr_bytes));
    let bridge = tokio::spawn(async move {
        while let Some(ev) = event_rx.recv().await {
            let frame = match ev {
                OutputEvent::Stdout(d) => {
                    out_ctr.fetch_add(d.len() as u64, Ordering::Relaxed);
                    DaemonFrame::Stdout(d)
                },
                OutputEvent::Stderr(d) => {
                    err_ctr.fetch_add(d.len() as u64, Ordering::Relaxed);
                    DaemonFrame::Stderr(d)
                },
            };
            if bridge_tx.send(frame).await.is_err() {
                break;
            }
        }
    });

    let mut engine = std::pin::pin!(exec::execute(
        state.conn.handle(),
        script_text,
        &nonce_hex,
        timeout,
        input_rx,
        event_tx,
    ));

    let outcome: std::result::Result<ExecOutcome, String> = loop {
        tokio::select! {
            frame = ipc::read_client_frame(&mut reader) => {
                match frame {
                    Ok(Some(ipc::ClientFrame::StdinData(d))) => {
                        if input_tx.send(InputEvent::Stdin(d)).await.is_err() {
                            break Err("engine died unexpectedly".into());
                        }
                    }
                    Ok(Some(ipc::ClientFrame::StdinEof)) => {
                        let _ = input_tx.send(InputEvent::StdinEof).await;
                    }
                    Ok(Some(ipc::ClientFrame::Signal(s))) => {
                        let _ = input_tx.send(InputEvent::Signal(s)).await;
                    }
                    Ok(Some(ipc::ClientFrame::Ping)) => {
                        let _ = out_tx
                            .send(DaemonFrame::Pong(Pong { pid: std::process::id() }))
                            .await;
                    }
                    Ok(Some(ipc::ClientFrame::Exec(_))) => {
                        let _ = input_tx.send(InputEvent::StdinEof).await;
                        break Err("nested exec on one connection is not supported".into());
                    }
                    Ok(None) => {
                        // Client vanished; give the remote side EOF, not a kill.
                        let _ = input_tx.send(InputEvent::StdinEof).await;
                    }
                    Err(e) => break Err(e.brief()),
                }
            }
            res = &mut engine => {
                match res {
                    Ok(outcome) => break Ok(outcome),
                    Err(e) => break Err(e.brief()),
                }
            }
        }
    };
    drop(input_tx);
    let _ = bridge.await;

    // A dead connection cannot be retried transparently (forwarded stdin is
    // gone), so evict the state; the next command reconnects on its own.
    if outcome.is_err() && state.conn.is_closed() {
        warn!("host={} connection lost, evicting state", req.host);
        shared.hosts.lock().await.remove(&req.host);
    }

    let report = match outcome {
        Ok(o) => {
            if let Some(cwd) = &o.new_cwd {
                *state.cwd.lock().expect("cwd lock") = Some(cwd.clone());
            }
            ExitReport {
                code: o.exit_code,
                cwd: o.new_cwd,
                error: None,
                timed_out: o.timed_out,
            }
        },
        Err(msg) => ExitReport {
            code: 254,
            cwd: None,
            error: Some(msg),
            timed_out: false,
        },
    };

    info!(
        "exec host={} cwd={} rc={} dur={}ms out={}B err={}B cmd={}",
        req.host,
        start_cwd.as_deref().unwrap_or("~"),
        report.code,
        started.elapsed().as_millis(),
        stdout_bytes.load(Ordering::Relaxed),
        stderr_bytes.load(Ordering::Relaxed),
        abbreviate(&req.command),
    );

    let _ = out_tx.send(DaemonFrame::Exit(report)).await;
}

fn abbreviate(s: &str) -> String {
    const MAX: usize = 300;
    if s.len() <= MAX {
        format!("{s:?}")
    } else {
        // Truncate at a char boundary to keep the log line valid UTF-8.
        let cut = s
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|i| *i <= MAX)
            .last()
            .unwrap_or(0);
        format!("{:?}...(total {} bytes)", &s[..cut], s.len())
    }
}

fn new_nonce() -> String {
    let bytes: [u8; 16] = rand::random();
    hex_simd::encode_to_string(bytes, hex_simd::AsciiCase::Lower)
}

/// Get a live connection for `host`, connecting (or reconnecting) as needed.
async fn get_or_connect(shared: &Arc<Shared>, host: &str) -> Result<Arc<HostState>> {
    let mut hosts = shared.hosts.lock().await;
    if let Some(state) = hosts.get(host)
        && !state.conn.is_closed()
    {
        return Ok(Arc::clone(state));
    }
    let state = connect_state(host).await?;
    hosts.insert(host.to_owned(), Arc::clone(&state));
    Ok(state)
}

async fn connect_state(host: &str) -> Result<Arc<HostState>> {
    let resolved = ssh_config::resolve(host).await?;
    let conn = ssh::connect(resolved).await?;
    Ok(Arc::new(HostState {
        conn,
        cwd: std::sync::Mutex::new(None),
        lock: Mutex::new(()),
    }))
}

// -- logging -----------------------------------------------------------------

use spdlog::{Level, LevelFilter, Logger, prelude::*, sink::FileSink};

fn init_logger() -> std::io::Result<()> {
    let dir = config::app_dir().join("logs");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("daemon.log");
    if let Ok(meta) = std::fs::metadata(&path)
        && meta.len() > ROTATE_BYTES
    {
        let _ = std::fs::rename(&path, dir.join("daemon.log.old"));
    }
    let sink = FileSink::builder()
        .path(&path)
        .build()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let level = config::load_config().map_or(LevelFilter::MoreSevere(Level::Info), |c| {
        parse_level(&c.log_level)
    });
    let logger = Logger::builder()
        .sink(Arc::new(sink))
        .level_filter(level)
        // Daemon logs must survive a hard kill; flush every line.
        .flush_level_filter(LevelFilter::All)
        .build()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    spdlog::set_default_logger(Arc::new(logger));
    Ok(())
}

fn parse_level(s: &str) -> LevelFilter {
    match s.to_ascii_lowercase().as_str() {
        "trace" => LevelFilter::All,
        "debug" => LevelFilter::MoreVerboseEqual(Level::Debug),
        "warn" => LevelFilter::MoreSevereEqual(Level::Warn),
        "error" => LevelFilter::MoreSevereEqual(Level::Error),
        _ => LevelFilter::MoreSevereEqual(Level::Info),
    }
}
