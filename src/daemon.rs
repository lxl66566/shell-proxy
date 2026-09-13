//! The resident daemon: owns persistent SSH connections per host, deploys
//! `sp-serve`, serializes commands per host (cwd is shared state), streams
//! output back over IPC and logs every execution.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use sp_proto::{EventFrame, ExecFrame, ExecRequest, ExitReport, INTERNAL_ERROR_CODE, Pong};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, mpsc},
};

use crate::{
    config,
    error::{Error, Result},
    remote::{self, ExecOutcome, InputEvent, OutputEvent},
    ssh::{self, SshConnection},
    ssh_config,
};

/// Log files above this size are rotated to `.old` at daemon startup.
const ROTATE_BYTES: u64 = 10 * 1024 * 1024;

/// One host alias with its connection and persisted shell state.
struct HostState {
    conn: SshConnection,
    /// Remote path of the deployed sp-serve binary.
    serve_path: String,
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
                let guard = ActiveGuard::acquire(&active, &idle_now);
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

/// Counts one live connection; the last drop wakes the accept loop so the
/// idle timer can re-arm. Increment/decrement must stay paired, otherwise
/// the counter underflows and the daemon never idles out.
struct ActiveGuard {
    active: Arc<std::sync::atomic::AtomicUsize>,
    idle_now: Arc<tokio::sync::Notify>,
}

impl ActiveGuard {
    fn acquire(
        active: &Arc<std::sync::atomic::AtomicUsize>,
        idle_now: &Arc<tokio::sync::Notify>,
    ) -> Self {
        active.fetch_add(1, Ordering::SeqCst);
        Self {
            active: Arc::clone(active),
            idle_now: Arc::clone(idle_now),
        }
    }
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
    let (out_tx, mut out_rx) = mpsc::channel::<EventFrame>(256);
    tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            if sp_proto::write_event_frame(&mut writer, &frame)
                .await
                .is_err()
            {
                break;
            }
        }
    });

    while let Some(frame) = sp_proto::read_exec_frame(&mut reader).await? {
        match frame {
            ExecFrame::Ping => {
                let _ = out_tx
                    .send(EventFrame::Pong(Pong {
                        pid: std::process::id(),
                    }))
                    .await;
            },
            // One exec per connection: stdin forwarding interleaves with the
            // engine, so the connection is closed after it finishes.
            ExecFrame::Exec(req) => {
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
    out_tx: &mpsc::Sender<EventFrame>,
) {
    let started = Instant::now();
    let state = match get_or_connect(shared, &req.host).await {
        Ok(s) => s,
        Err(e) => {
            warn!("connect host={} failed: {e}", req.host);
            let _ = out_tx
                .send(EventFrame::Exit(ExitReport {
                    code: INTERNAL_ERROR_CODE,
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

    let mut eff_req = req.clone();
    eff_req.cwd = start_cwd.clone();

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
                    EventFrame::Stdout(d)
                },
                OutputEvent::Stderr(d) => {
                    err_ctr.fetch_add(d.len() as u64, Ordering::Relaxed);
                    EventFrame::Stderr(d)
                },
            };
            if bridge_tx.send(frame).await.is_err() {
                break;
            }
        }
    });

    let mut engine = std::pin::pin!(remote::execute(
        state.conn.handle(),
        &state.serve_path,
        &eff_req,
        input_rx,
        event_tx,
    ));

    let mut reader_open = true;
    let outcome: std::result::Result<ExecOutcome, String> = loop {
        tokio::select! {
            frame = sp_proto::read_exec_frame(&mut reader), if reader_open => {
                match frame {
                    Ok(Some(ExecFrame::StdinData(d))) => {
                        if input_tx.send(InputEvent::Stdin(d)).await.is_err() {
                            break Err("engine died unexpectedly".into());
                        }
                    }
                    Ok(Some(ExecFrame::StdinEof)) => {
                        let _ = input_tx.send(InputEvent::StdinEof).await;
                    }
                    Ok(Some(ExecFrame::Signal(s))) => {
                        info!("forwarding signal {} to engine", s.as_str());
                        let _ = input_tx.send(InputEvent::Signal(s)).await;
                    }
                    Ok(Some(ExecFrame::Ping)) => {
                        let _ = out_tx
                            .send(EventFrame::Pong(Pong { pid: std::process::id() }))
                            .await;
                    }
                    Ok(Some(ExecFrame::Exec(_))) => {
                        let _ = input_tx.send(InputEvent::StdinEof).await;
                        break Err("nested exec on one connection is not supported".into());
                    }
                    Ok(None) => {
                        // Client vanished; give the remote side EOF, not a kill,
                        // and let it finish (cwd still updates). Polling an EOF
                        // stream again would busy-loop.
                        reader_open = false;
                        warn!(
                            "host={} client disconnected while the command was running; \
                             letting it finish",
                            req.host
                        );
                        let _ = input_tx.send(InputEvent::StdinEof).await;
                    }
                    Err(e) => break Err(e.to_string()),
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
            code: INTERNAL_ERROR_CODE,
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

    let _ = out_tx.send(EventFrame::Exit(report)).await;
}

fn abbreviate(s: &str) -> String {
    const MAX: usize = 300;
    if s.len() <= MAX {
        format!("{s:?}")
    } else {
        format!(
            "{:?}...(total {} bytes)",
            sp_proto::truncate_utf8(s, MAX),
            s.len()
        )
    }
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
    let serve_path = remote::deploy(conn.handle()).await?;
    Ok(Arc::new(HostState {
        conn,
        serve_path,
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
    let level =
        config::load_config().map_or(LevelFilter::MoreSevere(Level::Info), |c| c.log_level.into());
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

impl From<config::LogLevel> for LevelFilter {
    fn from(level: config::LogLevel) -> Self {
        match level {
            config::LogLevel::Trace => LevelFilter::All,
            config::LogLevel::Debug => LevelFilter::MoreVerboseEqual(Level::Debug),
            config::LogLevel::Info => LevelFilter::MoreSevereEqual(Level::Info),
            config::LogLevel::Warn => LevelFilter::MoreSevereEqual(Level::Warn),
            config::LogLevel::Error => LevelFilter::MoreSevereEqual(Level::Error),
        }
    }
}
