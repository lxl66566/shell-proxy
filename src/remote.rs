//! Remote side management: deploy `sp-serve` and run commands through it.
//!
//! One command = one SSH exec channel running `sp-serve`, speaking sp-proto
//! frames on its stdio. The serve binary is uploaded once per daemon
//! connection into `~/.local/share/shell-proxy/` (name carries version and
//! arch) and verified by sha256 before use. serve's own stderr arrives as SSH
//! extended data and is mirrored into the daemon log.

use std::{sync::Arc, time::Duration};

use russh::ChannelMsg;
use sha2::{Digest, Sha256};
use sp_proto::{EventDecoder, EventFrame, ExecFrame, ExecRequest, ExitReport, Signal};
use spdlog::prelude::*;
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
    time::timeout,
};

use crate::{
    embed::{self, Arch},
    error::{Error, Result},
    ssh::SshHandle,
};

/// Directory (relative to the remote home) holding deployed binaries.
const SERVE_DIR: &str = "~/.local/share/shell-proxy";

/// Bounded wait for the forwarder to drain its backlog and close the channel
/// once the execution finished or was abandoned. A remote stdin window that
/// never reopens must not hold `execute` (and through it the session lock)
/// hostage.
const FORWARDER_JOIN: Duration = Duration::from_secs(10);

/// Bounded wait for the forwarder's final channel-close request; the shared
/// event loop it queues onto can itself be stuck on a dead transport.
const FORWARDER_CLOSE: Duration = Duration::from_secs(2);

/// Bounded wait for the channel tasks to end after the engine future was
/// dropped mid-run; whatever is still stuck after this is aborted.
const TASK_REAP: Duration = Duration::from_secs(5);

/// Bound for each pre-engine setup step of [`execute`]: opening the exec
/// channel, the SSH exec request and the initial sp-proto Exec frame. The
/// daemon-side watchdog covers only the engine loop and only when the request
/// carries a timeout, so without this bound a wedged transport would park an
/// unlimited request before the engine even starts. Timing out fails the
/// whole execution; the dropped channel may then carry a half-written frame,
/// but nobody decodes it after that failure.
const EXEC_SETUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout error for one pre-engine setup step, stage-named and host-tagged
/// so the client report points at the stuck phase.
fn exec_setup_timeout(stage: &str, host: &str) -> Error {
    Error::Remote(format!(
        "host {host}: {stage} did not complete within {}s",
        EXEC_SETUP_TIMEOUT.as_secs()
    ))
}

/// Events on the daemon-to-engine stdin lane. `Eof` is an ordered frame: it
/// must reach the remote behind all data, so it travels on the same lane
/// instead of being expressed as a channel close.
#[derive(Debug)]
pub enum StdinEvent {
    Data(Vec<u8>),
    Eof,
}

/// Events a running execution emits.
#[derive(Debug)]
pub enum OutputEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}

/// Outcome of a finished execution.
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    pub exit_code: i32,
    /// New persisted cwd when the serve wrapper reported it.
    pub new_cwd: Option<String>,
    /// New persisted shell state dump when the serve wrapper reported one.
    pub new_state: Option<String>,
    pub timed_out: bool,
}

/// Ensure `sp-serve` is deployed for the connection's host; returns the remote
/// path to execute.
pub async fn deploy(handle: &SshHandle) -> Result<String> {
    let (rc, out, _) = exec_collect(handle, "uname -m").await?;
    if rc != 0 {
        return Err(Error::Remote(format!("`uname -m` failed with rc={rc}")));
    }
    let arch = Arch::parse(&String::from_utf8_lossy(&out)).ok_or_else(|| {
        Error::Remote(format!(
            "unsupported remote arch: {}",
            String::from_utf8_lossy(&out).trim()
        ))
    })?;
    let bin = embed::serve_binary(arch).ok_or_else(|| {
        Error::Remote(format!(
            "no embedded sp-serve binary for {}; set {} to a musl build of sp-serve and rebuild",
            arch.as_str(),
            arch.env_var()
        ))
    })?;

    let name = format!("sp-serve-{}-{}", env!("CARGO_PKG_VERSION"), arch.as_str());
    let path = format!("{SERVE_DIR}/{name}");
    if remote_matches(handle, &path, bin).await? {
        if let Err(e) = cleanup_stale(handle, &name).await {
            warn!("stale deployment cleanup failed: {e}");
        }
        return Ok(path);
    }

    exec_status(handle, &format!("mkdir -p {SERVE_DIR}")).await?;
    let tmp = format!("{SERVE_DIR}/.upload-{}", new_nonce());
    upload(handle, &tmp, bin).await?;
    exec_status(handle, &format!("chmod 700 {tmp}")).await?;
    // Rename is atomic on the same filesystem: no half-written serve binary.
    exec_status(handle, &format!("mv {tmp} {path}")).await?;
    if !remote_matches(handle, &path, bin).await? {
        return Err(Error::Remote(format!(
            "deployed {path} failed checksum verification"
        )));
    }
    if let Err(e) = cleanup_stale(handle, &name).await {
        warn!("stale deployment cleanup failed: {e}");
    }
    info!("deployed {path} ({} bytes)", bin.len());
    Ok(path)
}

/// Remove stale deployments (old versions, orphaned uploads) from SERVE_DIR,
/// keeping `keep` (the just-verified binary name).
///
/// Only names this tool could have generated are considered, and each must
/// match a strict character set before it is put into the `rm` command line -
/// the remote login shell (fish, csh, ...) parses it. Deleting the path of a
/// running binary is safe on Linux: the open inode survives.
async fn cleanup_stale(handle: &SshHandle, keep: &str) -> Result<()> {
    let (rc, out, _) = exec_collect(handle, &format!("ls {SERVE_DIR}")).await?;
    if rc != 0 {
        return Ok(()); // directory gone: nothing to clean
    }
    let tool_generated = |name: &str| {
        (name.starts_with("sp-serve-") || name.starts_with(".upload-"))
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    let stale: Vec<String> = String::from_utf8_lossy(&out)
        .lines()
        .map(str::trim)
        .filter(|n| *n != keep && tool_generated(n))
        .map(|n| format!("{SERVE_DIR}/{n}"))
        .collect();
    if stale.is_empty() {
        return Ok(());
    }
    exec_status(handle, &format!("rm -f {}", stale.join(" "))).await?;
    info!("cleaned {} stale deployment(s)", stale.len());
    Ok(())
}

/// Run one command through `sp-serve` over a fresh exec channel.
///
/// `stdin` receives stdin data / eof with backpressure (the lane is awaited,
/// never skipped: a full lane stalls the daemon's client reads instead of
/// dropping data); `signals` receives signals; `output` receives forwarded
/// stdout/stderr chunks, whose send errors (client gone) are ignored so the
/// remote side can still finish cleanly.
///
/// This function always returns, and its tasks never outlive its future: every
/// channel write is cancellable against a latched shutdown flag (russh parks
/// data writes on the send-window notifier and channel Close never wakes
/// them, see the forwarder below), the final joins are time-bounded, and a
/// dropped future aborts the tasks via [`EngineTasks`]. Signals travel out of
/// band (all but Kill) from a dedicated sender task, so they are delivered
/// even while stdin writes are parked on a full window.
pub async fn execute(
    handle: &SshHandle,
    serve_path: &str,
    req: &ExecRequest,
    mut stdin: mpsc::Receiver<StdinEvent>,
    mut signals: mpsc::Receiver<Signal>,
    output: mpsc::Sender<OutputEvent>,
) -> Result<ExecOutcome> {
    let channel = timeout(EXEC_SETUP_TIMEOUT, handle.channel_open_session())
        .await
        .map_err(|_| exec_setup_timeout("open exec channel", &req.host))?
        .map_err(|e| Error::Remote(format!("open exec channel: {e}")))?;
    timeout(EXEC_SETUP_TIMEOUT, channel.exec(false, serve_path))
        .await
        .map_err(|_| exec_setup_timeout("exec request", &req.host))?
        .map_err(|e| Error::Remote(format!("request exec {serve_path}: {e}")))?;
    let (mut reader, writer) = channel.split();

    let exec_frame = sp_proto::encode_exec_frame(&ExecFrame::Exec(req.clone()))?;
    timeout(EXEC_SETUP_TIMEOUT, writer.data_bytes(exec_frame))
        .await
        .map_err(|_| exec_setup_timeout("send Exec frame", &req.host))?
        .map_err(|e| Error::Remote(format!("send Exec frame: {e}")))?;

    let (shutdown, shutdown_rx) = Shutdown::new();

    // Reader task owns wait() so the control loop below can run alongside.
    let (msg_tx, mut msg_rx) = mpsc::channel(64);
    let reader_shutdown = shutdown.clone();
    let mut reader_wake = shutdown_rx.clone();
    let reader_task = tokio::spawn(async move {
        loop {
            let msg = tokio::select! {
                m = reader.wait() => match m {
                    Some(m) => m,
                    // Channel closed or transport dead.
                    None => break,
                },
                _ = reader_wake.changed() => break,
            };
            let ev = match msg {
                ChannelMsg::Data { data } => ChanEvent::Data(data.to_vec()),
                ChannelMsg::ExtendedData { data, ext: 1 } => ChanEvent::Log(data.to_vec()),
                ChannelMsg::ExitStatus { exit_status } => ChanEvent::Status(exit_status),
                ChannelMsg::Eof | ChannelMsg::Close => ChanEvent::Closed,
                _ => continue,
            };
            if msg_tx.send(ev).await.is_err() {
                break;
            }
        }
        // Channel gone: no WindowAdjust will ever arrive, so the forwarder's
        // parked writes must be woken by us.
        reader_shutdown.fire();
    });

    // The write half is shared by the forwarder (sole data-path writer) and
    // the out-of-band signal sender below. ChannelWriteHalf is not Clone, but
    // its methods take &self and only clone the event-loop sender internally,
    // so an Arc suffices: both tasks enqueue whole SSH messages, and only the
    // data path ever touches the send window.
    let writer = Arc::new(writer);

    // Out-of-band signal sender: consumes the signal lane and calls only
    // writer.signal() - an SSH channel request that consumes no stdin window
    // and writes no data frame. A dedicated task keeps this path alive while
    // the forwarder is parked inside a data write on a full window, which is
    // precisely when an interrupt must get through (the forwarder cannot
    // serve the signal lane from inside that park). Each signal is then
    // relayed to the forwarder's in-band lane for the compatibility frame.
    let (inband_tx, mut inband_rx) = mpsc::channel::<Signal>(8);
    let sig_writer = Arc::clone(&writer);
    let mut sig_shutdown = shutdown_rx.clone();
    let signal_sender = tokio::spawn(async move {
        while let Some(sig) = tokio::select! {
            sig = signals.recv() => sig,
            _ = sig_shutdown.changed() => None,
        } {
            if goes_out_of_band(sig) {
                let sent = tokio::select! {
                    r = sig_writer.signal(russh_sig(sig)) => Some(r),
                    _ = sig_shutdown.changed() => None,
                };
                match sent {
                    Some(Ok(())) => {},
                    Some(Err(e)) => warn!("out-of-band signal {}: {e}", sig.as_str()),
                    // Shutdown mid-send: teardown owns the channel now.
                    None => break,
                }
            }
            // In-band relay (compat path; the frame is ordered behind queued
            // stdin data). Best-effort by design: a signal that went out of
            // band is already delivered, so a drop here only loses its
            // duplicate - except Kill, whose only delivery path this is.
            if inband_tx.try_send(sig).is_err() {
                if goes_out_of_band(sig) {
                    warn!(
                        "in-band signal lane full, dropping {} signal (out-of-band request \
                         already sent)",
                        sig.as_str()
                    );
                } else {
                    warn!(
                        "in-band signal lane full, dropping Kill signal; it has no out-of-band \
                         fallback"
                    );
                }
            }
        }
    });

    // Frame forwarder: the sole data-path writer. Every write is selected
    // against the shutdown flag: russh 0.63 parks data writes on the window
    // notifier (`reserve_writable_chunk`), which only a WindowAdjust ever
    // fires - a channel Close does not - and `ChannelWriteHalf` has no Drop
    // impl, so without this a full stdin window (serve stopped reading) would
    // park the task forever. Cancelling a data write mid-frame would leave a
    // partial frame on the wire, so it happens on teardown only, when nobody
    // reads the stream anymore; signals never cancel a write - out-of-band
    // delivery lives in its own task above.
    let fwd_writer = Arc::clone(&writer);
    let mut fwd_shutdown = shutdown_rx.clone();
    let forwarder = tokio::spawn(async move {
        let writer = fwd_writer;
        // False until Eof was sent (or the lane closed without one); only
        // late signals are forwarded afterwards.
        let mut stdin_open = true;
        'main: loop {
            if !stdin_open {
                let sig = tokio::select! {
                    sig = inband_rx.recv() => match sig {
                        Some(sig) => sig,
                        // In-band lane closed: the signal sender exited, the
                        // engine side is done.
                        None => break 'main,
                    },
                    _ = fwd_shutdown.changed() => break 'main,
                };
                if !send_signal_frame(&writer, &mut fwd_shutdown, sig).await {
                    break 'main;
                }
                continue;
            }
            tokio::select! {
                biased;
                // Signal frames first: control traffic may overtake queued
                // stdin data (the request itself already went out of band).
                sig = inband_rx.recv() => {
                    if let Some(sig) = sig
                        && !send_signal_frame(&writer, &mut fwd_shutdown, sig).await
                    {
                        break 'main;
                    }
                },
                ev = stdin.recv() => {
                    match ev {
                        Some(StdinEvent::Data(d)) => {
                            let frame = ExecFrame::StdinData(d);
                            let sent = tokio::select! {
                                r = send_frame(&writer, &frame) => r,
                                _ = fwd_shutdown.changed() => break 'main,
                            };
                            if sent.is_err() {
                                break 'main; // transport dead
                            }
                        },
                        Some(StdinEvent::Eof) => {
                            // Drains behind the data already queued on the
                            // lane, which is what keeps EOF ordered.
                            let frame = ExecFrame::StdinEof;
                            let _ = tokio::select! {
                                r = send_frame(&writer, &frame) => r,
                                _ = fwd_shutdown.changed() => break 'main,
                            };
                            stdin_open = false;
                        },
                        // Lane closed without an Eof: the engine is being torn
                        // down; do not synthesize an EOF for it.
                        None => stdin_open = false,
                    }
                },
                _ = fwd_shutdown.changed() => break 'main,
            }
        }
        // Best-effort close: tells the remote side the channel is over so it
        // kills the process group. Bounded because the event loop underneath
        // can itself be wedged.
        if timeout(FORWARDER_CLOSE, writer.close()).await.is_err() {
            warn!("exec channel close did not complete within {FORWARDER_CLOSE:?}");
        }
    });

    // Dropped (instead of finished) when the engine future is cancelled at
    // any await point; see EngineTasks for what that guarantees.
    let mut engine_tasks = EngineTasks {
        shutdown,
        // No teardown side effects: both exit on the shutdown flag and are
        // simply aborted.
        side_tasks: vec![reader_task, signal_sender],
        forwarder: Some(forwarder),
    };

    // Control loop: decodes serve's output frames. It never touches the
    // write half - stdin and signals are the lanes consumed above.
    let mut decoder = EventDecoder::new();
    let mut serve_log = ServeLog::default();
    let mut report: Option<ExitReport> = None;
    let mut serve_status: Option<u32> = None;

    'outer: loop {
        match msg_rx.recv().await {
            None | Some(ChanEvent::Closed) => break,
            Some(ChanEvent::Data(bytes)) => {
                for frame in decoder.push(&bytes)? {
                    match frame {
                        EventFrame::Stdout(d) => {
                            let _ = output.send(OutputEvent::Stdout(d)).await;
                        },
                        EventFrame::Stderr(d) => {
                            let _ = output.send(OutputEvent::Stderr(d)).await;
                        },
                        EventFrame::Exit(rep) => {
                            report = Some(rep);
                            break 'outer;
                        },
                        EventFrame::Pong(_) => {},
                    }
                }
            },
            Some(ChanEvent::Log(bytes)) => serve_log.feed(&bytes),
            Some(ChanEvent::Status(s)) => serve_status = Some(s),
        }
    }

    serve_log.flush();
    engine_tasks.finish().await;

    match report {
        Some(rep) => Ok(ExecOutcome {
            exit_code: rep.code,
            new_cwd: rep.cwd,
            new_state: rep.state,
            timed_out: rep.timed_out,
        }),
        None => Err(Error::Remote(format!(
            "sp-serve closed the channel without an exit report (exit status {serve_status:?}); \
             see daemon log for its stderr"
        ))),
    }
}

/// Latched shutdown flag shared by the channel tasks and the drop guard:
/// every long-running await in them selects on `changed()`, which resolves
/// for all receivers exactly once `fire` has been called (or the sender was
/// dropped). `watch` instead of `Notify` because a bare notify permit can be
/// missed by a task that has not reached its await point yet.
#[derive(Clone)]
struct Shutdown(Arc<watch::Sender<bool>>);

impl Shutdown {
    fn new() -> (Self, watch::Receiver<bool>) {
        let (tx, rx) = watch::channel(false);
        (Self(Arc::new(tx)), rx)
    }

    /// Idempotent.
    fn fire(&self) {
        let _ = self.0.send(true);
    }
}

/// Owns the channel tasks so a cancelled engine future cannot leak them: the
/// daemon's watchdog (or a dying runtime) drops `execute`'s future at an
/// arbitrary await point. `finish` is the normal completion path; `Drop`
/// covers every other one - it fires the shutdown flag first so the forwarder
/// can still send the channel close (which makes the remote side kill the
/// process group) and aborts whatever is still stuck after a grace period.
/// Aborting a finished task is a no-op.
struct EngineTasks {
    shutdown: Shutdown,
    /// Tasks without teardown side effects (channel reader, out-of-band
    /// signal sender): they exit on the shutdown flag and are aborted
    /// outright.
    side_tasks: Vec<JoinHandle<()>>,
    /// Owns the channel close; joined with a bound instead of aborted.
    forwarder: Option<JoinHandle<()>>,
}

impl EngineTasks {
    /// Normal completion: stop the side tasks, then let the forwarder drain
    /// and close the channel - time-bounded, so `execute` always returns.
    async fn finish(&mut self) {
        self.shutdown.fire();
        for task in std::mem::take(&mut self.side_tasks) {
            task.abort();
            let _ = task.await;
        }
        let Some(forwarder) = self.forwarder.take() else {
            return;
        };
        let mut forwarder = forwarder;
        if timeout(FORWARDER_JOIN, &mut forwarder).await.is_err() {
            warn!(
                "stdin forwarder did not finish within {FORWARDER_JOIN:?}; aborting it, the \
                 channel stays open until the connection ends"
            );
            forwarder.abort();
            let _ = forwarder.await;
        }
    }
}

impl Drop for EngineTasks {
    fn drop(&mut self) {
        self.shutdown.fire();
        let mut side_tasks = std::mem::take(&mut self.side_tasks);
        let Some(mut forwarder) = self.forwarder.take() else {
            return;
        };
        let all_done = forwarder.is_finished() && side_tasks.iter().all(JoinHandle::is_finished);
        if all_done {
            return;
        }
        warn!("execution abandoned with channel tasks running; reaping them");
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let joined = timeout(TASK_REAP, async {
                    for task in &mut side_tasks {
                        let _ = task.await;
                    }
                    let _ = (&mut forwarder).await;
                })
                .await
                .is_ok();
                if !joined {
                    warn!("channel tasks still stuck after shutdown; aborting");
                    for task in &mut side_tasks {
                        task.abort();
                    }
                    forwarder.abort();
                    for task in side_tasks {
                        let _ = task.await;
                    }
                    let _ = forwarder.await;
                }
            });
        } else {
            // No runtime (e.g. runtime shutdown dropping this future): abort
            // still flags the tasks so they cannot run on.
            for task in &mut side_tasks {
                task.abort();
            }
            forwarder.abort();
        }
    }
}

/// Whether `sig` may travel as an out-of-band SSH channel request. Kill must
/// not: sshd delivers channel signal requests to the serve process itself,
/// not to the command's process group, and an uncatchable SIGKILL there kills
/// serve before it can kill the group or report an exit (137). Kill travels
/// in-band only, where serve does `kill_group(SIGKILL)` and still reports.
fn goes_out_of_band(sig: Signal) -> bool {
    sig != Signal::Kill
}

/// Send one in-band Signal frame, best-effort; returns false when the caller's
/// loop must stop (shutdown fired or the transport is dead). The frame is the
/// compatibility path - the out-of-band request (sent by the signal sender
/// task, except for Kill) is what actually carries the signal.
async fn send_signal_frame(
    writer: &russh::ChannelWriteHalf<russh::client::Msg>,
    shutdown: &mut watch::Receiver<bool>,
    sig: Signal,
) -> bool {
    let frame = ExecFrame::Signal(sig);
    match tokio::select! {
        r = send_frame(writer, &frame) => Some(r),
        _ = shutdown.changed() => None,
    } {
        Some(Ok(())) => true,
        Some(Err(e)) => {
            warn!("in-band signal frame {}: {e}", sig.as_str());
            false
        },
        None => false,
    }
}

/// sp-proto signal to the matching SSH channel-request signal.
fn russh_sig(sig: Signal) -> russh::Sig {
    match sig {
        Signal::Int => russh::Sig::INT,
        Signal::Term => russh::Sig::TERM,
        Signal::Kill => russh::Sig::KILL,
        Signal::Hup => russh::Sig::HUP,
    }
}

async fn send_frame(
    writer: &russh::ChannelWriteHalf<russh::client::Msg>,
    frame: &ExecFrame,
) -> Result<()> {
    writer
        .data_bytes(sp_proto::encode_exec_frame(frame)?)
        .await
        .map_err(|e| Error::Remote(format!("send frame: {e}")))
}

enum ChanEvent {
    Data(Vec<u8>),
    Log(Vec<u8>),
    Status(u32),
    Closed,
}

/// Assembles serve's stderr chunks into log lines.
#[derive(Default)]
struct ServeLog {
    buf: String,
}

impl ServeLog {
    fn feed(&mut self, bytes: &[u8]) {
        self.buf.push_str(&String::from_utf8_lossy(bytes));
        while let Some(i) = self.buf.find('\n') {
            let line: String = self.buf.drain(..=i).collect();
            info!("{}", line.trim_end());
        }
    }

    fn flush(&mut self) {
        if !self.buf.is_empty() {
            info!("{}", self.buf.trim_end());
            self.buf.clear();
        }
    }
}

/// Run a fixed command on an exec channel; returns (status, stdout, stderr).
///
/// Only for trusted, metacharacter-free command strings we build ourselves;
/// the remote login shell (fish, csh, ...) parses them.
async fn exec_collect(handle: &SshHandle, cmd: &str) -> Result<(i32, Vec<u8>, Vec<u8>)> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| Error::Remote(format!("open channel for {cmd:?}: {e}")))?;
    channel
        .exec(false, cmd)
        .await
        .map_err(|e| Error::Remote(format!("exec {cmd:?}: {e}")))?;
    let (mut reader, writer) = channel.split();
    let mut status = None;
    let mut out = Vec::new();
    let mut err = Vec::new();
    while let Some(msg) = reader.wait().await {
        match msg {
            ChannelMsg::Data { data } => out.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, ext: 1 } => err.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => {
                status = Some(i32::try_from(exit_status).unwrap_or(255));
            },
            ChannelMsg::Close => break,
            _ => {},
        }
    }
    let _ = writer.close().await;
    Ok((status.unwrap_or(255), out, err))
}

/// Like [`exec_collect`], but requires exit status 0.
async fn exec_status(handle: &SshHandle, cmd: &str) -> Result<()> {
    let (rc, _, err) = exec_collect(handle, cmd).await?;
    if rc != 0 {
        return Err(Error::Remote(format!(
            "`{cmd}` failed with rc={rc}: {}",
            String::from_utf8_lossy(&err).trim()
        )));
    }
    Ok(())
}

/// Check whether the remote file's sha256 matches `expected`.
///
/// Fast path hashes remotely (coreutils and busybox both provide sha256sum),
/// transferring 64 bytes instead of the whole binary. When the tool is
/// missing (rc 127) the file is pulled and hashed locally instead.
async fn remote_matches(handle: &SshHandle, path: &str, expected: &[u8]) -> Result<bool> {
    let expected_hex =
        hex_simd::encode_to_string(Sha256::digest(expected), hex_simd::AsciiCase::Lower);
    let (rc, out, _) = exec_collect(handle, &format!("sha256sum {path}")).await?;
    if rc == 0 {
        let got = String::from_utf8_lossy(&out)
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        return Ok(got == expected_hex);
    }
    if rc != 127 {
        // Hashed fine but the file is missing/unreadable: redeploy.
        return Ok(false);
    }
    let (rc, out, _) = exec_collect(handle, &format!("cat {path}")).await?;
    if rc != 0 {
        return Ok(false); // missing or unreadable: deploy
    }
    Ok(Sha256::digest(&out)[..] == Sha256::digest(expected)[..])
}

/// Upload `data` to `path` through a dedicated `cat > path` channel.
async fn upload(handle: &SshHandle, path: &str, data: &[u8]) -> Result<()> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| Error::Remote(format!("open upload channel: {e}")))?;
    channel
        .exec(false, format!("cat > {path}"))
        .await
        .map_err(|e| Error::Remote(format!("request upload: {e}")))?;
    let (mut reader, writer) = channel.split();
    writer
        .data(data)
        .await
        .map_err(|e| Error::Remote(format!("upload: {e}")))?;
    writer
        .eof()
        .await
        .map_err(|e| Error::Remote(format!("finish upload: {e}")))?;
    let mut status = None;
    while let Some(msg) = reader.wait().await {
        match msg {
            ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
            ChannelMsg::Close => break,
            _ => {},
        }
    }
    let _ = writer.close().await;
    if status != Some(0) {
        return Err(Error::Remote(format!(
            "upload to {path} failed (status={status:?}); is the home directory writable?"
        )));
    }
    Ok(())
}

fn new_nonce() -> String {
    let bytes: [u8; 16] = rand::random();
    hex_simd::encode_to_string(bytes, hex_simd::AsciiCase::Lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_mapping_covers_every_sp_signal() {
        // A wrong mapping silently signals the remote process with the wrong
        // signal; the compiler cannot catch enum-to-enum drift.
        assert!(matches!(russh_sig(Signal::Int), russh::Sig::INT));
        assert!(matches!(russh_sig(Signal::Term), russh::Sig::TERM));
        assert!(matches!(russh_sig(Signal::Kill), russh::Sig::KILL));
        assert!(matches!(russh_sig(Signal::Hup), russh::Sig::HUP));
    }

    #[test]
    fn only_kill_is_gated_off_the_out_of_band_path() {
        // Out of band, sshd hands the request to serve itself; an
        // uncatchable Kill would end serve without an exit report.
        assert!(goes_out_of_band(Signal::Int));
        assert!(goes_out_of_band(Signal::Term));
        assert!(goes_out_of_band(Signal::Hup));
        assert!(!goes_out_of_band(Signal::Kill));
    }

    #[tokio::test]
    async fn shutdown_latches_for_later_awaiters() {
        // The teardown guarantee relies on the flag being latched: a task that
        // has not reached its `changed()` await yet must still observe an
        // earlier fire().
        let (shutdown, mut rx) = Shutdown::new();
        shutdown.fire();
        shutdown.fire(); // idempotent
        assert!(rx.changed().await.is_ok());
        assert!(*rx.borrow_and_update());
    }
}
