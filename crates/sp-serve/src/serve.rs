//! Protocol loop of sp-serve: one `Exec` request in, run it, frames out.
//!
//! serve is stateless and handles exactly one execution, then exits 0. Its own
//! stderr (diagnostics) travels as SSH extended data and lands in the daemon
//! log; only frames go to stdout.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use sp_proto::{
    EventFrame, ExecFrame, ExecRequest, ExitReport, INTERNAL_ERROR_CODE, Signal, TIMEOUT_EXIT_CODE,
    truncate_utf8,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
    time::Instant,
};

use crate::child::{self, Spawned};

/// Give the daemon this long to send the Exec frame before giving up.
const EXEC_WAIT: Duration = Duration::from_secs(30);

/// How long to keep draining child pipes after the exit status, so tail bytes
/// are not lost. A job surviving the command (`nohup ... &`) inherits the
/// pipes and never EOFs; past the grace the pumps are aborted and any further
/// output is dropped.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// Grace between the timeout TERM and the escalating KILL, so remote cleanup
/// handlers (traps, make/gradle shutdown hooks) get a chance to run.
const TERM_GRACE: Duration = Duration::from_secs(5);

/// Cap for the cwd report; anything beyond a path is garbage.
const CWD_CAP: usize = 8 * 1024;
/// Cap for the shell state dump; a user command can build huge variables, and
/// an unbounded dump would balloon the Exit frame and daemon memory. Overflow
/// keeps the previous state (logged) and the pipe is drained, not cut, so the
/// child's exit code is untouched.
const STATE_CAP: usize = 256 * 1024;

/// Entry point: returns the process exit code.
pub async fn run() -> i32 {
    match inner().await {
        Ok(()) => 0,
        Err(e) => {
            // A transport/protocol failure: no Exit frame can be trusted to
            // arrive anymore, so die loudly and let the exit status speak.
            log(&format!("fatal: {e:#}"));
            1
        },
    }
}

async fn inner() -> Result<()> {
    let mut stdin = tokio::io::stdin();
    let req = match tokio::time::timeout(EXEC_WAIT, sp_proto::read_exec_frame(&mut stdin)).await {
        Ok(Ok(Some(ExecFrame::Exec(req)))) => req,
        Ok(Ok(Some(other))) => bail!("first frame must be Exec, got {other:?}"),
        Ok(Ok(None)) => bail!("stdin closed before Exec frame"),
        Ok(Err(e)) => bail!("bad Exec frame: {e}"),
        Err(_) => bail!("timed out waiting for Exec frame"),
    };
    log(&format!(
        "exec cmd={:?} cwd={:?}",
        abbrev(&req.command),
        req.cwd
    ));

    // Spawn failures (missing bash, fd exhaustion) are reported as a regular
    // Exit frame so the client sees a clean error instead of a dropped channel.
    let spawned = match child::spawn(&req) {
        Ok(s) => s,
        Err(e) => {
            let report = ExitReport {
                code: INTERNAL_ERROR_CODE,
                cwd: None,
                state: None,
                error: Some(format!("spawn bash: {e}")),
                timed_out: false,
            };
            write_exit(&report).await?;
            return Ok(());
        },
    };

    execute(&req, spawned, stdin).await
}

/// Run the protocol loop until the child exits, then send the Exit frame.
async fn execute(req: &ExecRequest, spawned: Spawned, stdin: tokio::io::Stdin) -> Result<()> {
    let Spawned {
        mut child,
        stdin: child_stdin,
        stdout,
        stderr,
        cwd,
        state,
    } = spawned;
    let pgid = child
        .id()
        .context("child already reaped?")?
        .try_into()
        .context("pid does not fit i32")?;

    // Single stdout writer keeps frames ordered.
    let (out_tx, mut out_rx) = mpsc::channel::<EventFrame>(256);
    let (dead_tx, dead_rx) = tokio::sync::oneshot::channel::<()>();
    let writer = tokio::spawn(async move {
        let mut out = tokio::io::stdout();
        while let Some(f) = out_rx.recv().await {
            if sp_proto::write_event_frame(&mut out, &f).await.is_err()
                || out.flush().await.is_err()
            {
                break;
            }
        }
        // Daemon gone: output can no longer be delivered.
        let _ = dead_tx.send(());
    });

    let mut out_pump = pump(stdout, EventFrame::Stdout, out_tx.clone());
    let mut err_pump = pump(stderr, EventFrame::Stderr, out_tx.clone());
    let cwd_collect = tokio::spawn(read_pipe(cwd, CWD_CAP, "cwd report"));
    let state_collect = tokio::spawn(read_pipe(state, STATE_CAP, "state dump"));

    // Child stdin writer: a closed channel (Eof, or a broken child pipe) drops
    // the write end, which is what sends EOF to the child.
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<StdinMsg>(256);
    tokio::spawn(async move {
        let mut w = child_stdin;
        while let Some(m) = stdin_rx.recv().await {
            match m {
                StdinMsg::Data(d) => {
                    if w.write_all(&d).await.is_err() {
                        break;
                    }
                },
                StdinMsg::Eof => break,
            }
        }
    });

    // Transport reader. Stdin data is forwarded with a bounded await: when the
    // child stops reading, the SSH window closes and the producer on the
    // client side blocks - backpressure end to end instead of dropped data.
    // Control frames are routed to the main loop so signal handling never
    // waits behind this task's own awaits.
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Ctrl>(16);
    let ping_tx = out_tx.clone();
    let route = tokio::spawn(async move {
        let mut stdin = stdin;
        let ctrl_tx = ctrl_tx;
        let stdin_tx = stdin_tx;
        let ping_tx = ping_tx;
        loop {
            match sp_proto::read_exec_frame(&mut stdin).await {
                Ok(Some(ExecFrame::StdinData(d))) => {
                    if stdin_tx.send(StdinMsg::Data(d)).await.is_err() {
                        break; // child stdin writer gone (child exited)
                    }
                },
                Ok(Some(ExecFrame::StdinEof)) => {
                    if stdin_tx.send(StdinMsg::Eof).await.is_err() {
                        break;
                    }
                },
                Ok(Some(ExecFrame::Signal(s))) => {
                    if ctrl_tx.send(Ctrl::Signal(s)).await.is_err() {
                        break;
                    }
                },
                Ok(Some(ExecFrame::Ping)) => {
                    let _ = ping_tx
                        .send(EventFrame::Pong(sp_proto::Pong {
                            pid: std::process::id(),
                        }))
                        .await;
                },
                // One exec per process; a second request is a protocol violation.
                Ok(Some(ExecFrame::Exec(_))) => {},
                Ok(None) => {
                    let _ = ctrl_tx.send(Ctrl::Closed).await;
                    break;
                },
                Err(e) => {
                    let _ = ctrl_tx.send(Ctrl::Bad(e.to_string())).await;
                    break;
                },
            }
        }
    });

    let timeout = req
        .timeout_ms
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis);
    let mut term_deadline = timeout.map(|t| Instant::now() + t);
    let mut kill_deadline: Option<Instant> = None;
    let far = Instant::now() + Duration::from_secs(86_400 * 365);
    let mut dead_rx = std::pin::pin!(dead_rx);
    let mut wait = std::pin::pin!(child.wait());
    let mut timed_out = false;
    let mut ctrl_open = true;

    let status = loop {
        let sel = tokio::select! {
            c = ctrl_rx.recv(), if ctrl_open => Sel::Ctrl(c),
            s = &mut wait => Sel::Exit(s),
            () = tokio::time::sleep_until(kill_deadline.or(term_deadline).unwrap_or(far)), if kill_deadline.is_some() || term_deadline.is_some() => Sel::Timeout,
            d = &mut dead_rx => Sel::Dead(d.is_ok()),
        };
        match sel {
            Sel::Ctrl(Some(Ctrl::Signal(s))) => {
                log(&format!("forwarding {} to pgid {pgid}", s.as_str()));
                kill_group(pgid, s);
            },
            // Transport gone: the daemon will not send anything anymore. Kill
            // the group like the writer-failure path does - the child runs in
            // its own session and would otherwise survive as an orphan.
            Sel::Ctrl(Some(Ctrl::Closed)) => {
                kill_group_raw(pgid, libc::SIGKILL);
                bail!("transport closed while the command was running");
            },
            Sel::Ctrl(Some(Ctrl::Bad(e))) => {
                kill_group_raw(pgid, libc::SIGKILL);
                bail!("bad frame: {e}");
            },
            // Router done (its terminal message was delivered above, or the
            // child stdin writer is gone); the child exit decides the rest.
            Sel::Ctrl(None) => ctrl_open = false,
            Sel::Exit(s) => break s.context("wait on child")?,
            Sel::Timeout => {
                timed_out = true;
                if kill_deadline.is_none() {
                    // TERM first so traps and cleanup handlers run; escalate to
                    // KILL after the grace period (like `timeout -k`).
                    log(&format!(
                        "timeout after {}ms, sending TERM to pgid {pgid}",
                        timeout.unwrap_or_default().as_millis()
                    ));
                    kill_group(pgid, Signal::Term);
                    term_deadline = None;
                    kill_deadline = Some(Instant::now() + TERM_GRACE);
                } else {
                    log(&format!("grace elapsed, sending KILL to pgid {pgid}"));
                    kill_group_raw(pgid, libc::SIGKILL);
                    kill_deadline = None;
                }
            },
            Sel::Dead(d) => {
                if d {
                    kill_group_raw(pgid, libc::SIGKILL);
                    bail!("daemon vanished while the command was running");
                }
            },
        }
    };

    // The router holds an out_tx clone for Ping replies; it must be gone
    // before the writer task can observe channel closure.
    route.abort();

    let code = status_code(&status);
    // Drain tail output. Orphaned jobs holding the pipes open must not block
    // us: past the grace the pumps are aborted, not merely detached - a
    // detached pump keeps its writer sender alive, so the writer (and the Exit
    // frame behind it) would wait on a channel that cannot close until the
    // last orphan exits.
    if tokio::time::timeout(DRAIN_GRACE, async {
        let _ = (&mut out_pump).await;
        let _ = (&mut err_pump).await;
    })
    .await
    .is_err()
    {
        log("drain grace elapsed with output pipes still open (orphan job?); dropping tail");
        out_pump.abort();
        err_pump.abort();
    }
    let new_cwd = match tokio::time::timeout(DRAIN_GRACE, cwd_collect).await {
        Ok(Ok(Some(cwd))) => Some(cwd),
        Ok(Ok(None)) => None,
        _ => {
            log("cwd report did not terminate in time; cwd unchanged");
            None
        },
    };
    let new_state = match tokio::time::timeout(DRAIN_GRACE, state_collect).await {
        Ok(Ok(state)) => state,
        _ => {
            log("state dump did not terminate in time; state unchanged");
            None
        },
    };

    let report = ExitReport {
        code: if timed_out {
            TIMEOUT_EXIT_CODE
        } else {
            code
        },
        cwd: new_cwd,
        state: new_state,
        error: None,
        timed_out,
    };
    log(&format!("exit rc={} timed_out={timed_out}", report.code));
    // Every sender is gone now (route aborted, pumps finished or aborted), so
    // the writer flushes queued frames and exits; then the Exit frame goes out
    // in order behind them.
    drop(out_tx);
    let _ = writer.await;
    write_exit(&report).await?;
    Ok(())
}

enum Sel {
    Ctrl(Option<Ctrl>),
    Exit(std::io::Result<std::process::ExitStatus>),
    Timeout,
    Dead(bool),
}

/// Control event routed from the transport reader task to the main loop.
enum Ctrl {
    Signal(Signal),
    /// Transport EOF while the command is running.
    Closed,
    /// Malformed frame on the transport.
    Bad(String),
}

enum StdinMsg {
    Data(Vec<u8>),
    Eof,
}

/// Read an out-of-band report pipe to its NUL terminator.
///
/// The wrapper ends both reports with a NUL byte (bash data can never contain
/// one), so a surviving background job holding the write end open cannot stall
/// the read: the terminator, not EOF, is the completion signal. EOF without a
/// terminator (the wrapper `exec`ed away or was killed) still yields whatever
/// bytes arrived. `None` means "nothing to update": empty report, invalid
/// UTF-8, or `cap` exceeded (garbage guard; overflow is logged, the caller
/// keeps the previous value). On overflow the pipe is still drained to EOF so
/// a mid-write wrapper never sees EPIPE - the child must keep its real exit
/// code.
async fn read_pipe(
    mut r: tokio::net::unix::pipe::Receiver,
    cap: usize,
    what: &str,
) -> Option<String> {
    let mut buf = Vec::new();
    let mut overflow = false;
    let mut chunk = [0u8; 4096];
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if !overflow {
                    if let Some(pos) = chunk[..n].iter().position(|&b| b == 0) {
                        buf.extend_from_slice(&chunk[..pos]);
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.len() > cap {
                        overflow = true;
                        log(&format!(
                            "{what} exceeded {cap} bytes, keeping previous value"
                        ));
                    }
                }
                // Overflow: keep draining silently so the writer stays alive.
            },
        }
    }
    if overflow {
        return None;
    }
    if buf.is_empty() {
        return None;
    }
    match String::from_utf8(buf) {
        Ok(s) if !s.is_empty() => Some(s),
        _ => {
            log(&format!(
                "{what} is not valid UTF-8, keeping previous value"
            ));
            None
        },
    }
}

/// Forward one child pipe to frame output until EOF.
fn pump<R>(
    mut r: R,
    mk: fn(Vec<u8>) -> EventFrame,
    tx: mpsc::Sender<EventFrame>,
) -> tokio::task::JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(mk(buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                },
            }
        }
    })
}

/// Signal the whole process group of the child.
fn kill_group(pgid: i32, sig: Signal) {
    kill_group_raw(pgid, sig.as_raw());
}

/// `kill(-pgid, sig)`, falling back to the leader alone when the group is gone.
fn kill_group_raw(pgid: i32, sig: i32) {
    // SAFETY: kill with a negative pid targets the process group.
    let r = unsafe { libc::kill(-pgid, sig) };
    if r < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        // SAFETY: plain signal delivery to the leader pid.
        unsafe { libc::kill(pgid, sig) };
    }
}

/// Exit code from a wait status: normal code, or 128+signum like a shell.
fn status_code(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    if let Some(c) = status.code() {
        return c;
    }
    if let Some(s) = status.signal() {
        return 128 + s;
    }
    255
}

/// Send the terminal Exit frame directly (bypassing the pump channel).
async fn write_exit(report: &ExitReport) -> Result<()> {
    let mut out = tokio::io::stdout();
    sp_proto::write_event_frame(&mut out, &EventFrame::Exit(report.clone())).await?;
    out.flush().await?;
    Ok(())
}

fn log(msg: &str) {
    eprintln!("sp-serve: {msg}");
}

fn abbrev(s: &str) -> String {
    const MAX: usize = 300;
    if s.len() <= MAX {
        s.to_owned()
    } else {
        format!("{}...(total {} bytes)", truncate_utf8(s, MAX), s.len())
    }
}
