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
/// are not lost while a hung orphan (e.g. `sleep 100 &`) cannot block us
/// forever. Matches the behavior of the daemon-side implementation.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

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
async fn execute(req: &ExecRequest, spawned: Spawned, mut stdin: tokio::io::Stdin) -> Result<()> {
    let Spawned {
        mut child,
        stdin: child_stdin,
        stdout,
        stderr,
        cwd,
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

    let out_pump = pump(stdout, EventFrame::Stdout, out_tx.clone());
    let err_pump = pump(stderr, EventFrame::Stderr, out_tx.clone());
    let cwd_collect = tokio::spawn(read_cwd(cwd));

    // Child stdin writer: a full channel means the child is not reading; data
    // frames are dropped (logged) rather than blocking signal handling.
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
                StdinMsg::Eof => break, // dropping w sends EOF to the child
            }
        }
    });

    let timeout = req
        .timeout_ms
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis);
    let deadline = timeout.map(|t| Instant::now() + t);
    let far = Instant::now() + Duration::from_secs(86_400 * 365);
    let mut dead_rx = std::pin::pin!(dead_rx);
    let mut wait = std::pin::pin!(child.wait());
    let mut timed_out = false;

    let status = loop {
        let sel = tokio::select! {
            f = sp_proto::read_exec_frame(&mut stdin) => Sel::Frame(f),
            s = &mut wait => Sel::Exit(s),
            () = tokio::time::sleep_until(deadline.unwrap_or(far)), if deadline.is_some() && !timed_out => Sel::Timeout,
            d = &mut dead_rx => Sel::Dead(d.is_ok()),
        };
        match sel {
            Sel::Frame(Ok(Some(ExecFrame::StdinData(d)))) => {
                if stdin_tx.try_send(StdinMsg::Data(d)).is_err() {
                    log("child stdin backlog full, dropping a data frame");
                }
            },
            Sel::Frame(Ok(Some(ExecFrame::StdinEof))) => {
                let _ = stdin_tx.send(StdinMsg::Eof).await;
            },
            Sel::Frame(Ok(Some(ExecFrame::Signal(s)))) => {
                log(&format!("forwarding {} to pgid {pgid}", s.as_str()));
                kill_group(pgid, s);
            },
            Sel::Frame(Ok(Some(ExecFrame::Ping))) => {
                let _ = out_tx
                    .send(EventFrame::Pong(sp_proto::Pong {
                        pid: std::process::id(),
                    }))
                    .await;
            },
            // One exec per process; a second request is a protocol violation.
            Sel::Frame(Ok(Some(ExecFrame::Exec(_)))) => {},
            Sel::Frame(Ok(None)) => bail!("transport closed while the command was running"),
            Sel::Frame(Err(e)) => bail!("bad frame: {e}"),
            Sel::Exit(s) => break s.context("wait on child")?,
            Sel::Timeout => {
                timed_out = true;
                log(&format!(
                    "timeout after {}ms, killing pgid {pgid}",
                    timeout.unwrap_or_default().as_millis()
                ));
                kill_group_raw(pgid, libc::SIGKILL);
            },
            Sel::Dead(d) => {
                if d {
                    kill_group_raw(pgid, libc::SIGKILL);
                    bail!("daemon vanished while the command was running");
                }
            },
        }
    };

    let code = status_code(&status);
    // Drain tail output; orphans holding the pipes open must not block us.
    let _ = tokio::time::timeout(DRAIN_GRACE, async move {
        let _ = out_pump.await;
        let _ = err_pump.await;
    })
    .await;
    let new_cwd = match tokio::time::timeout(DRAIN_GRACE, cwd_collect).await {
        Ok(Ok(Some(cwd))) => Some(cwd),
        Ok(Ok(None)) => None,
        _ => {
            log("cwd report not fully read (orphan holds the pipe?); cwd unchanged");
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
        error: None,
        timed_out,
    };
    log(&format!("exit rc={} timed_out={timed_out}", report.code));
    drop(out_tx);
    let _ = writer.await;
    write_exit(&report).await?;
    Ok(())
}

enum Sel {
    Frame(sp_proto::Result<Option<ExecFrame>>),
    Exit(std::io::Result<std::process::ExitStatus>),
    Timeout,
    Dead(bool),
}

enum StdinMsg {
    Data(Vec<u8>),
    Eof,
}

/// Read the cwd pipe to the end; empty (wrapper `exec`ed away) means None.
async fn read_cwd(mut r: tokio::net::unix::pipe::Receiver) -> Option<String> {
    let mut buf = Vec::new();
    // A cwd is a path; anything beyond 8 KiB is garbage.
    let mut chunk = [0u8; 4096];
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 8192 {
                    return None;
                }
            },
        }
    }
    if buf.is_empty() {
        return None;
    }
    String::from_utf8(buf).ok().filter(|s| !s.is_empty())
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
