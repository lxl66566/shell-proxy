//! Client side: connect to the daemon (spawning it when absent), run one
//! command and pump stdin/stdout/stderr/signals.

use std::{path::Path, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};

use crate::{
    config,
    error::{Error, Result},
    ipc::{ClientFrame, DaemonFrame, ExecRequest, ExitReport, Signal, read_frame, write_frame},
    transport::IpcStream,
};

/// Connect to the daemon, spawning it if it is not running yet.
pub async fn connect_or_spawn() -> Result<IpcStream> {
    let path = config::sock_path();
    if let Ok(s) = IpcStream::connect(&path).await {
        return Ok(s);
    }
    #[cfg(unix)]
    if path.starts_with('/') {
        // A leftover socket from a dead daemon blocks the bind.
        let _ = std::fs::remove_file(&path);
    }
    spawn_daemon()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match IpcStream::connect(&path).await {
            Ok(s) => return Ok(s),
            Err(e) if std::time::Instant::now() >= deadline => {
                return Err(Error::Daemon(format!(
                    "daemon did not come up at {path}: {e}"
                )));
            },
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

fn spawn_daemon() -> Result<()> {
    let exe = std::env::current_exe().map_err(|e| Error::Daemon(format!("current_exe: {e}")))?;
    let mut cmd = tokio::process::Command::new(&exe);
    cmd.arg("daemon")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        // Detached: survives the console and ignores console Ctrl+C events.
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Own process group: terminal Ctrl+C must not hit the daemon.
        cmd.process_group(0);
    }
    cmd.spawn()
        .map_err(|e| Error::Daemon(format!("spawn daemon {}: {e}", exe.display())))?;
    Ok(())
}

/// Ping the daemon without spawning it; returns its pid.
pub async fn ping() -> Result<u32> {
    let path = config::sock_path();
    let mut stream = IpcStream::connect(&path)
        .await
        .map_err(|e| Error::Daemon(format!("daemon not running at {path}: {e}")))?;
    write_frame(&mut stream, &ClientFrame::Ping).await?;
    match tokio::time::timeout(Duration::from_secs(3), read_frame(&mut stream)).await {
        Ok(Ok(Some(DaemonFrame::Pong(p)))) => Ok(p.pid),
        Ok(Ok(other)) => Err(Error::Protocol(format!("unexpected reply: {other:?}"))),
        Ok(Err(e)) => Err(Error::Ipc(e.brief())),
        Err(_) => Err(Error::Ipc("ping timed out".into())),
    }
}

/// Inputs of a client-side run.
pub struct RunIo<'a> {
    pub stdin: Box<dyn AsyncRead + Send + Unpin + 'a>,
    pub stdout: Box<dyn AsyncWrite + Send + Unpin + 'a>,
    pub stderr: Box<dyn AsyncWrite + Send + Unpin + 'a>,
}

/// Result of a client-side run.
#[derive(Debug, Clone)]
pub struct RunReport {
    pub code: i32,
    pub cwd: Option<String>,
    pub timed_out: bool,
}

impl From<ExitReport> for RunReport {
    fn from(r: ExitReport) -> Self {
        Self {
            code: r.code,
            cwd: r.cwd,
            timed_out: r.timed_out,
        }
    }
}

/// Execute one request against the daemon, forwarding streams and signals.
///
/// A dropped `signals` receiver disables forwarding. Returns after the
/// daemon's exit frame; the connection is closed afterwards (one exec per
/// connection, matching the daemon side).
pub async fn run(
    req: ExecRequest,
    io: RunIo<'_>,
    mut signals: mpsc::Receiver<Signal>,
) -> Result<RunReport> {
    let mut stream = connect_or_spawn().await?;
    write_frame(&mut stream, &ClientFrame::Exec(req)).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);

    let RunIo {
        stdin,
        stdout,
        stderr,
    } = io;
    let mut stdin = stdin;
    let mut stdout = stdout;
    let mut stderr = stderr;
    // Heap-allocated: a stack array here would make every caller's future
    // huge (clippy::large_futures).
    let mut in_buf = vec![0u8; 64 * 1024];
    let mut stdin_open = true;
    let mut signals_open = true;

    let report = loop {
        tokio::select! {
            n = stdin.read(&mut in_buf), if stdin_open => {
                match n {
                    Ok(0) => {
                        write_frame(&mut writer, &ClientFrame::StdinEof).await?;
                        stdin_open = false;
                    }
                    Ok(n) => {
                        write_frame(&mut writer, &ClientFrame::StdinData(in_buf[..n].to_vec())).await?;
                    }
                    Err(_) => stdin_open = false, // unreadable stdin: stop forwarding
                }
            }
            frame = read_frame(&mut reader) => {
                match frame? {
                    Some(DaemonFrame::Stdout(d)) => {
                        stdout.write_all(&d).await?;
                        stdout.flush().await?;
                    }
                    Some(DaemonFrame::Stderr(d)) => {
                        stderr.write_all(&d).await?;
                        stderr.flush().await?;
                    }
                    Some(DaemonFrame::Exit(rep)) => break Ok(RunReport::from(rep)),
                    Some(DaemonFrame::Pong(_)) => {}
                    None => {
                        break Err(Error::Daemon(
                            "daemon closed the connection before exit".into(),
                        ));
                    }
                }
            }
            sig = signals.recv(), if signals_open => {
                match sig {
                    Some(sig) => {
                        write_frame(&mut writer, &ClientFrame::Signal(sig)).await?;
                    }
                    None => signals_open = false,
                }
            }
        }
    };

    let _ = writer.shutdown().await;
    report
}

/// Convenience wrapper capturing output in memory (used by MCP and tests).
pub async fn run_captured(
    req: ExecRequest,
    stdin: Vec<u8>,
    signals: mpsc::Receiver<Signal>,
) -> Result<(RunReport, Vec<u8>, Vec<u8>)> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let io = RunIo {
        stdin: Box::new(std::io::Cursor::new(stdin)),
        stdout: Box::new(&mut stdout),
        stderr: Box::new(&mut stderr),
    };
    let report = run(req, io, signals).await?;
    Ok((report, stdout, stderr))
}

/// Read a script file for `-f` execution.
pub fn read_script_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    String::from_utf8(bytes)
        .map_err(|e| Error::Config(format!("{} is not valid UTF-8: {e}", path.display())))
}
