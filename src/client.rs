//! Client side: connect to the daemon (spawning it when absent), run one
//! command and pump stdin/stdout/stderr/signals.

use std::{
    path::Path,
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};

use crate::{
    config,
    error::{Error, Result},
    proto::{
        EventFrame, ExecFrame, ExecRequest, ExitReport, Signal, read_event_frame, write_exec_frame,
    },
    transport::IpcStream,
};

/// Two Ctrl+C presses within this window force a local exit (130). The daemon
/// may be wedged and unable to relay the remote exit code; a healthy flow
/// reports it before a human can press twice.
const FORCE_EXIT_WINDOW: Duration = Duration::from_secs(1);

/// Connect to the daemon, spawning it if it is not running yet.
pub async fn connect_or_spawn() -> Result<IpcStream> {
    let path = config::sock_path();
    if let Ok(s) = IpcStream::connect(&path).await {
        return Ok(s);
    }
    #[cfg(unix)]
    if path.starts_with('/') {
        // Only a refused connection proves the socket file is stale (bound
        // once, no listener anymore); removing it on any other error could
        // race with a live daemon that just bound its socket.
        match IpcStream::connect(&path).await {
            Ok(s) => return Ok(s),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                let _ = std::fs::remove_file(&path);
            },
            Err(_) => {},
        }
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

/// Spawn the daemon detached; see the Windows notes on the `cfg(windows)`
/// twin. On unix the daemon gets its own process group so terminal Ctrl+C
/// does not hit it.
#[cfg(unix)]
pub fn spawn_daemon() -> Result<()> {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe().map_err(|e| Error::Daemon(format!("current_exe: {e}")))?;
    let mut cmd = tokio::process::Command::new(&exe);
    cmd.arg("daemon")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // Own process group: terminal Ctrl+C must not hit the daemon.
    cmd.process_group(0);
    cmd.spawn()
        .map_err(|e| Error::Daemon(format!("spawn daemon {}: {e}", exe.display())))?;
    Ok(())
}

/// Spawn the daemon detached; inherits the environment (SP_SOCK etc.) but no
/// handles and no console.
///
/// `std::process::Command` always inherits every inheritable handle on
/// Windows; the daemon would then pin the parent's console pipes open and any
/// parent reading them to EOF (terminals, editors, CI) hangs forever. With
/// DETACHED_PROCESS and no inherited handles the daemon gets no stdio at all,
/// which is fine: it only writes to its log file.
#[cfg(windows)]
pub fn spawn_daemon() -> Result<()> {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::Threading::{
            CREATE_NEW_PROCESS_GROUP, CreateProcessW, DETACHED_PROCESS, PROCESS_INFORMATION,
            STARTUPINFOW,
        },
    };

    let exe = std::env::current_exe().map_err(|e| Error::Daemon(format!("current_exe: {e}")))?;
    let mut cmdline: Vec<u16> = format!("\"{}\" daemon", exe.display())
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = u32::try_from(size_of::<STARTUPINFOW>()).expect("size fits");
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: cmdline is a valid mutable nul-terminated UTF-16 buffer kept
    // alive for the call; si/pi are correctly sized out-params; the returned
    // process/thread handles are closed immediately.
    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmdline.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            std::ptr::null(),
            std::ptr::null(),
            &raw const si,
            &raw mut pi,
        )
    };
    if ok == 0 {
        return Err(Error::Daemon(format!(
            "spawn daemon {}: {}",
            exe.display(),
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: both handles are valid after a successful CreateProcessW.
    unsafe {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    Ok(())
}

/// Ping the daemon without spawning it; returns its pid.
pub async fn ping() -> Result<u32> {
    let path = config::sock_path();
    let mut stream = IpcStream::connect(&path)
        .await
        .map_err(|e| Error::Daemon(format!("daemon not running at {path}: {e}")))?;
    write_exec_frame(&mut stream, &ExecFrame::Ping).await?;
    match tokio::time::timeout(Duration::from_secs(3), read_event_frame(&mut stream)).await {
        Ok(Ok(Some(EventFrame::Pong(p)))) => Ok(p.pid),
        Ok(Ok(other)) => Err(Error::Protocol(format!("unexpected reply: {other:?}"))),
        Ok(Err(e)) => Err(Error::Ipc(e.to_string())),
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
    /// Daemon/serve-side failure reason (connect, auth, deploy, ...), when the
    /// daemon reported one alongside a non-zero code.
    pub error: Option<String>,
}

impl From<ExitReport> for RunReport {
    fn from(r: ExitReport) -> Self {
        Self {
            code: r.code,
            cwd: r.cwd,
            timed_out: r.timed_out,
            error: r.error,
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
    write_exec_frame(&mut stream, &ExecFrame::Exec(req)).await?;
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
    let mut last_int: Option<Instant> = None;

    let report = loop {
        tokio::select! {
            n = stdin.read(&mut in_buf), if stdin_open => {
                match n {
                    Ok(0) => {
                        write_exec_frame(&mut writer, &ExecFrame::StdinEof).await?;
                        stdin_open = false;
                    }
                    Ok(n) => {
                        write_exec_frame(&mut writer, &ExecFrame::StdinData(in_buf[..n].to_vec())).await?;
                    }
                    Err(_) => {
                        // Unreadable stdin: tell the daemon it is done.
                        let _ = write_exec_frame(&mut writer, &ExecFrame::StdinEof).await;
                        stdin_open = false;
                    }
                }
            }
            frame = read_event_frame(&mut reader) => {
                match frame? {
                    Some(EventFrame::Stdout(d)) => {
                        stdout.write_all(&d).await?;
                        stdout.flush().await?;
                    }
                    Some(EventFrame::Stderr(d)) => {
                        stderr.write_all(&d).await?;
                        stderr.flush().await?;
                    }
                    Some(EventFrame::Exit(rep)) => break Ok(RunReport::from(rep)),
                    Some(EventFrame::Pong(_)) => {}
                    None => {
                        break Err(Error::Daemon(
                            "daemon closed the connection before exit".into(),
                        ));
                    }
                }
            }
            sig = signals.recv(), if signals_open => {
                match sig {
                    Some(Signal::Int) => {
                        let now = Instant::now();
                        if last_int.is_some_and(|t| now.duration_since(t) < FORCE_EXIT_WINDOW) {
                            break Ok(RunReport {
                                code: 130,
                                cwd: None,
                                timed_out: false,
                                error: None,
                            });
                        }
                        last_int = Some(now);
                        write_exec_frame(&mut writer, &ExecFrame::Signal(Signal::Int)).await?;
                    },
                    Some(sig) => {
                        write_exec_frame(&mut writer, &ExecFrame::Signal(sig)).await?;
                    },
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
