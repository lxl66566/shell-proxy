//! Remote command execution engine.
//!
//! One command = two SSH channels on the persistent connection:
//! 1. upload channel: `cat > /tmp/.sp-<nonce>.sh`, script bytes on stdin;
//! 2. exec channel: `bash /tmp/.sp-<nonce>.sh`, whose stdin stays free for the user's stdin
//!    forwarding.
//!
//! Completion is driven by the SSH exit-status/exit-signal message; streams are
//! drained for a grace period afterwards so tail bytes are not lost, while a
//! hung orphan (e.g. `sleep 100 &`) cannot block completion forever.

use std::time::Duration;

use russh::{ChannelMsg, Sig};
use tokio::{sync::mpsc, time::Instant};

use crate::{
    error::{Error, Result},
    ipc::Signal,
    marker::MarkerFilter,
    script,
    ssh::SshHandle,
};

/// Events fed into a running execution.
#[derive(Debug)]
pub enum InputEvent {
    Stdin(Vec<u8>),
    StdinEof,
    Signal(Signal),
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
    /// New persisted cwd when the wrapper marker was parsed.
    pub new_cwd: Option<String>,
    pub timed_out: bool,
}

/// How long to keep draining streams after the exit status arrived.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// Exit code used when the remote side closed without reporting a status.
const NO_STATUS_CODE: i32 = 255;

/// Exit code reported for timed-out commands, matching timeout(1), regardless
/// of how the remote side actually died (KILL would surface as 137).
const TIMEOUT_EXIT_CODE: i32 = 124;

/// Internal events produced by the channel reader task.
enum ChanEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(i32),
    ExitSignal(Sig, String),
    Eof,
    Close,
}

/// Run one wrapper script over the connection.
///
/// `input` receives stdin data / eof / signals; `output` receives forwarded
/// stdout/stderr chunks. Send errors on `output` (client gone) are ignored so
/// the remote side can still finish cleanly.
#[allow(clippy::too_many_lines)]
pub async fn execute(
    handle: &SshHandle,
    script_text: String,
    nonce_hex: &str,
    timeout: Option<Duration>,
    mut input: mpsc::Receiver<InputEvent>,
    output: mpsc::Sender<OutputEvent>,
) -> Result<ExecOutcome> {
    upload_script(handle, script_text, nonce_hex).await?;

    let path = script::remote_script_path(nonce_hex);
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| Error::Remote(format!("open exec channel: {e}")))?;
    channel
        .exec(false, format!("bash {path}"))
        .await
        .map_err(|e| Error::Remote(format!("request exec: {e}")))?;
    let (mut reader, writer) = channel.split();

    // Reader task owns wait() so the main loop can also select on input/timers.
    let (msg_tx, mut msg_rx) = mpsc::channel(64);
    let reader_task = tokio::spawn(async move {
        while let Some(msg) = reader.wait().await {
            let ev = match msg {
                ChannelMsg::Data { data } => ChanEvent::Stdout(data.to_vec()),
                ChannelMsg::ExtendedData { data, ext: 1 } => ChanEvent::Stderr(data.to_vec()),
                ChannelMsg::ExitStatus { exit_status } => {
                    ChanEvent::Exit(to_exit_code(exit_status))
                },
                ChannelMsg::ExitSignal {
                    signal_name,
                    error_message,
                    ..
                } => ChanEvent::ExitSignal(signal_name, error_message),
                ChannelMsg::Eof => ChanEvent::Eof,
                ChannelMsg::Close => ChanEvent::Close,
                _ => continue,
            };
            if msg_tx.send(ev).await.is_err() {
                break;
            }
        }
    });

    // Placeholder deadline used when a timer is disabled.
    let far = Instant::now() + Duration::from_secs(86_400 * 365);
    let mut marker_filter = MarkerFilter::new(nonce_hex);
    let mut exit: Option<i32> = None;
    let mut timed_out = false;
    let mut input_open = true;
    let mut drain_at: Option<Instant> = None;
    let mut pgid: Option<u32> = None;
    let deadline = timeout.map(|t| Instant::now() + t);

    loop {
        enum Sel {
            Msg(Option<ChanEvent>),
            In(Option<InputEvent>),
            Drain,
            Timeout,
        }
        let sel = tokio::select! {
            ev = msg_rx.recv() => Sel::Msg(ev),
            ev = input.recv(), if input_open => Sel::In(ev),
            () = tokio::time::sleep_until(drain_at.unwrap_or(far)), if drain_at.is_some() => Sel::Drain,
            () = tokio::time::sleep_until(deadline.unwrap_or(far)), if deadline.is_some() && !timed_out => Sel::Timeout,
        };
        match sel {
            // Connection closed without (or after) a status: nothing left to read.
            Sel::Msg(None | Some(ChanEvent::Close)) => {
                if exit.is_none() {
                    exit = Some(NO_STATUS_CODE);
                }
                break;
            },
            Sel::Msg(Some(ChanEvent::Stdout(d))) => {
                let passthrough = marker_filter.push(&d);
                if pgid.is_none() {
                    pgid = marker_filter.pgid();
                    if let Some(p) = pgid {
                        spdlog::info!("captured remote pgid={p}");
                    }
                }
                if !passthrough.is_empty() {
                    let _ = output.send(OutputEvent::Stdout(passthrough)).await;
                }
            },
            Sel::Msg(Some(ChanEvent::Stderr(d))) => {
                let _ = output.send(OutputEvent::Stderr(d)).await;
            },
            Sel::Msg(Some(ChanEvent::Exit(code))) => {
                exit = Some(code);
                drain_at = Some(Instant::now() + DRAIN_GRACE);
            },
            Sel::Msg(Some(ChanEvent::ExitSignal(sig, message))) => {
                if !message.is_empty() {
                    let _ = output.send(OutputEvent::Stderr(message.into_bytes())).await;
                }
                exit = Some(signal_exit_code(&sig));
                drain_at = Some(Instant::now() + DRAIN_GRACE);
            },
            Sel::Msg(Some(ChanEvent::Eof)) => {
                // No more data will come; stop early once the status arrived.
                if exit.is_some() {
                    break;
                }
            },
            Sel::In(Some(InputEvent::Stdin(d))) => {
                writer
                    .data_bytes(d)
                    .await
                    .map_err(|e| Error::Remote(format!("send stdin: {e}")))?;
            },
            Sel::In(Some(InputEvent::StdinEof)) => {
                let _ = writer.eof().await;
                // stdin is done, but signals may still arrive: only a closed
                // channel (`Sel::In(None)`) disables this branch.
            },
            Sel::In(Some(InputEvent::Signal(s))) => {
                let (sig, name) = signal_spec(s);
                if let Some(p) = pgid {
                    // SSH signal requests only reach the session leader,
                    // whose handling interactive bash defers: kill the whole
                    // process group through a dedicated channel instead.
                    kill_group(handle, p, name).await;
                } else {
                    let _ = writer.signal(sig).await;
                }
            },
            Sel::In(None) => input_open = false,
            Sel::Drain => break,
            Sel::Timeout => {
                timed_out = true;
                match pgid {
                    Some(p) => kill_group(handle, p, "KILL").await,
                    None => {
                        let _ = writer.signal(Sig::KILL).await;
                    },
                }
                drain_at = Some(Instant::now() + DRAIN_GRACE);
            },
        }
    }

    reader_task.abort();
    let _ = writer.close().await;

    let (leftover, new_cwd) = marker_filter.finish();
    if !leftover.is_empty() {
        let _ = output.send(OutputEvent::Stdout(leftover)).await;
    }

    Ok(ExecOutcome {
        exit_code: if timed_out {
            TIMEOUT_EXIT_CODE
        } else {
            exit.unwrap_or(NO_STATUS_CODE)
        },
        new_cwd,
        timed_out,
    })
}

/// Upload the wrapper script through a dedicated `cat > path` channel.
async fn upload_script(handle: &SshHandle, script_text: String, nonce_hex: &str) -> Result<()> {
    let path = script::remote_script_path(nonce_hex);
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
        .data(script_text.as_bytes())
        .await
        .map_err(|e| Error::Remote(format!("upload script: {e}")))?;
    writer
        .eof()
        .await
        .map_err(|e| Error::Remote(format!("finish upload: {e}")))?;

    let mut status: Option<i32> = None;
    while let Some(msg) = reader.wait().await {
        match msg {
            ChannelMsg::ExitStatus { exit_status } => status = Some(to_exit_code(exit_status)),
            ChannelMsg::Close => break,
            _ => {},
        }
    }
    let _ = writer.close().await;
    if status != Some(0) {
        return Err(Error::Remote(format!(
            "script upload failed (status={status:?}); is /tmp writable on the remote host?"
        )));
    }
    Ok(())
}

/// russh signal value plus the `kill(1)` name for the same signal.
fn signal_spec(s: Signal) -> (Sig, &'static str) {
    match s {
        Signal::Int => (Sig::INT, "INT"),
        Signal::Term => (Sig::TERM, "TERM"),
        Signal::Kill => (Sig::KILL, "KILL"),
        Signal::Hup => (Sig::HUP, "HUP"),
    }
}

/// Kill the remote process group through a dedicated exec channel. Failures
/// are logged but otherwise ignored: the command may already have exited.
async fn kill_group(handle: &SshHandle, pgid: u32, name: &str) {
    let Ok(mut channel) = handle.channel_open_session().await else {
        spdlog::warn!("group-kill: open channel failed");
        return;
    };
    // Diagnostics: rc of kill plus the group membership at signal time. The
    // command goes through bash explicitly: the login shell may be anything
    // (e.g. fish, which rejects `;`-chained POSIX syntax).
    let cmd = format!(
        "bash -c 'kill -{name} -{pgid}; echo kill_rc=$?; \
         ps -o pid,ppid,pgid,sid,comm -g {pgid} 2>&1'"
    );
    // want_reply=true: await the server's acceptance before reading/closing.
    if let Err(e) = channel.exec(true, cmd).await {
        spdlog::warn!("group-kill exec failed: {e}");
        return;
    }
    let mut out = Vec::new();
    let mut code: Option<u32> = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => out.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
            ChannelMsg::Close => break,
            _ => {},
        }
    }
    let _ = channel.close().await;
    let text = String::from_utf8_lossy(&out);
    let text = text.replace('\n', " | ");
    spdlog::info!("group-kill {name} -{pgid}: status={code:?} out={text}");
}

/// Map an SSH exit-signal to a shell-style 128+signum exit code.
fn signal_exit_code(sig: &Sig) -> i32 {
    let num = match sig {
        Sig::HUP => 1,
        Sig::INT => 2,
        Sig::QUIT => 3,
        Sig::ABRT => 6,
        Sig::KILL => 9,
        Sig::ALRM => 14,
        Sig::TERM => 15,
        _ => 0,
    };
    128 + num
}

/// SSH exit statuses are shell exit codes (0..=255); anything else is garbage.
fn to_exit_code(exit_status: u32) -> i32 {
    i32::try_from(exit_status).unwrap_or(NO_STATUS_CODE)
}
