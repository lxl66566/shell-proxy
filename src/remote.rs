//! Remote side management: deploy `sp-serve` and run commands through it.
//!
//! One command = one SSH exec channel running `sp-serve`, speaking sp-proto
//! frames on its stdio. The serve binary is uploaded once per daemon
//! connection into `~/.local/share/shell-proxy/` (name carries version and
//! arch) and verified by sha256 before use. serve's own stderr arrives as SSH
//! extended data and is mirrored into the daemon log.

use russh::ChannelMsg;
use sha2::{Digest, Sha256};
use sp_proto::{EventDecoder, EventFrame, ExecFrame, ExecRequest, ExitReport, Signal};
use spdlog::prelude::*;
use tokio::sync::mpsc;

use crate::{
    embed::{self, Arch},
    error::{Error, Result},
    ssh::SshHandle,
};

/// Directory (relative to the remote home) holding deployed binaries.
const SERVE_DIR: &str = "~/.local/share/shell-proxy";

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
    /// New persisted cwd when the serve wrapper reported it.
    pub new_cwd: Option<String>,
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
    info!("deployed {path} ({} bytes)", bin.len());
    Ok(path)
}

/// Run one command through `sp-serve` over a fresh exec channel.
///
/// `input` receives stdin data / eof / signals; `output` receives forwarded
/// stdout/stderr chunks. Send errors on `output` (client gone) are ignored so
/// the remote side can still finish cleanly.
pub async fn execute(
    handle: &SshHandle,
    serve_path: &str,
    req: &ExecRequest,
    mut input: mpsc::Receiver<InputEvent>,
    output: mpsc::Sender<OutputEvent>,
) -> Result<ExecOutcome> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| Error::Remote(format!("open exec channel: {e}")))?;
    channel
        .exec(false, serve_path)
        .await
        .map_err(|e| Error::Remote(format!("request exec {serve_path}: {e}")))?;
    let (mut reader, writer) = channel.split();

    writer
        .data_bytes(sp_proto::encode_exec_frame(&ExecFrame::Exec(req.clone()))?)
        .await
        .map_err(|e| Error::Remote(format!("send Exec frame: {e}")))?;

    // Reader task owns wait() so the main loop can also select on input.
    let (msg_tx, mut msg_rx) = mpsc::channel(64);
    let reader_task = tokio::spawn(async move {
        while let Some(msg) = reader.wait().await {
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
    });

    let mut decoder = EventDecoder::new();
    let mut serve_log = ServeLog::default();
    let mut report: Option<ExitReport> = None;
    let mut serve_status: Option<u32> = None;
    let mut input_open = true;

    'outer: loop {
        enum Sel {
            In(Option<InputEvent>),
            Msg(Option<ChanEvent>),
        }
        let sel = tokio::select! {
            ev = input.recv(), if input_open => Sel::In(ev),
            ev = msg_rx.recv() => Sel::Msg(ev),
        };
        match sel {
            Sel::In(Some(InputEvent::Stdin(d))) => {
                send_frame(&writer, &ExecFrame::StdinData(d)).await?;
            },
            Sel::In(Some(InputEvent::StdinEof)) => {
                send_frame(&writer, &ExecFrame::StdinEof).await?;
            },
            Sel::In(Some(InputEvent::Signal(s))) => {
                send_frame(&writer, &ExecFrame::Signal(s)).await?;
            },
            Sel::In(None) => input_open = false,
            Sel::Msg(None | Some(ChanEvent::Closed)) => break,
            Sel::Msg(Some(ChanEvent::Data(bytes))) => {
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
            Sel::Msg(Some(ChanEvent::Log(bytes))) => serve_log.feed(&bytes),
            Sel::Msg(Some(ChanEvent::Status(s))) => serve_status = Some(s),
        }
    }

    reader_task.abort();
    serve_log.flush();
    let _ = writer.close().await;

    match report {
        Some(rep) => Ok(ExecOutcome {
            exit_code: rep.code,
            new_cwd: rep.cwd,
            timed_out: rep.timed_out,
        }),
        None => Err(Error::Remote(format!(
            "sp-serve closed the channel without an exit report (exit status {serve_status:?}); \
             see daemon log for its stderr"
        ))),
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
async fn remote_matches(handle: &SshHandle, path: &str, expected: &[u8]) -> Result<bool> {
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
