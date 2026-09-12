//! IPC between the `sp` client and the daemon.
//!
//! Transport is a windows named pipe / unix socket; messages are framed as
//! `[1-byte kind][u32 LE length][payload]`. Control payloads are JSON, stream
//! payloads are raw bytes.

use std::io::ErrorKind;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

/// Signals the client can forward to the remote process group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Signal {
    Int,
    Term,
    Kill,
    Hup,
}

impl Signal {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Signal::Int => "int",
            Signal::Term => "term",
            Signal::Kill => "kill",
            Signal::Hup => "hup",
        }
    }
}

/// Request for one remote execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    /// Host alias, resolved via the system ssh config by the daemon.
    pub host: String,
    /// Command text, executed verbatim by bash.
    pub command: String,
    /// Positional arguments ($1..) for the command.
    #[serde(default)]
    pub args: Vec<String>,
    /// Override starting cwd for this call; also becomes the new persisted cwd.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Kill the command after this many milliseconds; 0/None = unlimited.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

/// Final report of one execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitReport {
    pub code: i32,
    /// Persisted cwd after the command, when the wrapper reported it.
    pub cwd: Option<String>,
    /// Daemon-side failure before/while running (auth, connect, ...).
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub timed_out: bool,
}

/// Daemon liveness reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pong {
    pub pid: u32,
}

/// Frame kinds, client to daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClientKind {
    Exec = 1,
    StdinData = 2,
    StdinEof = 3,
    Signal = 4,
    Ping = 5,
}

/// Frame kinds, daemon to client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DaemonType {
    Stdout = 0x81,
    Stderr = 0x82,
    Exit = 0x83,
    Pong = 0x84,
}

impl TryFrom<u8> for ClientKind {
    type Error = Error;

    fn try_from(v: u8) -> std::result::Result<Self, Self::Error> {
        Ok(match v {
            1 => ClientKind::Exec,
            2 => ClientKind::StdinData,
            3 => ClientKind::StdinEof,
            4 => ClientKind::Signal,
            5 => ClientKind::Ping,
            _ => return Err(Error::Protocol(format!("bad client frame kind {v:#x}"))),
        })
    }
}

impl TryFrom<u8> for DaemonType {
    type Error = Error;

    fn try_from(v: u8) -> std::result::Result<Self, Self::Error> {
        Ok(match v {
            0x81 => DaemonType::Stdout,
            0x82 => DaemonType::Stderr,
            0x83 => DaemonType::Exit,
            0x84 => DaemonType::Pong,
            _ => return Err(Error::Protocol(format!("bad daemon frame kind {v:#x}"))),
        })
    }
}

/// One decoded frame.
#[derive(Debug, Clone)]
pub enum ClientFrame {
    Exec(ExecRequest),
    StdinData(Vec<u8>),
    StdinEof,
    Signal(Signal),
    Ping,
}

#[derive(Debug, Clone)]
pub enum DaemonFrame {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(ExitReport),
    Pong(Pong),
}

const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// Read one frame from a stream.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<DaemonFrame>> {
    read_frame_as(r, DaemonType::try_from, decode_daemon).await
}

/// Read one client frame from a stream.
pub async fn read_client_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<ClientFrame>> {
    read_frame_as(r, ClientKind::try_from, decode_client).await
}

async fn read_frame_as<R, K, F, T>(
    r: &mut R,
    kind_of: F,
    decode: fn(K, Vec<u8>) -> Result<T>,
) -> Result<Option<T>>
where
    R: AsyncRead + Unpin,
    F: Fn(u8) -> std::result::Result<K, Error>,
{
    let mut hdr = [0u8; 5];
    match r.read_exact(&mut hdr).await {
        Ok(_) => {},
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let kind = kind_of(hdr[0])?;
    let len = u32::from_le_bytes(hdr[1..5].try_into().expect("4 bytes")) as usize;
    if len > MAX_PAYLOAD {
        return Err(Error::Protocol(format!("frame too large: {len}")));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    decode(kind, payload).map(Some)
}

fn decode_client(kind: ClientKind, payload: Vec<u8>) -> Result<ClientFrame> {
    Ok(match kind {
        ClientKind::Exec => ClientFrame::Exec(json(&payload)?),
        ClientKind::StdinData => ClientFrame::StdinData(payload),
        ClientKind::StdinEof => ClientFrame::StdinEof,
        ClientKind::Signal => ClientFrame::Signal(json(&payload)?),
        ClientKind::Ping => ClientFrame::Ping,
    })
}

fn decode_daemon(kind: DaemonType, payload: Vec<u8>) -> Result<DaemonFrame> {
    Ok(match kind {
        DaemonType::Stdout => DaemonFrame::Stdout(payload),
        DaemonType::Stderr => DaemonFrame::Stderr(payload),
        DaemonType::Exit => DaemonFrame::Exit(json(&payload)?),
        DaemonType::Pong => DaemonFrame::Pong(json(&payload)?),
    })
}

fn json<T: for<'de> Deserialize<'de>>(payload: &[u8]) -> Result<T> {
    serde_json::from_slice(payload).map_err(|e| Error::Protocol(format!("bad frame payload: {e}")))
}

/// Write one client frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &ClientFrame) -> Result<()> {
    let (kind, payload): (u8, Vec<u8>) = match frame {
        ClientFrame::Exec(req) => (ClientKind::Exec as u8, serde_json::to_vec(req)?),
        ClientFrame::StdinData(d) => (ClientKind::StdinData as u8, d.clone()),
        ClientFrame::StdinEof => (ClientKind::StdinEof as u8, Vec::new()),
        ClientFrame::Signal(s) => (ClientKind::Signal as u8, serde_json::to_vec(s)?),
        ClientFrame::Ping => (ClientKind::Ping as u8, Vec::new()),
    };
    write_raw(w, kind, &payload).await
}

/// Write one daemon frame.
pub async fn write_daemon_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    frame: &DaemonFrame,
) -> Result<()> {
    let (kind, payload): (u8, Vec<u8>) = match frame {
        DaemonFrame::Stdout(d) => (DaemonType::Stdout as u8, d.clone()),
        DaemonFrame::Stderr(d) => (DaemonType::Stderr as u8, d.clone()),
        DaemonFrame::Exit(r) => (DaemonType::Exit as u8, serde_json::to_vec(r)?),
        DaemonFrame::Pong(p) => (DaemonType::Pong as u8, serde_json::to_vec(p)?),
    };
    write_raw(w, kind, &payload).await
}

async fn write_raw<W: AsyncWrite + Unpin>(w: &mut W, kind: u8, payload: &[u8]) -> Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| Error::Protocol(format!("frame too large: {}", payload.len())))?;
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.push(kind);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(payload);
    w.write_all(&buf).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_all_frames() {
        let frames = vec![
            ClientFrame::Exec(ExecRequest {
                host: "ls".into(),
                command: "echo 'a'".into(),
                args: vec!["x y".into()],
                cwd: Some("/tmp".into()),
                timeout_ms: Some(5000),
            }),
            ClientFrame::StdinData(vec![0, 255, 10]),
            ClientFrame::StdinEof,
            ClientFrame::Signal(Signal::Int),
            ClientFrame::Ping,
        ];
        let mut buf = Vec::new();
        for f in &frames {
            write_frame(&mut buf, f).await.unwrap();
        }
        let mut cur = std::io::Cursor::new(&buf);
        for f in &frames {
            let got = read_client_frame(&mut cur).await.unwrap().unwrap();
            match (f, &got) {
                (ClientFrame::Exec(a), ClientFrame::Exec(b)) => {
                    assert_eq!(a.command, b.command);
                    assert_eq!(a.timeout_ms, b.timeout_ms);
                },
                (ClientFrame::StdinData(a), ClientFrame::StdinData(b)) => assert_eq!(a, b),
                (ClientFrame::Signal(a), ClientFrame::Signal(b)) => assert_eq!(a, b),
                (ClientFrame::StdinEof, ClientFrame::StdinEof)
                | (ClientFrame::Ping, ClientFrame::Ping) => {},
                (a, b) => panic!("frame kind mismatch: {a:?} vs {b:?}"),
            }
        }
        assert!(read_client_frame(&mut cur).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn exit_report_roundtrip() {
        let f = DaemonFrame::Exit(ExitReport {
            code: 130,
            cwd: Some("/r".into()),
            error: None,
            timed_out: false,
        });
        let mut buf = Vec::new();
        write_daemon_frame(&mut buf, &f).await.unwrap();
        let mut cur = std::io::Cursor::new(&buf);
        match read_frame(&mut cur).await.unwrap().unwrap() {
            DaemonFrame::Exit(r) => {
                assert_eq!(r.code, 130);
                assert_eq!(r.cwd.as_deref(), Some("/r"));
            },
            _ => panic!("wrong frame"),
        }
    }
}
