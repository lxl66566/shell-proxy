//! Wire protocol shared by both hops of shell-proxy:
//!
//! - `sp` CLI / MCP client <-> local daemon (named pipe / unix socket)
//! - local daemon <-> remote `sp-serve` (SSH channel stdio)
//!
//! Framing: `[1-byte kind][u32 LE length][payload]`. Control payloads are JSON,
//! stream payloads are raw bytes. [`ExecFrame`] flows from the initiator,
//! [`EventFrame`] flows back.

use std::io::ErrorKind;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Protocol error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("protocol error: {0}")]
    Protocol(String),
}

/// Protocol result.
pub type Result<T> = std::result::Result<T, Error>;

/// Exit code for daemon/serve-side failures before/around the command
/// (connect, auth, deploy, spawn). Shared by every hop.
pub const INTERNAL_ERROR_CODE: i32 = 254;

/// Exit code for timed-out commands, matching timeout(1).
pub const TIMEOUT_EXIT_CODE: i32 = 124;

/// Longest char-boundary-safe prefix of `s` within `max_bytes` bytes.
///
/// Plain slicing (`&s[..max]`) panics when the cut lands inside a multibyte
/// char; log truncation must never kill a process.
#[must_use]
pub fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Signals the initiator can forward to the remote process group.
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

    /// The libc signal number, unix only.
    #[cfg(unix)]
    #[must_use]
    pub fn as_raw(self) -> i32 {
        match self {
            Signal::Int => libc::SIGINT,
            Signal::Term => libc::SIGTERM,
            Signal::Kill => libc::SIGKILL,
            Signal::Hup => libc::SIGHUP,
        }
    }
}

/// Request for one remote execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    /// Host alias, resolved via the system ssh config by the daemon. Unused by
    /// `sp-serve` (the daemon picks the host).
    pub host: String,
    /// Command text, executed verbatim by bash.
    pub command: String,
    /// Positional arguments ($1..) for the command.
    #[serde(default)]
    pub args: Vec<String>,
    /// Starting cwd for this call; `sp-serve` cds there before running.
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
    /// cwd after the command, when the wrapper reported it.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Daemon/serve-side failure before/while running (auth, connect, ...).
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub timed_out: bool,
}

/// Liveness reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pong {
    pub pid: u32,
}

/// Frame kinds, initiator to responder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExecKind {
    Exec = 1,
    StdinData = 2,
    StdinEof = 3,
    Signal = 4,
    Ping = 5,
}

/// Frame kinds, responder to initiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventKind {
    Stdout = 0x81,
    Stderr = 0x82,
    Exit = 0x83,
    Pong = 0x84,
}

impl TryFrom<u8> for ExecKind {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self> {
        Ok(match v {
            1 => ExecKind::Exec,
            2 => ExecKind::StdinData,
            3 => ExecKind::StdinEof,
            4 => ExecKind::Signal,
            5 => ExecKind::Ping,
            _ => return Err(Error::Protocol(format!("bad exec frame kind {v:#x}"))),
        })
    }
}

impl TryFrom<u8> for EventKind {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self> {
        Ok(match v {
            0x81 => EventKind::Stdout,
            0x82 => EventKind::Stderr,
            0x83 => EventKind::Exit,
            0x84 => EventKind::Pong,
            _ => return Err(Error::Protocol(format!("bad event frame kind {v:#x}"))),
        })
    }
}

/// One decoded initiator frame.
#[derive(Debug, Clone)]
pub enum ExecFrame {
    Exec(ExecRequest),
    StdinData(Vec<u8>),
    StdinEof,
    Signal(Signal),
    Ping,
}

/// One decoded responder frame.
#[derive(Debug, Clone)]
pub enum EventFrame {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(ExitReport),
    Pong(Pong),
}

const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// Read one initiator frame from a stream; `None` on clean EOF.
pub async fn read_exec_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<ExecFrame>> {
    read_frame_as(r, ExecKind::try_from, decode_exec).await
}

/// Read one responder frame from a stream; `None` on clean EOF.
pub async fn read_event_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<EventFrame>> {
    read_frame_as(r, EventKind::try_from, decode_event).await
}

async fn read_frame_as<R, K, F, T>(
    r: &mut R,
    kind_of: F,
    decode: fn(K, Vec<u8>) -> Result<T>,
) -> Result<Option<T>>
where
    R: AsyncRead + Unpin,
    F: Fn(u8) -> Result<K>,
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

/// Incremental decoder for a responder frame stream arriving as byte chunks
/// (SSH channel data). Feed chunks with [`EventDecoder::push`].
#[derive(Default)]
pub struct EventDecoder {
    buf: Vec<u8>,
}

impl EventDecoder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one chunk; returns every frame that became complete.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<EventFrame>> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 5 {
                break;
            }
            let len = u32::from_le_bytes(self.buf[1..5].try_into().expect("4 bytes")) as usize;
            if len > MAX_PAYLOAD {
                return Err(Error::Protocol(format!("frame too large: {len}")));
            }
            if self.buf.len() < 5 + len {
                break;
            }
            let kind = EventKind::try_from(self.buf[0])?;
            let payload = self.buf[5..5 + len].to_vec();
            self.buf.drain(..5 + len);
            out.push(decode_event(kind, payload)?);
        }
        Ok(out)
    }
}

fn decode_exec(kind: ExecKind, payload: Vec<u8>) -> Result<ExecFrame> {
    Ok(match kind {
        ExecKind::Exec => ExecFrame::Exec(json(&payload)?),
        ExecKind::StdinData => ExecFrame::StdinData(payload),
        ExecKind::StdinEof => ExecFrame::StdinEof,
        ExecKind::Signal => ExecFrame::Signal(json(&payload)?),
        ExecKind::Ping => ExecFrame::Ping,
    })
}

fn decode_event(kind: EventKind, payload: Vec<u8>) -> Result<EventFrame> {
    Ok(match kind {
        EventKind::Stdout => EventFrame::Stdout(payload),
        EventKind::Stderr => EventFrame::Stderr(payload),
        EventKind::Exit => EventFrame::Exit(json(&payload)?),
        EventKind::Pong => EventFrame::Pong(json(&payload)?),
    })
}

fn json<T: for<'de> Deserialize<'de>>(payload: &[u8]) -> Result<T> {
    serde_json::from_slice(payload).map_err(|e| Error::Protocol(format!("bad frame payload: {e}")))
}

/// Encode one initiator frame to wire bytes.
pub fn encode_exec_frame(frame: &ExecFrame) -> Result<Vec<u8>> {
    let (kind, payload): (u8, Vec<u8>) = match frame {
        ExecFrame::Exec(req) => (ExecKind::Exec as u8, serde_json::to_vec(req)?),
        ExecFrame::StdinData(d) => (ExecKind::StdinData as u8, d.clone()),
        ExecFrame::StdinEof => (ExecKind::StdinEof as u8, Vec::new()),
        ExecFrame::Signal(s) => (ExecKind::Signal as u8, serde_json::to_vec(s)?),
        ExecFrame::Ping => (ExecKind::Ping as u8, Vec::new()),
    };
    encode_raw(kind, &payload)
}

/// Encode one responder frame to wire bytes.
pub fn encode_event_frame(frame: &EventFrame) -> Result<Vec<u8>> {
    let (kind, payload): (u8, Vec<u8>) = match frame {
        EventFrame::Stdout(d) => (EventKind::Stdout as u8, d.clone()),
        EventFrame::Stderr(d) => (EventKind::Stderr as u8, d.clone()),
        EventFrame::Exit(r) => (EventKind::Exit as u8, serde_json::to_vec(r)?),
        EventFrame::Pong(p) => (EventKind::Pong as u8, serde_json::to_vec(p)?),
    };
    encode_raw(kind, &payload)
}

fn encode_raw(kind: u8, payload: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(payload.len())
        .map_err(|_| Error::Protocol(format!("frame too large: {}", payload.len())))?;
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.push(kind);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(payload);
    Ok(buf)
}

/// Write one initiator frame.
pub async fn write_exec_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &ExecFrame) -> Result<()> {
    w.write_all(&encode_exec_frame(frame)?).await?;
    Ok(())
}

/// Write one responder frame.
pub async fn write_event_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &EventFrame) -> Result<()> {
    w.write_all(&encode_event_frame(frame)?).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_all_frames() {
        let frames = vec![
            ExecFrame::Exec(ExecRequest {
                host: "ls".into(),
                command: "echo 'a'".into(),
                args: vec!["x y".into()],
                cwd: Some("/tmp".into()),
                timeout_ms: Some(5000),
            }),
            ExecFrame::StdinData(vec![0, 255, 10]),
            ExecFrame::StdinEof,
            ExecFrame::Signal(Signal::Int),
            ExecFrame::Ping,
        ];
        let mut buf = Vec::new();
        for f in &frames {
            write_exec_frame(&mut buf, f).await.unwrap();
        }
        let mut cur = std::io::Cursor::new(&buf);
        for f in &frames {
            let got = read_exec_frame(&mut cur).await.unwrap().unwrap();
            match (f, &got) {
                (ExecFrame::Exec(a), ExecFrame::Exec(b)) => {
                    assert_eq!(a.command, b.command);
                    assert_eq!(a.timeout_ms, b.timeout_ms);
                },
                (ExecFrame::StdinData(a), ExecFrame::StdinData(b)) => assert_eq!(a, b),
                (ExecFrame::Signal(a), ExecFrame::Signal(b)) => assert_eq!(a, b),
                (ExecFrame::StdinEof, ExecFrame::StdinEof) | (ExecFrame::Ping, ExecFrame::Ping) => {
                },
                (a, b) => panic!("frame kind mismatch: {a:?} vs {b:?}"),
            }
        }
        assert!(read_exec_frame(&mut cur).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn exit_report_roundtrip() {
        let f = EventFrame::Exit(ExitReport {
            code: 130,
            cwd: Some("/r".into()),
            error: None,
            timed_out: false,
        });
        let mut buf = Vec::new();
        write_event_frame(&mut buf, &f).await.unwrap();
        let mut cur = std::io::Cursor::new(&buf);
        match read_event_frame(&mut cur).await.unwrap().unwrap() {
            EventFrame::Exit(r) => {
                assert_eq!(r.code, 130);
                assert_eq!(r.cwd.as_deref(), Some("/r"));
            },
            _ => panic!("wrong frame"),
        }
    }

    #[test]
    fn decoder_handles_split_and_joined_frames() {
        let a = encode_event_frame(&EventFrame::Stdout(b"hello".to_vec())).unwrap();
        let b = encode_event_frame(&EventFrame::Stderr(b"world".to_vec())).unwrap();
        let mut wire = a.clone();
        wire.extend_from_slice(&b);

        let mut dec = EventDecoder::new();
        // byte-by-byte: every split point must work
        let mut frames = Vec::new();
        for byte in &wire {
            frames.extend(dec.push(&[*byte]).unwrap());
        }
        assert_eq!(frames.len(), 2);
        match (&frames[0], &frames[1]) {
            (EventFrame::Stdout(x), EventFrame::Stderr(y)) => {
                assert_eq!(x, b"hello");
                assert_eq!(y, b"world");
            },
            _ => panic!("wrong frames"),
        }
    }

    #[test]
    fn decoder_rejects_oversized_frames() {
        let mut dec = EventDecoder::new();
        let mut hdr = vec![0x81];
        let too_large = u32::try_from(MAX_PAYLOAD).unwrap() + 1;
        hdr.extend_from_slice(&too_large.to_le_bytes());
        assert!(dec.push(&hdr).is_err());
    }

    #[test]
    fn truncate_utf8_cuts_on_char_boundaries() {
        // 2 ASCII + one 3-byte char; max lands inside the multibyte char.
        let s = "ab你cd";
        assert_eq!(truncate_utf8(s, 10), s);
        assert_eq!(truncate_utf8(s, 4), "ab"); // byte 4 is mid-char, falls back to 2
        assert_eq!(truncate_utf8(s, 5), "ab你");
        assert_eq!(truncate_utf8(s, 0), "");
        assert_eq!(truncate_utf8("abc", 3), "abc");
    }

    #[test]
    fn exit_codes_fit_u8() {
        assert!(u8::try_from(INTERNAL_ERROR_CODE).is_ok());
        assert!(u8::try_from(TIMEOUT_EXIT_CODE).is_ok());
    }
}
