//! Wire protocol shared by both hops of shell-proxy:
//!
//! - `sp` CLI / MCP client <-> local daemon (named pipe / unix socket)
//! - local daemon <-> remote `sp-serve` (SSH channel stdio)
//!
//! Framing: `[1-byte kind][u32 LE length][payload]`. Control payloads are JSON,
//! stream payloads are raw bytes. [`ExecFrame`] flows from the initiator,
//! [`EventFrame`] flows back.

use bytes::{Buf, BytesMut};
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
    /// Persisted shell state (vars/functions/aliases/options) as bash source,
    /// eval'd after the bashrc and the cd, before the command. Daemon-owned;
    /// same lifecycle as `cwd`.
    #[serde(default)]
    pub state: Option<String>,
    /// Kill the command after this many milliseconds; 0/None = unlimited.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Session name: the daemon routes persisted cwd/state by (host, session).
    /// `None` means the default session. Ignored by `sp-serve`.
    #[serde(default)]
    pub session: Option<String>,
}

/// Final report of one execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitReport {
    pub code: i32,
    /// cwd after the command, when the wrapper reported it.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Shell state dump after the command, when the wrapper reported one.
    /// `None` means "no update" (command exec'ed away, was killed, or the dump
    /// exceeded the size cap); the caller keeps the previous state.
    #[serde(default)]
    pub state: Option<String>,
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
///
/// EOF is clean only at a frame boundary; a connection closed inside a header
/// or payload surfaces as [`Error::Protocol`] instead of a bare io EOF, so a
/// peer dying mid-frame is not mistaken for a normal shutdown.
pub async fn read_exec_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<ExecFrame>> {
    read_frame_as(r, ExecKind::try_from, decode_exec).await
}

/// Read one responder frame from a stream; `None` on clean EOF.
///
/// See [`read_exec_frame`] for the mid-frame EOF semantics.
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
    // Byte-counted header read: only zero bytes at the frame start is a clean
    // EOF. read_exact would collapse a 4-of-5-byte header into the same
    // UnexpectedEof, silently losing a truncated frame.
    let mut hdr = [0u8; 5];
    let mut filled = 0;
    while filled < 5 {
        let n = r.read(&mut hdr[filled..]).await?;
        if n == 0 {
            if filled == 0 {
                return Ok(None);
            }
            return Err(Error::Protocol(format!(
                "connection closed mid-frame: partial header ({filled}/5 bytes)"
            )));
        }
        filled += n;
    }
    let kind = kind_of(hdr[0])?;
    let len = u32::from_le_bytes(hdr[1..5].try_into().expect("4 bytes")) as usize;
    if len > MAX_PAYLOAD {
        return Err(Error::Protocol(format!("frame too large: {len}")));
    }
    let mut payload = Vec::with_capacity(len);
    while payload.len() < len {
        // read_buf fills the reserved capacity directly: no zero-init pass.
        let n = r.read_buf(&mut payload).await?;
        if n == 0 {
            return Err(Error::Protocol(format!(
                "connection closed mid-frame: partial payload ({}/{len} bytes)",
                payload.len()
            )));
        }
    }
    decode(kind, payload).map(Some)
}

/// Buffer capacity kept across pushes once fully consumed; anything larger
/// (a max-size frame passed through) is released. Comfortably above the
/// ~32 KiB chunks the SSH hop delivers, so steady-state decoding never
/// re-allocates.
const KEEP_CAPACITY: usize = 256 * 1024;

/// Incremental decoder for a responder frame stream arriving as byte chunks
/// (SSH channel data). Feed chunks with [`EventDecoder::push`].
#[derive(Default)]
pub struct EventDecoder {
    buf: BytesMut,
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
            // advance consumes in O(1); drain would memmove the remainder.
            self.buf.advance(5 + len);
            out.push(decode_event(kind, payload)?);
        }
        if self.buf.is_empty() && self.buf.capacity() > KEEP_CAPACITY {
            self.buf = BytesMut::new();
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
    let hdr = frame_header(kind, payload.len())?;
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.extend_from_slice(&hdr);
    buf.extend_from_slice(payload);
    Ok(buf)
}

/// Header for one frame: `[kind][u32 LE len]`.
fn frame_header(kind: u8, len: usize) -> Result<[u8; 5]> {
    let len = u32::try_from(len).map_err(|_| Error::Protocol(format!("frame too large: {len}")))?;
    let mut hdr = [0u8; 5];
    hdr[0] = kind;
    hdr[1..5].copy_from_slice(&len.to_le_bytes());
    Ok(hdr)
}

/// Raw payloads below this size are packed into one contiguous buffer; copying
/// a few KiB costs less than the second write syscall that a split write adds.
/// Larger payloads are written as header + payload with no copy.
const PACKED_PAYLOAD_MAX: usize = 8 * 1024;

/// Write one initiator frame.
///
/// Large raw payloads ([`ExecFrame::StdinData`]) are written directly from
/// `frame` as two writes (header, then payload) instead of being copied into
/// one buffer. This requires an exclusive writer per stream: the two writes
/// must not interleave with another frame's. Every write path of this
/// protocol is an exclusive task by design.
pub async fn write_exec_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &ExecFrame) -> Result<()> {
    match frame {
        ExecFrame::StdinData(d) if d.len() >= PACKED_PAYLOAD_MAX => {
            write_raw(w, ExecKind::StdinData as u8, d).await
        },
        _ => {
            w.write_all(&encode_exec_frame(frame)?).await?;
            Ok(())
        },
    }
}

/// Write one responder frame.
///
/// Large raw payloads ([`EventFrame::Stdout`], [`EventFrame::Stderr`]) are
/// written directly from `frame` as two writes (header, then payload) instead
/// of being copied into one buffer. This requires an exclusive writer per
/// stream: the two writes must not interleave with another frame's. Every
/// write path of this protocol is an exclusive task by design.
pub async fn write_event_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &EventFrame) -> Result<()> {
    match frame {
        EventFrame::Stdout(d) if d.len() >= PACKED_PAYLOAD_MAX => {
            write_raw(w, EventKind::Stdout as u8, d).await
        },
        EventFrame::Stderr(d) if d.len() >= PACKED_PAYLOAD_MAX => {
            write_raw(w, EventKind::Stderr as u8, d).await
        },
        _ => {
            w.write_all(&encode_event_frame(frame)?).await?;
            Ok(())
        },
    }
}

/// Copy-free frame write: header and payload as two writes.
async fn write_raw<W: AsyncWrite + Unpin>(w: &mut W, kind: u8, payload: &[u8]) -> Result<()> {
    let hdr = frame_header(kind, payload.len())?;
    w.write_all(&hdr).await?;
    w.write_all(payload).await?;
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
                state: Some("declare -- x=1".into()),
                timeout_ms: Some(5000),
                session: Some("agent-a".into()),
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
                    assert_eq!(a.state, b.state);
                    assert_eq!(a.timeout_ms, b.timeout_ms);
                    assert_eq!(a.session, b.session);
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
            state: Some("declare -- x=1".into()),
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
                assert_eq!(r.state.as_deref(), Some("declare -- x=1"));
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

    #[tokio::test]
    async fn eof_mid_frame_is_a_protocol_error_not_clean_eof() {
        let wire = encode_event_frame(&EventFrame::Stdout(vec![7; 10])).unwrap();

        // EOF before any header byte: clean end of stream.
        let mut cur = std::io::Cursor::new(Vec::new());
        assert!(read_event_frame(&mut cur).await.unwrap().is_none());

        // Truncation at every point inside the frame must be a protocol error
        // naming the mid-frame close, never a clean EOF or a bare io error.
        for take in 1..wire.len() {
            let mut cur = std::io::Cursor::new(&wire[..take]);
            match read_event_frame(&mut cur).await {
                Err(Error::Protocol(msg)) => assert!(msg.contains("mid-frame"), "{msg}"),
                other => panic!("expected protocol error at {take} bytes, got {other:?}"),
            }
        }

        // Full frame then EOF stays clean.
        let mut cur = std::io::Cursor::new(&wire);
        assert!(read_event_frame(&mut cur).await.unwrap().is_some());
        assert!(read_event_frame(&mut cur).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn large_payloads_take_the_split_write_path() {
        // Above the threshold: written as header + payload writes, yet the
        // wire bytes must equal the packed encoding.
        let payload: Vec<u8> = (0..=PACKED_PAYLOAD_MAX)
            .map(|i| u8::try_from(i % 251).expect("fits in u8"))
            .collect();

        let ev = EventFrame::Stdout(payload.clone());
        let mut buf = Vec::new();
        write_event_frame(&mut buf, &ev).await.unwrap();
        assert_eq!(buf, encode_event_frame(&ev).unwrap());
        let mut cur = std::io::Cursor::new(&buf);
        match read_event_frame(&mut cur).await.unwrap().unwrap() {
            EventFrame::Stdout(d) => assert_eq!(d, payload),
            _ => panic!("wrong frame"),
        }

        let ex = ExecFrame::StdinData(payload);
        let mut buf = Vec::new();
        write_exec_frame(&mut buf, &ex).await.unwrap();
        assert_eq!(buf, encode_exec_frame(&ex).unwrap());
        let mut cur = std::io::Cursor::new(&buf);
        match read_exec_frame(&mut cur).await.unwrap().unwrap() {
            ExecFrame::StdinData(d) => assert_eq!(d.len(), PACKED_PAYLOAD_MAX + 1),
            _ => panic!("wrong frame"),
        }
    }

    #[test]
    fn exec_request_without_session_field_is_none() {
        // Wire compat: old clients never send `session`.
        let req: ExecRequest = serde_json::from_str(r#"{"host":"ls","command":"true"}"#).unwrap();
        assert_eq!(req.session, None);
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
