//! Streaming filter that strips control messages from remote stdout.
//!
//! The wrapper prints `\x1cSPM:<nonce>:<base64 cwd>\x1c` as the very last bytes
//! of stdout and `\x1cSPPG:<nonce>:<pgid>\x1c` as the first bytes. stdout can be
//! arbitrary binary and chunk boundaries can split a message, so the filter
//! holds back only bytes that could still become part of a message and emits
//! everything else immediately.

use base64_simd::STANDARD as B64;

use crate::script::{MARKER_PREFIX, PGID_PREFIX};

/// Upper bound for the base64 cwd payload inside the marker.
const MAX_B64_LEN: usize = 8192;

/// Upper bound for the pgid payload inside the control message.
const MAX_PGID_LEN: usize = 16;

/// How a chunk starting with the control byte (0x1c) should be treated.
enum Class {
    /// Chunk fully matches a control message header.
    Header(Header),
    /// Chunk may still grow into a header: hold it back.
    Hold,
    /// Not a control message: plain data.
    Data,
}

enum Header {
    Cwd,
    Pgid,
}

fn classify(pending: &[u8], cwd_h: &[u8], pgid_h: &[u8]) -> Class {
    if pending.starts_with(cwd_h) {
        return Class::Header(Header::Cwd);
    }
    if pending.starts_with(pgid_h) {
        return Class::Header(Header::Pgid);
    }
    if cwd_h.starts_with(pending) || pgid_h.starts_with(pending) {
        return Class::Hold;
    }
    Class::Data
}

/// Incremental stdout filter. Feed chunks with [`MarkerFilter::push`], then
/// finalize once with [`MarkerFilter::finish`].
#[derive(Debug)]
pub struct MarkerFilter {
    cwd_marker_start: Vec<u8>,
    pgid_marker_start: Vec<u8>,
    pending: Vec<u8>,
    cwd: Option<String>,
    pgid: Option<u32>,
    finished: bool,
}

/// Outcome of scanning a control message body.
enum Scan {
    /// Message complete and consumed.
    Consumed,
    /// Body may still grow: hold the pending bytes back.
    Hold,
    /// Body invalid: the bytes are plain data.
    Data,
}

impl MarkerFilter {
    #[must_use]
    pub fn new(nonce_hex: &str) -> Self {
        Self {
            cwd_marker_start: format!("{MARKER_PREFIX}{nonce_hex}:").into_bytes(),
            pgid_marker_start: format!("{PGID_PREFIX}{nonce_hex}:").into_bytes(),
            pending: Vec::new(),
            cwd: None,
            pgid: None,
            finished: false,
        }
    }

    /// Process group id reported by the wrapper, once its message arrived.
    #[must_use]
    pub fn pgid(&self) -> Option<u32> {
        self.pgid
    }

    /// Feed one stdout chunk; returns the bytes safe to forward right now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.finished {
            return Vec::new();
        }
        self.pending.extend_from_slice(chunk);

        let mut out = Vec::new();
        loop {
            // Invariant: `pending` never starts with an already-inspected 0x1c.
            let Some(start) = find_byte(&self.pending, 0x1c) else {
                out.append(&mut self.pending);
                return out;
            };
            if start > 0 {
                out.extend(self.pending.drain(..start));
            }

            match classify(&self.pending, &self.cwd_marker_start, &self.pgid_marker_start) {
                Class::Hold => return out,
                Class::Header(Header::Cwd) => match self.scan_cwd_message() {
                    Scan::Consumed => {
                        // Bytes after the cwd marker cannot legitimately
                        // exist; drop.
                        self.pending.clear();
                        self.finished = true;
                        return out;
                    },
                    Scan::Hold => return out,
                    Scan::Data => {},
                },
                Class::Header(Header::Pgid) => match self.scan_pgid_message() {
                    Scan::Consumed => continue, // more data may follow
                    Scan::Hold => return out,
                    Scan::Data => {},
                },
                Class::Data => {},
            }

            // The leading 0x1c is data: emit it and rescan from the next byte.
            out.push(self.pending.remove(0));
        }
    }

    /// Scan the body after a full cwd-marker header: base64 payload up to the
    /// terminating 0x1c.
    fn scan_cwd_message(&mut self) -> Scan {
        let hlen = self.cwd_marker_start.len();
        let body = &self.pending[hlen..];
        let Some(i) = find_non_b64(body) else {
            return if body.len() <= MAX_B64_LEN {
                Scan::Hold // open-ended candidate
            } else {
                Scan::Data // over the bound: can never be a real marker
            };
        };
        if body[i] != 0x1c {
            return Scan::Data; // invalid base64 body: data, not a marker
        }
        let b64 = &body[..i];
        if b64.len() <= MAX_B64_LEN {
            self.cwd = B64
                .decode_to_vec(b64)
                .ok()
                .and_then(|v| String::from_utf8(v).ok());
        }
        Scan::Consumed
    }

    /// Scan the body after a full pgid-message header: decimal payload up to
    /// the terminating 0x1c. On success the whole message is consumed.
    fn scan_pgid_message(&mut self) -> Scan {
        let hlen = self.pgid_marker_start.len();
        let body = &self.pending[hlen..];
        let Some(term) = body.iter().position(|&b| b == 0x1c || !b.is_ascii_digit()) else {
            return if body.len() <= MAX_PGID_LEN {
                Scan::Hold
            } else {
                Scan::Data
            };
        };
        if body[term] != 0x1c {
            return Scan::Data; // non-digit before the terminator: not ours
        }
        let digits = &body[..term];
        if digits.len() <= MAX_PGID_LEN {
            self.pgid = std::str::from_utf8(digits)
                .ok()
                .and_then(|s| s.parse().ok());
        }
        self.pending.drain(..=hlen + term);
        Scan::Consumed
    }

    /// Finalize the stream: returns leftover data plus the parsed cwd.
    #[must_use]
    pub fn finish(mut self) -> (Vec<u8>, Option<String>) {
        if self.finished {
            return (Vec::new(), self.cwd);
        }
        let leftover = std::mem::take(&mut self.pending);
        (leftover, None)
    }
}

fn find_byte(haystack: &[u8], needle: u8) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

/// Index of the first byte that is not in the standard base64 alphabet.
fn find_non_b64(bytes: &[u8]) -> Option<usize> {
    const fn is_b64(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
    }
    bytes.iter().position(|&b| !is_b64(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::{MARKER_SUFFIX, PGID_PREFIX};

    fn marker(nonce: &str, cwd: &str) -> Vec<u8> {
        let b64 = B64.encode_to_string(cwd.as_bytes());
        format!("{MARKER_PREFIX}{nonce}:{b64}{MARKER_SUFFIX}").into_bytes()
    }

    fn pgid_msg(nonce: &str, pgid: u32) -> Vec<u8> {
        format!("{PGID_PREFIX}{nonce}:{pgid}{MARKER_SUFFIX}").into_bytes()
    }

    #[test]
    fn passes_plain_data_through() {
        let mut f = MarkerFilter::new("n");
        assert_eq!(f.push(b"hello"), b"hello");
        let (rest, cwd) = f.finish();
        assert_eq!(rest, b"");
        assert!(cwd.is_none());
    }

    #[test]
    fn strips_marker_at_end() {
        let mut f = MarkerFilter::new("n");
        let mut data = b"hi".to_vec();
        data.extend(marker("n", "/tmp"));
        assert_eq!(f.push(&data), b"hi");
        let (rest, cwd) = f.finish();
        assert_eq!(rest, b"");
        assert_eq!(cwd.as_deref(), Some("/tmp"));
    }

    #[test]
    fn marker_split_across_chunks() {
        let m = marker("n", "/var/log");
        let mut f = MarkerFilter::new("n");
        assert_eq!(f.push(b"abc"), b"abc");
        assert_eq!(f.push(&m[..5]), b"");
        assert_eq!(f.push(&m[5..]), b"");
        let (rest, cwd) = f.finish();
        assert_eq!(rest, b"");
        assert_eq!(cwd.as_deref(), Some("/var/log"));
    }

    #[test]
    fn data_that_looks_like_partial_marker_is_kept() {
        let mut f = MarkerFilter::new("n");
        assert_eq!(f.push(b"data\x1cSPM:n"), b"data");
        // '!' is neither base64 nor the terminator: the held prefix is data.
        assert_eq!(f.push(b":more!"), b"\x1cSPM:n:more!");
        let (rest, cwd) = f.finish();
        assert_eq!(rest, b"");
        assert!(cwd.is_none());
    }

    #[test]
    fn different_nonce_marker_is_data() {
        let mut f = MarkerFilter::new("n1");
        let mut data = b"out".to_vec();
        let foreign = marker("othernonce", "/x");
        data.extend_from_slice(&foreign);
        // Everything except the trailing 0x1c (a possible partial prefix) is
        // emitted immediately; finish() flushes the held terminator.
        let mut expected = b"out".to_vec();
        expected.extend_from_slice(&foreign[..foreign.len() - 1]);
        assert_eq!(f.push(&data), expected);
        let (rest, cwd) = f.finish();
        assert_eq!(rest, b"\x1c");
        assert!(cwd.is_none());
    }

    #[test]
    fn binary_data_with_0x1c_passes_through() {
        let mut f = MarkerFilter::new("n");
        let data: Vec<u8> = vec![0, 0x1c, 255, 0x1c, 0];
        assert_eq!(f.push(&data), data);
        let (rest, cwd) = f.finish();
        assert_eq!(rest, b"");
        assert!(cwd.is_none());
    }

    #[test]
    fn long_base64_looking_run_is_not_held_forever() {
        let mut f = MarkerFilter::new("n");
        let mut chunk = b"\x1cSPM:n:".to_vec();
        chunk.extend(std::iter::repeat_n(b'A', MAX_B64_LEN + 100));
        let out = f.push(&chunk);
        assert_eq!(out.len(), chunk.len());
        let (rest, cwd) = f.finish();
        assert_eq!(rest, b"");
        assert!(cwd.is_none());
    }

    #[test]
    fn data_after_marker_is_dropped() {
        let mut f = MarkerFilter::new("n");
        let mut data = b"ok".to_vec();
        data.extend(marker("n", "/root"));
        data.extend(b"junk");
        assert_eq!(f.push(&data), b"ok");
        assert_eq!(f.push(b"more"), b"");
        let (rest, cwd) = f.finish();
        assert_eq!(rest, b"");
        assert_eq!(cwd.as_deref(), Some("/root"));
    }

    #[test]
    fn extracts_pgid_and_forwards_surroundings() {
        let mut f = MarkerFilter::new("n");
        let mut data = b"pre".to_vec();
        data.extend(pgid_msg("n", 1234));
        data.extend_from_slice(b"post");
        assert_eq!(f.push(&data), b"prepost");
        assert_eq!(f.pgid(), Some(1234));
        let (rest, cwd) = f.finish();
        assert_eq!(rest, b"");
        assert!(cwd.is_none());
    }

    #[test]
    fn pgid_split_across_chunks() {
        let m = pgid_msg("n", 42);
        let mut f = MarkerFilter::new("n");
        assert_eq!(f.push(&m[..7]), b"");
        assert_eq!(f.pgid(), None);
        assert_eq!(f.push(&m[7..]), b"");
        assert_eq!(f.pgid(), Some(42));
    }

    #[test]
    fn pgid_with_foreign_nonce_is_data() {
        let mut f = MarkerFilter::new("n1");
        let msg = pgid_msg("other", 7);
        let mut data = b"x".to_vec();
        data.extend(&msg);
        // everything is emitted except the trailing 0x1c, which stays held as
        // a possible partial header
        let mut expected = b"x".to_vec();
        expected.extend_from_slice(&msg[..msg.len() - 1]);
        assert_eq!(f.push(&data), expected);
        assert_eq!(f.pgid(), None);
        let (rest, _) = f.finish();
        assert_eq!(rest, b"\x1c");
    }
}
