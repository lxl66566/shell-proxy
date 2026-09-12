//! Streaming filter that strips the trailing cwd marker from remote stdout.
//!
//! The wrapper prints `\x1cSPM:<nonce>:<base64 cwd>\x1c` as the very last bytes
//! of stdout. stdout can be arbitrary binary and chunk boundaries can split the
//! marker, so the filter holds back only bytes that could still become part of
//! the marker and emits everything else immediately.

use base64_simd::STANDARD as B64;

use crate::script::MARKER_PREFIX;

/// Upper bound for the base64 cwd payload inside the marker.
const MAX_B64_LEN: usize = 8192;

/// Incremental stdout filter. Feed chunks with [`MarkerFilter::push`], then
/// finalize once with [`MarkerFilter::finish`].
#[derive(Debug)]
pub struct MarkerFilter {
    marker_start: Vec<u8>,
    pending: Vec<u8>,
    cwd: Option<String>,
    finished: bool,
}

impl MarkerFilter {
    #[must_use]
    pub fn new(nonce_hex: &str) -> Self {
        Self {
            marker_start: format!("{MARKER_PREFIX}{nonce_hex}:").into_bytes(),
            pending: Vec::new(),
            cwd: None,
            finished: false,
        }
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

            let m = self.marker_start.as_slice();
            if self.pending.len() < m.len() {
                if self.pending.as_slice() == &m[..self.pending.len()] {
                    return out; // partial marker prefix, hold back
                }
            } else if self.pending[..m.len()] != *m {
                // fall through: 0x1c is plain data
            } else {
                // Full prefix matched: scan the base64 body for the terminator.
                let body = &self.pending[m.len()..];
                match find_non_b64(body) {
                    Some(i) if body[i] == 0x1c => {
                        let b64 = &body[..i];
                        if b64.len() <= MAX_B64_LEN {
                            self.cwd = B64
                                .decode_to_vec(b64)
                                .ok()
                                .and_then(|v| String::from_utf8(v).ok());
                        }
                        // Bytes after the marker cannot legitimately exist; drop.
                        self.pending.clear();
                        self.finished = true;
                        return out;
                    },
                    Some(_) => { /* invalid base64 body: data, not a marker */ },
                    None => {
                        if body.len() <= MAX_B64_LEN {
                            return out; // open-ended candidate, hold back
                        }
                        // Over the bound: can never be a real marker.
                    },
                }
            }

            // The leading 0x1c is data: emit it and rescan from the next byte.
            out.push(self.pending.remove(0));
        }
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
    use crate::script::MARKER_SUFFIX;

    fn marker(nonce: &str, cwd: &str) -> Vec<u8> {
        let b64 = B64.encode_to_string(cwd.as_bytes());
        format!("{MARKER_PREFIX}{nonce}:{b64}{MARKER_SUFFIX}").into_bytes()
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
}
