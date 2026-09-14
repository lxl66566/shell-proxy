//! Validated session names: the daemon routes persisted cwd/state by
//! (host, session), giving parallel callers independent shell state on one
//! host.

use std::fmt;

/// Session used by requests that do not name one; behavior identical to the
/// pre-session single-state daemon.
pub const DEFAULT_NAME: &str = "default";

/// Longest allowed session name, in UTF-8 bytes.
pub const MAX_LEN: usize = 64;

/// Why [`SessionId::parse`] rejected a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionNameError {
    #[error("session name must not be empty")]
    Empty,
    #[error("session name is {len} bytes long, the limit is {MAX_LEN}")]
    TooLong { len: usize },
    #[error("session name contains {c:?}; allowed characters are A-Z a-z 0-9 . _ -")]
    BadChar { c: char },
}

/// A validated session name.
///
/// The charset keeps names safe as log tokens and map keys (no newlines, no
/// shell metacharacters); names never reach a remote command line or file
/// path. [`SessionId::parse`] is the only constructor, so every `SessionId`
/// in the process is known valid.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(String);

impl SessionId {
    /// Validate and wrap `s`.
    ///
    /// # Errors
    /// One of [`SessionNameError`]: empty, longer than [`MAX_LEN`] bytes, or
    /// containing a character outside `[A-Za-z0-9._-]`.
    pub fn parse(s: &str) -> Result<Self, SessionNameError> {
        if s.is_empty() {
            return Err(SessionNameError::Empty);
        }
        if s.len() > MAX_LEN {
            return Err(SessionNameError::TooLong { len: s.len() });
        }
        if let Some(c) = s.chars().find(|c| !is_allowed(*c)) {
            return Err(SessionNameError::BadChar { c });
        }
        Ok(Self(s.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SessionId {
    /// The fallback session ([`DEFAULT_NAME`]); its validity is pinned by a
    /// unit test.
    fn default() -> Self {
        Self(DEFAULT_NAME.to_owned())
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn is_allowed(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_names() {
        assert_eq!(SessionId::parse("default").unwrap().as_str(), DEFAULT_NAME);
        assert_eq!(SessionId::parse("agent-1").unwrap().as_str(), "agent-1");
        assert_eq!(SessionId::parse("a.b_c-d").unwrap().as_str(), "a.b_c-d");
        // boundary: exactly MAX_LEN bytes
        let long = "a".repeat(MAX_LEN);
        assert_eq!(SessionId::parse(&long).unwrap().as_str(), long);
    }

    #[test]
    fn rejects_invalid_names() {
        assert_eq!(SessionId::parse("").unwrap_err(), SessionNameError::Empty);
        assert_eq!(
            SessionId::parse(&"a".repeat(MAX_LEN + 1)).unwrap_err(),
            SessionNameError::TooLong { len: MAX_LEN + 1 }
        );
        assert_eq!(
            SessionId::parse("a b").unwrap_err(),
            SessionNameError::BadChar { c: ' ' }
        );
        assert_eq!(
            SessionId::parse("a/b").unwrap_err(),
            SessionNameError::BadChar { c: '/' }
        );
        // multibyte characters are outside the charset
        assert_eq!(
            SessionId::parse("会话").unwrap_err(),
            SessionNameError::BadChar { c: '会' }
        );
    }

    #[test]
    fn default_name_stays_valid() {
        // SessionId::default() bypasses parse; keep the constant honest.
        assert!(SessionId::parse(DEFAULT_NAME).is_ok());
        assert_eq!(SessionId::default().as_str(), DEFAULT_NAME);
    }
}
