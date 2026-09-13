//! Error types shared by the library.

use thiserror::Error;

/// Library result.
pub type Result<T> = std::result::Result<T, Error>;

/// Library error.
#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("config error: {0}")]
    Config(String),

    #[error("ssh config resolve failed for host {host:?}: {reason}")]
    Resolve { host: String, reason: String },

    #[error("host key verification failed: {0}")]
    HostKey(String),

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("connect failed: {0}")]
    Connect(String),

    #[error("remote exec failed: {0}")]
    Remote(String),

    #[error("ipc error: {0}")]
    Ipc(String),

    #[error("daemon not reachable: {0}")]
    Daemon(String),

    #[error("protocol error: {0}")]
    Protocol(String),
}

impl From<sp_proto::Error> for Error {
    fn from(e: sp_proto::Error) -> Self {
        match e {
            sp_proto::Error::Io(e) => Error::Io(e),
            sp_proto::Error::Json(e) => Error::Json(e),
            sp_proto::Error::Protocol(m) => Error::Protocol(m),
        }
    }
}

impl Error {
    /// Human oriented short reason, used by the CLI to print one-line errors.
    #[must_use]
    pub fn brief(&self) -> String {
        format!("{self}")
    }
}
