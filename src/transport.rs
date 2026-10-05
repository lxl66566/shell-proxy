//! Platform IPC endpoint: named pipe on Windows, unix socket elsewhere.

use std::time::Duration;

use spdlog::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite};

/// Pause between accept retries. Accept runs in the resident daemon, where a
/// propagated failure would end the process and lose every host connection
/// and session, so accept-stage errors are logged and retried instead.
/// Endpoint-level failures were already surfaced by [`bind`].
const ACCEPT_RETRY_BACKOFF: Duration = Duration::from_millis(250);

/// Anything that can serve as an IPC stream.
pub trait IpcIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> IpcIo for T {}

/// A connected IPC stream, client or server side.
pub struct IpcStream(Box<dyn IpcIo>);

impl AsyncRead for IpcStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for IpcStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

/// Platform listener.
pub enum IpcListener {
    #[cfg(windows)]
    NamedPipe {
        server: tokio::net::windows::named_pipe::NamedPipeServer,
        path: String,
    },
    #[cfg(unix)]
    Unix {
        listener: tokio::net::UnixListener,
        path: String,
    },
}

/// Bind the daemon endpoint. Fails if another daemon owns it.
pub fn bind(path: &str) -> std::io::Result<IpcListener> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let listener = tokio::net::UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(IpcListener::Unix {
            listener,
            path: path.to_owned(),
        })
    }
    #[cfg(windows)]
    {
        let server = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(path)?;
        Ok(IpcListener::NamedPipe {
            server,
            path: path.to_owned(),
        })
    }
}

impl IpcListener {
    /// Accept the next connection.
    ///
    /// Runs in the resident daemon: every accept-stage error (a client that
    /// broke the pipe handshake, transient resource pressure) is treated as
    /// transient, logged and retried; only [`bind`] reports endpoint-level
    /// failures such as another daemon owning the pipe.
    pub async fn accept(&mut self) -> std::io::Result<IpcStream> {
        match self {
            #[cfg(unix)]
            IpcListener::Unix { listener, path } => loop {
                match listener.accept().await {
                    Ok((stream, _)) => return Ok(IpcStream(Box::new(stream))),
                    // The listener stays valid after a failed accept (aborted
                    // connection, transient resource pressure).
                    Err(e) => {
                        warn!("accept on {path}: {e}; retrying");
                        tokio::time::sleep(ACCEPT_RETRY_BACKOFF).await;
                    },
                }
            },
            #[cfg(windows)]
            IpcListener::NamedPipe { server, path } => loop {
                if let Err(e) = server.connect().await {
                    // The instance is in an unknown state after a failed
                    // connect; replace it. The replacement is created before
                    // the broken one is dropped, so the pipe name always has
                    // at least one instance and never disappears.
                    warn!("accept on {path}: {e}; replacing the pipe instance");
                    tokio::time::sleep(ACCEPT_RETRY_BACKOFF).await;
                    *server = create_listen_instance(path).await;
                    continue;
                }
                // Hand the connected instance out; listen on a fresh one. The
                // brief span without a listening instance is seen by clients
                // as ERROR_PIPE_BUSY, which they already retry. Pre-creating
                // the next instance before connect() instead would let a
                // client land on the instance nobody waits for, stalling it
                // until another client arrives.
                let next = create_listen_instance(path).await;
                let connected = std::mem::replace(server, next);
                return Ok(IpcStream(Box::new(connected)));
            },
        }
    }
}

/// Create a listening named pipe instance, retrying transient failures: this
/// only runs inside the daemon accept loop, where returning an error would
/// end the resident process.
#[cfg(windows)]
async fn create_listen_instance(path: &str) -> tokio::net::windows::named_pipe::NamedPipeServer {
    loop {
        match tokio::net::windows::named_pipe::ServerOptions::new().create(path) {
            Ok(server) => return server,
            Err(e) => {
                warn!("create pipe instance on {path}: {e}; retrying");
                tokio::time::sleep(ACCEPT_RETRY_BACKOFF).await;
            },
        }
    }
}

impl IpcStream {
    /// Connect to the daemon endpoint, with busy-retry for pipes.
    pub async fn connect(path: &str) -> std::io::Result<IpcStream> {
        #[cfg(unix)]
        {
            Ok(IpcStream(Box::new(
                tokio::net::UnixStream::connect(path).await?,
            )))
        }
        #[cfg(windows)]
        {
            const ERROR_PIPE_BUSY: i32 = 231;
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                match tokio::net::windows::named_pipe::ClientOptions::new().open(path) {
                    Ok(s) => return Ok(IpcStream(Box::new(s))),
                    // All instances busy: another client is mid-handshake.
                    Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                        if std::time::Instant::now() >= deadline {
                            return Err(e);
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    },
                    Err(e) => return Err(e),
                }
            }
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// Accept hands the connected instance to the caller and keeps serving
    /// later clients from a fresh instance.
    #[tokio::test]
    async fn accept_rotates_pipe_instances() {
        let path = format!(
            r"\\.\pipe\sp-transport-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        );
        let mut listener = bind(&path).expect("bind");

        for round in 0..2 {
            let mut client = IpcStream::connect(&path).await.expect("client connect");
            let mut server = listener.accept().await.expect("server accept");
            let payload = [b'0' + round; 4];
            client.write_all(&payload).await.expect("client write");
            let mut buf = [0u8; 4];
            server.read_exact(&mut buf).await.expect("server read");
            assert_eq!(buf, payload);
        }
    }
}
