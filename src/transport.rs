//! Platform IPC endpoint: named pipe on Windows, unix socket elsewhere.

#[cfg(windows)]
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

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
    Unix(tokio::net::UnixListener),
}

/// Bind the daemon endpoint. Fails if another daemon owns it.
pub fn bind(path: &str) -> std::io::Result<IpcListener> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let listener = tokio::net::UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(IpcListener::Unix(listener))
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
    pub async fn accept(&mut self) -> std::io::Result<IpcStream> {
        match self {
            #[cfg(unix)]
            IpcListener::Unix(l) => Ok(IpcStream(Box::new(l.accept().await?.0))),
            #[cfg(windows)]
            IpcListener::NamedPipe { server, path } => {
                server.connect().await?;
                // Hand the connected instance out; listen on a fresh one.
                let next = tokio::net::windows::named_pipe::ServerOptions::new().create(path)?;
                let connected = std::mem::replace(server, next);
                Ok(IpcStream(Box::new(connected)))
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
