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

/// Windows named-pipe security: an explicit DACL granting full access only to
/// the current user, mirroring the unix socket's 0600 mode. The default pipe
/// DACL also grants read access to Everyone and Anonymous, letting any local
/// process hold connections open.
#[cfg(windows)]
mod security {
    use std::{io, mem::size_of};

    use windows_sys::Win32::{
        Foundation::{CloseHandle, GENERIC_ALL, HANDLE},
        Security::{
            ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAce, GetLengthSid,
            GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor, SECURITY_ATTRIBUTES,
            SECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE, SetSecurityDescriptorDacl, TOKEN_QUERY,
            TOKEN_USER, TokenUser,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    /// `SECURITY_DESCRIPTOR_REVISION` from the Win32 headers; the windows-sys
    /// constant sits in a crate feature that is not enabled.
    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

    /// Buffer lengths here are bounded (one SID plus one ACE), far below
    /// `u32::MAX`; a saturating value makes any overflow fail the API call.
    fn as_u32(len: usize) -> u32 {
        u32::try_from(len).unwrap_or(u32::MAX)
    }

    /// SIDs are bounded by `SECURITY_MAX_SID_SIZE`, far below `usize::MAX`.
    fn as_usize(len: u32) -> usize {
        usize::try_from(len).unwrap_or(usize::MAX)
    }

    fn win_err(step: &str) -> io::Error {
        io::Error::other(format!("{step}: {}", io::Error::last_os_error()))
    }

    /// Raw SID bytes of the user owning this process.
    pub(crate) fn current_user_sid() -> io::Result<Vec<u8>> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a valid pseudo handle; the out
        // pointer targets an uninitialized HANDLE slot.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
            return Err(win_err("OpenProcessToken"));
        }
        // TokenUser writes TOKEN_USER followed by the SID itself. A u64 buffer
        // keeps the platform alignment TOKEN_USER requires.
        let cap = as_usize(SECURITY_MAX_SID_SIZE) + size_of::<TOKEN_USER>();
        let mut buf = vec![0u64; cap.div_ceil(size_of::<u64>())];
        let mut ret_len = 0u32;
        // SAFETY: token comes from OpenProcessToken; buf is larger than any
        // user SID; ret_len targets a u32.
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr().cast(),
                as_u32(buf.len() * size_of::<u64>()),
                &raw mut ret_len,
            )
        } == 0
        {
            let e = win_err("GetTokenInformation");
            // SAFETY: token is a valid token handle; closed exactly once.
            unsafe { CloseHandle(token) };
            return Err(e);
        }
        // SAFETY: the successful call wrote a TOKEN_USER whose Sid points
        // into buf.
        let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        // SAFETY: Sid points at a valid SID inside buf; GetLengthSid returns
        // its byte length.
        let sid_len = unsafe { GetLengthSid(sid) };
        // SAFETY: sid..sid+sid_len is readable and does not alias buf's store.
        let bytes = unsafe { std::slice::from_raw_parts(sid.cast(), as_usize(sid_len)) }.to_vec();
        // SAFETY: token is a valid token handle; closed exactly once.
        unsafe { CloseHandle(token) };
        Ok(bytes)
    }

    /// An absolute-format security descriptor granting pipe access to the
    /// current user only. The DACL references the internal ACL buffer, so the
    /// value must outlive every `SECURITY_ATTRIBUTES` derived from it.
    pub struct OwnerOnly {
        // The descriptor stores a pointer into this buffer; the OS dereferences
        // it during pipe creation, a read the compiler cannot see.
        #[allow(dead_code)]
        acl: Vec<u8>,
        sd: Vec<u8>,
    }

    impl OwnerOnly {
        /// Build the descriptor: one allowed ACE for the current user's SID.
        pub fn new() -> io::Result<Self> {
            let sid = current_user_sid()?;
            // ACL header plus one allowed ACE; the ACE's SidStart overlaps the
            // copied SID, so its trailing u32 is not counted twice.
            let acl_len =
                size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + sid.len();
            let mut acl = vec![0u8; acl_len];
            // SAFETY: acl has the exact byte size InitializeAcl requires for
            // one ACE.
            if unsafe { InitializeAcl(acl.as_mut_ptr().cast(), as_u32(acl_len), ACL_REVISION) } == 0
            {
                return Err(win_err("InitializeAcl"));
            }
            // SAFETY: acl holds space for the SID, which AddAccessAllowedAce
            // copies into the new ACE.
            if unsafe {
                AddAccessAllowedAce(
                    acl.as_mut_ptr().cast(),
                    ACL_REVISION,
                    GENERIC_ALL,
                    sid.as_ptr().cast_mut().cast(),
                )
            } == 0
            {
                return Err(win_err("AddAccessAllowedAce"));
            }

            let mut sd = vec![0u8; size_of::<SECURITY_DESCRIPTOR>()];
            // SAFETY: sd is SECURITY_DESCRIPTOR-sized.
            if unsafe {
                InitializeSecurityDescriptor(sd.as_mut_ptr().cast(), SECURITY_DESCRIPTOR_REVISION)
            } == 0
            {
                return Err(win_err("InitializeSecurityDescriptor"));
            }
            // SAFETY: sd was initialized by InitializeSecurityDescriptor; acl
            // stays alive in the returned value, which the absolute-format
            // descriptor references by pointer.
            if unsafe {
                SetSecurityDescriptorDacl(
                    sd.as_mut_ptr().cast(),
                    1,
                    acl.as_ptr().cast_mut().cast(),
                    0,
                )
            } == 0
            {
                return Err(win_err("SetSecurityDescriptorDacl"));
            }
            Ok(Self { acl, sd })
        }

        /// `SECURITY_ATTRIBUTES` for pipe creation, referencing this value's
        /// buffers; CreateNamedPipeW copies the descriptor, so nothing needs
        /// to outlive the call.
        #[must_use]
        pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: as_u32(size_of::<SECURITY_ATTRIBUTES>()),
                lpSecurityDescriptor: self.sd.as_ptr().cast_mut().cast(),
                bInheritHandle: 0,
            }
        }
    }
}

/// Raw SID bytes of the current user, for caller-side user identity needs.
#[cfg(windows)]
pub(crate) use security::current_user_sid;

/// Platform listener.
pub enum IpcListener {
    #[cfg(windows)]
    NamedPipe {
        server: tokio::net::windows::named_pipe::NamedPipeServer,
        path: String,
        /// Owner-only DACL applied to every instance created for this pipe.
        security: security::OwnerOnly,
    },
    #[cfg(unix)]
    Unix {
        listener: tokio::net::UnixListener,
        path: String,
    },
}

/// Create a listening named pipe instance with the owner-only DACL.
#[cfg(windows)]
fn create_pipe_instance(
    path: &str,
    security: &security::OwnerOnly,
    first: bool,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    let mut options = tokio::net::windows::named_pipe::ServerOptions::new();
    options.first_pipe_instance(first);
    let mut attrs = security.attributes();
    // SAFETY: attrs points to a SECURITY_ATTRIBUTES whose referenced
    // descriptor lives in `security` across the call.
    unsafe {
        options.create_with_security_attributes_raw(path, std::ptr::from_mut(&mut attrs).cast())
    }
}

/// Bind the daemon endpoint. Fails if another daemon owns it.
pub fn bind(path: &str) -> std::io::Result<IpcListener> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // The endpoint's parent (the app dir for default paths) must exist
        // before bind; config::app_dir is a pure read.
        if let Some(parent) = std::path::Path::new(path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        let listener = tokio::net::UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(IpcListener::Unix {
            listener,
            path: path.to_owned(),
        })
    }
    #[cfg(windows)]
    {
        let security = security::OwnerOnly::new()?;
        let server = create_pipe_instance(path, &security, true)?;
        Ok(IpcListener::NamedPipe {
            server,
            path: path.to_owned(),
            security,
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
            IpcListener::NamedPipe {
                server,
                path,
                security,
            } => loop {
                if let Err(e) = server.connect().await {
                    // The instance is in an unknown state after a failed
                    // connect; replace it. The replacement is created before
                    // the broken one is dropped, so the pipe name always has
                    // at least one instance and never disappears.
                    warn!("accept on {path}: {e}; replacing the pipe instance");
                    tokio::time::sleep(ACCEPT_RETRY_BACKOFF).await;
                    *server = create_listen_instance(path, security).await;
                    continue;
                }
                // Hand the connected instance out; listen on a fresh one. The
                // brief span without a listening instance is seen by clients
                // as ERROR_PIPE_BUSY, which they already retry. Pre-creating
                // the next instance before connect() instead would let a
                // client land on the instance nobody waits for, stalling it
                // until another client arrives.
                let next = create_listen_instance(path, security).await;
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
async fn create_listen_instance(
    path: &str,
    security: &security::OwnerOnly,
) -> tokio::net::windows::named_pipe::NamedPipeServer {
    loop {
        match create_pipe_instance(path, security, false) {
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
