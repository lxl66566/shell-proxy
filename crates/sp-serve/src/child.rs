//! Spawning the interactive bash that runs one user command.
//!
//! File descriptor layout of the child:
//!
//! | fd | target | source |
//! |----|--------|--------|
//! | 0  | user stdin forwarding | pipe from serve |
//! | 1  | user stdout | pipe to serve |
//! | 2  | /dev/null until the rcfile restores it | real stderr pipe, inherited |
//! | N  | rcfile memfd (`--rcfile /dev/fd/N`) | serve |
//! | M  | command text memfd (`eval "$(cat /dev/fd/M)"`) | serve |
//! | R  | shell state restore memfd (`eval "$(cat /dev/fd/R)"`) | serve |
//! | K  | cwd report (`printf %s "$PWD" >&K`) | pipe to serve |
//! | D  | shell state dump (`{ declare -p; ... } >&D`) | pipe to serve |
//!
//! All dynamic content travels through inherited fds/argv/env, so no string
//! the user controls is ever parsed as shell syntax by our layer. The child is
//! made a session leader (`setsid`) so its process group id equals its pid and
//! serve can signal the whole group with `kill(-pgid, ...)`.

use std::{
    ffi::CStr,
    io::{self, Seek, SeekFrom, Write},
    os::unix::io::AsRawFd,
    process::Stdio,
};

use sp_proto::ExecRequest;
use tokio::{net::unix::pipe, process::Command};

use crate::wrapper;

/// A running interactive bash plus the parent's ends of its pipes.
pub struct Spawned {
    pub child: tokio::process::Child,
    /// Write end of the child's stdin.
    pub stdin: pipe::Sender,
    /// Child stdout (user output).
    pub stdout: pipe::Receiver,
    /// Child stderr (user output; restored by the rcfile).
    pub stderr: pipe::Receiver,
    /// Cwd report channel: the wrapper writes the final `$PWD` here.
    pub cwd: pipe::Receiver,
    /// State dump channel: the wrapper writes the post-command shell state.
    pub state: pipe::Receiver,
}

/// Spawn the bash wrapper for one request.
pub fn spawn(req: &ExecRequest) -> io::Result<Spawned> {
    let (stdin_w, stdin_r) = pipe::pipe()?;
    let (stdout_w, stdout_r) = pipe::pipe()?;
    let (stderr_w, stderr_r) = pipe::pipe()?;
    let (cwd_w, cwd_r) = pipe::pipe()?;
    let (state_w, state_r) = pipe::pipe()?;

    let in_fd = stdin_r.as_raw_fd();
    let out_fd = stdout_w.as_raw_fd();
    let err_fd = stderr_w.as_raw_fd();
    let cwd_fd = cwd_w.as_raw_fd();
    let dump_fd = state_w.as_raw_fd();

    // memfd: anonymous in-memory files, no filesystem leftovers. CLOEXEC is
    // cleared for the child in pre_exec. The restore memfd is empty content
    // when no state exists - the wrapper's eval of "" is a no-op.
    let rc_file = memfd(c"sp-rcfile", wrapper::rc_body(err_fd).as_bytes())?;
    let cmd_file = memfd(c"sp-cmd", req.command.as_bytes())?;
    let state_file = memfd(c"sp-state", req.state.as_deref().unwrap_or("").as_bytes())?;
    let rc_fd = rc_file.as_raw_fd();
    let cmd_fd = cmd_file.as_raw_fd();
    let restore_fd = state_file.as_raw_fd();

    let mut cmd = Command::new("bash");
    cmd.arg("--noprofile")
        .arg("--rcfile")
        .arg(format!("/dev/fd/{rc_fd}"))
        .arg("-i")
        .arg("-c")
        .arg(wrapper::wrapper_body(cmd_fd, restore_fd, dump_fd, cwd_fd))
        // $0 named bash so error messages match a plain bash session.
        .arg("bash")
        .args(&req.args);
    if let Some(cwd) = &req.cwd {
        cmd.env("SP_CWD", cwd);
    }
    // Placeholders; pre_exec replaces stdin/stdout below. stderr starts as
    // /dev/null so interactive bash's non-tty job-control warnings are
    // swallowed; the rcfile restores it from the inherited `err_fd`.
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // SAFETY: setsid/dup2/fcntl are async-signal-safe and no allocation
    // happens in the closure. All source fds are >= 3 (0..=2 belong to our own
    // stdio), so the dup2 targets never collide with a source. O_NONBLOCK must
    // be cleared on the child's pipe ends: tokio pipes are nonblocking, the
    // flag lives on the shared open file description, and a blocking program
    // (e.g. `seq`) dies with EAGAIN once the pipe fills. The parent's ends are
    // separate descriptions and stay nonblocking for tokio.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::dup2(in_fd, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::dup2(out_fd, 1) < 0 {
                return Err(io::Error::last_os_error());
            }
            for fd in [in_fd, out_fd, err_fd, cwd_fd, dump_fd] {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                if flags < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            // Let the rcfile/command/state memfds and the stderr/cwd/state
            // pipes survive exec.
            for fd in [rc_fd, cmd_fd, restore_fd, err_fd, cwd_fd, dump_fd] {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }

    let child = cmd.spawn()?;

    // Parent closes the child's ends; the child keeps its inherited copies.
    drop(stdin_r);
    drop(stdout_w);
    drop(stderr_w);
    drop(cwd_w);
    drop(state_w);
    drop(rc_file);
    drop(cmd_file);
    drop(state_file);

    Ok(Spawned {
        child,
        stdin: stdin_w,
        stdout: stdout_r,
        stderr: stderr_r,
        cwd: cwd_r,
        state: state_r,
    })
}

/// Create an in-memory file with `content`, rewound for reading.
fn memfd(name: &CStr, content: &[u8]) -> io::Result<std::fs::File> {
    // SAFETY: plain syscall; the returned fd is owned by us.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh, uniquely owned descriptor.
    let mut file = unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(fd) };
    file.write_all(content)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}
