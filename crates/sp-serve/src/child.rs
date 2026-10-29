//! Spawning the interactive bash that runs one user command.
//!
//! File descriptor layout of the child (fixed numbers; see `pre_exec` for how
//! the sources are relocated onto them):
//!
//! | fd | target | source |
//! |----|--------|--------|
//! | 0  | user stdin forwarding | pipe from serve |
//! | 1  | user stdout | pipe to serve |
//! | 2  | /dev/null until the rcfile restores it | real stderr pipe, inherited |
//! | 3  | stderr restore (`exec 2>&3`) | pipe to serve |
//! | 7  | rcfile memfd (`--rcfile /dev/fd/7`) | serve |
//! | 8  | command text memfd (`eval "$(cat /dev/fd/8)"`) | serve |
//! | 9  | shell state restore memfd (`eval "$(cat /dev/fd/9)"`) | serve |
//! | 10 | cwd report (`printf %s "$PWD" >&10`) | pipe to serve |
//! | 11 | shell state dump (`{ declare -p; ... } >&11`) | pipe to serve |
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

use sp_proto::ServeExec;
use tokio::{net::unix::pipe, process::Command};

use crate::wrapper;

/// Fixed child-side fd numbers (see the module docs); the static wrapper
/// scripts reference them.
const FD_STDERR: i32 = 3;
const FD_RCFILE: i32 = 7;
const FD_CMD: i32 = 8;
const FD_RESTORE: i32 = 9;
const FD_CWD: i32 = 10;
const FD_DUMP: i32 = 11;

/// Floor for the scratch descriptors parking the sources in pre_exec: above
/// every fixed target, so no relocation dup2 can clobber a parked copy.
const SCRATCH_FLOOR: i32 = FD_DUMP + 1;

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

/// Spawn the bash wrapper for one request. `state` is the persisted shell
/// state (bash source) to eval after the rcfile and the cd, or `None`.
pub fn spawn(req: &ServeExec, state: Option<&str>) -> io::Result<Spawned> {
    let (stdin_w, stdin_r) = pipe::pipe()?;
    let (stdout_w, stdout_r) = pipe::pipe()?;
    let (stderr_w, stderr_r) = pipe::pipe()?;
    let (cwd_w, cwd_r) = pipe::pipe()?;
    let (state_w, state_r) = pipe::pipe()?;

    let in_fd = stdin_r.as_raw_fd();
    let out_fd = stdout_w.as_raw_fd();
    let err_fd = stderr_w.as_raw_fd();
    let pwd_fd = cwd_w.as_raw_fd();
    let dump_fd = state_w.as_raw_fd();

    // memfd: anonymous in-memory files, no filesystem leftovers. CLOEXEC is
    // cleared for the child in pre_exec. The restore memfd is empty content
    // when no state exists - the wrapper's eval of "" is a no-op.
    let mut rc_file = memfd(c"sp-rcfile")?;
    let rc_fd = rc_file.as_raw_fd();
    fill(&mut rc_file, wrapper::RC_BODY.as_bytes())?;
    let mut cmd_file = memfd(c"sp-cmd")?;
    let cmd_fd = cmd_file.as_raw_fd();
    fill(&mut cmd_file, req.command.as_bytes())?;
    let mut state_file = memfd(c"sp-state")?;
    let restore_fd = state_file.as_raw_fd();
    fill(&mut state_file, state.unwrap_or("").as_bytes())?;

    let mut cmd = Command::new("bash");
    cmd.arg("--noprofile")
        .arg("--rcfile")
        .arg(format!("/dev/fd/{FD_RCFILE}"))
        .arg("-i")
        .arg("-c")
        .arg(wrapper::WRAPPER_BODY)
        // $0 named bash so error messages match a plain bash session.
        .arg("bash")
        .args(&req.args);
    if let Some(cwd) = &req.cwd {
        cmd.env("SP_CWD", cwd);
    }
    // Placeholders; pre_exec replaces stdin/stdout below. stderr starts as
    // /dev/null so interactive bash's non-tty job-control warnings are
    // swallowed; the rcfile restores it from fd 3.
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // SAFETY: setsid/dup2/fcntl/close are async-signal-safe and no allocation
    // happens in the closure. All source fds are >= 3 (0..=2 belong to our own
    // stdio) and distinct, but pipe/memfd fds land wherever the parent has
    // free slots, so a source may double as another pair's fixed target and a
    // naive dup2 order could clobber it before its own move: every source is
    // therefore parked on a scratch descriptor above every target (`F_DUPFD`)
    // first, and the relocation reads only parked copies. O_NONBLOCK must be
    // cleared on the child's pipe ends: tokio pipes are nonblocking, the flag
    // lives on the shared open file description, and a blocking program (e.g.
    // `seq`) dies with EAGAIN once the pipe fills. The parent's ends are
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
            let sources = [err_fd, rc_fd, cmd_fd, restore_fd, pwd_fd, dump_fd];
            let targets = [FD_STDERR, FD_RCFILE, FD_CMD, FD_RESTORE, FD_CWD, FD_DUMP];
            // One scratch slot per source; the length must be a literal
            // because array lengths are const expressions.
            let mut parked = [0; 6];
            for (i, src) in sources.iter().enumerate() {
                parked[i] = libc::fcntl(*src, libc::F_DUPFD, SCRATCH_FLOOR);
                if parked[i] < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            for (i, dst) in targets.iter().enumerate() {
                if libc::dup2(parked[i], *dst) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            for fd in parked {
                let _ = libc::close(fd);
            }
            for fd in [0, 1, FD_STDERR, FD_CWD, FD_DUMP] {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                if flags < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            // Belt and braces: dup2 already cleared CLOEXEC on the targets;
            // the explicit sweep also covers a target that ever equals its
            // source (dup2 is then a no-op leaving the flag set).
            for fd in [FD_RCFILE, FD_CMD, FD_RESTORE, FD_STDERR, FD_CWD, FD_DUMP] {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }

    let child = cmd.spawn()?;

    // Parent closes the child's ends; the child keeps its relocated copies.
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

/// Create an empty in-memory file.
fn memfd(name: &CStr) -> io::Result<std::fs::File> {
    // SAFETY: plain syscall; the returned fd is owned by us.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh, uniquely owned descriptor.
    unsafe { Ok(<std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(fd)) }
}

/// Fill a memfd with `content`, rewound for reading.
fn fill(file: &mut std::fs::File, content: &[u8]) -> io::Result<()> {
    file.write_all(content)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(())
}
