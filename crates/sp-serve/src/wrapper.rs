//! Static bash wrapper pieces.
//!
//! Everything dynamic (command text, cwd, args) reaches bash through inherited
//! fds, environment variables or argv - never through string interpolation
//! into shell syntax, so there is no escaping layer to get wrong.

/// rcfile body read by `bash -i` at startup.
///
/// The child starts with stderr redirected to /dev/null so the job-control
/// warnings interactive bash prints on a non-tty (`cannot set terminal process
/// group`, `no job control in this shell`) are swallowed; the first rcfile
/// line restores stderr to the real pipe (`stderr_fd`), then the system and
/// user bashrc are sourced like a normal interactive shell would.
pub fn rc_body(stderr_fd: i32) -> String {
    format!(
        "exec 2>&{stderr_fd}\n[ -r /etc/bash.bashrc ] && . /etc/bash.bashrc || :\n[ -r ~/.bashrc \
         ] && . ~/.bashrc || :\n"
    )
}

/// The `-c` body of the interactive bash running the user command.
///
/// - `$1..` are the user's positional args (argv after the `-c` string);
/// - `SP_CWD` (env) selects the starting directory;
/// - the command text is read verbatim from `cmd_fd` and `eval`ed in this shell, so `sp cd ...`
///   mutates the working directory we report;
/// - after the command, the final `$PWD` is written to `cwd_fd` (out of band, stdout stays
///   byte-clean) and the command's exit status is propagated;
/// - the traps pin the exit status to 128+signum when a group-wide signal (sent by serve on local
///   Ctrl+C / timeout) also hits this bash.
pub fn wrapper_body(cmd_fd: i32, cwd_fd: i32) -> String {
    format!(
        "if [ -n \"${{SP_CWD:-}}\" ]; then\n  cd -- \"$SP_CWD\" || {{ printf 'sp: cannot cd to \
         %s, using HOME\\n' \"$SP_CWD\" >&2; cd; }}\nfi\ntrap 'exit 130' INT\ntrap 'exit 143' \
         TERM\ntrap 'exit 129' HUP\neval \"$(cat /dev/fd/{cmd_fd})\"\n__sp_rc=$?\nprintf %s \
         \"$PWD\" >&{cwd_fd}\nexec 2>/dev/null\nexit \"$__sp_rc\"\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies_reference_the_given_fds() {
        let rc = rc_body(7);
        assert!(rc.starts_with("exec 2>&7\n"));
        assert!(rc.contains(". /etc/bash.bashrc"));
        assert!(rc.contains(". ~/.bashrc"));

        let w = wrapper_body(9, 11);
        assert!(w.contains("eval \"$(cat /dev/fd/9)\""));
        assert!(w.contains("printf %s \"$PWD\" >&11"));
        // traps must pin 128+signum exit codes
        assert!(w.contains("trap 'exit 130' INT"));
        assert!(w.contains("trap 'exit 143' TERM"));
        assert!(w.contains("trap 'exit 129' HUP"));
        // exit status propagation last
        assert!(w.ends_with("exit \"$__sp_rc\"\n"));
    }
}
