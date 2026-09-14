//! Static bash wrapper pieces.
//!
//! Everything dynamic (command text, cwd, shell state, args) reaches bash
//! through inherited fds, environment variables or argv - never through string
//! interpolation into shell syntax, so there is no escaping layer to get wrong.
//!
//! The report/dump pipe fds are inherited by everything the command spawns, so
//! a surviving background job (`nohup foo &`) holds their write ends open and
//! EOF never arrives; both reports therefore end with a NUL terminator, which
//! serve treats as the completion signal instead of EOF.

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
/// - the persisted shell state is read verbatim from `restore_fd` and eval'd after the cd: it must
///   override bashrc settings, and a restored OLDPWD only survives if no cd follows it. Empty
///   content is a no-op eval. Restore errors (readonly vars like BASH_VERSINFO refuse reassignment)
///   are suppressed - the dump is best-effort state, not a contract;
/// - the command text is read verbatim from `cmd_fd` and `eval`ed in this shell, so `sp cd ...`
///   mutates the working directory we report;
/// - after the command, the final `$PWD` is written to `pwd_fd` and the state dump to `dump_fd`
///   (both out of band, stdout stays byte-clean; both NUL-terminated - bash data can never contain
///   NUL, and a background job surviving the command holds the pipe write ends open, so serve must
///   not wait for EOF), and the command's exit status is propagated. SP_CWD (daemon-provided, stale
///   after a user `--cwd`) and PWD (owned by the cd mechanism; restoring a stale string would
///   desync `$PWD` from the real directory) are kept out of the dump; OLDPWD stays so `cd -` works
///   across commands;
/// - the dump is all builtins, no fork: declare/alias/shopt/set/umask read in-memory tables, and
///   `declare -p` output is one safely quoted line per variable, so it round-trips through eval as
///   data, not syntax;
/// - errexit is dropped right after the command: a restored `set -e` plus a failing command would
///   abort the wrapper before the cwd report and state dump run;
/// - the traps pin the exit status to 128+signum when a group-wide signal (sent by serve on local
///   Ctrl+C / timeout) also hits this bash.
pub fn wrapper_body(cmd_fd: i32, restore_fd: i32, dump_fd: i32, pwd_fd: i32) -> String {
    format!(
        "if [ -n \"${{SP_CWD:-}}\" ]; then\n  cd -- \"$SP_CWD\" || {{ printf 'sp: cannot cd to \
         %s, using HOME\\n' \"$SP_CWD\" >&2; cd; }}\nfi\ntrap 'exit 130' INT\ntrap 'exit 143' \
         TERM\ntrap 'exit 129' HUP\n{{ eval \"$(cat /dev/fd/{restore_fd})\"; }} 2>/dev/null\neval \
         \"$(cat /dev/fd/{cmd_fd})\"\n__sp_rc=$?\nset +e\nprintf '%s\\0' \"$PWD\" \
         >&{pwd_fd}\nexec 2>/dev/null\nunset SP_CWD PWD\n{{ declare -p; declare -f; alias; shopt \
         -p; set +o; umask -p; printf '\\0'; }} >&{dump_fd}\nexit \"$__sp_rc\"\n"
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

        let w = wrapper_body(9, 10, 12, 11);
        assert!(w.contains("eval \"$(cat /dev/fd/9)\""));
        assert!(w.contains("eval \"$(cat /dev/fd/10)\""));
        assert!(w.contains(">&11"));
        assert!(w.contains(">&12"));
        // traps must pin 128+signum exit codes
        assert!(w.contains("trap 'exit 130' INT"));
        assert!(w.contains("trap 'exit 143' TERM"));
        assert!(w.contains("trap 'exit 129' HUP"));
        // errexit must be off before the reports run
        let rc_capture = w.find("__sp_rc=$?").expect("rc captured");
        let report = w.find("printf '%s\\0' \"$PWD\"").expect("pwd report");
        assert!(
            w[rc_capture..report].contains("set +e"),
            "set +e must sit between rc capture and the reports"
        );
        // exit status propagation last
        assert!(w.ends_with("exit \"$__sp_rc\"\n"));
    }

    #[test]
    fn state_restores_after_cd_and_before_command() {
        let w = wrapper_body(9, 10, 12, 11);
        let cd = w.find("cd -- \"$SP_CWD\"").expect("cd present");
        let restore = w.find("/dev/fd/10").expect("restore present");
        let cmd = w.find("/dev/fd/9").expect("command present");
        assert!(cd < restore && restore < cmd);
    }

    #[test]
    fn state_dump_excludes_sp_and_pwd() {
        let w = wrapper_body(9, 10, 12, 11);
        let unset = w.find("unset SP_CWD PWD").expect("unset present");
        let dump = w.find("declare -p").expect("dump present");
        assert!(unset < dump);
        // OLDPWD is not excluded: cd - across commands depends on it
        assert!(!w.contains("OLDPWD"));
    }

    #[test]
    fn reports_end_with_nul_terminator() {
        // A surviving background job holds the report pipes open, so serve
        // must rely on the terminator, not EOF, to know a report is complete.
        let w = wrapper_body(9, 10, 12, 11);
        assert!(w.contains("printf '%s\\0' \"$PWD\" >&11"));
        assert!(w.contains("umask -p; printf '\\0'; } >&12"));
    }
}
