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
/// - the dump is all builtins reading in-memory tables (declare/alias/shopt/set/umask), and
///   `declare -p` output is one safely quoted line per variable, so it round-trips through eval as
///   data, not syntax. It runs in a subshell so the unsets keeping wrapper internals and PWD/SP_CWD
///   out of the dump cannot clear `__sp_rc`, which the final `exit` still has to read;
/// - errexit is dropped right after the command: a restored `set -e` plus a failing command would
///   abort the wrapper before the cwd report and state dump run;
/// - the traps record the signal as a flag instead of exiting: bash runs a trap only after the
///   current foreground command finishes, so both a signal that killed the foreground child (eval
///   returns with 128+signum already in `$?`) and one that hit an idle bash still leave the
///   epilogue - cwd report and state dump - intact. The recorded flag then pins the exit status to
///   128+signum when the signal also reached this bash (serve sends it to the whole group on local
///   Ctrl+C / timeout). The only unrecoverable case is a SIGKILL aimed at this bash itself, which
///   could never report anything anyway.
pub fn wrapper_body(cmd_fd: i32, restore_fd: i32, dump_fd: i32, pwd_fd: i32) -> String {
    format!(
        "if [ -n \"${{SP_CWD:-}}\" ]; then\n  cd -- \"$SP_CWD\" || {{ printf 'sp: cannot cd to \
         %s, using HOME\\n' \"$SP_CWD\" >&2; cd; }}\nfi\n__sp_sig=\ntrap '__sp_sig=130' INT\ntrap \
         '__sp_sig=143' TERM\ntrap '__sp_sig=129' HUP\n{{ eval \"$(cat /dev/fd/{restore_fd})\"; \
         }} 2>/dev/null\neval \"$(cat /dev/fd/{cmd_fd})\"\n__sp_rc=$?\n[ -n \"$__sp_sig\" ] && \
         __sp_rc=$__sp_sig\nset +e\nprintf '%s\\0' \"$PWD\" >&{pwd_fd}\nexec 2>/dev/null\n( unset \
         __sp_rc __sp_sig SP_CWD PWD; declare -p; declare -f; alias; shopt -p; set +o; umask -p; \
         printf '\\0'; ) >&{dump_fd}\nexit \"$__sp_rc\"\n"
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
        // exit status propagation last
        assert!(w.ends_with("exit \"$__sp_rc\"\n"));
    }

    #[test]
    fn traps_record_a_flag_instead_of_exiting() {
        let w = wrapper_body(9, 10, 12, 11);
        // The flag starts empty (so nothing restored from a dump can fake a
        // signal) and the traps arm before the command can receive one.
        assert!(w.contains("__sp_sig=\ntrap '__sp_sig=130' INT"));
        assert!(w.contains("trap '__sp_sig=143' TERM"));
        assert!(w.contains("trap '__sp_sig=129' HUP"));
        assert!(!w.contains("trap 'exit"));
        let trap = w.find("trap '__sp_sig=130' INT").expect("trap");
        let cmd = w.find("eval \"$(cat /dev/fd/9)\"").expect("command eval");
        assert!(trap < cmd);
    }

    #[test]
    fn signal_flag_pins_exit_code_without_skipping_epilogue() {
        let w = wrapper_body(9, 10, 12, 11);
        let rc = w.find("__sp_rc=$?").expect("rc captured");
        let sig = w
            .find("[ -n \"$__sp_sig\" ] && __sp_rc=$__sp_sig")
            .expect("signal override");
        let off = w.find("set +e").expect("errexit off");
        let report = w.find("printf '%s\\0' \"$PWD\"").expect("pwd report");
        let dump = w.find("declare -p").expect("state dump");
        let exit = w.rfind("exit \"$__sp_rc\"").expect("exit last");
        assert!(rc < sig && sig < off && off < report && report < dump && dump < exit);
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
        // The dump runs in a subshell: the unsets hide the wrapper internals
        // from `declare -p` without clearing `__sp_rc` for the final exit.
        // PWD must stay the last unset word - bash records it in `_`, whose
        // dumped value is then identical to a dump taken without the unsets.
        let unset = w
            .find("( unset __sp_rc __sp_sig SP_CWD PWD; declare -p;")
            .expect("unset inside the dump subshell");
        let dump_end = w.rfind(">&12").expect("dump redirect");
        assert!(unset < dump_end);
        // OLDPWD is not excluded: cd - across commands depends on it
        assert!(!w.contains("OLDPWD"));
    }

    #[test]
    fn reports_end_with_nul_terminator() {
        // A surviving background job holds the report pipes open, so serve
        // must rely on the terminator, not EOF, to know a report is complete.
        let w = wrapper_body(9, 10, 12, 11);
        assert!(w.contains("printf '%s\\0' \"$PWD\" >&11"));
        assert!(w.contains("umask -p; printf '\\0'; ) >&12"));
    }
}
