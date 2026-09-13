//! Remote wrapper script generation.
//!
//! Per command the daemon uploads one bash script to the remote host and runs
//! `bash <path>`. The script:
//!
//! 1. deletes itself first (the fd stays readable on Linux, so crashes leave no leftovers);
//! 2. execs an interactive bash (`-i`) so `~/.bashrc` is loaded with aliases and functions
//!    available; the rcfile trick (`/dev/fd/3` + `4>&2` + `2>/dev/null`) swallows the two
//!    job-control warnings interactive bash prints on a non-tty while keeping real stderr intact
//!    (restored by the rcfile before sourcing);
//! 3. cds to the persisted cwd, runs the user command, then prints a `<marker><base64 cwd><marker>`
//!    trailer on stdout and exits with the user command's exit status (forwarded natively via the
//!    SSH exit-status message).
//!
//! The final `exec 2>/dev/null` silences the `exit` line interactive bash prints
//! when the *wrapper* runs the exit builtin (V3 in the prototype logs).

/// Prototype-validated pieces of the remote wrapper.
pub const MARKER_PREFIX: &str = "\x1cSPM:";
/// Marker terminator.
pub const MARKER_SUFFIX: &str = "\x1c";
/// Control message prefix for the wrapper's process group id report.
pub const PGID_PREFIX: &str = "\x1cSPPG:";

/// Inputs for building one remote wrapper script.
#[derive(Debug, Clone)]
pub struct ScriptSpec<'a> {
    /// User command text, executed verbatim as bash script lines.
    pub command: &'a str,
    /// Positional arguments (`$1..`) for the command, file mode mainly.
    pub args: &'a [String],
    /// Directory to cd into before running; `None` keeps the session default.
    pub cwd: Option<&'a str>,
    /// Per-command random hex nonce, used in the marker and remote file name.
    pub nonce_hex: &'a str,
}

/// Remote path the wrapper script is uploaded to.
#[must_use]
pub fn remote_script_path(nonce_hex: &str) -> String {
    format!("/tmp/.sp-{nonce_hex}.sh")
}

/// POSIX single-quote escape for embedding text inside `'...'` in bash.
#[must_use]
pub fn sq_escape(s: &str) -> String {
    s.replace('\'', r"'\''")
}

/// Build the full wrapper script uploaded to the remote host.
#[must_use]
pub fn build(spec: &ScriptSpec<'_>) -> String {
    use std::fmt::Write as _;

    let nonce = spec.nonce_hex;
    let delim = format!("__SP_{nonce}__");

    let mut inner = String::new();
    if let Some(cwd) = spec.cwd {
        let e = sq_escape(cwd);
        let _ = writeln!(
            inner,
            "if ! cd -- '{e}'; then printf 'sp: cannot cd to {e}, using $HOME\\n' >&2; cd -- ~; fi"
        );
    }
    if !spec.args.is_empty() {
        let args: Vec<String> = spec
            .args
            .iter()
            .map(|a| format!("'{}'", sq_escape(a)))
            .collect();
        let _ = writeln!(inner, "set -- {}", args.join(" "));
    }
    // The user command runs in THIS shell (foreground): `sp cd ...` must
    // mutate the persisted cwd, which the epilogue marker reports.
    // Report the process group id first: SSH signal requests only reach the
    // session leader (whose handling interactive bash defers), so the daemon
    // kills the whole group through a dedicated `kill -SIG -PGID` channel.
    // The pgid cannot be derived from $$: the login shell (e.g. fish) may not
    // exec our bash, making the group leader its own pid, not ours.
    // The control message is stripped by the daemon-side marker filter.
    inner.push_str("IFS=' ' read -r _ _ _ __sp_pgid _ < /proc/self/stat 2>/dev/null || \
                    __sp_pgid=$$\n");
    let _ = writeln!(inner, "printf '\\034SPPG:{nonce}:%s\\034' \"$__sp_pgid\"");
    // The group INT also hits this bash; without the trap its exit status
    // after an aborted foreground child is 1, not the expected 128+signum.
    let _ = writeln!(inner, "trap 'exit 130' INT");
    let _ = writeln!(inner, "trap 'exit 143' TERM");
    let _ = writeln!(inner, "trap 'exit 129' HUP");
    inner.push_str(spec.command);
    inner.push('\n');
    // Capture rc before anything else runs; the marker goes to stdout and is
    // stripped client-side. `exec 2>/dev/null` before `exit` hides the "exit"
    // line interactive bash prints to stderr for its own exit builtin.
    let _ = write!(
        inner,
        "__sp_rc=$?\nprintf '\\034SPM:{nonce}:%s\\034' \"$(printf %s \"$PWD\" | base64 | tr -d \
         '\\n')\"\nexec 2>/dev/null\nexit $__sp_rc\n"
    );

    let inner_escaped = sq_escape(&inner);

    format!(
        "rm -f -- \"$0\" 2>/dev/null || :\nexec bash --noprofile --rcfile /dev/fd/3 -i -c \
         '{inner_escaped}' 4>&2 3<<'{delim}' 2>/dev/null\nexec 2>&4\n[ -r /etc/bash.bashrc ] && . \
         /etc/bash.bashrc || :\n[ -r ~/.bashrc ] && . ~/.bashrc || :\n{delim}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(command: &str) -> ScriptSpec<'_> {
        ScriptSpec {
            command,
            args: &[],
            cwd: None,
            nonce_hex: "ab12",
        }
    }

    #[test]
    fn escape_single_quotes() {
        assert_eq!(sq_escape("a'b"), r"a'\''b");
        assert_eq!(sq_escape("''"), r"'\'''\''");
    }

    #[test]
    fn build_contains_all_layers() {
        let s = build(&spec("echo 'hi'"));
        assert!(s.starts_with("rm -f -- \"$0\""));
        // inner is sq-escaped once for the -c argument; pgid control message
        // (read from /proc, $$ may differ from the pgid) precedes the user
        // command, which runs in this shell (foreground)
        assert!(s.contains("__sp_pgid _ < /proc/self/stat 2>/dev/null"));
        assert!(s.contains(
            r#"printf '\''\034SPPG:ab12:%s\034'\'' "$__sp_pgid""#
        ));
        // anchor the exit status for group-killed signals (quotes arrive
        // sq-escaped for the -c embedding)
        assert!(s.contains("trap '\\''exit 130'\\'' INT"));
        assert!(s.contains("trap '\\''exit 143'\\'' TERM"));
        assert!(s.contains("trap '\\''exit 129'\\'' HUP"));
        // the user command follows the traps in the same shell
        assert!(s.contains("exit 129'\\'' HUP\necho '\\''hi'\\''"));
        assert!(s.contains("4>&2 3<<'__SP_ab12__' 2>/dev/null"));
        assert!(s.contains(". /etc/bash.bashrc"));
        assert!(s.contains(". ~/.bashrc"));
        assert!(s.ends_with("__SP_ab12__\n"));
        // cwd marker printf, escaped for the -c embedding
        assert!(s.contains(r"printf '\''\034SPM:ab12:%s\034'\''"));
        assert!(s.contains("exec 2>/dev/null\nexit $__sp_rc\n' 4>&2"));
    }

    #[test]
    fn build_cwd_and_args() {
        let args = vec!["a b".to_owned(), "c".to_owned()];
        let s = build(&ScriptSpec {
            command: "echo $1",
            args: &args,
            cwd: Some("/ro'ot"),
            nonce_hex: "ff",
        });
        // the cd line inside inner carries one escape level, which is then
        // escaped again when inner is embedded into the -c argument
        assert!(s.contains("-c 'if ! cd -- '\\''/ro'\\''\\'\\'''\\''ot'\\'';"));
        assert!(s.contains("set -- '\\''a b'\\'' '\\''c'\\''"));
    }
}
