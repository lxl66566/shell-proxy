//! Integration tests against a real SSH host.
//!
//! Host alias comes from `SP_TEST_HOST` (default "ls") and must be reachable
//! through the system ssh config. When it is not (e.g. plain CI runners),
//! every test skips itself with a notice instead of failing.

use std::{
    process::Command,
    sync::{
        OnceLock,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

use shell_proxy::{
    client::{self, RunReport},
    config,
    proto::{ExecRequest, Signal},
};
use tokio::sync::mpsc;

struct Harness {
    host: String,
    /// Serializes tests: they share one daemon and its per-host cwd state.
    lock: tokio::sync::Mutex<()>,
    reachable: AtomicU8, // 0 = unknown, 1 = yes, 2 = no
}

static HARNESS: OnceLock<Harness> = OnceLock::new();

fn harness() -> &'static Harness {
    HARNESS.get_or_init(|| {
        // Unique IPC endpoint per test binary run; the daemon gets an idle
        // timeout so no orphan survives a test session.
        let sock = if cfg!(windows) {
            format!(r"\\.\pipe\shell-proxy-test-{}", std::process::id())
        } else {
            let tmp = std::env::temp_dir();
            tmp.join(format!("shell-proxy-test-{}.sock", std::process::id()))
                .to_string_lossy()
                .into_owned()
        };
        // SAFETY: every test reaches `harness()` before touching SP_SOCK /
        // SP_IDLE_SECS / SP_DAEMON_EXE, and OnceLock serializes this
        // initialization, so no thread reads these variables while they are
        // being written.
        unsafe {
            std::env::set_var(config::ENV_SOCK, &sock);
            std::env::set_var("SP_IDLE_SECS", "300");
            // The daemon must be the real sp binary: current_exe() here is the
            // test binary, and libtest would parse "daemon" as a test-name
            // filter, re-running matching tests that spawn more copies of
            // themselves. spawn_daemon also avoids inheriting our handles
            // (std::process::Command inherits all of them on Windows and would
            // pin the test runner's pipes open forever).
            std::env::set_var(config::ENV_DAEMON_EXE, env!("CARGO_BIN_EXE_sp"));
        }

        // `ssh -G` emits drive-relative known_hosts paths on Windows (the
        // global "/etc/ssh/ssh_known_hosts" resolves against the current
        // drive). When SP_TEST_CWD names a directory on the intended drive,
        // run the daemon from there so those paths resolve under it.
        if cfg!(windows)
            && let Some(dir) = std::env::var_os("SP_TEST_CWD")
        {
            std::env::set_current_dir(&dir).expect("SP_TEST_CWD must be a directory");
        }

        client::spawn_daemon().expect("spawn daemon");

        Harness {
            host: std::env::var("SP_TEST_HOST").unwrap_or_else(|_| "ls".into()),
            lock: tokio::sync::Mutex::new(()),
            reachable: AtomicU8::new(0),
        }
    })
}

/// Serialize tests and skip when the host is unreachable.
async fn guard() -> Option<tokio::sync::MutexGuard<'static, ()>> {
    let h = harness();
    let guard = h.lock.lock().await;
    if h.reachable.load(Ordering::SeqCst) == 0 {
        wait_for_daemon().await;
        let probe = run("exit 0", None, None).await;
        match probe {
            Ok(_) => h.reachable.store(1, Ordering::SeqCst),
            Err(e) => {
                h.reachable.store(2, Ordering::SeqCst);
                eprintln!("skipping: host {} unreachable: {e}", h.host);
                return None;
            },
        }
    }
    if h.reachable.load(Ordering::SeqCst) == 2 {
        return None;
    }
    Some(guard)
}

/// Panic unless the daemon answers a ping within the startup window. A dead
/// daemon is broken test infrastructure and must fail loudly; without this
/// every test silently skips and the run still reports success.
async fn wait_for_daemon() {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match client::ping().await {
            Ok(_) => return,
            Err(e) if Instant::now() >= deadline => {
                panic!("daemon not answering at {}: {e}", config::sock_path());
            },
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

async fn run(
    command: &str,
    cwd: Option<&str>,
    timeout_ms: Option<u64>,
) -> shell_proxy::Result<(RunReport, Vec<u8>, Vec<u8>)> {
    let req = ExecRequest {
        host: harness().host.clone(),
        command: command.to_owned(),
        args: Vec::new(),
        cwd: cwd.map(str::to_owned),
        timeout_ms,
        session: None,
    };
    let (_tx, rx) = mpsc::channel(1);
    client::run_captured(req, Vec::new(), rx).await
}

/// Like [`run`] but in a named session. Sessions use unique names per test
/// run, so they never collide with the default bucket or previous runs.
async fn run_in(
    session: &str,
    command: &str,
    cwd: Option<&str>,
    timeout_ms: Option<u64>,
) -> shell_proxy::Result<(RunReport, Vec<u8>, Vec<u8>)> {
    let req = ExecRequest {
        host: harness().host.clone(),
        command: command.to_owned(),
        args: Vec::new(),
        cwd: cwd.map(str::to_owned),
        timeout_ms,
        session: Some(session.to_owned()),
    };
    let (_tx, rx) = mpsc::channel(1);
    client::run_captured(req, Vec::new(), rx).await
}

/// Unique session name for a test (charset matches SessionId validation).
fn unique_session(tag: &str) -> String {
    format!("t-{tag}-{}", std::process::id())
}

/// Spawn `command` in `session`, forward `sig` after a short lead, and await
/// the report - the interactive Ctrl+C flow.
async fn run_and_signal(
    session: Option<&str>,
    command: &str,
    sig: Signal,
) -> shell_proxy::Result<(RunReport, Vec<u8>, Vec<u8>)> {
    let req = ExecRequest {
        host: harness().host.clone(),
        command: command.to_owned(),
        args: Vec::new(),
        cwd: None,
        timeout_ms: None,
        session: session.map(str::to_owned),
    };
    let (tx, rx) = mpsc::channel(1);
    let spawned = tokio::spawn(client::run_captured(req, Vec::new(), rx));
    tokio::time::sleep(Duration::from_millis(800)).await;
    tx.send(sig).await.unwrap();
    spawned.await.unwrap()
}

/// Like [`run`] but feeds `stdin` bytes to the command.
async fn run_stdin(
    command: &str,
    stdin: Vec<u8>,
    timeout_ms: Option<u64>,
) -> shell_proxy::Result<(RunReport, Vec<u8>, Vec<u8>)> {
    let req = ExecRequest {
        host: harness().host.clone(),
        command: command.to_owned(),
        args: Vec::new(),
        cwd: None,
        timeout_ms,
        session: None,
    };
    let (_tx, rx) = mpsc::channel(1);
    client::run_captured(req, stdin, rx).await
}

fn out_str(v: &[u8]) -> String {
    String::from_utf8_lossy(v).into_owned()
}

#[tokio::test]
async fn echo_stdout() {
    let Some(_g) = guard().await else { return };
    let (rep, out, err) = run("echo hello", None, None).await.unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(out_str(&out), "hello\n");
    assert_eq!(err, b"");
}

#[tokio::test]
async fn exit_codes() {
    let Some(_g) = guard().await else { return };
    assert_eq!(run("exit 42", None, None).await.unwrap().0.code, 42);
    assert_eq!(run("false", None, None).await.unwrap().0.code, 1);
    assert_eq!(run("true", None, None).await.unwrap().0.code, 0);
}

#[tokio::test]
async fn command_not_found() {
    let Some(_g) = guard().await else { return };
    let (rep, out, err) = run("definitely_not_a_cmd_xyz", None, None).await.unwrap();
    assert_eq!(rep.code, 127);
    assert_eq!(out, b"");
    assert!(out_str(&err).contains("command not found"));
}

#[tokio::test]
async fn stderr_is_separate() {
    let Some(_g) = guard().await else { return };
    let (rep, out, err) = run("echo o1; echo e1 >&2", None, None).await.unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(out_str(&out), "o1\n");
    assert_eq!(out_str(&err), "e1\n");
}

#[tokio::test]
async fn no_stderr_noise_from_wrapper() {
    let Some(_g) = guard().await else { return };
    let (_, _, err) = run("echo clean", None, None).await.unwrap();
    // Interactive bash without a tty must not leak job-control warnings.
    let e = out_str(&err);
    assert!(!e.contains("no job control"), "unexpected stderr: {e}");
    assert!(
        !e.contains("cannot set terminal process group"),
        "unexpected stderr: {e}"
    );
}

#[tokio::test]
async fn pipes_and_quotes() {
    let Some(_g) = guard().await else { return };
    let (rep, out, _) = run("printf 'a,b' | tr ',' '\\n' | head -1", None, None)
        .await
        .unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(out_str(&out), "a\n");
    let (rep2, out2, _) = run("echo \"it's 'quoted'\"", None, None).await.unwrap();
    assert_eq!(rep2.code, 0);
    assert_eq!(out_str(&out2), "it's 'quoted'\n");
}

#[tokio::test]
async fn pipefail_exit_code() {
    let Some(_g) = guard().await else { return };
    let (rep, ..) = run("set -o pipefail; false | true", None, None)
        .await
        .unwrap();
    assert_eq!(rep.code, 1);
}

#[tokio::test]
async fn interactive_shell_flag_and_bashrc() {
    let Some(_g) = guard().await else { return };
    let (rep, out, _) = run("case $- in *i*) echo yes;; *) echo no;; esac", None, None)
        .await
        .unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(out_str(&out), "yes\n");
}

#[tokio::test]
async fn binary_output_is_byte_exact() {
    let Some(_g) = guard().await else { return };
    // No trailing newline: output must pass through byte-exactly.
    let (rep, out, _) = run("printf hi", None, None).await.unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(out, b"hi");
    // Arbitrary binary (incl. control bytes) must pass through unmangled.
    let (_, out2, _) = run(r"printf 'a\x1cb\x00\xff'", None, None).await.unwrap();
    assert_eq!(out2, b"a\x1cb\x00\xff");
}

#[tokio::test]
async fn large_output_streams() {
    let Some(_g) = guard().await else { return };
    // 80000 lines = ~469KB: near the client-side capture cap (512KB/stream),
    // but under it, so the full-passthrough assertions stay meaningful.
    let (rep, out, _) = run("seq 1 80000", None, None).await.unwrap();
    assert_eq!(rep.code, 0);
    let text = out_str(&out);
    assert_eq!(text.lines().count(), 80_000);
    assert!(text.ends_with("80000\n"));
}

#[tokio::test]
async fn unicode_roundtrip() {
    let Some(_g) = guard().await else { return };
    let (_, out, _) = run("echo 你好，世界", None, None).await.unwrap();
    assert_eq!(out_str(&out), "你好，世界\n");
}

#[tokio::test]
async fn stdin_forwarding() {
    let Some(_g) = guard().await else { return };
    let req = ExecRequest {
        host: harness().host.clone(),
        command: "cat".into(),
        args: vec![],
        cwd: None,
        timeout_ms: None,
        session: None,
    };
    let (_tx, rx) = mpsc::channel(1);
    let (rep, out, _) = client::run_captured(req, b"line-one\nline-two\n".to_vec(), rx)
        .await
        .unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(out_str(&out), "line-one\nline-two\n");
}

/// 8 MiB of stdin into a command that never reads: backpressure must park the
/// pipeline, and the command's exit must tear it down instead of wedging.
#[tokio::test]
async fn stdin_backpressure_does_not_wedge_host() {
    let Some(_g) = guard().await else { return };
    let pattern = b"sp-backpressure-block";
    let mut stdin = pattern.repeat(8 * 1024 * 1024 / pattern.len() + 1);
    stdin.truncate(8 * 1024 * 1024);
    let started = Instant::now();
    let (rep, ..) =
        tokio::time::timeout(Duration::from_secs(20), run_stdin("sleep 3", stdin, None))
            .await
            .expect("unread stdin must not wedge the exec")
            .unwrap();
    assert_eq!(rep.code, 0);
    assert!(started.elapsed() < Duration::from_secs(20));
}

/// 8 MiB of stdin must arrive intact end to end - no silently dropped
/// mid-stream frames.
#[tokio::test]
async fn stdin_large_transfer_is_intact() {
    let Some(_g) = guard().await else { return };
    let stdin = b"0123456789abcdef".repeat(8 * 1024 * 1024 / 16);
    let (rep, out, _) = run_stdin("wc -c", stdin, Some(30_000)).await.unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(out_str(&out).trim(), "8388608");
}

#[tokio::test]
async fn cwd_persists_across_calls() {
    let Some(_g) = guard().await else { return };
    let (rep, ..) = run("cd /tmp", None, None).await.unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(rep.cwd.as_deref(), Some("/tmp"));
    let (rep2, out, _) = run("pwd", None, None).await.unwrap();
    assert_eq!(rep2.code, 0);
    assert_eq!(out_str(&out).trim(), "/tmp");
    // --cwd override also persists
    let (rep3, ..) = run("pwd", Some("/usr"), None).await.unwrap();
    assert_eq!(rep3.cwd.as_deref(), Some("/usr"));
    let (rep4, out4, _) = run("pwd", None, None).await.unwrap();
    assert_eq!(rep4.cwd.as_deref(), Some("/usr"));
    assert_eq!(out_str(&out4).trim(), "/usr");
    run("cd /root", None, None).await.unwrap();
}

#[tokio::test]
async fn shell_state_persists_across_calls() {
    let Some(_g) = guard().await else { return };
    // exported var
    run("export SP_STATE_MARK=hello", None, None).await.unwrap();
    let (rep, out, _) = run("echo [$SP_STATE_MARK]", None, None).await.unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(out_str(&out), "[hello]\n");
    // plain shell var
    run("sp_plain_var=42", None, None).await.unwrap();
    let (_, out, _) = run("echo $sp_plain_var", None, None).await.unwrap();
    assert_eq!(out_str(&out), "42\n");
    // function
    run("sp_fn() { echo fn-$1; }", None, None).await.unwrap();
    let (rep, out, _) = run("sp_fn ok", None, None).await.unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(out_str(&out), "fn-ok\n");
    // alias (expansion happens after the restore, before the command)
    run("alias spal='echo alias-works'", None, None)
        .await
        .unwrap();
    let (rep, out, _) = run("spal", None, None).await.unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(out_str(&out), "alias-works\n");
    // umask and OLDPWD-backed cd -
    run("umask 077; cd /tmp", None, None).await.unwrap();
    run("cd /usr", None, None).await.unwrap();
    let (_, out, _) = run("cd - >/dev/null && pwd && umask", None, None)
        .await
        .unwrap();
    let lines = out_str(&out);
    assert!(
        lines.contains("/tmp"),
        "cd - should return to /tmp: {lines}"
    );
    assert!(lines.contains("0077"), "umask should persist: {lines}");
    // cleanup: fresh state via unset (next dump drops them)
    run(
        "unset SP_STATE_MARK sp_plain_var sp_fn; unalias spal; umask 022",
        None,
        None,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn state_updates_take_latest_value() {
    let Some(_g) = guard().await else { return };
    // re-export overwrites the persisted value; unset removes it
    run("export SP_PATH_MARK=1", None, None).await.unwrap();
    run("export SP_PATH_MARK=2", None, None).await.unwrap();
    let (_, out, _) = run("echo $SP_PATH_MARK", None, None).await.unwrap();
    assert_eq!(out_str(&out), "2\n");
    run("unset SP_PATH_MARK", None, None).await.unwrap();
    let (_, out, _) = run("echo [$SP_PATH_MARK]", None, None).await.unwrap();
    assert_eq!(out_str(&out), "[]\n");
}

/// State values needing quoting on dump must round-trip byte-exactly.
#[tokio::test]
async fn state_dump_escapes_roundtrip() {
    let Some(_g) = guard().await else { return };
    let s = unique_session("esc");
    run_in(&s, r#"export SP_ESC="a'b\"c$(echo d)""#, None, None)
        .await
        .unwrap();
    run_in(&s, r"SP_NL=$'l1\nl2'", None, None).await.unwrap();
    run_in(&s, "sp_q() { echo \"x'y $(pwd)\"; }", None, None)
        .await
        .unwrap();
    let (rep, out, _) = run_in(&s, "printf '%s' \"$SP_ESC\"", None, None)
        .await
        .unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(out_str(&out), "a'b\"cd");
    let (rep, out, _) = run_in(&s, "printf '%s' \"${SP_NL}\"", None, None)
        .await
        .unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(out_str(&out), "l1\nl2");
    let (rep, out, _) = run_in(&s, "sp_q ok", None, None).await.unwrap();
    assert_eq!(rep.code, 0);
    assert!(
        out_str(&out).starts_with("x'y /"),
        "quoted fn body must survive the dump: {}",
        out_str(&out)
    );
}

/// Positional args ($1..) must reach the command with boundaries intact.
#[tokio::test]
async fn positional_args_reach_command() {
    let Some(_g) = guard().await else { return };
    let req = ExecRequest {
        host: harness().host.clone(),
        command: r#"printf '%s|%s\n' "$1" "$2""#.into(),
        args: vec!["a b".into(), "c".into()],
        cwd: None,
        timeout_ms: None,
        session: None,
    };
    let (_tx, rx) = mpsc::channel(1);
    let (rep, out, _) = client::run_captured(req, Vec::new(), rx).await.unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(out_str(&out), "a b|c\n");
}

/// errexit set by the user must persist across calls.
#[tokio::test]
async fn errexit_persists_across_calls() {
    let Some(_g) = guard().await else { return };
    let s = unique_session("errexit");
    run_in(&s, "set -e", None, None).await.unwrap();
    let (_, out, _) = run_in(
        &s,
        "case $- in *e*) echo on;; *) echo off;; esac",
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(out_str(&out).trim(), "on");
    // Behavioral anchor: a failing command aborts the script.
    let (rep, out, _) = run_in(&s, "echo before; false; echo after", None, None)
        .await
        .unwrap();
    assert_eq!(rep.code, 1);
    assert_eq!(out_str(&out).trim(), "before");
    run_in(&s, "set +e", None, None).await.unwrap();
}

/// A state dump exceeding the 256 KiB cap is dropped: the oversized variable
/// disappears and the previous state stays intact.
#[tokio::test]
async fn oversized_state_keeps_previous() {
    let Some(_g) = guard().await else { return };
    let s = unique_session("big-state");
    run_in(&s, "export SP_KEEP=1", None, None).await.unwrap();
    let (rep, ..) = run_in(
        &s,
        "export SP_BIG=$(head -c 300000 /dev/zero | tr '\\0' x)",
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(rep.code, 0);
    let (_, out, _) = run_in(&s, "echo \"[$SP_BIG][$SP_KEEP]\"", None, None)
        .await
        .unwrap();
    assert_eq!(
        out_str(&out).trim(),
        "[][1]",
        "oversized dump must be dropped, previous state kept"
    );
}

#[tokio::test]
async fn timeout_kills_command() {
    let Some(_g) = guard().await else { return };
    let started = Instant::now();
    let (rep, ..) = run("sleep 60", None, Some(1500)).await.unwrap();
    assert!(rep.timed_out, "expected timeout");
    assert_eq!(rep.code, 124);
    assert!(started.elapsed() < Duration::from_secs(10));
}

/// A TERM-immune group member must be reaped by the KILL escalation, not left
/// behind as an orphan when the leader dies inside the TERM grace.
#[tokio::test]
async fn timeout_escalates_kill_to_term_immune_group() {
    let Some(_g) = guard().await else { return };
    // Unique duration (101) so pgrep/pkill cannot match other tests' sleeps.
    let started = Instant::now();
    let (rep, ..) = run(
        "sh -c \"trap '' TERM; exec sleep 101\" & sleep 60",
        None,
        Some(1500),
    )
    .await
    .unwrap();
    assert!(rep.timed_out, "expected timeout");
    assert_eq!(rep.code, 124);
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "TERM grace is 5s; the KILL escalation must return well before 15s"
    );
    // The KILL is delivered before the exit report is written; poll only to
    // absorb process-table update jitter on the remote.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (_, out, _) = run("pgrep -f 'sleep 101' | wc -l", None, None)
            .await
            .unwrap();
        if out_str(&out).trim() == "0" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "TERM-immune orphan must be SIGKILLed after the grace"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// A timeout that fires while the command blocks reading stdin (no data, no
/// EOF) must still return 124 within the bounded teardown, not wedge.
#[tokio::test]
async fn timeout_while_reading_stdin() {
    let Some(_g) = guard().await else { return };
    let req = ExecRequest {
        host: harness().host.clone(),
        command: "cat".into(),
        args: vec![],
        cwd: None,
        timeout_ms: Some(1500),
        session: None,
    };
    let (_tx, rx) = mpsc::channel(1);
    // A stdin that never yields data or EOF keeps `cat` blocked in read, so
    // only the timeout watchdog can end the exec.
    let io = client::RunIo {
        stdin: Box::new(PendingStdin),
        stdout: Box::new(tokio::io::sink()),
        stderr: Box::new(tokio::io::sink()),
    };
    let started = Instant::now();
    let rep = client::run(req, io, rx).await.unwrap();
    assert!(rep.timed_out, "expected timeout");
    assert_eq!(rep.code, 124);
    // The still-open stdin lane is torn down by a bounded join (~10s) after
    // the exec ends; the run must stay bounded, never hang.
    assert!(started.elapsed() < Duration::from_secs(20));
}

/// A stdin reader that stays Pending forever: no data, no EOF.
struct PendingStdin;

impl tokio::io::AsyncRead for PendingStdin {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
}

/// A detached job (own session via setsid, so serve's group kill cannot reach
/// it) that keeps the session's stderr write end open forever: the exit report
/// must still arrive within serve's bounded drain instead of waiting for EOF.
#[tokio::test]
async fn orphan_holding_pipes_does_not_wedge_the_host() {
    let Some(_g) = guard().await else { return };
    let started = Instant::now();
    let res = tokio::time::timeout(
        Duration::from_secs(30),
        run(
            "setsid sh -c 'sleep 120 >&2' >/dev/null & echo ok",
            None,
            None,
        ),
    )
    .await;
    // Cleanup runs under its own bound: if the bug regressed, the wedged exec
    // still holds the host lock and even this must not hang the test run.
    let _ = tokio::time::timeout(
        Duration::from_secs(15),
        run("pkill -f 'sleep 120' 2>/dev/null; true", None, None),
    )
    .await;
    let (rep, out, _) = res
        .expect("exec must finish while the orphan lives")
        .unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(out_str(&out).trim(), "ok");
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "orphan-held pipes must not stall the exit report"
    );
    // The host lock must be free again: the next command answers promptly.
    let t = Instant::now();
    let (rep2, out2, _) = run("echo alive", None, None).await.unwrap();
    assert_eq!(rep2.code, 0);
    assert_eq!(out_str(&out2).trim(), "alive");
    assert!(t.elapsed() < Duration::from_secs(10));
}

/// A plain background job (no setsid, no redirection) keeps the session's
/// stdout write end open: the exit report must still arrive within the bounded
/// drain, and the group kill at command end reaps the job.
#[tokio::test]
async fn orphan_holding_stdout_does_not_wedge() {
    let Some(_g) = guard().await else { return };
    let started = Instant::now();
    let res = tokio::time::timeout(
        Duration::from_secs(30),
        run("sh -c 'exec sleep 102' & echo ok", None, None),
    )
    .await;
    let _ = tokio::time::timeout(
        Duration::from_secs(15),
        run("pkill -f 'sleep 102' 2>/dev/null; true", None, None),
    )
    .await;
    let (rep, out, _) = res
        .expect("exec must finish while the orphan lives")
        .unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(out_str(&out).trim(), "ok");
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "orphan-held stdout must not stall the exit report"
    );
}

/// cd and exported state must persist even when a surviving background job
/// holds the report pipes open: the reports are NUL-terminated, so serve does
/// not depend on EOF to collect them.
#[tokio::test]
async fn state_persists_with_surviving_background_job() {
    let Some(_g) = guard().await else { return };
    let res = tokio::time::timeout(
        Duration::from_secs(30),
        run(
            "cd /tmp; setsid sh -c 'sleep 120 >&2' >/dev/null & export SP_BG_MARK=1",
            None,
            None,
        ),
    )
    .await;
    let _ = tokio::time::timeout(
        Duration::from_secs(15),
        run("pkill -f 'sleep 120' 2>/dev/null; true", None, None),
    )
    .await;
    let (rep, ..) = res
        .expect("exec must finish while the orphan lives")
        .unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(
        rep.cwd.as_deref(),
        Some("/tmp"),
        "cwd report must arrive despite the orphan"
    );
    let (_, out, _) = run("echo \"[$SP_BG_MARK] $(pwd)\"", None, None)
        .await
        .unwrap();
    let text = out_str(&out);
    assert!(text.contains("[1]"), "exported var must persist: {text}");
    assert!(text.contains("/tmp"), "cwd must persist: {text}");
    run("cd /root; unset SP_BG_MARK", None, None).await.unwrap();
}

#[tokio::test]
async fn sigint_forwards_to_remote() {
    let Some(_g) = guard().await else { return };
    let started = Instant::now();
    let (rep, ..) = run_and_signal(None, "sleep 60", Signal::Int).await.unwrap();
    assert_eq!(rep.code, 130, "SIGINT should surface as 130");
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// Term and Hup ride the in-band frame only: out of band, sshd killpgs the
/// session child's whole group, which kills the forking login shell (fish on
/// this host) and tears the exec channel down before serve can report.
#[tokio::test]
async fn sigterm_forwards_to_remote() {
    let Some(_g) = guard().await else { return };
    let started = Instant::now();
    let (rep, ..) = run_and_signal(None, "sleep 60", Signal::Term)
        .await
        .unwrap();
    assert_eq!(rep.code, 143, "SIGTERM should surface as 143");
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// See sigterm_forwards_to_remote.
#[tokio::test]
async fn sighup_forwards_to_remote() {
    let Some(_g) = guard().await else { return };
    let started = Instant::now();
    let (rep, ..) = run_and_signal(None, "sleep 60", Signal::Hup).await.unwrap();
    assert_eq!(rep.code, 129, "SIGHUP should surface as 129");
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// Kill travels in-band only (an uncatchable out-of-band request would end
/// serve itself and lose the exit report): serve survives, reaps the group and
/// reports the wrapper's 128+9.
#[tokio::test]
async fn sigkill_forwards_to_remote() {
    let Some(_g) = guard().await else { return };
    let started = Instant::now();
    let (rep, ..) = run_and_signal(None, "sleep 60", Signal::Kill)
        .await
        .unwrap();
    assert_eq!(rep.code, 137, "SIGKILL should surface as 137");
    assert!(rep.error.is_none(), "the exit report must survive");
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// cwd and state updates of a signal-interrupted command must persist: the
/// wrapper epilogue runs despite the interruption.
#[tokio::test]
async fn interruption_keeps_cwd_and_state() {
    let Some(_g) = guard().await else { return };
    let s = unique_session("sig-keep");
    let (rep, ..) = run_and_signal(
        Some(&s),
        "cd /tmp; export SP_SIG_MARK=1; sleep 60",
        Signal::Int,
    )
    .await
    .unwrap();
    assert_eq!(rep.code, 130, "SIGINT should surface as 130");
    assert_eq!(rep.cwd.as_deref(), Some("/tmp"));
    let (_, out, _) = run_in(&s, "pwd; echo [$SP_SIG_MARK]", None, None)
        .await
        .unwrap();
    let text = out_str(&out);
    assert!(text.contains("/tmp"), "cwd must persist: {text}");
    assert!(text.contains("[1]"), "exported var must persist: {text}");
}

/// The timeout path also persists the interrupted command's cwd updates.
#[tokio::test]
async fn timeout_keeps_cwd() {
    let Some(_g) = guard().await else { return };
    let s = unique_session("tmo-cwd");
    let (rep, ..) = run_in(&s, "cd /tmp; sleep 60", None, Some(1500))
        .await
        .unwrap();
    assert!(rep.timed_out, "expected timeout");
    assert_eq!(rep.code, 124);
    assert_eq!(rep.cwd.as_deref(), Some("/tmp"));
    let (_, out, _) = run_in(&s, "pwd", None, None).await.unwrap();
    assert_eq!(out_str(&out).trim(), "/tmp");
}

#[tokio::test]
async fn exec_replacement_still_reports_rc() {
    let Some(_g) = guard().await else { return };
    // `exec` skips the wrapper epilogue (no marker); exit status still flows.
    let (rep, ..) = run("exec true", None, None).await.unwrap();
    assert_eq!(rep.code, 0);
    let (rep2, ..) = run("exec false", None, None).await.unwrap();
    assert_eq!(rep2.code, 1);
}

#[tokio::test]
async fn serve_binary_is_deployed() {
    let Some(_g) = guard().await else { return };
    // Assert the exact current version, not a file count: leftover binaries
    // of other versions or a concurrent daemon deploying in parallel (nextest
    // runs one process per test) would make counting flaky.
    let (rep, out, _) = run(
        &format!(
            "test -x ~/.local/share/shell-proxy/sp-serve-{}-* && echo executable",
            env!("CARGO_PKG_VERSION")
        ),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(rep.code, 0, "current-version sp-serve must be deployed");
    assert_eq!(out_str(&out).trim(), "executable");
}

#[tokio::test]
async fn daemon_error_surfaces_in_report() {
    let Some(_g) = guard().await else { return };
    // The daemon reports connect failures inside the Exit frame; the client
    // must keep them instead of exiting 254 silently.
    let req = ExecRequest {
        host: "sp-test-unreachable-host.invalid".into(),
        command: "true".into(),
        args: vec![],
        cwd: None,
        timeout_ms: Some(10_000),
        session: None,
    };
    let (_tx, rx) = mpsc::channel(1);
    let (rep, ..) = client::run_captured(req, Vec::new(), rx).await.unwrap();
    assert_eq!(rep.code, 254);
    let err = rep.error.expect("error reason must be surfaced");
    assert!(!err.is_empty(), "error reason must not be empty");
}

#[tokio::test]
async fn cli_exit_code_passthrough() {
    let Some(_g) = guard().await else { return };
    let out = Command::new(env!("CARGO_BIN_EXE_sp"))
        .args(["--host", &harness().host, "exit", "33"])
        .output()
        .expect("run sp");
    assert_eq!(out.status.code(), Some(33));
    let out2 = Command::new(env!("CARGO_BIN_EXE_sp"))
        .args(["--host", &harness().host, "echo", "cli-hello"])
        .output()
        .expect("run sp");
    assert_eq!(out2.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out2.stdout), "cli-hello\n");
}

#[tokio::test]
async fn cli_quoted_line_runs_as_command_line() {
    let Some(_g) = guard().await else { return };
    // One argument carrying shell syntax must reach bash verbatim, not as a
    // single quoted command name.
    let out = Command::new(env!("CARGO_BIN_EXE_sp"))
        .args(["--host", &harness().host, "echo 333 | grep 3"])
        .output()
        .expect("run sp");
    assert_eq!(out.status.code(), Some(0), "{}", out_str(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "333\n");
}

/// `--timeout` beyond the 24 h bound is rejected at argument parsing, before
/// any daemon or host contact; no guard needed for a pure CLI failure.
#[tokio::test]
async fn cli_rejects_huge_timeout() {
    let out = Command::new(env!("CARGO_BIN_EXE_sp"))
        .args(["--timeout", "99999999999999999", "--host", "ls", "true"])
        .output()
        .expect("run sp");
    assert_eq!(out.status.code(), Some(2));
    let err = out_str(&out.stderr);
    assert!(
        err.contains("exceeds the maximum"),
        "expected a timeout bound error: {err}"
    );
}

#[tokio::test]
async fn push_pull_roundtrip() {
    let Some(_g) = guard().await else { return };
    // Binary + UTF-8 payload: both directions must be byte-exact.
    let mut payload = b"line-one\n\x00\xff\x01binary\n".to_vec();
    payload.extend_from_slice("你好，世界\n".as_bytes());
    let remote = format!("/tmp/sp-push-test-{}", std::process::id());
    let up = client::upload_request(
        harness().host.clone(),
        shell_proxy::session::DEFAULT_NAME.to_owned(),
        &remote,
        None,
        None,
    );
    let (_tx, rx) = mpsc::channel(1);
    let (rep, ..) = client::run_captured(up, payload.clone(), rx).await.unwrap();
    assert_eq!(rep.code, 0, "push must succeed");
    let down = client::download_request(
        harness().host.clone(),
        shell_proxy::session::DEFAULT_NAME.to_owned(),
        &remote,
        None,
        None,
    );
    let (_tx, rx) = mpsc::channel(1);
    let (rep2, out, _) = client::run_captured(down, Vec::new(), rx).await.unwrap();
    assert_eq!(rep2.code, 0);
    assert_eq!(out, payload);
    run(&format!("rm -f {remote}"), None, None).await.unwrap();
}

#[tokio::test]
async fn push_to_missing_dir_reports_error() {
    let Some(_g) = guard().await else { return };
    let remote = format!("/nonexistent-sp-test-{}/f", std::process::id());
    let up = client::upload_request(
        harness().host.clone(),
        shell_proxy::session::DEFAULT_NAME.to_owned(),
        &remote,
        None,
        None,
    );
    let (_tx, rx) = mpsc::channel(1);
    let (rep, _, err) = client::run_captured(up, b"x".to_vec(), rx).await.unwrap();
    assert_ne!(rep.code, 0);
    assert!(out_str(&err).contains("No such file"));
}

#[tokio::test]
async fn cli_push_pull_files() {
    let Some(_g) = guard().await else { return };
    let dir = tempfile::tempdir().unwrap();
    let payload = b"cli \x00\xff roundtrip\n".to_vec();
    let local = dir.path().join("payload.bin");
    std::fs::write(&local, &payload).unwrap();
    let remote = format!("/tmp/sp-cli-push-{}", std::process::id());
    let st = Command::new(env!("CARGO_BIN_EXE_sp"))
        .args([
            "--host",
            &harness().host,
            "push",
            &local.to_string_lossy(),
            &remote,
        ])
        .output()
        .expect("run sp");
    assert_eq!(st.status.code(), Some(0), "{}", out_str(&st.stderr));
    let back = dir.path().join("back.bin");
    let st2 = Command::new(env!("CARGO_BIN_EXE_sp"))
        .args([
            "--host",
            &harness().host,
            "pull",
            &remote,
            &back.to_string_lossy(),
        ])
        .output()
        .expect("run sp");
    assert_eq!(st2.status.code(), Some(0), "{}", out_str(&st2.stderr));
    assert_eq!(std::fs::read(&back).unwrap(), payload);
    run(&format!("rm -f {remote}"), None, None).await.unwrap();
}

#[tokio::test]
async fn cli_doctor_reports_remote() {
    let Some(_g) = guard().await else { return };
    let out = Command::new(env!("CARGO_BIN_EXE_sp"))
        .args(["--host", &harness().host, "doctor"])
        .output()
        .expect("run sp");
    assert_eq!(out.status.code(), Some(0), "{}", out_str(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("os: Linux"), "doctor output: {text}");
    assert!(text.contains("bash:"), "doctor output: {text}");
}

#[tokio::test]
async fn sessions_isolate_cwd() {
    let Some(_g) = guard().await else { return };
    let a = unique_session("iso-cwd-a");
    let b = unique_session("iso-cwd-b");
    let (_, d_before, _) = run("pwd", None, None).await.unwrap();

    run_in(&a, "cd /tmp", None, None).await.unwrap();
    run_in(&b, "cd /usr", None, None).await.unwrap();
    let (rep, out, _) = run_in(&a, "pwd", None, None).await.unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(out_str(&out).trim(), "/tmp");
    let (rep, out, _) = run_in(&b, "pwd", None, None).await.unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(out_str(&out).trim(), "/usr");

    // the default bucket is a third, independent state
    let (_, d_after, _) = run("pwd", None, None).await.unwrap();
    assert_eq!(out_str(&d_before), out_str(&d_after));
}

#[tokio::test]
async fn sessions_isolate_state() {
    let Some(_g) = guard().await else { return };
    let a = unique_session("iso-st-a");
    let b = unique_session("iso-st-b");

    run_in(&a, "export SP_MARK=a", None, None).await.unwrap();
    let (_, out, _) = run_in(&b, "echo [$SP_MARK]", None, None).await.unwrap();
    assert_eq!(
        out_str(&out).trim(),
        "[]",
        "session b must not see a's vars"
    );

    run_in(&b, "export SP_MARK=b", None, None).await.unwrap();
    let (_, out, _) = run_in(&a, "echo $SP_MARK", None, None).await.unwrap();
    assert_eq!(out_str(&out).trim(), "a", "b's export must not leak into a");
}

#[tokio::test]
async fn sessions_execute_concurrently() {
    let Some(_g) = guard().await else { return };
    let a = unique_session("conc-a");
    let b = unique_session("conc-b");
    let started = Instant::now();
    let fa = {
        let a = a.clone();
        tokio::spawn(async move { run_in(&a, "sleep 3; echo done-a", None, Some(30_000)).await })
    };
    let fb = {
        let b = b.clone();
        tokio::spawn(async move { run_in(&b, "sleep 3; echo done-b", None, Some(30_000)).await })
    };
    let (ra, rb) = tokio::join!(fa, fb);
    let (rep_a, out_a, _) = ra.expect("task a").expect("exec a");
    let (rep_b, out_b, _) = rb.expect("task b").expect("exec b");
    assert_eq!(rep_a.code, 0);
    assert_eq!(rep_b.code, 0);
    assert_eq!(out_str(&out_a).trim(), "done-a");
    assert_eq!(out_str(&out_b).trim(), "done-b");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "two sessions must run in parallel over one connection, took {:?}",
        started.elapsed()
    );
}

/// Killing the connection's sshd drops the SSH transport mid-command; the
/// daemon evicts only the host connection and the session's cwd/state survive
/// the reconnect (pre-session daemon lost them with the whole host state).
#[tokio::test]
async fn reconnect_preserves_session_state() {
    let Some(_g) = guard().await else { return };
    let s = unique_session("recon");
    run_in(&s, "cd /tmp", None, None).await.unwrap();
    // Kill the sshd serving this connection (parent of sp-serve, parent of
    // the wrapper whose $PPID we see). The killing exec itself loses its
    // channel before the exit report - that is the point.
    let _ = run_in(&s, "kill $(ps -o ppid= -p $PPID)", None, Some(10_000)).await;
    // The reconnect may race the dead-link detection in the daemon; allow the
    // first attempt(s) to surface the dropped connection as an error.
    let (rep, out, _) = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match run_in(&s, "pwd", None, Some(30_000)).await {
                Ok(r) => break r,
                Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        }
    })
    .await
    .expect("reconnect must succeed eventually");
    assert_eq!(rep.code, 0);
    assert_eq!(
        out_str(&out).trim(),
        "/tmp",
        "session cwd must survive the reconnect"
    );
}
