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
    time::Duration,
};

use shell_proxy::{
    client::{self, RunReport},
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
        // SP_IDLE_SECS, and OnceLock serializes this initialization, so no
        // thread reads these variables while they are being written.
        unsafe {
            std::env::set_var("SP_SOCK", &sock);
            std::env::set_var("SP_IDLE_SECS", "300");
        }

        // The daemon must not inherit our handles (std::process::Command
        // inherits all of them on Windows and would pin the test runner's
        // pipes open forever); spawn_daemon gets this right.
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
    };
    let (_tx, rx) = mpsc::channel(1);
    client::run_captured(req, Vec::new(), rx).await
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
    let (rep, out, _) = run("seq 1 100000", None, None).await.unwrap();
    assert_eq!(rep.code, 0);
    let text = out_str(&out);
    assert_eq!(text.lines().count(), 100_000);
    assert!(text.ends_with("100000\n"));
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
    };
    let (_tx, rx) = mpsc::channel(1);
    let (rep, out, _) = client::run_captured(req, b"line-one\nline-two\n".to_vec(), rx)
        .await
        .unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(out_str(&out), "line-one\nline-two\n");
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
async fn timeout_kills_command() {
    let Some(_g) = guard().await else { return };
    let started = std::time::Instant::now();
    let (rep, ..) = run("sleep 60", None, Some(1500)).await.unwrap();
    assert!(rep.timed_out, "expected timeout");
    assert_eq!(rep.code, 124);
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test]
async fn sigint_forwards_to_remote() {
    let Some(_g) = guard().await else { return };
    let req = ExecRequest {
        host: harness().host.clone(),
        command: "sleep 60".into(),
        args: vec![],
        cwd: None,
        timeout_ms: None,
    };
    let (tx, rx) = mpsc::channel(1);
    let spawned = tokio::spawn(client::run_captured(req, Vec::new(), rx));
    tokio::time::sleep(Duration::from_millis(800)).await;
    tx.send(Signal::Int).await.unwrap();
    let started = std::time::Instant::now();
    let (rep, ..) = spawned.await.unwrap().unwrap();
    assert_eq!(rep.code, 130, "SIGINT should surface as 130");
    assert!(started.elapsed() < Duration::from_secs(5));
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
    let (rep, out, _) = run(
        "ls ~/.local/share/shell-proxy/sp-serve-*-* | wc -l",
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(rep.code, 0);
    assert_eq!(out_str(&out).trim(), "1", "exactly one sp-serve binary");
    let (rep2, out2, _) = run(
        "test -x ~/.local/share/shell-proxy/sp-serve-*-* && echo executable",
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(rep2.code, 0);
    assert_eq!(out_str(&out2).trim(), "executable");
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
