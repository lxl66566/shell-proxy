//! sp-serve: remote execution server of shell-proxy.
//!
//! Deployed to the remote host by the daemon and started once per command as
//! an SSH exec program. Speaks the sp-proto frame protocol on stdio: one
//! `Exec` request in, `Stdout`/`Stderr`/`Exit` frames out. All diagnostics go
//! to real stderr (SSH extended data), which the daemon writes to its log.

#[cfg(unix)]
mod child;
#[cfg(unix)]
mod serve;
// Pure bash-string templates with no libc dependency; compiled on every
// platform under test so its assertions also run on Windows dev machines.
#[cfg(any(unix, test))]
mod wrapper;

fn main() {
    // Exact `sp-serve <version>` format, no prefix or suffix: the daemon
    // matches it to detect stale binaries deployed via SP_SERVE_* overrides.
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("sp-serve {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    serve_main();
}

#[cfg(unix)]
fn serve_main() -> ! {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = rt.block_on(serve::run());
    // Skip runtime teardown: a blocking stdin read may still be parked and
    // must not delay the exit status report.
    std::process::exit(code);
}

#[cfg(not(unix))]
fn serve_main() {
    eprintln!("sp-serve only runs on unix targets");
    std::process::exit(2);
}
