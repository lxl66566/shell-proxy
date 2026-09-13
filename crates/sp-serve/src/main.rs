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
#[cfg(unix)]
mod wrapper;

#[cfg(unix)]
fn main() -> ! {
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
fn main() {
    eprintln!("sp-serve only runs on unix targets");
    std::process::exit(2);
}
