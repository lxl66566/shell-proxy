//! Terminal signal capture: forward Ctrl+C (and Unix SIGTERM) to the daemon
//! instead of dying, so the exit code of the interrupted remote command is
//! still reported.

use tokio::sync::mpsc;

use crate::ipc::Signal;

/// Install handlers that forward SIGINT/SIGTERM to `tx`.
///
/// Call at most once per process. Windows needs a static sink because the
/// console API takes a plain function pointer.
#[cfg(windows)]
pub fn install(tx: mpsc::Sender<Signal>) {
    static SINK: std::sync::OnceLock<mpsc::Sender<Signal>> = std::sync::OnceLock::new();
    let _ = SINK.set(tx);

    unsafe extern "system" fn handler(ctrl_type: u32) -> i32 {
        const CTRL_C_EVENT: u32 = 0;
        const CTRL_BREAK_EVENT: u32 = 1;
        const TRUE: i32 = 1;
        let sig = match ctrl_type {
            CTRL_C_EVENT | CTRL_BREAK_EVENT => Signal::Int,
            _ => return 0, // close/logoff: default handling kills us anyway
        };
        if let Some(tx) = SINK.get() {
            let _ = tx.try_send(sig);
        }
        TRUE // handled: keep running until the remote exit code arrives
    }

    // SAFETY: `handler` is a valid extern function; registration is idempotent.
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(handler), 1);
    }
}

#[cfg(unix)]
pub fn install(tx: mpsc::Sender<Signal>) {
    use signal_hook::{
        consts::{SIGINT, SIGTERM},
        iterator::Signals,
    };

    let mut signals = Signals::new([SIGINT, SIGTERM]).expect("register signal handlers");
    std::thread::spawn(move || {
        for sig in signals.forever() {
            let s = if sig == SIGTERM {
                Signal::Term
            } else {
                Signal::Int
            };
            if tx.blocking_send(s).is_err() {
                return;
            }
        }
    });
}
