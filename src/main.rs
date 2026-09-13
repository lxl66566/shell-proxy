//! `sp` - run local commands on a remote Linux host with persistent shell state.

use std::{io::IsTerminal, path::PathBuf, process::ExitCode};

use clap::{CommandFactory, Parser, Subcommand};
use shell_proxy::{
    client::{self, RunIo},
    config, console,
    proto::{self, ExecRequest, Signal},
};
use tokio::sync::mpsc;

/// Exit code for daemon/internal errors.
const EXIT_INTERNAL: u8 = proto::INTERNAL_ERROR_CODE as u8;
/// Exit code for timed-out commands, matching timeout(1).
const EXIT_TIMEOUT: u8 = proto::TIMEOUT_EXIT_CODE as u8;

#[derive(Parser)]
#[command(
    name = "sp",
    version,
    about = "Run commands on a remote Linux host with persistent shell state",
    arg_required_else_help = false
)]
struct Cli {
    /// Remote host alias (ssh config), overrides config/env
    #[arg(long, global = true)]
    host: Option<String>,

    /// Starting directory for this command (becomes the persisted cwd)
    #[arg(long, global = true)]
    cwd: Option<String>,

    /// Kill the command after SECONDS seconds (0 = unlimited)
    #[arg(long, global = true)]
    timeout: Option<u64>,

    /// Execute the given script file instead of the command line
    #[arg(short, long)]
    file: Option<PathBuf>,

    #[command(subcommand)]
    sub: Option<Sub>,

    /// Command with arguments, passed to the remote bash
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    cmd: Vec<std::ffi::OsString>,
}

#[derive(Subcommand)]
enum Sub {
    /// Run the resident daemon in the foreground
    Daemon,
    /// Run as an MCP server on stdio
    Mcp,
    /// Check whether the daemon is running
    Status,
}

fn main() -> ExitCode {
    // Manual runtime: `shutdown_background` below must not wait for parked
    // blocking tasks. `tokio::io::stdin()` reads are dispatched to the
    // blocking pool, and a console read only completes on Enter - with the
    // default `#[tokio::main]` teardown the process would hang on exit until
    // the user pressed a key.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = rt.block_on(async_main());
    rt.shutdown_background();
    code
}

async fn async_main() -> ExitCode {
    let cli = Cli::parse();

    match cli.sub {
        Some(Sub::Daemon) => match shell_proxy::daemon::run().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sp: daemon error: {}", e.brief());
                ExitCode::from(EXIT_INTERNAL)
            },
        },
        Some(Sub::Mcp) => match shell_proxy::mcp::run().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sp: mcp error: {e:#}");
                ExitCode::from(EXIT_INTERNAL)
            },
        },
        Some(Sub::Status) => match client::ping().await {
            Ok(pid) => {
                println!("daemon running (pid {pid})");
                ExitCode::SUCCESS
            },
            Err(e) => {
                eprintln!("sp: {e}");
                ExitCode::FAILURE
            },
        },
        None => run_command(cli).await,
    }
}

async fn run_command(cli: Cli) -> ExitCode {
    let (command, args) = match build_command(&cli) {
        Ok(Some(x)) => x,
        Ok(None) => {
            Cli::command().print_help().expect("print help");
            return ExitCode::from(2);
        },
        Err(e) => {
            eprintln!("sp: {e}");
            return ExitCode::from(EXIT_INTERNAL);
        },
    };

    let host = match config::resolve_host(cli.host.as_deref()) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("sp: {e}");
            return ExitCode::from(EXIT_INTERNAL);
        },
    };

    let req = ExecRequest {
        host,
        command,
        args,
        cwd: cli.cwd,
        timeout_ms: cli.timeout.map(|s| s.saturating_mul(1000)),
    };

    let (sig_tx, sig_rx) = mpsc::channel::<Signal>(4);
    console::install(sig_tx);

    // A terminal stdin is not forwarded (no TUI support): typing would compete
    // with the console for input and keep a blocking read parked. Piped stdin
    // is forwarded as usual.
    let stdin: Box<dyn tokio::io::AsyncRead + Send + Unpin> = if std::io::stdin().is_terminal() {
        Box::new(tokio::io::empty())
    } else {
        Box::new(tokio::io::stdin())
    };

    let io = RunIo {
        stdin,
        stdout: Box::new(tokio::io::stdout()),
        stderr: Box::new(tokio::io::stderr()),
    };

    match client::run(req, io, sig_rx).await {
        Ok(report) => {
            if let Some(e) = &report.error {
                eprintln!("sp: {e}");
            }
            if report.timed_out {
                eprintln!("sp: command timed out");
                return ExitCode::from(EXIT_TIMEOUT);
            }
            // Out-of-range codes never come from a shell; treat them as internal errors.
            ExitCode::from(u8::try_from(report.code).unwrap_or(EXIT_INTERNAL))
        },
        Err(e) => {
            eprintln!("sp: {e}");
            ExitCode::from(EXIT_INTERNAL)
        },
    }
}

/// Build the command text: file mode, positional args, or piped stdin.
fn build_command(cli: &Cli) -> shell_proxy::Result<Option<(String, Vec<String>)>> {
    let cmd_args = || {
        cli.cmd
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect::<Vec<String>>()
    };
    if let Some(file) = &cli.file {
        let text = client::read_script_file(file)?;
        // Trailing args after `--` become the script's positional parameters.
        return Ok(Some((text, cmd_args())));
    }
    if !cli.cmd.is_empty() {
        return Ok(Some((cmd_args().join(" "), Vec::new())));
    }
    if !std::io::stdin().is_terminal() {
        let mut script = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut script)?;
        if !script.is_empty() {
            return Ok(Some((script, Vec::new())));
        }
    }
    Ok(None)
}
