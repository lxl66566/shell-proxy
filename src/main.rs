//! `sp` - run local commands on a remote Linux host with persistent shell state.

use std::{io::IsTerminal, path::PathBuf, process::ExitCode};

use clap::{CommandFactory, Parser, Subcommand};
use shell_proxy::{
    client::{self, RunIo},
    config, console,
    ipc::{ExecRequest, Signal},
};
use tokio::sync::mpsc;

/// Exit code for daemon/internal errors.
const EXIT_INTERNAL: u32 = 254;
/// Exit code for timed-out commands, matching timeout(1).
const EXIT_TIMEOUT: u32 = 124;

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

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.sub {
        Some(Sub::Daemon) => match shell_proxy::daemon::run().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sp: daemon error: {}", e.brief());
                ExitCode::from(EXIT_INTERNAL as u8)
            },
        },
        Some(Sub::Mcp) => match shell_proxy::mcp::run().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sp: mcp error: {e:#}");
                ExitCode::from(EXIT_INTERNAL as u8)
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
            return ExitCode::from(EXIT_INTERNAL as u8);
        },
    };

    let host = match config::resolve_host(cli.host.as_deref()) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("sp: {e}");
            return ExitCode::from(EXIT_INTERNAL as u8);
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

    let io = RunIo {
        stdin: Box::new(tokio::io::stdin()),
        stdout: Box::new(tokio::io::stdout()),
        stderr: Box::new(tokio::io::stderr()),
    };

    match client::run(req, io, sig_rx).await {
        Ok(report) => {
            if report.timed_out {
                eprintln!("sp: command timed out");
                return ExitCode::from(EXIT_TIMEOUT as u8);
            }
            ExitCode::from(report.code as u8)
        },
        Err(e) => {
            eprintln!("sp: {e}");
            ExitCode::from(EXIT_INTERNAL as u8)
        },
    }
}

/// Build the command text: file mode, positional args, or piped stdin.
fn build_command(cli: &Cli) -> shell_proxy::Result<Option<(String, Vec<String>)>> {
    if let Some(file) = &cli.file {
        let text = client::read_script_file(file)?;
        return Ok(Some((text, Vec::new())));
    }
    if !cli.cmd.is_empty() {
        let joined = cli
            .cmd
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect::<Vec<String>>()
            .join(" ");
        return Ok(Some((joined, Vec::new())));
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
