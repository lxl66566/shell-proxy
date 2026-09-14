//! `sp` - run local commands on a remote Linux host with persistent shell state.

use std::{io::IsTerminal, path::PathBuf, process::ExitCode};

use clap::{CommandFactory, Parser, Subcommand};
use shell_proxy::{
    client::{self, RunIo, is_bare_word},
    config, console,
    proto::{self, ExecRequest, Signal},
};
use tokio::sync::mpsc;

/// Exit code for daemon/internal errors. Fits u8; pinned by a sp-proto test.
#[allow(clippy::cast_possible_truncation)]
const EXIT_INTERNAL: u8 = proto::INTERNAL_ERROR_CODE as u8;
/// Exit code for timed-out commands, matching timeout(1).
#[allow(clippy::cast_possible_truncation)]
const EXIT_TIMEOUT: u8 = proto::TIMEOUT_EXIT_CODE as u8;

/// Timeout (ms) for the `doctor` remote probe.
const DOCTOR_TIMEOUT_MS: u64 = 30_000;

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
    /// Copy a local file to the remote host
    Push {
        /// Local path, or "-" to read stdin
        local: PathBuf,
        /// Remote path (relative to the persisted cwd), truncated on write
        remote: String,
    },
    /// Copy a remote file to the local machine
    Pull {
        /// Remote path (relative to the persisted cwd)
        remote: String,
        /// Local path, or "-" to write stdout
        local: PathBuf,
    },
    /// Show local and remote environment diagnostics
    Doctor,
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

    match &cli.sub {
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
        Some(Sub::Push { local, remote }) => run_push(&cli, local, remote).await,
        Some(Sub::Pull { remote, local }) => run_pull(&cli, remote, local).await,
        Some(Sub::Doctor) => run_doctor(&cli).await,
        None => run_command(cli).await,
    }
}

/// Resolve the host or print the error and bail with the internal exit code.
fn resolve_host_or_fail(cli: &Cli) -> Option<String> {
    match config::resolve_host(cli.host.as_deref()) {
        Ok(h) => Some(h),
        Err(e) => {
            eprintln!("sp: {e}");
            None
        },
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

    let Some(host) = resolve_host_or_fail(&cli) else {
        return ExitCode::from(EXIT_INTERNAL);
    };

    let req = ExecRequest {
        host,
        command,
        args,
        cwd: cli.cwd,
        state: None,
        timeout_ms: cli.timeout.map(timeout_ms),
    };

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
    exec_with_console(req, io).await
}

/// `sp push`: stream a local file (or stdin) into a remote path.
async fn run_push(cli: &Cli, local: &std::path::Path, remote: &str) -> ExitCode {
    let Some(host) = resolve_host_or_fail(cli) else {
        return ExitCode::from(EXIT_INTERNAL);
    };
    let stdin: Box<dyn tokio::io::AsyncRead + Send + Unpin> = if local.as_os_str() == "-" {
        if std::io::stdin().is_terminal() {
            eprintln!("sp: `-` reads stdin, but stdin is a terminal; pipe data in or name a file");
            return ExitCode::from(EXIT_INTERNAL);
        }
        Box::new(tokio::io::stdin())
    } else {
        match tokio::fs::File::open(local).await {
            Ok(f) => Box::new(f),
            Err(e) => {
                eprintln!("sp: open {}: {e}", local.display());
                return ExitCode::from(EXIT_INTERNAL);
            },
        }
    };
    let io = RunIo {
        stdin,
        stdout: Box::new(tokio::io::stdout()),
        stderr: Box::new(tokio::io::stderr()),
    };
    let req = client::upload_request(host, remote, cli.cwd.clone(), cli.timeout.map(timeout_ms));
    exec_with_console(req, io).await
}

/// `sp pull`: stream a remote file to a local path (or stdout).
async fn run_pull(cli: &Cli, remote: &str, local: &std::path::Path) -> ExitCode {
    let Some(host) = resolve_host_or_fail(cli) else {
        return ExitCode::from(EXIT_INTERNAL);
    };
    let stdout: Box<dyn tokio::io::AsyncWrite + Send + Unpin> = if local.as_os_str() == "-" {
        Box::new(tokio::io::stdout())
    } else {
        match tokio::fs::File::create(local).await {
            Ok(f) => Box::new(f),
            Err(e) => {
                eprintln!("sp: create {}: {e}", local.display());
                return ExitCode::from(EXIT_INTERNAL);
            },
        }
    };
    let io = RunIo {
        stdin: Box::new(tokio::io::empty()),
        stdout,
        stderr: Box::new(tokio::io::stderr()),
    };
    let req = client::download_request(host, remote, cli.cwd.clone(), cli.timeout.map(timeout_ms));
    exec_with_console(req, io).await
}

/// `sp doctor`: report local setup, daemon state and the remote environment.
///
/// The remote probe runs through the normal execution path, so a success
/// proves the whole chain (config -> daemon -> ssh -> serve -> bash).
async fn run_doctor(cli: &Cli) -> ExitCode {
    println!(
        "sp {} ({} {})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!(
        "config: {}",
        config::app_dir().join("config.toml").display()
    );

    let source = if cli.host.is_some() {
        "--host"
    } else if std::env::var_os(config::ENV_HOST).is_some_and(|v| !v.is_empty()) {
        config::ENV_HOST
    } else {
        "config.toml"
    };
    let Some(host) = resolve_host_or_fail(cli) else {
        return ExitCode::from(EXIT_INTERNAL);
    };
    println!("host: {host} (from {source})");

    match client::ping().await {
        Ok(pid) => println!("daemon: running (pid {pid})"),
        Err(_) => println!("daemon: not running (starts on first use)"),
    }

    let req = ExecRequest {
        host,
        command: r#"echo "os: $(uname -srm)"; echo "bash: $(bash --version | head -1)"; echo "home: $HOME"; echo "cwd: $PWD""#.into(),
        args: Vec::new(),
        cwd: cli.cwd.clone(),
        state: None,
        timeout_ms: Some(DOCTOR_TIMEOUT_MS),
    };
    let io = RunIo {
        stdin: Box::new(tokio::io::empty()),
        stdout: Box::new(tokio::io::stdout()),
        stderr: Box::new(tokio::io::stderr()),
    };
    exec_with_console(req, io).await
}

/// Run one request with console signal forwarding and map the report to an
/// exit code, the shared tail of every exec-like subcommand.
async fn exec_with_console(req: ExecRequest, io: RunIo<'_>) -> ExitCode {
    let (sig_tx, sig_rx) = mpsc::channel::<Signal>(4);
    console::install(sig_tx);

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

fn timeout_ms(secs: u64) -> u64 {
    secs.saturating_mul(1000)
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
        // A lone argument that is not a bare word carries shell syntax the
        // local shell made the user quote (`sp "a | b"`): run it verbatim as a
        // command line, like ssh. Several arguments are words whose boundaries
        // must survive (`sp grep "a b" f`): re-quote each before joining.
        if let [only] = cli.cmd.as_slice()
            && !is_bare_word(&only.to_string_lossy())
        {
            return Ok(Some((only.to_string_lossy().into_owned(), Vec::new())));
        }
        return Ok(Some((join_command(&cmd_args()), Vec::new())));
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

/// A single arg is a whole command line and must reach the remote bash
/// verbatim (`sp "a | b"` would break if quoted). Multiple args arrive
/// shell-dequoted from the local shell; re-quote each one so the remote bash
/// parses the joined line back into the same words (`sp echo "a b"` stays one
/// remote argument).
fn join_command(args: &[String]) -> String {
    match args {
        [single] => single.clone(),
        many => many
            .iter()
            .map(|s| client::shell_quote(s))
            .collect::<Vec<_>>()
            .join(" "),
    }
}

#[cfg(test)]
mod tests {
    use super::join_command;

    #[test]
    fn single_arg_is_verbatim() {
        // Quoting a lone arg would turn the whole line into one command name.
        assert_eq!(
            join_command(&["echo $X | grep 3".into()]),
            "echo $X | grep 3"
        );
        assert_eq!(join_command(&["ls".into()]), "ls");
    }

    #[test]
    fn joins_multiple_quoted_args() {
        assert_eq!(join_command(&["ls".into(), "-alF".into()]), "ls -alF");
        assert_eq!(join_command(&["echo".into(), "a b".into()]), "echo 'a b'");
    }

    #[test]
    fn quotes_embedded_quotes() {
        assert_eq!(
            join_command(&["echo".into(), "it's".into()]),
            "echo 'it'\\''s'"
        );
    }
}
