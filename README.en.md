# shell-proxy

[简体中文](./README.md) | English

<details>
<summary>Preface</summary>

Freeloading idle-time tasks on GLM zcode is [a great deal](https://t.me/withabsolutex/2824), but its biggest limitation is that tasks can only run locally, not over ssh. My perf-first project drifts too much in performance on WSL, so it has to run on my Linux server. Hence I built this tool as a shell proxy, so that idle-time tasks can run on my server.

</details>

Execute bash commands on a remote Linux machine.

- stdout / stderr / stdin / pipes / exit codes / Ctrl+C are all forwarded faithfully
- cwd + shell state (env, functions, aliases, umask, shopt) persist across invocations
- Multiple sessions: independent shell state buckets running in parallel on one host
- The remote side runs an interactive bash that loads `~/.bashrc`
- `sp push` / `sp pull` for file transfer; `sp -f` to run local scripts
- Works as an MCP server for AI agents

## Installation

Download a prebuilt binary from the [releases](https://github.com/lxl66566/shell-proxy/releases) page.

## Usage

```sh
# First-time setup (host is your ssh target)
echo 'host = "root@127.0.0.1"' > ~/.config/shell-proxy/config.toml

sp ls -alF                     # run a command
sp "echo 333 | grep 3"         # pipes, quotes: quoting the whole line is most reliable
sp cd /root && sp pwd          # cwd persists across invocations -> /root
sp --cwd /var pwd              # set the starting directory for this invocation
sp -f deploy.sh                # run a local script; positional args ($1 $2) go after --
echo data | sp cat             # stdin forwarding
sp --timeout 60 make           # exit code 124 on timeout
sp push patch.py /tmp/x.py     # upload a file (local `-` reads stdin)
sp pull /etc/os-release -      # download a file (local `-` writes stdout)
sp doctor                      # diagnose local/daemon/remote environment

# Sessions: --session (or the SP_SESSION env var) selects an independent
# state bucket; cwd/env of different sessions on one host never mix, and
# sessions run in parallel
sp --session a cd /root && sp --session b cd /tmp
sp --session a pwd             # -> /root
```

Argument assembly: if a single argument contains shell syntax, it is passed verbatim to the remote bash; with multiple arguments, each is quoted and joined with spaces, so word boundaries are preserved. For complex scripts use `-f` or `cat script.sh | sp`.

Exit codes: a remote command's exit code is returned as-is, 128+n when it is killed by a signal; a command force-terminated on timeout reports 124 (as timeout(1) does); daemon/connection errors report 254. A remote command whose real exit code is exactly 124 or 254 is indistinguishable from sp's internal meanings.

Session names match `[A-Za-z0-9._-]` and are at most 64 bytes; unspecified means `default`. Sessions live as long as the daemon: when it exits, state resets.

## Architecture

```
sp CLI / MCP --IPC--> local daemon (one long-lived SSH connection per host + cwd/shell state per (host, session)) --> remote sp-serve --> bash
```

The daemon is started automatically if absent, and deploys the embedded `sp-serve` to the remote host on connect (the file name carries the version and the content is sha256-verified) — zero setup on the server side. No ports are opened; authentication and encryption are handled by SSH, with known_hosts matching compatible with OpenSSH wildcards, hostkeyalias, and @revoked entries (host certificates get no CA verification and are rejected in strict mode). Host configuration (aliases, ProxyJump, etc.) is resolved via `ssh -G`. The persisted shell state covers cwd, env, functions, aliases, umask, and shopt, bucketed independently per session. Daemon logs rotate by size (10 MB × 3 files).

## MCP

`sp mcp` serves five tools over stdio: `exec` / `read_file` / `write_file` / `read_file_binary` / `write_file_binary` (binary content is base64-encoded). Command text goes straight to the remote bash, so there are no local shell quoting issues; cwd persists across invocations. Every tool takes optional `session` and `host` parameters, selecting an independent state bucket and the target host; a failed exec (non-zero exit code, internal error, or timeout) sets isError=true, and the result ends with the current cwd.

For two AI agents working in parallel on the same host, pin one `SP_SESSION` each (one `sp mcp` process per agent, invisible to the agent):

```json
{ "mcpServers": {
    "sp-a": { "command": "sp", "args": ["mcp"], "env": { "SP_SESSION": "agent-a" } },
    "sp-b": { "command": "sp", "args": ["mcp"], "env": { "SP_SESSION": "agent-b" } }
} }
```

## Configuration

`~/.config/shell-proxy/`, or `%APPDATA%\shell-proxy\` on Windows, following the XDG spec:

```toml
host = "lse"               # default host alias
log_level = "info"
default_timeout_secs = 0   # default CLI command timeout in seconds, 0 = unlimited
```

Priority: `--host` > `SP_HOST` > config.toml; sessions: `--session` / tool parameter > `SP_SESSION` > `default`. Authentication prefers ssh-agent, then IdentityFile (add encrypted keys to your agent).

CLI timeout: an explicit `--timeout` wins, otherwise `default_timeout_secs` applies, capped at 24 h; MCP exec takes its own `timeout_ms` parameter (default 10 minutes).

Daemon logs live at `<config_dir>/shell-proxy/logs/daemon.log`, recording the time, host, session, cwd, exit code, duration, and command content for every command.

## Known limitations

- Remote supports x86_64 / aarch64 Linux with `bash` on PATH; requires a mounted `/proc` and kernel 3.17+ (the rcfile, command text, and state all travel through memfd + `/dev/fd`), and a writable deploy directory `~/.local/share/shell-proxy`
- No tty/pty, so TUIs and fullscreen programs like `top` are unsupported; terminal stdin (running `sp cat` without redirection) gets an immediate EOF, unlike ssh; piped stdin works fine
- State dumps are capped at 256 KB; when the cap is exceeded, that state update is dropped and the previous state is kept
- Orphan processes still holding the output pipes after the command ends: tail output is dropped after about 2 s without output progress
- When the local client exits early (broken pipe), the remote process is not killed: the command runs to completion but its output is dropped; ssh instead kills the remote on disconnect (double Ctrl+C force-exits locally with 130)
- `push` / `pull` transfer a single file only, no directory recursion
- `-f` scripts and the MCP text tools are UTF-8 only (use `push` / `pull` or the base64 tools for binaries)

## Testing

```sh
cargo test --workspace
SP_TEST_HOST=lse cargo nextest run
```

Integration tests connect to the host named by `SP_TEST_HOST` (default "ls") and auto-skip when it is unreachable; both `cargo test` and nextest are supported.

## License

MIT OR Apache-2.0
