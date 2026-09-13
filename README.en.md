# shell-proxy

[简体中文](./README.md) | English

<details>
<summary>Preface</summary>

Freeloading idle-time tasks on GLM zcode is [a great deal](https://t.me/withabsolutex/2824), but its biggest limitation is that tasks can only run locally, not over ssh. My perf-first project drifts too much in performance on WSL, so it has to run on my Linux server. Hence I built this tool as a shell proxy, so that idle-time tasks can run on my server.

</details>

Execute bash commands on a remote Linux machine.

- stdout / stderr / stdin / pipes / exit codes / Ctrl+C are all forwarded faithfully
- cwd + env persist across invocations
- The remote side runs an interactive bash that loads `~/.bashrc`
- `sp push` / `sp pull` for file transfer; `sp -f` to run local scripts
- Works as an MCP server for AI agents

## Installation

Download a prebuilt binary from the [Releases](https://github.com/lxl66566/shell-proxy/Releases) page.

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
```

Argument assembly: if a single argument contains shell syntax, it is passed verbatim to the remote bash; with multiple arguments, each is quoted and joined with spaces, so word boundaries are preserved. For complex scripts use `-f` or `cat script.sh | sp`.

Exit codes: remote commands return as-is; 124 on timeout; 254 for daemon/connection errors.

## Architecture

```
sp CLI / MCP --IPC--> local daemon (persistent SSH connection + cwd state) --> remote sp-serve --> bash
```

The daemon is started automatically if absent, and deploys the embedded `sp-serve` to the remote host on connect — zero setup on the server side. No ports are opened; authentication and encryption are handled by SSH. Host configuration (aliases, ProxyJump, etc.) is resolved via `ssh -G`.

## MCP

`sp mcp` serves three tools over stdio: `exec` / `read_file` / `write_file`. Command text goes straight to the remote bash, so there are no local shell quoting issues; cwd persists across invocations.

```json
{ "mcpServers": { "sp": { "command": "sp", "args": ["mcp"] } } }
```

## Configuration

`~/.config/shell-proxy/`, or `%APPDATA%\shell-proxy\` on Windows, following the XDG spec:

```toml
host = "lse"       # default host alias
log_level = "info"
```

Priority: `--host` > `SP_HOST` > config.toml. Authentication prefers ssh-agent, then IdentityFile (add encrypted keys to your agent).

Daemon logs live at `<config_dir>/shell-proxy/logs/daemon.log`, recording the time, host, cwd, exit code, duration, and command content for every command.

## Known limitations

- Remote supports x86_64 / aarch64 Linux with `bash` on PATH
- No tty/pty, so TUIs and fullscreen programs like `top` are unsupported; piped stdin works fine
- `push` / `pull` transfer a single file only, no directory recursion
- `-f` scripts and `read_file` / `write_file` are UTF-8 only (use `push` / `pull` for binaries)

## Testing

```sh
cargo test --workspace
SP_TEST_HOST=lse cargo nextest run   # requires a reachable real host; auto-skipped otherwise
```

## License

MIT OR Apache-2.0
