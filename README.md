# shell-proxy (sp)

让本地命令在远程 Linux 机器上执行，效果如同直接在那台机器的交互式 bash 里敲入。

- 命令前加 `sp` 即可：`sp ls -alF`、`sp "echo 333 | grep 3"`
- 完整转发 stdout / stderr / stdin / 管道 / 退出码 / `command not found`
- Ctrl+C 转发为远端进程组 SIGINT，本地拿到真实的 130 退出码
- **cwd 在多次调用之间保持**（`sp cd /root` 后，下一条命令仍在 /root）
- 远端以交互式 bash 运行，加载 `~/.bashrc`（alias、函数可用）
- 支持作为 MCP server 提供给 AI Agent

## 架构

```
sp CLI / MCP ──IPC(命名管道/socket)──> 本地 daemon ──SSH exec channel──> 远端 sp-serve ──> bash
```

- 常驻 daemon（本机）持有到远端的持久 SSH 连接（russh），并保存每主机的 cwd 状态；`sp` 命令通过 IPC 与 daemon 通信，daemon 不存在时自动拉起（Windows 上用 `CreateProcessW` 禁止句柄继承，避免占住父进程的管道）。
- daemon 在（重）连后把内嵌的 `sp-serve` 静态 musl 二进制部署到远端 `~/.local/share/shell-proxy/sp-serve-<版本>-<架构>`（sha256 校验、临时文件原子改名、权限 0700）。远端零手工配置。
- 每条命令 = 一条 SSH exec channel 上跑一个 `sp-serve` 进程，两端用 sp-proto 帧协议（`[kind][len][payload]`）通信：Exec 请求进，Stdout/Stderr/Exit 帧出。无端口监听，认证加密完全由 SSH 承担。
- `sp-serve` fork 交互式 bash（`setsid` 使子进程成为进程组组长，Ctrl+C/超时 = `kill(-pgid, sig)`）；命令文本经 memfd 传递（不经 shell 字符串拼接），cwd 经专用 fd 带外回传（stdout 字节纯净），`~/.bashrc` 经 `--rcfile` 加载（rcfile 首行恢复被静默的 stderr，吞掉非 tty 下的 job control 警告）。
- 主机配置（别名、端口、IdentityFile、ProxyCommand/ProxyJump、StrictHostKeyChecking）直接复用系统 `ssh -G` 解析结果；known_hosts 严格校验（已记录但变更的密钥始终拒绝）。

## 安装

```sh
cargo install --git https://github.com/lxl66566/shell-proxy
```

二进制名为 `sp`。需要系统 PATH 中有 `ssh`（用于解析 `~/.ssh/config`）。

注意：`sp` 内嵌远端 `sp-serve` 二进制（x86_64 / aarch64 musl）。从源码构建时需先交叉编译：

```sh
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
RUSTFLAGS="-C linker=rust-lld -C target-feature=+crt-static" \
  cargo build --release -p sp-serve --target x86_64-unknown-linux-musl
# (aarch64 同理)
cargo build --release   # build.rs 自动从 target/<triple>/release/ 拾取
```

也可用 `SP_SERVE_X86_64=/path/to/sp-serve` 环境变量显式指定。release 构建已内嵌，无需上述步骤。

## 用法

```sh
# 首次配置：指定默认主机（别名来自 ~/.ssh/config）
mkdir -p ~/.config/shell-proxy && echo 'host = "lse"' > ~/.config/shell-proxy/config.toml
# Windows: $XDG_CONFIG_HOME/shell-proxy/config.toml

sp ls -alF                     # 执行命令
sp "echo 333 | grep 3"         # 管道、引号：整条加引号最可靠
sp cd /root && sp pwd          # cwd 跨调用保持 -> /root
sp --cwd /var pwd              # 本次指定起始目录（并成为新的持久 cwd）
sp "definitely_missing"        # -> stderr: command not found, 退出码 127
echo data | sp cat             # stdin 转发（管道）
sp gcc -o t t.c                # Ctrl+C 会转发到远端，本地拿到真实的 130；1 秒内连按两次则本地强制退出
sp --timeout 60 make           # 超时先向远端进程组发 TERM，5 秒后 KILL，退出码 124
sp -f deploy.sh                # 执行本地脚本文件（多行 bash）
sp -f run.sh -- arg1 "arg 2"   # 位置参数 -> 脚本内 $1 $2
sp status                      # daemon 存活状态
sp daemon                      # 手动前台运行 daemon（通常无需，会自动拉起）
```

命令行参数拼接规则：单参数原样执行；多参数以空格连接。复杂命令建议整体加引号，或用 `-f` 文件执行（本地 shell 不需要能理解该命令）。

退出码约定：远端命令退出码原样返回；超时 124（同 `timeout(1)`）；daemon/连接类错误 254。

## MCP

`sp mcp` 在 stdio 上提供 MCP server，暴露一个工具：

```json
{ "command": "echo hi", "cwd": "/tmp", "timeout_ms": 30000 }
```

返回 `exit_code`、`cwd`、`--- stdout ---`、`--- stderr ---`；cwd 在多次调用间保持。

配置示例（客户端 stdio 方式）：

```json
{ "mcpServers": { "sp": { "command": "sp", "args": ["mcp"] } } }
```

## 配置

`config.toml`（优先 `$XDG_CONFIG_HOME/shell-proxy/`，否则 `~/.config/shell-proxy/` 或 Windows `%APPDATA%\shell-proxy\`）：

```toml
host = "lse"       # 默认主机别名
log_level = "info" # daemon 日志级别
```

环境变量：`SP_HOST`（默认主机）、`SP_SOCK`（daemon socket 覆盖，主要供测试）。
优先级：`--host` > `SP_HOST` > config.toml。

认证：优先 ssh-agent（Windows 为 OpenSSH 管道），其次 IdentityFile（加密私钥请加入 agent）。

## 日志

daemon 日志位于 `<config_dir>/shell-proxy/logs/daemon.log`（超过 10MB 启动时轮转为 `.old`），每条命令记录时间、主机、起始 cwd、退出码、耗时、输出字节数与命令内容；`sp-serve` 自身的 stderr 也汇入该日志。

## 已知限制

- 远端架构暂支持 x86_64 / aarch64 Linux（musl 静态二进制）；远端需要 PATH 中有 `bash`。
- 终端（tty）stdin 不转发（无 TUI 支持）；管道 stdin 正常。
- 远端后台进程（`sleep 100 &`）在命令结束后继续运行，但其后续输出不再转发（与本地 `&` 后退出终端的行为类似），且会阻止本次调用的 cwd 更新。
- `-f` 脚本与命令必须是 UTF-8。
- 不提供 pty（无 TUI 交互）；`top` 这类全屏程序不适用。

## 测试

```sh
cargo test --workspace                  # 单元测试
SP_TEST_HOST=lse cargo nextest run      # 集成测试（需可连的真实主机，不可达时自动跳过）
```

## License

MIT OR Apache-2.0
