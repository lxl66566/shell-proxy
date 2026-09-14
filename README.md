# shell-proxy

简体中文 | [English](./README.en.md)

<details>
<summary>前言</summary>

白嫖 GLM zcode 的闲时任务实在是[太爽了](https://t.me/withabsolutex/2824)，但是这玩意最大的问题是只能在本机执行，不能 ssh 执行。我的 perf first 项目在 WSL 上性能漂移太大，因此必须跑在我的 Linux server 上。因此整了个工具用来做 shell 代理，让闲时任务可以跑在我的 server 上。

</details>

在远程 Linux 机器上执行 bash 命令。

- stdout / stderr / stdin / 管道 / 退出码 / Ctrl+C 全部如实转发
- cwd + env 在多次调用之间保持
- 多 session：同一主机上并行多个独立 shell 状态（cwd/env），互不污染
- 远端为交互式 bash，加载 `~/.bashrc`
- `sp push` / `sp pull` 文件传输；`sp -f` 执行本地脚本
- 可作为 MCP server 供 AI Agent 使用

## 安装

从 [Release](https://github.com/lxl66566/shell-proxy/Releases) 里下载预编译的二进制文件。

## 用法

```sh
# 首次配置（host 为你的 ssh target）
echo 'host = "root@127.0.0.1"' > ~/.config/shell-proxy/config.toml

sp ls -alF                     # 执行命令
sp "echo 333 | grep 3"         # 管道、引号：整条加引号最可靠
sp cd /root && sp pwd          # cwd 跨调用保持 -> /root
sp --cwd /var pwd              # 指定本次起始目录
sp -f deploy.sh                # 执行本地脚本，-- 后跟位置参数（$1 $2）
echo data | sp cat             # stdin 转发
sp --timeout 60 make           # 超时退出码 124
sp push patch.py /tmp/x.py     # 上传文件（local 为 `-` 时读 stdin）
sp pull /etc/os-release -      # 下载文件（local 为 `-` 时写 stdout）
sp doctor                      # 诊断本地/daemon/远端环境

# 多 session：--session（或环境变量 SP_SESSION）选择独立的状态桶
sp --session a cd /root && sp --session b cd /tmp
```

参数拼接：单参数含 shell 语法时整条原文交给远端 bash；多参数逐个引用后以空格拼接，词边界不丢。复杂脚本用 `-f` 或 `cat script.sh | sp`。

退出码：远端命令原样返回；超时 124；daemon/连接错误 254。

session 名限 `[A-Za-z0-9._-]`、最长 64 字节，不指定时为 `default`；session 生命周期与 daemon 一致，daemon 退出即回到初始状态。

## 架构

```
sp CLI / MCP --IPC--> 本地 daemon（持久 SSH 连接 + cwd 状态）--> 远端 sp-serve --> bash
```

daemon 不存在时自动拉起，并在连接后自动部署内嵌的 `sp-serve` 到远端，server 端零配置。无端口监听，认证与加密由 SSH 承担；主机配置（别名、ProxyJump 等）复用 `ssh -G` 解析。

## MCP

`sp mcp` 在 stdio 上提供 `exec` / `read_file` / `write_file` 三个工具。命令原文直达远端 bash，无本地 shell 引号问题；cwd 跨调用保持。每个工具可选传 `session` 参数选择独立状态桶。

两个 AI Agent 并行接入同一台机器时，各自固定一个 `SP_SESSION`（每个 agent 一个独立 `sp mcp` 进程，agent 无感知）：

```json
{
  "mcpServers": {
    "sp-a": { "command": "sp", "args": ["mcp"], "env": { "SP_SESSION": "agent-a" } },
    "sp-b": { "command": "sp", "args": ["mcp"], "env": { "SP_SESSION": "agent-b" } }
  }
}
```

## 配置

`~/.config/shell-proxy/`，Windows 为 `%APPDATA%\shell-proxy\`，遵循 XDG 规范：

```toml
host = "lse"       # 默认主机别名
log_level = "info"
```

优先级：`--host` > `SP_HOST` > config.toml；认证优先 ssh-agent，其次 IdentityFile（加密私钥请加入 agent）。

session 优先级：`--session` / tool 参数 > `SP_SESSION` > `default`。

daemon 日志位于 `<config_dir>/shell-proxy/logs/daemon.log`，记录每条命令的时间、主机、session、cwd、退出码、耗时与命令内容。

## 已知限制

- 远端支持 x86_64 / aarch64 Linux，PATH 中需有 `bash`
- 无 tty / pty，不支持 TUI 与 `top` 等全屏程序；管道 stdin 正常
- `push` / `pull` 只传单个文件，不递归目录
- `-f` 脚本与 `read_file` / `write_file` 仅支持 UTF-8（二进制用 `push` / `pull`）

## 测试

```sh
cargo test --workspace
SP_TEST_HOST=lse cargo nextest run   # 需可连的真实主机，不可达时自动跳过
```

## License

MIT OR Apache-2.0
