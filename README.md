# shell-proxy (sp)

让本地命令在远程 Linux 机器上执行，效果如同直接在那台机器的交互式 bash 里敲入。

- 命令前加 `sp` 即可：`sp ls -alF`、`sp "echo 333 | grep 3"`
- 完整转发 stdout / stderr / stdin / 管道 / 退出码 / `command not found`
- Ctrl+C 转发为远端 SIGINT，本地拿到真实的 130 退出码
- **cwd 在多次调用之间保持**（`sp cd /root` 后，下一条命令仍在 /root）
- 远端以交互式 bash 运行，加载 `~/.bashrc`（alias、函数可用）
- 支持作为 MCP server 提供给 AI Agent

## 架构

常驻 daemon（本机）持有到远端的持久 SSH 连接（russh），`sp` 命令通过 IPC（Windows 命名管道 / Unix socket）与 daemon 通信，daemon 不存在时自动拉起。

每条命令使用两个 SSH channel：

1. 上传通道：`cat > /tmp/.sp-<nonce>.sh`，生成的 bash 包装脚本从 stdin 流入（exec 串不含任何元字符，任何登录 shell 都能解析，无跨 shell 转义问题）；
2. 执行通道：`bash /tmp/.sp-<nonce>.sh`，stdin 保持空闲用于转发用户输入；脚本首行自删除。

包装脚本以 `bash --rcfile /dev/fd/3 -i -c '...'` 启动交互式 bash：stderr 的 job control 噪音被 fd 重定向吞掉、`~/.bashrc` 正常加载、退出码经 SSH exit-status 原生回传，cwd 通过 stdout 末尾的随机 nonce 标记回传并在客户端剥离（不影响二进制输出）。

主机配置（别名、端口、IdentityFile、ProxyCommand/ProxyJump、StrictHostKeyChecking）直接复用系统 `ssh -G` 解析结果；known_hosts 严格校验（已记录但变更的密钥始终拒绝）。

## 安装

```sh
cargo install --git https://github.com/lxl66566/shell-proxy
# 或
cargo install shell-proxy
```

二进制名为 `sp`。需要系统 PATH 中有 `ssh`（用于解析 `~/.ssh/config`）。

## 用法

```sh
# 首次配置：指定默认主机（别名来自 ~/.ssh/config）
mkdir -p ~/.config/shell-proxy && echo 'host = "ls"' > ~/.config/shell-proxy/config.toml
# Windows: $XDG_CONFIG_HOME/shell-proxy/config.toml

sp ls -alF                     # 执行命令
sp "echo 333 | grep 3"         # 管道、引号：整条加引号最可靠
sp cd /root && sp pwd          # cwd 跨调用保持 -> /root
sp --cwd /var pwd              # 本次指定起始目录（并成为新的持久 cwd）
sp "definitely_missing"        # -> stderr: command not found, 退出码 127
echo data | sp cat             # stdin 转发
sp gcc -o t t.c                # Ctrl+C 会转发到远端，本地拿到 130
sp --timeout 60 make           # 超时杀掉远端进程，退出码 124
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
host = "ls"        # 默认主机别名
log_level = "info" # daemon 日志级别
```

环境变量：`SP_HOST`（默认主机）、`SP_SOCK`（daemon socket 覆盖，主要供测试）。
优先级：`--host` > `SP_HOST` > config.toml。

认证：优先 ssh-agent（Windows 为 OpenSSH 管道），其次 IdentityFile（加密私钥请加入 agent）。

## 日志

daemon 日志位于 `<config_dir>/shell-proxy/logs/daemon.log`（超过 10MB 启动时轮转为 `.old`），每条命令记录时间、主机、起始 cwd、退出码、耗时、输出字节数与命令内容。

## 已知限制

- 远端后台进程（`sleep 100 &`）在命令结束后继续运行，但其后续输出不再转发（与本地 `&` 后退出终端的行为类似）。
- `-f` 脚本与命令必须是 UTF-8。
- 不提供 pty（无 TUI 交互）；`top` 这类全屏程序不适用。

## 测试

```sh
cargo test --lib                    # 单元测试
SP_TEST_HOST=ls cargo nextest run   # 集成测试（需可连的真实主机，不可达时自动跳过）
```

## License

MIT OR Apache-2.0
