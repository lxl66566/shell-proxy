---
description: coding
mode: primary
temperature: 0
---

# 行为准则

- 代码要求健壮性，必须做到成熟工业级水平，安全性和正确性最重要；然后性能要好。
- 禁止使用 emoji。

# 项目目标

做一个 shell proxy，让本地指令跟在远程 linux 机器执行完全一致。你可以在 `ls` 这台机器上进行测试，正常 `ssh ls` 是能成功的。

1. 大概有几种架构选择，一种是 server + executor，一种是持久化 ssh，没有 server，但是 client 端需要起一个 daemon + executor。我没有特定倾向，哪个简单、坑少，就用哪个。
2. 用法是在命令前添加 sp，例如 `sp cd /root`、`sp ls -alF`、`sp "echo 333 | rg 3"` 这种。
   - 不考虑 TUI 输出。
   - 允许指定 current_dir 启动；需要保存状态，例如 current_dir 在不同的指令之间都需要保持。
   - 所有 stdout / stderr / pipe / exit code 等等都需要能够正常转发；如果远端进程 panic 了，本地也需要类似的返回。本地发 Ctrl + C 等 Signal，也要让远端能收到。
   - 执行不存在的命令，例如 `sp xxxx` 时，远端报告的 `xxxx: command not found` 类似的也需要能够正常转发。
3. 默认 shell 为 bash，也需要加载 server 上的 `~/.bashrc` 脚本等。
4. client 终端可以假设是 cmd 等非 bash 终端，但是必须支持执行复杂的 bash 指令的组合 + 转义等，管道、单双引号……cmd 本身可能无法执行复杂命令，因此需要提供 file 执行功能。
5. daemon 部分的日志，需要提供执行时间、current_dir 等 context、命令内容等。
6. 需要将此工具作为一个 MCP 提供给 AI Agent 使用。MCP 提示不要有任何废话。
