# shell-proxy 代码审查报告

- 审查时间：2026-10-06 06:28 (UTC+8)
- 工作区版本：shell-proxy v0.3.0，commit `87332907b4756f57b36faf8d4fce507de7ede463`（`8733290 chore: bump version`），工作区干净无未提交改动
- Reviewer 模型：GLM-5.3（account:bigmodel-individual-coding-plan/GLM-5.3）
- 审查方法：3 个并行 subagent 分别负责「客户端 CLI/MCP」「传输协议与 SSH 链路」「远端 serve 与测试」三块做静态审查，主 agent 对全部 P0/P1 级结论逐条复核源码后汇总。审查范围为主 crate `src/`（13 文件）、`crates/sp-proto`、`crates/sp-serve`、`build.rs`、`tests/integration.rs`，共约 5300 行。
- 审查约束声明：全程纯静态阅读，未运行 `sp` 二进制、未连接远端机器、未运行任何测试，未读取或修改任何运行中的 sp 进程、daemon 日志与用户配置。

## 总体架构与数据流

sp 分两级转发：本地 CLI / MCP 客户端通过命名管道（Windows）或 unix socket 用 sp-proto 帧协议（`[1B kind][u32 LE len][payload]`）与本机常驻 daemon 通信；daemon 按 host 维护一条 russh SSH 长连接，首次连接时部署构建期内嵌的 sp-serve 二进制（文件名带版本 + sha256 校验、原子 mv、stale 清理）；每条命令在独立 SSH exec channel 上启动一个 sp-serve 进程，serve 用 `setsid` + `bash -i --rcfile` 拉起交互式 bash（命令文本、rcfile、状态恢复全部经 memfd fd 传递，无字符串拼接进 shell 语法），stdout/stderr 以流式帧回传、Exit 帧（退出码 + 新 cwd + shell 状态 dump）收尾。daemon 按 (host, session) 分桶持久化 cwd/state，session 内用锁串行、session 间并行。超时由 serve 端 TERM、5s 后 KILL 双级强制，daemon 端 watchdog（timeout + 15s）兜底（仅在设置了 timeout 时启用）。信号从 Windows 控制台处理器 / signal_hook 转成协议帧逐跳转发。

整体分层清晰：memfd 无转义层设计从根上消灭了引号注入面，输出背压端到端打通（pump、有界通道、SSH window），单写者任务保证帧序，exit code 链路（signal、128+n / timeout、124 / 内部错、254）完整。以下问题集中在 stdin 方向的背压死锁、超时参数的溢出与覆盖范围、信号中断时的状态持久化、host key 校验的安全缺口，以及 MCP 工具能力面。

## 发现统计

| 级别 | 数量 | 说明 |
|---|---|---|
| P0 | 1 | 常规使用可触发的永久挂起 / 资源泄漏 |
| P1 | 7 | 特定但现实的输入或场景触发：daemon 崩溃、永久悬挂、静默数据损坏、安全缺口 |
| P2 | 13 | 边角场景的正确性问题、健壮性缺口、能力缺口 |
| P3 | 25 | 优化建议、可观测性、文档一致性 |

---

## P0 严重问题

### P0-1 stdin 方向 SSH window 打满时 forwarder 永久卡死：execute() 不返回、session 锁永久持有、watchdog 兜底失效

位置：`src/remote.rs:182-221`（forwarder 任务）、`src/remote.rs:282-289`（`reader_task.abort()` 后 `let _ = forwarder.await;`）、`src/daemon.rs:278-301`（watchdog 对 engine future 的 drop）、`src/daemon.rs:36-40`（注释 "Dropping the engine then closes the exec channel"）。

问题链路（已逐行复核源码确认）：

1. daemon 侧 forwarder 任务在 `send_frame(&writer, &ExecFrame::StdinData(d)).await`（`remote.rs:208`）上，当远端 stdin window 耗尽时会无限期阻塞。russh 0.63.3 的 `send_bytes` 内部在 window 不足时挂起等待，只在收到服务端 WindowAdjust 时被唤醒；而对端进程退出、channel 收到 CHANNEL_CLOSE 时 russh 仅向读端投递 `ChannelMsg::Close`，不会唤醒 window 等待者，`ChannelWriteHalf` 也没有 Drop 时关闭 channel 的实现。
2. 触发场景（现实可复现）：远端命令不读 stdin 而本地持续推送 stdin，例如 `sp 'sleep 30' < huge.bin`。本地全速推 → serve 侧子进程管道（64KB）满 → serve 停止读 channel → SSH window 打满 → forwarder 阻塞。30s 后 sleep 退出、serve 发出 Exit 帧并退出（Exit 走 stdout 方向不受影响），daemon 收到 Exit 后 `break 'outer`，随后 `drop(data_lane); drop(sig_lane); let _ = forwarder.await;`，forwarder 还要先把 data_rx 积压数据全部写完、再写 StdinEof、最后 `writer.close()`，而 serve 已死、WindowAdjust 永远不来，`forwarder.await` 永久挂起。keepalive 只在整条连接无流量时才断连，同 host 其他 session 的活跃流量会持续保活这条连接。
3. 后果一（正常完成路径）：`execute()` 永不返回 → `handle_exec` 永不返回 → `sess.lock`（`daemon.rs:242`）永久持有 → 该 (host, session) 的所有后续命令永久排队，客户端无超时（CLI 默认无 timeout）时表现为永久卡死。daemon 任务本身泄漏。
4. 后果二（watchdog 路径）：watchdog 触发后 drop 的是 engine future，forwarder 是独立 `tokio::spawn` 的 detached 任务照旧卡死，`remote.rs:220` 唯一的 `writer.close()` 永远执行不到，channel 不关闭、远端 serve 若还活着也不会被清理。`daemon.rs:36-40` 注释声称 drop engine 即关闭 exec channel 的前提实际不成立，watchdog 的兜底设计在恰恰最需要它的场景（远端 wedge）失效。
5. 关联缺陷（同根因，独立后果）：`src/remote.rs:174-179` 的注释声称 "dedicated lane with biased priority" 保证信号不被 stdin 写阻塞，但 biased select 只改变两个分支同时 ready 时的选择顺序；forwarder 一旦阻塞在 `send_frame(StdinData)` 内部，`sig_rx` 里的 Signal 帧根本无人接收，Ctrl+C 在最需要它的场景（stdin 阻塞挂死）送不到远端，只剩客户端 1 秒内双击 Ctrl+C 的本地 130 强退，远端进程继续跑。serve 侧对称存在同样问题（route 任务阻塞在 stdin 转发时控制帧无法送达）。

修复建议：

- 短期：`forwarder.await` 外加 `tokio::time::timeout`（如 10-30s，超时 abort forwarder 并 warn），同时在 daemon watchdog 分支显式 abort 引擎关联任务或调用 channel close，不要依赖 drop 的隐式传播。
- 根治：把 stdin 数据写入做成可中断——按 `writable_packet_size()` 手动分块写，块间 `tokio::select!` 信号 / 关闭通知（reader_task 收到 Close 或连接断开时经 Notify/oneshot 唤醒）；serve 侧 route 任务把 StdinData 转发与控制帧路由解耦为两个任务。
- 可顺带给 russh 上游提 issue：channel close 应唤醒 window 等待者。

---

## P1 重要问题

### P1-1 timeout 值无上限校验，`Instant + Duration` 溢出 panic，release 下 panic=abort 直接杀死 daemon 或 serve

位置：`src/daemon.rs:296-299`（`tokio::time::Instant::now() + Duration::from_millis(ms) + WATCHDOG_GRACE`，无 `checked_add`）；`crates/sp-serve/src/serve.rs:199`（`Instant::now() + t` 同样无检查）；入口 `src/main.rs:347-349`（`--timeout` 为裸 u64 秒，`saturating_mul(1000)` 后可达 `u64::MAX` ms）；`src/mcp.rs:31-32, 80`（`timeout_ms` 为模型可控参数，未校验直接透传）。

问题：用户敲 `sp --timeout 99999999999999999 ...` 或 AI 传一个巨大 `timeout_ms`，tokio 的 `Instant + Duration` 在溢出时 panic（"overflow when adding duration to instant"，Windows QPC 表示范围有限）。`Cargo.toml` 的 `[profile.release] panic = "abort"` 下：daemon 侧直接终止整个常驻 daemon，所有 host 连接、全部 session 的 cwd/state 丢失、所有在跑命令的客户端立刻收到 "daemon closed the connection before exit"（254）；serve 侧直接 abort 无 Exit 帧，daemon 报 "closed without an exit report"。一条用户输入即可杀死常驻进程，且报错信息完全不指向真实原因。

修复建议：在 CLI / MCP / 协议层集中钳制（如上限 24h，超出报参数错误），daemon 与 serve 侧均改用 `checked_add`，溢出按「无 watchdog / 无超时」降级处理。

### P1-2 超时不覆盖 connect / 认证 / deploy 阶段，MCP 调用可无限悬挂；ProxyCommand 路径连 TCP 超时都没有

位置：`src/daemon.rs:225`（`get_or_connect` 在 watchdog 建立之前执行）、`src/ssh.rs:139-160`（直连 TCP 有 15s 超时，但 SSH 握手/认证无超时；ProxyCommand 路径 `spawn_proxy` 的子进程管道可永久挂起，无任何超时）、`src/remote.rs:52-96, 349-375, 418-451`（deploy 的 uname、sha256sum、mkdir/cat/mv 与 `exec_collect`、`upload` 全部无界）、`src/mcp.rs:151-157`（MCP `call()` 无任何信号通道）。

问题：watchdog 只包住 `remote::execute` 的 engine future。首次连接慢（NFS 挂起的远端文件系统、慢盘上的 sha256sum、被墙的 ProxyCommand）时：CLI 用户可双击 Ctrl+C 强退（130），但 MCP 的 exec 工具调用会永久不返回，对 AI agent 是致命卡死；且该阶段错误信息为空或丢失上下文。

修复建议：给 handle_exec 整体（或至少 connect+deploy 各环节）加 deadline（`tokio::time::timeout` 30-60s 级别），watchdog 计时应从请求到达起算；ProxyCommand 与 SSH 握手阶段显式套超时。

### P1-3 Ctrl+C / 超时 / 信号中断会静默丢失该命令的全部 cwd 与状态更新

位置：`crates/sp-serve/src/wrapper.rs:53-54`（`trap 'exit 130' INT` / `trap 'exit 143' TERM` / `trap 'exit 129' HUP`）。

问题（已复核 wrapper 源码确认）：trap 直接 `exit` 会跳过 eval 之后的全部 epilogue，`printf '%s\0' "$PWD" >&pwd_fd` 与状态 dump 永远不会执行；serve 端 `read_pipe` 只收到 EOF / 空数据返回 None，daemon 按协议保留旧值。典型场景 `sp 'cd /long/build && make'` 被用户 Ctrl+C：make 中断没问题，但 `cd` 的效果也被静默丢弃，下一条 `sp make` 在旧目录执行；超时路径（TERM trap）同理。这与 README 宣称的核心卖点（cwd + env 在多次调用之间保持）直接冲突，且丢失完全无提示。

修复建议：trap 改为记录标志而非直接 exit：`trap '__sp_sig=130' INT` 等；bash 对前台命令期间的信号本就推迟到命令结束后处理，eval 返回后 epilogue 正常执行，再 `__sp_rc=$?; [ -n "$__sp_sig" ] && __sp_rc=$__sp_sig`。退出码不变（前台子进程死于 SIGINT 时 `$?` 本就是 130），报告得以发出。唯一无法覆盖的是 bash 本体被 SIGKILL（本就无法上报）。

### P1-4 stdin 积压满时静默丢数据：文件上传可静默损坏且退出码为 0

位置：`src/remote.rs:243-248`（`tx.try_send(d).is_err()` 时仅 `warn!("stdin backlog full, dropping stdin data")`）。

问题：本地磁盘快、远端慢（如 `sp 'cat > big.bin' < local.bin` 走 WAN）时，forwarder 被 window 阻塞（P0-1）→ data_rx（64 帧）打满 → 后续 stdin 帧被丢弃。`cat` 正常退出、退出码 0、无任何错误回传客户端，远端文件缺少中段数据，静默数据损坏；warn 只进 daemon 日志，用户不可见。

修复建议：不能简单改成 `send(d).await`（会与输出分支互锁形成全链路循环等待）。正确做法与 P0-1 根治方案一致：stdin 转发拆为独立任务全程 await 背压；至少在丢数据发生时使执行失败（向客户端回 `Exit(code != 0, error = "stdin overflow")`）而非放行成功。

### P1-5 known_hosts 文件全部不存在时，默认配置下静默接受任意 host key（非 TOFU，是永久免校验）

位置：`src/ssh.rs:52-57`（files 按 `is_file()` 过滤）、`src/ssh.rs:77-81`（`if files.is_empty() || !self.resolved.strict_host_keys { return Ok(true); }`）。

问题（已复核源码确认）：默认 `stricthostkeychecking=ask` 映射为 `strict_host_keys=true`，但全新机器上 `~/.ssh/known_hosts` 与全局文件都不存在时 `files.is_empty()` 成立，任意 host key 被接受。且 sp 从不写 known_hosts，所以不是「首次信任并固定」的 TOFU，而是每次连接都接受任何 key，中间人可永久劫持。`ssh.rs:88-89` 的报错提示（引导用户先 `ssh <host> true` 记录 key）因短路在 `files.is_empty()` 之后永远走不到，设计意图自相矛盾。对比 OpenSSH：strict 模式下无 known_hosts 会拒绝连接。

修复建议：`files.is_empty() && strict_host_keys` 时拒绝并提示先 `ssh <host> true`；或实现真正的 TOFU（首次接受并追加写入第一个可写的 known_hosts 文件，russh 已提供 `learn_known_hosts_path`）。

### P1-6 daemon accept 循环任何错误即整体退出

位置：`src/transport.rs:84-97`（Windows accept 中 `server.connect().await?` 与 `create(path)?` 均可失败）、`src/daemon.rs:105-107`（`res.map_err(...)?` 直接向上传播使 `run()` 返回 Err）。

问题：Windows 上客户端瞬断（ERROR_NO_DATA）、瞬时资源压力导致 create 失败等一次性抖动，会终止常驻 daemon，杀死所有 host 连接与在途命令、丢失全部 session 状态。对常驻服务过于脆弱。另注意 accept 两次 create 之间存在无监听实例的窗口，客户端可能拿到 FILE_NOT_FOUND 而触发多余的 spawn_daemon。

修复建议：accept 失败记日志 + 短退避重试，仅 bind 失败（端点被占）等不可恢复错误才退出；考虑「先 create 下一个实例再 connect 当前」的轮换方式消除空窗。

### P1-7 MCP 捕获输出无内存上限，可 OOM

位置：`src/client.rs:290-304`（`run_captured` 把 stdout/stderr 全量收进 `Vec<u8>`）、`src/mcp.rs:196-207`（`clip` 只在最终渲染时截断 64KB）。

问题：`sp mcp` 下执行 `yes` 之类高频输出命令（默认 600s 超时内）会无界增长内存；`MAX_TOOL_OUTPUT` 只截断最终文本，不限制捕获量。AI agent 完全可能触发。

修复建议：实现 capped 捕获——累计到 N 字节（如 1MB）后丢弃后续并计数，结果文本中注明 `[dropped M bytes]`，exit code 不受影响。

---

## P2 一般问题

### P2-1 超时升级（TERM 后 5s KILL）在组长提前死亡时被跳过，TERM 免疫的同组进程存活

位置：`crates/sp-serve/src/serve.rs:233`（`Sel::Exit(s) => break`）、`serve.rs:234-251`（升级逻辑只在 `Sel::Timeout` 分支生效）。

问题：若 bash 在 grace 内死于 TERM（trap `exit 143`），wait 先就绪、循环 break，KILL 永远不发出。同 pgid 中忽略 TERM 的成员（如内层 `trap "" TERM` 的脚本及其后台子进程继承 SIG_IGN）会作为孤儿存活。用户对 `--timeout` 的契约是到点全部杀掉（`timeout(1)` 的 `-k` 语义），此场景无测试覆盖。

修复建议：`Sel::Exit` break 之后若 `timed_out == true`，直接补一发 `kill_group_raw(pgid, SIGKILL)`（幂等且安全）；或在报告前等待 kill_deadline。

### P2-2 固定 2s DRAIN_GRACE 在慢消费链路上静默截断输出尾部

位置：`crates/sp-serve/src/serve.rs:27-29, 271-281`。

问题：子进程退出后 pump 还需把管道残余推过 out_tx → writer → SSH 窗口，而窗口是否打开取决于客户端消费速度（本地 `sp big | slow_reader` 即可让整条链路积压）。pump 的 `tx.send().await` 阻塞 2s 后被 abort，尾部字节被丢弃——没有任何孤儿进程，纯粹是消费者慢。注释声称 "so tail bytes are not lost"，固定时限无法保证。

修复建议：drain 上限改为「无进展超时」——每成功写出一帧重置计时器，仅持续无进展才判定孤儿并 abort；孤儿场景（写端被持有但无数据）同样被覆盖。

### P2-3 CLI 默认无超时 + session 锁串行：一条 wedge 命令永久阻塞同 session 后续所有命令

位置：`src/main.rs:44-46`（`--timeout` 默认 None）、`src/daemon.rs:242`（session 锁持有整个执行期）、`src/daemon.rs:296-301`（watchdog 仅 `timeout_ms > 0` 时启用）。

问题：`sp sleep infinity`（忘加 --timeout）后，同 session 的下一条命令在 daemon 内永久排队，无超时、无排队提示，表现为永久卡死；MCP 端有 600s 默认值不受影响。多 agent 共用默认 session 时最易踩。

修复建议：CLI 路径提供可配置的保守默认超时（config.toml 项），或排队时向后续客户端输出等待提示。

### P2-4 用户的 `set -e`（errexit）永远不会被持久化

位置：`crates/sp-serve/src/wrapper.rs:55-57`（epilogue 在 dump 之前执行 `set +e`，dump 中 `set +o` 永远输出 errexit off）。

问题：其余 set -o 选项（pipefail、nounset）、shopt、umask 都持久化，唯独 errexit 被静默丢弃，用户难以察觉。注释给出的理由（防 restored `set -e` 中断 epilogue）针对的是恢复时机，不是不能持久化。

修复建议：`set +e` 之前捕获 errexit 状态：`__sp_e=0; [[ $- == *e* ]] && __sp_e=1; set +e;`，dump 尾部按需补 `set -o errexit`。

### P2-5 daemon 与内嵌 sp-serve 之间没有协议版本握手

位置：`build.rs:34-37`、`src/remote.rs:52-96`。

问题：部署校验（文件名带 CARGO_PKG_VERSION + sha256 与 embed 内容比对 + 原子 mv + stale 清理 + 字符集白名单）保证「远端文件 == 本次编译嵌入的字节」，这部分扎实。但环境变量允许覆盖 `SP_SERVE_X86_64` / `SP_SERVE_AARCH64` 提供任意来源的二进制：若由旧版 sp-proto 编出（帧种类、ExitReport 字段、NUL 语义不同），运行前无检测，只能靠 "bad frame" / "closed without an exit report" 这类模糊错误事后兜底。

修复建议：serve 启动时向 stderr 打一行版本标识（SSH extended data 会进 daemon 日志），daemon 首次部署后读回校验；或在 Pong 帧里带版本号。成本极低，排查价值大。

### P2-6 deploy 与并发首连的 race：cleanup_stale 可删除并发方正在上传的临时文件

位置：`src/remote.rs:105-128`（cleanup_stale 删除所有 `.upload-` 前缀文件，仅排除自己的 keep）、`src/daemon.rs:438-452`（get_or_connect 两任务可同时 miss 缓存各自 connect + deploy）。

问题：同一 host 最初两条并发命令各建连接各 deploy，先完成一方的 cleanup_stale 会删掉另一方正在上传的 `.upload-<nonce>`，导致后者 chmod/mv 失败、命令以怪异错误告终（可自愈：下一次命令重新部署）。窗口小但 deploy 多轮往返，并非纯理论。

修复建议：cleanup_stale 只删与当前版本不匹配的 `sp-serve-*`，`.upload-*` 按 mtime 年龄阈值（如 >10 分钟）再删；或 per-host Mutex 串行化首连 deploy。

### P2-7 自动拉起 daemon 失败时用户反馈缺失：盲等 10 秒且真实原因丢失

位置：`src/client.rs:47-59`（10s 轮询）、`src/client.rs:102-148`（daemon 以 DETACHED_PROCESS + stdio null 启动）、`src/daemon.rs:79-84`（bind 失败仅作为 Err 返回不落日志）、`src/main.rs:105-111`。

问题：自动拉起的 daemon 若 bind 失败，错误写到已重定向为 null 的 stderr，也不进 daemon.log；客户端 10 秒后只报 "daemon did not come up"，真实原因丢失。

修复建议：daemon 返回前把 bind/初始化错误也写入日志文件；客户端报错时提示用 `sp daemon` 前台运行诊断。

### P2-8 Windows 命名管道使用默认安全描述符，与 unix 侧 0600 不对齐

位置：`src/transport.rs:70-79`（`ServerOptions::new().first_pipe_instance(true).create(path)` 未设置 DACL；unix 侧 `transport.rs:63-68` 显式 0600）。

问题：Windows 命名管道默认 DACL 对 Everyone 和 Anonymous 授予读权限。任意本地低权进程可打开管道建立只读连接（无法注入 Exec 帧，但会）占用 handler 任务与 ActiveGuard 计数阻止 daemon 空闲退出、无成本堆积任务；会话表 sessions 无上限，存在轻度内存增长面。

修复建议：用 `CreateNamedPipeW` + 显式 SECURITY_ATTRIBUTES（仅当前用户 SID 的 owner-only DACL）创建管道再交给 tokio；或至少文档化默认 DACL 的实际可达面。

### P2-9 russh known_hosts 匹配能力远弱于 OpenSSH：通配符 / CA / revoked / HostKeyAlias 全不支持

位置：`src/ssh.rs:59`（`check_known_hosts_path`，russh 的 `match_hostname` 仅做精确字符串等值或 HMAC 哈希匹配）；`src/ssh_config.rs`（未解析 `hostkeyalias` 指令）。

问题：(a) `*.example.com`、`?` 通配符条目永不匹配；(b) `@cert-authority` 行的主机字段被 russh 解析成字面 `@cert-authority`，使用 SSH host 证书或通配符条目的环境里 ssh 能连、sp 在 strict 模式下拒绝且报错困惑；(c) HostKeyAlias 下 ssh 把 key 记录在别名下，sp 用 hostname 查永远找不到；(d) `ssh.rs:63-72` 把 check 的任何 Err（包括某行 base64 损坏）都报成 "host key changed"，方向安全但信息误导。

修复建议：自己实现 OpenSSH 兼容的 `match_pattern_list` 语义（通配符、取反、`[host]:port`、`@revoked` / `@cert-authority`），解析并优先使用 `hostkeyalias`；至少在 README 写明限制。

### P2-10 agent 认证对每个 identity 都做完整签名尝试，可耗尽服务端 MaxAuthTries

位置：`src/ssh.rs:201-215`。

问题：russh 的 publickey 认证直接发起完整签名（每次计入服务端 auth 尝试计数，OpenSSH 默认 6 次），ssh 客户端会先用无签名查询过滤服务器不接受的 key。agent 里装多于 6 把 key（开发者常见）时，sp 可能在轮到 IdentityFile 之前被服务器断开，而 ssh 正常。

修复建议：按 `AuthResult::Failure { remaining_methods }` 检查 publickey 是否仍在允许集合、尝试次数设上限（如 6）。

### P2-11 MCP exec 结果恒为 success（isError=false），且结果不含新 cwd

位置：`src/mcp.rs:84-87`（非零退出码只写在文本里）、`src/mcp.rs:209-230`（RunReport.cwd 有值但未渲染）。

问题：多数 MCP 宿主依赖 isError 触发重试/纠错路径；agent 跟踪 session 状态需要额外跑一次 `pwd`。

修复建议：非零退出码（或 254 / 124）时置 isError=true；结果尾部附 `cwd=...`。

### P2-12 集成测试的串行化在 nextest 下失效（README 恰好推荐 nextest）

位置：`tests/integration.rs:25-27`（"Serializes tests: they share one daemon and its per-host cwd state"，进程内 tokio::Mutex）、`README.md:101`（推荐 `cargo nextest run`）。

问题：nextest 每测试一个独立进程，进程间锁不存在；每个进程各自拉起 daemon，所有使用默认 session 的测试并发读写同一远端默认 session 的 cwd/state，断言随机失败；N 个 daemon 并发部署也会让 `serve_binary_is_deployed` 的 `count == 1` 抖动。

修复建议：测试统一走 `unique_session()`（每测试独立状态桶）；部署计数断言改为精确文件名存在性；或 README 注明仅支持 cargo test。

### P2-13 非 UTF-8 命令行参数被 `to_string_lossy` 破坏

位置：`src/main.rs:354-357`（OsString 转 String 用 lossy，替换字符直接改写命令内容；Unix 上非 UTF-8 文件名场景，Windows 影响小）。

修复建议：逐参数报错而非静默替换。

---

## P3 优化建议

1. **decoder.push 错误路径资源清理不完整**（`src/remote.rs:261`）：提前 `?` 返回时 reader_task 未 abort、serve_log.flush() 未调用，serve 的 stderr 尾部日志丢失，而错误信息恰恰指引用户去看 daemon 日志。建议 break 出循环统一收尾。
2. **EventDecoder 的 `drain(..5+len)` 每次 O(n) 前移**（`crates/sp-proto/src/lib.rs:277`）：最坏 O(n^2/帧) 且 buf 永不收缩，建议换 `bytes::BytesMut`（advance）或环形缓冲；`read_frame_as` 的 `vec![0u8; len]` 对大帧有无谓零初始化，可用 `Vec::with_capacity` + `read_buf`。
3. **encode 逐帧 clone**（`crates/sp-proto/src/lib.rs:308-317`）：`StdinData(d) => d.clone()` 加上 client 侧 `to_vec`，每条 stdin 数据在链路上复制两到三次。建议提供 `write_exec_frame` 直接两段写（kind+len 与 payload 各一次 write_all；当前架构每个写端都是独占任务，不会被交错）。
4. **mid-payload EOF 语义**（`crates/sp-proto/src/lib.rs:232-243`）：payload 中途断开返回 `Err(Io(UnexpectedEof))`，客户端看到 "unexpected end of file"，丢失「daemon 半途死亡」的上下文，建议映射为明确的协议错误文案。
5. **ssh_config 解析细节**（`src/ssh_config.rs:209-213` 等）：`expand_proxy_command` 不处理 `%%`、`%r` / `%u` token，ProxyJump 字符串内 token 不展开；`connecttimeout` 值未 unquote；`default_identity_files` 缺 `id_ed25519_sk` / `id_ecdsa_sk`；USER 与 USERNAME 均缺失时 fallback 默认 `root`（ssh 语义是本地用户名），建议直接报错。
6. **ProxyCommand 的 Windows 细节**（`src/ssh.rs:174-195`）：`cmd /C <cmd>` 会对命令串做 `%VAR%` 展开，hostname/端口含 `%` 时行为未定义；整个 ProxyCommand 路径无超时（与 P1-2 关联）。
7. **RSA 一律 Sha512**（`src/ssh.rs:231-236`）：仅支持 ssh-rsa(SHA1) 的老旧服务器会认证失败，可用 `best_available_rsa_hash`。
8. **`app_dir()` 每次调用 create_dir_all 且忽略错误**（`src/config.rs:61-73`）：getter 带副作用、失败被吞，后续报错难定位。
9. **每次执行 `req.clone()`**（`src/daemon.rs:248`）：克隆整个请求（含最大 256KB state blob）仅为日志保留原文，可只克隆 command。
10. **日志轮转仅发生在 daemon 启动时**（`src/daemon.rs:488-493`）：长驻 daemon 超过 10MB 后 daemon.log 无界增长（flush_level_filter=All 加剧），建议按大小滚动。
11. **daemon 内 config 解析失败静默回退 Info 级别**（`src/daemon.rs:498-499`）：CLI 端同文件是硬失败，不一致且掩盖配置错误，至少 warn 一条。
12. **`Sel::Dead(false)` 忙循环**（`crates/sp-serve/src/serve.rs:212, 252-257`）：writer 任务 panic 时（主要影响 dev/test profile）oneshot 持续返回 Err 且不处理，100% CPU 忙循环直到命令结束。建议仿照 ctrl_open 加 dead_done 标志。
13. **Ping 应答与 stdout 帧共用阻塞通道**（`crates/sp-serve/src/serve.rs:174-180`）：route 任务在 out_tx 满时连 Pong 都发不出，信号被输出背压延迟。当前 daemon 从不发 Ping 属死路径，一旦启用 keepalive 即踩中。Pong 建议 try_send。
14. **第二个 Exec 帧被静默吞掉**（`crates/sp-serve/src/serve.rs:182`）：既不 log 也不报错，建议至少 log 一行。
15. **实现细节泄漏到用户 shell 环境**（`crates/sp-serve/src/child.rs:83, 121`、`wrapper.rs:55-57`）：`SP_CWD` 在 `--cwd` 时用户 `env` 可见；`__sp_rc` 未在 dump 前 unset 会进入状态 dump 持久化；rc/cmd/restore 三个 memfd 被 CLEAREXC 继承给所有子进程（`ls /proc/self/fd` 可见，命令文本可经 `/proc/self/fd/N` 读到）。建议 epilogue 里 `unset __sp_rc __sp_sig` 后再 dump、eval 前关闭 cmd/restore 两个 memfd。
16. **cwd 收集的 JoinError 走错日志分支**（`crates/sp-serve/src/serve.rs:282-289`）：任务 panic 的 JoinError 落入 `_` 分支被报成 "did not terminate in time"，误导排查。
17. **build.rs 忽略 CARGO_TARGET_DIR**（`build.rs:32`）：候选路径硬编码 `target/<triple>/release/sp-serve`，用户设置 CARGO_TARGET_DIR 时 embed 静默退化为占位符，运行期部署才报错。建议读 env 拼接并在缺失时 `cargo:warning`。
18. **rcfile 依赖 /proc 且失败静默**（`crates/sp-serve/src/child.rs:74-75`、`wrapper.rs:19-24`）：`--rcfile /dev/fd/N` 依赖 procfs，无 /proc 的极简容器里 rcfile 打不开且错误不可见（bash stderr 仍是 /dev/null），bashrc 静默不加载。README 已知限制未列出该前提（还有 memfd_create 需 kernel 3.17+、部署需可写 `~/.local/share`）。
19. **终端 stdin 立即发 StdinEof**（`src/main.rs:192-196`）：终端输入被替换为 empty()，`sp cat`（无重定向）会立刻 EOF 结束。注释已说明是有意取舍（不支持 TUI），仅提醒与 ssh 行为不同，建议 README 标注。
20. **客户端管道断裂后远端继续跑完**（`src/client.rs:200-287` + `src/daemon.rs:328-339`）：`sp cat huge | head` 本地 sp 退 254，daemon 有意 letting it finish，远端 cat 跑完输出被丢弃。与 ssh（断连杀远端）不同，属设计取舍，建议 README 标注或提供可选的断连转发 kill。
21. **退出码语义冲突（低危）**：sp 的 254 / 124 与远端命令真实退出码 254 / 124 无法区分（timeout(1) 同样如此），建议文档注明。
22. **`build_command` 在 async 上下文同步读尽 stdin**（`src/main.rs:376-382`）：阻塞 tokio worker（多线程 runtime 启动路径，影响有限），可移到 block_on 之前。
23. **Ctrl+C 信号 try_send 满时静默丢弃**（`src/console.rs:30`）：可 debug! 记录；unix 侧 `expect("register signal handlers")`（`src/console.rs:50`）在 panic=abort 下进程即死，改报错更稳。
24. **host 逐出存在良性竞争**（`src/daemon.rs:366-372`）：连接失败后无条件 remove 可能逐出并发任务刚建立的健康新连接（多余重连，无正确性问题）。
25. **Windows 管道名清洗可碰撞**（`src/config.rs:86-97`）：不同用户名清洗后（`a-b` 与 `a_b`）映射同一管道名，极端多用户场景互串，可加入 SID 或更多熵。

---

## 专项分析一：远端执行命令超时链路（重点关注项）

现有机制梳理：协议有 `timeout_ms` 字段（`crates/sp-proto/src/lib.rs:107-109`）；serve 端执行 TERM、5s 后 KILL 双级强制（`serve.rs:195-250`）；daemon 端 timeout+15s watchdog 兜底（`daemon.rs:296-301`）；exit code 124 表示超时；集成测试覆盖了超时 124 与 setsid 孤儿场景。主链路设计是成熟的，但存在以下缺口（按严重度排列）：

1. 超时值无上限 → 两处 `Instant + Duration` 溢出 panic=abort 杀死 daemon / serve（P1-1）。
2. 超时只覆盖命令执行阶段，connect / 认证 / deploy / ProxyCommand 全程无 deadline，MCP 调用可永久悬挂（P1-2）。
3. 未设置 timeout 的命令（CLI 默认）触发 P0-1 的 window 死锁时，session 锁永久持有且无任何兜底（P0-1 + P2-3）。
4. watchdog 的 drop-engine 关 channel 前提不成立，远端 wedge 时 watchdog 触发后 forwarder 任务泄漏、channel 不关、远端进程不被杀（P0-1 后果二）。
5. TERM 后 5s 的 KILL 升级在组长提前死亡时被跳过，TERM 免疫的同组进程存活（P2-1）。
6. 超时 / 信号中断的命令丢失 cwd 与状态更新（P1-3）。
7. 超时发生在命令阻塞读 stdin 时（`sleep 60` 换成 `cat` + timeout）无测试覆盖（见测试缺口 9）。

## 专项分析二：失败反馈链路（重点关注项）

总体完备：exit code 经 ExitReport（signal、128+n / timeout、124 / 内部错、254）逐跳回传；stderr 分流正常，`sp xxxx` 的 `bash: xxxx: command not found` 走 stderr 帧正常转发（集成测试有覆盖）；connect / auth / deploy / spawn 失败都走 ExitReport.error + 254 并在客户端 stderr 打印原因；serve 自身致命错误经 SSH extended data 进 daemon 日志并在错误信息中指路；协议损坏帧双向有长度（MAX_PAYLOAD=16MB）/ 类型校验并转明确错误。缺口：

1. stdin 积压丢数据静默成功（P1-4，唯一可能「假成功」的路径）。
2. daemon 半途死亡时客户端收到 "unexpected end of file"，丢失上下文（P3-4）。
3. decoder.push 错误路径丢 serve 日志尾部（P3-1）。
4. daemon 自动拉起失败原因丢失（P2-7）。
5. MCP 恒 success，宿主无法感知失败（P2-11）。
6. 部署阶段挂死时错误信息为空（P1-2）。

## 专项分析三：MCP 工具与文件传输能力优化（重点关注项）

现状：`src/mcp.rs` 提供 exec / read_file / write_file 三个工具，描述简洁无废话、`deny_unknown_fields` + SessionId 校验到位，符合项目要求。CLI 侧有 push / pull（`src/client.rs:351, 372`）做文件传输。能力缺口按价值排序：

1. **无 host 参数**：exec / read_file / write_file 均只能用 config / env 固定单 host，agent 无法按调用切换目标机器。建议每个工具加可选 host 参数（daemon 已按 host 维护连接，实现成本低）。
2. **无文件传输工具**：MCP 没有 push / pull 等价物；`read_file` 对二进制做 `from_utf8_lossy`（`mcp.rs:199-201`）静默替换损坏字节，`write_file` 只接受字符串。建议补 base64 编码的 read_file_binary / write_file_binary（或 push / pull 工具），否则 agent 无法搬运非文本文件。
3. **无法中断正在运行的 exec**：`call()` 的信号通道直接丢弃（`mcp.rs:152-153`），超时前 agent 只能等。建议提供 interrupt 工具或至少支持 cancellation notification。
4. **无列出 / 清理 session 的工具**：agent 无法发现有哪些持久 session（名字、host、空闲时间），多 agent 协作时尤其有用。
5. **结果缺新 cwd**（P2-11）：exec 结果尾部附 cwd 可让 agent 免去额外一次 pwd。
6. **CLI push / pull 的 `~` 不展开**（`src/client.rs:351, 372`）：`shell_quote` 把 `~/x` 变成 `'~/x'`，bash 不做波浪号展开，与 scp 直觉不符。可在 quote 前剥离前导 `~/` 拼接 `$HOME/`。
7. exec 工具可考虑暴露 interactive（bashrc 加载）开关透传，与 CLI 对齐。

## 测试覆盖缺口（tests/integration.rs）

已覆盖且质量不错的部分从略（stdout/stderr 分离、退出码、command not found、管道引号、pipefail、bashrc、二进制字节、10 万行大输出、unicode、stdin 转发、cwd / 状态持久化、超时 124、孤儿持管道、SIGINT、130、push-pull、doctor、session 隔离与并发等）。缺失的关键场景按价值排序：

1. 超时 + TERM 免疫进程的 KILL 升级（对应 P2-1，目前零覆盖）。
2. 信号中断后 cwd / 状态的行为锚定（无论 P1-3 修不修，都应有测试固化预期）。
3. stdin 背压 / window 打满场景（`sp 'sleep 30' < big` 验证不悬挂、P1-4 不丢数据），对应 P0-1。
4. Term / Hup / Kill 信号转发（现只测 Int）。
5. 不带 setsid 的经典 nohup 形态（后台作业持 stdout 写端；现有测试只构造了 `>&2` 变体）。
6. 状态值转义回环：`export x="a'b\"c$(echo d)"`、含换行 / unicode 的变量、函数体含引号。
7. 位置参数 `$1..`（`req.args` 全测试始终为空，`-f script -- a b` 路径无覆盖）。
8. 大状态 dump 触碰 256KB STATE_CAP（溢出后 exit code 不受影响、state 保留旧值）。
9. 超时发生在命令阻塞读 stdin 时（`cat` + timeout）。
10. 巨大 --timeout 值（P1-1 的回归测试）。
11. Ping / Pong 路径（serve 端实现无调用方也无测试）。

## README 与实现不一致清单

| 位置 | 不一致 |
|---|---|
| README.md:14, 33 | 「cwd + env 在多次调用之间保持」未注明例外：被 Ctrl+C / 超时 / 信号中断的命令其 cwd 与状态更新会被丢弃（P1-3） |
| README.md:92 | 已知限制缺少：远端需挂载 /proc（rcfile / 命令 memfd 均走 /dev/fd）、kernel 3.17+（memfd_create）、部署目录 `~/.local/share` 需可写、状态 dump 256KB 上限（超限静默保留旧值）、孤儿进程下 2s 后尾部输出被丢弃、`SP_CWD` 与多余 fd 对用户命令可见 |
| README.md:101 | 推荐 `cargo nextest run`，但测试串行化机制在 nextest 进程模型下失效（P2-12） |
| README.md:48 | 「退出码：远端命令原样返回」：被信号杀死报 128+n、超时强制改报 124，并非严格原样 |
| README.md:55 | 架构描述偏旧：现在还包括 env / 函数 / alias / umask / shopt 状态与多 session |
| README.md:23 | Release 链接大小写（GitHub 实际为小写 releases，靠重定向兜底，nit） |

## 值得肯定的设计

- memfd 传递用户数据（命令文本、rcfile、状态恢复）、「无转义层」设计从根上消灭引号 / 换行 / unicode 注入面，是全项目最漂亮的部分。
- nohup 悬挂修复（940f39c）落地完整：报告管道 NUL 终止（不依赖 EOF）+ drain 超时 abort（而非 detach，abort 释放 out_tx sender 使 writer 不等永不开的通道）+ 命令正常退出路径 dump 先于 exit 无竞态。
- 输出背压端到端打通（serve pump → 有界通道 → SSH window → daemon → client），数据不丢不爆内存（stdin 方向除外，见 P0-1）。
- 并发结构干净：map 锁不跨 await、connect 竞争胜者保留、单写者任务保帧序、ActiveGuard 配对正确。
- Windows 细节考究：DETACHED_PROCESS + CREATE_NEW_PROCESS_GROUP 拉起 daemon、管道 busy 重试、QPC / 编码问题均有意识处理。
- 部署链路（版本文件名 + sha256 + 原子 mv + stale 清理 + 字符集白名单）扎实；`rerun-if-changed` 无条件监听候选路径处理正确。

## 修复优先级建议

1. 立即修：P1-1（timeout 钳制 + checked_add，改动极小、后果是 daemon 被一条命令杀死）、P1-5（known_hosts 空文件短路，安全问题）、P2-7 / P1-6（daemon 拉起反馈与 accept 健壮性）。
2. 短期修：P0-1 + P1-4（stdin 方向背压重构，一次解决死锁 / 丢数据 / 信号失效三个问题，并补测试缺口 3）、P1-3（wrapper trap 改标志，行为对齐核心卖点）、P1-2（connect / deploy deadline）。
3. 中期：MCP 工具能力面（host 参数、二进制读写 / push-pull、isError、cwd 回显）、P2-1 / P2-2（serve 超时升级与 drain）、P2-9（known_hosts 匹配）。
4. 随版本迭代：P3 各项与 README / 测试补齐。
