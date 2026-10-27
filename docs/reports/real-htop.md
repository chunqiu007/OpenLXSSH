# htop：自有进程、缩放与正常退出的真实有限验收

日期：2026-10-28。Task `HTOP-OWN-CHILD-PREP-A` / `HTOP-CONSUMER-BUILD-A` / `REAL-HTOP-OWN-CHILD-LIVE-A`。

**唯一 fresh case 已经主管独立验收：真实 htop readiness、实际 31×93、经应用公开 PTY 输入 q 后正常 exit0、termios 恢复及自有进程/文件自然清理均通过。** 仅 host15 的公开生产 Transport API 消费者，不是正式 macOS26、人工像素、htop 内部显示状态或 IME 验收；整体 Goal 未完成。

## 范围与实现

新增 `Tests/HTOPAcceptance/`，不修改生产包、依赖或现有容器。固定 keyonly 容器 `1253a29501483eb71f80e39b9af5c85e10c3a49329d5e93700fecd3f00f334f2`、指纹 `SHA256:MHUel445tN/gQtcvZikLZVE1mlWZf7U38C0zZTTru+Q`，测试远端 UID10000。

- `Core.swift`：封闭帧/状态元数据与顺序预算；要求 ready 后实际 sized31×93，严格五帧 load-ready/hello/exited/done/returned。
- `Main.swift`：公开 DirectSSHSession/SystemOpenSSH+PTY+SwiftTerm；独立 short shell ACK 后才加载固定探针。管理状态 ready 后才通过终端 API resize，实际 sized 后才通过公开 sendInput 发送 q。认证回调一律拒绝，无 Keychain 或已保存密码路径。
- `remote_probe.py`：nonce0700 自有目录，HOME/XDG_CONFIG_HOME/HTOPRC 均指向该目录；启动一个自有 sleep，再运行 `/usr/bin/htop --pid=<该子进程>`。不使用 F9，不选择或终止用户进程，不读用户配置。
- readiness 同时验证自己的 htop 尚存活、UID/PPID/start/session/TTY、comm 与固定 argv、前台进程组和真实非 canonical/noecho。尺寸来自 TIOCGWINSZ，只有31×93才通过。q 后要求 htop 自然 exit0；自有 sleep 被回收，pidfd 确认结束，实际 tcgetattr 等于原值。
- `StatusQuery.swift`：仅固定 Docker Desktop CLI/本地 endpoint/exact CID/UID10000 的只读管理通道。nonce、parent PID/start、目录与 status inode 绑定，共享锁、0600/nlink1、闭合≤2048B JSON 和前后元数据稳定；不通过管理通道输入 q 或修改 TUI。
- 清理只处理自有固定 status/htoprc 与空目录，未知项保留并失败，不递归删除，不扫描/kill 其他 SSH 或 htop。

已有 htop 版本实测为3.3.0。版本结果本身不作为交互通过证据。

## 源码、离线与签名审查

主管已读核心状态机、完整远端探针、只读 status reader 与实际 consumer 输入/退出路径。独立8项 pure tests及完整 Main/LiveInput/StatusQuery API typecheck 通过，源审证据：

`DerivedData/Verification/primary-htop-source-67c13bf1-3eee-4168-8496-0069fd19d810/`

`python3 -B Tests/HTOPAcceptance/build_host.py build` 仅增量编译 HTOPCore/Offline/consumer，复用冻结89033的 Core+八依赖共九只读对象，不调用依赖全量构建。11 snapshots，31命令全部exit0；其中29条普通命令有独立日志，两个签名命令只有脱敏命令/退出元数据，不夸称31个完整输出日志。35个核心检查与8项 pure/typecheck 通过。

冻结 App：

`Tests/HTOPAcceptance/.build/host-853d6ab5-d853-41d6-8aa7-aee310588c50/OpenLXSSHHTOP.app`

| 内容 | SHA-256 |
| --- | --- |
| 已签 main | `7f1e1b87734a68c63cba1bf70e770412ea1e6a7106cd27d3eecc512ed2390d46` |
| 已签 helper | `d86e091ed9840649e911320eb5a915fb48f26460816a975f0736e8aef25079f5` |
| 实际嵌入 probe | `4c78fd40f9ab1d4c8b92237d8bbc27369d18fe76da37b5ad54022a3b5fcce7eb` |
| 构建 manifest | `c9db6c286fcbd624ee374dfd98fe9ad58156cf678273acfe0ffd40083db49c18` |

主管独立复核了当前源/快照、九对象、实际编译和链接输入、probe完整Base64与SHA确实在已签main、同Team/Development/Hardened Runtime/空entitlements/strict App与helper、arm64/min15和35个实际核心检查。default、`--help`、validate 均exit0且惰性；位置参数 `help` 按原契约exit2。主管初始检查脚本错误假设每个签名记录有log、误用位置参数help，两次只读检查失败保留，修正读取实际schema/参数后通过，无产品改动。

签名审查：`DerivedData/Verification/primary-htop-signed-final-059916c2-e4d4-477d-8347-5f1ffea6532a/`。

## 唯一真实案

执行：

`python3 -B Tests/HTOPAcceptance/.build/htop-live-838db0cf-1a3e-4284-9c84-779fa7f2c8d5/run_case.py`

collect/relay/consumer各一次，没有源码重写、第二案或断言降级。外层exit0、consumer82038 exit0（外层观测25.217s），stderr0，原报告无failure。

- strict5帧；connected1，authenticationRequests0，postConnectedAuthenticationRequests0，stopfalse。
- 独立shell ACK成立；两次严格只读status观测支持ready与sized。
- 实际rows31/cols93；quitEnqueued、normalExit、remoteCleanup、returnedToOuter、remoteProcessReleased全true。
- 应用公开输入5次/返回5次，最后一个字节为q；关闭前同SSH82109仍connected，关闭后closed/PIDnil/FD回基线。
- 远端 parent17886/start10752218、htop17888/start10752231、sleep17887/start10752231均已取得精确身份。nonce `b8de92d60c654710bfa5a641c02116ed`。
- 原状态configPresent=false仅表示sized时未见配置；完成路径对可能生成的固定htoprc另行检查并清理，不把该false扩称整个运行从未生成配置。

原始结果：`Tests/HTOPAcceptance/.build/htop-live-838db0cf-1a3e-4284-9c84-779fa7f2c8d5/consumer-result.raw.json`。

SHA-256：`37fece68d72bc4a13f85962bbbac71ef79470832ac519628366377017ba453d7`。

## 资源后验与独立验收

远端三个已知PID的pidfd后验均absent，nonce root/status/htoprc自然消失，未手工远端清理或发信号。relay81938、consumer82038、SSH82109均不存在，helper列表为空；relay accepted/finished/rejected/cleanup_failed为4/4/0/0，22221～22225无listener，本地本案runroot已精确删除。

fixture CID/image/project/network/cap8/volume/readonly/健康状态未变。源/九对象/签名bundle/parent manifest哈希保持匹配。

`final-postverify.json` SHA-256：`537ce49f108a5cb355c1156dbc7d34cbf934652ca1906d4ff010c9758b7895c2`。

主管独立读取原JSON、逐条核验结果与身份关系、再次只读核验固定nonce/三pidfd/本地三PID及端口、重核源/对象/bundle，证据：

`DerivedData/Verification/primary-htop-pass-173f7f6f-9cc0-4cec-8d51-118c3a0fca2d/`

**有限程序化htop交互分项通过。** pixelsVerified/internalStateVerified/imeTested/productAcceptance均false；不以进程readiness证明所有画面像素正确，不声称btop、Docker日志、Claude Code/OpenCode或全部TERM-05通过。正式macOS26、人工交互、长测及发布门保持未满足。
