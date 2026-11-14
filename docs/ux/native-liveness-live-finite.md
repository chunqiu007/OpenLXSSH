# Native 活性候选：有限真实验证

日期：2026-10-30。状态：**normal、独立 MaxSessions 与严格 DROP 的有限真实门均通过。** DROP前两次失败及R4测试协调修复完整保留；这些结果仍不构成 App 默认后端替换、OpenSSH 保活等价或整体体验验收。

## 冻结产物与约束

- normal / DROP：`Experiments/UXNativeShellProbe/.build/liveness-normal-b14d8a5b-a095-48c6-b2eb-8d8fe85685cb/artifacts/UXNativeShellLiveness`；SHA256 `1ec86d1c0a6542b11867491155c839823d1b1ece2275ace7b4b95a4e1701f01f`，248 项公开输入。主管执行前逐项核当前源、不可变快照和二进制，变化均为 0。
- MaxSessions：`Experiments/UXNativeShellProbe/.build/liveness-maxsessions-6dafaaca-e3d2-4d53-8048-6ebd09d136ea/artifacts/UXNativeShellLivenessMaxSessions`；SHA256 `e2d38d25fef96f5ff4ee0d8fe7a2342cea0d5c897a73f251293e0989933dcaea`，249 项输入。独立 test-only 插桩，不进入 normal / DROP 或产品。
- 仅复用原批准 keyonly 服务及 `fixture.sh collect --authorized-run --service keyonly`。固定实际容器、image、internal network、项目、context 与带外指纹，由 consumer 在读取一次性材料前另行校验。
- 主管只读取公开合同、provenance 和指纹；未打开秘密文件。秘密只由已有稳定 consumer 读取。没有新环境、服务器变更、生产连接、Keychain 或长期测试。
- 同连接单 pending 辅助 session-channel open 是真实往返候选，不发送 PTY、shell、exec 或 subsystem；会临时占远端通道槽且可能产生审计/限流。不是 OpenSSH 的 N 次独立 ServerAlive 请求。

## 保留的准备失败

1. `normal-prepare-1-failure.json`：公开 provenance 合法紧凑 JSON 无末尾 LF，却误用 PIPE 终帧解析约束；在 relay / consumer 启动前拒绝。R2 将公开文件 parser 与 PIPE parser 分层，保留严格 schema、类型、duplicate、trailing document、权限、noFollow、稳定读取及 120 秒 freshness 检查。
2. `normal-2-preflight-failure.json`：旧 generation 超过 120 秒 freshness，在 relay / consumer 启动前拒绝。主管重新确认 248 输入与二进制未变、image / fingerprint 一致，没有改写时间、重用旧合同或扩大有效期。

根目录均为 `DerivedData/UXVerification/NativeLiveness-R2/Primary/`。失败不回写成通过。

## normal：主管真实执行与独立审查通过

命令：

```text
python3 -B Tests/KeepaliveAcceptance/NativeSupport/supervise_native.py run \
  --primary-reviewed-live \
  --build Experiments/UXNativeShellProbe/.build/liveness-normal-b14d8a5b-a095-48c6-b2eb-8d8fe85685cb \
  --contract <新建 marked native-liveness-case-9b54eb1772bf/liveness.json>
```

执行目录为仓库根，完整绝对 argv / cwd / exit / 时长在 `Primary/normal-3-run.json`，exit 0，含 collect 的总时长 67.530 秒。

原始结果：`Experiments/UXNativeShellProbe/.build/native-liveness-supervisor-4d4b95842dd04028ac112a3ca443e594/result.json`。

- 实际 shell ACK、12.041 秒零输出安静期与新的 shell ACK 均成立。
- native-ready 时 6 次确认 / 6 次释放；独立 PID birth / UID / PPID 与 lsof 唯一 TCP tuple 绑定后，arm-ready 是新完成的第 7 次往返，7 次均释放、helpers 0、pending false。
- 真实远端 `exit 7`，自然结果先于取消/截止/停止/owner 丢失。
- close 完成、interaction registry drained、文件描述符回到基线。
- consumer 40992 与 relay 40984 均自然 exit 0；没有 TERM / KILL 收尾。中继原 frozen-normal pump 完成，cleanupFailed false。
- 主管另核进程已消失，批准端口无 listener。

这证明当前冻结候选在该服务上的有限正常活性和释放，不证明全部服务器、调度压力、TCP 失联检测、正式 App 接线或历史保活设置的等价语义。

## DROP：失败保留，尚无有效超时结论

`Primary/blackhole-1-run.json`：同 normal 二进制及 248 输入，exit 1，总时长 73.804 秒。

原始结果：`Experiments/UXNativeShellProbe/.build/native-liveness-supervisor-02b967e3e1404585968a5e68a789713a/result.json`。

- 到达真实 shell ACK、12.091 秒零输出、fresh ACK；native-ready 6 次确认、arm-ready 7 次确认且全释放。
- PID / TCP tuple 与精确 flow 已绑定，然而 relay arm 返回拒绝，supervisor 只保存了泛化的 `relay-command-refused`，没有保留原 reply。
- 没有 arm ACK、没有有效 clock evidence、报告里没有 armedAt；不能据此声称 DROP 已成立，也不能将 consumer 等待 drop-confirm 的 3 秒 deadline 叫作 SSH round-trip 超时。
- 原 `remote_bridge_alive` 在 arm 中先于 drain / tcp / Flow.arm；其 metadata 最多 5 秒，而 consumer 的 drop-confirm 等待为 3 秒，是待调查的静态时序疑点，不足以归因。当前不延长任一预算。
- consumer 自然 exit 1；relay 由监督器对所拥有子进程 TERM 收尾并 exit 0。该 TERM 不能被记作自然正常门。
- MaxSessions 原串行脚本在此停止，没有继续运行或被算作通过。

R3 仅允许有界保存安全 relay refusal、固定阶段分类及原 15 秒失败排空预算中的后续 closed frame。原 relay / core / pump / strict arm / freshness 与 runtime 不改。若需 adapter 观察，仅记录原 module-level 函数的一次调用/返回/原异常事实，不增加测量窗元数据调用或等待，不改变 verdict。

## R3 精确诊断与第二次 DROP 失败

R3 仅增加五个测试infra源，原 runtime / relay_control / core 及所有安全门不变。工程师Python30/0，主管独立新诊断9/0。新冻结产物：

- normal/DROP `.build/liveness-normal-195d2a39-c6c1-4849-b80b-dbd07127b319`，SHA `cc8107587c18228c6f1c11d6462aca2479261b2c395c3a04c196d5a554968643`，251输入变化0。
- MaxSessions `.build/liveness-maxsessions-7a7789c7-ef29-42d7-80c6-d27aada00c27`，SHA `795633bede54e8600e9c2962e74a3cbad793c4a2ca9c60048ff22dda81ca5e79`，252输入变化0。

主管执行 `NativeLiveness-R3-Diag/Primary/blackhole-2-run.json` 的原严格合同，结果仍exit1。原始目录：`Experiments/UXNativeShellProbe/.build/native-liveness-supervisor-e7584bd1218f468a8492a6f2a7f0f17a/`。

- 仍到proof7 settled；准确原reply为 `arm / {ok:false,failure:worker-control-refused}`。
- 远端pidfd存活核验调用实际成功，耗时 **3.080175秒**；drain随后完成，再次 tcp-state 检查抛错。客户端等drop-confirm的3秒已到，已进入关闭。
- 这些证据将问题收敛到管理arm协调的时序冲突，不是已测到SSH活性超时；不凭单次诊断精确推断未记录的底层TCP错误。
- 新有界失败排空保留failed与closed两帧；closed=true、interactionsDrained=true、fdReturnedToBaseline=true。consumer自然exit1，relay TERM收尾exit0；失败没有被清理成功升级。
- 正在实施R4最小修：仅blackhole adapter在原backend实例spawn后后台预热同token的只读guardian，原spawn一次、原Relay/Flow/drop方法不变。READY不读或缓存alive；ARM/RESULT各freshnonce现场重核receipt/UID/mode/pidfd/startticks，原5键返回。未ready/busy/timeout不重试、不延门；normal/MaxSessions不安装。
- 增加consumer确切新proof完成区间Plo/Phi与Csend/Cack，用因果偏移区间计算实际Flow.arm的最坏年龄，要求≤1.5秒；原ready→发送门和3秒确认、4～7检测、45/85/12/120预算全保留。
- guardian清理成功需远端准确终止帧、EOF、自然CLI exit0与启动线程join；只kill本地CLI或未知不能冒远端已退出。固定remote85秒上限从guardian创建起计，比consumer活跃预算更严格，不改服务器配置。
- R4目前Python42/0，主管独立guardian12/0及关键源审通过；Swift严格/normal新receipt正在串行构建，尚未live，旧两次DROP失败不改绿。

## 独立 MaxSessions：主管真实执行通过

`NativeLiveness-R3-Diag/Primary/maxsessions-1-run.json`，总时长67.477秒（含collect），exit0。原始目录：`Experiments/UXNativeShellProbe/.build/native-liveness-supervisor-842cb3fb8a384e10a363048a7ba0f268/`。

- 仅独立test-only C对象插桩；同连接先占7个无startup通道，fixture原MaxSessions8未改。
- 12.057秒零输出安静期，native-ready实际6次拒绝，arm-ready实际7次拒绝，均settled、pending=false。
- 真实public open code=-21与实际7次拒绝计数，仍由固定上游error-origin gate决定alive，不以本地数值单独冒服务器回复。
- 拒绝后fresh shell ACK成立，原shell自然exit7。
- 额外通道在proof时7、session free后0，instrumentedSessionFreed=true、无线程并发违例；close、interaction drain及FD基线均通过。
- consumer46036与relay46028均自然exit0，没有TERM/KILL，批准端口释放。preClose的几个尚未收尾字段保持其真实当时值，最终闭合事实来自closedReport。

## R4 严格 DROP：主管真实执行通过

最终normal/DROP产物 `.build/liveness-normal-9d4ef338-2021-4f27-b1ba-501173324f49/artifacts/UXNativeShellLiveness`，SHA `5f3f0eb0581fb7c5b18e0286a5a3be07be54d4aba9b8fa1854ae7351bc739c1a`，255公开输入变化0，arm64/min26；13本轮source均绑定，Swift测试为辅助验证输入而非link输入。首次build虽编译成功但漏绑测试源的receipt被拒绝并保留，补最小snapshot登记后新immutable产物才live。Python42/0、Swift6+warnings-as-errors probe22/0，主管独立guardian12/0。

主管新fresh合同执行见 `NativeLiveness-R4-Guardian/Primary/blackhole-3-run.json`，cwd仓库根，exit0，含collect总时长76.715秒。原始结果 `.build/native-liveness-supervisor-f7baf00257bb4a6987a220ccb6147663/result.json`。

- shell ACK、fresh ACK、12.034秒零输出安静期；arm前7次确认全释放、pending=false。
- consumer proof完成区间与两边PIPE因果偏移推得**实际arm年龄保守上界0.109303秒**，下界0.000031秒；原1.5秒上限满足。不是用墙钟单点或ready收到时间替代实际Flow.arm。
- 真实Flow切DROP时TCP为ESTABLISHED，独立PID birth/UID/PPID/唯一tuple/token匹配。ARM及RESULT各freshnonce现场核同一远端pidfd/startticks/UID/token，均alive。
- DROP后forwardedBytes保持 `[3508,3459]` 不变，discardedAtArm `[0,0]`，实际dropped `[52,0]`；中继两方向half-close均false，backend未先EOF；15次TCP快照。客户端自然超时关闭后可观察client EOF，这不是relay注入FIN。
- **实际DROP→自然typed timeout5.917054秒**，`nativeOperation=ssh-round-trip`；arm请求→supervisor观察5.974699秒，原4～7秒双门及≤0.5秒一致性通过。clock disagreement约0.0000073秒，elapsedAtACK0.023346秒。
- started从7变8且confirmed/freed仍7，恰好一个新增未响应probe，无取消/外部截止/stop/owner丢失先发生。
- close、interactionsDrained及FD恢复基线均true；consumer52580与relay52572自然exit0，无TERM/KILL。
- guardian精确remote source SHA `6c71252eacad17acaa4150abe613bec8fe1715dc92e061a33350955e84400148`；一owned实例真实终止fact=requested、EOF/自然CLI退出、startupjoin、本地reap均满足，forcedLocalTermination=false；不是仅回收本地CLI就称remotegone。
- 主管另核实际测试进程消失及22221～25无listener。原两次DROP失败未改写。

## 尚未通过的必要门

- 活性 probe 不饿死输入、resize、终端输出等受影响场景；策略 ADR 与设置迁移。
- 正式 App 的候选连接、changed 事实可靠交付与失败 connect 的 registry 排空观察。

**不标 UX_READY_FOR_USER，不切默认后端，不删除失败或削弱断言。**
