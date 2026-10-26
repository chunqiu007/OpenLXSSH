# P7 五终端视图有限本地输出压力

## 结论与范围

本轮有限 HostProbe 补证通过主管独立审查与复验。五个真实 `NativeTerminalView` 使用逻辑 session driver，同步接收确定性 UTF-8/ANSI 输入，并通过原生控件切换标签、搜索、粘贴、缩放和关闭。**没有建立 SSH、PTY 或网络连接，没有读取 Keychain；不代替真实五会话、远端输出背压、人工像素/IME、Release PERF 或 24 小时验收。**

修改仅为 `Application/OpenLXSSH/SessionProbe.swift`、`NativeSmoke.swift`、`Tests/OpenLXSSHAppTests/SessionPressureTests.swift` 和 Xcode 测试引用。全部压力入口受 `HOST_PROBE` 限定；正式产品平台未降低。fixture builder 使用弱引用观察 driver，不以测试自身的强引用阻止视图回收。

## 负载与观察方法

- 五 view，每 view 200 批、814,108 字节，总计 4,070,540 字节。每批不超过 8,192 字节，生成并同步 feed 后等待至少 40ms；最多一批生产队列，不用丢弃输入维持响应。
- 内容包括中文、组合字符、SGR、清行/回车以及各 view 唯一末 marker。feed 计数精确相等，最终 marker、历史搜索及真实粘贴回调均检查；这不等于逐字检查历史中每一个字符的像素。
- 初始 80×24，历史 10,000 行；终态 120×26，保留 9,803 行。隐藏标签持续消费输入，窗口 hide/show 不重建 view。
- 50ms heartbeat 的本轮自检阈值为 500ms，仅用于发现明显主线程停顿，不是产品帧率或硬延迟预算。
- 资源取自自有 HostProbe PID 的 `ps` 与 `proc_pidinfo`。短时 RSS、采样 CPU 和 FD 不是长期泄漏证明，也不包含真实 SSH 子进程。

## 工程师证据

`DerivedData/Verification/p7-app-output-stress/`：

- `delivery-tests.log`：`Scripts/build-app.sh HostProbe test`，105 tests、0 failures、exit 0，保留原 103 项及新增 2 项。
- `delivery-native-report.json`、`delivery-pressure-metrics.json`：进程 exit 0，77 项检查，23 轮交互；全场景 23.669s，输出 14.056s。每 view 隐藏消费批数 144/159/163/166/168，heartbeat 最大 374.24ms。
- `delivery-release.log`：`Scripts/build-app.sh Release build-for-testing` exit 0；arm64/min26，正式二进制未含压力 fixture 符号。
- 该次构建发生在 Transport voucher 修复之前，16 项 shipping 输入当时前后未变；不能据此证明旧 App/helper/candidate 已覆盖新 C。后续受影响回归另行记录。

工程师资源观察：建立 view 前 RSS 80.14MiB/FD9，五 view 已建 115.28MiB/FD16，输出停止 282.97MiB/FD16，关闭且 weak view 为零 231.38MiB/FD16，重开 232.16MiB/FD16。外部有限采样观察峰 RSS 约 283.22MiB。内存没有回到冷启动值如实保留，不解释为已经证明泄漏或无泄漏。

## 主管独立复验

宿主 macOS 15.8.1/24H32、arm64、Xcode 26.3。此时 `AskpassMach.c` 已含接收后拒绝 voucher 的最小修复，SHA256 `18ab8f1644d645bdb17a87fe66bae52a80c5ecc5b0fc66334df6f380f35755e7`。

1. `Scripts/build-app.sh HostProbe test`：exit 0，105 tests、0 failures。证据 `DerivedData/Verification/p7-manager-app-review-4c8d9445-50f6-4ab0-a2fe-81a9fe40dc3b/hostprobe-tests.log` 与 `hostprobe-tests-result.json`。
2. 该新 binary 的 `--self-test-phase sessions-pressure`，独立标记 UUID 临时目录、外部 60s timeout：真实进程 exit 0。全场景 20.876s，输出 11.497s，22 轮交互，76 项原生检查全部通过，heartbeat 最大 377.93ms。每 view 814,108 字节/200 批，五个 view 同实例、隐藏消费、末 marker、搜索、17-byte 粘贴与历史界限均通过。
3. 关闭后 closed=5、disposed=5，`updateUiClosed()` 真返回；weak view 存活为 0，重开无标签；自有 PID 已退出。
4. 五 view 已建 FD16，关闭且 weak view 为零时仍 FD16；冷启动 FD9。RSS 时点为 82.39/115.52/299.47/267.69/269.50MiB（建立 view 前/已建/输出停止/关闭/重开）。这些是时点值，不冒称完整运行峰值。

主管原生证据目录 `DerivedData/Verification/p7-manager-pressure-ec3b692e-0d5d-472f-81ec-ed0007a38c26/`，含 `execution.json`、`smoke-sessions-pressure.json`、`pressure-metrics.json`、`validated-summary.json`。

主管首个外部解析脚本误把工程师本轮 77 项检查总数当作固定下限，因交互循环本次只有 22 轮、实际 76 项而 exit 1；原生进程本身成功。随后读取原始报告，按每个必需行为的检查名及完整指标复核通过，没有修改产品、减少断言或重跑掩盖。检查总数受交互轮数影响，不能机械固定为 77。

## 验收影响

支持 AC-30 的有限本地渲染输入/交互与 AC-32 的视图释放分项证据，不把这两个产品条目标记整体通过。真实 SSH/PTY、系统 macOS26、所有 TUI/IME、Release App 加子进程资源、网络异常及 200 次/连续 24h 仍须对应环境下验证。没有改动电源设置、创建定时任务/常驻服务、开启宿主 SSH 或上传产物。
