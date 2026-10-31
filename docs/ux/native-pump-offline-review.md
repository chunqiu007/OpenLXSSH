# Native shell pump — offline scheduling review

日期：2026-10-31。此门验证原Swift pump、准入、缓冲与资源owner，不代表真实已认证channel、libssh2内部EAGAIN或SSH互通；默认后端不变。

## 实现范围

- `NativeShellSession.swift`仅加入每实例internal typed-step closures、局部IO/liveness时钟与只读snapshot。生产未注入时调用原C函数，无全局hook或public API变化。
- offline initializer明确拒绝`establish`，不发布authenticated/shellReady事实；仍创建真实`rf_connection`并持有socket副本，取消/关闭走真实destroy。
- 原pump轮转、pending优先、单queue、5/25ms定时未改。pump正文仅四处时间读取接入clock，归一化后摘要与原正文相同；认证路径未注入虚拟时间。
- `NativeShellPumpTests.swift`六项脚本返回I/O结果，不模拟SSH报文，不直接驱动step或另写pump，unexpected调用令测试失败。

## 已验证行为

1. write跨IN/OUT EAGAIN保持真实pointer、length与bytes，部分成功才推进，OUT pending时没有其他出站step交错。
2. read/exit恢复原API；receive等待到期不会提前释放pending buffer，operation deadline仍有效。
3. resize/sendEOF包括IN-only EAGAIN均锁定原control及尺寸；timeout正确终止。
4. 单pending辅助probe，普通应用输出不延期；虚拟3600至39600秒截止、确认/拒绝及helper close/free/cleanup timeout有明确断言。
5. 有限输入、连续64KiB pull、resize及活性并行均能前进，字节顺序准确。
6. 满额128笔×2KiB输入、一个64KiB reader与一个control取消，130个任务各结束一次；真实时钟取消1.948ms（工程师全包运行，门500ms），队列/缓冲归零，native destroy一次，peer EOF与调用者FD准确关闭。

## 实际验证

证据根：`DerivedData/UXVerification/NativePumpCoverage-R1/`。

- 严格Swift并发、warnings-as-errors、arm64/min26新6项、相关67项、完整209项均通过。
- 原203方法所在测试文件逐字节不变，执行名单完整，无skip。
- 主管审查精确差异与六测试实现后，独立执行`Primary/pump6`，6项通过。
- 五件实际对象/测试产物minOS26，native guard前后通过，vendor/archive/pins及兼容五源未改变。
- 增量SHA256：`564ba76f56af0f4c248705d0305fd917a399ca00d1423e6fd8917de9dbfb6754`。

本轮没有App构建、新live/collect/签名/GUI、长测或旧normal/DROP重跑。有限真实mixed-load及默认切换ADR仍是独立门；真实App weak/FD和用户界面验收未因本地209通过而改绿。
