# SFTP 服务生命周期与明确授权重试审查

日期：2026-11-02。仅记录本轮已验收的包层增量；不代表完整双栏或整个 App 验收完成。

`TransferManager` 的快照现在发布服务可用、正在关闭及实际关闭返回后的移除状态，并带单调 revision。注册与首份快照在同一 actor turn 返回，消费者可拒绝迟到的注册前空快照。活动 lease 不被闲置关闭，正在关闭的服务拒绝新操作。原闲置时限不变，不把快照当网络健康证明。

新增明确替换服务的 `prepareRetry` 重载，沿用原任务的主机、路径和类型，重新生成清单及批次；新目标的能力确认独立提供，不继承旧连接的授权。旧重载仍拒绝已关闭服务。App 层还要求完整连接身份匹配及重新通过系统选择器授权原本地位置，相关 App 整合代码尚未随本提交纳入。

主管已独立阅读实际 diff、正常与关闭竞争分支及两项新增回归。当前两个包文件 SHA 与 Task29 的实际验证输入逐字一致。`TransferManagerTests` 在 arm64/macOS26、严格警告配置下实际执行18项/0失败，exit0；217输入前后不变。原命令和结果：`DerivedData/CodexTakeover/Retry-Rebind-29/package-command-r1.json`、`package-result-r1.json`、`package-tests-r1.log`。此处复用同源有效结果，没有声称另跑一轮。

R10 完整 App 的实际 GUI 窄门：取消下载、手动同身份重连、重试选择器取消保原任务、错误本地位置被拒、重新授权原位置后新审核，再明确确认；新任务改名一个14B文件并跳过45B文件，UI明确部分跳过。两个原文件 SHA 不变，新副本与原14B文件相等，证据 `DerivedData/CodexTakeover/20261101/candidate-live-5/r10-retry-files-sha.json` 及同目录 `r10-retry-*.txt`。不是续传、自动重连或59B全部成功。

保留原闲置 UI 陈旧、旧服务重试拒绝、构建及几何崩溃等历史失败。批策略传播、跨栏/Finder拖放、同暖态资源趋势及整个 UX_READY 仍需各自证据。本地提交不授权推送、生产连接或 Apple 操作。
