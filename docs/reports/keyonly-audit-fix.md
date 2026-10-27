# keyonly 审计能力修正：单服务运行检查点

日期2026-10-27，Task FIXTURE-KEYONLY-AUDIT-FIX-A / KEYONLY-RECREATE-PORT-R1。

**keyonly 现已增加 AUDIT_WRITE 并在真实原daemon强制PTY中返回精确ACK/exit0。原另外三个认证服务的CID/启动时间、内部网络及key-data namedvolume未变。单服务管理命令首次exit1/incomplete仍保留，后续精确start恢复另记，不追认为原命令通过。App终端/TUI和传输生命周期复验仍进行中。**

## 修复范围与来源

依据 `docs/reports/pty-audit-capability.md` 的同image单差A/B：原七cap时-tt255/无ACK，只加AUDIT_WRITE bit29后-tt0/CRLFACK。`compose.yaml` 仅keyonly覆盖为原七项+AUDIT_WRITE，其他三服务保持原七项；不新增AUDIT_CONTROL/READ、TTY_CONFIG、SYS_ADMIN或privileged，不放宽readonly/noNewPrivs/网络/资源/挂载。

环境管理增加独立双事故门 `recreate-keyonly --authorized-run --manager-authorized-keyonly-recreate`，固定本project/image、single keyonly/no-deps/no-build/pullnever、原卷/网络验证及另外三服务ID/starttime核对。该开关不等授权。每service精确cap门同步到relay，原七项keyonly在变更后不再被当当前有效目标。历史旧consumer/CID/FP/报告不被重写。

主管已读关键差异及原控制流，独立环境39/relay28/MINA管理35离线通过：`DerivedData/Verification/primary-keyonly-audit-fix-offline-f8f24d3b-1820-4e59-a08c-d60b8103c486/`。并行额外只读review因账户并发限额失败，未计为审查通过；采用主会话直接完整关键代码审查，不为该限制另换provider或绕过。

## 原单服务命令与精确恢复

真实执行一次manager动作，预先五批准端口无listener，四容器没有用户进程/sshd子会话。原命令exit1，保存public preflight与 `status=incomplete`：

`Tests/IntegrationEnvironment/.runtime/keyonly/recreate-8bba5916cace/`

Compose已删除旧keyonly并创建新容器，但新容器处于Created/PID0/State.Error空、未启动；其他三服务继续Healthy。没有重复recreate。管理层 `_bounded_stdout` 抑制stderr，不能从当前记录还原Compose具体错误。整个动作期间持有loopback bind预留与Docker启动检查可能交互；这是受控start恢复支持的疑点，不编造实际errno。

主管核新完整CID/image/labels/keyonlyservice/原namedvolume后，仅 `docker start <该CID>` 一次，exit0/0.083s，随后Healthy；原action/old result仍incomplete。后续R1只把固定端口预留限制在空闲预检，执行Compose前释放，保留活动relay拒绝门；不通过重跑真实recreate来改写旧案。

## 当前正式fixture身份

- Project：`openlxssh-fixture-61ed25328c13`
- 固定image：`sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363`
- 新keyonly CID：`1253a29501483eb71f80e39b9af5c85e10c3a49329d5e93700fecd3f00f334f2`
- 新主机指纹：`SHA256:MHUel445tN/gQtcvZikLZVE1mlWZf7U38C0zZTTru+Q`
- 原NetworkID：`b949645e158058f7484e21b758459f8d0e6a284f0d2bb641879faf67f2b50ed1`
- 原数据卷：`openlxssh-fixture-61ed25328c13_key-data`；卷元数据及挂载精确相同，无down-volumes/removevolume/corpus生成。
- 另三服务CID/StartedAt逐项与preflight相同，cap仍七项，未重启。

`/run` tmpfs bootstrap换了host/clientkey与测试凭据，旧导出generation不再代表当前keyonly；这是预期测试实例变化，不是静默绕过主机信任。原namedvolume保留，但bootstrap会刷新home/.ssh与受保护fixture，未宣称整个卷字节逐一未变/未重算旧2GiB corpus SHA。旧完整文件campaign结果仍只属于旧实例。

## 真实修后PTY与证据

同已审固定Linux客户端helper、新一次UUID token、strict本实例带外known_hosts，原daemon-tt实际exit0/0.235327s、53B精确CRLF ACK，pty-accepted/exec-accepted/exit-status分类、childreaped/pipesclosed、无deadline/信号。stdout/stderr仅内存，不记录原文。

初次主管调用手抄了33字符token，被参数门拒绝，未连接；定位后使用uuid.hex产生新合法token执行一次。不放宽32hex契约、不把参数拒绝称PTY故障。

public preflight/resultincomplete、精确start argv/exit、修后identity与PTY结果：

`DerivedData/Verification/primary-keyonly-audit-recreate-f807abfe-183d-40b8-a90f-e1668888f046/`

其中 `postcheck-and-pty.json` 标明 `originalActionRemainsIncomplete=true`、`volumeUnchanged=true`、`otherThreeExactUnchanged=true`。这些是环境修正证据，不是App输入/Ctrl+C/Vim、人工IME、完整认证或macOS26验收。

## 活动消费者后续约束

- AppRealIntegration仅更新两compiled测试pin为新CID/FP，新签名快照及build之后的新collect；保留inflight/sessionConnected/16MiB/安全probe/生命周期断言。
- RemoteTerminal契约本已动态CID/FP，可用冻结已审App，必须fresh contract+generation/带外信任；旧结果和旧generation不覆盖。
- 旧RemoteFile/DiskFull/AuthFailure campaign来源pin与报告不改、不为换测试实例重跑已通过大文件验收。
- 所有真实网络场景串行占rootruntime，工程师source/offline域独立。

整体Goal NOT COMPLETE。
