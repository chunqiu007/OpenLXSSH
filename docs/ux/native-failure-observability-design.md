# Native失败事实与排空：实施任务边界

日期：2026-10-30起。**设计提案及后续实施边界；包层typed事实/sealedhandle现已完成且22/55/180+主管22通过，见native-failure-package-review.md。** Apptypedchanged已统一53/0（待主管最终独立复验）；有限retirement/全局结果gate尚未实施。旧R4有限真实门只证明其原冻结源，新runtime须新consumer，不复用旧ledger。

## 已定位缺口

1. `SharedHostTrust.verify` 在 `.rejected` 异步派发 changed 后立即抛错；Native Bool reply丢具体error，close取消lifetime/token可先过滤迟到事件。App的NativeTrustEventRecord只能保存已经交付的事件。
2. `LibSSH2ShellSession.connect` 失败只带pendingInteractionTasks数字，无后续registry owner；App永久unavailableRegistryDrain fence不伪closed，但SessionController等.closed可挂全局关闭。
3. registry.begin在revoke后仍能新增，零计数不是封口后的单调完成态；仅包装snapshot不够。

## 已收敛最小方案

### Typed changed事实

- 保留现FileServiceError/NativeShellError外壳、Kind和旧init，新增默认nil的`changedHostKey: ChangedHostKey?`字段。
- 每次connect有私有锁内attempt record；store观察到changed先记录事实，再跨Bool reply(false)。handler仍best-effort，不永久等handler、不延迟close赌时序。
- convert/close后enrich保留事实；无handler时也可读准确endpoint/新旧指纹。取消早于实际观察不凭空造changed。
- App按run/token/endpoint处理error，不能用runtime已撤销token抹掉确证事实；callback/error去重，已关tab不重新开sheet。
- SFTP同轮只补同样的changed事实跨Bool传播，不扩整个SFTP排空架构。

### Sealed drain handle

- canonical只读handle仅持registry与真实nativeClosed事实，不持session/native指针/socket/回答/secret能力。
- NativeShellError追加默认nil的interactionDrain；旧pending数字保为抛出时快照。handle按不可变identity比较，不随排空改变error equality。
- 所有Task/dispatch先登记后派发，begin与revoke/seal同锁，封口后拒新增。只有真实defer finish删除pending；晚install立即撤销。
- drained要求nativeClosed、producersSealed与pending0。wait为单调有界事件驱动、waiter取消只取消自己，不用TaskGroup等待不合作loser。
- 释放session/error后handle仍可观测laterfinish；不承诺Swift能强杀不合作provider。

### App显式退役而非假关闭

- 内部关闭结果区分closed（确已排空）、retired（真实nativeclose/revoke/seal已证但provider尚pending）与incomplete（关闭/封口未知）。保留旧入口兼容。
- 总有界预算，不逐段重置；Controller不无限轮询.closed，不让A阻塞B。
- 只读退役票据不能保存整个Run/transport/terminal；必要时先抽可撤销primary owner，以weak UI事件和前后授权校验避免滞留driver。
- 同tab pending拒重连；准确latefinish清票据后只允许显式新代次。额度预留且有上限，满时在新连接/秘密读取前拒绝，不事后丢owner。
- 未知nativeclose不能以UI超时假retire；退出时如仍incomplete需如实反馈，不抹pending事实。

## 最小离线验证集

1. changed且nilhandler，typed事实准确、known_hosts不变、primary0。
2. 强制callback晚于error/close，事实不丢，不等handler、不接受变化。
3. Native Bool/convert/connect catch保字段与真实closehandle。
4. MainActor竞争error-first/callback-first一次展示，关tab不复活。
5. SFTP无callback的changed同endpoint/代次事实。
6. 不合作provider忽略cancel超过0.5秒，handle保持pending；laterreturn归零且材料不消费。
7. begin/install/revoke/seal/queuedcallback重复close竞争，不提前drained、continuation一次。
8. A pending+B健康，closeAll有限，A retired不假closed；nativeClosedfalse为incomplete。
9. A排空前拒重连，排空后新代次拒旧mailbox，terminal view保持。
10. waiter取消/晚订阅/重复订阅/额度满，其他owner不受影响；error equality排空前后稳定。

必要真实有限门：新冻结版本changed拒绝与primary0；真实handshake后有限延迟provider取消/handle归零；SFTPchanged；passwordKI/keyKI各一条不受seal误伤。旧wronghostkey有限成功不代新接口门。

## 写域与排队约束

后续runtime任务须独占Files包NativeShellTypes/Session/Authentication、SharedHostTrust/RemoteFileService及必要测试；App driver/controller接入串行，不能与FilesReviewOwners对FilesController同写。R4实验/NativeSupport当前不改runtime；所有真实receipt必须绑定实际新源，不挪用旧consumer。

不改vendor/archive/pins，不预读秘密、不降低hostkey验证、不泛扩SFTP/生命周期，不重24h或无关campaign。
