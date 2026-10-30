# U5 TrustStore 原子一次授权与精确移除：独立审查

日期：2026-10-30。结论：**底层API所列本地安全门通过；三按钮UI与实际握手集成仍未完成。**

## 实现

- `HostTrustStore.confirmOnce(_:displayedFingerprint:)`与持久confirm共享consume：单次pending实例/decision全字段/300秒连续时钟/显示fingerprint校验，所有错误都先消费。之后持有原trust.lock，重读唯一持久库并核revision与目标尚无记录，返回精确TrustedHostKey。无atomicWrite/额外持久文件，known_hosts的bytes/inode/generation不改。
- 仅firstKey/additionalAlgorithm允许一次授权。manuallyVerifiedReplacement抛temporaryReplacementNotAllowed，不能临时绕过已知变化。
- `remove(_ expected:TrustedHostKey)`锁下核endpoint+algorithm+完整公钥，missing→recordNotFound，stale/differentkey→storageChanged，只原子删除精确记录并保其余端点/算法与0600。成功更改revision并清本store pending，其他实例旧revision也失效。不读取系统known_hosts。
- public init固定ContinuousClock.now；internal测试init注入时钟仅用于确定性expiry，无系统时钟修改，无公开过期绕过。

## 差异审查

主管已读实际HostTrustStore全关键逻辑、Identity两error、12新OnceRemoval测试与1 ACL测试。持久confirm未放松、文件ACL/lock规则复用原PrivateDirectory；无新依赖/manifest/pins/上游改动。调用方依然必须把返回key绑定实际握手/会话代次，并在结束释放；底层返回不等于已建立安全SSH连接。

## 验证

工程师实际命令（`--disable-automatic-resolution`，包路径OpenLXSSHTrust）：

- Debug完整：59/0，exit0，`DerivedData/UXVerification/U5-TrustStore/debug-tests.log`。
- Release首轮：59/1，exit1，原未改BoundedToolRunnerTests读取临时pid文件NSCocoa260失败，日志`release-tests.log`保留；不是新Trust API断言失败。
- 原runner定向复验1/0，exit0，`release-runner-recheck.log`；完整Release复验59/0，exit0，`release-tests-recheck.log`。未改runner/fixture/断言，时序偶发仍记录，不把首次失败改绿。
- 主管独立：`swift test --package-path Packages/OpenLXSSHTrust --disable-automatic-resolution --filter 'HostTrustOnceRemovalTests|ACLTests.testRuntimeACLsRejectOneTimeConfirmationAndExactRemovalWithoutMutation'`，**13 tests/0 failures/exit0**；`DerivedData/UXVerification/U5-TrustStore/primary/targeted-tests.log`。

覆盖一次不落盘/精确返回、重复/错fingerprint/伪display/跨store/过期/取消/revision拒绝、replacement禁止once、remove其他端点算法保全与原子inode、陈旧记录/缺失拒绝、并发remove与replace互斥、删除再恢复不复活旧decision、存储丢失/损坏/allow及deny-only ACL拒绝。

## 后续门

现系统OpenSSH只能严格读持久known_hosts，一次继续须增加SessionWorkspace拥有的临时严格快照，仍StrictHostKeyChecking yes且只本次选中key；libssh2须在当前握手验证精确raw key，不写持久库。两个调用链分别接线与有限真实fixture正负例后，UI才可实现三个真实动作。已知变化始终独立阻止状态。当前未运行网络/GUI/Keychain/Apple/新长测。
