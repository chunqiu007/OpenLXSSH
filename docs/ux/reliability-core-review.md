# RELIABILITY Core：陈旧编辑的原子拒绝

日期：2026-10-30。结论：**最小Core事务门通过，App接线及六类可靠性整体尚在验收**。

## 需求与实际修改

针对保留Vault旧表单可能将已解除密钥/保存密码授权写回，新增兼容命令 `updateHostIfUnchanged(_:expected:)` 与 `HostEditPrecondition`。旧无条件API不变，无schema迁移/清库。

- 在既有同一个immediate SQLite写事务里读取当前host，比较预期快照；可选同时比较host-tag ID集合。ID不符、已变配置/引用/组织/展示元数据或tag关联变化即拒绝 `staleRecord`，全批回滚。
- 只有最近真实连接时间不参与编辑陈旧判断，并将数据库中的当前时间带入新行，避免用户改名覆盖认证成功更新。
- `HostQuery/HostSort/HostSortDirection`增加Equatable供UI对有效查询比对，没有改查询语义。
- 这是快照相等的乐观前置条件，不是持久revision或对所有ABA情况的承诺；与具体App保存基线/失效通知合用。它不会凭共享ID授予秘密使用权。

文件：`Packages/OpenLXSSHCore/Sources/OpenLXSSHCore/{Models,OpenLXSSHDatabase}.swift`及`Tests/OpenLXSSHCoreTests/VaultMetadataTests.swift`。

## 独立审查与验证

主管读取实际三文件diff，确认现有`apply`在一个immediate write事务逐命令执行，检查和更新间没有外部await；比较失败前的新credential登记及后续tag写入整批回滚。SQL使用参数绑定。原授权/资源清理规则和无条件调用不被替换。

工程师与主管分别执行相同命令（cwd工作区根）：

```sh
swift test --package-path /Users/liuwenshuo/Desktop/OpenLXSSH/Packages/OpenLXSSHCore \
  --disable-automatic-resolution --filter VaultMetadataTests.testConditionalHostUpdate
```

两次均exit0、**3 tests / 0 failures**。主管日志/命令记录：

- `DerivedData/UXVerification/Reliability-0d438588-299b-4506-8b8e-47334ae9c256/Primary/core-conditional-tests-1.log`
- 同目录`core-conditional-tests-1.json`

覆盖：已撤销key拒绝且credential/tag全批回滚；tag与收藏变化拒绝、单独recent推进不误拒且保新时间；两个真实SQLite实例竞争writer后读取已提交撤销，不能复活旧保存授权。全部用合成临时数据库，无真实凭据或网络。

没有重复全迁移/长测，没有将三项Core通过冒充App保存、原生草稿、MFA或全部116条通过。相关App接线另需审查和正式min26定向回归；旧失败保留。
