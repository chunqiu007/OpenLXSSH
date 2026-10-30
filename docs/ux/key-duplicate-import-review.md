# 重复公钥导入：精确 review / reuse 审查

日期：2026-10-30。状态：**本地模型/包门已通过；实际导入 UI 与内联 picker 原生操作尚未验收。** 未增加数据库公钥唯一约束，不宣称任意跨进程直接注册具备原子去重。

## 实现与主管审查

本轮七文件及初始冻结在 `DerivedData/UXVerification/KeyDuplicateImport-R1/source-ready-hashes.json`，本轮相对 before 增量在 `source-ready.diff`。主管已读取实际增量和关键源码，而非仅依据工程师返回。

- `KeyStore.reviewImport` 使用原安全目录/文件读取和系统 ssh-keygen 验证；验证 stage 在返回 review 前精确清理。公钥规范表示不含 comment，不凭源文件名或整个私钥文件摘要去重。
- review opaque token 单次、默认120秒；仅内存保源 bytes、dev/inode、owner/mode/link/size、mtime/ctime 与父目录身份。confirm 再安全读取核身份和 exact bytes，写入只采用已审查的 bytes；原 import/generate API 保持。
- `SecurityCoordinator` 在注册和记住口令前读取当前已登记的准确 UUID 的规范公钥；任一已登记文件不可读即 fail closed，不扫描私钥目录，不读取 Keychain。前后 key metadata snapshot 不同则拒绝。
- duplicate 只提供已有精确候选的复用/取消，丢弃本次 remember 输入；不新增 key/credential/journal，不读取或改写已有口令，不改旧 label。多个 legacy 重复候选按 UUID 稳定排序，不删除合并旧实体。
- confirm 重新核候选。无重复才走原 journal 新建事务；commit 后、remember-save 前再查一次。若源被替换、review失效、选中实体删除或授权变化，拒绝而非猜另一个对象。
- 已提交新 key 的 label 失败仍只重试其 UUID；复用是独立终态，沿现管理/inline picker UUID 完成通道返回真实 label，不进创建/标签重试。
- 取消、迟到 owner 和验证清理失败使用精确 review/恢复票据；不清理未知资源或修改导入源。

本任务没有改 Core schema、依赖、Xcode 工程、Auth 消费者或 vendor。与认证任务共享 Coordinator 的25行 material块 SHA 保持 `d1851c878fa1355ee9b26ebfa6269e5e576f3468765d27a5ff1043a94aa76a03`。

## 实际验证

### 主管独立正式 App 定向

`DerivedData/UXVerification/KeyDuplicateImport-R1/Primary/app-tests-1.{json,log,xcresult}`。

- 仓库根执行正式 Debug / arm64 / macOS26 `xcodebuild test-without-building`，exit 0。
- **34 tests / 0 failures**：KeyDuplicateImportRegressionTests 8、SecurityIntegrationTests 19、KeyLabelCompletionRegressionTests 7。
- source-binding 另核六个产品/App测试源对冻结摘要一致；使用已经成功的正式整合 build，不把当前 Auth 后续未编译改动当此测试来源。
- 覆盖不同名/重编码/不同comment同规范公钥、无凭据save/read/delete、旧label/授权不扩大、legacy多候选、源替换、删除/新增候选、busy/lateowner、不同公钥同文件名。
- 所有凭据为 fake；临时新建密钥通过成熟系统工具验证，不读真实用户 Keychain 或密钥。

### Security 包严格定向

原命令保存于 `Primary/package-tests-1.json`：Swift6、完整严格并发、warnings-as-errors，Swift/C 明确 target arm64-apple-macosx26.0，filter 为 KeyImportReviewTests / KeyStoreTests / KeyACLTests。

- 首次 exit 1，29 tests，2处断言失败；原日志保留。
- 根因是新包测试将 Ed25519 与 RSA 放在同一 destination循环；Ed已成功commit后，RSA的“错误口令后/正确review后”仍期待目录只有 `.OpenLXSSH.lock`。这是夹具基线错误，不是证实产品留了stage。
- 仅修改 `KeyImportReviewTests.swift`：用已commit准确文件名→bytes字典形成每轮完整预期集合；每一步同时证明所有已成功key字节不变。没有删成功key、放宽忽略文件或移除清理断言。
- 修后 **29 tests / 0 failures / exit0**：新增 review7、原 KeyStore11、ACL11；5.827秒。其余六源hash不变。
- 工程师记录：`Engineer/ExactTestRepair/package-tests-2.{log,json}`、`test-repair.diff`、`final-hashes.json`。
- vtool逐一核 KeyStore、KeyFiles、review test、SecurityPOSIX C对象及最终xctest均 MACOS/minos26.0/SDK26.2，exit0。不是以命令字符串或Swift Testing宿主行代目标核验。

主管已独立审测试修复实际diff、运行命令、min26记录；最终测试SHA `07595c66bd911fb38c6fbdd5d6ea6bec5cbb48762fe572fc4c09266cf0dcf59e`。产品源未变，因此不机械重复已独立通过的App34。

## 局限与人工重点

- 去重依赖生产唯一 SecurityCoordinator、KeyStore目录锁和当前metadata重查。绕过入口直接 repository.register 的任意外部并发，没有数据库公钥 unique 约束；本轮未扩 Core 迁移。
- 实际原生选择文件、重复提示、复用/取消、管理与主机内联 picker 回填及紧凑布局仍待。模型回归不代表 GUI 或视觉验收。
- Swift/Data临时副本不承诺完全擦除。review过期/关闭只减少驻留并释放引用。
- 本门不代表全部116项或本地体验候选完成；无push、无新最终出包、无Apple操作。
