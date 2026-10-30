# RELIABILITY-R1：桌面事务与短期输入独立审查

日期：2026-10-30。结论：**交接六类可靠性问题的本地逻辑/真实合成SQLite范围已复验；原生控件与真实认证门仍待**。不提交UX_READY_FOR_USER。

## 来源与审查方法

分支`ux/termius-desktop`接续HEAD27a1d26，保留全部既有未提交新Vault/双栏/终端/NativeShell整合。主管保存修复前公开源码至`DerivedData/UXVerification/Reliability-0d438588-299b-4506-8b8e-47334ae9c256/before`，按该副本审本批增量，不将相对HEAD的所有既有整合差异都冒成本轮新作。

Core最小前置条件已独立3/0并提交`5e73f7c`，详见`reliability-core-review.md`。App产品/测试已冻结，工程师最终正式Debug/min26定向119/0；主管独立关键32/0加导航准确symbol1/0。上述均不是网络互通/像素证据。

## 六个问题与结果

| 问题 | 实际保护 | 覆盖与边界 |
| --- | --- | --- |
| 密钥解除关联后保留Vault陈旧 | AppRepository单向metadataChanges，commit发布、read不发布；App/Vault订阅刷新；保存携带Core原子host/tag基线 | `ReliabilityVaultTests`实际协议派发、解除key后两消费者更新、无reload循环；`ReliabilityEditorTests`旧表单拒绝并显式刷新恢复；Core跨writer撤销不复活 |
| 保存await期间新输入/关闭覆盖 | 实际View使用每editor状态owner；writing冻结字段、关闭及nested动作；save token和presentation UUID/epoch拦迟到 | 挂起apply后输入拒绝、失败保草稿，旧成功/错误不mark/关新表单；原生Save/Discard/Cancel仍须新probe |
| 记住密码已提交但刷新失败 | saveHostCommitted返回真正新credentialRef；已保存待刷新只读，重复Save只重读，清UI秘密，不重复写/新建 | 新建/编辑两案save1/delete0/apply1，读失败恢复保持授权；postcommit cleanup pending如实提示；FakeCredentials不真实Keychain |
| 迟到impact/drag/key回调顶替 | PresentationOwner ticket核当前owner/epoch，所有新显示/关闭按准确ID；删除失效filter后用有效query重新读 | 合成gate覆盖旧impact/drop/picker/save/confirm；实际View接线源审，GUI回调仍待原生验证 |
| LocalBrowser首读失败刷新无效 | path=nil可重新activate，loading拒重入，token拒取消/隐藏后的迟到读取 | 实际marked本地临时目录失败→刷新成功；成功路径/history保留；离页仅取消metadata、不取消已确认mutation，mkdir/delete真实报告保留 |
| 保留SFTP页离页秘密残留 | View-owned非Codable初始input，以workspace可见性/host连接身份/非秘密epoch清空；take后即清 | 元数据重命名不清身份，真正参数/代次/离页清；连接/TransferManager/job不取消；测试不是实际屏幕内容擦除或Swift所有副本零化保证 |

## 审查中修复的回退与失败

- 首轮正式定向59项有3个断言失败，定位`AppRepository.metadataChanges`的actor同步实现与协议async默认实现派发不一致。改成显式async witness并增加`any AppRepositoryProtocol`直接mutation→stream事件回归；没有延长等待或删断言。原失败log保留。
- 连续SwiftUI类型检查超时后拆body、sheet分发和闭包为小表达式；另修unhosted tests共享source位置和MainActor闭包类型。没有降并发/警告检查，前5次build失败保留。
- 独立审查防止普通离页通过owner失效静默丢主机草稿：App导航关闭门在select/open资源副作用之前，dirty先请求原保存/放弃/取消；无授权不新建隐藏会话。
- 独立审查发现本地deactivate原拟cancel所有operation，会取消已确认变更/丢报告；改为区分metadata与mutation，新增真实临时文件回归。
- 新导航保护会拦在writing中的“保存并连接”；最终实际View使用`saveAndFinish`，完成提交/刷新后先释放准确editor owner再非秘密路由，新增AppModel+recording router组合证明open1；失败不回滚已存配置、迟到不关新owner。本次transient handler仍未注入MainView，不能把此视为本次密码直连完成。
- 最后显式重新读取放弃草稿也清短期输入，并在最终源复验。

## 实际验证

工程师日志根：`DerivedData/UXVerification/Reliability-0d438588-299b-4506-8b8e-47334ae9c256/Engineer/`。

- 正式`Scripts/build-app.sh Debug build-for-testing`最终成功；后续定向`xcodebuild ... -scheme OpenLXSSH -configuration Debug ... MACOSX_DEPLOYMENT_TARGET=26.0 test`。
- `targeted-tests-5.log/.xcresult`：**119 tests / 0 failures / exit0**。涵盖DualPane/EditorDraft/ReliabilityEditor/ReliabilityVault、Files/Session受影响回归及SecurityIntegration。
- Core `--filter VaultMetadataTests.testConditionalHostUpdate`：3/0，独立结果见Core报告。

主管独立，cwd工作区根，固定版本图/同正式min26 Debug（完整argv、duration、exit记在每个json）：

- `Primary/targeted-tests-1.log/.json/.xcresult`：DualPane19、ReliabilityEditor7、ReliabilityVault6，共**32/0 / exit0**。
- 首次导航过滤使用了不存在的symbol，该suite实际0项，不能算覆盖。按实际函数名纠正后独立`Primary/navigation-tests-1.log/.json/.xcresult`执行`SessionControllerTests/testVaultNavigationRefusalPrecedesSessionSelectionAndNewSessionAllocation`：**1/0 / exit0**。
- `git diff --check`通过。原AppIntents无依赖的metadata warning、系统linkd连接日志保留，未冒成产品失败或静默滤除。

## 剩余门

新NativeSmoke适配的实际字段/草稿关闭、两次真正CmdV、三尺寸/全屏/分栏动作与截图仍待。不能以这些测试把父矩阵全部升级。一次性密码、两类真实MFA、首次三按钮信任、密钥去重、设置/全局window-quit草稿保护和全部116项仍需后续。

没有生产、真实用户凭据、真实Keychain写入、fixture重建、新环境、Apple操作、最终出包、24h或无关大文件重跑。
