# OpenLXSSH UX：新ZCode会话接续任务书

日期：2026-10-30。本文件是最新会话交接，不取代完整体验规格，也不表示原开发工作已完成。

## 1. 首先控制并发和所有权

当前对话内最多3个同时活动的子智能体，主管另计；默认仅一个写代码的工程师。等待/重试/未确认退出的任务保守占位；禁止子智能体派生，不通过嵌套或工作流绕过。

先核对当前任务清单与写入范围。状态文件里的历史ID仅作线索，不能未经核对全部恢复或重复派发。用户级和项目级AGENTS已有相同规则，必须执行。

## 2. 先读实际现场，不从头开发

工作区：`/Users/liuwenshuo/Desktop/OpenLXSSH`。交接检查时分支`ux/termius-desktop`，HEAD`01884da`；main仍在重构前的`152489c`。已有4个本地功能提交：

- `60bd6d8`：U1工作区、焦点、搜索与会话交互修复。
- `2bd9cae`：连接级一次信任和已知主机精确移除底层API。
- `f06a649`：Core v3分组层级、标签、密钥标签及迁移。
- `01884da`：仓储桥接、原子复制和标签不影响认证身份。

另有33个已跟踪文件修改及21个新增路径条目（部分为目录），包括新Vault、双栏、终端、NativeShell候选和测试。以恢复时git status/diff为准；不reset、不clean、不删分支、不把所有未提交改动直接当已验收提交。按模块核对、修复、验收后提交。

本次Codex只新增调度规则与交接，没有修改这些产品实现，也没有恢复旧代理、启动App或运行测试。

## 3. 必读资料及优先级

先读用户级`/Users/liuwenshuo/.zcode/AGENTS.md`和项目AGENTS、ENGINEERING_STATE，再读：

1. docs/requirements.md、docs/architecture.md、docs/execution-plan.md、docs/acceptance.md。
2. docs/ux/termius-redesign-handoff.md、desktop-experience-spec.md、visual-reference-text.md。
3. docs/ux/termius-parity-matrix.csv、termius-parity-subitems.csv、verification-plan.md。
4. docs/ux/desktop-integration-review.md、u4-realpath-review.md、u0-native-shell-live-positive.md。
5. 需要复核某已提交阶段时再读u1-workspace-review、u2a-core-review、u2b-repository-review及u5-trust-store-review。

注意：`codex-zcode-checkpoint-review.md`是更早U1修复前快照，其中“U1尚未完成/无功能提交”已经过时；不能用它覆盖本文件和当前状态。六图文字规格有效，不需要继续重复委派无法看到像素的模型读图；新版视觉验收仍要实际截图/可视复核。

## 4. 已有验证：保留并按来源使用

- U1正式App175/0、主管关键69/0、原生workspace34检查通过；已提交。
- Core和仓储桥接已有各自独立分项证据，不因新会话重做全部迁移/底层实现。
- 桌面整合R2：Debug build0、App209/0、HostProbe build0；主管关键37/0。是当时源码的结果，不自动覆盖之后的编辑。
- 原生native-dismiss在`host.name`超时、只前2检查通过，保留失败。新SwiftUI AX与旧NSTextField.identifier搜索失配是静态定位，需确认真实界面而非修改产品迎合测试。
- 后续desktop-cua启动记录在`DerivedData/UXVerification/DesktopIntegration/Primary/desktop-cua-1-run.json`，只有启动身份/路径，不是验收结果；恢复时核对进程是否仍在，不凭旧PID运行命令或广扫kill。
- SFTP登录目录initialDirectory/realpath能力已写、包离线回归112/0，主管15/0；新增5项App consumer测试及真实服务器登录目录显示仍待。
- NativeShell候选四类真实隔离正向场景通过，同socket完成密码/密钥及KI、PTY/resize/退出；不是已经替换生产App后端，更不是完整MFA UI验收。负例、保活等价、TUI/资源与App接线仍待。
- 父矩阵116条仍INVESTIGATED；50子项中17 VERIFIED、29 IMPLEMENTED、4 INVESTIGATED。不将分项比例当整体完成率。

## 5. 下一步优先处理的具体问题

### 第一批：数据与事务可靠性

按desktop-integration-review逐项复核并修复，不先继续堆新页面：

1. 密钥解除主机关联后VaultDesktopModel未同步，陈旧主机编辑可能把已解除引用写回。需要统一元数据失效/刷新及保存前陈旧检测。
2. 主机保存await期间仍可更改字段/关闭，旧回调可能覆盖新输入或关闭后来的编辑器。需要保存版本与presentation owner检查及一致的in-flight策略。
3. 记住密码提交后刷新失败，仍以旧无credentialRef快照重试可能撤销刚保存授权。明确“已提交、待刷新”并只读恢复，不重复写/新建。
4. 分组/标签影响查询及drag回调迟到可能顶替新表单，统一owner验证。
5. LocalBrowser首读失败后activated=true且path=nil，Refresh再activate被guard吞掉；验证失败→重试恢复。
6. 保留页隐藏不一定触发onDisappear，SFTP初始secret应在离页/失效时明确清除，同时保留正确任务状态。

主管独立审查关键代码和必要新增回归，先收口一批小提交。主要编码交一个software-engineer；调查/审查按需排队，最多3子任务。

### 第二批：实际界面验证

以隔离数据库/marked临时目录运行新页面，确认新建编辑器实际控件和焦点，再适配旧probe的AX查找；不得直接写ViewModel代替用户操作或弱化断言。完成Save/Discard/Cancel、真正Cmd+V普通/Bracketed Paste、三尺寸/全屏及双栏动作。看不到像素时可继续功能，视觉项留待实际复核，不冒充已通过。

### 第三批：认证和首次连接整合

- MainView当前仍传`transientConnection: nil`。新编辑器虽只有两类主认证，但输入本次未保存密码后“保存并连接”尚未真正接线，必须补成可用流程。
- NativeShell先补必要负例、取消/代次/并发归属、保活与原有功能等价证据，记录ADR再决定后端；不能为减少密码弹窗向未知KI自动投递长期秘密。
- 首次信任UI仍旧，底层once API不是三按钮已完成；需要自动出现的关闭/仅此次继续/添加并继续，实际握手严格绑定；变化密钥仍阻止。
- 密钥重复导入、已知主机管理、设置/菜单/退出草稿保护以及116条其余细节继续按矩阵补齐。

## 6. 持续推进与交付边界

顶层主管规划/派工/独立审查，工程师只完成当前明确任务且不派生。每轮基于真实diff和证据决定下一项，普通Bug继续修，不以DONE或build0代替目标完成。

授权不变：不生产、不读取真实用户凭据、不推送、不新增环境、不重开24h或无关大文件测试；真实连接只用已有批准fixture并先核对现状。主管可在相关里程碑验收后做本地提交。

本轮终点是完整可运行的`UX_READY_FOR_USER`本地体验候选，含新版截图、矩阵、差异与待人工项。用户确认体验满意后才进入新的最终出包/Apple公证；旧build3上传许可不覆盖新产物。
