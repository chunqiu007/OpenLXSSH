# 桌面新页面整合：主管独立检查点

日期：2026-10-30。结论：**新 Vault / 双栏页面已能构建，关键本地数据与路径测试通过；原生界面验收尚未通过。** 不提交 UX_READY_FOR_USER。

## 代码与构建来源

分支 `ux/termius-desktop`，HEAD `01884da`；所有既有未提交改动保留。工程师 DESKTOP-INTEGRATION-R2 修复新页面的显式 self、SwiftUI 类型检查表达式、MainActor 回调、ViewBuilder 返回值及 HostProbe 类型问题，没有移出源文件、降低并发检查或删断言。

文件路径桥接原先经 Foundation 的文件系统字符串表示损失非法 UTF-8：208 项首轮测试中原始 3 字节路径变成 5 字节。现以 URL 百分号编码的原字节解码，拒绝远程 file host、userinfo/port/query/fragment、转义斜杠、NUL 与点路径。`FileName` / `RemotePath` 仍是实际操作身份；显示文本不反向构造身份。新增边界测试，原失败断言保留。

工程师最终：Debug build exit0、App **209/0**、HostProbe build exit0；首次 build/test 和 HostProbe 类型失败保留。证据 `DerivedData/UXVerification/DesktopIntegration/R2/`。AppIntents 无框架的 metadata extraction warning 与系统 linkd 连接日志不被隐藏，不是本轮 Swift 并发警告豁免。

主管实际检查 Git diff、路径桥接实现及新 DualPaneFilesTests；独立运行正式 min26 Debug 的 DualPaneFilesTests、VaultDesktopTests、EditorDraftTests、FilesTransferTests：**37/0 / exit0**，`DerivedData/UXVerification/DesktopIntegration/Primary/targeted-tests-1.log` 与对应 xcresult。本地替身测试不是 SSH/SFTP 互通证据。

冻结 HostProbe 主二进制 SHA256：`af7c38bad6cab6556eea064692f465c8441271423f8bca6ce61c7605b4a82231`。HostProbe 是测试配置，不替代正式 min26 产品运行验收。

## 原生失败与定位边界

主管实际启动新的 marked 0700 临时根，以 `native-dismiss` 运行上述冻结二进制。只有主窗口可见与启动无会话两项通过，`menu.newHost` 后在 `host.name` 超时，进程 exit1；没有进入草稿关闭测试，不能写为通过。

原始证据：`DerivedData/UXVerification/DesktopIntegration/Primary/native-dismiss-1-{run,result}.json` 与 log；临时根中的 `smoke-native-dismiss.json` 保留。

已核的静态事实：新 VaultHostEditor 使用 SwiftUI TextField 的 accessibilityIdentifier，而旧 NativeSmoke.type 只查原生 NSTextField.identifier；两者不是同一自动化契约。命令路由确有消费者。现有证据尚不足以断言弹窗没有呈现，也不能据此修改产品以迎合旧测试。

下一轮以独立有界、marked、只用隔离数据库和目录的 `desktop-cua` 观察实际控件树；通过官方 Computer Use 操作新界面。对旧 NativeSmoke 只适配实际可见控件，不直接写 ViewModel、不降低精确字节断言、不把菜单 target 强设终端以伪造粘贴成功。

## 新 Vault 事务审查发现（修复前）

独立只读审查发现以下具体分支，当前单元通过不构成这些分支通过：

1. 密钥页解除主机关联只刷新 AppModel，不刷新保留的 VaultDesktopModel。返回旧主机列表后仅改名称并保存，会以旧全行快照把已解除的密钥引用/认证方式写回。需要同一个公开元数据失效通知及保存前陈旧编辑检测，不能靠共享 ID 恢复授权。
2. 主机保存 await 期间字段与 dirty 确认的放弃/取消仍可用，成功 markCommitted 会覆盖期间新输入，旧回调还可能关闭后来出现的编辑器。需要稳定 presentation ID、保存版本/owner fence 与一致的 in-flight 策略。
3. 原无凭据主机“记住密码”已提交，但随后刷新失败：编辑器先以仍无新 credentialRef 的 supplied 标记 committed、清密码，再保存可能选择 `.manual`，从而撤销刚保存的授权并清理秘密。需要明确“已提交、待刷新”状态与只读恢复；不能把重读失败当事务未提交或根据陈旧 ref 重新推导授权。
4. 分组/标签删除影响查询与 drag 回调迟到时没有检查 presentation owner，可能顶替新表单；所有异步显示/关闭须比对当前 owner。

主管另核本地栏首读失败后 activated 仍 true、path=nil，Refresh 再调 activate 被 guard 吃掉；保留页切换不触发 onDisappear，SFTP 初始 secret 清理不能只依赖该回调。后续限定 UI 修复并补失败→恢复和隐藏路由测试，不扩大 realpath 包任务。

## 未完成门

- native-dismiss 的 deny/allow/unknown sheet、实际编辑器 Save/Discard/Cancel。
- 实体 Cmd+V 普通与 Bracketed Paste、后续键鼠/IME/TUI。
- 新 Vault/双栏实际动作、三尺寸/全屏/连续缩放与像素对照。
- 一次性编辑器密码、两种主认证的真实附加挑战、三动作首次信任、密钥重复导入。
- 远端登录目录 realpath、设置与全局窗口/退出草稿保护。

未连接生产或真实用户服务器，未读取真实凭据；未重开长测、重建环境、推送、Apple 上传/时间戳或最终出包。
