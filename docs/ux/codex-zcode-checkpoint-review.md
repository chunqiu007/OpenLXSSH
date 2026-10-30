# ZCode中断现场核对与接续位置

日期：2026-10-30。依据：用户提供的ZCode输出、当前Git差异、实际源码及既有构建/测试日志。本文是本次审查快照，不宣称控制了ZCode运行状态，也不推定其会话一定因API错误终止。

## 1. 当前进度

- 分支`ux/termius-desktop`，HEAD为`152489c`，与main同一提交。本轮功能改动全在工作区，没有新的功能提交。19个tracked文件修改，4个ZCode新增文档；其中产品Swift文件11个、测试文件2个、既有文档6个。
- 已从U0调查进入U1第一轮工作区骨架。最后记录是派发`U1-REPAIR-AND-NATIVE-WORKSPACE`，工程师ID为`agent_af75c26e-ee36-45e5-a859-c48e35692f40`；另有原生认证最小探针设计调查。这个ID仅是旧会话线索，不证明当前仍存活。
- 当前代码仍能看到被派发修复前的关键问题，未发现修复任务完成报告、新验证结果或本轮功能提交，因此判断：**U1修复尚未收口，整体体验重构远未完成**。
- 父矩阵116项均为INVESTIGATED；29个子项中24个IMPLEMENTED、5个INVESTIGATED，0个VERIFIED。不能把24/29解释为整体产品完成率。

## 2. 已有代码改动

| 区域 | 实际修改 | 完成边界 |
| --- | --- | --- |
| MainView | 顶部固定Vault/SFTP、SSH标签、加号选择器、右键/排序/临时改名/关闭；三个工作页；窄窗详情覆盖 | 第一轮结构已写，非最终视觉/交互验收 |
| AppModel/AppRepository | workspace路由/命令、全部主机catalog、连接参数identity | 新连接选择不再局限Vault过滤结果；不是认证模型已重构 |
| SessionController | 按连接参数而非只hostID复用、可见性、排序/名称、邻项关闭；保存密码前后校验排除展示元数据 | 有逻辑测试；真实两种认证切换及原生焦点尚未验收 |
| OpenLXSSHApp | 新连接/设置/标签导航/断开重连及菜单、CmdW等路由 | 部分菜单仅有命令发送，尚无完整消费者 |
| FilesController/Views/Tasks | 部分元数据比较修正、旧文件面板扩宽并移到独立页、队列显示条件 | 未实现图五本地/远端双栏，授权校验仍有全行比较 |
| SecurityViews/TrustViews | 支持嵌入Vault子页的宽度适配 | 没有完成整洁新视觉，也没有改首次信任三按钮 |
| 两个测试文件 | 增加4项测试，覆盖路由/catalog、会话可见/排序、复用快照、identity字段 | 单元结果不等于原生GUI/真实互通通过 |

## 3. 确认存在、仍需修的代码问题

1. **Cmd+F未接通**：OpenLXSSHApp发`.search`，当前workspace监听未消费；不能只凭菜单存在算完成。
2. **切会话丢搜索状态**：SessionWorkspaceView用`.id(tab.id)`重建SessionDetailView，其`@State search/found/dialog`仍在view层；需要逐会话状态与正确弹窗归属，而不是去掉id后让A状态串到B。
3. **隐藏页原生焦点未独立验证**：MainView对三个保留页面用opacity、allowsHitTesting、accessibilityHidden；这些不单独证明嵌入NSTextField/field editor与firstResponder已隔离。应验证原生容器实际隐藏/离焦、IME、剪贴板和快捷键路由。
4. **SFTP全行授权比较仍在**：FilesController.show已用connectionIdentity，但FilesConnection.validate与validateAuthorization仍使用`metadata.hosts.contains(request.host)`/`contains(host)`；展示元数据更新仍可能误取消。需贯穿真实授权链修复，并保留真正认证参数变化的拒绝。
5. **“查看任务”可能关闭队列**：全局/侧栏入口用`tasksVisible.toggle()`；从其他页进入时本来已展开会被收起。导航“查看”应显式展开，与SFTP页内主动折叠分开。

上列是当前源码可定位的待办，不冒充已经实际复现过全部原生焦点事故。ZCode之前提到六项审查问题，所提供输出未列全；应恢复旧审查报告或重新逐条确认，不能虚构第六项已知内容。

## 4. 后续主要功能尚未做

- SFTP本地/远程真正双栏、完整文件浏览及新传输队列布局。
- 精简新主机检查器、密码/SSH密钥两类UI、旧四枚举迁移和本次未保存密码直接连接。
- 两类方式下可靠的真实MFA挑战及所需后端适配；最小探针尚无交付结论。
- 首次连接自动简洁三按钮及真正会话级临时信任。
- 完整深色终端视觉/紧凑搜索、去掉常驻旧说明和按钮、颜色/键盘/IME交互验收。
- 主机卡片、分组/标签/多选、密钥管理完整交互、设置/快捷键、全部空/忙/错/取消状态及116项收口。

## 5. 已有验证及边界

- `DerivedData/UXVerification/U1/debug-build.log`含BUILD SUCCEEDED。
- `DerivedData/UXVerification/U1/debug-tests.log`在2026-10-30 03:01:10记录155 tests、0 failures及TEST SUCCEEDED。
- 结果包：`DerivedData/Debug/Logs/Test/Test-OpenLXSSH-2026.10.30_03-00-37-+0800.xcresult`；Debug App路径见同日志末尾。
- 本次仅检查既有日志，没有重复构建/重跑。日志证明当时那一轮构建/测试，不证明之后任何新编辑仍然通过，不代表视觉、实体键盘或真实MFA/SFTP新UI通过。
- 当前diff空白检查通过；没有修改产品代码、安装新版App、访问真实服务器或进行Apple操作。

## 6. 接续顺序

1. 重新核对状态与工作区，不重置、不删除分支，不覆盖现有未提交修改；查旧工程师是否仍可恢复，不能恢复则按现有diff明确重新派工。
2. 先读新增`visual-reference-text.md`。把无法读图的状态改为“已有可读文字依据，实际新版像素验收待复核”，不要改成“已完成图片/新UI视觉验收”。
3. 串行完成U1修复门并补适当原生控件/状态验证；主管复核后提交这一小阶段。不要在焦点/路由未收口时继续堆页面。
4. 按U0/U2～U6依赖继续：认证最小探针、Vault编辑、终端、SFTP及完整菜单状态。可靠上下文问题用实证和ADR解决，不按提示文案猜OTP。
5. 持续维护矩阵。交付真实本地体验候选及截图，由用户实际确认后再安排新最终出包/公证；不复用旧build3审批。

本次Codex仅新建这份审查及六图文字规格；保留ZCode全部已有未提交源码/文档，未把它们代为验收或提交。
