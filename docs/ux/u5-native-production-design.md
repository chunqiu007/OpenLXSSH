# U5 下一接线：NativeShell生产适配与等价性门

日期：2026-10-30。状态：**设计收敛，未定案替换默认后端**。只读任务 AUTH-NEXT-DESIGN-R1 已结束，无源码改写、构建、网络/Keychain/GUI动作。已有四个NativeShell正向案例仅按 `u0-native-shell-live-positive.md` 保留；不是新App接线通过。

## 实施边界与推荐

保留已经存在的成熟libssh2单socket shell实现，不重写SSH/密码学。新增App adapter前先补必要负例及保活证据；采用后须写正式ADR。旧System OpenSSH继续保留，不扩大Askpass首masked自动秘密投递白名单。

### 所有权和终端

- 每tab保留同一个NativeTerminalView；每显式重连创建新的native session/token。native串行队列唯一拥有socket/libssh2，App只有一个receive consumer；每块完成MainActor feed才取下一块。
- native路径不创建PTYGeneration/LocalProcess/Askpass，不能给同流配置两个reader。SwiftTerm呈现、历史/搜索/精确粘贴保持。
- App输入必须在创建Task/复制队列前有界准入；resize合并为一个in-flight加最后待发尺寸。关闭同步撤销输入/回答/intent，再await实际native.close；断开保留视图，关tab才release。
- `.connected`以实际shellReady为依据；EOF、远端exit、取消和transport失败区分，libssh2 reportedStatus0不证明收到exit-status。

依据：`NativeShellSession.swift`的单队列/有界pull与原`PTYGeneration.swift`唯一LocalProcess owner；`NativeTerminalView.swift`渲染不要求LocalProcess。

### 类型化秘密与多字段挑战

现SessionAuthenticationPrompt是Askpass单字段，不足以表示KI多字段/回显/零通知。新增backend-neutral primaryPassword、managedKeyPassphrase、keyboard(name/instruction/prompts)及legacyAskpass payload；回答绑定token和每请求ID，一整轮提交。复用Files的呈现结构，不复用其controller owner。

- Native public connect需兼容新增typed primary provider，在实际握手信任和method discovery之后获取选定primary材料；返回类型仍须匹配预选方法，一次调用，不切换长期凭据探测。
- 一次性intent绑定最终已提交host身份、新session/generation、primaryRequestID；校验和take之间不再await。消费先标used并释放引用。取消、失效、关闭、失败不能供重连使用。
- 本次显式输入优先；saved读取按host授权、credential purpose和key authentication identity，await前后及最终消费前复核。不向KI handler提供saved reader/intent。未知KI始终人工，不按文案分类，不将零字段的`[]`与取消混淆。
- 四个持久enum不清库/批量改值，运行时按两主方式统一手动KI能力；SFTP也使用同策略。UI保留原ID/引用/授权。
- 网络操作预算与人工认证预算分离。候选operationTimeout默认10秒不能直接作为生产审批等待；采用明确有界每请求/总体预算，沿用既有120s/300s原则，不改fixture TTL或时钟。

### 一次信任

HostTrustStore.confirmOnce已有精确临时授权；FileHostTrustAnswer仍需once分支，SharedHostTrust调用后继续核endpoint与实际rawkey。自动活动会话三动作：关闭/仅此次继续/添加并继续；后台提示不抢另一会话输入。changed独立阻止态，取消只取消本pending，不cancelAll误伤其他会话。

## 保活不可混淆的事实

### 当前不满足等价性的接口

固定libssh2 1.11.1 `keepalive.c`发送global request但吞EAGAIN，无公开关联reply/missed counter；发送成功、raw recv或静默输出都不能替代ServerAliveCountMax。

Darwin公开SO_KEEPALIVE、TCP_KEEPALIVE、TCP_KEEPINTVL、TCP_KEEPCNT可配置/回读，但只证明TCP栈与网络可达，无法证明sshd仍处理SSH。既有KeepaliveAcceptance用户态DROP仍ACK TCP，因此不能用它验证TCP失联检测。新pf/路由/系统权限不在本轮默认授权内；不得改系统做包级黑洞。

### 可做有限探针的SSH round-trip候选

通过成熟公开 `libssh2_channel_open_ex("session")` 在同SSH连接开一个辅助channel，不启动PTY/shell/exec/subsystem；等待真实OPEN_CONFIRMATION或OPEN_FAILURE，成功后close/free。OPEN_FAILURE是收到远端回复，不能当dead。它暂占远端session槽，需明确MaxSessions/限流/审计成本。

只有一个pending open状态，EAGAIN必须继续原API；不能每interval另发一个open冒N次未响应ServerAlive计数。可定义一个明确的“SSH round-trip超时”策略，但必须ADR/界面说明，不能偷偷重释旧Count字段。超时后不复用被中断open状态，关闭整个本次session。

有限门应覆盖：正常安静、MaxSessions拒绝仍alive、用户态DROP后单pending deadline、同queue不饿死shell read/write/resize、取消、辅助channel与FD归零、真实fresh ACK。库默认packet_read超时亦需用公开API协调，不被隐含60秒预算截断。

若必须精确保留OpenSSH逐次ServerAliveCount语义，则固定库未发现直接满足的零副作用公开接口；另评估成熟库而非自写SSH包或修改固定vendor。当前没有libssh选型证据，不宣称其已经可替代。

## 下一任务与验收顺序

1. 完成RELIABILITY-R1并审查/回归，后串行native控件发现与真正草稿/粘贴门。
2. Native候选现有fault-prep：wrong primary、changed hostkey、KI pending/ready后取消、encrypted Ed/RSA、未知KI不回填、并发/迟到。只用已有fixture，不重24h或2GiB。
3. 保活短探针与ADR定案后再切正式默认builder，保留旧后端作为受审兼容路径。
4. 正式App一次性未记住密码、两类真实MFA、多字段/零通知/审批/并发/取消、once/persistent/changed；再短TUI/resize/有限输出与资源回收。旧OpenSSH门不能冒新后端门。

潜在文件：新增NativeSessionDriver；SessionEnvironment/Controller/Views、AppModel/MainView/Vault intent、FilesConnection、SecurityCoordinator、NativeTerminalView relay；NativeShell Types/Session/SharedHostTrust/C bridge及限定测试。此为实施范围建议，不是完成记录。
