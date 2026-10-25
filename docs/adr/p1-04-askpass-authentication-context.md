# ADR-P1-04：Askpass 认证上下文与秘密投递边界

状态：待原型验证；2026-10-25。该记录固定安全约束，不表示 AUTH 验收已通过。

## 证据与问题

只读研究对照本机 OpenSSH 9.9p2 手册、上游 `V_9_9_P2` 与 Apple `OpenSSH-346.120.3`：

- [readpass.c](https://github.com/openssh/openssh-portable/blob/V_9_9_P2/readpass.c) 中 `SSH_ASKPASS_REQUIRE=force` 可与 PTY 共存，且不依赖 DISPLAY。只影响本地 ssh 的认证读取，不接管远端 shell。
- [sshconnect2.c](https://github.com/openssh/openssh-portable/blob/V_9_9_P2/sshconnect2.c) 的 `userauth_passwd`、密码更改、`load_identity_file`、`input_userauth_info_req` 都可能进入相同 Askpass 接口。Keyboard-Interactive 的 echo 位及部分挑战分组/说明没有完整传给 helper。
- `SSH_ASKPASS_PROMPT=confirm` 是确认 UI hint，`none` 是通知 hint；无 hint 不等于登录密码。启动时必须清理继承的 hint。
- helper stdout 是 ssh 私有输入通道；回答约有 1023 字节上限并在 CR/LF 截断。helper 非零退出不保证 ssh 整体取消；取消必须撤销会话授权并停止直属 ssh。
- ssh 早期 closefrom(3)，不能假设预传任意 FD 可跨 ssh 继承。socket 0700/0600 和环境 nonce 不能单独抵御同 UID 假客户端。

Apple 对应公开源码：[readpass.c](https://github.com/apple-oss-distributions/OpenSSH/blob/OpenSSH-346.120.3/openssh/readpass.c)、[sshconnect2.c](https://github.com/apple-oss-distributions/OpenSSH/blob/OpenSSH-346.120.3/openssh/sshconnect2.c)。这些资料不证明本机全部补丁完全对应，系统升级仍须回归。

## 暂定设计约束

1. 认证控制面与 PTY 输出严格分离。绝不扫描远端 `Password:`、sudo 或内层 ssh 提示来投递秘密。
2. 每个 helper 请求须绑定 App 实际创建的直属 ssh、PID 出生时间/存活状态、helper 身份、会话代次和请求 ID；不相信请求体自报 PID/PPID。nonce 只作关联，不作唯一授权。
3. 在 macOS 验证 XPC 的 peer/audit-token/签名校验路径，或等价受控本机 IPC。Unix socket 权限不足以替代签名与进程归属；双方身份都要校验。
4. 未证明认证类型时默认为未知、遮蔽人工输入，confirm 显式确认，none 仅通知。回答限制长度并拒绝 NUL/CR/LF，不静默截断。并发、取消、超时和迟到回答均失效隔离。
5. 仅在能证明其他 `read_passphrase` 来源不可达的、用户授权的受限认证模式中，才考虑单次自动使用 Keychain 长期秘密。单凭 password-only 配置、第一条提示或提示文字不构成完整证明。P1-04 初始实验不得默认自动投递；AUTH-02 完整自动使用要求仍保留，不能因此从验收清单移除。
6. 若原型实测证明系统接口不能满足已确认认证需求，按架构授权比较成熟替代实现/最小上游适配并记录证据，不能以削减安全要求或功能替代。

## 后续源码证据：受限认证与本地事件（待实际SSH实测）

2026-10-26补充只读对照Apple OpenSSH-346.120.3（9.9p2）：

- ssh.c登录返回后、PTY/shell channel-open确认前执行LocalCommand；固定签名helper的`--authenticated-event`只证明外层用户认证已成功，不证明远端终端就绪。事件必须Mach审计/签名/直属ownedssh/代次验证，取消后丢弃。此受控常量命令需在Transport ADR作为SEC03最小例外：无用户字段、无%h/%r/%n，bundle路径POSIX引用与%转义、SHELL=/bin/sh、清启动环境、禁escape；不是开放任意LocalCommand。
- 严格password-only封闭配置可排除key/KBI/FIDO/hostkey询问/mux/hostbased/provider。userauth_passwd先读取初始密码、send(change=0)，之后才注册改密handler。因此首个合法无hint请求若存在可作为单次显式授权自动额度候选，之后全部人工；不能只因NumberOfPasswordPrompts=1认为改密循环也有限。
- 自动候选还须固定BatchMode=no、PKCS11Provider=none、AddKeysToAgent=no、Apple UseKeychain=no、独立strict配置与白名单环境，清旧hint、force。不匹配系统build/版本/签名或混合模式退回人工；公开源码标签不证明本机全部补丁完全对应，仍需真实隔离服务认证/改密/取消实测。

这些新证据更新了“完全无法区分”的设计空间，但不允许通用prompt分类或静默投递；正式实现和对抗测试在Transport包任务中推进，未作产品通过声明。

## 必须验证

- PTY 存在、无 DISPLAY 时本地 Askpass force；远端仿提示不触发控制面。
- 同 UID 假客户端、错误签名、错误父进程、泄露 nonce、跨会话重放和 PID 生命周期竞态。
- 多轮/多提示/空提示/通知/确认/超长回答、取消/超时/断开/辅助程序崩溃；无无限重试或串用。
- 受限自动投递前提、密码更改与混合认证；上下文不明确时人工回退。
- 正式 `.app` helper 路径、签名、Hardened Runtime、Sandbox 与资源回收。

当前只完成研究，没有真实 SSH、MFA、IPC 或 helper 安全验收。最终采用方案与已知风险应由 P1-04/P1-05 实测更新。
