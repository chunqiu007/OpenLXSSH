# ADR-P5：直接会话 Transport 集成与受限认证控制面

状态：正式包本地集成已实现，真实 SSH/目标系统运行验收未完成。日期：2026-10-26。

## 决策与范围

新增 `Packages/OpenLXSSHTransport`，默认部署 macOS 26，提供 library `OpenLXSSHTransport` 与独立 executable `openlxssh-askpass`。SwiftTerm 精确固定 1.99.1 / `2f573f73af5e768d90847dce20c97fa9535d7164`，明确为 2.0 前预览；锁文件及依赖许可随包保存。主机身份/公钥/存储只依赖正式 `OpenLXSSHTrust`，不复制第二套 trust 实现，不引用实验模块、Core 或 Keychain/Security 包。

迁移来源：P1-04C 的 Mach inline/audit/signature、请求状态与 helper；P1-02 受控配置边界；P2 已选 preview 的 LocalProcess/有界输入与原生 TerminalView 包装。保留原实验与历史失败证据；未迁移旧 socket、候选分支或整套 adversarial harness。

`DirectSSHSession` 每标签一实例，`SessionToken(sessionID,generation)` 每次显式连接递增；连接期间不编辑 endpoint，先 cancel 并等待清理后再 connect 新配置。隐藏/标签切换只隐藏同一 terminal，不重建进程。preparing/awaitingTrust/authenticating/connectionPending/connected/disconnected/failed/closing/closed 有区分。无自动重连。

## 主机信任与配置

`SystemHostKeyScanner` 固定 `/usr/bin/ssh-keyscan`，argv 含 `-T/-p/-t` 和已验证 HostAddress；无 shell、无用户配置、无真实目标在本轮被扫描。输出上限 128 KiB，短命工具 sole waiter 保留 PID 至最后信号后再 reap；取消/超时不会 kill 已复用 PID。严格解析 endpoint、非 22 端口和支持算法，重复不同 key 拒绝，无 key/坏输出/超时分别报错。

扫描只是 **systemSSHKeyscan 未认证候选**。UI 必须展示 endpoint、算法、SHA256 指纹及来源，独立核对后显式 `acceptTrust(challenge,displayedFingerprint:)`；不能默认接受。共享 store 消费一次性 token，并用 revision/期限约束。取消、代次变化、关闭后 transport 拒绝旧回答。已发起的显式接受操作可在线性化点提交存储，取消不撤销已经授权的提交；在操作结束前禁止新代次越过它。

实际 `/usr/bin/ssh -F <会话0700目录/0600配置> -- openlxssh-direct` 固定 alias；无任意用户 option/远端命令。`StrictHostKeyChecking yes` + 同一共享 App known_hosts，HostKeyAlgorithms 只允许预检已信任的 key 算法（RSA 使用 rsa-sha2-512/256），系统 known_hosts `/dev/null`。Agent/proxy/forwarding/ControlMaster/ControlPath/LocalCommand 自由输入均禁用，不碰 `~/.ssh`。后述固定事件命令是唯一受限例外。默认 connect timeout10秒、1次尝试、keepalive15秒/3次，配置界限分别1…60、0…3600、1…10。总认证窗口300秒、单请求120秒、每代8请求，helper125秒等待；无无限自动尝试。

## 身份与资源

现场 SSH：macOS15.8.1 build24H32，OpenSSH_9.9p2 / LibreSSL3.3.6。实际 `/usr/bin/ssh` identifier 为 **com.apple.ssh**，要求 `anchor apple and identifier "com.apple.ssh"`，不猜 com.openssh.ssh。正式宿主 Bundle ID `org.openlxssh.OpenLXSSH`，helper 固定 `org.openlxssh.askpass`。双方从自身 Apple-anchor/runtime 有效签名派生 Team，消息和环境不能传入 requirement。当前策略拒绝额外 entitlement；Sandbox 不是已支持配置。

每条 Mach request/reply 取内核 audit trailer，按冻结 audit token 动态 SecCode 检查 UID/签名；helper PPID 必须为 session 自己的 LocalProcess.shellPid，parent 的 PPID/UID/出生时间/存活/系统镜像也检查。没有 public adoptPID API。先创建 grant/service/state，再同步读取唯一 LocalProcess 启动结果登记 parent，main queue 才开始消费请求。nonce 是关联信息而不是唯一授权。

bounded inline12288字节；拒绝 complex/OOL/voucher/异常头，释放无效消息和 send-once rights。关闭先撤销认证授权与 reply/service rights，再释放 LocalProcess；helper receive 被唤醒失败，取消旧回答无效。实际 native readpass fixture 验证了该唤醒路径。bootstrap_register 为公开 deprecated API，权利释放后独立进程确认 service unknown；**macOS26/Sandbox 运行未验证**，不能据编译通过承诺该路径可发布。

只有 SwiftTerm LocalProcess 拥有 PTY、reader、write channel、child reaper。正常退出无限期排空已读输出，关闭为显式取消。取消使用上游带锁的 TERM→350ms KILL/reap，adapter 不对 published PID/PGID 另发信号。该实现保证直属 child 与正常 Askpass helper 清理，**不保证任意逃逸/另起 session 的后代树清理**；不能宣称做到了 group kill。禁止 Agent/LocalCommand 自由输入降低额外后代来源，仍需正式会话压力与后代边界验收。

## 可信 authenticated 事件：SEC-03 的受限例外

不扫描 PTY、远端 Password:/sudo/嵌套 SSH，也不匹配 `-v/-E` 人类日志。Apple OpenSSH346.120.3 的 sshconnect2.c 中 keyboard-interactive 的 name/inst 会进入 logit；单凭日志 fd 来源不等于字段可信，未选择文本匹配方案。

主管补充审查对应公开 Apple 源码：ssh.c 登录返回约1851；ssh_session2 排 channel-open 约2286、执行 LocalCommand 约2374、再进 client_loop 约2401；sshconnect.c ssh_local_cmd 约1878 fork `$SHELL -c`。LocalCommand 在认证完成后执行，但不证明 PTY/shell 请求已被服务器接受。

因此本包只允许固定：`exec '<已验证包内helper绝对路径>' --authenticated-event v1`。命令不含主机/用户/%h/%r/%n 等数据；拒控制字符，POSIX单引号转义，`%`→`%%` 防 ssh token 展开；干净环境固定 SHELL=/bin/sh，无 ENV/BASH_ENV/继承 agent/hint。`PermitLocalCommand yes` 仅为此命令，EscapeChar none/EnableEscapeCommandline no，配置不接受用户命令。

两参数 mode 不能与 Askpass 的单个不可信 prompt 冲突（即便 prompt 恰为 --authenticated-event）。helper 经同一签名 Mach 控制面发送 typed event，audit/PPID/birth/grant/generation 校验，broker 成功给该 peer ack 后只消费一次，再撤销 readpass 自动回答；重放/关闭后的事件拒绝。state.connected 的语义严格为 **外层已认证，不是 terminalReady**，之后 shell 请求失败仍可断开。没有事件时始终 connectionPending，进程 PID 或 PTY 内容不产生成功。

## AUTH-02 单次 saved-password 授权

不导入凭据库。上层每次 connect 显式提供 `SavedPasswordAuthorization` 的 async provider，只返回内存 `AuthenticationSecret`（redacted，最多1023字节，拒NUL/CR/LF），transport 不存储、不记录答案；OTP从不自动提供。

仅 `.passwordOnly` 封闭配置可考虑自动额度：PreferredAuthentications=password、Password yes、KbdInteractive/Pubkey/GSSAPI/Hostbased no、PKCS11Provider none、IdentityAgent none、IdentitiesOnly yes、IdentityFile/Certificate none、AddKeysToAgent no、BatchMode no、NumberOfPasswordPrompts1、UseKeychain no，外加上述 strictknownhost/noDNS/nohostupdate/noControl/noProxy/固定配置与干净环境/Askpass force。

公开 Apple346.120.3 sshconnect2.c userauth_passwd 约1048…1071 初始 read_passphrase 后发送 change=0，随后才注册 passwd_changereq；改密handler约1110/1120/1129 的调用更晚。因此在该闭合模式中，**第一个通过身份/会话校验且 hint=nil 的请求**可以消耗本代唯一授权。首个有hint请求也永久消耗潜在额度；所有后续请求（包括强制改密）人工，不拿文字、PTY行或第一个未知混合挑战猜密码。MFA混合模式无额度、不在失败后换模式投递。provider拒绝/不可用人工回退，不自动重试；取消/代次变化时 provider 迟到结果弃用。

自动 gate 只白名单 build24H32 + 上述 ssh -V 精确结果 + 实际固定 `/usr/bin/ssh` Apple签名，未知 OS/build/version 保守人工。**版本号本身不能证明全部 Apple 补丁对应；本轮是源码约束+本机policy实现，不是远程密码认证验收。默认 shipping macOS26 不在白名单，故自动密码实际仍人工回退，AUTH-02 完整目标未完成。** 后续必须为目标系统核对源码/二进制/真实服务认证和密码更改流程后扩白名单。

Apple ssh -G 把 PubkeyAuthentication no 输出为 pubkeyauthentication false；UseKeychain 与 PKCS11Provider none 未出现在 dump 子集。测试同时要求实际 -G 解析退出0、可见字段精确对照以及不可变源配置中这两项固定指令；没有伪造 -G 字段。

## 终端接口与验证边界

`NativeTerminalView` 公开输入适配、paste/search/font/colors/history/visibility。历史默认10000、上限50000；256KiB输入上限、16KiB单个 completion 写入；满时拒绝，不截协议字节。禁OSC clipboard/URL opening/local image媒体；复制选区使用原生TerminalView公开API。隐藏继续消费输出，减少绘制；disconnect保留标签内输出，closeTab移除delegate并关闭UI计时器，session deinit同样释放自己的资源。

复现命令（目录为包根，日志与产物只在本包 `.build`）：

- `python3 Scripts/verify.py debug`
- `python3 Scripts/verify.py release`
- `python3 Scripts/compile-macos26.py`

前两项显式 OPENLXSSH_TRANSPORT_HOST_PROBE=1，仅供macOS15宿主运行；fixture目标/测试访问接口不进入默认shipping图。各17项XCTest覆盖真实PTY control/Unicode/bracketed-paste/resize/search/history/隐藏压力排空、取消/EOF/多会话/旧代次/owner deinit/20周期FD45→45、错误指纹/已信任变更预检拒绝/同步回调重入取消、恶意scan解析/工具timeout/cancel/超限，以及ssh-G/单次密码policy。签名fixture使用现有Development身份，不创建证书、不改权限、不上传；每配置6个真实 `/usr/bin/ssh-keygen -y` readpass与4个signed parent事件场景，含错误parent/replay/cancel/port撤销/实际shell-exec链。bundle路径特意含空格、单引号与%，验证quote及ssh-G。provider通路在合成readpass中测试，**没有把keygen语境开放为产品自动密码**。

compile-macos26编译默认图 Debug/Release，核实际 helper/transport object 的minos26.0/SDK26.2；不执行这些产物。无授权服务器，不启动sshd，不连接外部/真实主机；真实认证/多轮MFA/审批、预检后主机密钥变化的实际OpenSSH拒绝、内层SSH/TUI/中文IME、目标macOS26运行/Sandbox/DeveloperID/公证/双机与长期性能仍未验收。P1更广的different-signer/queued-exec/OOL矩阵未全量移植，需针对正式包另补回归。

来源：
- https://github.com/apple-oss-distributions/OpenSSH/tree/OpenSSH-346.120.3/openssh
- 项目ADR p1-04-askpass-authentication-context、p1-02-host-trust、p1-03-file-keychain-selection、p2-terminal-version-selection。
