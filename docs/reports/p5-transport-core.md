# P5-TRANSPORT-A/R1：正式SSH终端核心审查

日期2026-10-26。工程师实现；Primary Agent独立审查。当前PARTIAL：本地正式包范围通过，真实SSH/MFA/macOS26运行未通过。

## 实现与审查

主管读取DirectSSHSession、AskpassBroker、AuthenticationPolicy、Configuration、PTYGeneration、HostKeyScanner、NativeTerminalView、协议、主要测试/验证脚本和ADR。复用已审查Mach消息安全链与唯一SwiftTerm LocalProcess，不引入第二PTY/reader/reaper，不扫描PTY或人类日志投递秘密。

- typedconfig/固定argv/独立0700会话目录与0600配置/共享正式Trust；keyscan仅未认证候选，指纹显式确认才写信任；实际ssh StrictHostKeyChecking=yes并只允许已信任算法。真实握手未测。
- 会话ID+generation，准备/待信任/认证/connectionPending/connected/断开/失败/关闭区分。进程启动不算connected；固定签名helper LocalCommand事件才算外层已认证，非shellReady。命令只包路径/固定双参mode，POSIX引用/%转义、SHELL固定，非用户任意命令，详见ADR。
- Mach每消息audit+动态签名、真实Team/固定对端identifier/UID/直属ownedssh PPID/birth；helper不读stdin。取消先撤销权利再释放上游sole reaper，避免旧PGID杀误进程。只保证直属child与正常helper，任意逃逸后代不承诺。
- 严格password-only+显式provider每代一次预算，未知hint/混合MFA人工；不读Keychain。自动gate目前只核24H32/精确ssh版本/Apple签名，shipping macOS26不在白名单，AUTH02目标自动使用仍未验。
- 输入256KiB/单次16KiB completion、历史10000上限50000；输出正常排空/关闭取消分离、隐藏不重建。R1修复字体6…72、保活0…3600、自定义前景背景光标不被系统外观覆盖，非法设置明确拒绝不静默fallback。

## 主管独立验证

两轮分别独立执行 `python3 .../Packages/OpenLXSSHTransport/Scripts/verify.py release`，修正前17项、修正后23项均通过；Release6真实系统readpass与4个签名parent shell-exec事件场景通过，10个服务退出后独立lookup unknown，签名严格verify通过。主管读取R1三处差异/边界测试，实际App尚未接Transport。

工程师Debug/Release各23项0失败、FD45→45，默认min26两配置编译对象/helper元数据minos26.0/SDK26.2。日志 `.build/verification/`。readpass用真实系统ssh-keygen+一次性key，不是ssh服务器认证，事件fixture不是远端认证。

## 未完成

无授权服务器，四类认证/MFA/审批/握手后密钥变化/嵌套SSH均未测；macOS26自动白名单与运行、Sandbox、DeveloperID/公证、人工IME/TUI/长期稳定性未验。正式包尚未全量移植历史different-signer/queued-exec/complex/OOL矩阵，集成回归须补。不能以此或App构建宣布Goal完成。
