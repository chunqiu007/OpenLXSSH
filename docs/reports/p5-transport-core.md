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

## P7 会话配置与私钥 ACL 复验

原mode-only会话目录/ssh_config接受危险继承ACL，修前真实无网络ssh-G显示可被改成StrictHostKeyChecking false/ProxyCommand /usr/bin/true（未执行代理）。P7-TRANSPORT-ACL-R1新增descriptor-only FileSecurity，用fstatx/filesec成功且MODE populated与ACL absent判断，任意ACE或查询失败拒绝，不改ACL。

Sessions根在mkdir UUID前核对，UUID在创建配置前核，config与root/UUID在写前后复验，保留configFD与inode，最终spawn前无suspension重验路径对应对象、ACL及私钥元数据。私钥用O_EVTONLY|O_NONBLOCK|O_NOFOLLOW，不读取密钥内容；FIFO测试曾真实阻塞，sample定位后添加NONBLOCK，失败证据和修复结果分别保留。公共API、PTY唯一owner、严格签名helper与白名单预算不变。

工程师双配置各35项（原23+新12ACL）、严格签名离线IPC、min26双配置编译均退出0。主管阅读4文件实际差异和12新tests，在包稳定后独立执行verify.py release退出0：35项、6真实系统readpass、4签名事件、10独立postexit lookup、runtime依赖检查通过；日志 `.build/verification/p7-acl-primary-release-verify.log` 及本轮release-test/ipc日志。普通20次workspace/ssh-G+FD与cleanup、新继承/运行期/写前后/替换/queryerror等边界通过。

这减少了路径与ACL窗口，不是对同UID进程的完整sandbox。App整体、macOS26运行与真实SSH认证仍未验收；本轮系统组件调用均离线。

## 未完成

无授权服务器，四类认证/MFA/审批/握手后密钥变化/嵌套SSH均未测；macOS26自动白名单与运行、Sandbox、DeveloperID/公证、人工IME/TUI/长期稳定性未验。正式包历史different-identifier/adHoc/queued-exec/complex/OOL矩阵后续已补齐并发现修复voucher/timeout ownership，主管独立Release完整复验通过，见 `p7-transport-adversarial.md`；真正第二Apple Team仍未测。不能以此或App构建宣布Goal完成。
