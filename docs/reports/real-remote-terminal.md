# 远端 PTY/Vim 探针：源码与预检检查点

日期2026-10-27，Task REAL-OUTER-PTY-TUI-PREP-A / TERMINAL-POSTAUTH-DIAG-LIVE-A。**两次真实consumer均在认证后、测试ACK之前断开；新短ACK案确证生产状态failed(launchFailed)/exit255，原loader尚未发送。没有PTY/Vim通过结论。** 系统SSH的-T成功/-tt失败，而容器两UID均能分配PTY，根因仍待更窄的sshd会话诊断，不猜改能力或PAM。

原先named-volume预检在relay/consumer前即暂停，不算一次consumerattempt；修后单案如下保留真实失败。

## 限定场景与安全边界

新 `Tests/RemoteTerminalAcceptance/` 独立host15测试wrapper，生产公开DirectSSHSession+SwiftTerm+已严格签名Askpass。固定keyonly@127.0.0.1:22221/精确generation及带外trust，无Keychain/密码/OTP/inner认证。仅固定非秘密测试动作：shell nonceACK、UTF-8 stdin字节SHA、Ctrl+C中断自有sleep、真实resize/stty31×93、vim.tiny无插件/无swap编辑自有EXCL文件字节SHA、清理与返回outer。

普通终端只临时解析有界固定nonce/count/SHA/阶段元数据，不匹配认证提示或注入秘密、不记录fullterminal/wire。固定短loader低于canonical边界，nonce/count/SHA ACK后raw读编入的固定非秘密Python源码；原始source不是用户任意命令。remotealarm110s/consumer160s/外层200s与sessiondrain12s；所有文件按knownnonce/root/heldinode清理，失败不声称remotecleanup。

手动嵌套SSH、内层secret同步、人工IME/像素、全部TUI工具与mac26明确未覆盖。现有容器vim-tiny/tmux/htop安装日志只是工具存在，不是运行通过。

## 已完成源码修正与静态独立核验

主管读Core/remotePython/consumer/privateinput/build/retry/tests，发现并要求两个确定控制流修正：

1. 原预算expected12帧，但done就complete、returned缺switch，无法真正完成。现done仅cleanupACK，returned0才complete；离线完整12frames/retainedhistory重复inspect/done未完成回归通过。
2. direct-build rootimage没有compose.project label，不能对image用容器project门；现image精确ID/arm64/linux/fixture/base，container/network仍各自project，离线实物shape覆盖。

Core66/Python7、strictDevelopment同Team固定不同ID/Runtime/空权限、min15及parentinput/compiledobjecthash均主管独立核验。依赖宽构建第一轮OfflineMain nonthrowingautoclosure编译失败、第二轮consumer import/try失败，分别保留exit/inputs；第二轮raw编译log被消费者增量retry同label成功输出覆盖，局限如实记录，不补造原raw。

消费者onlyretry复用已核父依赖对象，仅Main/LiveInput最小修复，两文件私有新快照/独立retry命令和结果，没有第三次全依赖宽build。

初始静态App：`Tests/RemoteTerminalAcceptance/.build/host-f43c264c-363f-4cf3-829e-73dd3e4a7f90/OpenLXSSHRemoteTerminal.app`

- 主程序SHA256 `f8ca1fc7549d9b4b974f50a9396a2ff7c95978e8e59e09233264ecf48f4746bc`
- helperSHA256 `94190e2792371694f80d256edc3dfd26ee342abb8d633fcb29c670da25aec788`
- remoteprobeSHA256 `f323f2c7785d22acb4c4af318de7715faa22ed50958a2be5a874961b26919b89`

独立静态证据：`DerivedData/Verification/primary-remote-terminal-static-3395626c-b60f-465d-977a-91f77a3f129d/`。

## 启动前真实元数据发现与R1

fresh keyonlycollect generation `credentials-43a51b1e5701`已成功，但尚未启动relay/consumer时，外层只读实物核验发现LiveMetadata要求HostConfig.Binds=null不符合当前已审环境：实际Binds是owned named-volume `openlxssh-fixture-61ed25328c13_key-data:/fixture:rw`，Mounts为唯一volume而非hostpath。此前guard会错误拒绝，未浪费一次必失败consumer或把hostbind风险放开。

最小R1限定terminal子树：对container只允许固定project_key-data/name/Typevolume/Destination/fixture/local/RWtrue且无额外挂载，所有hostbind/socket/extra/wrongname/dest/RW拒绝；其他身份/Healthy/internal/readonly/PortBindings门保留。contract CID保持完整64hex，由inspect.Id取得，不把parent短CID填入或放宽schema。

R1纯validator实物JSON反例与增量Core/consumer/offline/strict重签已通过，Core83/Python8主管独立复验、sourceSHA256五变更文件/九快照/八父依赖对象核验通过：`DerivedData/Verification/primary-terminal-mount-r1-d5689ecc-3f22-4fbe-bb22-73f148a43615/`。

新App：`Tests/RemoteTerminalAcceptance/.build/host-e2177fe4-f587-4f29-b710-7cd3278460c3/OpenLXSSHRemoteTerminal.app`，driverSHA256 `39cb698a4eff854f0d667f54781548d77b1a74bc46d9a3e2ad2c94bec68e2b98`，helper `72299d74fa47a2f4cdc9bd563e7a09a39a6e2930f5e32bc787907e917258c4e0`，probe未变。日志使用新UUID，未覆盖旧产物。

## 首次真实consumer：认证后ACK前失败

一个300s有限relay、一个consumerattempt，实际consumer PID31085 exit1/28.688s。trustedconnectedEvents1、ownedSSH PID31127，但probeEvents0/shellACKfalse、failure=connection。authrequests0/postConnectedDelta0；stdin字节、Ctrl+C、远端尺寸和Vim均无通过证据。原代码没有serialize lastSessionState/lastExitCode/具体sendInput阶段，不能推断是shell准备、固定loader、PTY或其他原因。

close/PID释放/FD回baseline通过；自有relay31020精确TERM/waitexit0、accepted4/finished4/rejected0/cleanup_failed0，端口无LISTEN。只读远端固定driver/nonce文件后验没有观察到driver或目录；不据此宣称未曾启动，不扫描删除或kill其他进程。

原报告与完整命令/exit/有限清理：`Tests/RemoteTerminalAcceptance/.build/live-r1-a/consumer-result.raw.json`、`live-result.json`、`relay-events.log`。原合同 `Tests/RemoteTerminalAcceptance/.runtime/case-d6ea9bda2906/remote-terminal.json`。

下一步仅在本机受控PTY以固定非秘密loader做最小复现，最多两个有证据假设；先核原API/state/quoting/canonical边界，不重新远端连接、不记录fullterminal或改生产。

限定本地两实验已完成：Darwininteractivebash启动时直接送1530bytes整行，而本地PC_MAX_CANON1024，10s无loadACK；不能外推Linux现场根因。绕启动行纪律的bash-c同loader可接12479bytes非秘密替身source、执行/returned0，但整体termios前后比较false，未取位差原因，不能声称恢复通过。两ownedbash均reap、只记录bytecount/hash，不运行Linux/Vim业务路径。

只读生产/config/fixture调查未发现确证根因，并排除RemoteCommandnone字面命令猜测：固定OpenSSH9.9p2 readconf normalize把none清为NULL，clientloop发shellrequest；无-N/-n、LocalCommand子进程exec/helper不读stdin，eventConsumed后初始authTTL不再stop，强owner链完整，imagebash与fixture用户/bin/bash、PAM account/session permit已核。不能据cap名称猜加权限或改服务器。

随后同一freshkeyonly/systemssh stricttrust、禁agent/Keychain/LocalCommand、相同固定非秘密printf命令的两项对照提供了新实证：

- noPTY `-T`：exit0/6.305s，stdout52bytes，固定nonceACK精确LF匹配、stderr0。
- forcedPTY `-tt`：exit255/15.792s，stdout0/无ACK、stderr0，均非外层20s超时、无输出超限，ownedchild与pipes已收。
- 自有180s有限relay39271 TERM/waitexit0，2/2/0/0；端口/连接/ownedPIDs归零。前置自写ctypes/路径alias/额外age门误拒记录保留，最终复用已审Cchecker对同generation核门，不改产品或重试SSH。

证据 `DerivedData/Verification/postauth-system-ssh-control-b9a22fc3-c911-422e-86fe-c2673e46d3c8/`。这是相同远端exec的PTY差异，不直接证明交互login shell或某cap不足；255不改判认证拒绝。

随后exactCID内UID0/10000各一次standard `pty.openpty()` 均成功，TIOCGPTN=0，slave为/dev/pts/0、0620/GID5、owner分别0/10000，master为0666；两次FD4→4/finally全部关闭。devpts为rw/nosuid/noexec/gid5/mode620/ptmxmode666；UID0 CapEff/Bnd=000400eb（原七项能力），UID10000 Eff/Prm=0，NoNewPrivs1/Seccomp2。未执行SSH、controlling-TTY或session fork，未改服务/权限。只证明两个exec上下文可分配PTY，不覆盖sshd monitor的pty_setowner/FD传递、do_exec_pty dup/fork或child setsid/TIOCSCTTY/stdio。证据 `DerivedData/Verification/fixture-pty-metadata-507dc766-f62f-43db-98eb-9cdbfe485afe/`。

## 短ACK与typed退出新案

仅测试consumer补≤256bytes非秘密printf nonce shellACK后才发原loader，以及封闭typed状态/SessionFailure/lastExitCode/inputError/pendingInput/PID/stop/阶段相对时间；原12probe门不放宽。Core128/Python10、27命令、9输入快照/8父依赖对象与严格签名已主管独立核验：`DerivedData/Verification/primary-terminal-postauth-static-fcd07a08-66a7-4478-9489-f4329c7a2e6c/`。固定新App `Tests/RemoteTerminalAcceptance/.build/host-de94ef3f-197c-4c56-a3f9-2fc7793c577f/OpenLXSSHRemoteTerminal.app`，driverSHA256 `67d1cab5940e5dd3c95b7ec246b658f26a858bf8642988320102b238c3435562`、helper `3d19d8f1220bcfb2b5b8ec19fa7d9fd1acdab03fde8e8930c9c07fb35f1dd527`，probe未变。

唯一新case使用fresh generation credentials-8e5deebe1431，consumer40915 exit1/28.561s，无外层timeout。outer connected在t12.455643；t12.473855尝试73bytes短命令，t12.473894返回pending73；t21.722916会话结束。failureStage=waitingShortACK，failure/preClose均为failed(launchFailed)/lastExitCode255/pending0；stopRequested=false、inputError=nil、authenticationRequests0。**入队不证明远端执行；shellACK=false/probeEvents0/remoteStarted=false，原loader从未发送。** 不据此确认远端shell或把255解释为认证拒绝。

closed/PID释放/FD回baseline=true；自有SSH41010、consumer40915和relay40824均不存在，relay TERM/wait0、4/4/0/0、端口释放。精确nonce7999203307e844208c4918446fadb9bb的driver/Vim/目录未观察到，active relay owners为空，未执行远端kill/delete；不将未观察到追认为remote cleanup成功。exact keyonly仍Healthy。

原报告和命令：`Tests/RemoteTerminalAcceptance/.build/postauth-live-a/{consumer-result.raw.json,live-result.json,relay-events.log,final-postverify.json}`。主管独立核原报告一致性、时序、三PID实际不存在，确认send返回到退出9.249022s；证据 `DerivedData/Verification/primary-terminal-postauth-live-14a17ac5-93bd-469e-9124-092d0861ba34/`。冻结源码/对象与双App严格签名再核见 `DerivedData/Verification/primary-app-terminal-frozen-a24c034b-da4a-4254-907e-4f311351baec/`。没有重跑原case或更改生产/服务cap。

## 容器内直连原daemon对照

`Tests/PTYDebugAcceptance/client_helper.py` 仅固定Linux SSH -vv -tt直连现有127.0.0.1:2222，不经宿主relay、不新增端口/服务。原root私有测试key/带外known_hosts只在容器内读取，不复制导出；固定alias及keepalive5/1与原对照一致。stdout/stderr合计64KiB内存上限、20s执行+5s回收，只输出ACK/计数/摘要和静态阶段集合。主管指出pidfd初始化前异常会漏回收后，最小R1移入try/finally并保留Popen精确回收fallback；8项pure/fake回归主管独立2.158s exit0，含pidfd_open/read异常、TERM忽略→KILL/reap、输出上限与默认无I/O。证据 `DerivedData/Verification/primary-pty-client-r1-3b82fad0-07ad-4ae5-8060-5735edfa676d/`。

唯一容器内对照固定helperSHA256 `3a3653193ea51ee4880effcbbc0c6b295a77151e2fb60ec1c39b81081f96c385`，outer dockerexec45481 exit0/3.313s；**内部SSH实际exit255/0.241257s、stdout0/ACK=false，非外层或helper期限。** stderr7418B只在内存，摘要24c76a3206f1f319a2b27a1e40d8219c3e031c54468e262f56bb736b87627ee8；静态阶段仅sent-pty/exec-sent，103未分类行，不当时序/不猜具体fatal，也不以缺某regex匹配证明服务器未到该阶段。

前后exactCID/image/Healthy、原cap/readonly/internal/无default route相同，configSHA256 `0e1b32cfda7e0f60ae521dbc66a5a9a9f1db6e003f5290db5f857ac710e98616` 不变，pids.current4/max128、R1/S3/Z0均不变。childreaped/pipesclosed/runtimeReleased=true，无新generation/relay/安装/服务修改。原证据 `DerivedData/Verification/fixture-internal-pty-client-3fbf9ac7-610c-4b99-8bc1-989588685d66/`；主管核原结果、source/codehash、前后元数据与outerPID实际不存在：`DerivedData/Verification/primary-internal-pty-client-d2e43ea0-70ac-41b9-9736-cc14bd1e18ed/`。

该结果证明不经宿主relay仍可复现强制PTY失败，不支持PID额度耗尽；仍不能确定原daemon内部错误。只读核server监督器已证sshd stdin/stdout/stderr均DEVNULL，没有未drain日志PIPE，但服务端错误也因此被丢弃。当前只准备一次同隔离容器临时单会话sshd的错误类别诊断，原daemon/auth/cap/PAM不变，仅自有配置/容器回环2223，无宿主新增端口，必须先审脚本及离线自有后代回收后才运行。此前sshd-i/桥方案均未实施。没有真实PTY、Ctrl+C、resize或Vim通过，不能因packet/终端原型证据补齐。

## 临时服务端错误分类

小型 `server_helper.py` 复用原client，仅容器内临时1272223监听，自有/tmp UUID配置只替换Port/ListenAddress/PidFile/LogLevel，原daemon/hostkeys/认证/PAM/caps不改。ready由固定服务端日志触发，不探TCP消耗单连接；两process合计64KiB内存/20s执行+5s回收，subreaper/PPID/start/pidfd限定自有后代，未知文件保留。主管修前审出正常进程消失与pidfd初始化失败会跳清理，R1最小修复后独立server8/client8 exit0；证据 `DerivedData/Verification/primary-server-pty-offline-57dde16a-1d3e-452f-a308-68d121e8c326/`。固定serverSHA256 `b144743be8f2bb57d4b0fadfb45c86e454a837e96d7a80df550ad68cad320e4a`。

唯一临时单案outer exec46947 exit2/3.346s；内部server/client均255，ready=true/ACK=false，实际捕获32534B/0.241845s，raw只内存。服务端固定分类为audit/audit-fatal/login-accounting、errno集合1/30；`audit-fatal`仅匹配 `linux_audit_write_entry failed:`，不凭cap名称猜测。分类为集合，不能把1/30自动逐条配对或从中恢复日志时序。`-ddd`也改变daemon路径，尚不直接等于原daemon根因。

**原helper ownedProcessesReaped=false，原案保持exit2/PARTIAL，不改为清理成功。** workspaceAbsent=true；外层独立后验原daemon20/PPID6/start430/S、confighash不变，pids4→4/Z0→0，debugProcesses/2223listener为空、exactroot不存在，ownexecPIDgone、宿主批准端口无listener。外层无残留不覆盖内部failed字段。

原结果/命令/前后元数据：`DerivedData/Verification/fixture-server-pty-error-43181553-8d78-4a11-bfd9-6ad3746591a3/`；主管独立核auditfatal/原失败/原daemon身份/资源及实际outerPID不存在：`DerivedData/Verification/primary-server-pty-live-12eba838-b5b2-41ba-a8cf-d393c1ba2116/`。

固定上游V_9_6_P1 `loginrec.c`/`audit-linux.c` 只读证据显示login记录后的Linux audit写入失败存在该fatal，普通lastlog/wtmp只读写失败多为logit/debug返回；上游不是Ubuntu完整补丁/编译证明。现证据支持针对audit写入的最小对照方案，尚未加cap或修改原服务；不采用privileged/AUDIT_CONTROL/关闭认证等绕过。临时helper内部标志false的原因另按源码收窄，不重跑旧案。没有真实PTY、Ctrl+C、resize或Vim通过，整体Goal NOT COMPLETE。
