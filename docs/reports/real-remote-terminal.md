# 远端 PTY/Vim 探针：源码与预检检查点

日期2026-10-27，Task REAL-OUTER-PTY-TUI-PREP-A / TERMINAL-SIZE-VIM-SYNC-R2-LIVE-A。**原认证后255、Vim就绪与切屏竞争失败均保留；测试环境AUDIT_WRITE修正、tiny coreEx握手与size确认同步后，唯一新案严格12帧/真实Vim文档SHA/termios恢复/资源清理通过主管验收。** 仅host15公开生产API有限分项，不是全部TUI/人工/目标系统验收。下文先保留历史，再记录最终实际通过证据。

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

固定上游V_9_6_P1 `loginrec.c`/`audit-linux.c` 只读证据显示login记录后的Linux audit写入失败存在该fatal，普通lastlog/wtmp只读写失败多为logit/debug返回；上游不是Ubuntu完整补丁/编译证明。现证据支持针对audit写入的最小对照方案，尚未加cap或修改原服务；不采用privileged/AUDIT_CONTROL/关闭认证等绕过。临时helper内部标志false的原因另按源码收窄，不重跑旧案。## 修后真实完整探针：通过八帧，Vim前失败

新keyonly身份/八cap下，冻结de94 App使用fresh generation7120ec7ad11c/contract1e81f02595fa执行唯一actual consumer，PID58117 exit1/28.707s。前置harness CAP_前缀误比及本地Python缩进SyntaxError都在relay/consumer0次时发生，保留原诊断，修正后才本次实际尝试；未重复collect或连接。

相比旧auth后255，现short shellACK=true/probeProcessACK=true，actual remotePID2996/start8461985/UID10000已确认；strictframe顺序通过8项至size31×93，UTF8输入SHA匹配/CtrlC中断已观察，App认证回调总数及connected后增量均0。failure=unexpectedFrame/failureStage=waitingProbe，failure/preClose仍connected/ownedSSH58157/pending0/stop=false，没有记录255或SessionFailure；不回填旧错误。

尚未确认vim-ready/Vim文件SHA/done/returned0，完整12帧未通过。原report remoteSizeMatched=false原样保留：该字段旧代码要到vim-ready才置true，不抹去8帧严格validator已经核size的事实，也不追改旧report。具体Vim前内部失败未知，仅source/offline最小诊断，不猜Vim缺失或权限。

本地closed/PIDreleased/FDreturn=true；relay58050 TERM/wait0/4-4-0-0/端口释放。精确nonce05eb0e78143e49908a741769c63141bf远端driver2996/start8461985已不存在、knownroot不存在/非symlink、exactVim与activebridgeowners空，未手工remote kill/delete，newkeyonly仍Healthy。外层后验无残留不把原remoteCleanup=false/remoteProcessReleased=false改绿。

原报告/命令/精确后验：`Tests/RemoteTerminalAcceptance/.build/audit-fix-live-a/`。主管独立核原typed报告、阶段/8帧计数、原失败字段和三个实际本地PID不存在：`DerivedData/Verification/primary-terminal-audit-fix-c453eefe-2617-4b36-aed7-e6cd38a102c4/`。这确认环境修复恢复shell/输入/CtrlC的分项进展，但不是完整终端/TUI验收。

## Vim闭集新案与实际tiny能力

四文件最小诊断保留12成功帧/strictorder/文档SHA/cleanup+returned门：remote异常只发闭集stage/kind/errno，unexpectedframe只allowlist；size在实际validframe立即记录，inspect随后抛错也保存进度，不回改旧report。主会话读完整diff并独立14puretests（含原128checks）exit0，证据 `DerivedData/Verification/primary-terminal-vim-diagnostic-172e25cd-242f-4d7a-ac74-4c7a4ea8bf01/`。

增量builder只复用已审de94/8依赖对象、compileCore/Offline/consumer，31cmd全0，新probe实际嵌入binary；新82d87 App mainSHA `8708b98b14818d2cd233084e366ad2dd1e2721011752bf42ccd924114c4c2c46`、helper `5a48aeed1be6d0841f2afca2915dbe8216b48ddd2993bec2f3a33745ef6b6b54`、probe `d92188a5125a1b5cb588eafd7e03da34db33c3ec367c495cbadbe78db5f0354b`。主管独立10inputs/8objects/31cmd/probeBase64与SHA实际在binary/strict通过：`DerivedData/Verification/primary-terminal-vim-signed-b616644e-9052-4ea5-9fe1-2c4054d6377c/`。

fresh单案collect/relay/consumer各1次，consumer仍exit1但取得精确诊断：remoteProbeFailure={stage:vim-ready,kind:refused,errno:none}，unexpectedProbeFrame=failed，events8/size=true，sessionconnected/stopfalse/无255；确认不是成功帧名称不匹配。VimSHA/done/returned仍未过。原报告与后验 `Tests/RemoteTerminalAcceptance/.build/vim-diag-live-f0a74889-cda2-4bfa-b441-46b915f5eccb/`；主管独立原typed值/本地三PID不存在见 `DerivedData/Verification/primary-vim-ready-live-6a544ff3-2ddc-46ae-b7b7-228287acc6d2/`。remote5272/start8800812、nonce634ea9b7307143f09dfcaa882a71350e已释放/knownroot不存在/Vim空，relay62124/consumer62200/SSH62286均结束/4-4-0-0/FD与端口释放。外层首次遗漏固定trust.lock导致本地清理安全拒绝，核定owner/mode后仅knownfiles恢复，未重跑consumer。

随后固定新CID内UID10000仅一次 `/usr/bin/vim.tiny --version`，10s/16KiB上限，实际exit0/3.061s/3448B，公开版本Vim9.1/Tiny version without GUI/**-eval**。当前ready命令 `call writefile(...)` 依赖实际不具备的表达式/函数求值能力，确认测试握手兼容性错误；未观察E319/E117实际码，不编造。没有第二execute/临时文件/安装或镜像变更。

下一修复仅用核心Ex写入已持有readyFD：启动前非空sentinel，Vim `write! /proc/self/fd/N` 真截断为空后父核同inode判ready；原真实编辑/保存摘要/12帧不降低。当前source/offline准备中，替代方案尚未真实验证，不能宣布Vim问题已解决。

## tiny就绪R1与尺寸同步R2：完整实际成功

R1仅改测试ready握手为固定非空sentinel→fsync/armed→核心Ex `write! /proc/self/fd/N`→父核同held/namedinode且size0/pread空。纯18项含原128门通过；固定CIDUID10000小Ex once exit0/3.090s、ready22→0/sameinode/documentstillEmpty/knowncleanup与tmpabsence通过，无raw屏幕、无image/包变更。新5e8 App的probe f74a3e2e…已实际嵌入、31cmd/10snapshot8object/strict主管核过，证据 `DerivedData/Verification/primary-vim-tiny-ready-r1-3486b000-259f-40e0-99b9-1d91333db940/`。

R1正式新案未通过：strict7帧后直接看到vim-ready但size尚未消费，未投Vimkeys/无文档SHA。原`vim-tiny-r1-live-077851f5-70fd-4f52-9e96-377367580843`失败保留。probe emit(size)后立即进入Vim，验证器从渲染快照读取，存在帧被切屏抹去的测试同步竞争；不通过固定sleep或跳size凑过。

R2新增双向同步：只有validator严格消费size31×93后才返回一次 `.vimStart`，Main发送固定非秘密V\r；remote size后必须在12s内收到精确V\n才createDocument/PopenVim。成功帧仍原12；错序/错误/重复/未见size不得发启动动作，同次多动作仍拒绝。原128断言原位保留，加35共163core、19pure主管独立通过：`DerivedData/Verification/primary-size-vim-sync-r2-6c1cb1c3-a07b-43e0-9c80-ba7e33eb6e0c/`。

新89033 App：`Tests/RemoteTerminalAcceptance/.build/host-89033e34-66db-4c4c-9a23-c2c881636baf/OpenLXSSHRemoteTerminal.app`；mainSHA256 `ba6d985a5afd8bbe99144fa93e3f83fea365d6201683e56e94f8c9e6719cbfb6`、helper `b7d48e6a209c256c54b603247f5ed406b536daacd6e9525d6f9d59330e426f4e`、probe `a21f1e2931b873d75274da3e86b8723513d6ee7bc852dff1a9ca93e2a47f4391`。仅复用8父依赖对象/增量Core-Offline-consumer，31cmd均0；10snapshots/actualprobeBase64+SHA在签名binary/strict主管核验 `DerivedData/Verification/primary-size-vim-r2-signed-e7b99930-c8e1-4c71-94b4-57a2bac4e9b0/`。

**R2唯一freshcase实际consumer exit0，无failure，全部12帧成功。** connected1/auth0、shortACK/probePID/inputSHA/CtrlC/size/实际Vim编辑保存文档SHA/termios原恢复断言/remoteCleanup/done/returned0/returnedToOuter均通过；typed事件vimStartEnqueued早于vimEnqueued早于probeComplete，未降低任何门。无额外重跑、source/bundle未变。

remoteACKPID6973/start未采到如实null，pidfd确认absent，nonce4a86c4ca0f5441fd9a85d7eaaefaa123 knownroot不存在、terminalfolders/Vim空，无手动remote signal/delete；relay65925/consumer66025/SSH66065实际结束，4-4-0-0/portsfree/FDreturn/localrunrootgone。

原report/命令/后验：`Tests/RemoteTerminalAcceptance/.build/size-vim-sync-r2-live-204dbfa4-a310-45bb-b500-4efce1a8af21/`。主管独立原12帧/所有成功字段/事件时序/实际三PID不存在与远端后验核验：`DerivedData/Verification/primary-terminal-r2-pass-0228a9da-aaca-412d-9193-13df51b29b3c/`。

有限host15公开DirectSSHSession+SwiftTerm外层PTY/Vim分项通过，不扩为人工IME、嵌套认证、全部TUI工具、macOS26、200次/24h或产品PERF。整体Goal NOT COMPLETE。
