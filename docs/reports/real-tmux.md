# tmux交互探针：首案缩放阶段失败检查点

日期2026-10-28，Task REAL-TUI-VERSION-A / REAL-TMUX-RESIZE-R2-LIVE-A。**原首案与闭集诊断R1失败保留；R2显式输入确认/新增resize-ready/事件驱动实际尺寸等待后，唯一新案完整十帧、真实Ctrl-b d脱离及正常server/pane清理通过主管验收。** 原九个成功门全部保留，新增同步帧；仅程序化host15 tmux分项，非人工像素/IME/htop/mac26。

## 限定实现和静态证据

新 `Tests/TUIToolsAcceptance/`，公开DirectSSHSession/SystemOpenSSH+PTY+SwiftTerm。同exactkeyonly1253CID/MHUFP、固定单pane/nonce0700自有socket目录，tmux -S固定socket/-f/devnull。hello后固定T ACK才切入TUI，pane精确非秘密sample SHA→resize31×93→D ACK→App实际Ctrl-b d；退出后仅自有socket管理核session_attached0/window_panes1/listclients空，再kill ownserver/pidfd等待/termios恢复/known目录清理。不是管理命令伪detach，不查询用户server、不kill报告PID，不dump屏幕或解析密码。

仅公开版本命令各一次实测tmux3.4/htop3.3.0、20B/exit0，没有把安装/版本当交互通过。htop/pixels/IME始终false。

主会话全读Core/Main/remoteprobe与source58core/9pure/完整APItypecheck，指出own Popen超时TERM后未升级KILL可能漏回收，最小修为wait3→TERM/wait2→KILL/wait1，发生强制回收仍Refused不报成功detach。主管独立9pure5.612s通过：`DerivedData/Verification/primary-tmux-source-c8f95df2-2c34-4476-ba58-2b353f18775f/`。

只复用89033 Core+8依赖9对象/原私有recipe，增量编译TUI Core/Offline/consumer，31命令全0/10snapshot、新probe97fd实际base64+SHA嵌入签名binary、sameTeamDevelopment/Runtime/emptyentitlement/strict。新App `Tests/TUIToolsAcceptance/.build/host-87dc7531-0215-49bd-8143-d29ee67b27fb/OpenLXSSHTUITools.app`，main SHA256 `ca99a765e9d382134421c2d7d9be6d9e12c9f7addc306fee18697f8323b3ad5f`、helper `eeb870beba153372a0e7fa115626c5d357a945e1812370a91cffa4caa4ec8570`。主管独立来源/符号/签名证据 `DerivedData/Verification/primary-tmux-signed-8b790f6e-5d83-4488-a58d-ac52c5ceae74/`。

## 唯一真实首案

fresh collect/relay/consumer各1，外层0/consumer1，不重跑：

- failure=unexpectedFrame/toolFailureStage=resizing/unexpectedProbeFrame=input/probeEvents4。
- connected1/auth0/shortACK/probePID/panePID ACK、真实inputByteHashMatched=true。
- remoteSizeMatched/detached/remoteCleanup/returnedToOuter均false；无remoteProbeFailure。
- 失败时connected/pending0/stopfalse，本地closed/ownedPIDreleased/FDreturntrue。

原report没有异常input帧内容/字段数，不能确认是渲染重绘/残留包络、内容损坏或其他原因。parser目前只跳过完整相同frame，不能据name忽略旧帧来凑成功。当前仅source/offline补四项闭合diagnostic（拒绝原因/字段数桶/长度match/hashmatch，不raw值或答案hash），保持拒绝和九帧要求。

## 资源与精确外层恢复

remote parent13977/pane13981 pidfd均absent，serverPID/start未采到明确null，不能称serverpidfd已验。nonce baf7414520ef42a7b1d4f29218b58139下仅stale server socket，dir dev113/inode94/UID10000/0700、socket dev113/inode97/0600；精确/proc/net/unix该路径无entry，重复identity/knownentries核后仅unlink该socket/rmdir空目录。无远端signal/broadkill，不反改原remoteCleanupfalse或冒正常server清理通过。

relay76742/consumer76830/SSH76871均实际结束，4accepted4finished/0rejected0cleanupfailed、批准端口空/localrunrootgone。原report/source/bundle未变。

证据 `Tests/TUIToolsAcceptance/.build/tmux-live-a389d29c-8877-47d7-baf0-838a27992c95/`，包括consumer-result.raw.json/live-result.json/exact-remote-readonly.json/final-postverify.json。主管独立原4帧/inputSHA/原失败与三实际PIDgone核验：`DerivedData/Verification/primary-tmux-first-partial-0085ef69-598e-4f5d-b334-c198926b8487/`。

## R1拒绝诊断新案

新增四项closedmetadata保持原九帧/顺序/完整frame去重/inputSHA/size拒绝不变：reason实际guard enum、fieldcount桶0/1/2/3/other、inputlength/hashmatch可选Bool，无字段原文/hash值。原58+53=111core/10pure及完整consumer类型检查、31cmd10snapshot9objects/实际未变97fdprobe/strict已主管独立核：`DerivedData/Verification/primary-tmux-reject-r1-d10bb21d-fbfe-4ba0-bc28-371f8fa28e26/`。

新dc948App main79143de7…/helper318fe92c…下唯一新案外层0/consumer1，**没有重复旧input异常**，而是remoteFailure={stage:detach,kind:process-exit,errno:none}、unexpectedFramefailed、rejectReasonremoteFailure/count3/events4。inputSHAtrue；inputlength/hashmatch缺省因不是input拒绝，不能填false。size/detach/normalcleanup/returned未过。证明远端实际子命令失败，但未保存具体tmux子命令/退出状态，不能据stage直接认尺寸传播或session消失根因。

parent14718/pane14722 pidfd absent；serverPID/start未采到null。noncead8159bfad0c4860b621ee32e57f19df唯一stalesocket经dir113/116/socket113/119 UIDmode/knownentries及exactkernelpath无entry双核外层精确删除，原remoteCleanupfalse不改，无远端signal/broadkill。relay77922/consumer77998/SSH78084实际不存在，4-4-0-0/FD端口释放/localrunrootgone。

原结果与后验：`Tests/TUIToolsAcceptance/.build/tmux-reject-r1-live-28b19c0b-bb55-4256-95d8-4a4f097c5d64/`；主管独立原typed分类/缺省字段/4帧与三PIDgone：`DerivedData/Verification/primary-tmux-reject-live-partial-ad129551-746b-40df-94a8-a79ab293669d/`。

## R2显式同步与实际通过

源码确认pane原收到R只读一次ioctl，没有等tmux传播尺寸，原process-exit并不足证明完整失败链，因此修的是可观察同步条件而非跳过失败。固定官方tmux3.4 input.c一次阅读确认ED2清可见screen、ED3清history。R2在inputSHA已验证后，Main只新Action发C，pane严格收C后清已验测试输出并发新增resize-ready，Main才resize+R；pane用SIGWINCH/selfpipe/select在12s内反复核真实TIOCGWINSZ，仅31×93通过。无固定sleep满足成功，迟到exact也因deadline拒。

原九成功帧保留，总十帧；错序/改变hash/未确认/重复ready均严格拒，pane EXCL0600 statusFD只记录first闭stage/kind/errno与可选正rows/cols，parent优先firstpanefailure而非后续nosession覆盖。不记录终端/rawerror。原111门保留，总138core/13pure与API完整typecheck主管独立通过：`DerivedData/Verification/primary-tmux-resize-r2-f10d5c79-0c64-4622-8344-268204aceacd/`。

新72eebApp `Tests/TUIToolsAcceptance/.build/host-72eeb8cc-b535-4f02-bd7a-b9ce776d57a2/OpenLXSSHTUITools.app`，mainSHA256 `2b8791524f67ab5270d60104ab720b6b0b6080e1515a1cfae63cbbb15119e4ba`、helper `a5cd363578fc9ff9ea518bf65d08797592cb0a8d7c35d1db5e52434270a2f14a`、probe `d74219f7f2358ffe52f4bc3ca35168931d670c9da8f25601f65c16885d9988b6`。仅增量ownCore/Offline/consumer/九readonly依赖，31cmd10snapshot/strict同TeamRuntimeempty/actualprobeBase64及SHA在签名binary主管核：`DerivedData/Verification/primary-tmux-r2-signed-98e2b057-c980-4cb2-b979-60dd05b1eb9d/`。

**R2唯一freshcase外层0/consumer0，无failure，十帧全部通过。** inputSHA/真实31×93/实际Ctrl-b d detach、clients0/window_panes1、onlyownsocket killserver、serverpane pidfdgone、termios恢复/done/returned0均实际成立。connected1/auth0/stopfalse/closed/PIDnil/FDreturn；源和bundle未变/不重跑。

remote parent15913/server15916/pane15917后验pidfd全部absent，nonce65cb57fb165c4fdab6e02c2d4b3f3e3f root/status/socket自然消失、exactkernelentry空，无手动远端清理或信号；startticks未采到如实null，不据猜测signal。relay79892/consumer79961/SSH79997实际结束，4-4-0-0/端口空/localrunrootgone。

原结果/命令/后验：`Tests/TUIToolsAcceptance/.build/tmux-resize-r2-live-816833d5-c03a-40bc-92ad-9d45ce31b67c/`。主管独立原十帧/成功字段/已取得serverpanePID与三本地实际PIDgone、远端自然清理后验：`DerivedData/Verification/primary-tmux-r2-pass-a10bf0ec-8c5f-4dd5-a65d-9403882abbdb/`。

有限tmux分项通过，原两个失败及外层stale恢复保留。htop仅版本、人工像素/IME/mac26/全部TUI未过，整体Goal NOT COMPLETE。
