# Native 有限混合负载：真实三连接短验

结论：**当前冻结生产 Native 包的有限 transport 门通过。** 不覆盖 App 弱对象/图形 FD、真实 UI、像素、默认后端切换或全部终端工具。2026-11-01（Asia/Shanghai）。

## 范围与来源

仅复用批准的 keyonly 隔离服务。一个消费者最多三条串行连接，始终只一条活动；每条独立核实际 PID birth/UID、TCP source port、native session 与 relay token，真实 finish 后才允许下一条。不重 normal/MaxSessions/DROP、24h、2GiB/1000 文件 campaign，不更改成熟库、公有API、固定归档或fixture。

唯一新增写域 `DerivedData/UXVerification/NativeFiniteMixedLoad-R1/`。冻结156份公开源码和163个原生输入，独立构建当前 Files/Trust 与同锁 SwiftTerm 1.99.1 commit `2f573f73af5e768d90847dce20c97fa9535d7164`，不拿旧 readiness228 的构建来源冒当前版本。原manifest/归档前后SHA均保持。

- consumer SHA256：`7e3d4373148eaeef7dee0cac2ea612b31e611ac69f380a33b66e8ce77fb77afb`。
- headless SwiftTerm.o：`f1b8ab8169cb53017ec887afe251307aa65db457ae6f77437625726a1335a1cc`。
- 准确 build：`Builds/build-c79525fab08c4ec997e2eeeed0bb3c78`。
- v4修复patch：`72b6c9427424e49761cd9c18764323e8f93f3c0a5b702f060d96b8903014d697`；最终账本 `final-source-frozen.json`。

## 实现与审查

三个leg共用preparation30秒、active45秒、full85秒，累计cleanup12秒及总接收1MiB，mixed部分最多15秒，不逐leg重置。唯一receive入口；write/control各串行，异常先取消准确token/session，再取消并join两个producer；成功join后才进入tmux，watchdog也真实join，无TaskGroup遗留loser。

Mixed A逐帧验证64×1024B公开输出内容、序号和总量，输入16×128B含跨write UTF-8，六次resize逐个等远端ioctl ACK。唯一reader有意暂停625ms，实际超过650ms即失败。远端每次实际write起止和H事件形成保守clock offset两端，只有整个write区间在最坏映射下落入pause才计数，不用midpoint或按调度时间推断。

同连接B复用成熟tmux helper/十帧协议、headless Terminal语义，实际输入/31×93/Ctrl-b d/自有server与socket清理/返回outer后才exit7。不把tmux重绘合并解释成原始ANSI每字节可见，也不冒像素。

主管独立读取builder、consumer及窄修，另只读审owner/timing为NO_FINDINGS；此结论仅源码审查。首次缺macOS TTImage alias、第二次纯测试tuple表达式typecheck超时均保留；只在新域使用上游精确 `TTImage = NSImage` alias、显式Double tuple编译修复。存在编译期AppKit类型和对象autolink，最终consumer未加载AppKit，无NSApplication/view/event loop，不称完全无AppKit依赖。

## 实际离线验证

- 最终23条构建命令exit0，9个Swift模块严格Swift6/完整并发/warnings-as-errors；17件实际Mach-O arm64/minOS26。
- Python纯测试12 methods/0；实际Swift pure checker **1208 checks/exit0**，不是1208个测试方法。
- consumer默认/help/validate和四种拒绝共7案符合预期；builder/supervisor validate惰性。
- 主管另独立运行1208 checks、Python12及help/validate/旧flags拒绝，核main/headless实际SHA和min26。证据`Primary/independent.json`。

## 唯一 fresh 真实运行

run `a9cb141d26744fecb7e037df9da76ca1`，consumer PID38706（birth在各收据），监督用时32.510秒。consumer preparation6.262秒、active23.099秒、累计cleanup0.144秒、full29.361秒。消费者与有限normal relay均自然exit0/noSignal，批准端口已核free。

| Leg | 实际事实 |
| --- | --- |
| long | interval3600/count10通过真实配置/认证/shellReady链；约76ms的必要exact绑定后立即关闭，无shell工作/输出/probe等待。不证明十小时活性。 |
| disabled | policy nil，实际公开livenessSnapshot为nil，fresh ACK成立；不宣称抓包零相关包。 |
| mixed | 2.358秒内64帧/65536B输出、16帧/2048B精确输入、6尺寸ACK；pause实际0.630735秒、clock区间宽0.059949秒，19个远端完整write可证在pause内；12次write和1次control在pause内完成。 |

Mixed阶段probe从0到1，实际pending被观测，confirmed1/freed1、helpers0/pendingfalse；完成发生在可证更晚的远端输出之前，不是所有负载结束后闲等一次。原termios恢复/返回outer和fresh ACK成立，随后同session tmux10事件、输入/31×93/真实detach/清理/返回outer全true，最终EOF/exit7/noSignal。

三个leg各 `nativeClosed/producersSealed/tasksJoined/socketGone` 为true，pendingTasks/pendingInput/helper均0；**FD准确计数各4→4**。此成熟metadata是完整数值相等门，不是逐entry身份相等证明。三个独立sourcePort及token未复用，relay逐连接finished/ended、bridgeGone、cleanupFailed=false后再放行下一条。

原始公开结果在 `Live/run-a9cb141d26744fecb7e037df9da76ca1/`；主管重新执行各leg/final/relayFinished canonical判据全部通过，记录 `Primary/independent-live-review.json`。主只prepare公开provenance/known_hosts/client公钥和固定材料引用，没有打开一次性私钥；消费者沿成熟stable reader内存读取。

## 不覆盖与未解决项

没有确定性制造“pending长时间存在且持续输出仍到期”，公开API无absolute deadline，本门不伪称覆盖；保留原pump离线和旧严格DROP各自证据。没有App路由/弱对象/图形FD/GUI、IME或全部TERM-05工具证据，不据此切换Direct默认。并发MFA的A挑战残留、三Trust及旧App weak/FD失败均独立保留，未 `UX_READY_FOR_USER`。
