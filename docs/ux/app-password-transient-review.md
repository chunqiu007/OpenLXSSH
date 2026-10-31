# App Native transient password — M1 review

日期：2026-10-31。结论：**实际App本次密码认证与终端成立，整案仍failed cleanup；未UX_READY_FOR_USER。** Native仍候选，默认Direct未变。

## 实现与安全边界

- 新独立password Arguments、四键wrapper与公开material schema固定passwordonly/127.0.0.1:22222/fixture、现批准CID/FP/base/image/project/network/context/endpoint。没有任意endpoint/backend/pin/secret override。
- 旧keyonly Contract 34,123字节与原18项测试前缀逐字保持，旧supervisor contract_id/wrapper/check_report函数逐字保持。新密码source不调用旧keyonly pin validator。
- 共享Integration按闭合source分准备：保存manual host、不授权保存密码；创建一次性intent，实际App prepare后检查零标签/零连接/尚未消费；commit后唯一新Native标签与正确路由。两个builder注入点使用同一观察connector。
- password仅由消费者进程内成熟安全FD reader读取固定一次性fixture叶；不进模型、源码、日志、argv、env或hash。无key导入，sourceKeyScope明确不适用，未填假key检查。
- 主机实际公钥、带外FP、代际、权限、稳定FD、fresh≤120秒及buildEpoch校验保持。共享原113×37、exit7、close、weak、FD、自然Delegate quit；45/12/90及外层95秒不变。

## 本地验证

证据`DerivedData/UXVerification/AppPasswordTransient-M1-Verify/`：Debug及显式HostProbe26首构建均exit0、无需源码编译修正。Python12/0，Debug60/0（旧18+密码11+相关31），Host63/0（旧18+密码12+相关31+geometry2），无skip。26件实际Mach-O arm64/min26，Debug专属符号隔离及新旧六入口early exit64通过。未执行受occlusion限制的visibleR9和中键门。

主管源审后独立执行密码12+旧契约18+geometry2=**32/0**。原契约与资源门没有放宽。两项验证harness首失败（数字词法/schema层混淆、nm需要demangle）保留，只修ignored检查器。

## 一次真实App结果

候选`DerivedData/UXVerification/AppPasswordTransient-M1-Live/OpenLXSSH.app`，mainSHA`9ef2e11756e3cdfa3f34e9acaf09fc616a347d6c47ca47536b41689c0adfc32d`。既有Development仅timestampnone离线签名，helper/main固定ID严格校验；无Apple请求。

run `1babb01e-89b7-4b18-9c4a-319c03bcd02d`，实际App PID2742：

- prepare标签0、连接0、intent未消费；commit1、标签1。
- primary provider1、intent消费true、credential owner调用0。
- typed password primary/result各1、code0/authenticatedtrue、authenticated/shellReady各1。
- 实际App terminal relay ACK/PTy/DONE与远端SIZE37×113、exit7成立。
- closeDisposition closed、canonical drained、Driver队列空、registry0。
- **weakWait期间tab/driver/view仍alive，原12秒门失败**，没有进入cleanup FD扫描或known-host终核。baseline19完整；终核未执行不表示文件发生变化。
- App经原Delegate stores/willTerminate自然exit0、无signal；supervisor仍failed app-failure-receipt。独立认证收据明确`authentication-only-resources-unverified`，不把自然退出或认证成功当整案通过。

relay2569自然exit0、204.756108秒（含预检）、accepted1/finished1/rejected0/cleanup_failed0，无signals。主管核批准22221～22225无listener，公开收据已归档`AppPasswordTransient-M1-Live/public-receipts/`。

## 剩余

两主认证下的真实KI/零输入尾轮、once/persistent/changed、并发取消、真实双栏SFTP与资源关闭继续单独验收。既有keyonly间歇weak/FD20→23未解决，其中一个新增FD已匹配QuartzCore default.metallib、两个RW仍未知。没有降低断言、时间预算或批准新的生产/Apple操作。
