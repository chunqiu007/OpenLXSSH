# P7 有限稳定性验收驱动准备审查

## 当前结论

仅驱动准备范围通过，未执行真实200次连接或五会话连续24小时。`Tests/StabilityAcceptance/` 提供依赖为空的离线安全/计时/证据核心与CLI，另有target外真实DirectSSHSession AppKit consumer源码，未链接、构建、签名或运行真实driver。默认help/validate无连接，离线CLI即使带flag也拒绝真实run。

正式驱动未来仅接受获用户授权的官方隔离keyonly服务127.0.0.1:22221、fixture账号、无口令一次性Ed25519。运行flag只是防误操作，不等用户授权。启动检查目标macOS26、严格产品App/helper固定身份、out-of-band已核指纹与fixture provenance、权限/无ACL/无链接材料及输出目录。不从keyscan自动接受、不读Keychain/ssh-agent、不支持猜测挑战。未知/加密密钥/MFA明确拒绝，产品四类认证仍另验。

## 验收合同

- cycles只在正式可信outer-auth事件后且closed+ownedPID nil才计入200；另20次穿插取消单独计数，不从认证数扣除。
- soak固定五个独立真实session全部认证后计时，至少86400秒连续；wall、awake monotonic、continuous三口径、睡眠/观测缺口/时钟异常或任一断线失败，不改时钟/电源、不重连/拼接。
- JSONL有行/字节上限，不含终端输出/秘密/完整参数；指标只已知ownedPID与精确helper路径，核UID/PPID/birth，不全机按名字杀进程。point RSS直接相加会重复共享页，PTY为vnode描述符非唯一设备，kernel线程非Swift任务，短命helper可能漏采，不能代表完整产品PERF。
- 清理只调用正式Transport拥有的session关闭并等待，不自行kill，保留证据与public trust，不扫描删凭据/容器/App数据。

## 独立审查修复

初轮离线20+6通过后，只读审查发现两项P2：查询失败被当作已退出、后端先closing/failure的尝试被当主动取消。作者新增修前9项8断言失败并保留快照/日志。R1改身份alive/confirmed-gone-or-recycled/unknown三态，EACCES/短读/身份不稳/同birth异常不得cleanup empty；未知立即失败并标metricsIncomplete。主动取消必须pending/无failure/未认证且真实backend preparing或connectionPending，拒绝无效取消仍完整drain，不增加计数。

主管读取真实driver/Options/PrivateMaterial/Lifecycle/Evidence/C与新增回归，独立执行 `PYTHONDONTWRITEBYTECODE=1 python3 Tests/StabilityAcceptance/verify_offline.py` 退出0：34项XCTest、6项Python、真实公开API既有mac26模块warnings-as-errors typecheck、C严格syntax检查。独立原审查者定向复核两项resolved，不扩大范围。日志 `.build/verification/primary-r1-offline.log` 及offline-swift/python，修前 `.build/verification/r1-before/`。

## 签名偏差记录

作者早期普通swift test被SwiftPM隐式执行本目录离线CLI的ad-hoc debug签名，无身份查询、没有正式App/helper或真实driver签名。已报告，不能写为本轮绝无签名。最终总入口显式 `--disable-get-task-allow-entitlement`，先仅生成job graph核没有codesign/debug entitlement步骤再执行tests；主管最终复验同样无该步骤。不通过全局安全设置绕过。

## 真实驱动构建 B

后续P7-STABILITY-DRIVER-BUILD-B仅在Tests/StabilityAcceptance新增离线配方和12个拒绝测试，使用固定已缓存源及官方SwiftTerm generator，从源在本目录独立UUID编译真实driver/helper。现有低部署版本依赖对象可合法用于min26正式App，但本驱动任务采用更严格全部runtime input min26，所以不直接混用min15/min11旧对象。

实际完成11个arm64/MH_OBJECT/min26对象、真实公开DirectSSHSession的MH_EXECUTE driver及官方helper。link map严格只允许记录对象和所选SDK .tbd，没有额外archive/host工具。官方generator只host-only执行，不链接runtime。163项源码/manifest/pins/生成输出快照与编译链接命令、对象/二进制hash可复核。wrapper不再接受随意revision替代来源，必须消费真实linked-build记录，UUID独占不覆盖。

本任务明确使用已有Apple Development身份，helper先/App后，正式不同identifier、同Team、Hardened Runtime、无entitlements、timestampnone及Apple anchor严格验证通过。没有证书/profile/ACL修改、系统授权代答或Apple上传；没有执行driver/helper（宿主macOS15）。早期WMO参数、requirement文本缺=前缀和SDK别名检查失败分别保留UUID/log，修后新UUID通过。

工程师成功产物：`Tests/StabilityAcceptance/.build/driver-8f5d1fcc-764d-4641-829c-7ff119888656/wrapper/OpenLXSSHStability.app`。driver SHA256 `e85de82f685f0455176916feb5f64d99def81ceea7b68d19cd7bd48ca2d2b07e`，helper `9173ad680234094d7d0a01b3db992d1c5453193e485920207722023fe232fb99`。来源commit b034db2/dirty=true，产物状态signed-static-only-not-run。

主管阅读6文件关键编译/来源/链接/签名/拒绝实现与tests，独立 `build_driver.py verify --record <该UUID>/result.json` 退出0，真实严格signature、对象min26/sourcehash/linkmap闭包通过；再独立verify_offline退出0，34XCTest+6既有Python+12新增Python、API typecheck/Csyntax通过。日志 `.build/primary-driver-build-verify.log`、`primary-driver-build-offline.log`。未重复消耗一次完整重编，独立核验实际产物和关键边界。SwiftTerm6处上游CVDisplayLink弃用warning保留，未压制。

## 待完成

真实driver构建/来源/Development静态签名现已准备完成，**尚未执行**。获授权环境、目标macOS26、实际网络200/连续24h及完整App/UI/文件连接/对象释放/输出切标签/Instruments均未执行。AC28/29/30/32、PERF-R不据此改通过。外部前提另见 `docs/release/acceptance-prerequisites.md`。
