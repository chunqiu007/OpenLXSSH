# NativeFailure新runtime：有限真实门记录

日期：2026-10-31。状态：**R3 Native changed / 非合作provider取消后排空 / SFTP changed 三真实负例及两类KI正向共五分项均通过。** 前两个5秒握手失败完整保留，旧R4三活性门只证明各自旧冻结来源，不自动覆盖本版；完整AppGUI/默认切换另验。

## 新来源

- consumer：`.build/failure-r1-453c9c2f-6b6a-434d-8416-eaee70cd042e/artifacts/UXNativeFailureConsumer`，SHA `a13a715a545ad072b6d0d6c30299cb46073f171bcdebfc8681f7dda6ed3f141d`。
- 475公开输入current+snapshot核0差异；只5个NativeFailurePackage已审生产源替换旧228baseline，其余208非实验输入不变，旧gate不改。
- Swift6 complete/warnings-as-errors及C-Werror，15Mach-O对象/产物均arm64/min26；14纯checks和inertCLI预期通过。初build非Sendable捕获失败保留，仅预取String路径修。
- main独立审buildrecipe、五案consumer、reportschema、资源/秘密观测边界后才启动原批准fixture relay（有限360秒），不生产/新环境/真实用户秘密。

## 首个nativeChangedNoHandler

证据根：`DerivedData/UXVerification/NativeFailureLive-R1/Primary/`。

`nativeChangedNoHandler-1-run.json`含真实argv/cwd/exit，exit1，11.353秒总时长；active5.016688秒。

实际事实：

- fixedidentity/policy/fresh≤120成立，ownedroot精确清理成功，fixture公开known_hosts bytes/inode不变。
- primaryprovider0，advertised/primary/KI/shell全0；只说明未请求/投递主材料，不说stable reader未读一次性fixture材料。
- observation=unexpected、failure=nativeOrEvidence，未取得typedchanged/handle证据；knownhoststeststore未完成比较字段保持false，不假称被改写。
- FD3→3、child0→0、同processid，资源回基线true。
- relay仅ready日志，当前没有足够握手phase证据。不能据5秒恰好时长归因hostkey回归或密码问题。
- capture此前只保kind/stages但guard失败后report漏kind/operation；R2只增加闭合whitelisttypeddiagnostic+固定validationFailure并新冻结构建，不改5/10/12预算或验收断言。主再按同fresh契约真实复验后决定原因。

后续两负案及两KI正向尚未执行，首串行脚本按失败停止；不把未跑案计成功。首有限relay62742已**自然exit0**（含预检总384.820秒，max360），accepted1/rejected0/finished1/cleanup_failed0，主另核进程消失/端口释放；未发signal，不以relay成功回写consumer失败。

## R2同案：已定位为握手操作超时

R2只补固定typedError/validationFailure观测，预算/断言不变；新binarySHA `927dc4db9921021eca3d4e9ffa4ebe3bfab4b34d4fad5b3fc6863ca4fc56fd8a`，475输入变化0，严格build/14pure通过。主管在新180秒relay63490与fresh合同下跑`nativeChangedNoHandler-2`，仍exit1。

准确typedError：**domain=nativeShell、kind=timeout、operation=handshake、code=-10002**，interactionDrainPresent=true、pending0，active5.017785秒、provider0/stages0；资源FD3→3/child0→0/ownedroot清理仍通过。这说明早于公钥/认证，不能称typedchanged逻辑回归；之前handleFromTypedErrorfalse只是caseguard未过后字段未赋，不代表错误未带handle。

主审据代码对照并校准：本新consumer网络操作预算5秒，既有LivenessConsumer及AppDriver为10秒，Released/Fault有限消费者实际为15秒（不误记10）。R3仅对齐**测试consumer**到已证10秒档，两处operationTimeout5→10；connection3/interaction10/auth12/active15/full/cleanup12/fresh120及拒绝断言保持。不是改产品timeout或信任策略，不确证慢启动精确根因；若10秒仍失败就重新调查，不继续涨预算。

原两次失败均保留。R2relay63490已自然exit0，含预检总204.714秒/max180，accepted1/finished1/rejected0/cleanup_failed0，主另核监听释放；未执行的其余四案不计通过。

## R3三项真实负例通过

新consumer `.build/failure-r1-e4da5f50-5927-4407-9356-2a5403c09d5d/artifacts/UXNativeFailureConsumer`，SHA `9efbfbad95645a517f6c1abb3ca20fe944a0ba9e5e1a5664676705062f67ab7f`。只有Consumer两处operation5→10，475输入current/snapshot0变化，严格build/14pure/15Mach-O min26过，其他预算/断言/recipe/五生产源都不变。主在第三有限relay63963/max360下新fresh合同执行。

| 分项 | 实际结果 |
| --- | --- |
| nativeChangedNoHandler-3 | exit0；active6.234秒；typeduntrusted/host-key，端点/算法/新旧FP精确匹配，provider0/stages0；canonicalhandle nativeClosed/revoked/sealed/drainedtrue |
| nativeCancelledProvider-1 | exit0；active6.787秒；typedcancel/pending1，真实handshake/methoddiscovery后provider1进入；关闭0.507秒后nativeClosed/sealed但provider仍pending，独立0.05秒wait仍pending，手动release后actualfinish归零，late材料未消费 |
| sftpChangedNoHandler-1 | exit0；active6.225秒；typedFileServiceErroruntrusted+精确changed事实，无handler、无accept；不伪造SFTP认证计数/registry |

三案known_hosts bytes/inode和fixture公开known_hosts均不变，FD3→3/child0→0/同pid、ownedroot精确清理true；主独立重读原JSON及argv/exit。R2新增typed诊断仍保在R3报告，不只看reportpassed。

## R3两类KI正向通过

同binary9efbfb…/475freeze，分别原批准key-kbd/password-kbd服务的新fresh材料，主亲跑：

- keyKIPositive-1 exit0，总25.073秒/active15.682秒；primarypublicKey一次、实际code-19且authenticated=false后KI一次code0、authenticated/shellReady各1。
- passwordKIPositive-1 exit0，总25.135秒/active15.742秒；primarypassword一次、实际code-18且authenticated=false后KI一次code0、authenticated/shellReady各1。
- 两案均callbacks4/replies4、management response读取3、zero notification回复1、late0；原始协议无复制替代。
- 两案真实ACK/PTy/37×113 resize/EOF/exit7/无signal/localclose成立，known_hosts bytes/inode不变，FD/child基线恢复，ownedroot清理及server challenge file removed true。
- 主独立重读两JSON、认证stage、完整argv/exit/时长，不以reportresult字符串独自判过。

五案consumer目标通过，App完整退出retirement仍在source-only实施，不等于App默认替换。第三有限relay63963已**自然exit0**（含预检总384.713秒/max360），accepted5/finished5/rejected0/cleanup_failed0；主另核其进程消失与22221～25监听释放，无signal或强制收尾。

## 观测边界

- ChangedHostKey公开API只含endpoint/algorithm/新旧fingerprint；consumer只比较经成熟解析的带外公开input指纹，rawHandshakeBytesExposed=false，不伪造握手raw直接比较。
- SFTP无认证stage/provider计数或Native drainregistry仪器，相关字段nil/false，不用mock冒真实。
- 非合作provider门主要看nativeClosed/sealed+pending/laterfinish；关闭耗时不是独立安全证明。现报告对close≥0.5门暂保留，真实若失败先记录再据实现裁决，不自动延期。
- 永久retirement/Lifecycle还在App源码实施，五案consumer只验证Package public API，不称完整App退出已修。
