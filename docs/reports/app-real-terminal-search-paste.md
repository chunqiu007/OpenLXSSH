# 原生搜索与内存 Bracketed Paste：真实有限验收

日期2026-10-28，Task `APP-REAL-TERMINAL-A` / `APP-REAL-TERMINAL-REVIEW-R1` / `APP-REAL-TERMINAL-R1-LIVE-A`。

**唯一真正运行的 fresh case 已经主管独立验收：原生双向搜索实际选择、固定 Unicode/NFD 多行的完整 Bracketed Paste 53字节/SHA、实际 termios 恢复、返回外层与原生关闭/重开均通过。** 仅 HostProbe/macOS15 的有限分项，不是人工剪贴板、IME、像素或正式macOS26验收，整体Goal未完成。

## 改动与验收边界

仅四文件：`Application/OpenLXSSH/AppRealIntegration.swift`、`AppRealIntegrationContract.swift`、`Tests/OpenLXSSHAppTests/AppRealIntegrationContractTests.swift`、`Scripts/verify-app-real-integration.py`。新增闭合phase `terminal-search-paste`，不改生产Transport/Files、依赖、认证gate或服务配置。

实际SSH与独立short shell ACK后，固定短Python程序在内存中启用raw mode，输出24行本案nonce marker并开启 bracketed paste。通过原生 `terminal.search` 字段、下一处/上一处按钮搜索；读取真实selectedRange和match summary，不用直接search调用替代原生控件。通过 `pasteFromApplication` 发送固定非秘密多行样本，远端≤1024字节/45秒原始capture核完整wrapper/长度/SHA。

不点击原生粘贴/复制按钮，因为它们访问用户 `NSPasteboard.general`；不读写用户剪贴板。不把memory API验证记为GUI剪贴板通过。此phase全程SFTP attempts/services/lists/handles为0，hard-denied credential provider调用为0。

## 两项独立审查修复

原初始127项测试虽然通过，主管发现证据字段和恢复断言仍不够，未放行live：

1. `TerminalEvidence.capturedPasteBytes/SHA` 原由expected硬填。R1新增严格两字段解析：规范十进制1..<1024、64位lowercasehex、精确expected count/hash后返回实际 `Capture`；报告取实际解析结果。
2. 远端原只调用 `tcsetattr` 就发restored。R1要求随后真实 `tcgetattr(0)==original`，不匹配exit66，调用失败也不得发restored=ok。

新增4个聚焦测试，包括 malformed/noncanonical/边界、合法但错误count/hash、实际帧字段，以及 exact embedded probe 的内存fake五分支：匹配、恢复不匹配、get错误、set错误、read EOF。全部原127个passed test名称保留，共131项/0failure；不将fake当远端验收。

原writer停滞时主管撤销写域、核稳定hash及无编译进程后串行交接。一次provider请求限流中断保留，用户真实“继续”后恢复同agent，没有换模型、另开Goal或并发绕限制。

## 静态构建与主管复核

唯一R1增量命令：`python3 -B Scripts/verify-app-real-integration.py diagnostic`，复用私有853缓存，不重全套Debug/Release/依赖。

证据：`DerivedData/AppRealIntegration/offline-853dd2e8-feff-4491-bc00-cf97bedfbfe4/diagnostic-df210e67-8290-4a1c-8b18-43a922682ae3/`。

131tests/0failure，49source哈希、native160输出、14命令（12普通日志+2私有签名元数据），exit均符合expected。App/helper同Team Development、Hardened Runtime、空entitlements、strict通过；pure help/validate0、missinglivegate64。

- 已签main：`de155c957a4618ddc80c5b6a2e3b3d95894a7bd13613bc0b0617d15d7886d38d`
- 已签helper：`7f50ff436383e8c41221de8015b103196bb57e61d263b935562d69604bd68954`
- manifest：`6b74cc7466eab9d241ae50e35bce3cb58d9971ff508d5ed95d1acc5af2c3e4cd`
- 固定probe原始源码974B/SHA：`64f62935dc0faaf66a96a9eeec36d544893c33c42989bcf4630169a5bd6a9cc7`

完整raw source确在签名main，由 `probeCommand` 运行时Base64编码。主管初始只读核验脚本误以为预编码Base64也应在binary，断言失败保留，按真实实现核完整raw source后通过，不改产品。主管独立源审/原127名称保留/当前49输入/native160/签名/inert证据：`DerivedData/Verification/primary-app-terminal-r1-3ab55e2e-cde1-4e49-9051-ef1c7051de7e/`。

## 两次pre-live拒绝（原样保留）

首ignored harness在collect前把标准 `ssh-keygen` 完整行误与纯SHA token比较，exit2，collect/relay/App均0。实际固定FP未变。仅新resume严格解析固定256/ED25519/comment完整行、唯一规范43字符token，expected FP不改；1正向+12错误输入纯拒绝通过。

首次resume又在collect前发现未知ssh PID87044/PPID46875而拒绝，仍0/0/0。主管只读核验时该ssh已自然消失，父进程为ChatGPT App，不属本Goal；未读其参数、未发信号，也未豁免仍活跃未知连接。第二独立resume证据目录经空闲/零次/所有旧hash门后才执行尚未开始的唯一真实案。

原harness、失败marker、15原证据及第一次resume证据均保持不变；不能将这两次预检失败追认通过，也不能把它们算两次真实连接失败。

## 唯一真实成功案

runID `75cc6d41-6fe0-4a1a-8d3b-dd3873ed464f`；原生App87531自然exit0/15.277秒，24checks全过。collect/relay/App各一次，freshgeneration晚于buildEpoch，显式testscan15；生产scan5/connect10不改。

- 原生搜索总24matches；next index1/range[340,46]，previous index24/range[1122,46]，实际选择变化。
- 固定样本 `native-paste 中文 é` + LF + `second fixed line`，e为组合字符；完整ESC[200~/ESC[201~ wrapper实际捕获53B。
- 实际SHA256 `3f491c71b5e73e954024b8dfe3b9f5211ebbd680031b163bd32d42206a66fc4e`，主管独立重算精确相等，不是仅复述expected。
- 实际termios readback恢复、returned0、freshouterACK、同session/PID均true。sessionID `D77F38C4-C793-4F77-B843-559576C35E2F` / generation1。
- SFTPattempt/services/lists/所有文件handles/forbiddencredentialcalls均0；原生关闭真实session/PID、关窗等待、重新打开不恢复、knownstore清理通过。
- relay87457有序exit0，accepted/finished/rejected/cleanup_failed=4/4/0/0；应用没有被外层TERM/KILL代退出。

原报告：`DerivedData/AppRealIntegration/Inputs/run-75cc6d41-6fe0-4a1a-8d3b-dd3873ed464f/app-result.json`。
SHA256 `693606e9285656364cd5f163f85a3aff17b0a299d193d9d5edefb65e5e529513`。

完整命令/后验：`DerivedData/AppRealIntegration/terminal-r1-live-85439f10-752f-4fb7-a133-db04821cfce6/resume-second-live-672f77c0-4f9a-4332-aea2-a2cc1d9b2bd3/`。最终43文件清单SHA `abb4b61bbbe3affda5ad49848e1e699ebb5a0b8debdcd879995a20fd2afbbf2d`。

## 资源与最终结论

App87531/relay87457/SSH87556均不存在，逐PID lsof无FD，22221～22225无listener，自有准确store消失/app-tmp空。远端UID10000进程0，daemon21/start7980921/FD4及cap0x200400eb不变，四服务CID/start/资源/network/volume/config/auth/host记录前后完整快照相等。本案knownhosts前后均90624f14…，不混用历史nested报告的旧摘要或猜测中间变化原因。

49source/5fixture/15bundle文件未变。主管独立读取原报告与全部43摘要清单、重算53字节内容、复核原生选择与零SFTP/凭据、fixture快照以及当前三PID/端口/store，证据：`DerivedData/Verification/primary-app-terminal-pass-2bfe1f68-7bde-4595-8693-647b078da65e/`。

原App通用taskID/boundary文案沿旧phase保留；本案由phase/runID/完整terminalOperations和命令绑定，不回写历史报告。**有限原生搜索/内存Bracketed Paste分项通过，AC-14整体仍进行中。** 人工剪贴板、IME/视觉、目标macOS26仍未验，后续双标签/手动重连和冲突批策略另案串行。
