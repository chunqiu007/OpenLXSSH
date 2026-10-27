# 真实双标签、自然断线历史与原生手动重连

日期2026-10-28。Task `APP-REAL-SESSIONS-RECONNECT-PREP-A` / `APP-REAL-SESSIONS-RECONNECT-LIVE-A`。

**唯一fresh案已由主管独立验收：同主机独立双标签、两轮原生选择/最近活动双击复用、A自然exit0后的历史保留、有限无自动重连观察、原生手动重连新代次，以及两会话资源清理均通过。** 本案是HostProbe/macOS15有限分项，不是正式macOS26、长期稳定性或完整AC03/AC16验收。

## 实现与约束

仅修改既有四个测试接线文件：`Application/OpenLXSSH/AppRealIntegration.swift`、`AppRealIntegrationContract.swift`、`Tests/OpenLXSSHAppTests/AppRealIntegrationContractTests.swift`、`Scripts/verify-app-real-integration.py`。新增封闭phase `sessions-reconnect`；不改生产SessionController/Transport、依赖、fixture配置或认证gate。

- 通过既有原生主机双击建立A、`session.new`建立B，两个真实DirectSessionDriver/DirectSSHSession/NativeTerminalView和所属ssh分别独立；每连接均有角色隔离的short shell ACK，不用connected冒shell就绪。
- 两轮A/B `tab.select.<UUID>`后双击同主机，应定位最近活动标签，始终只有两个标签；token/generation、proc_pidinfo出生身份、原driver/session/view均保持不变。
- A通过固定octal printf输出不会由命令回显伪造的marker，再让最外层shell自然 `exit 0`。要求真实 `.disconnected(0)`/lastExitCode0、runner PIDnil/旧PID不存在、canReconnecttrue。不调用cancel代自然断线，不覆盖生产状态回调或手置state。
- 切B返回A，通过原生搜索证明旧marker仍在；单调时钟有限2秒采样核A无新token/PID、B身份不变，不宣称无限期证明。
- 点击原生 `terminal.reconnect`，要求同tab/driver/session/view、同sessionID且generation精确+1、新进程出生身份、fresh ACK，以及旧history仍可原生搜索。
- 测试主机持久配置7/2与A初始/B/A重连配置逐项相同，只证明配置映射，不冒称黑洞保活/失联超时已测。
- 原生先关闭B再A，等待具体driver.closed/ownedPIDnil与实际进程回收；沿既有通用关窗/重开/knownstore清理。SFTP attempts/services/lists/handles及credentialcalls全0，无剪贴板操作。

## 静态与签名证据

新增6项pure契约测试，覆盖phase/nonce、角色ACK与回显隔离、malformed/重复/oversize、对象与精确新generation/允许PID号码复用但出生身份须改变、自然exit不能由nil/cancel替代、单调有界观察和错误采样。原131个passed test名称全部保留，合计137tests/0failure；原terminal-search-paste函数和协议逐字未改。

唯一增量 `python3 -B Scripts/verify-app-real-integration.py diagnostic` exit0，证据：
`DerivedData/AppRealIntegration/offline-853dd2e8-feff-4491-bc00-cf97bedfbfe4/diagnostic-0d280b4f-7be8-4896-afc7-d6e285ec8ad0/`。

49source/native160/14cmd（12普通日志+2私有签名记录）均符合expected exit；新main `58f13b23b09b0d53580583d6ca1c375cc74087e0d052d84ff71017ecbb744b2c`，helper `2e689deba0406e9a62e6e2ef6e825b07db3fdccf1f186ae59e56af430e02625f`，manifest `c3da07cba1e2712f0ce4c9701d35ebe434a54911259bcde1a747e675a34c2717`。

主管完整阅读实际四源diff/关键状态和资源路径，并独立核验137/原131保留/当前49输入/同TeamDevelopment/Runtime/空权限/strict与pure0-0-64，证据：`DerivedData/Verification/primary-app-sessions-static-2901a2ea-eecb-4331-acb6-0a06d26c28b8/`。未重跑无变化的正式Debug/Release或依赖全构建。

## 唯一真实案

runID `2e2d7a05-4f00-45b4-a4d8-9eeece5a412c`，collect/relay/App各一次，无失败、无重试。App89024自然exit0/44.889秒，35checks全通过。显式testscan15，生产scan5/connect10不变。

| 身份 | sessionID / generation | PID | 出生sec / usec |
| --- | --- | --- | --- |
| A初始 | 5BAAC51D-BCD7-4CDA-8684-E8B59B1B4FC5 / 1 | 89051 | 1793144569 / 389899 |
| B | 30AF0459-5BC1-4FD2-8A16-69CBFFC82BAE / 1 | 89088 | 1793144582 / 152929 |
| A手动重连 | 同A / 2 | 89152 | 1793144599 / 268340 |

三进程的真实父PID均89024。4条选择记录分别round1 A/B、round2 A/B，selected==reused，原token/进程/对象未变。

自然断开exit0与旧A已消失成立；实际有限观察2.045976秒、40samples。断开与重连后均原生搜索1match/index1/range[68,52]，同A对象 retained、fresh ACK成立，B未重新连接。配置三次均7/2。先关闭B后A、关窗/重开不恢复、store清理全部通过，未触SFTP或凭据。

relay88956有序exit0，accepted/finished/rejected/cleanup_failed=12/12/0/0，没有强制KILL；App没有外层TERM/KILL代退出。

原App metadata报告：`DerivedData/AppRealIntegration/Inputs/run-2e2d7a05-4f00-45b4-a4d8-9eeece5a412c/app-result.json`。
SHA256 `d0947a88c7612217e5bb1eb7682fa54019d9bfb1e7af0947edcbf84058b558ea`。

运行命令与资源：`DerivedData/AppRealIntegration/sessions-reconnect-live-bbf7433d-f152-459e-8a2e-e982e8c8ab52/`。40文件manifest SHA256 `810ff47c84889485f9b89a94b1080352e9375e3bbcd072f90d2816ebe985af0f`。

## 独立资源复核与限制

App89024/relay88956/三ssh89051、89088、89152均不存在、逐PID lsof无FD；22221～22225无listener、准确store不存在/app-tmp空。远端UID10000进程0，daemon21/start7980921/FD4，四服务CID/start/cap/network/volume/config/auth/known前后完整快照相同。49source/5fixture/15bundle未变。

主管独立核原35checks/三身份出生时间/精确generation/4选择/有限采样/历史/零SFTP、全部40摘要，以及当前五PID/端口/store与冻结源/签名产物：`DerivedData/Verification/primary-app-sessions-pass-6f11e7f4-08cd-4b64-b0a6-3c2a9c50dfde/`。初次只读复核脚本错用pre-fixture文件名，按真实resume-sessions前缀纠正后通过，未做状态动作或改原证据。

**真实双标签与有限自然断线/手动重连分项通过。** 2秒窗口不等无限期无自动重连，keepalive不等黑洞检测，天然退出不等网络故障全矩阵。人工IME/像素、正式macOS26/200次/24小时及发布双机仍未满足，原App通用taskID按历史保留，由phase/runID/sessionOperations绑定本案。
