# 真实正字节传输期间的原生 SSH 标签切换

日期2026-10-28，Task `APP-REAL-INFLIGHT-TAB-SWITCH-PREP-A` / `LIVE-A`。

**唯一fresh案经主管独立验收通过：16MiB真实上传在655360B和983040B两个正字节running时点原生A→B→A切换，同任务及两SSH身份不变；最终原service SHA一致、精确清理/正常关闭与资源后验通过。** 仅HostProbe/macOS15，任务入口仅完成后核可见，不扩称目标系统、像素/IME或长期稳定性通过。

## 最小实现与静态证据

仅既有App四源新增closedphase `transfer-survives-switch`，上传前原生新建B并对A/B真实short ACK、出生PID身份、tab/session/view/driver独立性进行检查。最小扩展原16MiB helper：新增switch分支，原close/hide动作块逐字保留在else，共用完成/streamSHA/knownledger/local-source清理。不复制另一套transfer、不暂停或节流、不改变生产包/fixture。

每次操作在原manager fresh snapshot后核原job/request/batch/generation/service/host、0<progress<16777216且running、A/B token/PID出生/对象未变，再无await同步原生performClick。实际选择变化后再核双会话；过快完成则拒绝，不伪造覆盖。

独立SwitchEvidence保存两次动作进度/uptime、原任务与会话身份、最终SHA、任务入口实际状态、清理；不把switch数据填入旧close/hide字段。任务入口在完成后通过原生hide/open核同job可见，明确不是在途入口可见性证明。最后原生关闭B→A并等待真实driver/PID释放，再沿通用关窗/重开/store清理。

新增3项puregates，拒0bytes/满大小/非running/错job-gen-batch-host-service-path/变token-PIDbirth/对象失配/pending/不改选择。原145个passed names与40Contract主体保留。唯一 `python3 -B Scripts/verify-app-real-integration.py diagnostic` exit0，148tests/0failure，无编译/测试失败或第二构建。

`diagnostic-53ef47b8-73ab-4cd9-85e3-41f08b1df31d`：49source/native160/14cmd（12logs+2私有签名记录）通过，manifest `c0f48bfb08c4be7243ed54cb6530973121a833924d115b72ac941998adcbde9c`；main `a6dc14464a0f7a6b901c85848884346754dbe6362e0cb125481e9b510774b036`，helper `e3fd903f09eb81e8f437d3e13188dce0e31e0f5aee8daa0de0cad0c55a782fba`。

主管全源审及独立148/原145保留/49输入/严格同TeamDevelopment-Runtime-空权限签名/inert0-0-64证据：`DerivedData/Verification/primary-app-switch-static-2ba25de5-6c7d-4867-88a0-5693133c2291/`。

## 唯一真实案

runID `8f7dcf87-4fa1-433c-92fb-925385d18bb2`，collect/relay/App各1，无失败、重试、暂停或节流。App94485自然exit0/46.146秒，31checks全过；显式testscan15，production scan5/connect10不改。

- A94510/gen1，出生1793147925/78036µs；B94581/gen1，出生1793147945/28347µs。实际父PID均94485。
- A→B：655360B，uptime546549.1644098334。
- B→A：983040B，uptime546549.2799988333。
- 两次均fresh actual running/正字节且<16MiB，真实native选择改变，双token/进程出生/对象未变。
- 同job C71ADDDA-21BD-414E-BD04-72DFCD103565、generation7676EEF0-583D-4BF3-A69C-8DE5DACE5210、batchE6412A89-DC02-4500-8F15-3E45C119D2D3及同service/host/lifetime/serverBinding、attempt1。
- 最终16777216B，source与原service流式SHA均 `e3a417b4096ae29df2f7bae6cffd693d99004229c1b22601f52150f5d3b838f9`。主管独立按64KiB块/offset小端数据公式重算相同。
- 任务入口在uptime546556.2681507916实际succeeded/16MiB、同job可见；不写成在途入口验证。
- 原service精确root/temp/payload清理、held source清理，两tab原生closed/window重开不恢复/store清理；8opens8正常closes/end0/shutdownrescue0/credential0。

原App报告：`DerivedData/AppRealIntegration/Inputs/run-8f7dcf87-4fa1-433c-92fb-925385d18bb2/app-result.json`；SHA256 `4ebefd54621b9b6538b5b7ef8bad9a314efdfc2d164bf53370877fe0a589aaae`。

运行命令及41文件清单：`DerivedData/AppRealIntegration/inflight-switch-live-15856947-296f-4910-b83a-d6e1d605c355/`，manifest SHA256 `d11baba56a5d42fb3e9ab68ff5fd3a9fc790adc31eefee0d92580bb3191be239`。

## 资源与结论

App94485/relay94396/A94510/B94581均不存在、逐PID FD0，22221～22225无listener、准确store消失/app-tmp空。fixedCID UID10000只读lexists确认精确transfer root不存在，不做外层删除/SFTP。relay有序exit0/9accepted9finished0rejected0cleanupfailed，无强制KILL；远端UID10000进程0、daemon21-start7980921-FD4及四服务/CID/start/caps/network/volume/config/auth/known前后快照相同。49source/5fixture/15bundle未变。

主管独立读取原31checks/两transition进度时间与完整identity关系、任务入口完成后事实、全部41摘要并重算完整16MiB源公式，再核当前四PID/端口/store与源签名，证据：`DerivedData/Verification/primary-app-switch-pass-5a9026e2-7684-4f06-bdb5-d1561f167834/`。

**有限真实正字节在途切SSH标签分项通过。** 不改变既有关闭/隐藏分项结论；任务入口在途可见、完整多任务排列、正式macOS26及长期/人工验收仍按总表，不用本案替代。
