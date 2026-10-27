# 原生真实上传跨标签关闭：首案失败检查点

日期2026-10-27，Task APP-REAL-TRANSFER-PREP-A / LIVE-A / APP-TRANSFER-DIAGNOSTIC-R1 / APP-TRANSFER-AUDIT-FIX-LIVE-A。**原两个真实16MiB phase失败保留；定位并修复测试环境AUDIT_WRITE缺失后，新f851单案28检查全部通过，实际上传跨原生关闭SSH/隐藏面板完成、同服务SHA一致、8opens/8closes/endhandles0/shutdown救援0。** 仅HostProbe/mac15上传分项，窗口/Quit活动任务/目标系统仍待。

## 已审实现与准备证据

仅修改既有AppRealIntegration.swift/Contract.swift、契约测试及独立构建脚本四文件，新增封闭phase `transfer-survives-close`；缺省仍read-only。生产Packages/P6/NativeSmoke/认证与环境不改。

真实原生路径：mkdir风险明确确认→当前service生产probe原生prepare/review/approve/execute→原生upload按钮→HostProbe测试picker URL选择→正式FilesController/Manager。测试picker不当人工Finder/NSOpenPanel。

生成/真实分配16MiB非秘密source，64KiB增量SHA；真实exclusive-temp成功账本存在且close/hide动作前各自snapshot必须running且0<bytes<16MiB，过早完成明确失败。同job/request/service/host/generation/binding及connectionattempt1完成后，同service lease流式SHA和精确knownpath清理才通过。不能用waitingRisk或静态演示冒在途I/O。

主管完整读四文件与差异、复核安全probe/风险/UI/动作时序/后验SHA与ledger，独立116tests（原113+3）/49sourcehash/20命令、HostProbe15与正式Debug/Release26、strictDevelopment签名通过：

`DerivedData/Verification/primary-app-transfer-static-158dbb70-6eed-461f-89c0-169be3ced380/`

精确App `DerivedData/AppRealIntegration/offline-853dd2e8-feff-4491-bc00-cf97bedfbfe4/HostProbe/Build/Products/HostProbe/OpenLXSSH.app`。

- 主程序SHA256 `1bccd1558595afde6e4076da76bf96cf301a295cde9e1f731025c8c8ac87019c`
- helperSHA256 `9c85cea633faa44ed0d8d2092224f5f167b82c67227cfe4573e3c9441ad9542a`

静态通过不是runtime通过。

## 唯一首案真实失败

新freshgeneration/带外trust/固定CID/image/internal/资源及hostfree46,820,093,952bytes/卷free35,148,218,368bytes核验后，run `ae16c0b5-9ad9-4bc2-baca-939e37343722`，phase固定、显式testscan15/connect10，一个600s有限rootrelay。

- App PID26914 exit1/25.466s，failureCode=failedCheck。
- 实际SSH PID26958已建立，productionSFTP1/list4，禁止CredentialAccess调用0。
- 18个已记录检查通过，最后为new-transfer-phase-no-previous-jobs；此前mkdir/root初空/生产probe通过，16MiB source已分配。
- transfer证据为null；原代码未serialize guard标签/job snapshot，无法由现结果区分firstjobidentity、tempcount、precloseinflight、prehide或其他后续守卫。
- **没有close/hide动作时进度或完成证据，不能说该行为通过。** 失败cleanup关闭SSH/PIDnil不等同测试动作覆盖。
- 公开handles最终0，但open7/正常close6、shutdown归账1，不能称全部正常关闭。
- files awaitclose1；自有App/SSH/relay PID均不存在、无directchildren，端口无LISTEN。relay26843 TERM/waitexit0、accepted5/finished5/rejected0/cleanup_failed0。

原result：`DerivedData/AppRealIntegration/Inputs/run-ae16c0b5-9ad9-4bc2-baca-939e37343722/app-result.json`。

命令/cwd/exit、fixedpubliccontract/资源及失败inspect：

`DerivedData/AppRealIntegration/transfer-live-0521e061-a808-4ff6-bf3e-c763605c0f21/`

## 精确残留与主管独立恢复

原report的base64账本明确root和成功exclusive-open temp；手写消息曾把尾E416误抄成F416，第一次主管只读断言因此拒绝，无写入/删除。后续从原base64字节解码，不猜名或宽扫描：

`/fixture/home/openlxssh-app-transfer-ae16c0b5-9ad9-4bc2-baca-939e37343722/.openlxssh-transfer.31E50F3F-18AB-4A4B-B495-31002F50E416.part`

主管固定exactCID/UID10000管理通道逐组件dirfd/O_NOFOLLOW只读核：root UID10000/0700/dev65025/inode23382，仅一个已知temp，finalpayload不存在；temp regular0600/单链接/dev65025/inode23383，真实750,896bytes，SHA256：

`7ab9b448ff0a1fba85098cd004c8235cf0053840d690cc2b5adbd2211f544cd5`

再次核held FD与当前path identity/属性/摘要后，仅unlink该temp和rmdir空UUID根，确认不存在。不将temp字节数反推原close/hide步骤，不把外层恢复当首案成功。

独立后验与删除命令：

`DerivedData/Verification/primary-app-transfer-failure-postcheck-4d9ff98c-e66e-49f4-850f-17d7f44c573e/`

本地canonical markedstore原dev16777228/inode114281690、16MiB source与managed key先只读metadata确认。主管随后核原App PID不存在、固定layout/noACL/UID/mode/单链接、各heldFD/pathidentity及非秘密marker，仅删除11个已知生成文件（含source原inode114281784/managedkey副本/marker）及五个空目录/root；canonical路径确认不存在。未读取私钥内容或摘要、不改fixturegeneration/corpus/raw结果，原report的failed/localStoreRemoved=false原样保留，外层恢复另记 `local-metadata-precheck.json` / `local-cleanup.json`。

原probe已清成功，但其临时目录名未serialize，不事后重建或扫描未知项。

## 阶段诊断R1与第二个真实新案

窄R1增加封闭stage/guard标签及最多8条纯metadata任务快照，unknown路径不导出，无rawerror/terminal/secret/privatehash；所有原inflight/身份/生产probe门不改。主管读四文件，独立118tests（原116+2）/49sourcehash/14命令及strictDevelopment通过。复用私有853树做受影响HostProbe build/tests/sign，不重建正式Debug/Release，原min26证据另引用。

当前同App路径已是R1主程序SHA256 `296eed8a48b6de619a9e309b4b9fd03719657148161090cf1f9068bf82c22f41`、helper `c70ad333b9fd822d95c4c86f5cc6b2ba50d946f230e4985d89f7c2d48cd51ec8`，不能与首案1bcc…混用。独立证据 `DerivedData/Verification/primary-app-transfer-diagnostic-static-58e12044-56f0-4b09-8d9a-fae507aec24f/`。

新freshgeneration/run `062f5ffa-6ea8-4464-bd03-e4e0538e4625` 唯一诊断实测exit1/25.494s：

- failedStage=preCloseAction、failedGuard=sessionConnected、failureCode=transfer.sessionConnected。
- 四条快照显示pendingDecision时任务waitingRisk/0bytes，**SSH已经failed且ownedPID不存在**；firstJob及preClose时SFTP真实running/720,896bytes，job/request/service/gen/binding一致、attempt1。
- 实际未到nativeclose/hide动作，不能说已覆盖关闭；故障在cleanup前出现，不能把cleanup关闭当原因。
- 初始actualOwnedSSHPID为31847；一条手写消息误报31871，原脚本从JSON取值本来正确，额外ps31847无存活记录保留纠正。
- App31821/relay31739/SSH31847最终不存在、filesawaitclose1、handles0，但open7/正常close6/shutdown归账1，不能称全部正常CLOSE。
- relay5/5/0/0 TERMwait0，端口释放；原报告localStoreRemoved=false、transfer=null不改。

原result：`DerivedData/AppRealIntegration/Inputs/run-062f5ffa-6ea8-4464-bd03-e4e0538e4625/app-result.json`，SHA256 `cc98c040155971d5c84c74965ed82ccd63bb55a3cca59f614eb2f8ba49b17f2d`。完整命令/快照/资源与PID纠正：`DerivedData/AppRealIntegration/diagnostic-live-8a79adc5-858a-4dfb-9efc-e2fdda48ccab/`。

主管按原base64账本fixedCID只读核，仅已知temp CA80BB64…/最终payload不存在，temp实存851,968bytes；再次核FD/inode/SHA后只删除该temp及空062f远端根，原失败不追认为成功。证据 `DerivedData/Verification/primary-app-transfer-diag-postcheck-149e38aa-f6c8-4d85-bba7-14a7c794b2c6/`。

本地markedstore原dev16777228/inode114299062、sourceinode114299153及完整固定账本在原App/SSH/relay PID已结束后，逐FD/noACL/owner/mode/单链接/pathidentity/非秘密marker全量预检，只unlink11已知文件+rmdir五空目录/root，canonical路径不存在。未读取私钥或source内容/摘要，未触rawreport/fixturegeneration；原failed reportSHA仍cc98…、localStoreRemoved=false不改，外层恢复另记原live目录的local-recovery-precheck/result.json。

## 认证后退出的下一诊断边界

第二案提供了实质新证据：SSH在动作之前已经失败。另一个真实Terminal探针亦认证后ACK前断开，故优先调查共同post-auth配置/PTY所有权/fixture shell与PAM session链，不把根因先归给loader或本phase动作。

生产调查只读，Terminal已用新短非秘密shellnonceACK单案取得真实failed(launchFailed)/exit255：connected后73bytes入队，9.249s后退出，stop=false/loader未发送。相同系统SSH远端exec的-T成功/-tt失败，容器UID0/10000 openpty均成功；这使调查收敛到PTY相关会话路径，但仍未确证sshd具体失败步骤。详见 `docs/reports/real-remote-terminal.md`。不将Terminal的255回填到本App旧案，不盲重跑App；不能删除sessionConnected守卫、放慢或造进度来凑通过。

主管再次核49冻结源码与既有118tests/0fail、双App主程序/helper摘要及strict签名，证据 `DerivedData/Verification/primary-app-terminal-frozen-a24c034b-da4a-4254-907e-4f311351baec/`。这是可复现诊断检查点，不是上传生命周期验收通过。

## AUDIT_WRITE修正后全新实际成功案

同image单差A/B确证环境missingAUDIT_WRITE破坏PTY后，仅keyonly修正/新身份，其余三服务与原数据卷/网络不变，见 `docs/reports/pty-audit-capability.md`、`docs/reports/keyonly-audit-fix.md`。App仅测试Contract两compiledpin换新CID1253a295…/FP SHA256:MHUel445tN/gQtcvZikLZVE1mlWZf7U38C0zZTTru+Q，生产/P6/phase/inflight/sessionConnected等逻辑和断言未改。

既有私有853树受影响增量build/test/sign，新UUID diagnostic436855a2…：118tests/49hash/14命令/native160/strict通过，主管独立核 `DerivedData/Verification/primary-app-rebind-ee8558f1-ac8b-4c9c-8b03-58e111d36525/`。同App路径现主程序SHA256 `f65aea8fd76ee23f55dce052a81b142f2ded1a24dbb8a6b7fa24c63f1bc0297d`、helper `fbd19ace487f75df06b5d0bfec5ad8834eac0dd175ef2afd6cfe55c80c1a871f`；旧hash仅对应旧记录，正式min26沿用旧证据而非本轮重建。

fresh collect晚于buildEpoch/newUUID run `f85121e5-6f69-4f04-8d4b-57c1bbd38519`，唯一实际运行exit0/32.116s、原JSON passed=true/28检查全过：

- 原生SSH close动作发生于running 720896/16777216B，动作前SSH connected且ownedPID存在；随后原生hide发生于983040B，均真实未完成，不把waitingRisk或快照完成当inflight。
- 同job/request/host/generation/service/serverbinding、connectionattempt1/reconnect0，任务实际succeeded/16777216B。
- source与同生产service流式读取remote SHA256均 `e3a417b4096ae29df2f7bae6cffd693d99004229c1b22601f52150f5d3b838f9`。
- 仅已知payload/空UUID远端根和held本地source/store清理，剩余ownedpaths空，remote root同service lstat notFound。原生窗口关闭awaitFiles并重开不恢复。
- productionFiles attempts/returned/awaitclose1/1/1，publicopens/closes8/8、endhandles0、shutdown救援0、forbiddencredentialcalls0。
- App58635/SSH58671/relay58540均不存在/无其directchildren；relay TERMwait0/5-5-0-0、hostports无listener、canonicalstore实际不存在。runtime已交回。

原result：`DerivedData/AppRealIntegration/Inputs/run-f85121e5-6f69-4f04-8d4b-57c1bbd38519/app-result.json`，SHA256 `1e9a508945c58bc1cfb0117a6a9e68dd9da7c61434be79f9ec99f10fb8a67819`。完整harness/setup/run/资源 `DerivedData/AppRealIntegration/audit-fix-live-c4c99694-e898-4b98-9f36-a3e8a2ad6041/`。

主管独立读原JSON/28checks、严格进度/动作前SSH状态、sameidentity/摘要/8正常closes、三实际PID和canonicalstore不存在，通过此有限分项：`DerivedData/Verification/primary-app-transfer-pass-6c91397d-7bf7-4f8a-877f-4f42492293fd/`。两次旧失败及外层恢复不追认为成功。

当前AC-22有限host15上传跨关闭/隐藏分项通过，**不等整体AC-22/24完成**；picker仍是HostProbe测试选择，不是人工Finder/NSOpenPanel。macOS26、人工交互、其他传输方向/活动窗口与Quit完整矩阵未覆盖，整体Goal NOT COMPLETE。
