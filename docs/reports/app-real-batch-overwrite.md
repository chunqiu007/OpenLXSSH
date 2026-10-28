# 真实批覆盖与逐项独立风险确认

日期2026-10-28，Task `APP-REAL-BATCH-OVERWRITE-PREP-A` / `LIVE-A`。

**唯一fresh案经主管独立验收通过：一次原生批overwrite冲突决定，两个job仍分别出现独立非CAS覆盖风险；实际回答前均零进度/无完成项/无临时文件，最终同名双目标匹配Fresh内容，原生清理及资源释放通过。** 不代表远端CAS保证、macOS26或在途切标签。

## 实现与静态回归

同四个App真实测试接线文件新增closedphase `batch-overwrite`，复用小Seed/Fresh数据、6节点FD/inode/SHA账本、现有current-service probe和原生上传/审核删除。已有batchConflicts等phase函数逐字不改，生产包/控件/fixture/依赖不改。

Gate仅从actual public snapshot/request逐字段转换。每job先remotePath风险；只允许一个applyToBatch=true overwrite conflict；然后每job必须新decisionID的非CAS风险，第二冲突/重复风险/错路径代次/非waitingRisk或非零写入元数据均拒绝。终态还核真实TransferItemResult.acknowledgedRisks恰为两项独立风险。等待风险时不申请同host服务lease读取摘要，避免阻塞当前transfer gate；不声称风险时取得独立SHA。

新增3项聚焦测试，原142passed names和37个旧Contract主体保留，总145tests/0failure。首a6812d9e因测试两处缺try导致xcode65、未跑tests，App编译成功；仅补try，失败日志保留。复验 `python3 -B Scripts/verify-app-real-integration.py diagnostic` exit0，`diagnostic-6d908493-7d39-4b2c-83d3-94cf0484150e`，49source/native160/14cmd（12log+2私有签名记录）通过。

已签main `932c1df1b4019d64eb2ceab81b99ceb71c62955f0a7025a4eed08e55465f89e2`，helper `688b1a7de7dd28b06e9c56963a09903b6c9f5c49d742e6b5a49bbb9713ba73cc`，manifest `87fff9f71532ad67817e39f48464b9a920e699113fbad761ad1bfa5539a0fb14`。

主管完整源审状态机/原生流程/风险前观察门与测试，独立核145/原142保留、49输入、同TeamDevelopment/Runtime/空entitlements/strict与inert0-0-64，原batchConflicts逐字不变，证据：`DerivedData/Verification/primary-app-overwrite-static-e7bb255a-87c4-4d6d-8a46-e0f34d446257/`。

## 唯一真实结果

runID `d2f6ac87-1a10-4c3f-9afe-b74fd7210118`，collect/relay/App各1，无真实失败或重试。App93193自然exit0/32.374秒，23checks全通过。显式testscan15，production scan5/connect10不改。

- Seed2和overwrite2均succeeded4096/8192，共4distinctjobs/2batches。
- 7distinctdecisions：4个remotePath风险、1个applyoverwrite批冲突、2个分别绑定job/generation/batch/path的overwrite非CAS风险。
- 覆盖风险回答前实际waitingRisk、transferredBytes0、completedItems0、retainedTemporary0、观察ownedtemp0；两个风险独立原生接受，不从冲突决定推断许可。
- 双目标同名同大小，最终SHA精确等于本案公式Fresh/a、Fresh/b，分别不同Seed。主管独立重算四local与seed/finalremote公式摘要。
- 同manager/service/lifetime/host/serverBinding，SFTPattempt/service/close各1，22opens22正常closes/endhandles0/shutdownrescue0/credential0。
- native精确审核删除root+a/b三路径，本地6节点及store清理完。无外层seed/SFTP/救援删除。

原App报告：`DerivedData/AppRealIntegration/Inputs/run-d2f6ac87-1a10-4c3f-9afe-b74fd7210118/app-result.json`，SHA256 `d17bf25b19996f805d26897261d1fd36b85c3e477b2a9fc43a76cbc96b2269a8`。

命令/资源/41文件清单：`DerivedData/AppRealIntegration/batch-overwrite-live-e7d8a16d-7be5-4e28-82da-5199a264778f/`，manifest SHA256 `db0483806432bbc645b120cd0d257d93668b55b173df841c6108312858a361fb`。

## 资源与结论

App93193/relay93114/SSH93256不存在，逐PID lsof无FD、22221～22225无listener、准确store消失/app-tmp空。fixedCID UID10000只读lexists确认native已删root不存在，不补删除。relay有序exit0/5-5-0-0，无强制KILL；远端UID10000进程0/daemon21-start7980921-FD4，四服务身份/资源/配置/授权/known/network/volume前后快照相同。49source/5fixture/15bundle不变。

主管独立核原报告、7项decision顺序/绑定、风险前实际零值、全部41hash与独立内容公式、当前三PID/端口/store和冻结源签名，证据：`DerivedData/Verification/primary-app-overwrite-pass-2815a787-cc2d-42dd-a80d-f3ccbaf3d4ab/`。

**有限真实批overwrite/独立风险分项通过。** 风险等待时未读独立内容SHA，不能将零进度门扩称原子内容快照；远端overwrite非CAS既有限制保持。人工Finder/mac26、并发外部修改完整矩阵与正字节inflight切标签仍未因此通过，整体Goal未完成。
