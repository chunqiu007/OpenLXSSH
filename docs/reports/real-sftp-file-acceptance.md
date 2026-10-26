# 真实远端文件核心验收：2 GiB / 1,000 文件

日期2026-10-26，Task REAL-SFTP-FILE-ACCEPTANCE-A / LIVE-A。**限定核心远端文件campaign通过，非macOS26 App、GUI、网络故障、长期或产品整体通过。**

## 输入、实现与审查

仅新增 `Tests/RemoteFileAcceptance/` 的10个源/构建/测试文件；生产Files/Trust/TransferManager/SafeTransferEngine、原生库和环境代码未为本测试修改。host15 Release独立驱动，固定fixture@127.0.0.1:22221、CID/project/image/base与带外key；新generation时间晚于构建、prepare只读取公共provenance/trust，live才精确nofollow私钥读取到内存，不打印秘密。

真实使用生产LibSSH2FileService/TransferManager/SafeTransferEngine；ObservedService原样转发，不造数据/错误/能力/fstat或进度；noReplace confirmation只来自当前service的生产ServerCommitProbe。相同host串行，chunk64KiB、concurrentchunks2/jobs1，实际readdir原始bytes作结果名，不从请求名重造通过信号。

主管完整读Core/Main/Campaign/Observation/build/资源C桥，独立核203input快照/32命令/160原生outputs/driverhash/ad-hoc严格签名，并执行93synthetic安全检查与5源码策略测试通过。driver `Tests/RemoteFileAcceptance/.build/host-6fe1cac4-7e98-457a-8a35-4e8d1a30b93c/artifacts/OpenLXSSHRemoteFileAcceptance`，SHA256`8e6f7ad9c5e56af4dcb325889107948478178c28e40bc759041e84799aa96420`。Mina*共享Core并行变化不影响使用的私有快照/PrivateInput/POSIX/旧Contract，主管区分而不伪称所有当前文件hash相同。

## 实际 campaign

主管先独立fixedCID管理通道statvfs检查：卷free37,300,047,872bytes、corpus不存在无symlink，hostfree64,694,542,336bytes。放行后仅一次完整data→collect→prepare→finite3600srelay→driver(上限3300s)，未缩样本或自动重跑。

生成大文件2,147,483,648bytes，allocated2,147,487,744bytes、singlelink；1000小文件共1,523,500bytes，另Unicode组合字符示例4096bytes，manifest合计1002常规payload和3已声明链接。data后/结束卷free均35,148,218,368bytes，空间恢复；源corpus保留不越界清理。

驱动进程exit0/1423.80s（result内部1423.68s）；唯一relay accepted1/finished1/rejected0/cleanup_failed0、TERM/awaitexit0，端口释放，原CIDHealthy/同image/read-only。没有第二campaign、产品代码改动、重建或服务重启。

### 完整往返

远端源、下载、本次上传、回程下载四份manifest各1002项，逐项大小/SHA和实际readdir原名bytes一致。大文件共同SHA256：

`ca191d53500bea54b7d20a86c03b96946aa7d4f6e1fe577fe673d3e97011f25f`

| 阶段 | 用时 | 吞吐 |
| --- | --- | --- |
| 2GiB下载 | 94.261s | 21.727MiB/s |
| 2GiB上传 | 804.481s | 2.546MiB/s |
| 2GiB回程下载 | 90.693s | 22.582MiB/s |
| 1000小文件下载 | 37.059s | 约40.1KiB/s |
| 1000小文件上传 | 25.755s | 约57.8KiB/s |
| 1000小文件回程 | 40.318s | 约36.9KiB/s |

上传明显慢于下载如实保留；吞吐包括生产安全检查、弱元数据源额外完整摘要与测试relay，不冒充最终产品性能。

### 取消与失败/能力

- 下载实际536,880,000bytes后取消(25.000423%，overshoot9088bytes<64KiB)，上传536,870,912bytes(25%)。两项typedcancelled，原目标metadata/SHA前后相同，无retainedtemp；取消后同远端session真实lstat成功，未自动重连。原目标SHA`8f7ca9e8215aa684ad1936bf9753242f284b7db480330cf79f81caa80fe68ed6`。
- 未确认noReplace真实门返回needsCapabilityConfirmation/server-no-replace-unproven、0bytes；当前service ServerCommitProbe通过，碰撞两原件保留。
- POSIX rename实际支持并成功；remote fsync实际成功1005次、unsupported0，不假称“不支持安全覆盖”已覆盖。
- 固定保护文件permissionDenied/open/code3、目标不存在；3个fixture symlink逐项symbolicLink失败，树整体failed，不跟随、不静默跳过。

### 资源与清理

5632次自身采样，RSS high-water26,263,552bytes(约25.05MiB)；APIopen/close12046/12046、峰handles2/结束0、关闭失败0、shutdown强收0。FD首5/峰9/终3，ownedrootFD峰3/终0，fixture socketFD采样峰2/终0；relay实际仅1连接，不把socketFD峰值解释成两会话。service lease drained/remote local asyncclose true，retainedremote/local空。

成功清理只覆盖已创建的自有UUID路径/已知allowlist与local保留parent/dev/inode；远端UUID真实lstatNotFound、本地data根已移除，不递归删除未知内容。source corpus/隔离一次性凭据代仍保留。

## 证据与主管独立结果核验

实测命令/cwd/exit、allocated/free、relay和源码摘要：

`Tests/RemoteFileAcceptance/.build/live-bfa703c2-a4b8-4cfa-9ee3-cd52c7d53c78/`

完整result：`Tests/RemoteFileAcceptance/.runtime/campaign-e1fc4343-beb4-4a54-8222-94354673870e/result.json`，SHA256：

`64ab1c675cdaf11e0e92a00d0c54a86d4a4674bc70e4105a801b920e3bdfd0ea`

主管独立读取result并核hash，重新对比全部四份1002项manifest/readdirbytes而非只信status；核两取消进度/原SHA/实际同session存活、API计数/FD/socket关闭、capability真实结果和localrootabsence。固化摘要 `DerivedData/Verification/primary-remote-file-result-20293a09-f398-467b-946c-c2afbed07593/`。没有机械重复24分钟完整campaign，但关键实现/结果/前置检查均独立复核。

## 验收影响与缺口

支持AC19/20/21/31/32的真实核心分项，不把整项提前通过。仍缺GUI/Finder/生命周期正式整合、macOS26、实际断网/磁盘满及另一不支持扩展的真实服务、长期/双机。SFTPv3路径检查非原子no-follow、最终覆盖非CAS；RSS只计消费者，不含relay/DockerVM/短命公钥解析子进程，非完整AppPERF。
