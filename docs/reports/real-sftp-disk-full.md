# 真实远端磁盘满：独立 tmpfs 上的 SFTP ENOSPC

日期2026-10-27（Asia/Shanghai），Task REAL-SFTP-DISKFULL-PREP-A / PRIVATE-READER-R1 / LIVE-A。**单次真实远端上传ENOSPC核心验收通过，主管已源审、独立离线复验及原结果联合证据核验。非正式App/macOS26或整项FILE验收。**

## 有界方案与安全恢复

仅新增 `Tests/DiskFullAcceptance/` 十文件，不改产品、fixture、依赖或正式min26。复用生产 `LibSSH2FileService` / `SafeTransferEngine` / `TransferManager`；观察wrapper原样转发，只有真实write抛错后、engine cleanup展开前才执行管理SAMPLE和RELEASE，然后原样重新抛出生产错误，不伪造ENOSPC。

只读调查发现现成 `/dev/shm` 是private IPC的64MiB独立tmpfs，与PAM/hostkey所在 `/run` 和relay token所在 `/tmp` 分离，不新增挂载/容器/capability。运行前必须空盘、总量恰64MiB、UID10000可写、内存余量足够。**不填宿主磁盘或/fixture大卷，也不使用共享/tmp制造故障。**

- 真实本地source8MiB、远端原target64KiB。
- helper固定exactCID、UID10000、`/dev/shm/openlxssh-enospc-<caseUUID>`，held目录/filler FD、0600/O_EXCL/O_NOFOLLOW。
- FILL为60MiB−4096bytes，最多追加一次4096bytes诊断，总量≤60MiB，真实write并核allocated，不稀疏占位。
- 原target创建且核SHA后才FILL；先建立全部连接及管理私有管道，满盘期间禁止其他case/新admission。
- 管理仅最多8行命令、每行≤1KiB、响应≤4KiB、单响应15s、写3s、helper绝对TTL120s、host管理135s、transfer watchdog110s；EOF/TTL/异常/finally先ftruncate(fillerFD,0)释放页，再关FD/清自己的filler及空根。
- helper不删除consumer target/temp或unknown；consumer只清成功创建的精确账本，不自动重连。

## 源码、R1与独立离线审查

主管完整读helper/host管道/typed事件/真实write失败采样位置/恢复顺序/原件SHA/ledger与构建。发现management私有读取仍以完整stat_result比较，要求同型R1：显式dev/ino/uid/gid/mode/nlink/size/mtime_ns/ctime_ns，排除读取会改变的atime。真实延迟首读及同秒ctime红→绿，原NOFOLLOW/owner/mode/single-link保留。

最终host15 Release driver：

`Tests/DiskFullAcceptance/.build/host-5e5bfb35-25fc-4f28-b621-ee57bd76e2f9/artifacts/OpenLXSSHDiskFullCase`

SHA256 `b62d287f4cde3b3fe408ff1b7e898a1dae5b6e5bc7aa9ec5512b0dd3df2b7efe`。

主管独立14Python/30Swift/CLI门、207输入及快照/29命令/160native outputs、strict ad-hoc验证通过，RealIntegrationCore精确只Contract.swift和PrivateInput.swift，不编译并行SFTPAuth/Mina/OpenSSH新增源，不假称共享目录全冻。证据：

`DerivedData/Verification/primary-diskfull-static-61a9987d-9e46-423d-a564-8bfd801aba17/`

旧失败构建与R1红绿记录保留，没有把机制测试注入errno28当真实磁盘满。

## 唯一真实case

Case `a8fc7a19-7594-4fcc-b8e9-0ed3d1dda896`；新keyonly generation `credentials-d6d198290cda` 晚于最终构建。fixed原CID/image/project/internal/no-default-route/no-hostmount/资源和空64MiB shm均先核，五服务未重启/重建/旋转。

仅一个300s上限rootrelay，唯一driver运行exit0/17.210s，实际状态 `verified-real-ENOSPC-original-preserved`：

1. 生产原始错误 `protocolFailure / write / code4`，originalWriteErrorMatched=true。
2. helper在该错误返回engine cleanup前真实append，得到errno28；采样前/后/最终available均0，realENOSPC=true。**FX4单独不作为磁盘满证据。**
3. 先RELEASE，恢复62,910,464bytes空闲，再让engine cleanup；helper未生成替代错误。
4. 64KiB原target kind/size/mode/mtime完全不变，SHA256前后：
   `07923883b1650e9ee0eb8580a5031ece687e0c97cfe0b69814eaddbcfdcb709f`
5. temp真实记录一个，engine已清，consumer精确删除自己的target，helper删除filler/空根，ownedLedger空；local source按SHA/inode清理。
6. API成功open/close6/6、close失败0、shutdown归账0、结束handles0/socket0，helperStopped/managerDrained=true。

源allocated=8,388,608bytes，SHA256 `66429b85a173dff804582de472903e082a2c7fc6e6b8568857c7c3b274b87e78`。传输writtenBytes4,194,304包含原sentinel与实际成功写入，不称完整source已上传。

## 内存、资源与退出

初始helper ready memory53,133,312bytes；release时73,707,520bytes；最终postflight52,133,888bytes。原raw memory.events保留max21050，不声称从未压力；本次所有计数delta0，oom/oom_kill/oom_group_kill均0且不增加。

关闭relay之前先独立确认shm恢复67,108,864bytes全空/根不存在。relay PID13846实际57.277s后精确TERM/waitexit0，accepted1/finished1/rejected0/cleanup_failed0。driver PID13930、host管理子进程、容器内exacthelper/bridge均不存在；无新增token、端口22221～22225无LISTEN，原4个无owner取消tombstone仅观察、不删除。keyonly仍Healthy，无新连接/重跑。

## 证据与主管独立复核

实际argv/cwd/exit、fresh配置/space/内存、release-before-relay-stop与postflight：

`Tests/DiskFullAcceptance/.build/live-872f455f-7311-414f-9ee8-da496f5ea392/`

原result：`Tests/DiskFullAcceptance/.runtime/enospc-a8fc7a19-7594-4fcc-b8e9-0ed3d1dda896/result.json`。

主管逐项核原result、真实code4与独立errno28/full0联合、release空间、原metadata/SHA并从固定sentinel公式重新计算、raw memory.events完全相同、6/6句柄/最终0、已知temp与localdata删除、final/postflight以及driver/source hash：

`DerivedData/Verification/primary-diskfull-results-98625a73-6f44-4618-ba33-679921e4f498/`

未机械重复满盘case。API关闭计数不是对所有不可观察原生协议CLOSE的普遍证明；这里仅报告实际公共调用/生命周期证据。

## 未覆盖

本案只覆盖真实远端上传空间不足，不覆盖宿主下载磁盘满、另一服务扩展能力、GUI任务/窗口生命周期、macOS26、长期、企业环境或双机安装。与已有完整2GiB/1000及断连报告共同支持AC-21/31分项，整体Goal仍NOT COMPLETE。
