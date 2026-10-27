# 真实活动上传：窗口继续与取消关闭

日期2026-10-27，Task APP-REAL-WINDOW-TRANSFER-A / LIVE-A。**host15/HostProbe唯一真实16MiB任务的原生关窗Continue→再次关窗CancelAndClose分项已通过主管验收。取消明确留下一个已声明temp，外层精确后验并清理，不冒称App自动清净。Quit及macOS26仍未覆盖。**

## 已审实现与离线产物

仅AppRealIntegration.swift/Contract.swift、既有契约测试与verify脚本四文件，封闭phase `window-continue-cancel`，复用原真实mkdir/probe/nativeupload、同job/request/host/service/gen/binding/attempt1。两次动作前与决定时都重读Manager快照，要求running且0<bytes<16MiB，过早完成明确失败。Continue需窗口可见/admission恢复/同Manager与任务；Cancel必须任务cancelled、原managerclosed/noactive、真实服务awaitclose、SSHclosed/nilPID、窗口实际关闭。只对原已知temp声明原生ack前先写exclusive/fsync checkpoint；关闭服务后不做IO或自动重连来伪造远端absence。

主会话完整读四文件diff，核原native控件/时序/身份/worker drain/精确账本；原118+3=121tests/49sourcehash/14命令/native160/strict签名通过：`DerivedData/Verification/primary-app-window-static-bc9aaed6-fa38-48f0-8e27-33d0fc205e9b/`。

产物：既有853私有HostProbe树受影响增量/newUUID diagnostic-fdd379f4-5fa8-4730-a8d7-7178342cf592，无复制依赖/三配置全重建。App SHA256 `c325a030f3d966a720604cf5ab6fa274a7c064f2c5ec83e2b893a350ef01ae23`、helper `acb09388fb58d94cadd16990074c7e8a7a5d8f0bd9305f7dafa84da3c2c458d4`；该路径已替代f65/fbd，旧实际上传记录保留其原hash。正式min26仅沿用旧编译证据。

## 唯一真实单案

fresh collect晚于buildEpoch，keyonly当前CID1253a295…/FP MHUel445…严格核，新run `9baf485b-25fc-45a0-b1e3-e9b8c611f7cc`，testscan15/connect10、relay600s/App480s上限。App61440 exit0/25.985s，23checks/7exclusive checkpoints。

| 动作 | 实际已传输字节 |
| --- | ---: |
| 第一次原生关窗 | 720896 |
| Continue恢复后 | 1179648 |
| 第二次原生关窗 | 1179648 |
| CancelAndClose决定 | 1441792 |

全部严格小于16777216且running，同job B97B290E-3D08-46B8-A047-7A1BF65FE91F、gen236068D0-10F0-40F6-8850-FBEECA92A772、service4CFBE413-1195-4782-80B1-187BA75229AB、bindingA2E4A9E5-9BB5-4753-81FB-E6FEB698F451、attempt1。终态cancelled而非成功提前完成，managerclosed/drained/windowclosed/SSHnil/filesclose1/handles0、credentialcalls0。

公开句柄open7/正常close6/shutdown归账1，取消dispose事实保留，不称全部正常CLOSE。App/relay61366/SSH61462三PID已不存在/无其directchildren，relayTERMwait0/5-5-0-0、批准端口无listener，canonical localstore实际不存在，重开不恢复连接。

## 远端声明与外层精确恢复

App准确报告唯一retained temp，原native ack前 `window-retained-before-ack.json` 已持久化。关闭后没有第二SFTP/服务IO；原report的remotePostcheck=NOT PERFORMED保持不改。

固定CID管理通道逐dirfd/O_NOFOLLOW后验：final payload不存在，root只包含原base64账本temp、unknown0；parent dev/inode65025/12958 UID10000/0700；temp dev/inode65025/12959 UID10000/0600/link1/1602864B，全量SHA256 `5a9c2b53cfe53c7d51f1628c9a589ad5c2d773465c0fddb19722d8c59eeb1d7b`。再核同heldinode/SHA后仅unlink该temp/rmdir空root，确认不存在。不是自动扫描清理，不改retained原报告。

辅助后验首次在任何Docker命令前因旧8KiB报告读取上限拒绝，改显式≤64KiB有界metadata读取后继续；UID/mode/noACL/link安全门未放宽，原拒绝留证，不重跑App。

## 证据

- 原App report与7checkpoint：`DerivedData/AppRealIntegration/Inputs/run-9baf485b-25fc-45a0-b1e3-e9b8c611f7cc/`，report SHA256 `e55ffb611f091914acf36b5a403e1d59c46a48e377743e63c41395be4ec17cf4`。
- 完整setup/run/后验/精确恢复：`DerivedData/AppRealIntegration/window-live-b8c62ccf-cb42-4c89-8aa8-ea6c58c1af54/`。`remote-exact-owned-cleanup.json`明确externalManagementRecoveryNotConsumerCleanup及reporthash前后相同。
- 主管独立读原23checks/windowEvidence/7checkpoint、严格inflight/终态/7-6-1归账/三PID与canonicalstore不存在：`DerivedData/Verification/primary-app-window-live-76824ef0-71ff-456d-a4a6-d3b7f477ae1a/`。外层已读finalpayloadabsent与temp身份/SHA/清理记录。

## 尚未满足

本分项不等AC24整体通过。Quit Continue/Cancel与真正退出、人工Finder/NSOpenPanel、IME、macOS26、长测/产品PERF仍待。测试picker和host15不冒充人工或目标runtime。测试数据取消后残留已明确告知并精确管理恢复，不宣称没有任何残留风险。

整体Goal NOT COMPLETE。
