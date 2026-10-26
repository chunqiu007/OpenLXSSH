# 真实上传断连：原目标保护与协调器回执缺口

日期2026-10-27（Asia/Shanghai），Task REAL-SFTP-DISCONNECT-PREP-A / LIVE-A / PRIMARY-DISCONNECT-R1-LIVE-A。**修复后由主管亲跑全新16MiB用例，真实断连、精确receipt、新显式SFTP连接核原目标及清理闭环通过；原首案receipt缺失仍保留PARTIAL。** 不覆盖失败、不补造终止时间，不算整项AC-21或产品通过。

## 独立入口与前置审查

独立新增 `Tests/RemoteFileAcceptance/Disconnect/`，已验收的完整2GiB/1000 campaign相对15012d3零diff，产品/环境/原生库不改。生产 `LibSSH2FileService`、`TransferManager`、`SafeTransferEngine` 的真实上传，进度回调只写非秘密ready后继续下一次I/O；没有token取消、人工transport错误或修改server冒充网络断开。

主管读七文件及复用路径/资源实现，独立47Swift metadata/5Python static、210输入及快照/29命令/160native outputs、strict ad-hoc通过：

`DerivedData/Verification/primary-disconnect-static-040fc99b-ae6f-481c-842a-9db05b37bdf6/`

精确host15测试driver：

`Tests/RemoteFileAcceptance/.build/disconnect-host-ed4fe77b-f47f-4e3c-bc7c-68308e43c166/artifacts/OpenLXSSHUploadDisconnectCase`

SHA256 `65fb389f30f2959277b7b37f731c324da5a55dac76dee806dddbc96bef0409e9`。正式App仍arm64/min26，不因测试降平台。

前置实际fixedCID/image/project/Healthy/internal/no-log/read-only/nonprivileged/384MiB/0.5CPU/128PIDs核验；host空闲63,062,695,936bytes、卷空闲35,148,218,368bytes。新generation `Tests/IntegrationEnvironment/.runtime/keyonly/credentials-4eb0c861526c` 的collect时间晚于构建。

## 唯一真实上传及中断

Case `3a3cdf25-8a05-4485-825d-75d3db636403`。真实生成并fsync 16,777,216bytes源文件，allocated同值，源SHA256：

`834bf9164e7e54d57bd50ea886a67f53dd657c9e6c6a24dfefa2e7c377050bc2`

- 生产真实progress达到4,194,304bytes（25%）写ready，源未完成。
- 外层仅TERM自己持有的180s有限relay Popen，PID2335；没有停止/重启容器或向consumer发取消。
- relay实际waitexit0，accepted1/finished1/rejected0/cleanup_failed0。
- 上传driver PID2424最终waitexit0，候选结果为 `transport/write/-43`，无完整commit；原service已关闭、manager operation drained、fixture socket0。
- API handles最终0，5次成功open、4次正常close、1次close失败由service shutdown回收。这里不宣称“所有handle close都成功”。
- 精确retained temp已报告：`.openlxssh-transfer.759DD70B-231F-4894-B7C2-7585A9DACD24.part`。

原始证据：

`Tests/RemoteFileAcceptance/.build/disconnect-live-7d7582cc-24ea-4a64-8807-d7a267b8a116/`

原case/ready/upload-result：

`Tests/RemoteFileAcceptance/.runtime/disconnect-3a3cdf25-8a05-4485-825d-75d3db636403/`

## 回执失败与证据界限

已审外层coordinator在relay TERM/wait完成后，读取relay metadata log时抛ValueError，未生成 `relay-termination.json`。原外层仅记录异常类型，未保存message、原TERM requested/completed精确时间；不能事后把ready时间或当前时间填作原TERM点。

后续在自有33bytes、0600/single-link/0700目录真实文件上延迟首次读取，复现 `changedMetadata`：仅atime变化，dev/inode/uid/mode/nlink/size/mtime/ctime等稳定。这与原首次读取同路径log约3秒后的失败高度一致，但没有原异常完整trace，故不称“原trace已确证”。最小R1针对稳定字段比较排除atime，保留内容/身份/权限变化拒绝；红绿证据独立记录，不改写原唯一runtime结果。

原TERM动作只能由既有外层代码、真实ready、relay stopped/exit和原事件上下界支持；精确回执门未过，因此**没有运行原 `--verify-disconnect-case`，也没有伪造恢复receipt**。

R1仅修改coordinator.py/test_static.py：显式稳定九字段dev/ino/uid/gid/mode/nlink/size/mtime_ns/ctime_ns，排除atime。原5项Python保留，新增8项真实元数据回归；修前延迟首次读取与同秒ctime变化红失败，修后13项通过。主管完整读两文件并独立13Python/原47Swift通过，核210原输入中仅两管理文件变化、driver65fb389f…未变，未重建或重跑upload。独立证据 `DerivedData/Verification/primary-disconnect-atime-r1-4cfda922-d0e5-4eee-a428-2220dde8c825/`。这是R1源码/离线验收，不补齐原缺失receipt。

结束立即bind检查曾为false，主管随后lsof确认22221～22225无LISTEN；TIME_WAIT等bind失败不等有常驻listener，未修改复用策略绕过。

## 主管独立后验与精确清理

主管亲自固定exactCID管理通道/UID10000、逐组件dirfd/O_NOFOLLOW核根，确认仅sentinel与已记录的一个temp，均regular0600/单链接/UID10000。读取前后及当前path身份一致；不是在已dispose的原service上伪核，也不冒充新的SFTP连接verify。

73bytes原target的kind/size/mode/mtime与上传前一致，SHA256前后：

`5443dec7422ea655e43db8ce42c70df8001098e026f5163f2094b561037d0b45`

临时文件实存4,259,840bytes，SHA256 `dc3c5b9da8cd066bdc4a455870d515b4b10c5ede9353669f5f2498a2b1f7da7b`。它大于客户端已确认progress，因为已到达远端而尚未计入客户端成功进度的字节可能存在；没有把progress等同远端落盘大小。

随后再次核根device/inode与两文件device/inode/权限/单链接/大小/SHA，**只删除这两个确切名字及空UUID根**，不扫描采用未知temp。根确认不存在。local仅根据已存dev16777228/inode114097184与精确source SHA，held FD验证唯一source.bin后删除本案data目录；case元数据、失败日志与测试generation保留。

独立原目标检查、精确删除命令及结果：

`DerivedData/Verification/primary-disconnect-postcheck-002f13ed-a94e-45eb-8c09-bfb0d5345994/`

原target无损、残留可准确报告和外部精确恢复获得实际证据；回执完整性和显式新连接verify未因此追认通过。

## 主管修复后全新用例闭环

在原失败已定位、R1独立13Python/47Swift通过后，主管明确安排**新的case与新的collect generation**，不是重放原case或给旧结果补回执。driver仍为65fb389f…，管理helper为已审R1 SHA `b40fe4e5c93ae49c16e80196a75ec0e70c01fb80fdb048eb4b1f9d8bf42112ae`。完整2GiB/1000 campaign未重跑。

新case `fb2a3e51-9399-4e5f-8140-e14af3baf4e5`：16MiB真实上传于4,194,304bytes后，由外层精确TERM自己relay PID3620，生产返回transport/write/-43、非timeout/cancel/完整提交；consumer用时11.163s。R1当场生成原TERM requested/completed时刻和readySHA绑定的真实receipt，其SHA256：

`9a90cc6f2892ff3aaeb12bdfd51ba20750cd8e463f912b4759dfe0343bee64cb`

随后主管另启有限relay，**显式运行独立verify命令**（6.392s），新service binding与原binding不同，非产品自动重连。真实核73B原target metadata前后完全一致，SHA256前后：

`f1eb736b5f0564d88dcc45d33bcdab698692258fbd71da706c72ce298d21822e`

仅本case成功创建账本中的精确temp、sentinel和空根被清理，本地data按inode/SHA验证后移除；新service awaitclose、fixture socket0。上传/后验两有限180s relay均各accepted1/finished1/rejected0/cleanup_failed0、TERM/waitexit0，lsof确认无listener。真实result为 `verified-original-and-cleaned-exact-owned-paths`。

主管亲跑命令/exit、receipt/两轮原报告摘要与清理证据：

`DerivedData/Verification/primary-disconnect-r1-live-232259aa-f6de-49e2-9ef4-b94818dfda8a/`

新case runtime metadata：`Tests/RemoteFileAcceptance/.runtime/disconnect-fb2a3e51-9399-4e5f-8140-e14af3baf4e5/`。原3a3…案PARTIAL不改，原receipt仍不存在。

## 剩余与限制

- 修复后新用例的完整断连闭环通过；原首案严格receipt门未过仍PARTIAL，历史与新结论分开。
- 本案不覆盖下载断连、磁盘满、GUI生命周期、正式macOS26或长期稳定性。
- SFTP路径检查非原子、覆盖非CAS；管理清理只适用本案成功创建账本和已核身份，不扩张为任意路径安全删除保证。
- 正式Goal仍NOT COMPLETE。
