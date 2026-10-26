# P6-FILES-A / TransferManager：正式文件核心审查

更新2026-10-26。工程师实现，Primary Agent独立审查。当前为本地范围通过；真实SFTP、App文件面板与目标系统仍未验收。

## 正式文件核心

`Packages/OpenLXSSHFiles/` 自包含libssh2 1.11.1/OpenSSL3.5.9LTS源码构建与许可物料，只公开library。typed TCP/DNS→同握手hostkey→正式Trust→认证，路径原始字节、流式有界、取消/timeout、结构化错误、默认无信任。生产入口无public任意FD adoption，不依赖实验/tmp/Homebrew。

主管前轮已读迁移实现、SafeFileOperations和ServerCommitProbe，并独立verify.py通过57项双配置/ASan/TSan/min26/native/license/外部消费者。删除先计划精确root/items/risks，再一次确认，执行前全量重验、执行中不扩大范围；禁止host根，不跟随链接，变化停止逐项报告。服务能力探针必须显式批准、只自有UUID目录，验证现存目标拒绝且内容不变、空目标成功才生成本service证据，不能自动给业务伪造token。

## 独立任务管理

TransferManager actor由应用级持有，服务/job/batch身份与生命周期不依赖SSH标签、panel或stream订阅。

- 有界jobs/等待/历史/观察者；每host FIFO、全局job上限，复用引擎chunk2，不第二套提交机制。
- 状态queued/running/waitingConflict/waitingRisk/succeeded/completedWithSkips/skipped/failed/cancelled；字节进度与逐项结果/retainedtemp可见。snapshot不含secret、服务对象或整文件Data。
- 决策一次性ID+job/generation，取消/晚回答/重复/错类型拒绝。overwrite/skip仅同host+batch复用；renameTo单项，风险不因选overwrite自动确认。
- cancel queued立即终结；running保持active直到真实engine清理；cancelAllAndWait停止接单、撤销决定、等待worker与service.close。idle只在没有job lease时关闭，不自动重连。观察取消后任务继续。

主管读全部Manager、13项原测试与engine冲突hook，独立运行完整Scripts/verify.py退出0：Debug/Release/ASan/TSan各70项，原57保留，外部消费/单library产品/native160产物和7许可hash/min26均通过，未重复重建未变native。

## R1审查修正

主管发现directory成功+file跳过会误报succeeded，派工程师增加completedWithSkips。成功仅report.allSucceeded；全skip仍skipped，含失败优先failed，新终态inactive。另修复alternate rename递归/拒绝/skip丢已确认risk记录。

工程师Debug/Release各16定向、73全量均退出0。主管独立Release16项ManagerTests退出0，真实树无symlink两skip+目录成功及额外777字节成功文件均不误报整体成功，失败夹skip/全skip/hasActiveWork与risk继承通过。该组合命令后续错误使用`/usr/bin/rg`返回127（非测试失败），已用PATH中的rg独立复核实际实现；不把错误命令写成通过。

R1未重跑ASan/TSan/native/min26，因为只改结果分类与风险记录；原70矩阵证据仍保留，新增3项在Debug/Release完整73项通过。日志 `.build/verification/results.json`、`p6-transfer-manager-r1/results.json`、native-hash-verification.json。

## R2：根目录枚举与源一致性修复

P7独立只读审查发现两项历史测试未覆盖的问题：根目录 FD 使用 dup 导致重复 list 消耗共享偏移、预览后整根复制漏文件却成功；源文件同 inode 等长跨块修改可能提交混合内容。已新增修前回归，8项测试出现36断言失败（exit1），证据保留而非将历史通过改写为从未有缺陷。

R2改为 openat(rootFD, ".", ...) 创建独立目录枚举描述；RemoteFileService 新增可选 fstat，默认nil保持旧conformer兼容。Local真实fstat保留device/inode与纳秒mtime，libssh2通过原串行/EAGAIN桥接FSTAT。私有SourceIntegrityCheck对初始path、打开后handle、读后和beforeCommit后再次复核；源句柄保留到所有最终检查结束。弱属性或无handle-stat路径增加一次有界流式SHA256复核，不缓存整文件、不无限retry；取消/关闭保留原错误，检测变化报raceDetected且不提交，原目标保留。

工程师Debug/Release各86项、ASan/TSan各57项受影响测试退出0；主管读取全部本轮实际差异、新13项完整性测试和结果日志，独立运行Release57项退出0。包含重复/并发根list、预览后4文件/7结果+SHA、同inode等长纳秒变化、同size/mtime换inode、beforeCommit修改、symlink、弱属性、增长上界、复核取消双句柄关闭、静态源及Manager/策略回归。

证据位于 `.build/verification/p7-files-integrity-r2/`，主管日志 `primary-release57.log`。min26、独立consumer/smoke、单library和160 native产物/7许可hash工程师通过。首次min26因SwiftPM旧source清单缓存遗漏新增文件失败，保留日志；显式 `--disable-build-manifest-caching` 重新规划后通过，verify脚本独立消费者同步修正。仅重编C桥，未重建上游libssh2/OpenSSL档案。

此修复仍是观察到的变化检测，不是source原子快照。最终检查后修改、恢复全部可观察元数据、远端秒级属性及摘要复核期间的剩余竞争如实保留；没有真实远端FSTAT/SFTP证据。本地2GiB/1000压力随后另行验证，不从57项推断已通过。

## R3：同服务根目录自拷边界

主管进一步核查到 raw byte prefix 判断对根 `/` 拼接出 `//`，漏掉同服务 `/` 到 `/inside` 的自拷。工程师真实Local复现（maxDepth2限制规模）：修前1项2断言失败、已创建inside并返回7递归结果；未伪称通过。最小修复用路径组件前缀，包含根空前缀与相等关系，不把/tree-sibling误作/tree后代。

新增3项回归后工程师双配置48相关/89全套退出0，主管读两文件实际diff并独立Release16完整性测试退出0，日志 `.build/verification/p7-files-root-self-r3/primary-release16.log`。拒绝发生在新目录/句柄创建前，真实64句柄槽仍可全开关闭，原文件不变，sibling复制正常。不重复未变native与sanitizer。当前同一service对象识别边界不扩大为不同服务对象底层目录别名检测，UI整合仍须保持受控服务/根的归属。

## 服务操作生命周期接口

为避免panel目录浏览/安全操作未计入Manager.users被idle关闭，新增 `withServiceOperation(serviceID:hostID:scheduling:_:)`：raw list/mkdir默认serialized复用engine同host gate；已有SafeFileOperations/probe显式callerScheduled只拿lifetime保护，其自身使用同scheduler。操作最多128，metadata snapshot不含service/closure/result/secret，hasActiveWork包含真实cleanup中的operation。

caller取消只通知该token、不service.cancel或取消共享worker；闭包必须await所有I/O/cleanup，迟到成功取消不返回，但不宣称回滚已提交文件。shutdown单flight封闭admission、取消jobs/operationtokens，等待worker/drain和实际service.close后才返回。禁止operation内等待本manager.shutdown（自等待），同manager嵌套operation主动typed拒绝；外层应用生命周期负责shutdown。

工程师仅Manager+新8tests，旧89保留，Debug/Release各97、ASan/TSan新8均退出0。主管读两文件完整差异/测试、独立Release完整97退出0，日志 `.build/verification/p6-files-service-operations-a/primary-release97.log`。真实Local覆盖2msidle+显式idleclose不打断、caller取消等cleanup、并发shutdown等真实close、容量/host/unknown/stale/error、同hostgate/异host并行、安全操作/probe无双锁、多个job/op共享最后user释放。没有真实网络或native重建，App接入另验。

## 未完成与整合约束

真实SFTP/认证/MFA、rename/fsync扩展、删除与能力probe远端运行未验证，本地FD fixture不是服务器。上游静态库未ASan/TSan插桩。macOS26只编译未实跑。

App必须应用级持有Manager并显示任务入口，所有enum终态含completedWithSkips均准确显示；panel默认隐藏/按需连接，关闭SSH标签不能取消任务。窗口/退出有activework须产品确认，继续保留窗口，取消并关闭需await真实cleanup。idle关闭后要明确新建服务，不假称续传或自动重连。
