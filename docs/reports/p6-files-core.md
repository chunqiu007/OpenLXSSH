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

## 未完成与整合约束

真实SFTP/认证/MFA、rename/fsync扩展、删除与能力probe远端运行未验证，本地FD fixture不是服务器。上游静态库未ASan/TSan插桩。macOS26只编译未实跑。

App必须应用级持有Manager并显示任务入口，所有enum终态含completedWithSkips均准确显示；panel默认隐藏/按需连接，关闭SSH标签不能取消任务。窗口/退出有activework须产品确认，继续保留窗口，取消并关闭需await真实cleanup。idle关闭后要明确新建服务，不假称续传或自动重连。
