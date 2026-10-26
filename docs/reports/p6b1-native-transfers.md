# P6B1 原生传输任务与关闭保护审查

## 本轮结论

本地自动验证范围通过：单/多文件、整目录上传下载、应用级任务/冲突风险UI、取消/新任务重试、文件URL拖放处理，以及活动传输的window/quit保护已接正式Manager/Engine。主管独立完整回归和专项修复复验通过；无真实SSH/SFTP或macOS26运行证据，不是FILE/性能/Release总体验收通过。

## 主要实现

FilesController持应用级Manager/scheduler，任务不可强引用终端/面板。Local selection用fileSystemRepresentation原字节，逐分量openat/O_NOFOLLOW得directoryFD，包复制持有不URL重开；上传按父root去重复用服务，下载锚定选择目录。失败注册只定向释放本次newIDs，不能全idleclose干扰浏览。TransferRequest host/service/path/batch不可变，换panelhost或关SSH标签不retarget/cancel已排任务。

生产NSOpenPanel单/多file/dir，NSTableView注册fileURL并拒绝文本/HTTP。HostProbe仅替选择结果，经真实按钮target/action；pasteboard实际fileURL/已注册handler验证不等人工Finder拖入。文件/任务路径显示完整localroot+原endpoint，显示转义不重建操作路径。

任务根级UI独立于FilesPanel：队列/streamedbytes（非已提交）、逐项成功/skip/失败、retainedtemp精确路径可见。batch overwrite/skip限同host/batch；renameTo只单项；风险独立确认，不从覆盖推断同意。pendingID+job/generation拒迟到/replay/错类型，cancel/retry复用真实Manager，新job从零、不隐式重连/续传，idleclosed拒绝。

关闭同步freeze且登记enqueueInFlight，在actorawait前拒新入场；等已admitted enqueues/metadata drain后取真实Manager snapshot，不依赖滞后mirror。window/quit共享决定/清理任务，继续保留窗口/取消Quit，不先permanentterminate；批准取消关闭才停任务/等tempcleanup与serviceclose/SSH清理。finalsnapshot与immutablelabel提取残留路径，用户记录后再resetManager/关窗/exit；不持久化恢复、不扫描删未知临时。

## 专项审查 R1

初轮主管99tests/GUI/signed通过后，独立只读审查以源码interleaving确证两P2：

1. beginWindowClose已发生、SSH仍drain时迟到askRisk不核windowClosing，Managerworker不Task.cancel，可能新挂continuation；后续close先awaitoperation，关闭等待环。
2. 历史“已核对”未固定当时展示终态集合，随后await新snapshot可能把新failed/retained报告也删除；freeze前已入场metadata删除可跨关闭修改最终报告。

作者先保留late-risk真实红测100项中旧99通过、新1两断言失败，未手答风险/forceclose冒过。修正入口和continuation安装处双核operationRiskIsCurrent（windowClosing/token/generation/operation/termination等）。历史review固定完整terminal TransferJobSnapshot、managerlifetime，只删除同一已确认集合；新terminal不扩大、changed/active/stale/replay拒。metadataMutations同步登记供close drain；freeze更新epoch并撤销review，continue恢复admission不复活旧授权。

新增4项确定性continuation回归，含reviewA后B真实Localfailed+retained保留完整report/label/file；snapshot边界freeze不删最终报告、不死锁；freeze/resume仍拒旧review。原审查者只读定向复核两项resolved，无实质remaining。

## 主管独立验证

初轮独立 `Scripts/verify-app.sh all` / `signed-security` exit0：99tests，正式Debug/Release arm64/min26，App/helper/FilesC对象、固定图/原生160输出/7noticehash通过，GUI15+8+7+17+17+Local14+Transfer17+Exit16，signed12+8+15+5。

R1后主管读取最终差异、新rawroot/selector/task/lifecycle/retained实现与14项TransferTests；独立运行：

- `Scripts/build-app.sh HostProbe test`：103tests/0失败，exit0。
- `Scripts/verify-app.sh gui`：15+8+7+17+17+14+18+17通过，exit0。实际App进程包含picker注入/真实Local SHA、fileURL handler、hide后决策、window/quit两选项、重复close/Quit单prompt、真实退出managerclosed/drained/SSHtabs0。
- `Scripts/verify-app.sh signed-security`：12+8+15+5通过，exit0；现有Development/runtime/timestampnone、不同identifier同Team helper/App严格验证。

日志 `DerivedData/Verification/primary-p6b1-all.log`、`primary-p6b1-signed.log`、`primary-p6b1-r1-103tests.log`、`primary-p6b1-r1-gui.log`、`primary-p6b1-r1-signed.log`。工程师R1最终all的正式双配置编译/Release另次通过，不重复未变native重建。

真Local4MiB在25%取消，目标inode/SHA不变、temp清理；130次失败注册后仍可入队，无128slot泄漏；queuecancel/retry新ID/代次0bytes、mixed非全部成功与links明确失败有断言。本轮小文件数据不作为App/PERF/远端2GiB性能证明。

## 未覆盖

真实SFTP/MFA/能力probe/网络异常/远端cancel/磁盘满仍未验，macOS26仅编译。人工NSOpenPanel、Finder拖入、IME/像素/远端TUI待人工。残留提示的数据/延后reset顺序和file保留已测，但特定native残留故障提示无专用GUI场景，不宣称已人工核过。真实200连接/五session24h/产品Release安装、DeveloperID、公证/双机企业场景仍必要。
