# U1 SFTP连接身份链：R4主管审查

日期：2026-10-30。范围为本地代码与逻辑回归，**不等U1全部通过或真实SFTP新版GUI验收**。

## 结果与范围

保留旧会话/文件连接实际快照，主机授权比较改为稳定主机ID与连接参数，排除名称、分组、收藏和最近连接时间等展示元数据。R2/R3/R4执行者先后遇到上游流错误，未返回完整验证；主管按当前实物审查并继续验证，而非将代理任务结束当验收。

- `AppModel.swift`：`HostConnectionIdentity`包括地址、端口、用户名、认证方法、密钥/凭据引用、保存授权和保活；`matchesConnection(of:)`另检查主机ID。`reload`将同ID最新row传至文件控制器更新显示，不把Vault选中另一host当SFTP换目标。
- `FilesConnection.swift`：`FilesRequest`仍要求同request UUID、generation、hostID与连接identity；准备前、保存秘密读取后和pre-TCP检查继续约束相同request及精确key/credential授权。
- `FilesController.swift`：同连接identity刷新只替换展示row，不重建service、manager或job；`isCurrent`和信任回调不再比较整条展示row。真正连接参数变化保留原服务及明确手动重新连接路径，不自动断开/认证。
- `SecurityCoordinator.swift`：私钥材料读取前后主机检查同样使用hostID+identity；密钥类型、文件/权限、取消和after精确key引用检查仍保留。

## 新增与已有回归证据

新增两项测试：

1. `testMetadataOnlyHostRefreshKeepsRequestAndPreparedPasswordAuthorized`：保存密码仅用内存fake credential，更新名称/真实已插入的分组/收藏/最近时间后，request身份不变，prepared plan复核通过，读取次数仍为1。
2. `testPreparedPlanRejectsTrueIdentityChangeDeletionAndDifferentRowID`：真实端口改变、host删除、同参数但不同UUID的row替换均拒绝旧plan。

既有取消/代次/保存授权撤销、口令引用变更、最终metadata await撤销等回归均保留。本次未新增专门的“私钥读取前后仅元数据变化”与“ready service/job身份不变”实证，不能把全部路径由上述两项推定通过，后续应补定向覆盖。

## 主管实际执行

工作目录：`/Users/liuwenshuo/Desktop/OpenLXSSH`。

- `git diff --check`：0。
- `Scripts/build-app.sh Debug build`：0；日志 `DerivedData/UXVerification/U1-R4/debug-build.log`。
- `Scripts/build-app.sh Debug test`：首次65（新增test await在XCTest autoclosure内）；修正先await局部值后第二次65（测试folderID未登记，真实SQLite外键失败）；将合成folder先保存后最终0。
- 最终日志 `DerivedData/UXVerification/U1-R4/debug-tests.log`：**157 tests，0 failures，TEST SUCCEEDED**；结果包 `DerivedData/Debug/Logs/Test/Test-OpenLXSSH-2026.10.30_10-56-14-+0800.xcresult`。

执行者中断留下的测试插入错误（漏原有取消测试函数声明）已由主管仅恢复原声明，未删除断言。失败过程见后台命令输出与相应xcresult；最终log路径仅代表末次运行，不将首两次失败追认为通过。

## 未覆盖与剩余审查

- 没有新SSH/SFTP连接、relay、服务器变更、真实Keychain读写、签名、Apple上传或出包。
- 没有完整SFTP双栏、真实传输/拖放/像素/IME验收。
- U1其他六项中的Cmd+F、隐藏原生焦点、每标签搜索与弹窗状态、跨页任务入口、旧隐藏按钮等交给U1-UI-INTERACTION-R5，尚未验收。
- `FilesController.pendingHostUpdate`遇到用户将连接参数改回原值时，应定向检查是否清除陈旧pending配置；当前无该边界的新增回归，不能声称所有配置编辑序列均已通过。

因此R4为**核心实现及所列逻辑回归通过，完整U1门仍开**，不标父DX条目全部VERIFIED。
