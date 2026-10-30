# U1 工作区交互修复：主管独立验收

日期：2026-10-30。结论：**U1本轮六项修复门通过，可进入U2；完整UX_READY_FOR_USER仍未达到。** 本地分支`ux/termius-desktop`，旧152489c之后的工作区增量，未改协议库/依赖pins/隔离服务器。

## 六项审查问题与实际处理

| 问题 | 实现与验收证据 | 边界 |
| --- | --- | --- |
| SFTP仍全行比较host，metadata刷新误取消 | HostConfiguration id+connectionIdentity贯穿FilesRequest、FilesController当前请求/信任、LibSSH2FilesConnector前后授权、SecurityCoordinator私钥读取前后；新metadata/撤销/删除/不同UUID/私钥跨await测试 | 不把仅同hostID当授权，不放宽key/credential purpose/ref/save授权；未新连真实SFTP |
| 隐藏原生页面焦点隔离不足 | NativeWorkspacePage稳定NSHostingView，isHidden/AX隐藏/hitTest与field-editor离焦；真实NSWindow/NSTextField切页XCTest和workspace smoke | 不是仅opacity；未冒充人工IME和VoiceOver全体验 |
| Cmd+F有菜单无消费者及modal后台动作 | Vault聚焦本地主机搜索；SSH紧凑搜索/前后/无匹配/Escape返回terminal焦点；SFTP暂禁用，待U4有真实过滤再启用。菜单validation和动作端均校验attached/modal/other key window；普通编辑仍走原生responder chain | 当前SFTP过滤未实现，明确禁用而非假接线；完整设置/菜单在后续收口 |
| A-B-A丢search/found/dialog | 每SessionTab持有非秘密搜索状态；每tab原生页面稳定保留；旧dialog撤下后新空编辑器，token/request更换拒绝旧回答 | 切页保留transport pending请求但不保留明文回答，不自动再提交；三按钮首次信任尚未实现 |
| 查看任务反而收起 | 所有跨页入口共享showTransferTasks明确tasksVisible=true；SFTP页内才toggle；job/service/manager保持 | U4新队列视觉/总量速度/双栏尚未实现 |
| 旧SFTP隐藏按钮无效 | 改“返回保险箱”，可见页真实切换，不取消连接/任务、不删除固定标签；最后SSH关闭回Vault并同步workspaceVisible=false | 固定SFTP页只是路由，当前仍旧远程浏览，绝不称双栏完成 |

## 主管发现并补修的交叉回归

- 连接参数A→B后若用户真实Core回退A，FilesController清pendingHostUpdate及仅files.hostChanged，保留无关错误。
- 切回SFTP不能把连接旧snapshot A当Core回退清掉pending B。AppModel统一以完整catalog按ID解析最新row，reload隐藏状态也同步，保留原visible；真实Core回退才清告警。
- 新增A→B反复切页仍告警/明确断开后连B、真实回退、隐藏期间变更、row删除不复活旧snapshot四项实际回归。
- FilesPanelView仅连接identity变化清初始输入/selection/dialog，纯名称/最近时间刷新不丢未提交输入。

## 审查与实际验证

主管已检查实际diff、NativeControls/NativeSheet/NativeWorkspacePage、SessionController的搜索与dialog代次、菜单context/close、FilesController/FilesConnection/SecurityCoordinator授权链、AppModel最新catalog路由、真实新增断言和项目登记。project仅把NativeControls加入unhosted test source，无@main混入、依赖无变更。

工程师最终执行（完整原始日志在`DerivedData/UXVerification/U1-R5/`）：

- `Scripts/build-app.sh Debug build`：0，`debug-build-4.log`。
- `Scripts/build-app.sh Debug test`：0，**175 tests/0 failures**，`debug-tests-4.log`。
- `Scripts/build-app.sh HostProbe build`：0，`hostprobe-build-4.log`。
- 新`workspace` NativeSmoke：App/外层0，**34/34 checks**，8.066秒，`workspace-run-4.json`、`workspace-report-4.json`。

主管另独立执行：

- 正式min26 Debug `xcodebuild test`，仅OpenLXSSHAppTests/SessionControllerTests/FilesAuthenticationTests/FilesControllerTests：**69 tests/0 failures/exit0**。原始命令/输出 `DerivedData/UXVerification/U1-Primary/targeted-tests.log`，四组分别21/17/14/17项。
- 对最终HostProbe（二次独立marked temp root、120秒外层时限）实际运行同workspace phase：App/外层0，**34/34 checks**，8.090秒。`workspace-final-review.json`、`workspace-final-report.json`、`workspace-smoke-final.log`。主binary SHA256 `90f38947e377556232a5e63aae06251e98502e5f8d89b5889d9685c52e45123b`。
- `git diff --check`：0。

34checks覆盖实际NSMenu key equivalents/target-action、NativeField field editor、隐藏native hitTest、A/B搜索和原terminal父容器/view/driver/token不重建、SFTP未提交输入metadata保持、查看任务显式展开、sheet期间后台命令双重拒绝、CmdT chooser/CmdW context、旧认证回答不复活和最后tab回Vault。网络是明确逻辑driver/local-file替身，不是系统SSH/真实SFTP证明。

最终原生截图真实落在独立临时测试root：`/private/var/folders/qh/g2p3kxks0s75gc6kz08kvtn00000gn/T/OpenLXSSH-AppTests-fd0q3ubw/workspace-r5.png`。只含合成主机。**当前模型没看见像素，不能将截图存在当视觉通过。**

## 失败历史保留

- R2/R3/R4上游流错误；没有把中断任务当成功。
- R4测试漏函数声明、async XCTest autoclosure、随机未登记folder外键等测试夹具错误已修，不删旧断言；最终157/0为当时分项。最终路径被末次log覆盖的事实已在R4报告如实说明，xcresult/命令输出不追改。
- R5首次Debug test因R6的SecretBytes.isEmpty不存在而65，日志`debug-tests-1.log`；R6改为withUnsafeBytes后复验。
- workspace初轮keyWindow缺失焦点→mainWindow回退修复；第二轮App0但外层汇总误取省略的failureCode致KeyError。原smoke/run与错误保留，最终34checks App/外层均0，不以App0遮盖首harness失败。

## 不在本轮通过范围

完整视觉tokens/窄窗三尺寸/全屏/长表单、完整tab溢出/实际拖排/中键、布局偏好持久；真实两类MFA及本次密码、一次/持久信任；完整深色终端/ANSI实体键鼠/IME/TUI新版；Vault主机card/组tag/多选/编辑/密钥管理；双栏SFTP/全部文件操作/队列；设置帮助/全状态/可访问性仍按116条矩阵后续实施和适当验证。

本轮没有生产连接、读取真实凭据、推送、Apple公证/时间戳或最终发行包，也没重启24h/大文件campaign。旧build3和原证据保留。进入U2是工程推进，不是用户体验满意或完整V1完成。
