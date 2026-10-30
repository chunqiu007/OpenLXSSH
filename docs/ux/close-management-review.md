# Close 与安全管理整合：独立审查检查点

日期：2026-10-30。结论：**正式Debug编译、关闭预检及管理本地状态门通过，实际原生关闭/按钮/像素仍未通过**。不提交UX_READY_FOR_USER。

## 实际源码变化与审查

### 全局关闭预检

- AppDelegate红点/CmdQ入口先等待单次准确owner的关闭review，再冻结连接/传输admission；取消在任何resource cleanup之前，统一复位window/quit状态及termination reply。
- 同一真实编辑器复用Save/Discard/Cancel，Save失败保草稿；commit成功readfail只重读或明确关闭已保存表单，不重复保存新授权。
- `WindowCloseReviewRequest/Registry`与`PresentationOwner`校验owner/epoch，旧回答不能放行新表单；已有closeFlow/lifecycle.closeTask/传输确认/retained temp唯一收尾保持。
- writing拒关写`host.closeWriting`近旁提示，结束review不清；unknown系统panel及host内key子表单保守拒绝，不强拆。
- 主机编辑器创建时捕获父content高度，限定500pt宽、父高度−60且420～680范围；正文ScrollView消费剩余、底部动作在滚动区外。该合理高度依据隔离真实500×119→500×660 A/B，不是提高主窗最小尺寸；本次正式构建的三尺寸GUI仍待。

主管读9文件相对before增量与layout patch，核预检在freeze前、无credential读/cleanup副作用、continuation一次回答/销毁解析、选择路由及失败恢复。尚未独立原生证明NSApp reply、焦点或红点/CmdQ。

### 已知主机与密钥标签

- 已知主机页消费现HostTrustStore：搜索端点/算法/完整指纹，复制公开元数据、来源如实为App专属库，精确record review后remove，保留独立核实replacement。
- remove冻结完整host+algorithm+blob与owner epoch，Store仍原子比较；读失败保上次记录，与空库/筛选空区分，close/reopen不永久失效。
- 创建editor记住准确committed key outcome，label失败只retry同UUID，不再生成；完成同步准确选中key/实际label，selection/draft epoch拒A→B→A及输入后的旧回调。
- 独立NSPasteboard用于本地复制回归，不读取用户剪贴板；真实general pasteboard/VoiceOver/窄布局另验。

## 真实失败与修复

正式build首轮65为测试helper不接受message位置参数，次轮65为主机editor新MainActor dismiss签名与旧caller转换不兼容；各自最小修正，原失败保留，第三轮build0。无警告/并发豁免。

TrustManagement首轮14项中1test的3断言失败（`testCommittedRemovalAfterReopenRereadsRatherThanRestoringOldSnapshot`）：真实Store remove已提交，但后台刷新是未跟踪Task，显式await load因loading guard直接返回，重试也可被吞。R2改为owner/token绑定共享loadTask，显式load加入同一真实读，commit前快照拒收；owner失效释放旧loading。原三断言及真实Store/读结束断言保留，未加sleep/延时。

## 已执行验证

工程师cwd工作区根，正式OpenLXSSH scheme/Debug/arm64/min26、固定pins/signingNo：

| 验证 | 实际结果 |
| --- | --- |
| Scripts/build-app.sh Debug build-for-testing | 第三轮exit0，25.657s；前两65保留 |
| Close新增10 editor+6 state+2准确session消费者 | 18/0，exit0 |
| Reliability两suite | 13/0，exit0 |
| SessionController/Concurrency | 31/0，exit0 |
| 管理原失败exact重验 | 1/0，exit0 |
| TrustManagement | R2 14/0，exit0；原14/3断言失败保持 |
| KeyLabelCompletion | 7/0，exit0 |
| SecurityIntegration | 19/0，exit0 |

主日志：`DerivedData/UXVerification/DesktopClose-R1/Engineer/`与`KeyTrustManagement-R2/Engineer/`；完整argv/cwd/exit/xcresult及最终源码hash各自保留。

主管独立执行实际同正式min26 Debug关键门：

- `DerivedData/UXVerification/ManagementClose-Primary/targeted-tests-1.{log,json,xcresult}`：Close18（10+6+2）、Trust14、KeyLabel7，共 **39 tests / 0 failures / exit0**。不是简单复用工程师自报。
- `git diff --check`通过；最终管理四文件与冻结清单一致。Native候选20项主管另独立通过，只候选包边界不代上述原生。

## 未覆盖与后续

原生新按钮发现仍仅三字段唯一性通过，Save按钮语义未发现；Probe R1～5失败/诊断桥接exit-5未改绿，R6按同ownedwindow真实激活单变量对照继续，不再无收益扩遍历。原生Save/Discard/Cancel、红点/CmdQ/NSApp reply、实际CmdV两种模式、三尺寸/全屏/截图/VoiceOver仍待。

重复公钥导入后端、独立生成后引用主机、设置分类/偏好/帮助、标签overflow等剩余见`resumption-remainder-audit.md`。未将本地门当全部116通过。

无生产/真实用户凭据、健康fixture重建、新环境、真实Keychain、Apple上传/时间戳/最终发行包或长测。
