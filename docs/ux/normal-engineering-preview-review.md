# 正常 Debug 工程预览：身份与未验边界

结论：**正常Debug工程预览已构建并离线签名；不是HostProbe，尚未完成正常启动/GUI检查，未UX_READY_FOR_USER。** 2026-11-01。

## 精确副本

`DerivedData/UXPreview/Engineering-R1/OpenLXSSH.app`

身份单：同目录 `identity.json`。本副本没有覆盖 `~/Applications` 中旧版、构建原件或任何旧候选；不是新最终发行包，无ZIP/DMG/Apple公证或时间戳请求。

- signed main SHA256：`69e8bab8a8ec4f75aa24d231e89503724bd6e5ed3a4eb79c8966ccafa7c4b3e3`。
- signed helper SHA256：`2746da3bb1d5cab4249fdfaef59f243a18cb5c013d50ed762f4df327f4e3a89d`。
- unsigned正常Debug源：`DerivedData/Debug-NormalUXPreviewR1/Build/Products/Debug/OpenLXSSH.app`。
- unsigned main：`d3c7d2f4f141aeb8639dbf0d2571a78c562a115ac6992f68578d688b73ba24cb`；新构建helper：`2cc6899a9b60322427916b4c0a1954bf2dbaf246a873c2981619851fd373d931`。
- 2728项source/native/vendor输入聚合SHA256：`c2a168a18d9b9b13f057dc4cd52c22dd1b729773ebb644fbbcd14cb724dbf2cb`。不能只用当前Git HEAD代表这些未提交整合源码。

主/helper均采用既有批准Development身份，固定identifier `org.openlxssh.OpenLXSSH` / `org.openlxssh.askpass`、同Team、Runtime、空entitlement、timestamp=none。主管逐个strict/deep/anchor+identifier核验；未请求Apple或读取签名私钥。最终独立R16只读核对身份单/来源/公开证据为NOFINDINGS；该审查不补作正常启动或像素验收。

## 正常启动的数据边界

**不要把本副本当空白隔离测试环境。** 无参数启动使用当前用户已有Application Support/OpenLXSSH与非秘密偏好，不具备HostProbe固定fixture合同或自动退出。没有自动连接/会话恢复功能，但用户数据可能在正常仓储初始化时被读取或迁移；本轮未执行无参数入口，没有以GUI测试为由清空或复制用户数据。

普通**新建**连接仍默认Direct，显式本次密码prepared handoff用internal Native候选；reuse可能选择已有Native标签，手动重连保持原driver/builder。当前策略四项模型消费者主独立4/0，**不等入口已统一**，见 `entry-routing-contract-review.md` 和入口ADR。

## 构建、来源与静态检查

证据根：`DerivedData/UXVerification/NormalUXPreview-R1/`。

- 正常OpenLXSSH scheme/Debug，`DEBUG`且无HOST_PROBE/TRANSPORT_HOST_PROBE；fixture runtime类未进入正常binary，契约parser仍保留early refusal。
- 正常App build52.54秒、新helper build8.55秒均exit0。App实际Swift6/complete/warnings-as-errors/testability；依赖遵从既有manifest（部分Swift5/警告策略），不是全包强压Swift6。
- 9件实际Mach-O arm64/min26，含App/NativeSessionDriver/NativeShellSession/C Bridge/NativeTerminalView/DirectSession/helper。主管另独立核全部9件摘要及实际minOS。
- 正常版本9族fixture参数共66项均exit64，stdout空/静态refused，拒绝发生于NSApplication.shared与存储/网络bootstrap之前。签后副本每族help另9项再次拒绝，未启动runtime。
- 12个帮助许可资源、15个notice副本、7份原native notices、GRDB privacy资源齐全。原归档仍arm64/min15且摘要未动；本轮指定App/bridge/Swift/helper对象为实际min26，不偷换口径。
- 两次自加构建sandbox wrapper在编译前exit74，定位嵌套sandbox_apply EPERM后返回既有普通离线配方；原失败保留，没有改系统保护/权限/全局配置。
- 未重跑完整测试；产品源与最近已验的Host111/Debug86、入口新4+旧42一致。没有把同源build当正常GUI通过。

## 本轮官方GUI观察

主Agent使用官方Computer Use只读listApps，仍全部active=false，不据此推断锁屏、登录或权限根因。为避免按bundle误启旧安装版，尝试通过访达语义菜单精确打开新副本路径：菜单动作后出现“前往文件夹”窗口，但工具返回 `empty_capture_reason=cg-only-no-ax-window`，没有可访问输入框/按钮，不能安全填路径。没有猜坐标或改用shell/AppleScript替代。

曾向该自有操作窗口发送一次Escape取消，工具接受但状态仍报告同CG-only窗口，**取消结果未获确认**。没有重复输入、键入路径、打开新预览或启动网络。此残留对话框状态需后续可用原生上下文确认，不能把accepted动作当已经关闭。

没有新版正常候选的实际截图/像素验收；此前U3图是各自原探针范围，不补作本版Vault/编辑器/双栏/设置完整截图。

## 不可宣称的完成度

Native App weak/FD资源失败、并发MFA A服务端challenge present、普通入口差异均保留。实体CmdV/IME/Finder/中键、规定1000×650/1280×800/1440×900与全屏、新版像素仍未验。详见 `acceptance-coverage.md`、`verification-plan.md`、`local-candidate-walkthrough.md`。

当前只交付**可复核的构建/签名工程实物及证据**，不是已验收可体验候选，不标UX_READY_FOR_USER。完整验收仍需要可用的原生前台/像素观察与相应实体输入条件；fixture取消卫生若改造，还需单独批准镜像/容器来源变更，不能热改健康服务或清除失败记录。
