# 正常 Debug 工程预览：身份与未验边界

## Codex 本次实测：R2 隔离离线预览（2026-11-01）

R2 已独立构建、离线 Development 签名并实际运行。它仅用于观察产品页面和本地草稿，不具备网络连接能力；**未达到 UX_READY_FOR_USER，也不替代下文R1或完整SSH/SFTP候选。**

- 副本：`DerivedData/UXPreview/Engineering-R2/OpenLXSSH.app`；身份单同目录`identity.json`，独立bundleID `org.openlxssh.OpenLXSSH.EngineeringPreview`，arm64/minOS26、Hardened Runtime、timestamp=none、strict/deep验证通过，无Apple请求，旧安装和R1未覆盖。
- main SHA256：`54f6c9fa68a6fb6749052627f42ce029bbfb64626c0414b6c8e1374b3483616c`。源码记录包含827个项目公开文件的逐文件摘要，不能只用Git HEAD代表未提交整合输入；此清单不是全部vendor输入证明。
- 首次构建成功，隔离测试16项/8断言失败。实际根因是Core/Foundation的`/var`与Darwin物理`/private/var`别名在数据库记录门被字面误拒，以及测试ACL文本构造在当前Darwin返回nil。两文件窄修后原断言全保留、新增跨根/文件名拒绝；工程师17/0，主管独立同产物17/0、exit0。原失败xcresult不改写。
- 无参、旧fixture、缺参数、错合同四项预NSApp拒64。合法合同首案因主管新建的Engineering-R2/Inputs目录为0755而拒64；保留准备失败记录，只将本轮新建两目录改0700，之后PID63234正常运行并经CmdQ自然exit0。
- 当前Codex能观察原生AX与真实像素。实际完成：空主机页→虚构主机输入→70000端口错误/保存禁用→改22→草稿关闭取消保留→关闭保护保存返回列表→单击只看详情；切换密钥空页、SFTP双栏本地空目录/远端离线、Cmd+,打开统一设置与取消返回。
- 真实JPEG：`DerivedData/CodexTakeover/20261101/screenshots/r2-host-details.jpg`、`r2-keys-empty.jpg`、`r2-sftp-offline.jpg`、`r2-settings-general.jpg`。截图只含虚构条目和本轮临时路径；它们不能证明真实终端、MFA、远端SFTP、规定三尺寸或全屏。
- 本次观察出的待修细节包括空详情标题偏低、主机编辑/隔离说明冗长。未完成的真实输入法、Finder、粘贴、窗口关闭矩阵和资源门仍保留；不会把旧客户端图像失败继续当本次工具限制。

证据根：`DerivedData/CodexTakeover/20261101/`；包含`r2-test-command.json`与原失败、`r2-fixed-test-command.json`、`r2-primary-test-command.json`、修复前源码/精确patch、两次启动记录和运行日志。下文R1与旧GUI调查保留其历史范围。

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

### R17：窗口恢复尝试与数据零写边界

后续官方CUA重新枚举窗口，已有磁盘窗口8476也报告CG-only；按工具给出的可用语义菜单新建访达窗口后，新窗口8492仍仅52个菜单元素、无非菜单可操作控件，返回`cg-only-no-ax-window`。本次截图返回不对当前模型可见，没有发送坐标、键入预览路径、启动App、切换登录或修改系统权限。旧路径对话框8472仍只有WindowServer条目，不能确认此前Escape已关闭它。重复相同窗口读取不会改变此条件，因此停止无变化重试。

同时已独立只读核查**正常启动并非只读**：App入口固定`AppRepository()`和`UserDefaults.standard`，加载主界面会确保目录权限、以read-write/WAL打开SQLite并检查/可能执行迁移；管理页恢复和frame autosave也可能回写。当前用户固定预期路径`~/Library/Application Support/OpenLXSSH/Data/OpenLXSSH.sqlite`及其WAL/SHM经仅元数据检查均已存在；未读取数据库内容、Keys/恢复记录或Keychain。这个路径是源码规则与现有文件的证据，**不是未启动进程已经实际解析该目录的运行时证明**。

当前正常binary没有只读/禁迁移/任意数据根CLI，测试`.isolated`入口只存在于HostProbe，不能用于证明Engineering-R1正常启动；也没有把HOME或Keychain namespace替换当隔离保证。恢复keys/trust子页还可能初始化相应存储，所以“不开连接”不保证不接触它们。为遵守本次避免修改用户数据的要求，未启动新副本。主再次核main/helper字节与identity相同、无该精确预览进程。证据`NormalUXPreview-R1/Primary/observation-r17.json`。

继续精确副本的正常界面验收，需要先有可读的原生窗口内容，并明确允许正常初始化的本地写入或提供经验证的数据隔离启动方案；现有Engineering-R1无法同时满足无参数主界面与用户数据零写。新增只读/隔离正常入口将改变代码/候选来源，必须独立实现、验证、重建并如实区分，不用测试探针冒本副本通过。

## 不可宣称的完成度

Native App weak/FD资源失败、并发MFA A服务端challenge present、普通入口差异均保留。实体CmdV/IME/Finder/中键、规定1000×650/1280×800/1440×900与全屏、新版像素仍未验。详见 `acceptance-coverage.md`、`verification-plan.md`、`local-candidate-walkthrough.md`。

当前只交付**可复核的构建/签名工程实物及证据**，不是已验收可体验候选，不标UX_READY_FOR_USER。完整验收仍需要可用的原生前台/像素观察与相应实体输入条件；fixture取消卫生若改造，还需单独批准镜像/容器来源变更，不能热改健康服务或清除失败记录。
