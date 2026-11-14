# 2026-11-03 两项修复 Trial 交付检查点

DMG 已生成并从挂载卷复制安装副本实际启动、正常退出。本次是本轮限定范围的本地试用候选交付；真实Goal已在第3轮同一外部条件审计后标记BLOCKED，未标完成，以下人工项及历史未完成项保留。

- 路径：`/Users/liuwenshuo/Downloads/OpenLXSSH-Trial-1.0.0-2026110301-arm64.dmg`
- 版本：1.0.0（2026110301），17,381,354 bytes，arm64 / macOS 26+。
- SHA256：`c05bc8037b7264dba73ad68932b95d051bbb7de41a5f3a689cf774072a957fbe`
- Developer ID Application / Team 74Q9ARM7JJ 离线签名，runtime、空 entitlements、无 Apple 时间戳，未经公证，未评为 Gatekeeper accepted。
- 沿用上一版 Trial 的1b911506-9969-4824-80f0-d017b1d0d1de身份和application-support-v1路径；无正式版迁移、无配置/数据库/测试密钥/凭据/日志打入。

## 实际原因与改动

原窗口为系统标题区与内容标签栏两层。现在用fullSizeContentView、隐藏可见大标题、透明标题区域与单一48点标签栏，保留真正standardWindowButton，按实际按钮几何留gutter并同步页面主题。实鼠检查发现新空top accessory仍由原生clip拦截标签/加号；窗口根hitTest的隐藏/移除对照确认后，已移除空层。实际Vault/SFTP/会话中心点击、加号、拖排、中键、X关闭和窄窗口溢出访问均已操作。

未知主机本身并不会映射为networkUnavailable；网络连接在SSH握手和信任之前。旧Trial在批准loopback服务上原本也能首次信任并同次进入shell。旧包缺本地网络用途说明，POSIX路径也没有等待首次系统授权；本轮加入同目标、无应用数据UDP readiness前置。仅明确localNetworkDenied进入有限120秒等待，普通pending最多3秒后回原DNS/TCP判错；取消不启动后续连接。真实信任及凭据/连接代次归属实现保持。**用户原NAS那次失败的精确原因未复现，不能断言缺权限就是根因。**

## 实际验证

- 包层24/24通过：真实回环TCP/握手超时/取消、原DNS边界、SharedHostTrust once/endpoint/代次/changed及本地网络事件等待。
- App定向33个命名通过证据：原83中30个未受影响用例与最终Chrome2+root1组合；原31/32失败和后续诊断失败完整保留。最新4960输入SHA `93d44ccd5f537def39aa819ee637bc9e37bfefc9616d759780881fc672e86b10`，打包及主复核时未变化。
- 原新测试把native accessory自身高度当48是不受SDK支持的结构假设。保留失败；更正为实际48内容条顶部贴合、真按钮身份/父级/完整可见裁剪/中心/gutter/命中归属，并保持3秒等待预算。未用删产品标准或放宽预算变绿。
- 最终候选三页×1000×650、1280×800、1440×900，共9张实拍。全屏进入1920×1080、退出恢复1440×900，切页与失焦/重新激活已操作；完整未共享悬停视觉仍列人工项。
- 密码首点未知主机→添加信任→同attempt真实shell，无手动重连、无重复密码；新attempt不再问。密钥once→真实shell，新attempt仍问；取消无迟到认证，取消后owned网络为空。仅修改自有public pin验证changed明确拦截，随后原字节恢复。22225无listener真实connect/61保networkUnavailable，无伪造信任。SFTP首点信任、取消、once后实际/fixture/home列表通过且未重复索口令。
- 最终源码候选再次首点key unknown→once→单次口令→同attempt shell，marker `UX88_FINAL_SHELL_OK`。
- App/helper严格签名与代码段等价、DMG签名/完整性/只读挂载树/Applications链接、复制安装副本校验均过，全部本轮挂载已卸载。主启动精确安装副本见0主机/0会话，旧Trial身份复用，未连接任何主机；正常退出，主程序SHA `70076a166aeabf95d51931cb1b2ae3184e9142db86f897fc51b6424b3b59ce46`。

## 2026-11-03 交付后独立收口审查

34项本轮要求逐项映射为29 PASS / 4 PARTIAL / 1 UNVERIFIED。此计数不是完成率；没有把未确认项改绿。主直接比较实际GUI候选与最终安装副本：主程序37个、helper25个file-backed段全部相同，只存在允许的签名元数据差异；启动后的23文件树仍与镜像安装树一致。证据`scoped-ux/closure90/gui-to-dmg-binary-equivalence.json`。

补做了隔离空白候选的真实Tab、反向Tab、OptionTab；当前键盘设置下只观察到搜索栏焦点，尚未获得顶部标签焦点环实拍。全局AppleKeyboardUIMode读取为0，未修改设置、未重建或更换DMG。已集中请求一次“临时开启键盘导航并恢复”的明确授权，尚无回答；没有把等待视为同意。该次隔离候选已退出，新建的5个自有数据文件按portable marker严格核验后清理。

## 待用户复核

1. 另一台Mac首次局域网访问的系统授权、首次信任及真实NAS现象。如仍失败，请只反馈脱敏operation/code和有无系统权限框。
2. 物理鼠标拖动顶部空白区：自动化在新版及未改原生白标题栏对照中均未移动窗口，不能冒称拖窗已实测通过。
3. 未共享屏幕时全屏悬停：初始终端全屏为连续顶部；后续捕获有系统紫色共享控件与32点覆盖层。Finder对照也出现系统共享/标题层覆盖，但未完全确认未捕获表现，保留原图，不豁免未知。
4. 顶部键盘焦点环：需在键盘导航能到达按钮的环境实测，或获得临时更改全局键盘导航并恢复的明确授权。当前设置下尚未观测，不能从FocusState源码直接判runtime通过。

## 证据与清理

原始证据在`DerivedData/CodexTakeover/20261103/scoped-ux/`：最终窗口/真实连接`gui/final-review.json`、`gui/live-network-review.json`；最新构建`pointer88-final-retest/result.json`；交付`package85/primary-delivery-review.json`。

本轮有限relay正常exit0，accepted10/finished10/rejected0/cleanup_failed0，22221–22225无监听残留。全部本轮App退出，b441自有测试数据（含导入的加密fixture副本）已精确清理；原fixture材料未删，用户R16 PID20638仍在，旧DMG/分支/未提交整合代码/历史失败保持，无push、无新Apple操作。

## 实际截图（1280×800）

![保险箱](/Users/liuwenshuo/Desktop/OpenLXSSH/DerivedData/CodexTakeover/20261103/scoped-ux/gui/final/vault-1280x800.jpeg)

![SFTP](/Users/liuwenshuo/Desktop/OpenLXSSH/DerivedData/CodexTakeover/20261103/scoped-ux/gui/final/sftp-1280x800.jpeg)

![终端](/Users/liuwenshuo/Desktop/OpenLXSSH/DerivedData/CodexTakeover/20261103/scoped-ux/gui/final/terminal-1280x800.jpeg)
