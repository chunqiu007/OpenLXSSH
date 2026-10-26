# 原生 App 真实 SSH 与按需 SFTP 首案

日期2026-10-27，Task APP-REAL-KEYONLY-PREP-A / LIVE-A。**宿主15 HostProbe原生真实接线在显式测试scan15下通过；默认scan5失败单独保留，正式macOS26/默认环境及完整传输生命周期未因此通过。**

## 接线与独立审查

六文件已独立审查并本地提交 `0da987b`：AppRealIntegrationContract.swift、AppRealIntegration.swift、OpenLXSSHApp.swift小分支、pbx membership、新契约测试及独立离线构建脚本。生产Packages、NativeSmoke逻辑替身、安全/密码gate、依赖和正式min26不改。

入口在AppKit/真实store初始化前解析：正式Debug/Release拒绝所有real-fixture旗标；HostProbe默认/help/validate无文件或网络I/O。只有双授权门＋精确固定keyonly/newgeneration/公开provenance/带外hostkey契约可进入真实路径。canonical系统temp新UUID/marker/noACL隔离store，使用正式SecurityCoordinator导入无口令私钥副本，不改fixture原件；拒绝所有CredentialAccess的测试对象只作“意外触Keychain即失败”的计数门，不提供认证秘密或服务替身。

真实 `DirectSessionBuilder/DirectSessionDriver/DirectSSHSession` 与真实系统scanner，Files观察forwarder原样调用 `LibSSH2FilesConnector` 和真实 `LibSSH2FileService`，没有ProbeSessionBuilder/LocalFilesProbeConnector替代网络。只读浏览 `/fixture/home`，不远端mkdir或文件传输。

独立构建：`DerivedData/AppRealIntegration/offline-817a8c1d-f46e-47ef-9416-d93b99878e51/`。

- 主App SHA256 `171c2bd4a86f195f9cf9efa114be2bfe9a73ca0165108bfc35341801e17edd13`。
- helperSHA256 `58e97c86c3023a6597436c2a4b702e03ed92521f30c1725b749e72779f42bb8e`。
- 既有Development同Team、不同固定ID、Runtime/空entitlements、strict通过。
- HostProbe min15、正式Debug/Release arm64/min26。原105＋新8＝113测试通过，20命令/49输入hash/160native输出通过，不请求resolve/download。
- 主管完整读六文件/差异，独立重跑113tests、核sourcehash/20cmd/minOS/native/sign及help/validate/noauth0/0/64，证据 `DerivedData/Verification/primary-app-real-static-af4e27c2-3efc-4fd4-b4f0-48d579230f12/`。

## 前置与外层检查失败

fixed原CID/image/project/internal/resource及公开带外key、构建后新generation已核。外层setup首次因不存在Darwin `filesec_get_fd` 符号在任何Docker/collect/App启动前失败；不是App认证失败。未使用猜测struct布局或跳过ACL，改为隔离C checker精确复用已审PrivateInput.c的ri_open_private接口，只检查公开路径/noACL/MODE populated/权限。原setup异常、checker源码/命令/hash保留，不改已签名App。

全部实测和外层metadata：

`DerivedData/AppRealIntegration/live-9dadb889-734f-4510-98f5-44d2cacc1187/`

## 默认scan5：真实失败保留

Case/run `2027c5a6-8bc9-43d8-8152-41531e71778c`。

- 无scan override，真实systemscanner5/connect10。
- App PID15376 exit1/5.779s，typed `session.trustScanFailed`。
- 已成功正式key导入、验证公钥/原件未变和保存无密码主机；扫描未获候选，未开始SSH认证，无owned SSH PID、SFTP尝试0、CredentialAccess调用0。
- relay15303 TERM/waitexit0，accepted3/finished3/rejected3/cleanup_failed0，端口无listener。扫描连接数不当认证次数或凭据拒绝。
- 本案own marked store/key当时保留并精确记录，原报告localStoreRemoved=false不改。后续独立本机恢复预检原root dev/inode、marker、固定文件布局/noACL/owner/mode/单链接后清理10个已知文件；辅助恢复脚本曾将目录自身删除导致的nlink变化误作身份变化而停，失败记录保留。按原inode/UID/type/mode/noACL与空目录复核后，仅续rmdir五个已知空目录及root，最终canonical路径不存在。没有读私钥内容/摘要、没有触fixture原generation或raw报告；恢复不是原默认案通过。独立记录 `scan5-local-recovery-final.json` 位于本轮live证据目录。

这与有限测试relay每连接新鲜Docker检查/exec延迟一致，但不将其视为“已证明正式默认在目标真实网络可用”。没有把产品默认预算改大。

原result：`DerivedData/AppRealIntegration/Inputs/run-2027c5a6-8bc9-43d8-8152-41531e71778c/app-result.json`。

## 显式测试scan15：真实原生链通过

根据事先限定分支，只有默认扫描明确失败且确认旧资源退出后，才用新runUUID `63d3549e-ee49-4acb-90f6-b2112328faaa`、新隔离store执行一次 `--real-fixture-scan-seconds 15`。仍是真实SystemHostKeyScanner，connect10不变、source/driver不变。

App PID15733 exit0/21.821s，16个实际检查通过：

- 原生双击主机，实际DirectSessionDriver、完整端点/算法/带外SHA精确比对后，点击真实信任verified/accept控件。
- 可信outer-auth事件与实际owned SSH PID15755，非PID产生/终端提示推断，仍不声称shellReady。
- SSH建立后文件面板仍隐藏、SFTP尝试0；点击打开文件面板/连接才建立生产SFTP。
- 实际productionServices1、list2、浏览fixedhome，非LocalFileService。原始名字只作非秘密base64 metadata，不保存终端输出。
- 原生关闭标签，同一SSH session closed且PID nil；无传输时关闭主窗口await文件服务close1。
- 重开窗口无SSH/文件连接恢复、无再次认证；总SFTP attempts1。
- CredentialAccess禁止调用计数0，测试host/key经正式接口删除，storeRemoved=true。

外层：自有relay15669 TERM/waitexit0，accepted5/finished5/rejected0/cleanup_failed0；App15733/SSH15755/relay15669实际PID均不存在，无所属directchildren，lsof无listener。新UUID canonicalstore路径实际不存在，不只信布尔字段。

成功原result：`DerivedData/AppRealIntegration/Inputs/run-63d3549e-ee49-4acb-90f6-b2112328faaa/app-result.json`。

## 主管独立结论

主管亲自读取两原App报告/契约/命令/exit，核默认typed扫描失败无认证/SFTP/凭据与显式15成功16checks、实际SSH PID、真实Files返回/list/awaitclose、无恢复及原先source/sign，独立lsof确认无listener。结果复核：

`DerivedData/Verification/primary-app-real-results-627530dc-bfbd-44f6-93cb-0703d32ac122/`

主管未机械重跑两原生流程；这是源码/离线独立执行和原真实结果审查，不冒称全部GUI人工通过。

## 尚未完成

- 默认scan5在该有限测试relay未通过，正式网络/目标mac26的默认运行须另验；15仅显式测试基础设施补测。
- 原失败run的已知managedkey/store已按固定账本/FD身份完成外层单独恢复，原失败报告不覆盖；没有未知递归或修改fixture原generation。
- 此案无传输，不证明“关闭SSH标签后真实SFTP任务继续”、有任务关闭/退出保护或Finder拖放。
- 未覆盖远端TUI/嵌套SSH、人工IME/像素、mac26、200/24h、双机/企业与正式发布。

整体Goal NOT COMPLETE。
