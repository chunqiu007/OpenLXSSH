# P5 正式 App SSH 标签与认证集成审查

## 结论

App已接正式Transport/Trust/Security、真实NativeTerminalView、包内helper与原生标签/信任/认证UI。本轮本地集成审查与独立复验通过；没有真实SSH服务器连接，阶段5完整远端/目标系统验收仍未通过。不能把此报告当可用完整V1.0 Release。

## 实现与安全边界

- 应用级SessionController按最近活动的有效标签复用，显式新建独立标签；每tab保留driver/terminal，切换/重绘不重连，断开只手动新generation重连并重新核Core配置。
- 真实DirectSessionBuilder将host/user/port/auth/keepalive映射typed配置；管理私钥只核精确Core UUID与安全包文件，不接受随意用户路径。可信auth事件后才写最近连接时间一次，不以进程启动/输入回答作成功。
- 首次指纹UI要求独立核实，说明keyscan未经认证；已有变化拒绝。管理仅用共享store records/prepareReplacement/confirm，不直接写known_hosts或静默删记录。
- unknown挑战安全输入，confirmation/notification分开；未可信文字plain显示、控制符/bidi转义、有界，无终端输出扫描。saved provider仅password-only授权host/ref，metadata读取前后与token核验，未知MFA/内层SSH绝不投秘密。
- 默认三色组合明确为跟随外观alias，实际深浅改变terminal背景；自定义三色不随外观覆盖，字体/历史受有效边界。复制/粘贴/历史搜索接真实view。
- App父目录、Session环境、Recovery与journal/temp均FD ACL查询，任意扩展ACL/查询失败拒绝，不自动改用户ACL。Core提交后App父目录后检失败用committedStorageUnsafe分类，已提交key/secret不错误补偿、不诱导重复创建。journal rename后错误同样保留真实提交状态和恢复记录。
- Journal throwing-init全部属性已初始化后手动close再throw会deinit双close；真实最小FD复用确认后改local所有权至全部校验完成才转交。2项新测试验证空/decoded路径末尾真实ACL故障后复用自有FD不被误关。

## 独立审查修正 R2

只读审查以实际控制器逻辑probe确证两P2：重叠closeAll各自defer解closingAll使新tab漏清；首次metadata悬时cancel/关tab后仍读取凭据（最终guard未返回secret，不是跨主机误发）。保留新增首批6项/11断言失败与旧58通过日志。

修正closeAll/tabCloseTasks单flight，所有调用等待同owned cleanup，等待者取消不撤销清理；Quit在首await前永久beginTermination，拒reopen/new/reconnect/回答。provider入口与每个await后检查Task取消/currenttab/host/generation，尤其credentials.read前再检查，同时保留read后授权检查。新增10项continuation确定调度回归，无sleep赌竞态。原审查者定向复核两项resolved，未扩大审查。

## 主管验证

主管先独立verify-app all/signed：正式Debug/Release arm64/min26含helper，56tests、GUI15+8+7+17+16、签名8+8+15+5通过。Journal/R2修复后再独立：

1. `Scripts/build-app.sh HostProbe test`：退出0，68项0失败（原58+新10）。
2. `Scripts/verify-app.sh gui`：退出0，15+8+7+17+17检查。真实App中window-close清理挂起后Quit共享同批，二Quit仍Later，终止期间reopen/newsession拒绝，tabs0后实际进程exit0。
3. `Scripts/verify-app.sh signed-security`：退出0，Transport8（strict helper/ssh-G/真DirectSession synthetic候选待信任后cancel，无PID/网络）、安全保存8、跨启动读取15、精确cleanup5。helper先签不同identifier、同Team，再主App，现有Development/runtime/timestampnone严格验证通过。

主管最终日志 `DerivedData/Verification/primary-p5-r2-68tests.log`、`primary-p5-r2-gui.log`、`primary-p5-r2-signed.log`。工程师最终Release build-for-testing及helper arm64/min26元数据通过；原未变Debug此前已通过。依赖43个manifest/source hash前后稳定。

SwiftTerm固定版本确有BuildInfoPlugin，需要Xcode插件校验override。根构建脚本先resolve不执行plugin，再核固定5pin图、所有manifest、允许plugin集合、SwiftTerm generator/terminfo真实hash和clean checkout，新/变更拒绝。主管读脚本与负测，changed/new/duplicate/missing pin在checkout执行前拒绝；不是对任意插件全局无条件绕过。

## 未完成

真实四类认证/MFA/审批、握手主机变化、嵌套SSH/TUI、目标macOS26、人工IME/像素、200连接/24小时均未验。HostProbe GUI逻辑double明确标注；真DirectSession只走未信任前取消，不冒充网络成功。SFTP UI仍待下一里程碑，TransferLifecycle保留应用级seam，不能让terminal/panel拥有传输。正式自动密码gate/mac26及DeveloperID/公证/双机条件仍未具备。
