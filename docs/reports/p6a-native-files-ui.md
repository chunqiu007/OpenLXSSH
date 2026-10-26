# P6A 原生文件面板与安全操作集成审查

## 本轮结论

默认隐藏的右侧文件面板、应用级FilesController、独立按需认证、共享信任、目录浏览与安全mkdir/rename/delete/probe已完成本地集成审查。主管独立all/signed通过，后续认证撤销R1也独立复验通过。仍无真实SSH/SFTP服务器连接，无macOS26 runtime，未实现上传下载/任务界面/有传输关闭决策（P6B后续）。本报告不是FILE全体验收。

## 实现与职责

生产默认LibSSH2FilesConnector调用正式typedTCP/LibSSH2FileService.connect，同握手公钥经正式共享HostTrustStore，和SSH独立认证/MFA。初始密码/私钥口令从明确manual或saved选择取得；KeyStore仅受检精确UUID→SecretBytes，Core引用/算法/授权前后核验，未知kbd不猜类型、不调用saved读取。prepareAuthentication是生产TCP前唯一内存计划路径，不Codable/日志/额外文件。

FilesController应用级持Manager与同一scheduler，不引用SessionTab；panel只observer。startup/选择host/重绘不连接，显式连接一次；request/generation/token与mailbox ID约束，取消/换host/window使旧答复无效。多轮/多提示/echo/zero通知保留，hide不丢等待。libssh2取消/超时可能dispose服务，界面要求显式重连，不把Local可复用外推远端。

文件条目操作绑定原始FileName/RemotePath，显示转义不反解；手工UTF8地址独立，空Go保留原bytes。mkdir核远端路径剩余风险，rename走SafeFileOperations及独立风险回答；delete先immutable plan显示root/count/items/issues/risks再一次确认并重验，变化停止、仅删link须明确选择；probe显示自有UUID目录/动作/风险，显式批准run后才给当前service证据，不硬造token。lease按raw serialized、安全ops/probe callerScheduled避免同host双锁，旧operation slot/代次guard不能清新任务状态。

同ID主机配置编辑保留当前连接快照并提示显式断开/重连，已排任务将保持原归属。无传输windowclose同步禁止Files与SSH admission、解除认证/risk等待，再singleflight await两类真实cleanup；门禁维持至Files完成，重开新Manager且面板隐藏。hasActiveTransfers只看jobs，不把普通browse/认证当传输确认。

## 专项审查 R1

只读审查发现P2：saved私钥口令读取并复核后，最终metadata/sharedTrustStore await期间forget/refchange只改Key行，旧finalvalidator只核Host，即使看到新Key行仍放旧plan。主管读代码确认，原作者不可恢复后新工程师仅FilesConnection/FilesAuthenticationTests派修。

先保留修前旧85通过、新2项4断言失败。R1计划携实际使用request/Key/Credential元数据（无secret），prepare末次return与sharedTrustStore后TCP前均validatePreparedPlan读取当前Core，核Key ID/算法、Key→口令确切ref、credential purpose/saving授权；不一致取消。manual无savedcredential，忘记已保存口令不误拒手工输入。最终观察后仍有普通竞争窗口，不宣称Core与网络原子事务。

新增4项回归后工程师89tests、Release及signed通过；主管独立HostProbe完整89、signed12+8+15+5退出0。原审查者定向确认resolved，无额外P1/P2。日志 `DerivedData/Verification/primary-p6a-auth-r1-89tests.log`、`primary-p6a-auth-r1-signed.log`；红绿证据 `p6a-auth-revoke-r1/`。

## 主管独立验证

R1前独立执行 `Scripts/verify-app.sh all` / `signed-security` 均退出0：正式Debug/Release App/helper/Files Bridge.o arm64/min26，85tests，原生GUI15+8+7+17+17+真实Local14，签名12+8+15+5。签名路径真实Keychain隔离namespace、private bytes授权/拒绝/cleanup、native版本smoke通过；非网络。R1无UI变动，仅再跑89tests和signed，正式Release工程师验证metadata与系统runtime依赖不变。

根构建显式ARCHS=arm64/ONLY_ACTIVE_ARCH=YES，修正首轮Xcode选x86触发C桥硬拒，未改包。verify-files-native只读160产物/7licensehash，不重建native；实际App静态链接，无Homebrew runtime，许可入bundle；formalRelease符号无Local fixture。主管读全部本轮实现/测试/工程差异；日志 `primary-p6a-all.log` / `primary-p6a-signed.log`。

## 后续

P6B接单/多/文件夹上传下载、Finder fileURL拖入、任务入口/冲突风险/进度/取消/新job重试、有传输window/quit保护。现有绿测试不证明这些尚未实现部分。真实互通、远端能力矩阵、网络异常/磁盘满/权限、企业MFA/mac26/长测及双机仍待相应条件。
