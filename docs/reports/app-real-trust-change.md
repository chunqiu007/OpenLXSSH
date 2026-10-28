# 真实主机预扫变化拒绝与原生信任管理恢复

日期2026-10-28，Task `APP-REAL-TRUST-CHANGE-PREP-A` / `LIVE-A`。

**唯一fresh案已主管独立验收：实际SystemHostKeyScanner对App已知错误公开key拒绝，原信任未变；仅原生管理prepare/verified/confirm精确替换，之后点击原生手动重连才进入新代次并获得真实shell ACK。** 不冒充服务器真实轮换、已启动SSH握手mismatch或正式macOS26验收。

## 窄范围实现

四个App真实测试接线文件新增closedphase `trust-change-recover`，plain key/terminal-only/noSFTP/credential/phrase/clipboard。仅新App隔离truststore空门下，用公开evaluate/confirm API设置不同的公开client key为故意错误server记录；成熟HostPublicKey解析和actualserverkey不相同门，不直接写known_hosts、不mockscanner、不改容器hostkey/config。

首次原生双击走实际SystemHostKeyScanner，要求typedtrustRejected、拒绝后旧公开records及known_hosts SHA不变。有限10ms采样、至多1000条闭合集合观察状态/所属交互SSH PID；keyscan子进程不算owned interactive SSH，明确不能从轮询证明采样间隙绝无瞬时进程。

恢复完全使用原生trust.manage.replace、publicfield、prepare、verified、confirm；confirm初始disabled需用户式核验动作。actual公开store后验只剩正确host/algorithm/key，hash改变，旧failedtoken仍gen1、无隐式重连。原生terminal.reconnect才同tab/driver/session/view/sessionID gen2，真实ownedbirthPID/outerconnected+freshACK，通用关闭/重开/store清理。

## 静态与签名

新增4tests覆盖closedphase/plain selection/端点与wrong区别、typedreject/noPIDauthprompt/旧hash不变、替换不隐式重连/精确下一gen+ACK及成熟公钥解析（公开RFC testvector，不是fixture秘密）。原152names与47Contract主体保留，唯一diagnostic74d4e7c8-11ae-4f2c-8a6a-a987f5655a3c exit0，156tests/0failure；49source/native160/14cmd（12logs+2signmetadata）通过。

main `aea234c5cd417d430c03681137cf3cc4a4aeecb9ab9b14ecbf28778d76a33293`；helper `5409d2317fb6405381fe4a7a249c47af3f35e5291df56cb3711ae42e7e16ceb3`；manifest `6d3be5bd097149e8c6935cabf6764c10f4c106218ddb75f851c3a185faa7e601`。

主管全源审/156原152保留/49当前输入/同TeamDevelopment-Runtime-空权限-strict/inert0-0-64核验：`DerivedData/Verification/primary-app-trust-static-9e2d7467-5238-4491-9897-6bb0b7d7bb30/`。

## 唯一真实结果

runID `e689113c-7b0e-4aed-a543-4fa7170ab77c`，collect/relay/App各1，无失败重试。App98252自然exit0/21.453s，15checks全过；testscan15、production scan5/connect10不改。

- 故意wrong公开FP `SHA256:iMzkEVjQk2OWmfBof0jgDz+z6ITTENGtyGD0VF4ZEDc`，actual `SHA256:MHUel445tN/gQtcvZikLZVE1mlWZf7U38C0zZTTru+Q`。主管独立从公开blob重算均匹配。
- 真实预扫至trustRejected，保存61状态样本/6.344s；未观察ownedinteractivePID/auth/首次信任prompt。
- knownhash拒绝前后均 `30cfc2db4410151f7bfc2b06eaad03edefffee5f93bc3d484afbe5433f2fb6a0`。
- 8原生动作，confirm先disabled，经verified确认后actual唯一正确record，hash `980dbfe4e8f68d5688b8025058a1970840678f0fe39acb2b6484b5d32e79070e`；替换后gen仍1。
- 手动reconnect才gen2，新SSH98313/出生1793151119.980338/parent98252，同对象/sessionID，actualouterauth+freshACK。
- 原生关闭/重开不恢复/store清理，SFTP/credential/handles全0，无phrase读取或剪贴板。

原报告：`DerivedData/AppRealIntegration/Inputs/run-e689113c-7b0e-4aed-a543-4fa7170ab77c/app-result.json`；SHA256 `bea35379dd50831f25dfffbb80b6b6b70096214964bf5a13cb7f73bbf605787c`。

命令/后验/40文件清单：`DerivedData/AppRealIntegration/trust-change-live-b93fd311-bfcb-462e-9891-3c91842caf35/`，manifest SHA256 `5906c5a92dd5b9c7c217e2d702dbd55b6fccf476b26b02868f82c864cc887a15`。

## 资源与结论

App98252/relay98172/SSH98313均不存在、逐PID FD0，22221～22225无listener、准确store消失/app-tmp空，relay7-7-0-0有序exit0、无强制KILL。远端UID10000进程0/daemon21-start7980921-FD4与四服务/CID/start/caps/network/volume/config/auth/known前后完整相同。49source/5fixture/15bundle未变。

主管独立核原15checks/61samples/8nativeactions/公有keyFP与旧hash-替换hash/代次/实际ACK、40摘要清单（秘密leaf拒绝、空App输出仅stat）和当前三PID/端口/store/源签名：`DerivedData/Verification/primary-app-trust-pass-3574a9c3-74cb-457c-92c7-483b5c5fda8e/`。初次只读脚本错用resume-trust-change前缀，真实名resume-trust纠正后通过，未做状态动作。

**有限DirectSSH真实预扫knownchanged拒绝和原生管理恢复分项通过。** 不改变首次信任或SFTP同握手mismatch既有证据，不宣称真实serverrotate、采样间隙absence、企业/正式mac26/完整AC12通过；整体Goal未完成。
