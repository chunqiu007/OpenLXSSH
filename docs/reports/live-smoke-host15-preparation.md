# 真实 SSH/SFTP 消费者：host15 离线准备检查点

Task LIVE-SMOKE-HOST15-A，仅新增 `Tests/RealIntegration/`，不改正式App/Packages、环境夹具或min26稳定性driver。本轮**source/offline/static signed build已准备并主管复核，真实互通未运行**。用户环境授权已具备，当前Engine仍停止等待本人Docker协议处理及资源设置；不能把可运行入口或静态构建写作真实认证通过。

## 最小验证入口与安全合同

`Consumer/ProductionConsumer.swift`使用production公开 `DirectSSHSession.connect` 和 `LibSSH2FileService.connect`，不使用probe构造器/startProbe、terminal输出匹配或CLI SSH包装。不读取Keychain/用户.ssh。测试图明确host15，正式产品/既有稳定性driver仍min26。

仅fixture@127.0.0.1:22221 keyonly、22222 passwordonly，positive/bad-password/unregistered-key固定案例。合同与所有材料必须来自 `Tests/IntegrationEnvironment/.runtime/<service>/credentials-<exact12hex>/` 单一实际generation：精确base/built-image/service provenance、带外known_hosts/完整指纹一致；无latest/glob/跨代fallback、无任意host/user/port。读私有文件用逐组件O_NOFOLLOW、UID、0600/0700、单链接常规文件、无ACL及有界长度；未知字段/无效路径/额外响应拒绝。

自动信任只来自独立本地管理通道导出的带外key，且与合同显式核实指纹一致，不接受keyscan候选。**这不是首次连接GUI信任AC证据。** SSH密码输入采用协调者显式核实的一次认证请求精确hash/类型/无hint计划，非提示文字猜测、非保存凭据自动化；多请求/unknown立即取消。密钥负向仅生成自有临时未注册key，不借另一服务/代的密钥。

SSH正向必须production `.connected` 外层可信认证事件；spawn/PTY文本不计成功。case30s、关闭drain12s，取消/close等待`.closed`且ownedPID=nil。公共API普通255/launchFailed可能混同网络错误，消费者对此返回`negativeUnclassified`且非零，不冒称坏凭据负向通过；后续实跑再用确证证据处理，不降低断言。

SFTP正向在成功认证/初始化后，对自有UUID目录及单个exclusive payload执行list/lstat、流式微型写读、SHA校验、精确payload删除/空UUID目录移除和await native close；未知子项/链接拒绝清理、无递归删除。连接/取消故障阻止清理时报cleanupIncomplete，不假装全部释放。远端lstat非原子no-follow/CAS，剩余同用户竞争边界明确。

CLI默认help/validate纯解析不打开合同；实际live必须明确 `--live --authorized-local-fixture --engine-ready --contract <实际generation>/real-integration.json`，flag只是防误操作，不自动创造授权。尚无真实generation，报告不编造可运行路径。输出仅固定case/计数/结果，不保存terminal/提示/秘密。中途失败可能保留精确0700 live-UUID材料供协调者处理，不扫描删未知数据。

## 构建与独立复核

- 无远程依赖的SwiftPM只用于离线Core/POSIX/preflight tests；build_host.py以现有固定SwiftTerm/native source/manifest只读输入，独立 `.build/host-UUID`快照/工具缓存/对象；不resolve/download、不改共享cache或上游。
- production broker/helper固定不同identifier、同既有Development Team、Runtime、无entitlements、timestampnone，helper先签。不是Developer ID/正式产品。
- 工程师独立build36条命令全exit0，328项输入快照、13对象；App/helperarm64/min15，源码前后不变，未运行live。

真实静态产物：

`Tests/RealIntegration/.build/host-8761df59-adc7-4992-9589-ef31280f8f32/OpenLXSSHRealIntegration.app`

consumer SHA256 `36e2f77dbdd55240cc47f4c6d336b4e95bba364cc5f0f63331f927ce0ee43a2e`；helper `8a30fe836457416bb9fb85c3456d03564cc1c5eeac0407ee266751b197614952`。record和commands在该UUID。

主管阅读consumer/Main、固定合同/PrivateInput/POSIX、资源/结果计数、构建配方与tests。独立匹配328原源/快照hash、13对象hash、36命令exit0；核App/helper实际arm64/min15及严格Appleanchor/不同identifier/封装签名，生成 `DerivedData/Verification/primary-real-smoke-static-artifact.json`，没有执行consumer live。

主管独立执行：

```sh
/usr/bin/python3 -B Tests/RealIntegration/verify_offline.py
```

exit0，8Swift tests、5Python静态检查、5CLI纯解析/拒绝分支通过。证据 `DerivedData/Verification/primary-real-smoke-offline-f3a7d0fd-973c-4686-a111-fd4450f9db75/`；原测试输出在子树`.build/offline-tests-final.log`、`static-tests.log`、`offline-verification.json`。私有文件真实测试覆盖mode/硬链接/parent与final链接/FIFO/ACL；synthetic public key不是真连接，不当互通替代。

保留工程师早期ACLtest编译/C指针/签名HOME错误及后续修复记录；SwiftTerm12条上游warning未压制，Core/consumer warnings-as-errors通过。没有为旧功能重跑所有App/包测试。

## 下一项必要动作

用户本人Docker许可和资源条件到位后，主管核Engine-ready/官方固定base、本机builder、实际隔离约束与PAM ABI；再collect真实generation、核带外指纹/provenance、明确创建每case合同并运行本consumer，必要故障由真实证据派修。当前没有SSH/SFTP成功、MFA/GUI/目标macOS26或200/24h验收声明。
