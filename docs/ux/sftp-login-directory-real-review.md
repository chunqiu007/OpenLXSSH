# SFTP 实际登录目录：只读有限真实门

结论：**当前包层实际initialDirectory/listing、预取消拒绝及同service恢复通过。** 不代表新版App默认消费或双栏GUI显示通过。2026-11-01。

## 范围与源码

既有三份AppFiles传输回执没有记录实际initialDirectory返回值，不能代DX-F04。新小消费者只使用当前成熟public `LibSSH2FileService`，一个固定批准的keyonly连接/单个公钥认证数组、严格hostkey；不启动shell、不读文件内容、不写远端、不重连救场。

fixture公开Dockerfile/server设置的home是 `/fixture/home`。消费者要求 `initialDirectory` 实际返回raw bytes恰等该非root路径，并将**实际返回的RemotePath对象**直接传给list，不用预期常量替换list参数。listing仅输出数量和预置`.ssh`目录kind/0700/mtime匹配布尔，不输出任意文件名或内容。

用已预取消operation token再次调用应typed cancelled，再以fresh token沿同service解析/list；只证明预取消，不冒在途native中断。关闭证据只列实际public close返回、weak service nil、socketGone及完整数值FD基线。没有公开native/handle snapshot，不能填shell drain/nativeClosed/producersSealed或把消费者pending当库全体计数。

唯一写域 `DerivedData/UXVerification/SFTPLoginDirectory-R1/`，7小源码；复用已独立min26的MixedLoad构建模块/objects，不重编Files/Trust/C/native/SwiftTerm/App、不改fixture/旧ledger。主读关键consumer/contract/build/supervise及窄修。

## 离线门与主管复验

准确构建 `Builds/build-2cf88ead379b4e92962895a9e8e2eda8`。

- main SHA256 `de1ccaeb18063259ac32c8289fa9c688f1222c181483c41a74e249c2921546d8`。
- pure SHA256 `38e59489994efb9837693a31a5a518ca415cdd9260ed6c7389ecb8611133f1dc`。
- ledger v3 SHA256 `3d277c74e20e301322c104f264a83fa32ac01d2f7681f4f7876b61b04da56c46`。

最终9构建命令exit0，仅两新Swift模块，Swift6/complete/warnings-as-errors；十二件实际Mach-O arm64/min26。459公开复用输入与44生产源及旧snapshot前后SHA保持；三轮构建均成功，后两轮只补实际编码宽度和stderr丢弃策略。

Python10/0、Swift37checks/0；实际完整success1284B/diagnostic1362B小于8192B。consumer11惰性/早拒案通过，禁网络/fixture材料/Docker读取的sandbox中default/help/validate三个入口均0。主管独立Python10/Swift37及十二件actualSHA/min26核验通过，未把pure当SSH。

## Fresh实网结果

监督目录 `Live/run-b3dae194b15c4791a5575f6a6ba01964`；consumer run `f7081dc7-48f7-4e09-94f9-c6c1033a20c7`，PID42617。

- 实际initialDirectory为 `/fixture/home`，非root；对该返回对象list得到3项，已知fixture目录metadata匹配。
- preCancelledOperationRejected=true，错误类型cancelled；fresh token同service再次返回 `/fixture/home`并list3项，metadata匹配，无第二连接。
- connectionAttempts/offeredPrimaryMethods/authenticatedServiceReturns各1、unexpectedTrustCallbacks0。offeredPrimaryMethods只是实际单方法数组，不冒typed provider调用计数。
- 六个顺序await完成、pending0；未使用raw stream API，不外推全库hidden handle计数。
- actual public close returned、weak service nil、socketGone均true，FD数值4→4（非entryidentity）。preparation6.274秒、active6.349秒、cleanup0.000329秒、full12.624秒。
- consumer exit0/noSignal，supervisor约12.636秒判passed；root finite180 relay PID42468自然exit0/204.774秒，accepted1/finished1/rejected0/cleanup_failed0。批准22221～22225端口已核free。

主管重新执行canonical verdict及原公开收据校验，记录 `Primary/live-independent.json`；主只prepare公开generation引用/provenance/known_hosts，秘密仅由消费者成熟reader在内存读取。没有Apple请求、GUI或生产连接。

## 保留缺口

包层F04真实能力门成立，不代App默认消费者在正常界面显示/保持登录路径，后者已有五项本地逻辑门但GUI仍待。没有在途cancel、任意服务器路径、权限边界、App weak/图形FD或完整双栏体验证据。总体仍未 `UX_READY_FOR_USER`。
