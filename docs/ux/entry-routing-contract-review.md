# 普通与本次密码入口：当前路由契约

结论：**新增四项实际AppModel/Controller/Editor逻辑消费者契约已独立通过，产品入口仍未统一。** 这不是SSH互通、真实GUI、资源或默认切换验收。2026-11-01。

## 窄变化

仅 `Tests/OpenLXSSHAppTests/SessionControllerTests.swift` 新增四个方法并增强文件内逻辑builder/driver；原30个测试正文不改、其他168个源码/manifest输入摘要不变。两个distinct builder分别模拟当前ordinary与typed candidate，不把两者替身合并成同一路再宣成功。

1. 普通新建连接对旧四个持久认证枚举都使用ordinary builder；真实configuration保持passwordOnly/passwordAndKeyboardInteractive/key的KI false/true差异。reuse不connect，显式new的tab/driver/view/token独立。
2. 无本次新密码（包括已有保存授权、两种key枚举）的保存并连接，在准确editor dismiss后只调用ordinary一次；不调用candidate、不读写凭据。
3. 本次密码经真实AppModel prepare不创建tab/连接/切页；dismiss后candidate commit一次，仅准确typed primary请求消费intent一次。随后列表reuse可复用该candidate owner，普通显式new仍使用ordinary。
4. 取消未消费candidate intent先撤销授权；手动reconnect保原driver/view及tab.builder，但生成新token generation/provider，旧intent/authorization不得复活，不自动重连或投旧密码。

此测试记录的是**当前行为**；未来批准切默认时应明确改路由与对应当前策略断言，不能只让新旧builder混同而追认统一。问题与采用门见 `../adr/ux-native-ssh-entry-consistency.md`。

## 实际验证与主管复审

证据 `DerivedData/UXVerification/EntryRoutingContract-R1/`，patch SHA256 `1ae231a308d741a0a3a9f7e9735e32058b08806b20b9ed960d1758e64bc9196a`。

- 独立 `HostProbe26-EntryRoutingR1` 首次build-for-testing exit0；新4/0，旧受影响42/0（Controller原30、Native9、Editor3），0skip。不重Files/全Native/visible-R9/中键。
- 九件实际Mach-O arm64/minOS26；编译命令可见Swift6/warnings-as-errors/enable-testing。有效App和XCTest设置为complete concurrency，但未观察显式 `-strict-concurrency` 参数，未伪称显式传入。
- 三个证据工具假设失败保留：必须显式flag、默认build action读取不到测试设置、主docs-only提交导致HEAD变化；均不是产品build/test失败，没有为文档HEAD移动重编。
- 主管读取唯一增量/关键四方法与test helpers，独立同产物运行新四项：**4/0、exit0**，证据 `Primary/independent-four.*`。

未读取真实密钥/Keychain、联网、运行visible GUI、签名、Docker或修改default。合成builder中的计数/typed-provider不是生产SSH证据，也不解决Appweak/FD或PAM取消卫生失败。
