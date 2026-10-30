# 新版Native App有限真实门：收敛任务

日期：2026-10-31。**只读准备完成，尚未实施或运行本轮App真实网络。** 当前默认仍DirectSessionBuilder。Package五真实消费者结果不能冒充App创建、授权、标签或退出接线。

## 已核可复用路径

- HOST_PROBE真实集成bootstrap已有隔离Repository/Security和拒绝Keychain的凭据owner，但当前强制DirectSessionBuilder与DirectSessionDriver/PID断言。
- 既有参数为`--real-fixture-test --real-fixture-contract <绝对契约路径> --authorized-local-fixture --primary-released`；可选扫描秒数只属于Direct，不能传给Native假称生效。旧契约仅keyonly/22221，不静默放宽其pins或批准。
- 隔离根为canonical temporaryDirectory下`OpenLXSSH-AppTests-real-<runID>`、0700、`.openlxssh-real-fixture`标记。现`verify-app-real-integration.py`只离线构建/签名，不执行live。
- AppModel可显式注入内部NativeSessionBuilder，不需改全局默认。实际builder创建真实NativeLibraryConnector/NativeSessionDriver；typed primary经生产SessionController。仅password允许Vault一次性intent，不能把key硬塞该路径。
- 可复用StableFixtureFiles/SFTPAuthInput的精确代际、来源、权限、稳定FD reader，以及固定argv/私有有界PIPE的management OTP reader。不得读取运行时秘密供模型查看、复制到argv/env/log/截图或公开hash。现App安全reader对password/KI仍需封闭白名单接线。

## 首批有限门

1. 本次password经实际`prepareTransientConnection/prepareTransient/commit`，不存credentialRef/授权，凭据owner调用零，只消费一次，路由和真实tab/NativeDriver可核。
2. key+KI及password+KI各走同生产Controller；typed stages记录真实primary方法/result、KI/result/authenticated/shellReady，KI只显式回答，不扫描终端提示或复用主秘密，不声称libssh2公开partial-success。
3. 信任once不落盘/新连接再问、persistent仅写预期记录/新连接免问；changed只在测试store预置错误公开key，primary零、旧pin不变、不得rotate服务器。
4. A取消/B可继续，旧回答不能跨tab/request/generation。迟到工作保真实pending和canonical handle，不拿PID=nil证明释放。
5. 实际App终端短ACK、37×113 PTY、EOF/exit7与关闭分别记录；走App owner，不直接调用ReleasedShellProbeCase.connect冒App消费。

## 证据和退出

每案有绝对deadline、有限cleanup、输入/receive/resize/registry及资源基线；closed/retired/incomplete按真实状态。现AppReal普通结尾`exit()`不算自然termination；新门应要求AppKit willTerminate和外部自然exit0，独立报告失败/期限信号，不伪成功。

逻辑App真实网络与实际GUI必须分列。进程内target/action不是实体鼠标；CUA像素/AX不可读时仍保真实命中、焦点、安全字段、SaveDiscardCancel、红点/CmdQ、CmdV/IME/终端选取及遮挡未验。2026-10-31主管重读已知合成`workspace-r5.png`仍由provider明确省略图像，不重复派无图像模型，也不猜坐标。

## 写域与顺序

只读`APP-NATIVE-LIVE-READPREP-R1`已STOP，无修改/构建/网络/GUI/凭据读取。后续最小source/test-only任务可局限HOST_PROBE bootstrap、AppRealIntegration/Contract、契约tests和独立有限wrapper；禁Package、Manifest、全局默认与Window域。须在准确契约和immutable来源审查后才放行live，不由工程师自行collect/启动relay。

## 首案已派source-only（尚未构建/运行）

收敛选择独立HOST_PROBE入口与薄契约，首案固定keyonly-controller-shell，避免静默扩旧契约的backend/scenario/pin。旧App安全reader可直接复用严格keyonly材料；支持password的SFTPAuthInput所属测试模块未接入App target，不能说直接import即可。本次首案验证真实生产AppController/NativeBuilder消费，不是重复Package probe。

新拟argv：`<HostProbe.app>/Contents/MacOS/OpenLXSSH --native-app-fixture-test --native-app-fixture-contract <绝对路径/native-app-fixture.json> --authorized-local-fixture --primary-released`。包装契约仅schema/runID/固定scenario/旧materialcontractpath；同runID、原readOnly、旧fixedidentity/freshness门原样保。

Task `APP-NATIVE-FINITE-KEYONLY-R1-SOURCE` 写域仅两新App源AppNativeFiniteContract/Integration、Delegate的HOST_PROBE分流与shipping早拒/退出审计、相应新contracttests/有限wrapper及project最小登记。唯一包Manifestbuilder在运行，本任务禁止构建、测试、签名、live、collect、relay和GUI，source-ready即STOP。

执行链必须经Security导入/保存无password授权host→model.requestSession→生产NativeBuilder/Controller→精确trust accept→真实typedstages；输入经真实terminal relay、输出经生产Driver单receive，不可另一个session receive消费者。短freshACK/stty113×37/exit7与closed/canonicaldrain分别记；实际NSApp.terminate和willTerminate+自然exit0为退出门。仅逻辑App真实网络，不称GUI点击/像素。

**首案EOF观测边界：** 生产NativeDriver在唯一receive内部消费.eof，只设inputEnabled=false；现snapshot没有独立EOF或exitSignal事实。严格不改Driver/Package、不加第二receive的范围下，首案应明确`eofEvidence=notDirectlyObservable`或nil，只记录真实reported exit7和canonicaldrain；不得由断开/禁输入推造EOF。Package已有真实EOF门不自动补成App证据，后续若必要应独立受审只读seam。

现有生产保活compatibility/default ADR缺口仍见`native-default-switch-gates.md`，新认证门通过也不会自动切默认。
