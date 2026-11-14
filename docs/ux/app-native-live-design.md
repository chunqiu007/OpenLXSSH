# 新版Native App有限真实门：收敛任务

日期：2026-10-31。**当前：真实App keyonly、本次passwordonly、key-KI与password-KI的认证/113×37终端/exit7分项成立，两KI挑战清理成立；整案仍因间歇weak cleanup或FD基线差异失败，尚未达到本地体验候选验收。** 保活范围兼容和原pump离线门已独立审查，默认仍DirectSessionBuilder。Package真实门不冒充App或完整GUI；详细新实证另见`app-password-transient-review.md`、`app-mfa-real-review.md`。以下前期设计与原失败均保留，不将旧阶段计划当成当前已完成结果。

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

**公开夹具身份来源修正：** 源审发现旧AppRealContract仍固定历史CID1253…/FPMHU…，不能对当前批准keyonly材料通过。旧合同/validate/pin/ledger不改。主管批准仅新AppNativeFiniteContract内建立独立fixed validator/loader，复用旧安全FD reader和公开material schema但绝不声称通过旧validate；绑定当前已亲跑五案的CID`ed38148af68e2c6cdb70f18b9a716876754a393df2d530b168ddd2144d99021a`、FP`SHA256:d2G+w7lBrjYDFHHd6c6GxIhk7qzFs6df1i7EVJfeUYs`，base/image/project不变。固定回环22221/fixture/keyonly/同runID/readOnly，保state/provenance/knownhost/publickey摘要/权限/代际/buildEpoch门，并收紧fresh≤120秒。新纯测试需接受current、拒旧/任意身份且旧validator仍拒current，不能重写历史case来源。此仅新consumer源绑定授权，不含live/inspect/collect。

新拟argv：`<HostProbe.app>/Contents/MacOS/OpenLXSSH --native-app-fixture-test --native-app-fixture-contract <绝对路径/native-app-fixture.json> --authorized-local-fixture --primary-released`。包装契约仍仅schema/runID/固定scenario/materialcontractpath；不是旧runner通过或新网络验收。

Task `APP-NATIVE-FINITE-KEYONLY-R1-SOURCE` 写域仅两新App源AppNativeFiniteContract/Integration、Delegate的HOST_PROBE分流与shipping早拒/退出审计、相应新contracttests/有限wrapper及project最小登记。唯一包Manifestbuilder在运行，本任务禁止构建、测试、签名、live、collect、relay和GUI，source-ready即STOP。

执行链必须经Security导入/保存无password授权host→model.requestSession→生产NativeBuilder/Controller→精确trust accept→真实typedstages；输入经真实terminal relay、输出经生产Driver单receive，不可另一个session receive消费者。短freshACK/stty113×37/exit7与closed/canonicaldrain分别记；实际NSApp.terminate和willTerminate+自然exit0为退出门。仅逻辑App真实网络，不称GUI点击/像素。

**首案EOF观测边界：** 生产NativeDriver在唯一receive内部消费.eof，只设inputEnabled=false；现snapshot没有独立EOF或exitSignal事实。严格不改Driver/Package、不加第二receive的范围下，首案应明确`eofEvidence=notDirectlyObservable`或nil，只记录真实reported exit7和canonicaldrain；不得由断开/禁输入推造EOF。Package已有真实EOF门不自动补成App证据，后续若必要应独立受审只读seam。

## Source-ready及修前工件缺失的独立恢复

新consumer六源已SOURCE_READY/STOP，尚未编译。工程师未保存要求的Delegate/project修前副本、patch或hashledger，已明确报告PARTIAL，不将HEAD混合diff冒任务增量。主管冻结六源并逐项核对工程师最终SHA后，从既有Retirement-R2/before恢复Delegate（原SHA68fa5d…）；项目文件没有找到准确旧副本，主管只在独立ignored副本移除唯一FC11/FC22新登记，重建字节SHA与独立记录的修前`3a4292a017b9dfeb3420cc95013d0bc2ad1eefb7a52c11d1fb742ff254d6d073`完全一致。未回写或重置实际项目。

证据`DerivedData/UXVerification/AppNativeFinite-Keyonly-R1/SourceReview/`：`source-freeze-primary.json`、`recovered-before/`、`reconstructed-task-increment.patch`和`before-reconstruction-receipt.json`。这是事后按已有证据恢复，不伪称当时已保备份。

Debug与HostProbe均有12方法；typed-stages子断言只在HostProbe，Debug过也不能代该门。后续唯一builder须显式HostProbe deployment26及实际Mach-O检查，不能使用旧build-app HostProbe默认min15或全量旧real runner擅自签名/live。

双方freeze后统一正式Debug首构建exit65，唯一明确失败是新ContractTests37嵌套数组类型检查超时。原owner仅一个方法拆显式`[[String]]`与十个append，保全部10 invalid cases/12方法和断言；compile-fix-1实际保存before/patch/SHA，新testsSHA`caf3c3aa6e30c6b4da5af7e3eb24dbf5ff0779e2b69306aee7e0dddf0e6ec9d1`。主已读12+/3-准确补丁，原失败保留，唯一builder恢复Debugattempt2；还未有新增App网络/GUI或自然退出证据。Python只语法和inerthelp/validate门已执行，不是preflight/live/schema覆盖。

## 有限首案启动检查点（不是通过）

统一Debug与显式HostProbe26构建均已成功；纯契约两图各12/0，主管独立Host12/0，24对象实核min26，Python仅语法/inert CLI通过。主管冻结该HostProbe26副本及Debug min26 helper，补已有许可，在独立副本用既有Development身份`--timestamp=none`离线签名，strict/sameTeam/Runtime/空entitlements通过，没有Apple请求。冻结签后mainSHA`d01c8a9e7023fcb0c57c2dd8073c0f65b3f617d33eb642c452144c784f8f1f95`；不包含后续Files面板高度小修，不冒最新全源。

首supervisor预检在启动App前拒绝：codesign命令把`-R`与requirements分开，实际stderr指requirement被当文件，普通strict verify0。主管保首失败并独立以单token`-R=anchor apple generic and identifier ...`验证exit0；原owner只修supervisor该argv，不丢严格要求，新scriptSHA`674c13a51498f4410e7feb3de0e0b3ddf3195c5237d150f249318e029b7658c4`。首有限relay自然exit0、0实际App连接；未把预检拒绝称真实SSH失败。

重新复用原批准隔离服务（只读inspect四服务健康，当前CID/image/network均匹配），新有限180秒relay和新fresh材料/独立run契约已建立，case2正在运行或待主读最终receipt；**尚未报告通过**。不改旧合同/pins，不读私钥/密码/口令供模型查看，不生产/新增环境。证据`AppNativeFinite-Keyonly-R1/FrozenCandidate-1/`。

## 新App case2实际结果：核心链成立，整案failed cleanup

修正supervisor后新fresh run`ce878f58-88cb-4dc0-8e48-1cc1380097e5`真实执行：生产App Native连接1、publickey primary1/code0/authenticated/shellReady均真；真实terminal ACK、PTY、stty37×113、reported exit7、Controller.closed、canonicaldrained、Driver队列空、registry0均真，凭据owner调用0。随后12秒弱对象门未满足，driver/view仍存活，固定failure=cleanup，整案**failed**。descriptorAfter和known-host字节终核尚未到达，report known=false不是文件被改变证据，不能推FD泄漏。

实际App PID74366经原Delegate before/after stores与willTerminate完整顺序后**自然exit0、无signals**；supervisor仍failed app-failure-receipt，不由exit0回写成功。两轮relay分别0/0和1/1连接、cleanup_failed0，均自然exit0，批准端口已主核free；无强收尾。公开原收据已保存`FrozenCandidate-1/case2-public-receipts/`，首签名语法早拒不覆盖。

只读调查未发现已证永久Driver环；优先假设真实隐藏保留sessions hosting页未及时处理内层ForEach删除，`SessionDetailView→SessionTab→Driver→Terminal`链需实际复现，不只按源码宣布泄漏。consumer exercise局部也需明确async task结束边界排除。已派`NATIVE-APP-WEAK-HOSTED-R3-REPRO`仅NativeSessionAdapterTests新增headless/真实SessionWorkspace+NativeWorkspacePage ownedwindow两组，helper只返回weakboxes/标量、caller await结束后3秒核；不手动拆root/nil生产owner，不改Driver或加预算，保原首失败。

R3两组首复现均2/0、严格build0，生产38源/project不变：headless和真实hosted在helper返回前局部strong仍存活，caller await任务完成后tab/driver/terminal立即nil；hosted固定sessions隐藏、实际子页0、tabcount0、terminal无superview/window，未手动拆root。这一新证据不支持“隐藏宿主必有永久持有”结论，也不能单凭未复现否定live失败。证据`NativeAppWeakHosted-R3/Verification/weak-two-first.{json,log,xcresult}`，原45方法保留、新2，原ownerfreeze/STOP。

下一步只修测试consumer准确任务结束边界：独立exerciseTask先真实await/result且句柄作用域结束，再进入cleanup；避免原work闭包末尾覆盖self.work启动新cleanup时旧async frame未退出。保持原12秒weak硬门，不改生产owner/nil/GC/预算；加固定cleanupStage、weakTab/driver/view与exactsuperview/window等非秘密观测，若仍失败可区分实际持有阶段。Task`APP-NATIVE-FINITE-CLEANUP-SCOPE-R2-SOURCE`仅consumer/报告契约和schema小修source-only，旧case2不改绿，不处理未知遗留或广删测试根。

## Candidate2复验：仍在weakWait失败，新诊断缩小范围

R2 Debug102/0、HostProbe26 Contract12/0、Python纯schema8/0、14实物min26，初Host模块无testability的失败保留；仅测试图追加ENABLE_TESTABILITY后通过，不改生产/包。主管冻结完整Candidate2并离线Development签名（timestampnone/strict/sameTeam/Runtime/空entitlements），mainSHA`ef9e7a791cca9fbec7f2cbd2b084f9b30fb2f65622b64db9f503f95b8cf8fb5e`，复用现夹具新fresh材料和有限180秒relay。

run`033fa776-2881-4cd0-a6d3-ee7d217fd8f6`再次真实完成publickey1/code0/auth/shell1、ACK/PTy/stty37×113/exit7、Controller.closed、canonicaldrain、Driverqueueempty/registry0，credential0。整案仍failurecleanup；首次失败快照明确：**cleanupStage=weakWait，actualTabs0/pageVault，weakTab/driver/view全alive，terminal没有superview/window**，descriptor/knowncheck尚未执行。实际session weak已释放/nativeInput未直接可观测，不把nil当0。

App77213经stores/willTerminate后naturalexit0无signals，supervisor正确failed，未因exit0过门。两轮同症状不再重复consumer作用域或增加预算，先改假设：R3最小root缺真实顶部WorkspaceTabBar，已派R4仅测试加入实际标签栏，对照原两绿组，保真实contextMenu/drag/闭包，不改生产。源码与实证分别记录，尚不能断言标签栏就是根因。

证据`FrozenCandidate-2/{candidate.json,live-case-1-run.json,live-case-1-supervisor.log,case1-public-receipts/}`；原Candidate1及两失败保持。Candidate2 relay77064已自然exit0（含预检总204.772秒），accepted1/finished1/rejected0/cleanup_failed0，无signals；主另核批准端口free。仍不能把网络/进程回收事实替代整案weak对象门，case保持failed。

R4只加实际WorkspaceTabBar（原contextMenu/drag modifier全留）后新1+原2均3/0，关闭后实际middlechild0/sessionchild0，任务返回即三弱nil，生产38源/project不变。该新证据同样未复现，不继续把tabbar当根因。

更窄的真实差异是自动信任sheet：live实际窗口visible，SessionDetailView可自动创建TrustChallengeView/NativeSheetPresenter，随后consumer直接controller.accept。可证存活时的强链为presenter coordinator.sheet/hosting/content/onAttemptDismiss→View.tab→driver→terminal；但尚未证明完成后谁继续持有。Native trust/mailbox/Controller callbacks未发现已证永久环；markConnected repository-await捕tab也仅待观察。

R5只读指出hiddenwindow两道visibleguard都不创建真实sheet，不能用覆isVisible或直接beginSheet冒该链。已派仅测试源码准备：实际tabbar+SessionWorkspace根、自有visible window（只orderFront不activate/不夺其他窗口），真HostTrustStore.pending→原自动sheet→同live直接accept→connected→实际sheet关闭→exit7/closed→任务结束3秒weak；源冻结后由主管执行标准selfownedAppKittest。生产Presenter/Views不先修、不清closure消绿、不把该测试当实体鼠标/视觉。所有旧48methods保持。

R5已由主管严格Debug构建并实际执行精确新2/0：ownedwindow真实visible、无夺key/activate，trustcase实际attachedsheettrue、accept后attachednil，sheet/contentVC已nil，Task结束tab/driver/view均立即nil；无trust可见window对照同样nil。生产38源不变，原48正文保，测试只追加2到50。精确证据`NativeAppWeakHosted-R5/Primary/{build-first.json,visible-trust-two-first.json,visible-trust-two-first.log,visible-trust-two-first.xcresult}`。records空仅fakeUI边界没有主动持久化，不冒真实SharedHostTrust once。

此证据不支持先修Presenter/清onAttemptDismiss。下一更窄差异为真实AppRepository的markConnected提交和metadata observer/reload链；先只读核准确捕获/完成，再收敛真实临时SQLite离线对照，不再重复已过root/sheet类比。live持有者仍unknown，两个真实failedcase不改绿，12秒资源门保持。

只读metadata检查确认：markConnected的Task隐式strong捕tab且只为hostID，真实Repository apply同步commit/yield不等待reload，AppModel值型snapshot/observer未发现保存已删tab；是否live任务长期未返回仍unknown。已派R6先blockedmarkConnected精确测试（DBwrite尚pending时closed/drained但weak必须释放），再把Task改捕不可变hostID值；不取消metadata、不强制nilUIowner、不宣布这是live根因。真实case2及Candidate2不改绿，后续仍需新冻结App复验。

R6修前准确red已建立：Controller生产字节与before一致，新1测试阻塞实际markConnected.apply，资源closed/drained/queue0/registry0而Task结束3秒三weak仍alive，terminal无super/window；3个XCTAssertNil失败，gate释放后metadata commit1/日期/授权/连接身份/无cancel/无重连均过。只改`let hostID=tab.hostID`同步值快照和Task内`.markConnected(hostID,Date())`，同一测试源码hash未改即green1/0；metadata gate尚未return时三weak已nil，释放后写入功能保持。准确证据`NativeMarkConnectedOwnership-R6/Verification/{mark-red.*,mark-green.*}`。受影响回归进行中，仍不将此同形态离线复现外推两个真实live的唯一根因；须新冻结Candidate3复验。

## Candidate3真实复验：认证成功，但新的activeDeadline阶段失败

R6最小hostID修后HostProbe26增量build0、Contract12/0、5实物min26且全部保护hash保持。主管冻结完整Candidate3、离线Development签名（timestampnone/strict/sameTeam/Runtime/空entitlements），mainSHA`6b9f242eab499522e1b7cff57eb0eb05724508688619788481dff999a89fa9bd`。新fresh run`ce404889-8df8-4716-89b8-9d3b92698fbf`真实publickey1/code0/authenticated/shellReady成立，凭据0/信任准确；**本次没有达到完整terminal evidence/exit7/正常close门**，45秒active期限触发，fixedfailure=activeDeadline，总57.7秒含cleanup，首次snapshot仍exerciseRunning/tab1/terminalmounted。不能称它复现或修复旧weakWait，也不把nil field当终端无输出证明。

App79922实际Delegate stores/willTerminate后naturalexit0，supervisorfailed无signal。relay79759自然exit0（总204.744秒，accepted1/finished1/rejected0/cleanupfailed0），主核批准端口free。原Candidate1/2与red/green均保留。公开收据`FrozenCandidate-3/case1-public-receipts/`。

下一仅给consumer加fixed activeStage与终端布尔/解析后SIZE两整数、Driver队列/resize事实，不保存完整输出、命令、nonce或提示；原45/12预算与37×113断言保持。可能手动resize后实际renderer layout自动发回另一cells尺寸，但尚无实际SIZE证据，不能预修/扩大超时。Task`APP-NATIVE-FINITE-ACTIVE-DIAG-R3-SOURCE`四源source-only，不live/build，主审后再决定准确有限复验。

## Candidate4诊断结果：重新到达完整终端，但R6后仍weakWait

仅增观测的R3ActiveDiag HostProbe26 build0、Contract12/0、schema8/0、5实物min26，主freeze/离线Development签名Candidate4 mainSHA`08ce7c4d20dda02c4db3a0e500b54ee79877db749b0208bee4f1164b408bfd9e`，新fresh run`a03a0416-d002-48ac-a0cc-41b1972d31ab`真实认证和terminal完整：ACK/PTy/DONE真、远端SIZE37×113真、exit7/Controller.closed/canonicaldrain/queueempty/registry0均真。

整案仍failurecleanup、fixedstageweakWait，activeStageclosingTab，tabs0/pageVault、三weakalive、terminal无super/window；真实sessionweak已释放，nativeInput不直接观测。terminal本地renderer实际39×139、consumer曾请求37×113、远端真实返回37×113；不能把本地cells不同直接称本案resize失败，也不能用本案成功SIZE解释Candidate3缺观测的active失败。R6明确多余capture已修但不足以解除live持有。

App80757 naturalexit0无signal，supervisor仍failed；relay80599自然exit0/accepted1finished1/cleanupfailed0，公开收据`FrozenCandidate-4/case1-public-receipts/`。下一R7只测试真实临时AppRepository/SQLite和AppModel元数据observer链（不覆盖回调、不真Keychain），沿fake native transport、真tabbar/sessionsroot，确认实际mark日期/最新snapshot后close再weak；生产不猜修。另记录exactwindow.firstResponder是否为已关闭terminal，不为绿强清responder。原51方法保，新1/精确5，红也先留证STOP。

R7真实临时AppRepository/SQLite+实际AppModel observer对照新1及原4共5/0，实际mark日期/App catalog刷新idle、独立rename触发metadataChanges均证实；不覆盖onAuthenticatedMetadata，不清observer。任务结束三弱立即nil，exactownedhiddenwindow firstResponder在连接/关闭/当前均不是terminal。生产38源/project不变，原51保、新1到52；显式nil偏好只是声明（AppModel默认本已nil），不是修复，第二同5重复不计新增覆盖。证据`NativeRealRepoWeak-R7/`。仍未复现live持有，下一转独立审阅实际typed primary调用路径/async frame，而非重复更多root类比。

独立critique未找到新的源码可证明tab强回边；实际未加密key会经过NativePrimaryOwner安全key材料读取，但material.encryptedfalse绕过authorization.acquire，R7根本没callrequest.primary。R8因此只新增A/B：真实临时SQLite+本轮生成无口令Edkey/实际AppModel与原root，B在返回logicaltransport前实际awaitrequest.primary并在子作用域消费材料，A不调用，仍closeTask结束3秒weak门。只测试源、原52保，不保存秘密bytes/哈希、不网络。若也绿将停止更多root类比，转exactfullconsumer定点入向引用观察而非无变化live；工具不能给Swift强边时明确限制，不用refcount单独判owner。

R8实际生成无口令Ed25519、真实KeyStore/SQLite/AppModel同配置A/B（B确实awaitrequest.primary、公钥case且无passphrase、子作用域材料结束）新2+R7control共3/0，Task结束三弱仍立即nil。credentials拒绝owner调用0，未hash/打印私钥、未网络/真Keychain，生产不变；仍未复现live。停止追加更多root/primary类比。

主检查系统诊断工具公开帮助确认支持`leaks --traceTree=<已知对象地址> --noContent <准确PID>`；下一仅在本fixture当前weakWait时用同步unretained地址写一次闭合公开point收据（runID/PID/阶段/elapsed/tab-driver-view地址），不强持对象、不延12秒、不停App。外主须即时核准确PID/身份/阶段，地址过时或工具权限拒绝都只记unknown，不绕Hardened权限/加entitlements。禁止对象描述、认证内容、全堆/完整terminal、outputGraph。R4PointedRef当前四源source-only准备，未运行引用诊断，不假称已找到owner。

## Candidate5：三弱释放成立，失败转为descriptorWait 20→23

R4PointedRef严格Host26 build0、Contract12/0、schema8/0、5min26，四源保护保持，主离线签名freezeCandidate5 mainSHA`a31365b4921216f280a0670f99da7a6fa6e05b18e5468bdcc69d20efeb20301f`。新fresh run`daffbfca-cf2a-4868-bf09-5583e476e79a`完整真实认证/ACK/PTy/远端37×113/exit7/closed/drained/queueempty/registry0，**tab/driver/view均已释放**，weakPointWritten=false，故没有可trace地址、未执行leaks，不伪造owner证据。

整案仍failedcleanup，首次snapshot阶段**descriptorWait**、descriptorObservedtrue、baseline20/after23，knowncheck尚未执行；不能把3个增量直接称网络FD泄漏，也不能自动白名单/clamp。App82664 naturalexit0无signals，supervisor正确failed。该新UI释放事实不回写Candidate1/2/4的历史weakalive，也不足以证明唯一根因已清。

只读核对已完成：AppRepository实际使用单个GRDB DatabaseQueue而不是延迟reader池，基线前已有key导入/host保存/securityMetadata/trust初始化与records读取。Trust PrivateDirectory持目录FD、临时锁defer关闭。当前没有实际FD身份，因此新增3个仍unknown，不按数量判SQLite或网络泄漏，也不先改断言/基线。

下一仅外部exact本次新run实际Popen的PID进行有限lsof元数据采样，保UID/birth/精确binary身份前后验证；raw输出仅有界内存，只保存数字FD/type/category/device/inode及批准loopbacktuple，不保存用户path/内容、不扩其他PID。原Candidate5/source/supervisor和12/95秒预算保持。外部时点没有源码阶段信号，不能冒内部baseline20同刻。证据`FrozenCandidate-5/case1-public-receipts/`及`live-case-1-run.json`。relay82514已到期自然exit0（总204.767539秒），accepted1/finished1/rejected0/cleanup_failed0，无signal；主管已核批准端口free。

## 同一Candidate5的外部FD采样：有效观察，但先暴露尺寸竞争

`APP-FD-IDENTITY-SAMPLER-R1`仅ignored外部wrapper/52纯测试，原supervisor字节、808源码和23项candidate bundle文件均未变；主管源审后独立52/0。仅原supervise实际Popen的精确子进程，样本前后UID/PPID/birth/精确binary dev/ino/SHA校验。最多80样本、间隔≥0.75秒、单样本≤1秒、原95秒门不变；raw lsof只在有界内存，输出数字FD/type/access/device/inode和固定类别，不绑定store、不保存路径/内容、不改App verdict。

首准备案`PrimaryFDCase1`在App启动前失败：主自写公开helper误把ssh-keygen展示格式fingerprint.txt当裸指纹。已保首失败/修前文件；只修展示行解析，实际known_hosts blob与固定带外FP双校验不变。relay84083自然exit0、0连接，无App/采样启动，不算认证失败。

新fresh run `f153e0ac-95f7-4642-af4f-be179bb0bfbe`复用同Candidate5，认证primary1/code0/authenticated/shellReady1，ACK/PTy/DONE成立；但**远端实际139列×41行，不是113×37**。首次准确快照`awaitingTerminalEvidence`，local terminal也139×41，Driver resize队列空。45秒activeDeadline失败、总58.047秒、App84575自然exit0无signal；未到正常exit7/close/descriptorWait，不能当Candidate5原关闭后20→23的复现，更不能把宽尺寸接受或涨预算作为修复。

取得77份已验身份的外部样本：0.025秒8FD，0.781秒25FD，两fixture socket21/24；8.368秒21消失，46.369秒24消失，随后23FD，最后退出前出现短期unix FD。20/22/23为普通REG、身份已记录但owner未知。采样按监督器结束停止而标unknown，已经接受的77份仍是各自时点有效元数据；首样本不冒内部baseline20。post-exit仅本run精确临时根stat可匹配部分DB/Trust目录inode，但不证明连续持有、不补造缺失阶段。证据`FDIdentity-R1/run-f153e0ac-95f7-4642-af4f-be179bb0bfbe/`与`PrimaryFDCase2/public-receipts/`。

relay84398自然exit0（总204.753571秒），accepted1/finished1/rejected0/cleanup_failed0，无signals；主已核批准端口free。下一窄查真实renderer尺寸回调与consumer手动resize的先后，先精确复现再修，不无变化重复live。

## 几何R1实证冲突与R2隔离fixture修正

R1正式测试图最初缺MainView/helper而build65，保留不算行为红。窄接共享helper到原Contract文件HOST_PROBE末尾、正式project仅追加10个既有UI Test Sources；生产members/settings/dependencies不变。真实MainView、自有hidden窗、原min920×580测得terminal912×527、114列×32行、cell8×16。113列需window宽[912,920)，中点916低于下限，因此不能靠窗口调整达成。旧helper随后真实layout变120×32而仍发送，1方法9断言红；未降min或改产品默认。

R2仅在隔离fixture开tab/baseline前通过AppModel.saveSettings→真实AppRepository固定受支持字号14（产品默认13保持），目标窗口约1030宽可达。相同font14测试字节在旧helper红1/9后，改共享HOST_PROBE helper为显式sameownedwindow正常contentSize/layout反馈、最多8次调整、真实cells113×37+原queueempty、至少两轮稳定100ms后最终复查与原send无await。迟到layout扰动118×39后恢复113×37，命令一次、最大resize并发1；默认13不可达明确terminalEvidence且零send/零write/窗frame不变。

最终双配置build0、Host20/0、Debug18/0、12实物实际min26，Debug无helper/new2符号。主管独立几何2+Contract12=14/0，实际稳定106.928ms、terminal113×37；只自有AppKit几何/逻辑transport，不冒远端/实体点击/CUA。source prefix/evidence/预算/weak/FD硬门均不变，首setup/编译失败保留。权威`NativeRendererGeometry-R2/final-freeze-authoritative.json`及`Primary/geometry-and-contract14.*`。

主管已冻结新Candidate6完整HostProbe26+Debughelper+原licenses，用既有Development仅timestampnone离线签名，strict/sameTeam/Runtime/空entitlements通过，无Apple请求。mainSHA`4cae5195983c720866362886d95072461ee04627cd59c52eaba3b63639bf6ca8`、helper`c988eca038e1b31e1451e9ac46d90e2e37b4285544fa8bd17887d3b595531b04`，旧候选与原failed结果保持。FD薄类别适配器纯22/0且主独立22/0，目前只绑定新候选准备，尚未有新live结论，不称已解释+3。

## Candidate6签名早拒与Candidate7新的真实weakWait

Candidate6 strict主签名通过，但helper未显式标识而被codesign命名为`openlxssh-askpass`，正式BundledAskpassHelper要求`org.openlxssh.askpass`；App bootstrap实际return64、44字节固定错误被supervisor丢弃，未启动连接/生成App收据。保留`PrimaryFDCase3`、0 accepted relay，不改生产校验或把它称SSH认证失败。

主管在独立Candidate7副本仅修正helper/main两个显式签名Identifier，source未变；strict精确requirement、sameTeam/Runtime/空entitlements/timestampnone通过。mainSHA`f0423c1fbd8dd83288d7732f8054f952483580c04b57122684a70e11ec089d67`、helper`87a0b80be451d81d37e19f4e81c0eb0ee8749d26fa014645a0ac0c9e18953f1c`。FD R3只新副本更新path/digest/描述，分类/原采样器/预算/verdict不变，22纯测过，R2历史不改。

run `d311ea20-9840-4413-b5f7-145499e31385`实际primary1/code0/auth/shell1、ACK/PTy/远端113×37、exit7/closed/canonicaldrained/queue0/registry0均成立，**整案仍weakWait三弱alive**，terminal detached、tab0/pageVault，FD门尚未执行。App88805自然exit0无signal、supervisor仍failed。27份精确FD样本确认fixture两个socket于8.377s已消失，额外3个REG未归类，不能据此称泄漏或资源全释放。

本次point真实于elapsed7.958秒写入，weakWait余11.952秒；主读取时App已结束，未执行leaks，旧地址不能复用。下一只增加外部及时观察器，原factory准确child、runID/UID/birth/binary与point新鲜度全校验，最多一次`leaks --noContent --nostacks --traceTree=<当前tab地址> <准确PID>`，无fullheap/outputGraph/对象描述/权限绕过/延deadline；工具拒绝或过时仍unknown。此插桩不冒未插桩资源门。证据`PrimaryFDCase4/public-receipts/`和`FDIdentity-R3/run-d311ea20-9840-4413-b5f7-145499e31385/`。

relay88267/88630分别自然exit0（204.803281/204.720297秒），0/0与1/1、rejected0/cleanup_failed0，无signals，主管已核批准端口free。产品当前仍未完整本地体验候选。

## Candidate7及时point观察：这次无point，准确复现FD门

新ignored observer仅复用冻结R3并在原factory真实child后附watcher，闭publicpoint/时点/精确身份校验；26纯测通过且主管独立26/0，未改产品/source/pins/原supervisor/预算/verdict。主fresh run `46abf0fb-6580-4b83-a15a-4032dca5fd8c`完整认证、ACK/PTy/113×37、exit7、closed/drained/队列registry0均真，**三弱立即nil、weakPointWritten=false**。因此observer正确attempts0，后见native-failure而unknown，没有执行leaks或产trace；不能称系统工具权限已过。

整案准确复现`descriptorWait`：baseline20/after23、known终核未到，failurecleanup，App89571自然exit0无signal仍failed。27份外部样本的owned DB/WAL/SHM/lock/Trust目录身份已匹配，fixture两socket8.377557秒前均消失；余21只读REG/稳定inode、24读写REG/跨run稳定inode、25读写REG/本run新inode仍other-redacted。没有内部baseline同刻身份，不能仅凭总数将三项自动豁免，分类也不证明持有者。

停止无变化重复live和继续猜类别；下一只读比较可归因元数据边界与冷UI对照方案。observer未调用leaks，仍没有引用链结论。证据`PrimaryWeakCase1/public-receipts/`与`WeakPointObserver-R1/{run-,point-run-}46abf0fb-6580-4b83-a15a-4032dca5fd8c/`。relay89389自然exit0（204.766357秒），accepted1/finished1/rejected0/cleanup_failed0，无signal，主核批准端口free；sourceLedger仍全匹配。

## 非网络对照的证据边界

冷UI单方法主实际运行1/0、0.937秒：真实visible trustsheet与weaknil断言通过，低域仅stdio0/1/2，Trustdir3在evaluate～dismiss出现、closed消失；所有snapshot `limitComplete=false`，不能称完整FD排除。原Swift JSON被XCTest完成行插入导致runner后解析失败；主管从未改原log中恢复九阶段scalarJSON并单独留postparse失败，不重跑消绿。`ColdUIFDControl-R1/primary-cold-{recovered-timeline,review}.json`。

空AppKit真实NSApplication.run对照，无SSH/terminal/Appdata：原156行严格min26程序完全unsigned原件未执行，主管独立正常linker-ad-hoc副本9点、0.998秒、natural0、ownedvisible非key，低域完整但fullTableCovered=false，始终stdio0/1/2。主管另仅5行增量的标准SwiftUI Text/TextField宿主（1.018秒）和own nonkey NSTextView.inputContext（1.021秒）也无额外低域REG。均不代表正式MainView或终端，也不能与unhosted结果拼成产品无问题证明；不修改系统保护或用户配置。

R9只读审没有找到terminal.send/render/link的可证反向强边，明确既有visible弱对象测试没有真实send/ACK/frame组合。新增唯一HOST_PROBE控制`testVisibleTerminalSendACKFrameThenWeakRelease`，复用原R5、保57旧methods及所有weak/send/ACK/frame断言。新诊断误把完整FD表覆盖和低域未知混为一谈已在主审纠正：保completefalse、仅unknownempty作低域质量，非放宽资源门。主实际一次write唯一精确payload成功并重新进入receive，但ACK后frames2→2、联合text/frame等待4.872秒timeout；没到close/weak，不能作持有复现。现只补公开renderer/occlusion等标量辨别前置，不force绘制、不关frame门、不激活外部App、不增加预算。证据`VisibleTerminalACK-R9/primary-once.*`。

## Candidate8准确内部FD基线与第一次工具调用

四源仅增加原扫描内的脱敏值集合，原全域count/相等断言/先weak门/20ms/45-12-90秒预算保持；32条诊断上限不截断计数，未知条目不造身份。新6项契约（旧12正文保留）与Python12+旧8通过；Host18+geometry2=20/0、Debug18/0，主管独立20/0，10实物min26。三份最大完整收据15,438B≤原16KiB。新包装只准确重绑source8a43ef…/Candidate8，100纯测全部保，主管独立point26/0；旧文件与历史来源不变。

Candidate8 main`6b5cde75e48accbc2a3a8b81d31d226848fc898945fe25781ffa010389980433`，显式helper/mainID离线Development/timestampnone/strict。run `ec329a5f-af53-48bc-aabd-9c6bd3d4608f`完整认证/113×37/exit7/closed/drain/queue/registry过；内部baseline elapsed0.569194542秒 count20、scan61440、20条stable/未截断，准确记录会话前集合。**本次又weakWait三alive，因此cleanupFirst/latest合法缺席，不能绕弱门取样**；整案failedcleanup、known未终核。

本次有新鲜point，watcher在point7.903199584秒后于8.042615125秒实际调用一次`leaks --noContent --nostacks --traceTree=<准确tab> 93662`；工具exit0、安全excerpt为空/不识别，observer明确unknown/ownershipProvenfalse，不把空结果作无入向引用证明。App自然exit0、总19.993秒、无signals仍failed；relay93481自然exit0（204.776696秒），accepted1/finished1/rejected0/cleanup_failed0，端口free。

停止无变化App重跑，先用完全合成globalRoot→Target无UI程序实核本机工具格式。只准确ownedPID/合成地址、无内容、≤2秒/有界PIPE；不调权限、不fullgraph、不读用户进程，不改旧filter去猜。原App工具raw已按隐私约定丢弃，不声称恢复它。证据`PrimaryPhaseCase1/public-receipts/`与`PhaseSnapshotObserver-R1/point-run-ec329a5f-af53-48bc-aabd-9c6bd3d4608f/observer.json`。

## 准确FD差集与系统文件身份；未完成项冻结

合成Root→Target工具格式对照主亲跑1次，exactself PID/地址、noContent、≤2秒、natural0，确证本机语法为`count <Class address> [size]`及strong边。旧filter只收address开头，不能把先前empty当无引用。新R2严格规范行29pure（主独立29/0），同Candidate8 fresh run78699738… actual trace识别`50 <SessionTab …> [1280]`，但复杂上游行未收，holder仍unknown；原raw按约定丢弃不可恢复。进一步R3只保安全metadata32pure，新R4主数值化prototype不输出原descriptor/路径（3合成拒绝checks）。旧filters与证据保留，不由pathcount推owner。

run `0fe2d581-7673-4c87-af9c-37a9d18c3dec`终于取得**准确内部差集**：baseline20、cleanupFirst23、cleanupLatest23三份均complete、全stable、未截断；原20身份全部保，无removed，新增FD20只读REG、22读写REG、23读写REG。本次三弱nil/noPoint/trace0，两个测试socket已消失。整案仍failedcleanup，不把自然exit0、weaknil或排空当FD门通过。

主仅在公开只读系统根有界stat按设备/inode比较，确认新增readonly `dev=16777229/ino=1152921500312163768` 精确匹配 `/System/Library/Frameworks/QuartzCore.framework/Versions/A/Resources/default.metallib`，UID0/REG。**仅此一项角色有证据**，两个RW仍unknown，不能据文件数/名字猜shader cache或默认SQLite reader。官方MTLBinaryArchive文档不提供可用的系统GPU缓存namespace；不扫描用户cache/Keychain，不按未知路径读内容，不加“+3豁免”。

relay95070自然exit0、204.791577秒、accepted1/finished1/rejected0/cleanup_failed0，无signals，批准端口已核free。精确收据`PrimaryPhaseCase3/public-receipts/`和`system-readonly-fd-match.json`。停止重复网络试验/类别扩展，保留资源未过；桌面occlusion前置与用户像素验收仍受限，不能以诊断替产品完成。并行推进不依赖此门的候选保活合法配置兼容，不自动切默认。

现有生产保活compatibility/default ADR缺口仍见`native-default-switch-gates.md`，新认证门通过也不会自动切默认。
