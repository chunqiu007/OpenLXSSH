# Native App退役与有限关闭：实施验收约束

日期：2026-10-31。**R1/R2本地实现门已独立审查通过：严格构建、R1唯一228项、R2受影响88项，主管分别40项和关键13项通过。真实Delegate退出、残留面板及网络App验收仍待。** NativeFailurePackage typed事实/sealedhandle和新版五个真实consumer分项只证明各自范围，不代表默认后端替换。

## 目标与最小结果模型

- SessionCloseResult.closed：真实native关闭、producer封口及交互排空均已确认。
- retired(ticket)：真实nativeClosed/revoked/sealed已确认，但外部provider仍pending；转App级只读非秘密票据，不能称provider已结束/秘密完全擦除。
- incomplete(context)：native关闭/封口未知、setup未返回或跟踪不可用；有限返回失败，保cleanup owner，不用UItimeout假retire。
- 2秒单ContinuousClock deadline贯穿所有tab和阶段；3秒仅测试观察上限，是响应预算选择而非安全等价。Files现有关闭等待不在该预算保证内，不假称整个Files架构已限时。

## 所有权和资源约束

- ticket仅SessionToken/canonical handleID/只读handle/snapshot，不能持Run/terminal/transport/credentialprovider/回答闭包。
- registry observer不捕ticket/handle形成互持，只捕token+handleID+reservation值；exact remove/release破订阅。不同A/B的完成不能争抢单全局onCompletion回调。
- primaryowner抽可撤销小状态，await前后授权复核，UI弱引用；用户取消/revoke释放intent/provider/prompt，迟到材料不自动发送。
- 预留64活跃/128总tracking槽限制后台清理与准备，不限制保存主机规模。满在新连接/secretread前显式拒绝，prepared丢弃自动cancel并归还额度，不事后丢owner。
- same tab pending拒绝重连，actual laterdrain后只允许用户显式新代次；A retired不能阻B真实关闭。移除tab只是UI资源释放，不能伪resourceDrained。

## Controller/Lifecycle/Delegate接线

- Native/Direct用显式async witness返回准确close结果，默认不能无条件closed。
- closeTabResult/closeAllResult聚合逐tab，旧兼容Bool由无incomplete推得，不忽略结果。
- 保原双层dirty Settings/Vault review与transfer确认顺序，批准后临时冻结cleanup；**没有incomplete才permanentquit/windowclose**。
- incomplete用固定非秘密错误/termination false/复位本attempt反馈，不kill无关terminal、不自动重连、不丢pending、不因resumeflow再投旧秘密。
- 需要真实最终transferreport后才检查残留，不能为2秒窗口跳过Files清理。

## 最小实际消费者回归

1. failedconnect typedhandle.pending>0，nativeclosed/sealed→retired不hang。
2. error/session/driver/view释放而handle仍pending，laterfinish归零且材料不消费。
3. canonical nativeclosedfalse/unsealed→incomplete，不移tab假closed。
4. A retired+B healthy，closeAll单deadline，B实际closed且A只票据。
5. A/B retire逆序完成，无全局callback覆盖/错清ticket。
6. same tab pending fence，drain后显式newgeneration，旧mailbox拒。
7. prepared丢弃和route拒绝归还预留，reservation容量满前不读secret。
8. waiter取消不cancelcleanup/其他waiter，重复close共享同owner幂等。
9. Lifecycle/Delegate incomplete拒退出/窗口并如实反馈，原dirty取消/transfer取消仍0误关闭。
10. Registry/ticket不保terminal/provider闭包，weak门与exactobserver移除可核。
11. 原AppChanged31/Files22、Window13+Middle既存红、PrefsClose18、Editor/Rel重要门均保留，不能删红测试冒全绿。

## 当前验证检查点

- Layout三源/10新方法SOURCE-READY，与Retirement七源/15方法共同冻结后才释放统一Debugbuild。
- 首正式build exit65，仅新Layout测试两weak未显式mutated警告。原owner只在析构XCTAssertNil之后显式nil一行，保weak/dealloc/原34前缀，不改产品两源，首失败日志保留；待唯一Retirementbuilder复验。
- 主管另审实际credentialawait强链：生产start已用SessionCredentialReadOwner，validity/claim弱controller/tab；仍要求15中heldgate测试走真实controller→request.primary→FakeCredential.read，证明driver/view可释放，不能只自定义authorizationgate算生产证据。
- driver弱完成订阅可因容量失败，但canReconnect/closeResult/新connect同步snapshot reconciliation不能永久fence；registry主订阅失败则incomplete保owner，不吞成retired。
- 第二正式Debugbuild已exit0（32.944秒），随后主审指出已存在close任务的直接join可能越更早调用deadline，改准确resultmailbox有限观察，不cancel原owner；同15方法扩短deadline测试。
- Delegate incomplete分支不能在Files已实际close后直接reset而跳过残留报告；结果gate移到准确finalTransfers/冻结labels提取与原showRetainedCleanup确认之后。SSHincomplete只拒最终退出，不声称回滚已取消/完成传输；Files协议不扩。

## R1 实际结果与主管复验

统一正式 Debug 构建最终成功。新15复验15/0；Native/Changed、FilesController、Session、Concurrency组106/0；Files布局/owner/Auth/Transfer组78/0；Close/Prefs/Editor组46/0。扣除重复的两个Session方法为唯一228项，新15已包含于106，不重复累加。App、Driver/Controller对象及xctest实核arm64/minos26.0，Swift6/complete/warnings-as-errors。证据：`DerivedData/UXVerification/NativeAppRetirement-R1/UnifiedVerification/verification-summary.json`。

主管核最终七源摘要及相对before补丁，再独立运行Retirement15、FilesLayout10、FilesReviewOwner15，共40/0，exit0、15.218秒。真实credential gate中生产Controller→request.primary→credentials.read路径的read1、claim一次、取消后driver/view弱引用释放、迟到材料拒收都保留。首新15的两项失败是注入错误尚未被setup捕获就取消的交付竞态，仅增加准确state.closing同步，未扩大预算或降低断言。首失败产物仍在。

## R2 源审修复与独立复验通过

R1绿色定向结果未覆盖的两处边界已精准修复：

1. 取消的是重复join观察者时，Controller的`try? Task.sleep`可立即抛出后在MainActor空转直至deadline；Driver的settle也有同类风险。取消应结束该观察并返回incomplete，不能取消资源owner、饿死其他UI或清理任务。须分别在实际tab/batch join已进入后取消，验证heartbeat、原owner与另一waiter均能执行；旧测试仅取消creator不能代表该门。
2. Driver将任意`CancellationError`或`FileServiceError`当作无native owner证明过宽，尤其显式wrapper.noNativeOwnerCreated=false不能被内层类型覆盖。生产`NativeLibraryConnector`可依据真实包connect的token/TCP/adopt前边界窄包装；establish后的错误已有canonical typedhandle。任意其他connector的generic无证明错误应保持unknown/incomplete，零pending不是关闭证明。

R2实际只修改Driver、Controller、NativeTests、ConcurrencyTests四文件，原范围其余三源和50保护源不变。取消返回`observationCancelled`的incomplete，不改资源owner；生产pre-native窄包装只在NativeLibraryConnector，显式false和generic未知始终保守。新增四方法，扩missingReceipt含NativeShellError及false包裹的CancellationError/FileServiceError；普通fake的无native事实明确包装，未知路径单独绕过，不删原测试或改deadline。

严格Debug首构建exit0；精确6/0已包含于三suite88/0（Native45、Controller30、Concurrency13），不重复累计。App/两对象/xctest实核arm64/min26。主管读R2相对before补丁、生产包控制流和测试fixture，再独立运行R2六门及primary真实credential弱释放、容量、逆序完成、同tab重连fence、单deadline/lifecycle等关键项，共**13/0、exit0**。第二join确已进入后取消，heartbeat和异步release<500ms，原owner/第三waiter正确；不是取消creator冒该门。

证据：`DerivedData/UXVerification/NativeAppRetirement-R2/{final.patch,final-sha256.json,Verification/verification-summary.json}`及`Verification/primary-r2-and-retirement-1.{json,log,xcresult}`。R1freeze、首失败均保留，无网络/GUI/真实凭据。代码本地门通过不解除真实退出、Window Middle及新App互通待验。

## 写域与调度

Retirement R2原执行者已freeze/STOP，释放writer/builder。当前后续唯一包builder为递归Manifest任务；Window仅准确单test/helper的source-only写入，App统一编译等源冻结，不越写Retirement。主管持文档/独立审查。

本检查点不是新增产品范围或用户授权；不生产/真凭据/Apple/push/长测。
