# App消费typed主机变化事实：整合检查点

日期：2026-10-31。状态：**统一正式构建后Native31+Files22共53项通过，主管最终独立53项复验亦通过。** 这些是实际App消费者与虚拟连接边界，不是真实SSH/SFTP互通。

## 实现与审查

仅NativeSessionDriver、FilesController、NativeSessionAdapterTests、FilesControllerTests四文件；source-ready及compilefix1在`DerivedData/UXVerification/NativeChangedApp-R1/`。

- Native connect catch优先读取NativeShellError/FileServiceError.changedHostKey，校验同run/SessionToken、实际HostIdentity、host连接配置和active/tab未关；不依赖传输层已取消token抹事实。
- 用户cancel/close会立即revoke owner，迟到typederror不能重新呈现。runtime失败清理cancel token而owner仍有效时，准确事实保留。
- callback/error共单次immutableprompt入口，callback-first不提前finish setup；由实际connect catch统一收尾。错误端点事实不fallback到另一个callback记录，generic无fact不凭空猜changed。
- 发现changed后禁止输入/primary继续；只显示拒绝及管理路径，不提供普通接受变化按钮、不写known_hosts、不读新credential。
- Files按request/generation/lifetime/host连接身份/端点处理typedfact，statefailed仍保changedprompt；samepromptid去重，取消reply且不可confirm/once，旧request/newgen/closedwindow拒迟到。
- 本轮不改SessionController协议或AppRetirement；旧永久unavailableRegistryDrain仍是后续必修，不因typedchanged完成称关闭已全部修好。

## 原失败与精确修复

统一第二次App build exit65：新增ChangedFilesConnector.emit调用Package internal ChallengeReply.wait（waitAsync亦internal）。没有为测试扩大publicAPI；仅helper改为主队列delivery fence后用公开resolve(.confirm exact fingerprint)==false检查同一informational reply已撤销。旧18测试和产品源不改，原失败保留。

Window自己的CGFloat.nan歧义及标签组件编译actor/typechecker错误均另域修，日志不混为Changed失败。标签真实组件机械移动供双target测试，不用testflag裁根页面。

## 实际验证

- `DesktopWindowTabs-R1/UnifiedVerification/debug-build-fourth`正式Debug build-for-testing exit0。
- `changed53-first`正式min26/arm64 test-without-building：**FilesController22/0、NativeSessionAdapter31/0，共53/0，exit0**。
- 10新增门：error-only+runtimecancel零credentialread、callback/error两顺序/dismiss不复活、ownerCancel/tabClose强制迟到、newgeneration/genericnofact、wrongendpoint/A不扰B、SFTP相同四类组合。
- 主审已读代码和实际53日志/退出/参数；窗口最终冻结后主管独立 `UnifiedVerification/primary-changed53-1` **53/0、exit0**，无重建复验最终产物，后续Retirement写入不冒此来源。Window最终保护区与Changed4/Package7摘要一致已核。

## 未覆盖

新runtime的真实handshake nil/delayedhandler/取消provider/typedfacts/SFTP拒绝门须新baseline消费者，旧R4消费者不能冒新源；默认Direct不切，liveness=nil未迁移。真实GUI/像素/CmdV/截图仍待。
