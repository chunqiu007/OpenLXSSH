# 正式构建：退出测试钩子隔离回归

日期2026-10-28，Task SHIPPING-HOOK-CONFIG-REGRESSION-A。**正式Debug/Release各一次arm64/min26真实增量compile/link通过，联合源码条件、实际编译defines与链接符号确认HOST_PROBE退出钩子和fixture运行实现未进入两产物。未运行macOS26、未签名或生成候选，不等可发布。**

仅复用853私有Debug/Release缓存，不复制checkout/resolve/download，不再build HostProbe。两次xcodebuild均CODE_SIGNING_ALLOWED=NO、ARCHS=arm64、MACOSX_DEPLOYMENT_TARGET=26.0；工具Xcode26.3/17C529、SDK26.2/Swift6.2.4/Clang17，实际target arm64-apple-macos26.0。Debug仅DEBUG，Release无额外define，均无HOST_PROBE。

AppRealIntegration运行实现和OpenLXSSHApp钩子/调用分支均由HOST_PROBE包围。两个linked binary的realQuitBeforeStoresClose/realQuitAfterStoresClose/realQuitFailure及fixture runtime类符号均0，纯参数解析/正式拒绝旗标门预期仍编译，不从字符串无命中单独推可达性。Info.plist/lipo/vtool均arm64/min26，runtime依赖系统路径/native160hash核过。每配置只有无AppIntents依赖的metadata extraction警告，无编译错误。

- Debug binary SHA256 `a3c60b7053d7749b4528b6645c6000c2a9030e3662311affafce873e6a1b9faa`。
- Release binary SHA256 `110b2e8fa7b03c62553eefdb58c08561cad9ee19823a94b5a9048a0b4d153439`。
- 19条命令/106输入hash前后相同，HostProbe main/helper未变；原123tests的shipping参数拒绝沿用，本轮未重复测试。

工程师命令/日志/产物：`DerivedData/AppRealIntegration/offline-853dd2e8-feff-4491-bc00-cf97bedfbfe4/shipping-hooks-10269334-bdf4-4f1c-ab22-40d86f731992/`。主管独立核106源码hash、两binaryhash/vtool26/nm钩子0与19命令证据：`DerivedData/Verification/primary-shipping-hooks-e06b1dcc-eab3-4c04-b311-c4277b01f0d7/`。

无源码修改、Docker/连接/凭据CRUD/Apple上传/发布候选。正式min26runtime/DeveloperID/Gatekeeper/最终helper嵌入仍待。整体Goal NOT COMPLETE。
