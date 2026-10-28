# 当前源码正式构建：fixture隔离回归 B

日期2026-10-28，Task `SHIPPING-FIXTURE-CONFIG-REGRESSION-B`。

**当前源码正式Debug/Release各一次arm64/min26真实增量编译、链接及HostProbe测试实现隔离已由主管独立通过。** 无min26运行、签名、公证、打包或发布结论，不重复旧候选构建。

## 范围与结果

复用私有853的Debug/Release缓存及固定checkout/native产物，无resolve/download，不触跟踪源码、锁文件或HostProbe。CODE_SIGNING_ALLOWED=NO、arm64、最低26.0/SDK26.2，Info无fixture opt-in。

- Debug build0/10.247秒，实际编译AppRealIntegration.swift、Contract.swift、OpenLXSSHApp.swift，App Ld1；实际defines仅DEBUG。
- Release build0/24.840秒，WMO实际27个App输入，App Ld1；实际defines空。
- 每配置均无HOST_PROBE，runtime消费者/hooks、AppRealBatchGate/AppRealSwitchGate/private material等nm符号0。pure scope/enum metadata及拒参数parser可以保留；源码条件＋实际compilerdefines＋链接符号联合，不只strings缺失或全程序可达性形式证明。
- readonly checkout、native160输出/7份许可notice摘要、系统动态链接、App实际两份资源notice来源通过。
- 106输入及额外两份notice源、HostProbe全15文件a6dcmain/e3fdhelper均未变。

正式Debug SHA256 `3d1c0f9a448fe67882e974bc200f46fc438885a3f2a4796d0ee8f88fe74f5e71`；Release `110b2e8fa7b03c62553eefdb58c08561cad9ee19823a94b5a9048a0b4d153439`。Release哈希与旧相同，但实际WMO编译与Ld日志证明本轮执行，未把摘要变化当构建依据。

## 检查脚本错误与非重复续行

初脚本在Debug build和静态隔离通过后，新增notice校验误将App NOTICE与不同用途的native NOTICE比较，exit1。原失败、recipe及13已完成命令/log完整保留；产品未改。

PBX实际资源来源为Application/OpenLXSSH/NOTICE.txt和SOURCE_ROOT下Packages/OpenLXSSHCore/ThirdPartyNotices/GRDB-LICENSE.txt；native七份许可仍另核。新resume只纠正资源来源，按精确argv/退出/logSHA只读复用前13命令，首次执行Release6命令。最终19唯一命令/19日志全部子命令exit0，Debug/Release均恰好各构建1次，不为检查错误重复编译。

证据目录：`DerivedData/AppRealIntegration/offline-853dd2e8-feff-4491-bc00-cf97bedfbfe4/shipping-fixture-b-ac2ba4c0-862b-422b-a04c-be9d97600336/resume-release-only-82cb46ca-d8ab-4373-be10-bb70651b8903/`。

- result SHA256 `573a5a69345a3bf5c49041297c2d68847d1ea76451ed38bd4b46df26167c6507`
- independent inspection `d93ce7d5554887f718a70baafa4a511ab055a7f196855fa09e61c809f31be09c`
- 41文件manifest `1be5500ad825380de6de93a85088b4ffc954f5a6817286eb3b48fdafb530e214`

主管独立核41清单/106当前输入/19命令loghash、两配置实际compile与Ld记录、当前binaryhash/vtool26/nm符号、PBX资源来源和HostProbe未变，证据：`DerivedData/Verification/primary-shipping-fixture-b-2366defe-1611-4318-a4e6-a159b830e8fc/`。主管首次只读核验也误将GRDB-LICENSE归App分组，实际SOURCE_ROOT路径修正后通过，未做状态动作或改产品。

本轮未重跑既有148HostProbe tests，复用其已审结果；无Docker/SSH/Keychain/SecItem/Apple上传、min26启动或签名打包。**只表示当前静态构建隔离通过，整体Goal仍未完成。**
