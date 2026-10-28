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

## AUTH/trust变更后的回归 C

B后新增的认证UI与信任管理测试源码已在C中实际正式编译复核；对应App源3adb274，独立Keepalive不进入产品目标。Debug/Release仍各一次incrementalcompile+Ld1，无重试：Debug11.372s编译AppRealIntegration/Contract/Entry三输入，Release21.421s按现有WMO27输入，actualdefines分别仅DEBUG/空，无HOST_PROBE。19命令/19日志全部exit0，106输入、native160/7许可、两实际PBX资源notice、Info26/系统动态链接通过。

运行Auth/Trust Evidence、认证/信任消费者、Batch/SwitchGate与hooks符号0，纯AppRealAuthUIGate/AppRealTrustGate/拒flagparser metadata按源码条件允许保留；不是靠某字符串不存在推全程序可达性。当前156tests只复用，不重跑。HostProbe全15文件aea234-main/5409helper和Keepalive App4文件2aace-main/b7d48-helper保持不变。

- C Debug SHA256 `e9bada830c064573e44002a8ba7a1edf946769c43d5726ff73f8e456e3effa53`
- C Release SHA256 `110b2e8fa7b03c62553eefdb58c08561cad9ee19823a94b5a9048a0b4d153439`（哈希仍同旧，实际compile/Ld日志明确执行）
- C证据：`DerivedData/AppRealIntegration/offline-853dd2e8-feff-4491-bc00-cf97bedfbfe4/shipping-fixture-c-03a4158a-6399-4053-90a7-fc36aaadb25a/`
- C result SHA256 `d4f802e546e326f399fe388498f4692ff42281ea9c29f0c3adc55dc1306fa2f3`，24文件manifest `098562202b62669e0bd6a1583fbf33ea93284805be3b6b38c94d09ccc8035f0b`
- 主管独立当前106输入/19log摘要/实际两次compile-Ld/当前binary-vtool26-nm/许可资源和两套测试App保护：`DerivedData/Verification/primary-shipping-fixture-c-452b2b7d-acac-4a3a-98b6-eb629599a6e7/`

C仍无运行、签名、打包或公证，不把编译闭环写为发布通过。此后若再改App接线源码，C的哈希只代表当时审点，不自动覆盖未来变更。

## 并发认证接线后的最终回归 D

对应App源码 `fa5191d`，最终Debug/Release仍各一次真实incrementalcompile+Ld1，无重复构建。Debug10.573s实际三变更输入，Release21.513s按既有WMO27输入；19命令/19日志全部exit0，arm64/min26/SDK26.2、Info无fixture opt-in、源码条件＋实际无HOST_PROBE编译参数＋运行符号缺失联合通过。ConcurrentAuthEvidence/并发helper与旧hooks等运行代码absent，pureConcurrentGate metadata按源码范围允许保留。

current106输入、native160/7许可、两实际PBXnotice/系统动态链接及HostProbe c558/b0f全15、Keepalive2aace/b7d全4文件保持。当前160tests只复用已审结果，不重跑。最终inspection最初期望-filelist未匹配，按真实@OpenLXSSH.SwiftFileList核27输入后通过，不修改产品/recipe或重构建。

- D Debug SHA256 `97f4e8f2a1756e80e4f5e40e0ff4e3cabc63cf8b6ff1aff12bc37f608acd1f84`
- D Release SHA256 `110b2e8fa7b03c62553eefdb58c08561cad9ee19823a94b5a9048a0b4d153439`，仍同旧字节但真实compile/Ld有记录
- D证据 `DerivedData/AppRealIntegration/offline-853dd2e8-feff-4491-bc00-cf97bedfbfe4/shipping-fixture-d-0df7cbd3-c5e5-4f80-ac00-677f1dd23043/`
- result `8af2368dedb95af84aeaf06a0dcb3749310eeca0d4d42450f081b007f7190e6f`，24证据manifest `dc4a2bdf3508800ccbd8c365638015ade6223e0d0a7fb759fb94c86cec6c009b`
- 主管独立106当前源、19loghash、两binary/vtool26/nm运行隔离/otool系统链接、PBX许可资源、两套测试App保护：`DerivedData/Verification/primary-shipping-fixture-d-f1c13ad5-32d3-4a3b-83ed-df3b50e12c7c/`

**D是本轮最终静态源码审点，不是正式签名、公证、Gatekeeper、macOS26运行或分发包验收。** 本轮到此不再新增host15测试phase，必要外部与人工条件集中见release前提清单。
