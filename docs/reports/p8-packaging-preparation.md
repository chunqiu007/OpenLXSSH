# P8 候选打包入口：实现与独立审查

## 本轮结论

候选打包脚本及其83项独立fixture测试已完成主管复验。尚未运行正式Release构建或打包；不能据此声称候选产物、安装、Gatekeeper、Developer ID、公证或双机验收通过。

文件：`Scripts/package-release-candidate.py`、`Tests/ReleasePackaging/`、`docs/release/README-candidate.md`。默认unsigned，只显式选择已有Development/Developer ID身份才签名；不创建证书、不修改Keychain访问设置。Developer ID时间戳请求有独立显式开关，本轮未执行。脚本没有公证上传入口。

## 真实边界

构建前核源提交与dirty状态、固定构建输出/缓存/插件路径和祖先链接；只创建本轮UUID输出，不覆盖已有候选。校验正式名称、arm64、min26、App/helper布局、真实Mach-O MH_EXECUTE/LC_MAIN、可重定位依赖闭包和许可来源。当前V1只批准第一方主程序和固定helper，任何新增内嵌dylib/framework默认拒绝，须先审查来源与许可。

签名按内层代码到App顺序，不使用deep签名；严格验证identifier、Team、Runtime与权限。manifest记录实际commit/dirty、构建工具链、App目录摘要/清单、ZIP摘要、逐代码来源、实际链接依赖与许可；始终notarized=false/uploaded=false。不完整/失败marker不能视为完成候选。spctl结果独立记录，失败或超时不能冒充安装通过。

## 独立审查与修复

首轮71fixture通过后，只读审查发现4项真实缺陷：构建路径symlink检查晚于写入、拒绝真实helper裸@loader_path、未审查dylib可逃过许可覆盖、chmod后的MH_DYLIB可充当入口。作者在原5文件范围内修复，修前78项矩阵退出1的失败证据保留，原71项未删，新增12项后83项通过。

主管读取关键路径/二进制检查/来源/manifest实现，并独立执行：

`python3 -B -m unittest discover -s /Users/liuwenshuo/Desktop/OpenLXSSH/Tests/ReleasePackaging -p 'test_*.py' -v`

退出0，83tests/OK；日志 `DerivedData/Verification/primary-packaging83.log`。独立只读审查者定向重放原4问题，全部resolved：五类预存输出/插件symlink在任何tool调用前拒绝且外部不变、裸token接受但越界拒绝、未知dylib无完成manifest、真实header异常入口拒绝。只读现有Release主程序/helper字节与运行路径通过；这不是实际候选打包。

作者修前/修后证据：`DerivedData/Verification/ReleasePackaging-R1-d40d2ec7-fefc-48d1-adc8-004cf883ba56/`。隔离假App的系统ditto归档真实执行，签名/时间戳/build等为fixture模拟。

## 后续约束

实际打包需App/helper/Files集成结束、全部工程写入与构建暂停后串行进行；构建前预检不防御恶意同UID并发抢改。新增代码布局、剥离符号或依赖需要明确适配，不静默放宽。当前macOS15宿主不能运行正式min26产物，不以HostProbe冒充。必要Developer ID、公证具体产物授权、目标系统及双机/企业实测仍待外部条件。
