# P2-LOCAL-A：本地终端集成与版本选择审查

日期：2026-10-26。执行者：software-engineer；主管独立审查：Primary Agent。

## 结论

本地AppKit/SwiftTerm/PTY核心行为已有实际运行证据；完整P2仍为PARTIAL。人工中文IME、严格Vim ZWJ显示、远端TUI和手动嵌套SSH尚未通过。版本选用 `v1.99.1`，精确提交 `2f573f73af5e768d90847dce20c97fa9535d7164`，明确为2.0前预览，不是稳定2.x。

## 代码与范围审查

主管读取了manifest、Package.resolved、全部终端适配/App/fixture/GUI smoke、16项测试和构建/对照脚本；许可证/NOTICE在ThirdParty并随App打包。主要边界：

- 唯一上游LocalProcess拥有PTY和直接子进程，TerminalView消费字节；无重复PTY owner/reader。
- 输入256KiB上限、16KiB单次completion写入，满时整块拒绝。历史默认10000、上限50000；输出背压保留顺序，不截协议字节。
- 退出正常排空与用户显式取消区分；预览使用公开checked start、completion write、resize和reaper。隐藏视图继续消费输出、减少帧；视图永久移除关闭上游UI计时器。
- 固定fixture或干净本机Vim，不接SSH、不读凭据/用户startup；OSC剪贴板/URL/图像local-media访问禁用。
- 实验min15供宿主运行；产品仍min26。正式App整合和任意后代进程树仍需独立验证。

## 主管独立验证

工作目录：`/Users/liuwenshuo/Desktop/OpenLXSSH`，包位于 `Experiments/P2-TerminalProbe/`。

1. `swift test --package-path <包> --disable-automatic-resolution`：退出0，16项0失败；20次创建关闭FD3→3、弱视图0、所属PID消失。
2. `python3 <包>/Scripts/native-smoke.py <包>/.build/app-release/OpenLXSSHTerminalProbe.app/Contents/MacOS/OpenLXSSHTerminalProbe <包>/.build/verification/supervisor-release`：退出0，真实原生窗口4581，13项检查全真，App/fixture退出后均无残留。采样峰值140608KiB，仅短测本地RSS相加口径，不是产品PERF验收。
3. `compare-candidate.sh test --filter TerminalProbeTests.testFastProducerBackpressurePreservesTail`：稳定1.20.0退出1，1项中3断言失败；仅收到62字节，缺末行和STREAM-END。相同源码预览版通过，不用sleep或删断言隐藏失败。
4. `codesign --verify --deep --strict` 对Release探针App退出0；`otool -L`仅系统库/框架，无Homebrew依赖。
5. 实际 `macos26-package/.build/.../release/OpenLXSSHTerminalProbe` 的vtool确认minos26.0、SDK26.2。主管第一次用了错误路径返回1，纠正后复核成功；没有将错误命令记为通过。此项只编译，不是macOS26运行。

工程师另完成Debug/Release各16项、两种真实App的13项GUI smoke、20周期资源对照；稳定版最终Debug/Release压力测试都失败。原始证据在实验 `.build/verification/`；同场景工程师Release App峰值157728KiB（稳定）/132816KiB（预览），不是长期性能结论。

## 显示与未通过项

实际TerminalView的AppKit draw capture已生成；WindowServer截图权限失败、Accessibility状态false，未修改权限。主管工具返回图像但当前模型不支持图像输入，不能声称主管人工像素审查通过；程序化窗口/绘制证据与人工视觉验收分别记录。

工程师Vim smoke退出1：编辑、Unicode粘贴、resize、保存、退出0和回收通过，但系统Vim9.1将ZWJ输出为`<200d>`，逐字断言失败；不经过SwiftTerm的系统PTY对照同样如此。该结果不等于终端引擎损坏，也不等于完整TUI/Emoji验收通过，保留失败和覆盖范围。

尚缺中文IME候选/marked text人工流程、真实键盘布局、tmux/htop/Neovim/Docker/指定AI工具、SSH/MFA/手动嵌套、macOS26实机、200次认证循环/5会话24小时、Instruments、正式Release签名和双机安装。

## 决策

接受预览作为当前原型集成候选，风险/迁移与复验策略详见 `docs/adr/p2-terminal-version-selection.md`。未来正式2.x发布后不可自动升级；保留同套尾部/Unicode/资源测试。P2整体及AC-13/14/15仍未通过。
