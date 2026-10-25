# ADR-P2-LOCAL-A：本地终端探针暂选 SwiftTerm 1.99.1 预览

- 状态：本地原型候选已通过主管代码审查、独立16项测试/原生App自检，并独立复现稳定版尾部失败；完整P2与正式产品依赖仍待验收
- 日期：2026-10-25～26（Asia/Shanghai）
- Task：P2-LOCAL-A
- 范围：`Experiments/P2-TerminalProbe/` 的离线 AppKit/本地 PTY 实验；不代表完整 P2、AC-13/14/15 或产品发布通过

## 决定与实测原因

选 `v1.99.1` / `2f573f73af5e768d90847dce20c97fa9535d7164`，明确为上游 **2.0 前预览，不是稳定 2.x**。默认稳定候选 `v1.20.0` / `5d14406844143538cd8f8851d2d8a67c1fe443e5` 在同源对照中出现实际输出丢失，因此本轮不选。没有引用或修改 master API，也没有 patch 上游。

两个版本复用相同 Sources/Tests，通过编译条件隔离少量公共 API；比较包由 `Scripts/compare-candidate.sh` 生成在忽略的 `.build/candidate-1.20.0/`，不复制两套源码。主包 `Package.swift` exact 1.99.1，自己的 `Package.resolved` 固定版本与 revision。

本机 macOS 15.8.1/arm64，Xcode 26.3，Swift 6.2.4，SDK 26.2。主探针最低 15 仅用于当前宿主实跑；`build-macos26.sh` 以独立同源 manifest 指定 26，`vtool` 实际确认 minos 26.0。单独传 `--triple ...26.0` 会被原包 platform 15 覆盖，不能作为 min26 证据。没有 macOS 26 runtime 验证。

## 同场景比较

| 场景 | 1.20.0 稳定 | 1.99.1 预览 |
| --- | --- | --- |
| Debug/Release AppKit 编译与原生窗口 | 均实际成功 | 均实际成功 |
| 最终自动化套件 | Debug/Release 各 16 项，15 项通过，压力尾部一项 3 个断言失败 | 最终 Debug/Release 各 16 项、0 失败 |
| 输出后立即退出，不在 fixture sleep | 曾出现整段 FINAL-TAIL 丢失；30 次短循环后续也出现全过，属竞态，不能只报告一次通过 | 最终 30 次循环均保留完整尾部 |
| 30,000 行输出，同时主线程受控阻塞 150ms | Debug 最终仅交付 3,441 字节，缺 STREAM-029999/STREAM-END；Release 最终对照仅 11,594 字节，失败 | Debug/Release 均收到 >900,000 字节并保留末行/尾标记 |
| 10,050 行、隐藏终端、历史/搜索 | 有限历史/搜索/输出通过 | 有限历史/搜索/输出通过；帧诊断同时确认隐藏期间最多增加 1 帧 |
| 20 次创建关闭资源 | FD 3→3，弱终端视图存活 0，所属 PID 消失 | FD 3→3，弱终端视图存活 0，所属 PID 消失 |
| 同负载 Release App＋本地 fixture RSS 峰值 | 157,728 KiB | 132,816 KiB（最后一次） |

RSS 是每 50ms `ps` 采样的 App＋直接所属 fixture RSS 相加；共享页可能重复计数，仅单窗口约 4 秒的本地对比，不是 5 会话、24 小时或产品 PERF 验收，也不说明预览必然更快。选择预览的主要原因是完整性与资源边界，不是这组短测内存差异。

稳定版的 `LocalProcess.processTerminated` 可先于 pending main-queue chunks；外层正常释放进程后丢尾部，没有公开 drain/EOF/待交付计数可形成可靠协调。`terminate()` 又取消其 exit monitor，不保证 waitpid。用固定 sleep 猜排空不可靠，因此保留失败断言而非延迟 fixture、删测或改上游。

## API 与生命周期适配

调查过 `LocalProcessTerminalView`：它已经创建唯一 PTY，但同时直接占用视图 delegate 并将输入无限制发往 `process.send`；稳定版 OSC52 还直接访问用户剪贴板。探针因此复用更小的 **TerminalView＋单个上游 LocalProcess**，没有自建/复制 PTY、第二个 reader 或另一个进程监视器。

- 统一显式 `.main` 交付，解析同步消费该批字节。预览 LocalProcess 默认队列与 1.x 不同，不能依赖默认值。
- 预览通过 `startProcessChecked`、`send(data:completion:)`、`updateWindowSize`，不在后台关闭时使用裸 FD；稳定比较分支才有限借用 FD。master 标记 CLOEXEC，避免下一个子进程继承。
- 输入总上限 256 KiB，单次上游写入至多 16 KiB，等待 completion 再写下一块；满时拒绝整个新块并显示状态，不静默截断。协议输出从不任意丢字节。
- 预览管线源码为 Darwin 4×65,536 字节 ring，通过阻塞生产者背压；稳定 main-queue path 为 4MiB/1MiB 高低水位。历史默认 10,000，可选 1,000/10,000/50,000，上限 50,000。
- 预览 parser 对 OSC/APC 各有 65MiB 上限并在超限后恢复；稳定 parser 的未终止 OSC/APC 累积未发现同类上限。探针禁用 Kitty 图像存储/local media，不授予 OSC 剪贴板或 URL 打开能力。这不等于已审计全部恶意终端序列。
- 预览 `drainTimeout = .infinity` 使用上游可取消的完整 drain，不拿固定时间当“排空完成”。正常退出因此保留已读/待解析输出。用户关闭释放 LocalProcess，由其 PID-safe reaper TERM→KILL，外层只以 waitid WNOWAIT/ECHILD 观察其已回收，不争夺 waitpid、不按旧 PID 发信号。显式关闭允许取消未完成输入及 I/O；与正常退出排空区分。
- 输出在进程退出后保留于视图；新 fixture 才替换。永久移除视图调用公开 `updateUiClosed()`，清理帧驱动、焦点观察者和计时器。隐藏视图不停止接收输出。
- 预览用 copied dimensions/content 与 `pasteText`；稳定文本导出要通过 public line/character provider，直接 getBufferAsData 会包含宽字符 NUL 并漏复杂字符。未使用私有 parser/getTerminal 的预览替代 API。

## 原生交互与证据

固定本地 fixture，不读 SSH 配置、钥匙串、凭据、用户 shell/vim 启动文件，不连接网络。可打开 `/usr/bin/vim -u NONE -U NONE -i NONE -n --noplugin` 的一次性文件。子进程仅接收 PATH/TERM/UTF-8/HOME/TMPDIR 白名单，HOME/TMPDIR 为专属权限 0700 临时目录，退出清理。

`--gui-smoke` 创建真实 NSApplication/NSWindow，以本窗口 NSEvent 发送 Ctrl+C、Up、Tab，经过真实 PTY 回显；验证 resize、搜索、Bracketed Paste、Unicode、字体深色主题、隐藏历史和关闭窗口。最终 Release window 4557、App 97067、fixture 97070；窗口关闭时子进程仍活跃，随后父子均消失；13 项检查全真。Debug 同样实际通过。没有用浏览器代替原生界面。

截图使用 AppKit 对实际终端子视图的 `cacheDisplay`，`terminal-only.png` 是上游绘制结果；系统 Vision OCR 识别出 HISTORY-10030～10049、HISTORY-END、SIZE。父 stack 的 `native-window.png` 不包含 layer-backed 子终端像素，仅证明控件布局，不能当终端像素证据。WindowServer `screencapture -l` 返回“could not create image from window”，现有 Accessibility 状态 false；未修改权限。人工像素/IME仍需独立检查。

`--vim-smoke` 实际插入/Bracketed Paste 中文、组合字符和单 Emoji，resize、保存内容、退出码0、所属进程回收通过；初始 ZWJ Emoji 逐字断言失败。系统 Vim 9.1 patches 1–1752 把 ZWJ 显示为 `<200d>`。独立 `os.openpty`＋系统 Vim（不使用 SwiftTerm）捕获也含 `<200d>` 而无原始 ZWJ 字节，说明该局部限制来自当前 Vim 输出行为。保留退出1的失败结果，不把部分通过写成完整 Vim/Emoji 通过。

## 许可证、打包与复验入口

SwiftTerm 两 tag 的 MIT LICENSE 相同，已原样保存；根许可证含 Miguel de Icaza、xterm.js、SourceLair、Christopher Jeffrey notices。完整许可证与 NOTICE 随 App Resources 打包。

最终解析：SwiftTerm 1.99.1；ArgumentParser 1.8.2/`6a52f3251125d74daf04fcbd5e6f08a75d074382`；swift-png 4.5.2/`2d17c6c51c098628574c0383f1119892655a73a2`；h 1.0.1/`aa3626829160917d4378330617971977cbd78f5b`。后三者 Apache-2.0，完整 LICENSE/NOTICE 本地保存；它们未进入 macOS App 链接目标。SwiftPM 6.2 本次解析裁掉未使用 DocC，不能照抄 P0 上游锁清单。`otool -L` 仅系统框架/系统 Swift 库，无 Homebrew dylib。

在实验目录执行以下命令可复核（全部产物在忽略的 `.build/`）：

```sh
./Scripts/offline-dependencies.sh  # 复用本机已有标签对象/缓存，禁止网络fallback
swift test --disable-automatic-resolution
swift test -c release --disable-automatic-resolution
./Scripts/build-app.sh debug
./Scripts/build-app.sh release
python3 Scripts/native-smoke.py .build/app-release/OpenLXSSHTerminalProbe.app/Contents/MacOS/OpenLXSSHTerminalProbe .build/verification/review-app
./Scripts/compare-candidate.sh test  # 稳定对照，预期压力尾部失败；禁止当CI通过项
./Scripts/build-macos26.sh          # compile-only，vtool须minos26.0
```

验证日志在实验 `.build/verification/`；最终主包测试日志为 `final-debug-test.log`、`final-release-test.log`，App GUI/资源为 `final-app-release/{gui-smoke.json,resources.json,terminal-only.png}`。App打包脚本使用 ad hoc 签名，deep/strict verify 成功；不是 Developer ID、公证或安装发行物。

## 未覆盖与后续风险

- 预览 API、许可证/依赖图与正式2.x可能变化；后续更新必须重跑同套测试，不自动跟进 branch。
- 本轮只有固定本地 fixture/直接 Vim 子进程；没有远端 SSH、手动嵌套 SSH、MFA、信任、SFTP，AC-13/15 等仍未通过。
- 未人工验证中文输入法候选、标记文本、真实键盘布局/Option组合；未修改系统输入法或辅助权限。
- tmux、htop、Neovim、Docker/AI联网工具没有合法测试条件，未安装、未宣称覆盖。
- 未验证一般用户 shell 的后代进程树、会话恢复、5会话24小时、200次真实SSH、长期内存/CPU/Swap或Instruments。关闭仅证明本地直接所属进程；不应扩展为任意shell进程树保证。
- 完整 drain 的 main-queue消费模式在UI永久阻塞时仍会等待；用户关闭可取消，后续生产集成应重新衡量后台解析与UI响应，不以丢字节换吞吐。
- 需要主管独立原生交互、人工IME与目标macOS26实机；本ADR不修改产品验收表状态。
