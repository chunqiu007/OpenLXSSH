# P0-01 环境证据报告

- Task ID：`P0-01`
- 工作区：`/Users/liuwenshuo/Desktop/OpenLXSSH`
- 核对时间：2026-10-25 14:42:11 +0800
- 核对方式：仅执行本机只读探测和临时目录中的编译/运行冒烟测试；未连接服务器、未读取凭据、未安装工具或虚拟机。
- 本报告状态：已完成环境核对；不代表 OpenLXSSH App 已创建、构建、签名或完成 SSH/SFTP 认证。

## 1. 结论摘要

1. 当前机器为 Apple Silicon（`arm64`），但实际运行系统是 **macOS 15.8.1（Build 24H32）**，低于 OpenLXSSH 已确认的 macOS 26 最低目标。该差异是当前环境的交付限制，后续不得把本机运行结果当成 macOS 26 人工验收。
2. Xcode 26.3（Build 17C529）已安装并被 `xcode-select` 选中；macOS 26.2 SDK（SDK build 25C58）可由 `xcrun` 定位。
3. Swift 6.2.4、Apple Clang 17.0.0、`xcodebuild`、`xctest`、`xctrace` 和 `xcbeautify` 均可用。独立 Swift 源文件已使用 macOS 26.0 deployment target 编译并运行，Mach-O 目标和 SDK 版本已检查。
4. 系统 `/usr/bin/ssh` 和 `/usr/bin/sftp` 可用。`ssh` 报告 OpenSSH 9.9p2 / LibreSSL 3.3.6；`sftp` 没有 `-V` 版本选项，但二进制 provenance 为 Apple `OpenSSH-346.120.3`，且与 `ssh` 同源。仅检查了受控配置生成，不执行真实连接，因此没有认证成功结论。
5. 当前工作区没有 Xcode 项目、Swift Package 或 Swift 源文件；因此 `xcodebuild -list`、`swift package describe` 不能针对 OpenLXSSH 项目执行。未创建 App 项目或 Git 仓库。

## 2. 主机、架构与系统版本

| 项目 | 证据命令 | 结果 |
| --- | --- | --- |
| 产品版本 | `sw_vers` | `macOS 15.8.1` |
| 系统 Build | `sw_vers` | `24H32` |
| Darwin 内核/架构 | `uname -a` / `uname -srm` | Darwin 24.6.0，`arm64` |
| 机器架构 | `uname -m`、`arch`、`sysctl -n hw.machine` | `arm64` |
| ARM64 支持 | `sysctl -n hw.optional.arm64` | `1` |
| 逻辑 CPU | `sysctl -n hw.ncpu` | `8` |

实际目标是 Apple Silicon；当前 macOS 版本不是需求基线中的 macOS 26，后续应在 macOS 26 主机上补充运行时验证。

## 3. Xcode、SDK 与 Swift/Clang

### 3.1 Xcode 与 SDK

| 项目 | 证据命令 | 结果 |
| --- | --- | --- |
| Developer 目录 | `xcode-select -p` | `/Applications/Xcode.app/Contents/Developer` |
| Xcode | `xcodebuild -version` | `Xcode 26.3`，Build `17C529` |
| macOS SDK 列表 | `xcodebuild -showsdks` | macOS 26.2（`macosx26.2`）可用；命令退出码 0 |
| SDK 路径 | `xcrun --sdk macosx --show-sdk-path` | `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.2.sdk` |
| SDK 版本 | `xcrun --sdk macosx --show-sdk-version` | `26.2` |
| SDK build | `xcrun --sdk macosx --show-sdk-build-version` | `25C58` |
| 平台版本 | `xcrun --sdk macosx --show-sdk-platform-version` | `26.2` |
| 首次启动状态 | `xcodebuild -checkFirstLaunchStatus` | 退出码 0 |
| Xcode 签名完整性 | `codesign --verify --verbose=2 /Applications/Xcode.app` | `valid on disk`、满足 designated requirement，退出码 0 |

`xcodebuild -showsdks` 同时列出 iOS、tvOS、visionOS、watchOS 和 DriverKit SDK；本任务只将 macOS SDK 作为后续原生 App 的目标证据。

### 3.2 Swift 与 Clang

| 工具 | 路径 | 版本/目标信息 |
| --- | --- | --- |
| `swift` | `/usr/bin/swift`；`xcrun --find swift` 指向 `/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift` | Apple Swift `6.2.4`，swift-driver `1.127.15`，目标 `arm64-apple-macosx15.0` |
| `swiftc` | `/usr/bin/swiftc`；`xcrun --find swiftc` 指向 `/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swiftc` | Apple Swift `6.2.4`，swiftlang `6.2.4.1.4`，内含 clang `1700.6.4.2` |
| SwiftPM | 由 `swift package --version` 检查 | Swift Package Manager `6.2.4` |
| `clang` | `/usr/bin/clang`；`xcrun --find clang` 指向 `/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang` | Apple clang `17.0.0`（clang `1700.6.4.2`），目标 `arm64-apple-darwin24.6.0` |
| `clang++` | `/usr/bin/clang++` | Apple clang `17.0.0` |

`swiftc -print-target-info` 返回 `arm64-apple-macosx15.0` 默认编译目标；后续正式 App 可在构建设置中显式设置 macOS 26 deployment target。

## 4. 系统 OpenSSH 与 SFTP

### 4.1 路径、版本与二进制信息

| 项目 | 证据命令 | 结果 |
| --- | --- | --- |
| SSH 路径 | `command -v ssh` / `xcrun --find ssh` | `/usr/bin/ssh` |
| SSH 版本 | `ssh -V` | `OpenSSH_9.9p2, LibreSSL 3.3.6`，退出码 0 |
| SSH Apple provenance | `what /usr/bin/ssh` | `PROGRAM:ssh PROJECT:OpenSSH-346.120.3` |
| SFTP 路径 | `command -v sftp` / `xcrun --find sftp` | `/usr/bin/sftp` |
| SFTP 版本接口 | `sftp -V` | 不支持 `-V`，退出码 1，仅打印用法；不能据此伪造独立版本号 |
| SFTP Apple provenance | `what /usr/bin/sftp` | `PROGRAM:sftp PROJECT:OpenSSH-346.120.3` |
| SFTP 选项帮助 | `sftp -h` | 用法输出，退出码 1（该程序以用法帮助为非零返回） |
| 二进制架构 | `file /usr/bin/ssh /usr/bin/sftp` | 两者均为 universal binary，包含 `x86_64` 与 `arm64e` |
| SSH 代码签名 | `codesign --verify --verbose=2 /usr/bin/ssh` | valid on disk，退出码 0 |
| SFTP 代码签名 | `codesign --verify --verbose=2 /usr/bin/sftp` | valid on disk，退出码 0 |

### 4.2 后续受控启动可用的事实

使用以下不发起网络连接的配置展开命令验证了系统 OpenSSH 的参数解析路径：

```sh
ssh -G -F /dev/null \
  -o BatchMode=yes \
  -o ConnectTimeout=1 \
  -o ForwardAgent=no \
  -o StrictHostKeyChecking=ask \
  p0-01.invalid
```

该命令退出码为 0。摘要结果包括：

- `stricthostkeychecking ask`：默认策略可要求主机密钥信任判断，不是静默接受未知/变化密钥。
- `forwardagent no`：默认不转发 Agent。
- `controlmaster false`：未启用连接复用主控。
- `connecttimeout 1`：超时参数可被受控传入。
- `kbdinteractiveauthentication yes`、`passwordauthentication yes`、`pubkeyauthentication true`：系统客户端具备后续认证流程所需的相应选项。

该命令只进行配置展开，没有 DNS/网络连接、主机密钥校验、密码输入或认证；不能宣称 SSH/SFTP 认证已通过。正式 App 仍需生成自己的受控配置、known_hosts 路径和参数边界，不能直接把本机用户配置当作产品实现。

## 5. 构建、测试、签名与辅助工具

### 5.1 已可用

| 工具 | 路径/版本 | 说明 |
| --- | --- | --- |
| `xcodebuild` | `/usr/bin/xcodebuild`；Xcode 26.3 (17C529) | SDK 查询可用；当前无项目，不能执行项目 build/test |
| `xctest` | `/Applications/Xcode.app/Contents/Developer/usr/bin/xctest` | `xcrun --find xctest` 可定位；当前无 XCTest bundle |
| `xctrace` | `/usr/bin/xctrace`；`xctrace version 26.0 (17C529)` | 可用于后续 Instruments 类采样；本任务未运行性能采样 |
| `swift` / `swiftc` | `/usr/bin/swift`、`/usr/bin/swiftc` | Swift 6.2.4；独立源文件编译运行已通过 |
| `clang` / `clang++` | `/usr/bin/clang`、`/usr/bin/clang++` | Apple clang 17.0.0 |
| `xcbeautify` | `/opt/homebrew/bin/xcbeautify`，`3.2.1` | 可用于后续 `xcodebuild` 日志美化 |
| `swiftlint` | `/opt/homebrew/bin/swiftlint`，`0.65.1` | 已安装，可在项目建立后使用 |
| `git` | `/usr/bin/git`，`2.50.1 (Apple Git-155)` | 可执行；本任务未初始化仓库 |
| `make` | `/usr/bin/make`，GNU Make `3.81` | 可用；不作为正式 Swift App 构建入口 |
| `codesign` | `/usr/bin/codesign` | 可验证系统二进制和 Xcode；本任务未签名产品 |
| `security` | `/usr/bin/security` | 可定位；本任务未读取或写入 Keychain |
| `notarytool` | `/Applications/Xcode.app/Contents/Developer/usr/bin/notarytool`；版本 `1.1.0 (39)` | 命令可用；未保存凭据、未提交任何产物 |
| `plutil`、`otool`、`file` | `/usr/bin/plutil`、`/usr/bin/otool`、`/usr/bin/file` | 可用于后续产物/依赖检查 |

### 5.2 未发现或不可用

以下检查均为路径/版本可用性探测，没有安装或修改系统：

- `swift-format`：未找到，退出码 1。
- `cmake`：未找到，退出码 1。
- `ninja`：未找到，退出码 1。
- `pkg-config`：未找到，退出码 1。
- 独立 `instruments` 命令：未找到，退出码 1；当前 Xcode 提供 `xctrace`，后续应以实际命令和权限验证为准。

`codesign --version` 和 `security version` 不是本机工具支持的版本查询形式（分别返回退出码 2 和 1）；工具本身通过路径定位，且 `codesign --verify` 实测成功。`notarytool` 的可用性不等于 Apple 账号、团队、证书或上传授权已就绪。

## 6. 工作区项目输入限制

工作区初始检查结果：

- 没有 `.xcodeproj`、`.xcworkspace`、`Package.swift` 或 Swift 源文件。
- 没有 `.git` 目录；本任务未初始化 Git。
- `xcodebuild -list`：退出码 66，提示当前目录不包含 Xcode project、workspace 或 package。
- `swift package describe`：退出码 1，提示找不到 `Package.swift`。
- `find . -maxdepth 2 (项目/Package/Swift 输入模式)`：未发现项目构建输入。

因此本报告只验证了工具链和独立编译路径，没有声称 OpenLXSSH App 构建成功，也没有创建后续产品代码。

## 7. 最小真实构建验证

### 7.1 可复核命令路径

以下命令在临时目录创建无项目依赖的 Swift 文件，显式使用当前 macOS SDK 和 Apple Silicon/macOS 26.0 deployment target；临时目录在验证后删除：

```sh
set -eu
tmp_dir="$(mktemp -d /tmp/openlxssh-p0-01.XXXXXX)"
trap 'rm -rf "$tmp_dir"' EXIT
printf '%s\n' \
  'import Foundation' \
  'print("OpenLXSSH P0-01 macOS target build")' \
  > "$tmp_dir/main.swift"
sdk_path="$(xcrun --sdk macosx --show-sdk-path)"
xcrun --sdk macosx swiftc \
  -sdk "$sdk_path" \
  -target arm64-apple-macosx26.0 \
  "$tmp_dir/main.swift" \
  -o "$tmp_dir/p0-01-swift-target26"
file "$tmp_dir/p0-01-swift-target26"
otool -l "$tmp_dir/p0-01-swift-target26" | grep -A4 -m1 'LC_BUILD_VERSION'
"$tmp_dir/p0-01-swift-target26"
```

### 7.2 实际结果

- 编译退出码：`0`。
- `file`：`Mach-O 64-bit executable arm64`。
- `otool -l` 摘要：`LC_BUILD_VERSION`，`minos 26.0`，`sdk 26.2`。
- 运行退出码：`0`，输出为 `OpenLXSSH P0-01 macOS target build`。
- 另以默认 Swift 目标 `arm64-apple-macosx15.0` 完成独立编译/运行冒烟，编译和运行均退出码 `0`。

该结果证明当前 Xcode/Swift/SDK 具备生成 arm64 macOS 26.0 目标 Mach-O 的本地命令路径；由于宿主实际为 macOS 15.8.1，不能替代 macOS 26 主机上的 App 运行时验收。独立二进制在本机命令中运行成功也不改变这一限制。

## 8. 验收标准对应关系

| Acceptance Criteria | 结果 | 证据 |
| --- | --- | --- |
| 1. macOS、架构、Swift/Xcode/clang/SDK 版本与路径 | 满足 | 本报告第 2、3 节；实际 macOS 15.8.1 与目标 macOS 26 差异已明确记录 |
| 2. 系统 OpenSSH ssh/sftp 版本、路径及受控启动事实 | 满足 | 本报告第 4 节；`ssh -V`、`what`、`file`、`ssh -G`；明确未做认证 |
| 3. xcodebuild、swift、clang、xcbeautify 及其他工具与限制 | 满足 | 本报告第 5 节；包含可用版本、路径和缺失工具 |
| 4. 不依赖项目代码的真实最小验证路径 | 满足 | 本报告第 7 节；Swift 编译/运行和 Mach-O target 检查均有实际退出结果 |
| 5. 不包含密码、私钥、令牌、真实服务器信息或完整敏感终端内容 | 满足 | 仅使用无效占位主机名进行 `ssh -G` 配置展开；未连接网络、未读取凭据；报告只保留摘要 |

## 9. 限制、风险与后续边界

- **宿主系统版本限制：** 当前 macOS 15.8.1，不是需求规定的 macOS 26；需要在 macOS 26 主机上完成后续运行、权限、UI、终端和 Release 验证。
- **无项目限制：** 没有 Xcode 项目或 Swift Package，尚未执行 `xcodebuild build/test`、XCTest bundle 测试、App 启动或 SwiftUI/AppKit 验证。
- **SSH/SFTP 未联网：** 仅验证本机二进制、版本、代码签名和配置展开；未验证服务器连通性、主机密钥首次信任/变化拒绝、四类认证、MFA、PTY 或 SFTP 文件行为。
- **版本随系统变化：** `/usr/bin/ssh`、`/usr/bin/sftp` 属于 macOS 系统组件，不能像 Swift Package 一样由项目锁定；后续应把实际版本写入构建/回归证据。
- **签名/公证未实施：** `codesign` 和 `notarytool` 仅作工具可用性检查；没有读取签名私钥、没有保存凭据、没有向 Apple 上传。
- **辅助工具缺口：** 当前未发现 `swift-format`、`cmake`、`ninja`、`pkg-config` 和独立 `instruments`；不影响本轮 Swift/Xcode 最小路径，但后续依赖或格式化方案需据实际需要处理，不应把“命令缺失”写成已安装。

## 10. 本轮未执行事项

- 未创建 OpenLXSSH App、Xcode target、Swift Package 或测试代码。
- 未初始化 Git、未提交或推送。
- 未安装任何工具、依赖、虚拟机或容器。
- 未连接任何服务器，未发起 SSH/SFTP 认证，未读取、写入或生成凭据/私钥/known_hosts 内容。
- 未执行签名、公证上传、真实应用构建或外部人工验收。
