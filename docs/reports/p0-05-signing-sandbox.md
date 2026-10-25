# P0-05 签名、Bundle ID、辅助程序与 Sandbox/Hardened Runtime 路径调查

- Task ID：`P0-05`
- 工作区：`/Users/liuwenshuo/Desktop/OpenLXSSH`
- 调查时间：2026-10-25 19:04（Asia/Shanghai）
- 执行者：`software-engineer`
- 报告状态：范围内调查完成，并通过主管独立审查；不代表 OpenLXSSH 产品或 Release 验收通过。
- 当前提交基线：`65e2edd docs: record P0-04 test environment survey`
- 调查边界：只执行本机只读工具/签名状态检查、公开 Apple 文档核对和 `/tmp` 一次性 fixture；没有创建正式 App/Xcode 项目/Target、Package.swift、证书、私钥、provisioning profile、Keychain item、Apple API key 或 Bundle ID；没有读取 profile、Keychain 内容、私钥、秘密或真实团队/服务器信息；没有签名正式产品，也没有向 Apple 上传。

## 1. 结论摘要

1. 本机工具链入口可用：Xcode 26.3（Build 17C529）、macOS 26.2 SDK、`codesign`、`security`、`xcodebuild`、`xcrun`、`stapler`、`spctl`、`productbuild`、`pkgbuild`、`ditto`、`clang`、`lipo` 和 `plutil` 均可定位；`xcrun notarytool help` 可用。当前宿主仍是 macOS 15.8.1（Build 24H32），不能替代目标 macOS 26 运行时验收。
2. `security find-identity -v -p codesigning` 返回退出码 0、1 个有效签名身份；按证书类型摘要为：Developer ID Application 0、Developer ID Installer 0、Apple Development 1、Apple Distribution 0。未记录完整 identity hash、姓名、Team ID 或 Keychain 内容。命令返回“1 valid identities found”，因此“有签名身份”不等于有 Developer ID 发行条件。
3. 当前没有可知的正式 OpenLXSSH Bundle ID、Team ID、Developer ID 证书、Apple 登录状态、公证凭据或上传授权；本机也没有 Xcode 项目/App target 可验证这些值。必须由用户在后续正式 Target 和授权的 Apple Developer/Xcode 环境中完成登录、团队选择、Bundle ID/证书准备及公证授权操作。
4. Apple 官方文档给出：普通 helper tool 可放在 `Contents/MacOS/` 或 `Contents/Helpers/`；Service Management login item 放在 `Contents/Library/LoginItems/`；XPC service 放在 `Contents/XPCServices/`。Apple 的 sandbox helper 示例使用 `Contents/MacOS/`，并要求 helper 独立 target、继承/匹配签名配置、Copy Files 的 Executables 目的地与 Code Sign On Copy。OpenLXSSH 的 askpass/认证辅助程序在正式 Target 建立后，应先用受控 `Contents/Helpers/`（或按实际 Service Management 设计使用 `Contents/Library/LoginItems/`）并以最终 `.app` 验证，不把临时 fixture 视为产品结论。
5. 对 helper 的签名顺序应采用“先构建/签名嵌入代码，再签主 App/外层 bundle”；正式构建使用 Code Sign On Copy 或等价可靠流程，最终运行前用 `codesign --verify --deep --strict`，并分别用 `codesign --display --verbose=4 --entitlements :-` 检查主 App 与每个 helper 的 identifier、runtime flag、Team/Authority（报告只记录摘要）和 entitlements。Apple 文档特别提醒 sandbox helper 的工具 entitlement 应保持最小，示例为 `com.apple.security.app-sandbox` 与 `com.apple.security.inherit`；额外 entitlement 需以真实能力验证为依据。
6. `codesign --options runtime`/Xcode Hardened Runtime capability、显式 entitlements、主 App 和 helper 的最终签名需要在正式项目中验证。当前只用临时 arm64 fixture 证明 bundle layout、runtime/ad hoc 代码签名和验证入口可运行；fixture 没有 Developer ID、Team ID 或 Apple notarization ticket。
7. 公证只能在用户明确确认具体产物、Apple 目的地和用途后执行。本轮没有运行 `xcrun notarytool submit`、`store-credentials`、`altool` 或任何上传。正式路径是 Developer ID 签名 + Hardened Runtime + 适当最小 entitlements，再由用户完成 Apple 登录/凭据授权；获得成功结果后才可 `xcrun stapler staple`，并用 `xcrun stapler validate` 与 Gatekeeper 入口验证。未提交、未返回成功结果时不写“已公证”。

## 2. 当前工作区与目标事实

| 检查 | 结果 |
| --- | --- |
| Git 状态 | 分支 `main`；基线提交 `65e2edd`；调查开始时工作区无未提交改动 |
| 正式 App/Xcode 项目 | 未发现 `.xcodeproj`、`.xcworkspace`、`Package.swift`、`.app`、`.entitlements` 或产品 `Info.plist` |
| 宿主 | Apple Silicon `arm64`；macOS 15.8.1，Build 24H32 |
| Xcode | Xcode 26.3，Build 17C529；active developer dir `/Applications/Xcode.app/Contents/Developer` |
| SDK | macOS 26.2 SDK；`xcodebuild -showsdks` 列出 macOS 26.2 等平台 SDK |
| 当前产品构建/签名 | 未执行；没有产品 Target 或正式产物 |

工作区调查没有修改需求、架构、执行计划或产品代码；本报告及状态/验收阶段记录是本轮允许的文档范围。

## 3. 本机工具、路径、版本与只读入口

### 3.1 工具路径摘要

| 工具 | 路径/解析结果 | 版本或入口结果 |
| --- | --- | --- |
| `codesign` | `/usr/bin/codesign` | `-h` 入口可用；支持 `--verify`、`--display`、`--options runtime` 等签名/验证入口（`--version` 不是此版本有效选项，未据此虚构版本） |
| `security` | `/usr/bin/security` | `security help` rc 0；`find-identity` 可执行 |
| `xcodebuild` | `/usr/bin/xcodebuild` | Xcode 26.3 / Build 17C529；`-help`、`-showsdks` rc 0 |
| `xcrun` | `/usr/bin/xcrun` | xcrun version 72；`-f codesign`、`-f notarytool`、`-f stapler`、`-f clang` 均 rc 0 |
| `notarytool` | `/Applications/Xcode.app/Contents/Developer/usr/bin/notarytool`（`xcrun -f`） | `xcrun notarytool help` rc 0；公开入口含 `submit`、`info`、`history`、`log`、`store-credentials`，本轮未调用会上传/写凭据的动作 |
| `stapler` | `/Applications/Xcode.app/Contents/Developer/usr/bin/stapler`（`xcrun -f`） | `stapler -h` 入口返回帮助；公开入口含 `staple`、`validate` |
| `spctl` | `/usr/sbin/spctl` | `--help` 入口可调用；对临时 ad hoc fixture 的 assess 按预期拒绝，不代表 Developer ID 产物状态 |
| `productbuild` | `/usr/bin/productbuild` | 可定位；本轮未生成正式 installer |
| `pkgbuild` | `/usr/bin/pkgbuild` | 可定位；本轮未生成正式 installer |
| `ditto` | `/usr/bin/ditto` | 可定位；本轮未生成正式 archive |
| `clang` | `/usr/bin/clang`；`xcrun -f clang` 指向 Xcode toolchain | 可构建临时 arm64 fixture |
| `lipo` | `/usr/bin/lipo` | 可定位；本轮未制作 universal 产品 |
| `plutil` | `/usr/bin/plutil` | 可创建/检查临时 plist/entitlements |

注意：本机 shell 的 `PATH`/解析状态曾受工具运行环境影响，因此报告以 `whence -p` 与绝对路径、`xcrun -f` 结果为准，不把单次 `command -v` 异常当作工具缺失。

### 3.2 SDK 与系统权限模板

- `xcrun --sdk macosx --show-sdk-path` rc 0：`/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.2.sdk`。
- `xcrun --sdk macosx --show-sdk-version` rc 0：`26.2`。
- SDK `Entitlements.plist` 存在，当前公开模板只显示 `com.apple.application-identifier` 的占位结构；它不是 OpenLXSSH 最终权限清单。
- 最终 entitlements 必须来自正式功能与 Apple capability 配置，不应把所有候选权限全部打开。

## 4. 签名身份与 Apple 条件

### 4.1 安全摘要

执行：

```text
security find-identity -v -p codesigning
```

结果：退出码 `0`；`1 valid identities found`。仅对输出按证书类型做计数，未记录完整 identity hash、证书主体、团队、序列号、Keychain 路径或任何私钥内容：

| 身份类型 | 当前可见数量 |
| --- | ---: |
| Developer ID Application | 0 |
| Developer ID Installer | 0 |
| Apple Development | 1 |
| Apple Distribution | 0 |
| 其他 | 0 |

相同的 `security find-identity -v -p basic` 也返回退出码 `0`、1 个有效身份；仍只记录上述安全摘要。

解释边界：

- 有 1 个 Apple Development 身份，只能说明当前 Keychain 身份摘要中存在该类型的有效签名身份；不代表它包含 OpenLXSSH 所需 Team、Bundle ID profile、发布证书或 Developer ID 权限。
- 当前没有 Developer ID Application/Installer 身份的本地证据；不补办、不创建、不读取证书或私钥。
- 没有执行 `security find-generic-password`，没有读取 Keychain secret、证书私钥、profile 或任何凭据内容。

### 4.2 当前未知项与用户操作项

下列项目在本轮保持未知，不猜测、不从 Apple 账号存在推断：

- 正式 OpenLXSSH 主 App Bundle ID。
- helper 的正式 Bundle ID/代码签名 identifier 命名。
- Apple Developer Team ID/团队选择。
- Developer ID Application 证书是否已签发并可访问。
- Developer ID Installer 证书是否已签发并可访问（仅当交付 PKG 时需要）。
- Xcode signing team、自动签名状态、provisioning profile 条件。
- Apple Developer 账号在 Xcode/Notary service 的登录状态。
- notarytool 的 Apple ID/app-specific password、ASC API key 或 profile 凭据是否存在及是否获授权。
- 公证上传是否获用户针对具体产物、目的地和用途的确认。
- 第二台 macOS 26 Apple Silicon 的安装和 Gatekeeper 验收条件。

用户后续需要自行完成或明确授权的动作：

1. 创建正式 OpenLXSSH Xcode App target 后，在 Xcode Signing & Capabilities 中选择正确 Team，固定 Bundle ID，并核对主 App 与 helper 的签名标识。
2. 准备/访问 Developer ID Application；如交付签名 installer，再准备 Developer ID Installer。证书创建、导入、私钥访问和账号安全由用户完成。
3. 通过用户认可的 Apple 登录方式配置公证授权。不要把凭据写入仓库、普通配置或报告；本任务不执行 `store-credentials`。
4. 在正式 Release 产物已生成后，集中确认“提交哪个产物、上传至 Apple 的目的地、用途、允许上传的时间窗口”，再由主管安排实际公证任务。
5. 在目标 macOS 26 与第二台 Mac 上执行安装、启动、Keychain、helper、Gatekeeper/公证和升级验证。

## 5. Apple 官方公开路径与 Bundle 结构

本轮用 Apple Developer 文档的公开 Markdown 入口核对，报告引用这些公开 URL：

- <https://developer.apple.com/documentation/xcode/embedding-a-helper-tool-in-a-sandboxed-app.md>
- <https://developer.apple.com/documentation/bundleresources/placing-content-in-a-bundle.md>
- <https://developer.apple.com/documentation/security/hardened-runtime.md>
- <https://developer.apple.com/documentation/security/app-sandbox.md>
- <https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution.md>
- <https://developer.apple.com/developer-id/>

Apple `Placing content in a bundle` 的公开表格明确列出：

| 内容 | macOS 路径 |
| --- | --- |
| App `Info.plist` | `Contents/Info.plist` |
| 主可执行文件 | `Contents/MacOS/` |
| resources | `Contents/Resources/` |
| framework/dynamic library | `Contents/Frameworks/` |
| helper tool/help app | `Contents/MacOS/` 或 `Contents/Helpers/` |
| XPC Service | `Contents/XPCServices/` |
| privileged helper tool | `Contents/Library/LaunchServices/` |
| Service Management login item | `Contents/Library/LoginItems/` |

Apple 同文档警告：错误 bundle 位置可能造成代码签名/分发问题，开发时能运行不代表 notarization 没有问题；代码位置应保持受支持的扁平布局，不要随意在代码目录下再分组。

### 5.1 OpenLXSSH helper 建议

- 当前架构文档中的 Askpass/认证辅助程序是配套打包的受控程序，不是登录项或 privileged helper 的产品决策。
- 因此，正式项目优先评估 `OpenLXSSH.app/Contents/Helpers/OpenLXSSHAskpass`，并将 helper 作为独立 target/可执行代码构建；如果后续采用 Service Management login item，才使用 `Contents/Library/LoginItems/`，不能仅因“helper”字样混用两种语义。
- Apple 的 sandbox helper 示例通过 Copy Files phase 的 `Executables` 目的地嵌入 `Contents/MacOS/`，并勾选 Code Sign On Copy；此路径是官方可行方案。`Contents/Helpers/` 是 Apple bundle 位置表列出的同样受支持的 helper tool 路径，但最终应在实际 Xcode target、运行时定位和公证流程中确认。
- 运行时路径必须由 bundle URL/API 解析，不拼接用户可控输入；启动前检查文件存在、是否为预期 arm64 Mach-O/可执行文件、版本/identifier 关联、权限与签名状态。不要依赖开发目录、Homebrew 路径或外部绝对路径。
- 签名顺序：构建 helper 和其依赖 → 对每个嵌入代码使用最终分发签名/Code Sign On Copy → 最后签主 App/外层 bundle；任何修改 bundle 内代码、Info.plist 或资源后都要重新签名并重新验证。
- 最终验证至少包括：`codesign --verify --deep --strict --verbose=2 OpenLXSSH.app`；对主 App 和每个 helper 执行 `codesign --display --verbose=4 --entitlements :-`；检查主 App/各 helper identifier、`flags=...runtime`、签名 Authority/Team 摘要、entitlements 和依赖路径。`--deep` 是验证入口，不应替代构建阶段对嵌套代码的显式签名与逐项验证。
- 对正式 Developer ID 产物再运行 `spctl --assess --type execute --verbose=4 OpenLXSSH.app`，并在目标系统做实际启动/辅助程序执行测试。临时 ad hoc fixture 的 `spctl` 拒绝不能用来推断 Developer ID 产物失败。

## 6. Hardened Runtime 与 App Sandbox 路径

### 6.1 Hardened Runtime

Apple 官方 `Hardened Runtime` 文档说明：Hardened Runtime 与 SIP 一起保护运行时完整性，阻止代码注入、动态库劫持和进程内存篡改等类别；在 Xcode target 的 Signing & Capabilities 添加 Hardened Runtime。官方还明确：

- Hardened Runtime 会禁止少数特殊能力（例如 JIT）；只有确需时才启用对应 runtime exception/access entitlement。
- entitlements 只添加到 executables；共享库、framework 和进程内 plug-in 继承 host executable 的 entitlements。
- Boolean entitlement 默认 false；手工签名时只在 true 时写入，false 不应显式写入。
- 上传 macOS app 进行 notarization 必须启用 Hardened Runtime。

OpenLXSSH 当前候选原则：

- 主 App 和必须单独执行的 helper 采用 `codesign --options runtime`（正式 Xcode 构建应由 Hardened Runtime capability 生成等价签名）。
- 原生 libssh2/OpenSSL 等库放到正确的 `Contents/Frameworks/` 或静态链接结果中，具体按 P0-03 依赖分发方案和正式构建产物确定；库本身不凭空添加 App Sandbox/Hardened Runtime entitlement。
- 默认不启用 JIT、unsigned executable memory、disable library validation、DYLD environment、debugger 等 runtime exception；若 PTY/OpenSSH/SFTP 实测证明某个例外绝对必要，必须写出证据、最小范围和安全影响，经主管审查后再纳入。

### 6.2 App Sandbox 候选与最小化

Apple 官方 App Sandbox 文档定义为：通过 entitlements 限制 App 对系统资源和用户数据的访问；该 capability 对 Mac App Store 分发是强制的。即使 Developer ID 分发不自动等同于必须启用 Sandbox，是否启用仍需基于 OpenLXSSH 的功能、用户数据访问、辅助进程和公证/分发目标做正式决策；不能靠关闭系统保护或扩大权限规避问题。

候选 entitlement 只作为待验证清单，不是当前产品配置：

- 基础：`com.apple.security.app-sandbox`。
- 直接出站 SSH/SFTP 网络：`com.apple.security.network.client`。不默认启用 `network.server`，因为 V1.0 不提供监听服务。
- 用户选择文件/目录：优先 `com.apple.security.files.user-selected.read-write`（按 UI 选择和 security-scoped bookmark 设计验证）；不默认 `files.all`，不把整个 Home 目录设为常开权限。
- Keychain：先验证 Security.framework/Keychain 在 App Sandbox + Developer ID 下的访问组、升级/重装和两台 Mac 行为；不要在未证明需求前添加更宽访问组或把秘密落入普通文件。
- 子进程/PTY：验证 App Sandbox 对启动系统 `/usr/bin/ssh`、PTY、`ssh` 的受控参数和子进程继承权限；不要以 `allow-unsigned-executable-memory`、`disable-library-validation` 或关闭 Sandbox 作为“启动成功”捷径。
- Helper：按 Apple 示例为 sandbox helper 评估 `com.apple.security.app-sandbox` + `com.apple.security.inherit` 的最小组合；通过真实执行和错误日志确认是否需要额外能力。不要复制主 App 的全部 entitlement 到 helper。
- 原生库/SFTP：验证动态库加载路径、library validation、文件访问、网络客户端和取消/关闭；不要给库单独伪造 entitlement。

待正式 App 验证的风险：PTY 与 OpenSSH 子进程是否能在选定 Sandbox 配置下正确运行；helper 继承 entitlement 是否支持认证桥接；Keychain 访问组/升级和重装是否稳定；libssh2/OpenSSL 动态/静态分发与 Hardened Runtime/library validation 是否兼容；SFTP 远程操作、临时文件、用户选择目录及安全提交是否满足权限边界。真实验证必须覆盖成功、拒绝、取消、超时、断开和资源回收。

### 6.3 不得采用的绕过

- 不关闭 Gatekeeper、SIP、Hardened Runtime 或系统保护来换取启动。
- 不通过扩大 `files.all`、`disable-library-validation`、unsigned/JIT 等权限掩盖架构问题。
- 不把 ad hoc 签名、临时 fixture、开发机 Xcode 运行成功或 `spctl` 以外的静态输出冒充 Developer ID/公证验收。

## 7. 临时 arm64 fixture 证据（不属于产品）

为验证 bundle layout 和签名入口，在 `/tmp` 创建并自动清理了一次性 `OpenLXSSHFixture.app`：

```text
OpenLXSSHFixture.app/
  Contents/Info.plist
  Contents/MacOS/OpenLXSSHFixture
  Contents/Helpers/OpenLXSSHHelper
  Contents/Library/LoginItems/OpenLXSSHLoginItemHelper
  Contents/Resources/
```

Fixture 使用 `clang -arch arm64` 构建三个最小 Mach-O；生成最小主 App entitlement（Sandbox、网络 client、用户选择读写）和 helper entitlement（Sandbox、inherit），按“先 helper、后主 App”顺序以 ad hoc 身份调用 `codesign --options runtime`，然后执行：

| 检查 | 结果 |
| --- | ---: |
| `clang` 主 App/helper 构建 | rc 0 |
| `plutil` 检查 Info.plist/entitlements | rc 0 |
| helper 签名（`codesign --sign - --options runtime`） | rc 0 |
| login-item 位置 helper 签名 | rc 0 |
| 主 App 签名（`codesign --sign - --options runtime`） | rc 0 |
| `codesign --verify --deep --strict --verbose=2` | rc 0 |
| 主 App/helper `codesign --display --verbose=4 --entitlements :-` | rc 0 |
| 主 App/helper CodeDirectory | `flags=0x10002(adhoc,runtime)`；Team 未设置（预期） |
| `spctl --assess --type execute` | rc 3，fixture 被拒绝；不是 Developer ID |
| `stapler validate` | rc 65，显示没有 stapled ticket；预期 |

这次 fixture 证明：临时 `.app` 的两种 helper 目录可创建；嵌入代码需在外层验证前完成签名；`codesign --options runtime`、entitlements 读取与 `--verify --deep --strict` 入口可复核。它没有证明正式 helper 的运行、Sandbox 兼容、Developer ID、Team、Gatekeeper、公证、Keychain、PTY、OpenSSH 或 SFTP 可用。

## 8. 公证路径（只记录形式，不执行上传）

### 8.1 前置条件

Apple 公证文档明确要求：

- 使用 Developer ID application、kernel extension、system extension 或 installer certificate；不能用 Mac Distribution、ad hoc、Apple Developer 或 local development certificate 代替。
- App 和 command line targets 启用 Hardened Runtime。
- 公证服务扫描代码签名问题/恶意内容；成功后产生 ticket，可在线由 Gatekeeper 查找或 stapler 到产物。
- 目标产物可以是 ZIP、PKG、DMG 等；当前没有正式产物。
- `altool` 与 Xcode 13 或更早版本上传路径已不再接受；使用 `xcrun notarytool`。

### 8.2 公开命令形式（本轮全部未执行上传/凭据写入）

正式产物与用户授权具备后，命令形态为（示意，不在本轮运行）：

```text
# 用户先准备受认可的 notarytool 凭据；本轮不执行 store-credentials
xcrun notarytool submit <confirmed-archive.zip-or-pkg-or-dmg> \
  --keychain-profile <user-approved-profile> \
  --wait

# 查询已授权提交状态（仅在用户确认提交后）
xcrun notarytool info <submission-id> --keychain-profile <user-approved-profile>
xcrun notarytool log <submission-id> --keychain-profile <user-approved-profile>

# 成功后才执行
xcrun stapler staple <confirmed-app-or-package>
xcrun stapler validate <confirmed-app-or-package>
spctl --assess --type execute --verbose=4 <confirmed-app>
```

上面的 `<...>` 占位符不是实际路径、凭据、submission ID、团队或 Bundle ID。不得把示意命令执行结果写成成功。

### 8.3 用户确认门槛

在任何实际 `submit` 前，主管应集中向用户确认：

1. 要上传的具体产物（路径、格式、摘要和对应提交）；
2. Apple 目的地/服务与用途（公证、测试分发还是正式分发）；
3. 用户是否已完成 Apple 登录、Developer ID 访问和公证凭据准备；
4. 是否同意本次网络上传及产物包含的依赖/辅助程序；
5. 上传后结果如何记录，确保报告不含凭据、秘密或不必要的服务器/团队细节。

## 9. 已具备 / 待用户 / 待正式 App 验证清单

### 已具备（本机可复核）

- Apple Silicon arm64 宿主、Xcode 26.3、macOS 26.2 SDK。
- `codesign`/`security`/`xcodebuild`/`xcrun`/`notarytool`/`stapler`/`spctl` 的只读入口及路径解析。
- 1 个 Apple Development 有效身份的数量摘要；没有 Developer ID 身份的摘要。
- Apple helper/bundle placement、Hardened Runtime、App Sandbox、公证的公开文档和命令形式。
- `/tmp` 临时 arm64 `.app`、`Contents/MacOS`、`Contents/Helpers`、`Contents/Library/LoginItems` 布局与 ad hoc runtime 签名验证入口。
- 不关闭 Gatekeeper/SIP/系统保护、不上传 Apple 的边界。

### 待用户操作 / 外部条件

- 正式 OpenLXSSH Xcode App/Target 创建（属于后续阶段，不在 P0-05 创建）。
- Team、Bundle ID、Developer ID Application/Installer 证书和访问条件确认。
- Apple/Xcode 登录和用户认可的公证凭据配置；不由本轮代操作。
- 具体 Release 产物、上传目的地/用途和上传授权确认。
- macOS 26 运行机、第二台 Apple Silicon Mac 的安装/启动/Gatekeeper/升级和人工验收。

### 待正式 App 验证

- 主 App 与 helper 实际 bundle path、Info.plist、identifier、签名嵌套关系与最终路径解析。
- helper 运行时权限、进程归属、取消、超时、退出与资源回收。
- Hardened Runtime + Sandbox 下 PTY/OpenSSH、Keychain、原生库、SFTP、用户选择文件与临时文件行为。
- 最小 entitlements 是否足够；拒绝分支是否可理解；是否需要额外 runtime exception。
- Developer ID 真实签名、`spctl`/Gatekeeper、notarytool 返回结果、stapled ticket 和 `stapler validate`。
- 目标 macOS 26 与第二台 Mac 的安装、启动、升级、卸载/凭据读取及不依赖开发目录。

## 10. 验收对应关系与结论

| P0-05 条件 | 结果 | 证据/限制 |
| --- | --- | --- |
| 本机签名/Xcode/SDK/公证工具入口有复核证据 | 满足 | 第 3 节路径、版本、退出码与安全摘要 |
| Developer ID Application/Installer、Apple Development/Distribution 数量仅作安全摘要 | 满足 | 第 4.1 节；未记录 hash/主体/Team/私钥 |
| Bundle ID/Team/证书/凭据未知项与用户操作项明确 | 满足 | 第 4.2 节；没有正式 App target，未猜测 |
| helper 嵌入路径、签名顺序、entitlement/运行时/最终验证路径明确 | 满足（路径调查） | 第 5 节、临时 fixture；正式 App 未验证 |
| Sandbox/Hardened Runtime 候选、最小化原则与 SSH/PTY/helper/Keychain/native/SFTP 风险明确 | 满足（路径调查） | 第 6 节；未在产品中验证 |
| 公证公开命令形式与上传门槛明确，未执行上传 | 满足（路径调查） | 第 8 节；无提交 ID、无成功结果 |
| 不创建正式 App/产品代码/凭据，不修改系统保护 | 满足 | 工作区只新增本报告及阶段记录；fixture 在 `/tmp` 并自动清理 |
| AC-33 / AC-34 / AC-35 | 未执行 | 没有正式 App、Release 产物、Developer ID 签名、公证或开发机安装验收 |

**阶段结论：P0-05 调查材料完成，并通过主管独立审查，已作为阶段任务通过记录。此结论不改变 AC-33/AC-34/AC-35 的“未执行”，也不代表产品 Release、签名、公证或整体 Goal 完成。**

## 11. 限制与下一步

- 当前宿主为 macOS 15.8.1，低于项目目标 macOS 26；SDK 可用不等于 macOS 26 运行时可用。
- 当前只有 1 个 Apple Development 身份摘要；Developer ID Application/Installer 均为 0；不能进行正式 Release 签名、公证或安装验收。
- 工作区没有正式 App/Xcode target，故不能验证真实 Bundle ID、Team、helper 执行、sandbox profile、Keychain access group、PTY/OpenSSH、原生库、SFTP 或 final `.app` 的深层签名关系。
- 本轮没有联网上传 Apple；没有 `notarytool submit`、`altool`、`store-credentials` 或真实公证结果。
- 下一步由主管独立审查报告、状态和验收记录；若继续到后续阶段，应在正式 App 建立后先制作最小 helper/entitlements target，在隔离环境验证 PTY/OpenSSH/Keychain，再以用户确认的 Developer ID 和具体产物执行 P8 Release 路径。
