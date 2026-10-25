# OpenLXSSH P0-03 依赖清单

更新时间：2026-10-25（Asia/Shanghai）  
Task ID：`P0-03`  
状态：候选核对完成；依赖尚未进入 OpenLXSSH 项目，也不代表任何 SSH/SFTP、终端或数据库产品功能通过。  
核对工作区：`/Users/liuwenshuo/Desktop/OpenLXSSH`  
临时探针根目录：`/tmp/openlxssh-p0-03`（仅用于本轮只读核对和构建，完成记录后清理）

## 1. 结论摘要与边界

- 本轮只核对公开上游来源、版本标签/提交、manifest、许可证、平台要求和本机 Apple Silicon 构建路径；未创建 App/Xcode 项目、`Package.swift`、产品代码或锁文件。
- 本机是 Apple Silicon，宿主 macOS 15.8.1；P0-01 已确认 Xcode 26.3、macOS 26.2 SDK、Swift 6.2.4。以 `arm64-apple-macosx26.0` 做的编译探针只证明源码在当前工具链下可编译，不证明宿主已经运行 macOS 26，也不证明 App 的签名、公证或真实互通。
- SwiftTerm 上游目前观察到的稳定 1.x 候选为 `v1.20.0`；需求指定的 `1.19.x` 起始候选 `v1.19.0` 也已核对。未观察到正式 `v2.x` 标签；`v1.99.1` 的上游发布说明标注为 2.0 前预览，不能当作稳定 2.x 定稿。SwiftTerm 暂定进入 P2 原型比较，不在 P0 固定 API。
- GRDB 暂定候选为 `v7.11.1` 的 `GRDB` 产品，使用上游默认的系统 SQLite 模块；未选择 `GRDB-dynamic`，也未启用自定义 SQLite 或 SQLCipher。GRDB 候选的源码编译探针成功，但迁移/仓储功能尚未实现或验证。
- libssh2 暂定 P3 原型候选为 `libssh2-1.11.1`（剥离提交 `a312b43325e3383c865a87bb1d26cb52e3292641`）+ OpenSSL 后端 + arm64 静态库。Autotools 配置和构建成功，静态链接小探针成功；CMake 源码选项已检查，但本机无 `cmake`，CMake 配置/构建未执行。尚未连接服务器、执行认证或 SFTP。
- libssh2 的一等加密后端是 OpenSSL、wolfSSL、Libgcrypt、mbedTLS、WinCNG；LibreSSL 虽有独立上游，但不在 `libssh2-1.11.1` 的 CMake/Autotools 后端枚举中，不能仅因 macOS 系统 OpenSSH 使用 LibreSSL 就宣称可作为 libssh2 后端。
- 传递依赖只按上游 manifest、`Package.resolved` 和实际构建中发现的公开包记录；“未发现”均只表示本次路径未发现，不能解释为生态中不存在其他可选依赖。

## 2. 固定证据格式

本清单中的上游提交来自只读命令：

```sh
git ls-remote --tags --refs <repository> <tag-ref>
```

对 SwiftTerm、GRDB 和 libssh2 的稳定候选，实际结果如下。命令退出码均为 `0`：

| 组件 | 来源 URL | 标签 | 标签命令输出的对象/提交 | 备注 |
| --- | --- | --- | --- | --- |
| SwiftTerm | <https://github.com/migueldeicaza/SwiftTerm.git> | `v1.19.0` | `464df5207fc2432e16c9a23abe538187196daf5f` | 需求指定的起始评估候选 |
| SwiftTerm | 同上 | `v1.20.0` | `5d14406844143538cd8f8851d2d8a67c1fe443e5` | 本次观察到的稳定 1.x 候选 |
| SwiftTerm | 同上 | `v1.99.1` | `2f573f73af5e768d90847dce20c97fa9535d7164` | 上游标注 2.0 前预览，不是正式 2.x |
| GRDB.swift | <https://github.com/groue/GRDB.swift.git> | `v7.11.1` | `b83108d10f42680d78f23fe4d4d80fc88dab3212` | 稳定标签；`master`/发布分支另行观察 |
| libssh2 | <https://github.com/libssh2/libssh2.git> | `libssh2-1.11.1` | 标签对象 `3a735286108ad19e3b49c64ebcb66342f1f21df7`；剥离提交 `a312b43325e3383c865a87bb1d26cb52e3292641` | 采用发布标签对应的源码提交 |

补充的分支/标签事实：

- SwiftTerm `main`：`c3436be32e3dc26d5e2181b1e451d91e21e50d53`；`git ls-remote --tags --refs ... 'refs/tags/v2*'` 无输出。`v1.99.1` 的发布 Atom 标题为 `Preview before 2.0.`。
- GRDB `master`：`0d8cf958b4b66a0473ec6e6986eb9da462171da9`；`releases/v7.12.0` 分支为 `13e531ec19ef9c2d880a94215f887e3bd5f5fd58`，本次没有观察到对应 `v7.12.0` 稳定标签，因此不作为已发布稳定版。
- libssh2 `master`：`6e7b2076a6ced2230968b27ee7c1abb77fe5a88d`；本次观察到的最高稳定发布标签为 `libssh2-1.11.1`。

## 3. SwiftTerm

### 3.1 来源、版本和许可证

- 上游仓库：<https://github.com/migueldeicaza/SwiftTerm>
- 版本来源：上表的 `v1.19.0`、`v1.20.0`、`v1.99.1` 标签；标签/源码访问命令退出码 `0`。
- 许可证：仓库根目录 `LICENSE` 为 MIT。许可证文件还保留 Miguel de Icaza、xterm.js 作者、SourceLair 和 Christopher Jeffrey 的版权声明；分发时必须保留版权、许可和免责声明。
- 上游文档：
  - 1.x README：<https://github.com/migueldeicaza/SwiftTerm/blob/v1.20.0/README.md>
  - 2.0 迁移文档（位于预览标签源码）：<https://github.com/migueldeicaza/SwiftTerm/blob/v1.99.1/Sources/SwiftTerm/Documentation.docc/MigratingFrom1To2.md>
  - 许可证：<https://github.com/migueldeicaza/SwiftTerm/blob/v1.20.0/LICENSE>

### 3.2 SwiftPM manifest、产品和最低平台

实际命令（均在临时源码目录执行）：

```sh
swift package dump-package \
  --package-path /tmp/openlxssh-p0-03/src/SwiftTerm-v1.19.0 \
  > /tmp/openlxssh-p0-03/src/SwiftTerm-v1.19.0/dump-package.json
# exit 0

swift package dump-package \
  --package-path /tmp/openlxssh-p0-03/src/SwiftTerm-v1.20.0 \
  > /tmp/openlxssh-p0-03/src/SwiftTerm-v1.20.0/dump-package.json
# exit 0

swift package dump-package \
  --package-path /tmp/openlxssh-p0-03/src/SwiftTerm-v1.99.1 \
  > /tmp/openlxssh-p0-03/src/SwiftTerm-v1.99.1/dump-package.json
# exit 0
```

manifest 核对结果：

| 候选 | swift-tools-version | Swift language mode | 最低 macOS | 其他 manifest 平台 | 产品/模块事实 |
| --- | --- | --- | --- | --- | --- |
| `v1.19.0` | 6.0 | `.v5` | 11.0 | iOS 14、tvOS 13、visionOS 1 | `SwiftTerm` 自动库；另有 `SwiftTermFuzz`、`termcast` 可执行产品 |
| `v1.20.0` | 6.0 | `.v5` | 11.0 | iOS 14、tvOS 13、visionOS 1 | 与 1.19 的产品形态相同；本次 dump 成功 |
| `v1.99.1` | 6.2 | `.v6` | 11.0 | iOS 14、tvOS 13、visionOS 1 | `SwiftTerm` 自动库；另有 `SwiftTermFuzz`、`termcast`、预览阶段的 traits/portable 目标 |

`v1.19.0`/`v1.20.0` 的 manifest 依赖声明包含 Apple `swift-argument-parser`（`from: 1.0.0`）和 `swift-docc-plugin`（`from: 1.4.3`）；benchmark 依赖在该 manifest 中由 `disableBenchmark = true` 关闭。`SwiftTerm` library target 本身没有指向这些包的运行时 target 依赖；`ArgumentParser` 只被 `termcast` 使用，DocC 是文档构建插件。

`v1.99.1` 增加 `tayloraswift/swift-png`（`from: 4.5.0`）以及 `PortableGraphics`、`Embedded`、`Wasm` traits。其 `PNG`/`LZ77` target 依赖带有非 Apple 平台条件；macOS 目标的本次构建未将它们作为 SwiftTerm macOS target 的外部运行时库。该事实不能替代最终 App 目标的完整依赖解析审计。

### 3.3 API、PTY 和打包影响

- 1.x README 明确提供 AppKit `TerminalView`、`MacTerminalView`/`LocalProcessTerminalView` 等可复用终端视图和本地进程能力；仓库同时说明 macOS 代码位于 `Mac`，共享终端核心位于 `Sources/SwiftTerm`。
- `v1.19.0` 的 `LocalProcess.swift` 将 `Subprocess` import 放在 `#if false` 中，当前实现使用系统 Foundation/Dispatch 与平台 PTY 能力；这不是对 OpenLXSSH 认证桥接或生命周期设计已满足的证明。
- `v1.99.1` 迁移文档明确指出 2.0 API 变化，包括 `LocalProcess`/`HeadlessTerminal` 的 `directDelivery` 参数、Terminal 读取/命令 API 和 `pasteText(_:)` 等；从 1.x 迁移有真实 API 成本，不能只改版本号。
- SwiftTerm 代码本身不携带 libssh2、OpenSSL 或其他 SSH 加密库；SSH 传输仍按架构文档由系统 OpenSSH 负责。SwiftTerm 的 Apple 图形/文本能力会链接系统框架（如 AppKit、CoreGraphics、Metal、CoreText、ImageIO、QuartzCore、UniformTypeIdentifiers 等），这些不是需要随 App 私自打包的第三方动态库。
- SwiftTerm 的构建工具/文档插件不是运行时产品依赖，但其源码包和锁定信息应在供应链记录中保留。最终 App 只应链接选定的 `SwiftTerm` library target，不应把 `termcast`、fuzz 或文档工具带入产品包。

### 3.4 本机探针

```sh
swift build \
  --package-path /tmp/openlxssh-p0-03/src/SwiftTerm-v1.19.0 \
  --target SwiftTerm \
  --triple arm64-apple-macosx26.0
# exit 0

swift build \
  --package-path /tmp/openlxssh-p0-03/src/SwiftTerm-v1.20.0 \
  --target SwiftTerm \
  --triple arm64-apple-macosx26.0
# exit 0

swift build \
  --package-path /tmp/openlxssh-p0-03/src/SwiftTerm-v1.99.1 \
  --target SwiftTerm \
  --triple arm64-apple-macosx26.0
# exit 0
```

三个探针均在 Xcode 26.3/Swift 6.2.4 工具链上完成；构建产物只在 `/tmp/openlxssh-p0-03`。这证明候选源码在本机指定目标下可编译，不证明 API 已接入 OpenLXSSH、终端行为已通过、PTY/关闭/背压已通过或 macOS 26 实机验收已完成。

### 3.5 SwiftTerm 传递依赖与许可证

候选标签内的 `Package.resolved` 记录如下；这些是上游包的锁定事实，不等于全部会进入 OpenLXSSH 的运行时包：

| 候选 | 传递/工具依赖 | 版本/提交 | 许可证来源与分发影响 |
| --- | --- | --- | --- |
| 1.19/1.20 同系 | `swift-argument-parser` | 1.7.0 / `c5d11a805e765f52ba34ec7284bd4fcd6ba68615` | 上游 `LICENSE.txt` Apache-2.0；1.x 的 `termcast`/工具链用途，不应自动进入 App |
| 1.19/1.20 同系 | `swift-docc-plugin` | 1.4.6 / `e977f65879f82b375a044c8837597f690c067da6` | Apache-2.0；文档构建用途 |
| 1.19/1.20 同系 | `swift-docc-symbolkit` | 1.0.0 / `b45d1f2ed151d057b54504d653e0da5552844e34` | Apache-2.0；DocC 工具传递依赖 |
| 1.99.1 | `h` | 1.0.1 / `aa3626829160917d4378330617971977cbd78f5b` | Apache-2.0；由 `swift-png`/可移植路径引入，尚未证明是 macOS App 运行时依赖 |
| 1.99.1 | `swift-png` | 4.5.1 / `8a0bcd4df5e4b307c804937776a56dd6ecdf6396` | 上游 `LICENSE` Apache-2.0；仅预览版本的可移植图像路径，进入 2.x 原型前重新核对 |

对应锁文件来源：

- `v1.19.0`/`v1.20.0` 标签中的 `Package.resolved`：<https://github.com/migueldeicaza/SwiftTerm/blob/v1.20.0/Package.resolved>
- `v1.99.1` 标签中的 `Package.resolved`：<https://github.com/migueldeicaza/SwiftTerm/blob/v1.99.1/Package.resolved>
- 传递包许可证：各包的 `LICENSE`/`LICENSE.txt`，均以本轮 `curl -LfsS` 读取退出码 `0` 核对。

## 4. GRDB / SQLite

### 4.1 来源、版本和许可证

- 上游仓库：<https://github.com/groue/GRDB.swift>
- 稳定候选：`v7.11.1`，提交 `b83108d10f42680d78f23fe4d4d80fc88dab3212`。
- 上游 README（标签页面）：<https://github.com/groue/GRDB.swift/blob/v7.11.1/README.md>
- 许可证：标签根目录 `LICENSE` 为 MIT；分发 GRDB 源码/二进制时保留版权、许可和免责声明。
- README 的上游要求：iOS 13.0+、macOS 10.15+、tvOS 13.0+、watchOS 7.0+；SQLite 3.20.0+；Swift 6.1+ / Xcode 16.3+。OpenLXSSH 的 macOS 26 基线高于这些最低平台，但这不是数据库迁移、事务和崩溃一致性验收。

### 4.2 SwiftPM 产品和 SQLite 方案

实际命令：

```sh
swift package dump-package \
  --package-path /tmp/openlxssh-p0-03/src/GRDB.swift-v7.11.1 \
  > /tmp/openlxssh-p0-03/src/GRDB.swift-v7.11.1/dump-package.json
# exit 0
```

`dump-package` 及源码 manifest 得到：

- `swift-tools-version: 6.1`，Swift language mode `.v6`。
- 平台最低版本：iOS 13、macOS 10.15、tvOS 13、watchOS 7。
- 产品：`GRDBSQLite`（system library）、`GRDB`（automatic library）、`GRDB-dynamic`（dynamic library）。上游 README 要求只选 `GRDB` 或 `GRDB-dynamic` 之一；本项目暂选 `GRDB`。
- `GRDB` target 依赖 `GRDBSQLite`；其 `Sources/GRDBSQLite/module.modulemap` 为：

  ```text
  module GRDBSQLite [system] {
      header "shim.h"
      link "sqlite3"
      export *
  }
  ```

  `shim.h` include `<sqlite3.h>`，因此默认方案使用目标操作系统提供的 SQLite，不是把一个第三方 SQLite 动态库自动塞入 App。
- manifest 默认设置 `SQLITE_ENABLE_FTS5` 和 `SQLITE_ENABLE_SNAPSHOT`；这是编译宏，不等于本轮已经验证所有 FTS5、快照、迁移或并发行为。
- 上游 `Documentation/CustomSQLiteBuilds.md` 明确写出默认使用目标系统 SQLite，并说明可以用独立 `SQLiteCustom` 工程构建自定义 SQLite。该路径需要 GRDB 源码/子模块和 Xcode framework embedding；文档还警告它与 SwiftPM companion libraries 不兼容。本任务不采用该路径。
- SQLCipher 只是 manifest 注释中的可选改造路径（`SQLCipher.swift`、`SQLITE_HAS_CODEC` 等）；未作为本项目默认依赖，也未核对其许可证和打包，不能把它写进已选依赖。

本机 SQLite 对照事实：

```sh
/usr/bin/sqlite3 --version
# exit 0
# 3.43.2 ... (64-bit)

grep -nE '#define SQLITE_VERSION|#define SQLITE_VERSION_NUMBER' \
  /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/sqlite3.h
# exit 0（匹配到 SDK header 3.51.0 / 3051000）
```

命令分别观察到宿主命令行 SQLite 3.43.2 和 SDK header 3.51.0；它们不是同一个版本层次，不能用 SDK header 版本冒充宿主运行库版本。最终 App 以 macOS 26 为目标时仍需在 macOS 26 运行时复核 SQLite 能力和行为。

### 4.3 本机探针

```sh
swift build \
  --package-path /tmp/openlxssh-p0-03/src/GRDB.swift-v7.11.1 \
  --target GRDB \
  --triple arm64-apple-macosx26.0
# exit 0；有 Swift 6.2 Sendable 警告，未作为错误

/usr/bin/clang -arch arm64 -mmacosx-version-min=26.0 \
  -I/tmp/openlxssh-p0-03/src/GRDB.swift-v7.11.1/Sources/GRDBSQLite \
  /tmp/openlxssh-p0-03/grdb-sqlite-probe.c -lsqlite3 \
  -o /tmp/openlxssh-p0-03/grdb-sqlite-probe
# exit 0

/tmp/openlxssh-p0-03/grdb-sqlite-probe
# exit 0；输出 3.43.2
```

GRDB Swift target 构建成功，日志中有 `FetchableRecord.swift` 关于 `Any` 不符合 `Sendable` 的警告；本轮没有改上游源码或降低检查。C SQLite 链接探针为 arm64 Mach-O，运行得到本机 SQLite 3.43.2。上述结果只证明编译/链接路径可行，不证明 OpenLXSSH 的数据库 schema、迁移、仓储、Keychain 引用一致性或崩溃恢复。

### 4.4 GRDB 分发和风险

- 选 `GRDB` 自动库可避免额外动态框架的独立签名/嵌入路径；最终 Xcode/SwiftPM 产物仍需检查实际链接形态和 App 签名。
- 默认 `GRDBSQLite` 通过 `-lsqlite3` 使用系统组件；不应把开发机 Homebrew SQLite 路径写入产品运行时。系统组件由操作系统提供，App 不应复制或重新分发系统 `libsqlite3` 作为第三方私有库。
- 若未来选择自定义 SQLite，需要将 SQLite 源码/子模块、配置宏、链接方式、许可证、架构、签名和 Hardened Runtime 一起重新评估；不能只切换一个宏。SQLite 上游版权/公有领域说明应从 <https://www.sqlite.org/copyright.html> 与选定源码包复核；本轮未把自定义 SQLite 当作已选依赖。
- `GRDB-dynamic` 只有在多个 target 共享一次动态框架并完成签名/嵌入验证时才有理由使用；当前没有 App target，不能提前断言动态方案更优。

## 5. libssh2 / SFTP 后端

### 5.1 来源、版本和主许可证

- 上游仓库：<https://github.com/libssh2/libssh2>
- 发布标签：`libssh2-1.11.1`；标签对象 `3a735286108ad19e3b49c64ebcb66342f1f21df7`，剥离提交 `a312b43325e3383c865a87bb1d26cb52e3292641`。
- 发布压缩包：<https://www.libssh2.org/download/libssh2-1.11.1.tar.gz>
- 本次下载命令退出码 `0`；临时压缩包 SHA-256：`d9ec76cbe34db98eec3539fe2c899d26b0c837cb3eb466a56b0f109cabf658f7`。
- `COPYING`、源文件 SPDX 注释以及 `REUSE.toml` 指向 BSD-3-Clause。仓库还包含 `LICENSES/` 下 BSD-2-Clause、BSD-3-Clause、MIT、curl、FSFULLR、SAX-PD-2.0 等文件级许可证，分发时应按实际打包文件保留完整 notices；不能只复制一个简化版权字符串。
- 上游构建/安装说明：
  - <https://github.com/libssh2/libssh2/blob/libssh2-1.11.1/docs/INSTALL_CMAKE.md>
  - <https://github.com/libssh2/libssh2/blob/libssh2-1.11.1/docs/INSTALL_AUTOTOOLS>
  - <https://github.com/libssh2/libssh2/blob/libssh2-1.11.1/CMakeLists.txt>

### 5.2 CMake/Autotools 事实

源码检查结果：

- `CMakeLists.txt` 的 `cmake_minimum_required(VERSION 3.7)`；`BUILD_STATIC_LIBS` 和 `BUILD_SHARED_LIBS` 都可配置，源码默认两个选项为 ON（文档的默认说明也如此）。
- `CRYPTO_BACKEND` 可选 `OpenSSL`、`wolfSSL`、`Libgcrypt`、`WinCNG`、`mbedTLS`，空值表示按可用库探测；CMake 会链接对应的 `libcrypto`、`wolfssl`、`libgcrypt` 或 `mbedcrypto` 等。
- Autotools 的 `./configure --help` 退出码 `0`，提供 `--with-crypto=auto|openssl|libgcrypt|mbedtls|wincng|wolfssl` 和对应 prefix 选项；同样没有 LibreSSL 选项。
- 上游 CMake/安装文档明确说 libssh2 需要 CMake 3.7+ 和上述加密库之一，默认可构建静态库并使用可用后端。本文不把 CMake 默认配置视为 OpenLXSSH 的最终构建设置。

本机 CMake 限制：

```sh
cmake -S /tmp/openlxssh-p0-03/libssh2-build/libssh2-1.11.1 \
  -B /tmp/openlxssh-p0-03/libssh2-build/cmake-arm64 \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=26.0 \
  -DCRYPTO_BACKEND=OpenSSL \
  -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3 \
  -DBUILD_TESTING=OFF -DBUILD_EXAMPLES=OFF
# exit 127：本机没有 cmake 命令；未安装 cmake/ninja/pkg-config
```

因此本轮只有 CMake 源码选项核对，没有 CMake configure/build 通过结论。

### 5.3 Apple Silicon 构建探针

本机已有 Xcode clang、Autotools 生成的发布 `configure` 和 `make`，未安装系统工具。使用临时发布源码执行：

```sh
cd /tmp/openlxssh-p0-03/libssh2-build/autotools-arm64

env CC=/usr/bin/clang \
  CFLAGS='-arch arm64 -mmacosx-version-min=26.0' \
  LDFLAGS='-arch arm64 -mmacosx-version-min=26.0' \
  /tmp/openlxssh-p0-03/libssh2-build/libssh2-1.11.1/configure \
  --host=arm-apple-darwin \
  --with-crypto=openssl \
  --with-libssl-prefix=/opt/homebrew/opt/openssl@3 \
  --disable-shared --enable-static \
  --disable-examples-build --disable-docker-tests --disable-sshd-tests
# exit 0

make V=1 -j2
# exit 0
```

configure summary 实际显示：版本 1.11.1、Host `arm-apple-darwin`、Compiler `/usr/bin/clang`、flags `-arch arm64 -mmacosx-version-min=26.0`、Shared=no、Static=yes、Crypto library=OpenSSL、zlib compression=yes。`src/.libs/libssh2.a` 及其对象文件经 `file` 识别为 arm64 Mach-O object/archive。

静态链接和运行探针：

```sh
/usr/bin/clang -arch arm64 -mmacosx-version-min=26.0 \
  -I/tmp/openlxssh-p0-03/libssh2-build/libssh2-1.11.1/include \
  /tmp/openlxssh-p0-03/libssh2-link-probe.c \
  /tmp/openlxssh-p0-03/libssh2-build/autotools-arm64/src/.libs/libssh2.a \
  /opt/homebrew/opt/openssl@3/lib/libssl.a \
  /opt/homebrew/opt/openssl@3/lib/libcrypto.a \
  -lz -framework Security -framework CoreFoundation \
  -o /tmp/openlxssh-p0-03/libssh2-link-probe
# exit 0

/tmp/openlxssh-p0-03/libssh2-link-probe
# exit 0；输出 1.11.1
```

链接产物为 arm64 Mach-O 可执行文件；`otool -L` 只显示 `/usr/lib/libz.1.dylib`、系统 `Security.framework`、`CoreFoundation.framework` 和 `libSystem`，没有 Homebrew OpenSSL 动态库依赖，说明本次小探针确实采用了 OpenSSL 静态档案。它不代表最终 App 可以直接复制该临时路径：正式方案必须固定 OpenSSL 源码/构建 hash，审计所有许可和 notices，并对主 App/原生库执行签名、加载路径和 Hardened Runtime 验证。

### 5.4 Keyboard-Interactive 与 SFTP API 事实

上游 API 文档（命令 `curl -LfsS <raw URL>` 均退出码 `0`）：

- Keyboard-Interactive：<https://github.com/libssh2/libssh2/blob/libssh2-1.11.1/docs/libssh2_userauth_keyboard_interactive_ex.3>
  - `libssh2_userauth_keyboard_interactive_ex` 接收响应回调。
  - 回调收到 name、instruction、`num_prompts`、`LIBSSH2_USERAUTH_KBDINT_PROMPT` 数组和待填充的 response 数组；库会把响应发送给主机并释放字符串。
  - 文档明确服务器可能发出一个“password” challenge，但协议并不要求这种形式；smartcard 等方案也可能使用 keyboard-interactive。因此不能按提示文字自动猜测长期密码/OTP。
  - 非阻塞时可能返回 `LIBSSH2_ERROR_EAGAIN`；回调、取消、线程/队列和资源所有权必须在 Swift 适配层建模。
- SFTP：<https://github.com/libssh2/libssh2/blob/libssh2-1.11.1/docs/libssh2_sftp_open_ex.3>
  - `libssh2_sftp_open_ex` 支持远端文件/目录、路径长度、读写/创建 flags、POSIX mode 和 open type。
  - 文档列出协议错误、超时和 `LIBSSH2_ERROR_EAGAIN` 等错误/非阻塞语义。
- 重命名：<https://github.com/libssh2/libssh2/blob/libssh2-1.11.1/docs/libssh2_sftp_rename_ex.3>
  - `libssh2_sftp_rename_ex` 支持源/目的路径、长度和 `LIBSSH2_SFTP_RENAME_*` flags。
  - `OVERWRITE` 未设置且目标存在时操作失败；原子 rename/native syscall flags 是远端偏好而非保证，不能把普通 SFTP rename 写成跨服务器事务保证。

这些是 C API 的可用性事实，不是 OpenLXSSH `RemoteFileService` 已实现，也没有证明所有服务器认证组合、特殊文件名、取消和文件完整性。

## 6. libssh2 加密后端候选与分发影响

本节同时记录已核对的候选标签和许可证；“可构建”只有 OpenSSL 在本机完成，其他后端没有在本机安装或构建，均为源码/许可证候选，不能写成已验证互通。

| 后端 | 上游候选标签/提交（本轮只读） | 许可证证据 | 分发/风险判断 | 当前状态 |
| --- | --- | --- | --- | --- |
| OpenSSL | `openssl-3.6.5` / `e5c234b0c471a676ae6141d2f157df61eb293477`；本机 Homebrew arm64 为 3.6.3 | 标签 `LICENSE.txt` Apache-2.0；<https://github.com/openssl/openssl/blob/openssl-3.6.5/LICENSE.txt> | Apache-2.0 相对适合 App 分发；静态链接可避免单独 dylib，但要保留 notices、固定源码/构建 hash，并复核 OpenSSL 3 API、模块/FIPS 状态和签名 | **本机 Autotools/静态链接已验证；P3 仍待原型固定** |
| mbedTLS | `v3.6.7` / `da6a8c7b9b8e0c1e236deef2910642657db1a7ec` | 精确标签 `LICENSE` 说明 Apache-2.0 OR GPL-2.0-or-later；<https://github.com/Mbed-TLS/mbedtls/blob/v3.6.7/LICENSE> | 选择 Apache-2.0 路径需保存许可/第三方文件并核对文件级例外；未在本机安装/构建，不能宣称 API、arm64 或 libssh2 组合已通过 | 候选，未验证构建 |
| wolfSSL | `v5.8.4-stable` / `b6fbfad945d4b98fce619b6e5b6561b3eca1205b` | 公共仓库 `COPYING` 为 GPL-3.0；<https://github.com/wolfSSL/wolfssl/blob/v5.8.4-stable/COPYING> | 可能存在商业/双许可，但本轮未取得或验证商业授权；GPL 分发和静态链接边界是高风险，未取得适用授权前不选 | 候选，未验证构建/授权 |
| Libgcrypt | `libgcrypt-1.11.3` / `01b9cca145e627f7163713974859631baa6e4244` | `COPYING.LIB` 为 LGPL-2.1-or-later；<https://github.com/gpg/libgcrypt/blob/libgcrypt-1.11.3/COPYING.LIB> | 还需带上/核对 libgpg-error 等传递依赖、静态/动态链接义务和 App notices；本轮未解析/构建 | 候选，未验证构建 |
| LibreSSL | `v4.4.0` / `05a68abffedd17c376759181ea40f807219251c9` | 上游 `COPYING` 混合 ISC、OpenSSL/原始 SSLeay 文本；<https://github.com/libressl/portable/blob/v4.4.0/COPYING> | `libssh2-1.11.1` CMake/Autotools 没有 LibreSSL backend 选项；需要兼容层/补丁和完整算法测试，不因系统 OpenSSH 使用 LibreSSL 而复用 | 记录为未采用候选 |
| WinCNG | libssh2 源码支持 Windows CNG | 由 Windows 系统组件提供，非 macOS App 依赖 | macOS/arm64 目标不适用 | 排除 |

OpenSSL、mbedTLS、wolfSSL、Libgcrypt、LibreSSL 的版本标签命令均通过 `git ls-remote --tags --refs` 返回退出码 `0`；许可证 URL 的 `curl -LfsS` 返回退出码 `0`。许可证核对不等于法律意见，正式发行前仍需对实际编译文件、构建脚本、测试/示例是否进入产物做软件物料清单（SBOM）和许可证审查。

## 7. 供应链、锁定与打包规则

### 7.1 当前候选的运行时依赖边界

| 依赖 | 来源/锁定方式 | 是否预期随 App 打包 | 备注 |
| --- | --- | --- | --- |
| SwiftTerm | SPM URL + 通过原型选定的 tag/源码提交；最终提交 `Package.resolved` | Swift 源码随 App 编译，通常不单独带第三方 dylib；系统 Apple framework 由 macOS 提供 | 只引入 `SwiftTerm` library target；不要把 termcast/fuzz/DocC 工具带入 App |
| GRDB | SPM URL + `v7.11.1`/最终 hash；最终提交 `Package.resolved` | GRDB Swift 源码编译进 App；默认 `GRDBSQLite` 链接系统 `sqlite3`，不复制 Homebrew SQLite | 自定义 SQLite/SQLCipher 是不同依赖方案，需重新建账 |
| libssh2 | 源码 tag + 剥离 commit + 加密后端源码/构建 hash；不依赖未锁定 Homebrew 路径 | 建议 P3 原型确认后将 libssh2 与选定 crypto backend 作为源码静态库或经过审计的 XCFramework/静态 framework 嵌入并签名 | 不应让朋友的 Mac 依赖开发机 Homebrew；若动态库方案，必须嵌入、签名、设置 `@rpath` 并检查加载 |
| OpenSSL（暂定） | 固定 tag、源码 hash、编译器/SDK、编译 flags；本机 Homebrew 仅作探针输入 | 不能依赖 `/opt/homebrew`; 静态链接是当前首选候选，最终以 Xcode/SPM 原型和许可审查为准 | OpenSSL 可能有额外模块/配置文件；确认最终只带所需内容 |
| 系统 OpenSSH/PTY | macOS 系统组件，按 P0-01 记录实际 `/usr/bin/ssh`/`sftp` 版本；不能像 SPM 一样锁定 | 不打包系统二进制 | OS 升级回归认证、PTY、签名和参数控制；与 libssh2 不共享加密库假设 |
| 系统 SQLite | macOS SDK/运行时 `sqlite3` | 不打包系统库 | 需以目标 macOS 26 运行时复核，不使用宿主 macOS 15 作为最终结论 |

### 7.2 版本锁定和供应链要求

P1/P2/P3 原型确定后，必须：

1. 把 SwiftTerm、GRDB 的 URL、版本规则和最终解析提交写入 App 的 `Package.resolved`；审查包的 manifest、源代码许可证和构建脚本，不只看版本字符串。
2. 把 libssh2、crypto backend 的上游 tag、剥离 commit、源码归档 SHA-256、编译器/Xcode/SDK、目标 triple、CMake/Autotools 选项和 patch 列为机器可复核的构建输入；没有 CMake wrapper 或 Xcode target 之前不把 Homebrew prefix 写进产品构建。
3. 在 CI/Release 前生成依赖清单或 SBOM，包含直接依赖和实际进入 App 的传递依赖；许可证 notices 随 App 文档/关于页面/发行物料按产品方案提供。
4. 对源代码构建使用干净临时目录和网络受限/可审计的来源；不从工作站未记录的缓存、Homebrew 当前 symlink 或未锁定 branch 取生产依赖。
5. 对静态链接重新确认许可要求：静态链接 OpenSSL/其他 crypto 不会把第三方许可和版权义务“消失”；动态库也不能靠签名替代许可证 notices。

### 7.3 打包路径建议（待后续原型）

- SwiftPM 依赖：在正式 Xcode target 中只声明产品依赖，提交 `Package.resolved`；Release 使用干净 DerivedData，确认生成的 App 不回指源码目录或 Homebrew。
- libssh2/crypto：优先验证源码静态库到 Xcode target 的路径；若静态库无法满足符号、架构或许可证要求，再比较 XCFramework/静态 framework。无论哪种方式，最终 `.app` 应只含 arm64、部署目标 macOS 26，并由 Xcode 统一签名/检查链接。
- 动态库方案只在有明确理由时使用：库和 App 一起放入 `Frameworks`/受控子目录，使用 `@rpath`，执行 `codesign --verify`、`otool -L`、隔离 `.app` 启动和 Hardened Runtime 检查；不通过关闭系统保护解决加载问题。
- OpenSSL 的静态/动态选择须在 P3 真实 SFTP 原型前固定；本轮的 Autotools 静态库只证明一条可行路径，未验证最终 Xcode 签名和公证。

## 8. 下一阶段可执行建议

- P1/P2：先建立最小正式 App/原型 target，在 SwiftTerm `v1.20.0` 和 `v1.99.1` 上用同一套终端/PTY/关闭/输入压力测试；若 2.0 预览 API 的线程/背压/生命周期没有明确收益，优先保留稳定 1.x；若选择预览，必须把迁移 guide 和实际 API 差异写入后续 ADR。等正式 SwiftTerm 2.x 标签出现后再重新核对，不把 `v1.99.1` 改称 2.0 stable。
- P3：建立 `RemoteFileService` 最小适配层，使用 libssh2 1.11.1 + OpenSSL 暂定组合，先证明 host-key、password/public-key/keyboard-interactive、SFTP 列目录/读写/rename/取消和资源释放；不得用 CLI 演示替代库适配器验收。
- P3：把 libssh2 与 OpenSSL 从 Homebrew 探针路径迁移到可重复的 Xcode/源码构建。固定源码哈希、arm64/macOS 26 deployment target、静态/动态方案、符号可见性、编译警告、签名和 notices；对选定后端运行 `otool -L`、`file`、`codesign --verify` 和隔离 `.app` 启动检查。
- P3：若 OpenSSL 的许可/体积/构建维护不合适，分别以同一测试矩阵重跑 mbedTLS 或 Libgcrypt；wolfSSL 先解决适用商业许可，LibreSSL 先证明 libssh2 后端兼容实现，均不能只因“能编译”替换。
- P4：GRDB `GRDB` 产品接入后固定 `Package.resolved`，另测迁移、事务、异常中断、重启、系统 SQLite 版本差异和 Keychain 引用一致性；不要把本清单的 compile probe 写成仓储功能完成。
- P8：Release 前在干净 Mac/目标 macOS 26 上验证 App 启动不依赖开发机 Homebrew、系统配置或临时目录，补齐所有第三方 notices、签名、公证和第二台 Mac 验收。

## 9. 本轮未验证和明确排除

- 未创建或修改 App、Xcode 工程、Swift Package、产品源代码、测试 target 或 `Package.resolved`。
- 未运行真实 SSH/SFTP 服务器、认证、Keyboard-Interactive、OTP、主机密钥信任、文件传输或取消场景。
- 未证明 SwiftTerm 的终端显示、输入法、Unicode、TUI、背压、PTY 资源释放或嵌套 SSH 可用。
- 未证明 GRDB 的 schema、迁移、事务、并发、崩溃一致性、Keychain 联动或数据库删除语义。
- 未执行 libssh2 CMake 构建（本机无 cmake，退出 127）；未在本机编译/链接 mbedTLS、wolfSSL、Libgcrypt 或 LibreSSL 后端。
- 未进行 Xcode `.app`、XCFramework、签名、公证、Sandbox/Hardened Runtime 或第二台 Mac 验收；P0-05 的签名/Sandbox 调查不在本任务范围。
- 未读取凭据、连接服务器、安装系统工具/虚拟机或设置 Git remote/push。
