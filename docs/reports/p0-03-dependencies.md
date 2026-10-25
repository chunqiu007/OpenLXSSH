# P0-03 依赖核对与构建探针报告

- Task ID：`P0-03`
- 工作区：`/Users/liuwenshuo/Desktop/OpenLXSSH`
- 核对日期：2026-10-25（Asia/Shanghai）
- 执行者：`software-engineer`；主管独立复核：Primary Agent
- 报告状态：范围内核对完成；不代表 OpenLXSSH 的 SSH、SFTP、终端、数据库、签名或 Release 功能已通过。

## 1. 范围、环境与证据边界

本任务只核对 SwiftTerm、GRDB、libssh2 及其加密后端候选的公开来源、标签/提交、许可证、SwiftPM 或原生构建输入、Apple Silicon 编译路径和打包风险。没有创建 App/Xcode 项目、`Package.swift`、产品源代码、测试 target 或 `Package.resolved`，没有安装缺失工具，没有连接服务器，也没有读取凭据。

P0-01 已记录当前环境：Apple Silicon `arm64`、宿主 macOS 15.8.1 (Build 24H32)、Xcode 26.3 (17C529)、macOS 26.2 SDK、Swift 6.2.4、Apple Clang 17.0.0。所有 `arm64-apple-macosx26.0` 编译只证明当前工具链能够生成该 deployment target 的产物；宿主不是 macOS 26，因此不构成 macOS 26 运行时验收。

本轮临时源码、构建目录和日志位于 `/tmp` 下的随机目录，探针结束后已清理；工作区不包含临时产物。

## 2. 主管独立复核结论

主管读取了以下实际改动：

- `docs/dependencies.md`
- `docs/adr/p0-03-swifterm-version-candidate.md`
- `docs/adr/p0-03-libssh2-crypto-backend.md`
- `ENGINEERING_STATE.md`

主管独立复跑了上游标签核对、三类构建探针、许可证/API 文档抓取和工作区边界检查。结果与依赖清单及 ADR 一致，没有发现秘密进入工作区，也没有把编译探针误写成产品功能通过。

## 3. 上游来源与版本核对

执行目录：`/Users/liuwenshuo/Desktop/OpenLXSSH`；以下只读 `git ls-remote` 命令均退出码 `0`。

```sh
git ls-remote --tags --refs \
  https://github.com/migueldeicaza/SwiftTerm.git \
  'refs/tags/v1.19.0' 'refs/tags/v1.20.0' 'refs/tags/v1.99.1'

git ls-remote --tags --refs \
  https://github.com/groue/GRDB.swift.git \
  'refs/tags/v7.11.1'

git ls-remote --tags --refs \
  https://github.com/libssh2/libssh2.git \
  'refs/tags/libssh2-1.11.1'
```

实际版本事实：

| 组件 | 候选 | 实际 ref/hash | 状态 |
| --- | --- | --- | --- |
| SwiftTerm | `v1.19.0` | `464df5207fc2432e16c9a23abe538187196daf5f` | 需求指定的 1.19.x 起始候选 |
| SwiftTerm | `v1.20.0` | `5d14406844143538cd8f8851d2d8a67c1fe443e5` | 本次观察到的稳定 1.x 候选 |
| SwiftTerm | `v1.99.1` | `2f573f73af5e768d90847dce20c97fa9535d7164` | 上游标为 2.0 前预览，不是稳定 v2 |
| GRDB.swift | `v7.11.1` | `b83108d10f42680d78f23fe4d4d80fc88dab3212` | 稳定候选 |
| libssh2 | `libssh2-1.11.1` | 标签对象 `3a735286108ad19e3b49c64ebcb66342f1f21df7`；剥离提交 `a312b43325e3383c865a87bb1d26cb52e3292641` | 稳定发布候选 |

依赖清单还记录了 SwiftTerm `main`、GRDB `master`/发布分支和 libssh2 `master`，但未把分支当作生产锁定输入。SwiftTerm 正式 `v2.x` 标签查询没有返回结果；因此 `v1.99.1` 不改称稳定 2.x。

## 4. SwiftTerm 证据

### 4.1 manifest、API 和许可证

来源：

- <https://github.com/migueldeicaza/SwiftTerm>
- <https://github.com/migueldeicaza/SwiftTerm/blob/v1.20.0/README.md>
- <https://github.com/migueldeicaza/SwiftTerm/blob/v1.20.0/LICENSE>
- <https://github.com/migueldeicaza/SwiftTerm/blob/v1.99.1/Sources/SwiftTerm/Documentation.docc/MigratingFrom1To2.md>

三个标签的 `swift package dump-package` 均退出码 `0`。manifest 摘要：

- `v1.19.0`、`v1.20.0`：Swift tools 6.0、Swift language mode v5、最低 macOS 11；提供 `SwiftTerm` 自动库，另有工具/测试相关产品。
- `v1.99.1`：Swift tools 6.2、Swift language mode v6、最低 macOS 11；加入预览阶段 traits 和 `swift-png` 路径。
- 1.x manifest 的 `swift-argument-parser`、DocC plugin 和 symbolkit 主要服务工具/文档；正式 App 只应引入 `SwiftTerm` library target。
- `v1.99.1` 迁移文档记录了 `LocalProcess`/`HeadlessTerminal` 的 `directDelivery`、读取接口和 `pasteText(_:)` 等 API 变化，不能只改版本号假设兼容。
- 根许可证为 MIT；传递工具/文档包的上游许可证在依赖清单中记录为 Apache-2.0。正式发布时仍需按最终解析结果生成 notices/SBOM。

### 4.2 独立构建探针

在临时目录分别执行：

```sh
swift package dump-package --package-path <SwiftTerm-v1.19.0>
swift build --package-path <SwiftTerm-v1.19.0> \
  --target SwiftTerm --triple arm64-apple-macosx26.0

swift package dump-package --package-path <SwiftTerm-v1.20.0>
swift build --package-path <SwiftTerm-v1.20.0> \
  --target SwiftTerm --triple arm64-apple-macosx26.0

swift package dump-package --package-path <SwiftTerm-v1.99.1>
swift build --package-path <SwiftTerm-v1.99.1> \
  --target SwiftTerm --triple arm64-apple-macosx26.0
```

六条命令实际均退出码 `0`。这只证明候选源码在当前 Xcode/Swift 工具链和指定目标下可编译，不证明终端显示、PTY、输入、历史、背压、关闭竞态或嵌套 SSH 已通过。

## 5. GRDB / SQLite 证据

来源：

- <https://github.com/groue/GRDB.swift>
- <https://github.com/groue/GRDB.swift/blob/v7.11.1/README.md>
- <https://github.com/groue/GRDB.swift/blob/v7.11.1/LICENSE>
- <https://github.com/groue/GRDB.swift/blob/v7.11.1/Documentation/CustomSQLiteBuilds.md>

`v7.11.1` 的 `swift package dump-package` 和 `swift build --target GRDB --triple arm64-apple-macosx26.0` 均退出码 `0`。manifest/源码事实：

- Swift tools 6.1、Swift language mode v6、最低 macOS 10.15；上游 README 还记录 Swift 6.1+/Xcode 16.3+ 与 SQLite 3.20.0+ 要求。
- SwiftPM 产品包含 `GRDBSQLite`、`GRDB` 和 `GRDB-dynamic`；本项目暂选 `GRDB`，不提前选动态产品。
- `GRDBSQLite` modulemap 链接 `sqlite3`，默认使用目标系统 SQLite；没有把 Homebrew SQLite 当作发行时依赖。
- 上游根许可证为 MIT。自定义 SQLite/SQLCipher 是不同依赖方案，本轮未选、未构建，也未把其许可证或打包义务写成已完成事实。
- 构建日志存在 Swift 6.2 `Sendable` 警告；本轮没有改上游代码或降低检查，也没有把警告隐藏为通过。

独立 C 探针：

```sh
/usr/bin/clang -arch arm64 -mmacosx-version-min=26.0 \
  <sqlite-probe.c> -lsqlite3 -o <sqlite-probe>
<sqlite-probe>
file <sqlite-probe>
```

编译和运行均退出码 `0`，输出宿主 SQLite `3.43.2`，产物为 arm64 Mach-O。该版本是当前宿主运行库事实，不替代 macOS 26 运行时复核；SDK header 与宿主库版本也不能混写成一个版本。

## 6. libssh2 / crypto backend 证据

来源：

- <https://github.com/libssh2/libssh2>
- <https://github.com/libssh2/libssh2/blob/libssh2-1.11.1/COPYING>
- <https://github.com/libssh2/libssh2/blob/libssh2-1.11.1/CMakeLists.txt>
- <https://github.com/libssh2/libssh2/blob/libssh2-1.11.1/docs/INSTALL_CMAKE.md>
- <https://github.com/libssh2/libssh2/blob/libssh2-1.11.1/docs/INSTALL_AUTOTOOLS>
- <https://github.com/openssl/openssl/blob/openssl-3.6.5/LICENSE.txt>

libssh2 发行压缩包下载退出码 `0`，独立 SHA-256 为：

`d9ec76cbe34db98eec3539fe2c899d26b0c837cb3eb466a56b0f109cabf658f7`

许可证/API 只读抓取实际退出码均为 `0`：SwiftTerm MIT、GRDB MIT、libssh2 BSD-3-Clause、OpenSSL Apache-2.0 的许可标记均存在；`libssh2_userauth_keyboard_interactive_ex`、`libssh2_sftp_open_ex` 和 `libssh2_sftp_rename_ex` 文档抓取成功。Keyboard-Interactive 文档说明挑战不能仅按 `Password:` 文本猜测，SFTP rename 文档也不保证跨服务器事务原子性；这些事实已写入依赖清单和 ADR。

源码/CMake 选项核对：

- `cmake_minimum_required(VERSION 3.7)`。
- 支持 `BUILD_STATIC_LIBS`、`BUILD_SHARED_LIBS` 和显式 `CRYPTO_BACKEND`。
- 后端枚举为 OpenSSL、wolfSSL、Libgcrypt、mbedTLS、WinCNG；本版本没有 LibreSSL 直接选项。
- Autotools `./configure --help` 退出码 `0`，支持 `--with-crypto=auto|openssl|libgcrypt|mbedtls|wincng|wolfssl`。

### 6.1 独立 Autotools/静态链接探针

临时解包源码后执行：

```sh
env CC=/usr/bin/clang \
  CFLAGS='-arch arm64 -mmacosx-version-min=26.0' \
  LDFLAGS='-arch arm64 -mmacosx-version-min=26.0' \
  <libssh2>/configure \
  --host=arm-apple-darwin \
  --with-crypto=openssl \
  --with-libssl-prefix=/opt/homebrew/opt/openssl@3 \
  --disable-shared --enable-static \
  --disable-examples-build --disable-docker-tests --disable-sshd-tests
make V=1 -j2
/usr/bin/clang -arch arm64 -mmacosx-version-min=26.0 \
  -I<libssh2>/include <probe.c> \
  src/.libs/libssh2.a \
  /opt/homebrew/opt/openssl@3/lib/libssl.a \
  /opt/homebrew/opt/openssl@3/lib/libcrypto.a \
  -lz -framework Security -framework CoreFoundation \
  -o <probe>
<probe>
file <probe>
otool -L <probe>
```

实际结果：

- `configure`：退出码 `0`。
- `make V=1 -j2`：退出码 `0`。
- 静态链接：退出码 `0`。
- 运行：退出码 `0`，输出 `1.11.1`。
- `file`：arm64 Mach-O。
- `otool -L` 只显示系统 zlib、Security、CoreFoundation 和 libSystem；未显示 Homebrew OpenSSL 动态库，说明该小探针使用了 OpenSSL 静态档案。

这不是最终 App 方案：正式构建不能依赖 `/opt/homebrew` 运行时路径，必须固定 OpenSSL 源码/构建 hash、编译选项、许可证 notices、签名和 Hardened Runtime。

### 6.2 CMake 与替代后端限制

实际 CMake 命令使用 arm64/macOS 26 deployment target、`-DCRYPTO_BACKEND=OpenSSL` 和 `-DBUILD_TESTING=OFF`；退出码 `127`，原因是本机未安装 `cmake`。按授权没有安装 `cmake`、`ninja` 或 `pkg-config`，因此 CMake configure/build 未验证。

mbedTLS、wolfSSL、Libgcrypt、LibreSSL 未完成本机 libssh2 组合构建：

- mbedTLS：Apache-2.0 OR GPL-2.0-or-later，需选择适用许可路径。
- Libgcrypt：LGPL-2.1-or-later，并需审查 libgpg-error 等传递依赖。
- wolfSSL：公共 `COPYING` 为 GPL-3.0；未取得商业/双许可证明前不采用。
- LibreSSL：混合 ISC/OpenSSL/原始 SSLeay 文本，且不是 libssh2 1.11.1 的直接 backend 选项，不因系统 OpenSSH 使用 LibreSSL 就复用。

## 7. 依赖与分发决策

两个 ADR 已写入：

- `docs/adr/p0-03-swifterm-version-candidate.md`：SwiftTerm 暂不在 P0 固定；P2 同时比较稳定 `v1.20.0` 与 2.0 前预览 `v1.99.1`，若正式 v2 标签出现则重新加入矩阵；默认倾向稳定 1.x，不能锁定 `main`。
- `docs/adr/p0-03-libssh2-crypto-backend.md`：P3 初始组合为 libssh2 1.11.1 + OpenSSL 3.x，优先验证 arm64 静态库/Xcode target；不使用自动后端探测，不依赖 Homebrew 运行时；替代后端需同一测试矩阵和许可审查。

后续必须把 SwiftTerm/GRDB 的最终解析提交写入 `Package.resolved`，把 libssh2/crypto 源码 tag、commit、归档 SHA-256、编译器/SDK/flags 和 patch 纳入可复核构建输入；Release 前生成实际 SBOM/许可证清单并验证 `.app` 不回指开发机 Homebrew。

## 8. 未验证项与阶段边界

以下项目仍未通过，不能由 P0-03 报告替代：

- 无正式 OpenLXSSH App/Xcode target、`Package.resolved`、Xcode Release 构建或 `.app` 打包。
- 未在 macOS 26 运行时启动 App；当前宿主仍为 macOS 15.8.1。
- 未执行真实 SSH/SFTP、Keyboard-Interactive、OTP/MFA、主机密钥信任、PTY、终端输入、文件传输、取消或资源释放测试。
- 未完成 libssh2 CMake 构建；替代 crypto backend 未完成本机组合构建。
- 未完成签名、公证、Sandbox/Hardened Runtime、第二台 Mac 或隔离服务器验收。
- GRDB schema、迁移、事务、仓储和崩溃恢复未实现/验证。

## 9. 工作区与安全检查

主管复核命令：

- `/usr/bin/git status --short --branch`：`## main`，P0-03 文档为未提交改动。
- `/usr/bin/git diff --check`：退出码 `0`。
- `git ls-files` 的秘密文件模式扫描无匹配；报告和依赖文档不包含密码、私钥、令牌或真实服务器信息。
- 临时探针目录在独立命令完成后无残留 `openlxssh-p0-03*` 目录。

本报告和依赖清单是审计记录，不是产品验收替代物。P0-03 可在主管完成文档审查、提交相关文档并更新状态后进入阶段 0 的 P0-04/P0-05；是否正式“阶段 0 通过”仍取决于后续环境与签名调查以及这些未验证项不被误标为通过。
