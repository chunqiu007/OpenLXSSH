# ADR-P0-03-02：libssh2 + 可审计 crypto backend 的初始候选

- 状态：暂定，待 P3 SFTP 原型固定
- 日期：2026-10-25（Asia/Shanghai）
- Task：`P0-03`
- 范围：SFTP 后端和原生加密库的来源、构建、许可证调查；不代表 SFTP、SSH 认证、主机信任或文件完整性已通过

## 问题

OpenLXSSH V1.0 需要直接服务器 SFTP，架构将 libssh2 作为优先候选。libssh2 不携带完整加密实现，必须选择并分发一个 crypto backend；候选会影响 API、Keyboard-Interactive、静态/动态链接、Apple Silicon 构建、许可证和最终 `.app` 打包。

## 候选事实

### libssh2

- 来源：<https://github.com/libssh2/libssh2.git>
- 版本：`libssh2-1.11.1`；标签对象 `3a735286108ad19e3b49c64ebcb66342f1f21df7`，剥离提交 `a312b43325e3383c865a87bb1d26cb52e3292641`。
- 主许可证：BSD-3-Clause；仓库采用 REUSE，其他文件还标注 BSD-2-Clause、MIT、curl、FSFULLR、SAX-PD-2.0 等，需按实际打包文件带 notices。
- API：上游提供 `libssh2_userauth_keyboard_interactive_ex` 回调和 EAGAIN 非阻塞语义；提供 `libssh2_sftp_open_ex`、read/write/rename 等 SFTP API。文档明确 keyboard-interactive 的 challenge 不一定是密码，rename 的原子/本地系统调用 flags 是偏好而非保证。
- 构建：CMake 最低 3.7，支持 static/shared、显式 `CRYPTO_BACKEND`；Autotools 支持 `--with-crypto=auto|openssl|libgcrypt|mbedtls|wincng|wolfssl`。
- 本机：Xcode clang + Autotools `configure`/`make`，指定 arm64、macOS 26 deployment target、OpenSSL、静态库成功；CMake 因本机缺少 `cmake` 退出 127，未安装补齐。

### crypto backend

| 后端 | 上游候选 | 许可证/打包结论 | 当前选择状态 |
| --- | --- | --- | --- |
| OpenSSL | `openssl-3.6.5`，`e5c234b0c471a676ae6141d2f157df61eb293477`；本机探针输入为 Homebrew arm64 OpenSSL 3.6.3 | Apache-2.0；静态链接可减少独立 dylib 打包，但仍需保留 notices、固定源码 hash，并复核模块/配置和签名 | 初始首选候选；本机静态 arm64 构建已验证 |
| mbedTLS | `v3.6.7`，`da6a8c7b9b8e0c1e236deef2910642657db1a7ec` | Apache-2.0 OR GPL-2.0-or-later；须选择适用 Apache 路径并审查文件级许可；未本机构建 | 备选，未验证 |
| Libgcrypt | `libgcrypt-1.11.3`，`01b9cca145e627f7163713974859631baa6e4244` | LGPL-2.1-or-later；还会带来 libgpg-error 等依赖/分发审查；未本机构建 | 备选，未验证 |
| wolfSSL | `v5.8.4-stable`，`b6fbfad945d4b98fce619b6e5b6561b3eca1205b` | 公共 `COPYING` 为 GPL-3.0；商业/双许可未在本轮核验；静态链接前置许可风险高 | 不采用，除非取得并审查适用商业许可 |
| LibreSSL | `v4.4.0`，`05a68abffedd17c376759181ea40f807219251c9` | ISC/OpenSSL/原始 SSLeay 等混合文本；libssh2 1.11.1 后端枚举不包含 LibreSSL | 不作为直接后端；需另行兼容实现证据 |
| WinCNG | libssh2 源码枚举 | Windows 系统组件；不适用于 macOS arm64 | 排除 |

## 候选对比

### 功能/API

OpenSSL、mbedTLS、Libgcrypt 和 wolfSSL 均在 libssh2 的公开后端分支中，但只有 OpenSSL 在本机完成了 configure/build/link 探针。libssh2 API 是否能满足 OpenLXSSH 的多轮认证、主机信任、取消和 SFTP 文件语义，必须在 P3 适配层验证；API 存在不等于服务器互通。

### 安全

- 生产构建必须显式指定 backend，不使用“扫描本机可用库”的自动模式，避免开发机/CI 环境漂移。
- OpenSSL 3 组合需要固定版本、编译选项和模块策略；不得依赖 `/opt/homebrew` 的运行时路径，也不得把宿主系统 OpenSSH 的 LibreSSL 当作 libssh2 后端。
- 所有 backend 的连接、认证、非阻塞 EAGAIN、取消和释放都应在隔离环境中做真实测试；不能以 mock 或静态编译成功替代。

### 许可证与分发

OpenSSL 的 Apache-2.0 路径是本项目当前最容易审计的初始候选；libssh2 本身 BSD-3-Clause。mbedTLS 的双许可证需要明确选择并保留相应文本；Libgcrypt 的 LGPL 需要审查静态链接合规和传递依赖；wolfSSL 在未取得商业授权前存在 GPL 风险；LibreSSL 不具备本版本 libssh2 的直接 backend 入口。

### 构建/打包

- **静态库候选**：将 libssh2 和 OpenSSL 以固定源码构建成 arm64 静态档案，在 Xcode target 中链接；优点是 App 不依赖独立 crypto dylib；缺点是构建时间、许可 notices、符号和升级链路需审计。
- **XCFramework/静态 framework 候选**：适合隔离原生 target 和架构产物，但仍需证明 Xcode 集成、modulemap、签名和静态重复符号没有问题。
- **动态库候选**：将 libssh2/crypto 放入 `.app` 的 `Frameworks` 或受控子目录，设置 `@rpath`，逐一签名并验证 Hardened Runtime；不能让安装用户依赖 Homebrew。
- CMake 在上游有明确选项，但本机没有 cmake；Autotools 探针证明源码和 Xcode clang 的 arm64 静态构建路径可行，不直接决定最终 Xcode 方案。

## 暂定决定

1. P3 原型初始组合使用 `libssh2-1.11.1` + OpenSSL 3.x（以可审计源码 tag 构建，不依赖 Homebrew 运行时）进行验证。
2. 首版原型优先尝试 arm64 静态库/Xcode 原生 target；是否转 XCFramework 或动态库由真实 Xcode 打包、符号、签名和许可证结果决定。
3. 不选择 libssh2 自动探测 backend；生产构建必须显式 backend 和版本/hash。
4. mbedTLS/Libgcrypt 仅保留为可比较替代，必须使用相同 P3 测试矩阵和许可审查；wolfSSL 暂不采用，LibreSSL 暂不视为可用 backend。
5. 本决定不宣布 SFTP 功能、Keyboard-Interactive、MFA、主机信任、取消或文件安全提交通过。

## 复验计划

P3 至少完成：

- 在干净 Xcode 工程或受控 SPM/CMake wrapper 中编译 arm64/macOS 26；固定 source archive SHA-256、编译器、SDK、deployment target 和 backend flags。
- 对 `libssh2_userauth_keyboard_interactive_ex` 验证多提示、空提示、取消、EAGAIN、旧回调隔离和错误回收。
- 对 host-key/known-host API、password/public-key/keyboard-interactive 认证和 SFTP open/read/write/list/rename/delete 做真实隔离服务器测试。
- 检查静态/动态产物的 `file`、`otool -L`、符号可见性、签名、App 内加载和 Hardened Runtime；不连接真实公司服务器。
- 对文件名、重命名冲突、临时文件提交、断线/取消/权限错误形成明确后续 ADR；不得把 rename 的“原子偏好”写成协议保证。
- 生成实际 SBOM/许可证清单，按最终进入 `.app` 的文件重新核对 notices；任何改变 backend 的行为都要重新审查。
