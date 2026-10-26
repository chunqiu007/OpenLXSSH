# 本地 Release 候选打包

`Scripts/package-release-candidate.py` 只准备本地内部候选，不安装、不公证、不上传；不是功能验收。需要现有 Python 3.9+、Xcode 与 macOS 系统工具。脚本调用原有 `Scripts/build-app.sh Release build`，不改工程或构建脚本。首次依赖解析仍受原构建脚本的固定依赖下载规则约束。

运行前先让所有 App 工程编辑、`build-app.sh` / `xcodebuild` 停止；打包锁只能防止本打包器自身并发，不能锁住其他工程师。调用构建前会检查 `Release`、`Askpass-Release`、`SourcePackages` 既有写入树（含 checkout、插件生成路径与 App/helper/notice 写入点）和构建/插件校验脚本，拒绝写入祖先 symlink、特殊文件与硬链接。只允许精确的 SwiftPM 内部 `release` 别名及不越出各自 checkout 的相对源码链接；不声称可阻止恶意同 UID 进程在预检后抢改路径。默认要求 Git 干净；已知改动的内部验证须明确加 `--allow-dirty`，manifest 会记录该授权、提交与源状态指纹。

```bash
python3 Scripts/package-release-candidate.py
# 仅在明确接受脏源码的内部候选时
python3 Scripts/package-release-candidate.py --allow-dirty
```

默认 **UNSIGNED INTERNAL CANDIDATE**，不查询或使用签名身份。编译器原有的 ad-hoc 签名不等于 Developer ID，也不保证资源封装验证通过；manifest 如实记录 strict/deep 验证、Hardened Runtime 与 `spctl` 退出码。`gatekeeperAccepted=false` 不是可直接分发安装的版本，不能通过关闭 Gatekeeper 或移除隔离标记绕过。

每轮新建 `DerivedData/Distributions/<version>-<build>-<commit前12位>/<UUID>/`，仅含 App、ZIP、manifest；不覆盖既有目标、不清理他人目录。构建/评估日志留在独立 `DerivedData/Verification/ReleasePackaging/<UUID>/`，不打进 ZIP，可能含敏感本地信息，不应直接外发。失败保留 `INCOMPLETE.json` / `failure.json` 与日志索引，不应分发失败目录。

- 正式 `Contents/Helpers/openlxssh-askpass` 必须已集成，否则明确失败，不从实验区域拷贝替代品。
- 检查 App 命名/Bundle ID、arm64、所有 Mach-O 的最低 macOS 26.0、可重定位的完整运行依赖闭包（支持裸 `@loader_path` / `@executable_path`，仍检查 bundle 内边界）；直接读取二进制 header/load-command，入口必须为 `MH_EXECUTE` 且有落在可执行文件段的有效 `LC_MAIN`。拒绝 Homebrew、临时/工作区依赖、逃逸链接、未使用的嵌入代码、测试/构建/签名材料。
- V1 当前静态链接依赖，只批准主程序与固定 askpass helper 两个运行代码路径；manifest 逐节点记录第一方来源/提交与实际链接依赖，依赖条目反向记录 `linkedCodePaths` 和许可证。不因依赖闭包有效就接受新 `.framework` / `.dylib`；未知节点一律失败，需先独立审查来源、许可与 filetype，再修改白名单，不自动归属到名称相近的依赖。XPC/插件等新布局同样须先审查支持。
- 用正式 target/lock、实际已定义符号与原生库来源/摘要判断集成；target 声明或 resolved pin 本身不是已链接证明。Swift 包仍要求 `nm -g -U -j` 的完整、锚定模块符号名。native 使用下述明确审查的 hidden-static 适配器；不泛放行 local 名称、大小写近似、字符串内容或 undefined import。GRDB、SwiftTerm、libssh2/OpenSSL 仅在有对应证据时标为 `included=true`，并在复制后的 App 中加入完整的真实许可证。未链接的 SwiftPM 传递包不会假称已包含。新依赖、未知格式、全剥离无符号证明或原生来源不一致时仍失败。
- App SHA256 使用 `sha256-canonical-tree-v1`：对排序后的相对路径、类型、模式、链接目标、文件大小/摘要组成的规范 JSON 求摘要；不声称是目录的普通文件摘要。ZIP 使用普通 SHA256，并逐项比对内容/模式。扩展属性不修改；其 ZIP 元数据包含在 ZIP 摘要中，不在 App 树摘要中。

## Native hidden-static 符号证据

真实 Release 只读诊断发现 `OpenLXSSHFiles` 的 libssh2/OpenSSL API 在主程序中为 `(__TEXT,__text) non-external (was a private external)`；native 构建记录有 `-fvisibility=hidden`。因此 `nm -g` 过滤掉这些定义不代表没链接，也不能据此说“符号已 strip”。适配器 `nm-defined-text-exact-archive-match-v1` 只接受 `nm -U -m` 明确列出的 `__TEXT,__text` 函数定义及四种已审查 binding（`external`、`private external`、`non-external`、`non-external (was a private external)`）。undefined、absolute、data/const、未知 binding、plain strings 或 substring 均不作证据。

- 先校验 `native-inputs.json`、`Packages/OpenLXSSHFiles/Scripts/build-native.py` 与 native `manifest.json` 的输入摘要，再校验 `libssh2.a`、`libssl.a`、`libcrypto.a` 的全部三个 archive 摘要，之后才读取 archive 符号；收集结束再次核对输入摘要。不会重建 native。
- App/helper 每个有证据的代码路径必须同时包含该库三个关键 API 的真实 text 定义。libssh2 为 `_libssh2_session_init_ex`、`_libssh2_session_handshake`、`_libssh2_sftp_init`；OpenSSL 为 `_OPENSSL_init_crypto`、`_OpenSSL_version`、`_EVP_CIPHER_fetch`。每个 API 都须按**完整同名**映射到所属、已校验 archive 中唯一的 external/private-external text 定义和 `.o` member，不能用别库中的同名、单个前缀或多个代码路径拼成证明。API/工具格式改变时失败，需重新审查适配。
- manifest 的 native `symbolEvidence` 记录实际代码路径、签名前代码 SHA256、匹配数及实际 binding、多个精确 witness、archive member/定义/摘要；`nativeBuildProvenance` 记录 native manifest、输入 lock、构建脚本和三个已校验 archive。`verifiedInputArchives` 只表示校验过的构建输入，不表示每个 archive（例如 `libssl.a`）都有代码进入 App；具体 witness 记录其真正来源。
- 这是已定义符号名与固定来源的可复核映射，**不是位码等价校验，也不是完整二进制 SBOM 证明**；不替代既有 Mach-O/依赖闭包、许可证、签名或功能验收。`--verify-manifest` 仍只复核候选内容/归档/许可证摘要，不重新运行 symbol/source provenance 审计。

只复核已产出候选的内容摘要（不会构建或签名，也不重新证明系统信任）

```bash
python3 Scripts/package-release-candidate.py --verify-manifest /绝对路径/manifest.json
```

## 可选签名，仅显式选择

```bash
# 只显示现有可用身份数量，不打印证书名称
python3 Scripts/package-release-candidate.py --list-identities
# 仅现有 Development 身份；离线 --timestamp=none，命令有超时且不代答系统授权
python3 Scripts/package-release-candidate.py --signing development
# 多个同类型身份时必须以精确指纹或完整名称选择
python3 Scripts/package-release-candidate.py --signing development --identity '<现有证书指纹>'
```

脚本不创建/导入证书，不读取私钥，不更改 Keychain ACL/search-list，不提供授权回答。签名按叶代码、内嵌 framework、主 App 顺序执行；不以 `codesign --deep` 签名，只用于严格验证。所有签名代码必须具有一致身份/团队、Hardened Runtime，无调试/运行时绕过权限。

`--signing developer-id` 还必须明确提供 `--allow-timestamp-request` 才会允许向 Apple 请求时间戳。这是额外对外操作授权，不是公证/上传授权。此前实际内部候选曾显式使用既有Development身份离线签名，Developer ID/时间戳/公证仍未执行；不能把早期脚本fixture测试的“未真实签名”状态当作当前所有产物状态。无论签名方式，本入口的`notarized=false`、`uploaded=false`。

## 独立验证

```bash
python3 -B -m unittest discover -s Tests/ReleasePackaging -p 'test_*.py' -v
```

测试仅使用临时假 App/依赖数据、模拟符号/签名/评估命令，以及临时假 App 的本地 `ditto` 归档；不构建正式 App、不执行 Apple 公证、真实签名或安装。hidden-static 适配器的真实 Release 符号复核是独立的只读诊断，不等于已重新生成可交付候选；实际 Release 构建/打包仍须待 App 工程编辑与并发构建结束后另行实跑。macOS 26 启动、真实 SSH/SFTP、安全与双机安装均需独立验收。
