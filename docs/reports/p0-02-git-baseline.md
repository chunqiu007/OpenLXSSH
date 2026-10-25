# P0-02 Git 基线报告

- Task ID：`P0-02`
- 工作区：`/Users/liuwenshuo/Desktop/OpenLXSSH`
- 执行时间：2026-10-25（Asia/Shanghai）
- 执行者：`software-engineer`
- 范围：仅核对并保护本项目已有文件，在项目根目录初始化本地 Git，建立范围明确的忽略规则，创建本地基线提交；未执行依赖核对、App 实现或后续阶段工作。
- 本报告不包含密码、私钥、令牌、真实服务器信息或凭据内容。

## 1. 初始工作区核对

执行前确认：

- 当前目录为 `/Users/liuwenshuo/Desktop/OpenLXSSH`。
- 初始 `git status --short --branch` 退出码为 `128`，提示当前目录及父目录不是 Git 仓库。
- 项目根目录此前没有 `.git`；父目录检查未发现 `/Users/liuwenshuo/Desktop/.git`，且初始 `git status` 没有沿父目录找到仓库。
- 初始文件包含 `AGENTS.md`、`ENGINEERING_STATE.md`、`ZCODE_SETUP.md`、`docs/requirements.md`、`docs/architecture.md`、`docs/execution-plan.md`、`docs/acceptance.md` 和 `docs/reports/p0-01-environment.md`。
- 初始目录没有 Xcode 项目、Swift Package、Swift 源文件或符号链接。
- 已存在的 `.DS_Store` 未删除或回滚；由 `.gitignore` 排除，不进入提交。
- 未发现、读取或创建凭据文件；没有安装工具、设置 remote、推送或修改项目父目录。

## 2. 忽略规则

新增根目录 `.gitignore`，规则按类别覆盖：

- macOS 元数据：`.DS_Store`、`.AppleDouble`、`.LSOverride`。
- Xcode/Swift 构建与个人状态：`DerivedData/`、`build/`、`.build/`、`.swiftpm/`、`xcuserdata/`、`*.xcuserstate`、`*.xcscmblueprint`、`*.xccheckout`、归档和符号文件等。
- 测试、覆盖率和诊断输出：`TestResults/`、`coverage/`、`*.xcresult`、`*.profdata`、`*.lcov`、`*.log` 等。
- 临时与编辑器文件：`tmp/`、`temp/`、`*.tmp`、交换文件和编辑器备份文件。
- 本地环境、凭据和签名材料：`.env*`（保留 `.env.example`/`.env.template`）、本地秘密扩展名、私钥/证书扩展名、SSH 私有目录，以及根目录 `credentials/`/`secrets/`。

规则没有忽略 `Sources/`、`Tests/`、`Package.swift`、`Package.resolved`、`.xcodeproj/project.pbxproj`、正式文档或其他常规产品输入。现有 `.DS_Store` 等个人状态不被纳入 Git；未来正式项目文件仍可被跟踪。

## 3. 实际 Git 操作

以下命令均在 `/Users/liuwenshuo/Desktop/OpenLXSSH` 执行：

1. `git init -b main`：在项目根目录创建唯一 `.git`，退出码 `0`。
2. `git status --short --branch`：初始化后显示 `## No commits yet on main`；`.DS_Store` 未列出，符合忽略规则。
3. `git check-ignore -v --no-index`：检查 `.DS_Store`、`DerivedData/Build/Products/app`、`.build/arm64-apple-macosx/debug/app`、`Sample.xcodeproj/xcuserdata/user.xcuserdatad/UserInterfaceState.xcuserstate`、`Tests.xcresult`、`.env.local`、`id_ed25519` 等路径均命中预期规则；`Sources/App/main.swift`、`Tests/AppTests.swift`、`Package.swift`、`Package.resolved`、`OpenLXSSH.xcodeproj/project.pbxproj`、`docs/requirements.md` 未命中规则。
4. `git config --get-regexp '^(remote\\.|branch\\.)'`：无输出、退出码 `1`，未配置 remote 或跟踪分支。
5. `git add --all`：仅暂存未被忽略的本项目文件；`.DS_Store` 和其他本地状态/凭据模式未进入暂存区。
6. `git commit -m "chore: establish OpenLXSSH git baseline"`：创建本地基线提交；实际 hash 在提交完成后补录于本报告和 `ENGINEERING_STATE.md`。

## 4. 基线内容与验收

初始基线应包含本项目当前相关的交接、需求、架构、执行计划、验收、P0-01 报告、状态文件、配置启动说明、本次 `.gitignore` 和本报告；不包含 `.DS_Store`、未跟踪秘密/凭据、构建产物或个人配置。

- 基线 commit hash：待基线提交创建后补录。
- 基线文件清单：以提交后的 `git ls-files` 和 `git show --stat --oneline` 实际输出为准，并在提交后补录。
- 提交后状态：以提交后的 `git status --short --branch` 实际输出为准，并在提交后补录。
- remote：未配置；本任务不执行 push。

## 5. 限制与后续边界

- 当前工作区仍没有 App/Xcode 项目或 Swift Package；本任务不创建它们。
- 当前任务只建立本地版本基线，不代表产品代码、依赖、构建、签名、SSH/SFTP 互通或 macOS 26 运行时验收完成。
- `.DS_Store` 保留在本地但不纳入 Git；若之后需要清理，须由主管另行决定，不能从本任务推断删除授权。
- P0-02 完成后由主管独立审查实际差异和提交内容，再决定是否进入 P0-03；本任务不自动执行后续阶段。
