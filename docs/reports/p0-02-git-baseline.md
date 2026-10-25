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

以下命令均在 `/Users/liuwenshuo/Desktop/OpenLXSSH` 执行；退出状态按实际结果记录：

1. 初始 `git status --short --branch`：退出码 `128`，当前目录及父目录不是 Git 仓库。
2. `git init -b main`：退出码 `0`，在项目根目录创建唯一 `.git`。
3. `git rev-parse --show-toplevel`：退出码 `0`，输出 `/Users/liuwenshuo/Desktop/OpenLXSSH`。
4. 初始化后 `git status --short --branch`：退出码 `0`，显示 `## No commits yet on main`；`.DS_Store` 未列出，符合忽略规则。
5. `git check-ignore -v --no-index`：忽略路径均命中预期规则；源码、Package 输入、Xcode 工程项目文件和正式文档均未命中。循环对每个候选路径处理未匹配的退出码 `1`，整体检查按预期完成。
6. `git config --get-regexp '^(remote\\.|branch\\.)'`：无输出、退出码 `1`，未配置 remote 或跟踪分支；`git remote -v` 退出码 `0` 且无输出，未设置 remote。
7. `git add --all`：退出码 `0`，仅暂存未被忽略的本项目文件；`.DS_Store` 和其他本地状态/凭据模式未进入暂存区。
8. `git diff --cached --check`：退出码 `0`，无空白错误。
9. `git commit -m "chore: establish OpenLXSSH git baseline"`：退出码 `0`，创建本地基线提交，短 hash 为 `4ccebe7`。
10. 提交后复核：`git rev-parse --show-toplevel` 退出码 `0`，仍输出 `/Users/liuwenshuo/Desktop/OpenLXSSH`；`git status --short --branch` 退出码 `0`，输出 `## main`；`git remote -v` 无输出；`git config --get-regexp '^(remote\\.|branch\\.)'` 无输出；`git ls-files` 和 `git show --stat --oneline --decorate 4ccebe7` 均与下列清单一致。

基线提交完成后，为把实际 hash、最终状态和退出状态补录到本报告及 `ENGINEERING_STATE.md`，产生了仅限文档记录的后续工作区修改；该修改不改变基线文件范围或忽略策略。


## 4. 基线内容与验收

初始基线应包含本项目当前相关的交接、需求、架构、执行计划、验收、P0-01 报告、状态文件、配置启动说明、本次 `.gitignore` 和本报告；不包含 `.DS_Store`、未跟踪秘密/凭据、构建产物或个人配置。

- 基线 commit hash：`4ccebe7d612afef1eaf20b890c2ce3df0b27b8d7`（`chore: establish OpenLXSSH git baseline`）。
- 基线文件清单（`git ls-files`）：`.gitignore`、`AGENTS.md`、`ENGINEERING_STATE.md`、`ZCODE_SETUP.md`、`docs/acceptance.md`、`docs/architecture.md`、`docs/execution-plan.md`、`docs/reports/p0-01-environment.md`、`docs/reports/p0-02-git-baseline.md`、`docs/requirements.md`。
- `git show --stat --oneline --decorate 4ccebe7`：`4ccebe7 (main) chore: establish OpenLXSSH git baseline`，10 files changed，1098 insertions。
- 基线之后的文档记录提交：`333ec8e docs: record P0-02 baseline verification`、`5edb20e docs: mark P0-02 ready for review`；两次提交仅更新本报告和 `ENGINEERING_STATE.md` 的实际验证记录，不改变基线文件范围或 `.gitignore`。
- 最终 `git status --short --branch`：输出 `## main`，无未提交或未跟踪文件；`.DS_Store` 仍以忽略文件存在，不影响干净工作区。
- remote：`git remote -v` 无输出，`git config --get-regexp '^(remote\\.|branch\\.)'` 无输出；未配置 remote，也未执行 push。

## 5. 限制与后续边界

- 当前工作区仍没有 App/Xcode 项目或 Swift Package；本任务不创建它们。
- 当前任务只建立本地版本基线，不代表产品代码、依赖、构建、签名、SSH/SFTP 互通或 macOS 26 运行时验收完成。
- `.DS_Store` 保留在本地但不纳入 Git；若之后需要清理，须由主管另行决定，不能从本任务推断删除授权。
- P0-02 完成后由主管独立审查实际差异和提交内容，再决定是否进入 P0-03；本任务不自动执行后续阶段。
