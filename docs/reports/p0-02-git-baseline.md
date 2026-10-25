# P0-02 Git 基线报告

- Task ID：`P0-02-R1`（修正 P0-02 基线记录）
- 工作区：`/Users/liuwenshuo/Desktop/OpenLXSSH`
- 执行时间：2026-10-25（Asia/Shanghai）
- 执行者：`software-engineer`
- 修正范围：仅修正根目录 `.gitignore`、本报告和 `ENGINEERING_STATE.md`；不进入 P0-03，不创建 App/Xcode 项目或 Swift Package，不修改需求、架构、执行计划和验收基线。
- 本报告不包含密码、私钥、令牌、真实服务器信息或凭据内容。

## 1. 初始工作区核对

P0-02 建立基线前确认：

- 当前目录为 `/Users/liuwenshuo/Desktop/OpenLXSSH`。
- 初始 `git status --short --branch` 退出码为 `128`，提示当前目录及父目录不是 Git 仓库。
- 项目根目录此前没有 `.git`；父目录检查未发现 `/Users/liuwenshuo/Desktop/.git`，且初始 `git status` 没有沿父目录找到仓库。
- 初始文件包含 `AGENTS.md`、`ENGINEERING_STATE.md`、`ZCODE_SETUP.md`、`docs/requirements.md`、`docs/architecture.md`、`docs/execution-plan.md`、`docs/acceptance.md` 和 `docs/reports/p0-01-environment.md`。
- 初始目录没有 Xcode 项目、Swift Package、Swift 源文件或符号链接。
- 已存在的 `.DS_Store` 未删除或回滚；由 `.gitignore` 排除，不进入提交。
- 未发现、读取或创建凭据文件；没有安装工具、设置 remote、推送或修改项目父目录。

## 2. 忽略规则

P0-02 新增根目录 `.gitignore`，P0-02-R1 补充了一个明确的本地秘密目录规则。规则按类别覆盖：

- macOS 元数据：`.DS_Store`、`.AppleDouble`、`.LSOverride`。
- Xcode/Swift 构建与个人状态：`DerivedData/`、`build/`、`.build/`、`.swiftpm/`、`xcuserdata/`、`*.xcuserstate`、`*.xcscmblueprint`、`*.xccheckout`、归档和符号文件等。
- 测试、覆盖率和诊断输出：`TestResults/`、`coverage/`、`*.xcresult`、`*.profdata`、`*.lcov`、`*.log` 等。
- 临时与编辑器文件：`tmp/`、`temp/`、`*.tmp`、交换文件和编辑器备份文件。
- 本地环境、凭据和签名材料：`.env`、`.env.*`（显式保留 `.env.example`/`.env.template`）、本地秘密扩展名、私钥/证书扩展名、SSH 私有目录，以及根目录锚定的 `/credentials/`、`/secrets/` 和 `/local-secrets/`。

目录规则使用根目录锚定路径，未添加任意 `password.txt` 等通用文件名规则。因此 `local-secrets/password.txt` 命中明确的 `/local-secrets/` 规则，而源码或测试输入中的普通 `password.txt` 不会仅因文件名被忽略。规则没有忽略 `Sources/`、`Tests/`、`Package.swift`、`Package.resolved`、`.xcodeproj/project.pbxproj`、正式文档或其他常规产品输入。

## 3. 初始基线与后续提交事实

P0-02 初始基线提交为：

- `4ccebe7d612afef1eaf20b890c2ce3df0b27b8d7`（短 hash：`4ccebe7`，`chore: establish OpenLXSSH git baseline`）。
- `git show --stat --oneline --decorate 4ccebe7` 显示 10 files changed，1098 insertions。
- 基线文件清单（`git ls-files`）：`.gitignore`、`AGENTS.md`、`ENGINEERING_STATE.md`、`ZCODE_SETUP.md`、`docs/acceptance.md`、`docs/architecture.md`、`docs/execution-plan.md`、`docs/reports/p0-01-environment.md`、`docs/reports/p0-02-git-baseline.md`、`docs/requirements.md`。

初始基线之后的实际提交链为以下仅文档记录提交，未改变初始基线的产品文件范围或 `.gitignore` 策略：

1. `333ec8e651d0714d6ab242d7bfba804a1b85af3d`（短 hash：`333ec8e`，`docs: record P0-02 baseline verification`）：仅更新 `ENGINEERING_STATE.md` 和本报告。
2. `5edb20edf9be04f6e0562a906e62b2d42da48b66`（短 hash：`5edb20e`，`docs: mark P0-02 ready for review`）：仅更新 `ENGINEERING_STATE.md`。
3. `b83a10bd201e9b08a27cac2da87b4ec8df5b3407`（短 hash：`b83a10b`，`docs: clarify baseline commit history`）：仅更新本报告。
4. `6a6f7cb19d6b657ca3dae7a7c7a00772179f0098`（短 hash：`6a6f7cb`，`docs: update workspace baseline state`）：仅更新 `ENGINEERING_STATE.md`。

P0-02-R1 开始时的当前 HEAD 是 `6a6f7cb19d6b657ca3dae7a7c7a00772179f0098`（`6a6f7cb`）。上述初始基线和四个后续提交均为实际 Git 历史；本报告不把 R1 工作区修改追溯归入这些较早提交，也不声称尚未提交的内容已经提交。R1 的三个允许文件在本轮本地文档提交中提交后，另由提交后的 `git show --stat` 和工作区状态核对。

## 4. P0-02 基线操作与历史验收证据

以下 P0-02 命令均在 `/Users/liuwenshuo/Desktop/OpenLXSSH` 执行；退出状态按实际结果记录：

1. 初始 `git status --short --branch`：退出码 `128`，当前目录及父目录不是 Git 仓库。
2. `git init -b main`：退出码 `0`，在项目根目录创建唯一 `.git`。
3. `git rev-parse --show-toplevel`：退出码 `0`，输出 `/Users/liuwenshuo/Desktop/OpenLXSSH`。
4. 初始化后 `git status --short --branch`：退出码 `0`，显示 `## No commits yet on main`；`.DS_Store` 未列出，符合忽略规则。
5. `git check-ignore -v --no-index`：P0-02 原始忽略路径命中预期规则；未匹配路径的单项退出码为 `1`，整体检查按预期完成。
6. `git config --get-regexp '^(remote\\.|branch\\.)'`：无输出、退出码 `1`，未配置 remote 或跟踪分支；`git remote -v` 退出码 `0` 且无输出，未设置 remote。
7. `git add --all`：退出码 `0`，仅暂存未被忽略的本项目文件；`.DS_Store` 和其他本地状态/凭据模式未进入暂存区。
8. `git diff --cached --check`：退出码 `0`，无空白错误。
9. `git commit -m "chore: establish OpenLXSSH git baseline"`：退出码 `0`，创建本地基线提交 `4ccebe7`。
10. 基线提交后的复核：`git rev-parse --show-toplevel` 退出码 `0`；`git status --short --branch` 输出 `## main`；`git remote -v` 无输出；`git config --get-regexp '^(remote\\.|branch\\.)'` 无输出；`git ls-files` 和 `git show --stat --oneline --decorate 4ccebe7` 与上面的基线清单一致。
11. 基线之后的 `333ec8e`、`5edb20e`、`b83a10b`、`6a6f7cb` 均已实际提交；通过 `git show --stat` 核对其修改范围均为报告或状态文档。

P0-02-R1 的修正核对另外确认：

- `git check-ignore -v --no-index local-secrets/password.txt` 命中根目录 `/local-secrets/` 规则。
- `.env.example`、`.env.template`、`Package.swift`、`Sources/OpenLXSSH/App.swift`、正式文档和 Xcode `project.pbxproj` 候选路径均不被忽略；针对 `.env.example`/`.env.template` 使用 `git check-ignore -q --no-index` 的退出码为 `1`，表示未被忽略（带 `--verbose` 的例外规则输出会显示匹配的否定规则）。
- 本轮 `git diff --check` 在提交前退出码为 `0`。
- 本轮仅允许修改 `.gitignore`、本报告和 `ENGINEERING_STATE.md`；未设置 remote、未 push、未删除现有文件，也未写入凭据。

## 5. 当前状态、限制与后续边界

- 初始基线和后续文档提交不代表产品代码、依赖、构建、签名、SSH/SFTP 互通或 macOS 26 运行时验收完成。
- 当前工作区仍没有 App/Xcode 项目或 Swift Package；本任务不创建它们。
- `.DS_Store` 保留在本地但不纳入 Git；若之后需要清理，须由主管另行决定，不能从本任务推断删除授权。
- P0-02-R1 仅修正忽略覆盖和事实记录；待主管独立审查本轮本地文档提交后，再决定进入 P0-03 依赖核对。本轮不自动执行后续阶段。
- remote：`git remote -v` 无输出；未配置 remote，也未执行 push。
