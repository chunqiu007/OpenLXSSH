# OpenLXSSH

[English](README.md) · **简体中文**

OpenLXSSH 是一款为 **Apple Silicon（M 系列芯片）Mac** 打造的轻量原生 **SSH 和 SFTP 客户端**，支持 **macOS 26 及以上版本**。应用使用 SwiftUI 和 AppKit 开发，无需 Electron 运行环境或云端账号。

## 下载试用版

[下载 Apple Silicon DMG](https://github.com/chunqiu007/OpenLXSSH/releases/download/v1.0.0-trial.2026110501/OpenLXSSH-Trial-1.0.0-2026110501-arm64.dmg) · [发布说明](https://github.com/chunqiu007/OpenLXSSH/releases/tag/v1.0.0-trial.2026110501)

打开 **1.0.0（构建号 2026110501）** 的 DMG，将应用拖到「应用程序」，然后从「应用程序」启动。试用版已使用 Developer ID 离线签名，Apple 公证尚未完成，其他 Mac 上的 Gatekeeper 可能会拦截。若遇到拦截，请在反馈中附上 macOS 提示原文。

## 内存占用

在 Apple Silicon Mac 上，先前的 **1.0.0 build 3** 空闲时实测驻留内存（RSS）约为 **107–111 MiB**。同时运行 **5 个 SSH 会话**时，应用和 SSH 子进程合计平均约 **125.1 MiB**。终端持续输出并切换标签时，实测峰值为 **135.4 MiB**。以上数据对应 build 3，当前试用包是后续构建。[完整测量记录](docs/reports/mac26-takeover.md)

## 主要功能

- 用分组、标签和收藏管理主机，在独立的终端标签中保持多个 SSH 会话。
- 支持密码和 SSH 密钥登录，以及服务器要求的 MFA 等交互式验证。支持将凭据保存到 macOS 钥匙串，并在连接时核对主机指纹。
- 通过 SFTP 双栏浏览本地和远端目录，上传或下载文件和文件夹，查看传输进度并处理同名冲突。
- 登录跳板机后，在远端终端里手动执行第二次 `ssh`。SFTP 文件浏览器直接连接目标服务器。

## 帮忙测试

1. 在 M 系列 Mac 上安装并启动试用版。添加一台有权限测试的主机，核对主机指纹，再用平时的认证方式连接。
2. 新建并切换多个终端标签。平时使用跳板机的话，可以试一下手动嵌套 SSH。
3. 用 SFTP 上传和下载一个小测试文件，再试一次同名传输，检查「取消」「替换」「都保留」是否符合预期。

反馈时请附上 Mac 芯片型号、macOS 版本、应用构建号、复现步骤、预期行为和实际结果。提交日志或截图前请去除密码、私钥、一次性验证码及真实主机信息。[提交 GitHub Issue](https://github.com/chunqiu007/OpenLXSSH/issues/new)
