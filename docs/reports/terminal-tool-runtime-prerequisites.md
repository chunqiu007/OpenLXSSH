# TERM-05：Claude Code / OpenCode 合法运行条件检查

日期2026-10-28（工程证据日期；系统给定日期另为2026-10-26，未修改系统时间）。本次仅公开官方资料只读研究，不执行CLI/安装下载，不读用户认证、配置或环境，不提交模型请求。

**结论：两工具交互尚未实测，不能由help/version、别的TUI或本报告替代。** 按执行计划P2-03，缺少合法运行条件时记录限制，不绕登录、账号、协议或网络边界。

## Claude Code

宿主 `command -v claude` 返回 `/opt/homebrew/bin/claude`，只证明入口存在，没有执行版本或读取其配置。官方[setup](https://code.claude.com/docs/en/setup)明确互联网连接及付费Claude订阅/Console账号或获准第三方provider条件；API key代替浏览器登录，不是免认证方案。该文档没有支持“免账号且完全离线”的交互模式；这不等于证明任何onboarding页面都不能离线绘制。

官方[CLI reference](https://code.claude.com/docs/en/cli-reference)区分交互命令和 `-p` 非交互。help/version并非TUI输入/缩放/退出的证据。

研究核过[v2.1.311](https://github.com/anthropics/claude-code/releases/tag/v2.1.311)（发布记录2026-10-26 21:51:23 UTC）；latest另返回晚于系统日期的v2.1.312，不能直接写为系统日期时最新版。[版本LICENSE](https://github.com/anthropics/claude-code/blob/v2.1.311/LICENSE.md)指向Commercial Terms；未接受协议、登录、提供API key或执行模型请求。

## OpenCode

官方[v1.19.4 release](https://github.com/anomalyco/opencode/releases/tag/v1.19.4)发布记录2026-10-22。该版本[MIT license](https://github.com/anomalyco/opencode/blob/v1.19.4/LICENSE)不要求账号；[TUI源码](https://github.com/anomalyco/opencode/blob/v1.19.4/packages/tui/src/app.tsx)有 `/help` 和 `/themes` 候选本地交互，但无provider时自动选择框能否无认证退出、严格离线冷启动尚UNKNOWN。源码存在本地功能不等实际运行成功。

官方[CLI文档](https://opencode.ai/docs/cli/)记录默认 `opencode [project]` TUI、`--pure`/`OPENCODE_PURE`、`OPENCODE_DISABLE_AUTOUPDATE`、`OPENCODE_DISABLE_MODELS_FETCH`、`OPENCODE_DISABLE_DEFAULT_PLUGINS`、`OPENCODE_DISABLE_LSP_DOWNLOAD`。这些是分功能开关，不是全局no-network保证；emptyHOME也不能单独隔离XDG、项目配置或环境凭据。

宿主opencode不在PATH；当前fixture安装清单没有该工具，未自动补装。若将来在合适授权和现有no-egress隔离条件下运行，应全新无凭据HOME/XDG/空目录/白名单环境、禁下载更新插件、不开provider/不发prompt；实际help/themes按键/选择/缩放/退出只算有限TUI证据，不算完整模型会话。

## 当前边界

不从必要依赖下载授权外推出Claude账号/商业协议/API调用、开放出网或宿主工具配置访问许可。任何需要额外安装/复制第三方运行工具、认证或网络的具体方案先核现有授权边界，必要时取得用户批准。当前TERM-05这两工具保留未实测/运行条件缺口；已有Vim/tmux/htop真实分项不受影响，也不代替它们。

Docker日志亦不能通过挂宿主Docker socket/特权容器/开启认证日志来补：现fixture logdriver none/internal，尚需界定非秘密日志源与受限读取路径，未执行。

主会话独立重取官方setup/CLI文档，确认账号/网络条件和精确OpenCode控制项；这仍只是条件调查，不改变任何产品验收状态。
