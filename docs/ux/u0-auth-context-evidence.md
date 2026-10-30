# U0 认证上下文调查补充（非后端变更决定）

日期：2026-10-30。主管在U1 UI工程师写入期间只读核对未修改的Transport/Files成熟库接口。本文不替代最小真实探针，也不表示后端已替换。

## 已证实的限制

- `AuthenticationPolicy.swift`的SavedPasswordBudget仅在受审OS/OpenSSH、`.passwordOnly`、首个无hint masked请求时允许一次provider；`DirectSSHSession.launch`明确不将password+KI设为eligible。Askpass不提供可用于自动投递长期密码的可靠密码/KI阶段类型。
- 原 `LibSSH2FileService.establish` 是明确password/publickey API再独立KI handler，多prompt/echo/zero已有生产适配和旧真实SFTP报告，不按文字猜秘密类型；但当前C bridge只做SFTP，没有shell channel/remote PTY。
- 固定libssh2 1.11.1上游`userauth.c` password失败分支（约397～407）释放响应并返回AUTHENTICATION_FAILED，没有公开partial-success位；`libssh2_session_callback_set2`官方公开callbacks也不提供通用auth packet/partial回调。不得从调试trace或自行解析SSH包推断“初始密码已接受”。
- `libssh2_userauth_list`公开文档会发送none请求取得method list；可用于成熟协议方法发现，不等价输错密码。但对已partial状态的恢复细节文档未说明，必须对原fixture实测，不能先行承诺。
- 固定libssh2 `keepalive.c`只按间隔发keepalive request，`want_reply`并未提供公开missed count/response deadline；不能以发送成功假称达到原OpenSSH ServerAliveCountMax的断连策略。

## 可评估路线

| 路线 | 已知优势 | 必须补证/风险 |
| --- | --- | --- |
| 保持系统OpenSSH + 扩首masked密码白名单 | 已有PTY/TUI/资源/签名与keepalive证据 | **不采用猜测方案**：KI启用后首masked无可靠类型，不能符合初始密码/OTP边界；仅改UI不算实现 |
| 复用现有libssh2 + 新shell channel/remote PTY | 同握手hostkey、typed password/publickey、独立KI；既有静态依赖/许可证无需新增成熟协议栈 | partial不公开；method discovery/拒绝路径、keepalive count、shell read/write/resize/close/backpressure需新实证；不修改上游私有struct/自写协议 |
| 评估libssh公开API | 官方0.12.0 API文档明确SSH_AUTH_PARTIAL、DENIED、AGAIN、INFO以及多prompt/echo的KI；0.12.2为官方2026-07安全发布 | 新依赖构建/固定hash/许可证/分发/资源均需评估，当前未下载或安装；不能仅凭文档就切库。完整keepalive行为仍需源码/API核对 |

## 官方资料实读

- https://libssh2.org/libssh2_userauth_password_ex.html ：typed password与change callback；页面未说明partial位。
- https://libssh2.org/libssh2_userauth_list.html ：none方法探测、method list、authenticated检查。
- https://libssh2.org/libssh2_session_callback_set2.html ：公开callback列表，无partial认证回调。
- https://libssh2.org/libssh2_channel_request_pty_ex.html ：真实PTY emulation/字符与像素尺寸；EAGAIN不等失败。
- https://libssh2.org/libssh2_channel_process_startup.html ：shell startup/denied/EAGAIN；resize页面正文为空，须查固定上游header/source并实测。
- https://libssh2.org/libssh2_keepalive_config.html ：非阻塞应用自己send，未承诺count failure。
- https://api.libssh.org/stable/group__libssh__auth.html ：公开PARTIAL/DENIED/AGAIN/INFO和多prompt APIs。
- https://api.libssh.org/stable/group__libssh__session.html ：公开status/counter/poll，不证明完整probe reply count。
- https://www.libssh.org/2026/07/28/libssh-0-12-2-security-release/ ：0.12.2修零channel packet size DoS；官方release目录https://www.libssh.org/files/0.12/。
- `https://www.libssh.org/about/`和`about/license/`返回404，get-it页未列license；后续官方mirror页面及COPYING链接可读到LGPL-2.1-only标识，但完整分发/重新链接条款尚未取得正文，**仍未通过许可合规评估**。官网目录已观察`libssh-0.12.2.tar.xz`及`.asc`；未下载或执行。实际`command -v cmake/ninja`均未找到，CMake.app常见路径也未找到；新库构建存在工具条件，不擅自装系统工具。

## 下一最小工程任务

U1通过后单独派唯一工程师先实现/验证一个有严格固定fixture目标的typed initial-password/publickey→KI→真实shell最小消费者；复用已有收集/冻结identity/有限relay，不重建容器、不读真凭据、不重复2GiB或24h。先验证四组合、未知KI人工、取消、hostkey same-handshake、真实resize/shell ACK和自然close，再决定最小后端适配与ADR。不得为探测MFA故意输错密码、建两条SSH连接冒同一条认证，也不得把SFTP auth成功当shell-ready。普通UI不依赖该探针的工作可继续，但两类MFA和本次未记住密码必须在最终候选真实可用。
