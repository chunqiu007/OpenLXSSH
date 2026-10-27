# PTY 失败根因：AUDIT_WRITE 单变量隔离对照

日期2026-10-27。**同一固定镜像、相同限制下，仅增加 AUDIT_WRITE 后，强制PTY从exit255/无ACK变为exit0/精确CRLF ACK。该证据支持修正keyonly测试环境，不是App终端/TUI或生命周期验收通过。** 原四个服务、主机密钥、凭据和文件测试集未改变。

## 问题收敛与依据

原真实App在上传close/hide动作前SSH先失败，独立终端在outer-auth后73B短ACK前failed(launchFailed)/255，原loader未发。系统-T成功/-tt失败；同容器两UID openpty成功；Linux客户端直连原daemon也在0.241s以255失败，不经宿主relay。临时同image/cap debugsshd命中固定 `linux_audit_write_entry failed:`，server/client255；helper内部cleanup=false/exit2保留PARTIAL，外层无残留另核。详细原案见 `docs/reports/real-remote-terminal.md`。

固定OpenSSH V_9_6_P1 audit-linux.c的AUDIT_USER_LOGIN写入失败存在该fatal；Linux官方定义CAP_AUDIT_WRITE bit29允许通过unicast netlink写审计记录，不是AUDIT_CONTROL/READ；Docker默认通常保留AUDIT_WRITE，而本fixture cap-drop ALL后仅回加七项，故不含它。上游非Ubuntu完整补丁证明，采用单差实测而不是据cap名称修改。该权限写入Docker VM Linux内核审计流，不是容器私有日志，也不取得macOS文件访问。

## 保持原环境的对照设计

- 固定既有image `sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363`，不重建/下载。
- A/B串行，独立UUID-label internal网络、各自空namedvolume、无host port/bind/socket、无LAN/no default route，不挂旧key-data或生成2GiB数据。
- 两组均readonly/no-new-privileges、0.5CPU/384MiB/no swap/128PIDs、run96MiB/tmp32MiB/shm64MiB、nofile1024、lognone/init、相同keyonly bootstrap/sshd配置。
- A原七cap，B仅加AUDIT_WRITE。不加AUDIT_CONTROL/READ、SYS_TTY_CONFIG、SYS_ADMIN或privileged。
- 两组均使用显式固定server.py health exec轮询，不配置常驻healthcheck；这与原Compose CMD健康监督有差异，但A/B彼此相同，不通过固定sleep伪造ready。
- 每组-T/-tt各一次，用容器内本组新测试key和带外known_hosts，只固定非秘密nonce printf。stdout/stderr只内存64KiB/20+5秒，输出仅ACK/摘要/静态阶段；不导出秘密。
- fresh UUID/name/fullCID/labels限定归属，exclusive/fsync非秘密创建账本；exact stop→确认stopped→rm→本组volume→空network，不prune/force/delete旧环境。

## 原首案与最小R1

冻结脚本首案 `b0a11d49a7944830a22de774209d9487` exit2/12.131s，在创建任何资源前的四CID batch inspect达到12秒预算。后续同literal只读计时12.043130s；原运行未留下完整baseline，不补造原returncode或A/B结果。exact UUID container/volume/network均0，原环境身份/公钥后验未变。证据 `DerivedData/Verification/fixture-audit-pair-live-5ce10f86-f3e1-4da9-9bd5-bdaba7cc2f50/failure-postcheck.json`。

R1只把四CID inspect专用预算调20秒（默认其他metadata12秒、总6分钟/组120秒不变），前置门移入异常记录并先写prepared账本，未尝试network时不收养清理、未获baseline时不假称originalUnchanged。主管完成剩余极小收口，原8项加1项fake timeout回归共9项通过。首个新增测试因macOS临时路径别名触发evidenceRoot安全门，修测试路径canonical后绿，产品安全门未放宽。

## 真实新案结果

run `d063d49c43d34fffb412b8b31412f3af`，总41.350s、outer exit0，无重试；每组每模式各一次。

| 组 | sshd CapEff/Prm/Bnd | -T | -tt |
| --- | --- | --- | --- |
| A原七cap | 00000000000400eb | exit0、52B精确LF ACK、0.207s | exit255、0B/无ACK、0.227s |
| B只加AUDIT_WRITE | 00000000200400eb | exit0、52B精确LF ACK、0.179s | exit0、53B精确CRLF ACK、0.212s |

两组config SHA256均 `0e1b32cfda7e0f60ae521dbc66a5a9a9f1db6e003f5290db5f857ac710e98616`；NoNewPrivs1/UID0、无default route、shm64MiB核实。B另见静态pty-accepted/exec-accepted/exit-status；分类集合不当日志时序。不同bootstrap产生本组不同host/client随机密钥，这是两组预期身份隔离；不复用旧信任来换取成功。

A CID `1ff01d2e991e86dfdb63e4fe0184e56e3a68891cf1f4fd3dd1016ee4b7aac3c6`；B CID `f258c881c95a1a2364aec6aabc63de77b5e319442a928684ac85331183ea5b14`。两组均明确停止后删除、本组卷删除，最后网络为空后删除。result cleanupComplete=true/originalUnchanged=true；主管另按run标签只读查询container/volume/network均0。

## 证据与结论边界

- 原命令/资源账本/结果：`Tests/PTYDebugAcceptance/.build/audit-pair-d063d49c43d34fffb412b8b31412f3af/`。
- 主管执行/退出/hash：`DerivedData/Verification/primary-audit-pair-r1-live-243aa9b9-115e-4b35-9b85-0ff66f64390a/`。
- 主管独立结果一致性、实际权限位和零资源后验：`DerivedData/Verification/primary-audit-pair-postcheck-b872435f-3a18-4566-a1b3-295fd5cd51b6/`。
- 脚本默认/help/plan均不触Docker；授权开关仅防误动作，非新增授权。

下一实现只修keyonly的cap allowlist及受控单服务重建，不动其他三认证服务、App协议/gate或关闭断言。原服务重建会更换CID、/run主机密钥及凭据，旧generation/测试报告继续保留，活动消费者必须fresh contract/带外指纹，不能静默接受变化。旧大文件namedvolume应保留且不重新生成数据。

App的真实PTY/输入/Ctrl+C/resize/Vim、传输跨close/hide/活动窗口Quit必须在修后的真实环境另验；本对照不能代替。整体Goal NOT COMPLETE。
