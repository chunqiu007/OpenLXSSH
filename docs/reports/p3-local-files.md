# P3本地直接文件后端与LTS依赖审查

更新2026-10-26；工程师实现，主管独立审查。状态PARTIAL：本地接口/安全策略通过，真实SSH/SFTP成功路径未验证。

## 交付与修订

实现 `Experiments/P3-RemoteFileProbe/`，原P3-LOCAL-A固定源码libssh2/OpenSSL构建、真实C适配与27本地测试已主管审查/独立27项+Release smoke通过。R1补齐typed endpoint DNS/TCP、同握手共用信任、分项传输能力与显式风险流程，并将短维护OpenSSL3.6.5改3.5.9 LTS。

最终固定OpenSSL3.5.9：tag object d0ca66a1abe52545f14eca635c648932fcde5615，peeled45e844fa2a14ec92d146bd8f5778ac130b6625fb，官方archiveSHA603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a。维护证据至2030-04-08；源码/官方checksum/许可和编译器/SDK/flags见native-inputs.json/manifest。

P0曾记录OpenSSL3.6.5 hash e5c234...与现场tag/peeled不一致，不能断言原因；本轮来源重新核对并明确区分tag object/peeled/归档hash，不用旧模糊hash作生产输入。3.6历史证据保留于实验.build/verification/history，不误删或假称最终仍使用。

## 代码审查

主管已读取C Bridge、Swift libssh2、RemoteFileService、LocalFixture、SafeTransferEngine、TransferPolicy、TCPConnector、SharedHostTrust、主要本地/原生/回调测试及verify脚本。

- 非阻塞libssh2 EAGAIN按方向poll，20ms检查cancel/timeout；预信任拒绝credentials，hostkey绑定同handshake，正式OpenLXSSHTrust按host/port/algorithm/rawblob确认，变化拒绝。
- DNS/TCP入口不暴露任意FD给产品，调用可取消/超时，resolver最多4未完成；底层getaddrinfo不可强制中止如实披露。
- 字节路径精确、结构化C API不解析CLI输出；callback支持多/零prompt、typed用户回答、截止/取消/迟到失效，不猜密码/OTP。
- 本地rootFD/noFollow与原子noReplace，唯一temp、单host串行/全局chunk2；远端逐component lstat与非CAS覆盖风险显式，不自动伪造能力确认。旧“所有能力false/全部拒绝”已被分项策略替代，具体见P3 ADR。
- 覆盖先完整temp、再目标属性/流式SHA检查、已知竞争拒绝；仅posix-rename扩展，不先删目标/普通renamefallback；没有真实扩展互通证据。

## 主管独立验证

工作目录工作区；先独立27项strict测试和Release native smoke退出0。R1最终独立运行：

```sh
python3 /Users/liuwenshuo/Desktop/OpenLXSSH/Experiments/P3-RemoteFileProbe/Scripts/verify.py
```

退出0，Debug/Release/ASan/TSan各46项、0失败；native输入/产物hash、真实库版本/libssh2 1.11.1+OpenSSL3.5.9 arm64、otool仅系统库、compile-only minos26.0/SDK26.2均过。

工程师清洁重复原生构建三个a档案hash相同，修复ar时间戳与SwiftPM triple被platform覆盖的问题后重新验证；主管没机械再重建未变原生库。正式Trust依赖迁移后工程师完整复跑46项矩阵，P3构建图只依赖Trust library不含fixture。

证据：实验 `.build/verification/results.json`、native-reproducibility.json、local-package-inputs.json、`.build/native/manifest.json`及完整licenses。

## 未完成

无服务器连接、认证/MFA、真实SFTP/POSIXrename/fsync/安全非覆盖服务能力证据。loopback/socketpair是无协议peer，绝非互通。上游静态库没有ASan/TSan插桩，上游tests未跑；macOS26仅编译，不是runtime。条件竞争非CAS风险不能记强保证；本地真实文件测试不能算远端成功。

正式唯一实现正在提升到Packages/OpenLXSSHFiles，含自包含依赖与文件UI所需安全删除计划/重命名选择。真正后端定稿和FILE验收须待隔离服务；不能以PARTIAL实验或候选App宣布Goal完成。
