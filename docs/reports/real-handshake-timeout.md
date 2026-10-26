# 真实本机 SSH 握手超时：静默单连接 peer

日期2026-10-27，Task REAL-HANDSHAKE-TIMEOUT-PREP-A / LIVE-A。**固定本机TCP已接通后的生产SSH握手超时单案通过；主管源审、独立离线复验与原错误/资源结果核验。不是TCP SYN或外网服务器超时。**

## 固定范围与原始失败门

仅新增 `Tests/HandshakeTimeoutAcceptance/` 八文件，默认/help/validate无I/O、live双门及精确自有UUID contract。固定127.0.0.1:22221，无任意地址/端口/预算，不REUSEADDR/REUSEPORT、冲突即失败，不回退端口。

测试自己的有限静默TCP peer仅accept一次，随即关闭listener；accepted FD从不read/recv/write/send，不解析、记录或快照SSH wire。生产公开LibSSH2FileService connect使用TCP1s/operation2s；peer8s/outerwatchdog10s/外层20s。没有Docker/relay/真实sshd或任何凭据、generation、Keychain。

无秘密KBI/trust handlers只作意外调用检测，调用即取消并使场景失败。成功须实际accept1、**原始typed timeout/handshake/-10002**、单调≥1.5且<8、auth/trust0/SFTP0、outercancel未触发及所有ownedpeer FD/task关闭、总FD恢复baseline联合。ECONNREFUSED、transport、取消或其他operation超时不能算通过。

## 实现与独立离线验收

PeerDescriptors唯一持有listener/accepted所有权，close前清持有数字，幂等；非阻塞5ms有限loop，stopAndWait实际await task，不fire-and-forget。Trust清理只固定空header known_hosts与lock，owner/mode/singlelink/nofollow/FDidentity核后删除，未知保留。

主管完整读peer/契约/分类/公共connect/watchdog/清理/build和测试，并独立5Python/50Swift synthetic及pipe-FD机制、5CLI、200输入及快照/29命令/160native、strict ad-hoc通过；未用offline socket测试冒充真实。

精确driver：`Tests/HandshakeTimeoutAcceptance/.build/host-cd6473b1-5820-474e-9992-026627217804/artifacts/OpenLXSSHHandshakeTimeout`

SHA256 `0d98b2cb588ba420620e7d6d7906328a38a061abad052267913f24f39b56edb7`。

独立静态证据：`DerivedData/Verification/primary-handshake-timeout-static-695889b7-f728-4c05-99cb-c4094dc4155e/`。

## 唯一真实单案

原rootrelay无listener且前任务明确释放后，仅本机测试占固定端口，新case `271329d5-2318-4a1b-933c-d3b0b768ec92`。driver PID26221首轮exit0，外层2.084881s，原生产connect单调2.015900s：

- raw FileServiceError：timeout / handshake / code−10002。
- peer accepted1、sentBytes0、readCalls0、ownedFD0、listenerClosed/acceptedClosed/taskCompleted=true，未peerexpiry。
- auth0/trust0/SFTP0/outerCancelled=false，不是watchdog先取消。
- 全进程FD4→4，fixture/client peer socket0→0。
- ownedRootFDsAfter=1是采样时仍在作用域内的Trust目录FD，不写成0；随后TrustRootRemoved=true、进程退出后exactroot不存在。
- lsof22221～22225无LISTEN或accepted/clientTCP，exactPID不存在，driver/sourcehash不变。

无重跑/改断言/构建/容器操作；case只保留0600/singlelink契约、runclaim与结果。

## 证据与主管独立结果核验

实际argv/cwd/exit、签名/preflight、原result-copy及postflight：

`Tests/HandshakeTimeoutAcceptance/.build/live-ae36235c-c299-4e90-92ca-5152521ba8b1/`

原result：`Tests/HandshakeTimeoutAcceptance/.runtime/handshake-271329d5-2318-4a1b-933c-d3b0b768ec92/result.json`。

主管另读原result，核raw错误三元组/单调时间、actualaccept1/no callbacks/watchdog、ownedFDtask/FD4→4、采样TrustFD1与最后rootabsence/sourcehash，不仅看exit0。独立复核：

`DerivedData/Verification/primary-handshake-timeout-results-e0c98a38-171e-4302-be07-808d6f939aeb/`

## 限制

仅证明本机TCP连接建立后等待SSH握手的真实deadline，不覆盖SYN timeout、外网/生产服务器、GUI、macOS26或所有网络异常。客户端可能向内核发送SSH数据，peer没有读取/记录，sent/read0不解释为整个系统无网络字节。资源结论为公开awaited-close与本进程FD/socket后验，不是逐原生内部协议CLOSE计数。整体Goal NOT COMPLETE。
