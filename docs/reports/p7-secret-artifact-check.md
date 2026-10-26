# P7 当前秘密出口与候选内容只读检查

当前范围：下方旧344文件/P6A为历史静态检查；最终修复与最新fdb05b4d候选的限定delta检查见末节，未发现可确认的新增秘密或敏感材料误入。两次均不替代完整运行时/全历史AC25验收。

限定静态检查结论：当前跟踪/索引未发现实际私钥、凭据库、证书或测试运行材料；所检查认证/日志/argv/env/SQLite显式出口未见密码、OTP、私钥字节落入普通配置或日志的明确路径。不是运行时或全部Git历史泄漏证明。

独立只读agent检查344个git跟踪文件/索引blob、68个正式App/包源码及3个新增App源。严格PEM/PuTTY私钥块0；6处privatekey头标记属于解析器常量/无效测试/打包拒绝规则，无固定私钥。SecretBytes与AuthenticationSecret普通/调试/反射脱敏；Askpass helper的stdout是预期认证管道，不是日志，stderr固定；ssh-keygen口令输入pipe不argv/env。Core/journal仅引用与元数据；SFTP内存材料未见日志/DB出口。没有读取.runtime、用户.ssh或Keychain，未运行build/GUI/网络。

P6A内部候选UUID996cff64：App31普通文件，ZIP31文件/18目录，逐文件hash差异0；test/fixture/experiment/runtime/signmaterial/敏感后缀/源码日志DB0。ZIP无重复、逃逸、特殊链接，二进制常量匹配经结构核对无有效私钥envelope，未打印匹配内容。主程序/helper系统runtime链接，无Homebrew/开发机绝对runtime。候选仍UNSIGNED INTERNAL、Gatekeeper false、未公证上传；后续B1新产物需再核。

实际命令：git status/ls-files(-z,--stage)/cat-file--batch/check-ignore--no-index，Python仅路径/规则计数扫描、ZIP清点/hash/私钥结构检查，otool-L/-l。未重跑packager全套，未扫描全部历史/任意编码秘密/运行时内存/所有日志。发现根gitignore未覆盖部分Keychain/证书/顶层runtime/signmaterial/id_dsa，当前跟踪0，属于预防性忽略缺口而非泄漏；主管按明确文件名/目录扩充并用合成路径验证，不删除任何内容。

## 最终修复与内部候选的限定 delta

P7-FINAL-SECRET-DELTA-CHECK由独立只读审查者执行，主管读取结果并对应本轮已审生产/fixture出口；未重复旧344文件全宽扫描。

- 仅扫描提交ba4a2ec/d331188的15文件变更、1062新增行，读取少量必要上下文；新增文本私钥/PuTTY材料规则0命中。
- 压力输入为合成文本，报告仅字节/批次/长度/资源/生命周期统计。Transport public marker非凭据；随机late answer一处生成、两处认证respond调用，无直接日志/文件/argv/env出口。父进程只记录PID/退出码/捕获字节数，不保存载荷。诊断stdout为模式/状态/计数/服务生命周期，无随机回答插值。
- 最新候选 `DerivedData/Distributions/0.1.0-1-8b6396199db2/fdb05b4d-a035-4040-8ded-5d549ffadb57/`：App32普通文件，ZIP32文件/19目录，文件名集合差异0；敏感/私钥/凭据/test/fixture/log/profile/personalruntime/database路径无违规。build规则4路径项仅为notice中的build-tool-Text-Template目录/LICENSE，非构建产物。
- 29份候选文本（含外层manifest）私钥头/有效OpenSSH载荷/PuTTY/证书块规则0命中。文件分类为2入口可执行、1正常签名seal、4元数据/隐私、25notice/许可/来源文件；不在本轮delta重验签名或archive hash，后者由主管独立打包验证承担。

实际命令：限定git status/show/diff（no-optional-locks/no-ext-diff/no-textconv/no-renames）及Python标准库新增行扫描、路径/文本/zipnames检查，全部exit0。不运行App/build/签名/网络/Keychain，不读个人.ssh、公司资料、秘密环境、ignored日志或trace，不打印疑似内容。

**结论：限定delta未发现新增真实秘密、lateanswer日志泄漏或敏感材料误入；不覆盖运行时、二进制内部、任意编码秘密或全Git历史，不将完整AC25标通过。**
