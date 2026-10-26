# P7 当前秘密出口与候选内容只读检查

限定静态检查结论：当前跟踪/索引未发现实际私钥、凭据库、证书或测试运行材料；所检查认证/日志/argv/env/SQLite显式出口未见密码、OTP、私钥字节落入普通配置或日志的明确路径。不是运行时或全部Git历史泄漏证明。

独立只读agent检查344个git跟踪文件/索引blob、68个正式App/包源码及3个新增App源。严格PEM/PuTTY私钥块0；6处privatekey头标记属于解析器常量/无效测试/打包拒绝规则，无固定私钥。SecretBytes与AuthenticationSecret普通/调试/反射脱敏；Askpass helper的stdout是预期认证管道，不是日志，stderr固定；ssh-keygen口令输入pipe不argv/env。Core/journal仅引用与元数据；SFTP内存材料未见日志/DB出口。没有读取.runtime、用户.ssh或Keychain，未运行build/GUI/网络。

P6A内部候选UUID996cff64：App31普通文件，ZIP31文件/18目录，逐文件hash差异0；test/fixture/experiment/runtime/signmaterial/敏感后缀/源码日志DB0。ZIP无重复、逃逸、特殊链接，二进制常量匹配经结构核对无有效私钥envelope，未打印匹配内容。主程序/helper系统runtime链接，无Homebrew/开发机绝对runtime。候选仍UNSIGNED INTERNAL、Gatekeeper false、未公证上传；后续B1新产物需再核。

实际命令：git status/ls-files(-z,--stage)/cat-file--batch/check-ignore--no-index，Python仅路径/规则计数扫描、ZIP清点/hash/私钥结构检查，otool-L/-l。未重跑packager全套，未扫描全部历史/任意编码秘密/运行时内存/所有日志。发现根gitignore未覆盖部分Keychain/证书/顶层runtime/signmaterial/id_dsa，当前跟踪0，属于预防性忽略缺口而非泄漏；主管按明确文件名/目录扩充并用合成路径验证，不删除任何内容。
