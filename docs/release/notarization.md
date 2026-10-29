# OpenLXSSH 公证交接

当前批准对象为1.0.0/build3、source4616677：

- 归档：`DerivedData/Distributions/1.0.0-3-4616677a3edc/89cfceaa-a6fb-45fd-8f67-07d430438ef0/OpenLXSSH.zip`
- SHA256：`e91a18d2d75b2cef32f82b1ea1cfe9356ac3f31a24577565b07ac43ed9ccb7a8`
- 大小：7,318,818字节。
- 用户已批准上传Apple公证服务，以及成功后附加票据并另记最终分发包摘要。尚未提交。

## 用户本人准备登录配置

1. 登录Apple账号的“登录与安全性→App专用密码”，本人创建仅用于本次公证的专用密码，建议名称OpenLXSSH Notary。参考[Apple官方说明](https://support.apple.com/102654)。不要把密码发到聊天中。
2. 在自己的终端运行下面命令，将邮箱占位文字替换为开发者账号。Team ID已从当前候选签名实际核对。

```sh
xcrun notarytool store-credentials "OpenLXSSH-notary" \
  --apple-id "你的开发者账号邮箱" \
  --team-id "74Q9ARM7JJ"
```

3. 等终端安全提示后输入App专用密码，不能把密码加到命令参数或写入文件。该命令默认向Apple验证后，将配置保存至本机Keychain。账号、双重认证和系统授权均由用户本人操作。
4. 成功后只回复配置名称`OpenLXSSH-notary`。若失败，仅提供去掉账号和秘密的错误说明。

## Agent接续

仅使用用户告知的指定profile，不枚举其他Keychain。提交前重新核对原ZIP摘要与候选完整性；只提交一次，保存submission ID，后续查询同一提交。公证成功后在独占副本附票据，严格验证主/helper签名、票据和Gatekeeper，并另建最终归档及摘要，保留原上传对象和候选manifest。候选打包器的`--verify-manifest`只接受未上传内部候选，不修改其`uploaded=false/notarized=false`来冒充最终发布记录。

公证后仍需第二台Mac与用户人工场景记录，不能仅凭Apple接受就宣布整个产品验收完成。
