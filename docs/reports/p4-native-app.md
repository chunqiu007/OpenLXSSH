# P4-APP-A：正式原生App最小集成审查

日期：2026-10-26。工程师实现，Primary Agent独立审查。

## 结论

正式OpenLXSSH Xcode Target、主机管理和持久化设置的本地最小集成通过。完整产品未完成：当前尚无真实SSH/终端/SFTP/密钥管理集成，连接路由明确返回transport.unavailable，不伪造连接或最近时间。

## 审查范围

主管已读取AppRepository、AppModel、App生命周期、MainView、Editors、NativeControls、业务测试与build/verify脚本。

- SwiftUI+AppKit原生窗口；Target/module/product/display均OpenLXSSH，arm64，正式Debug/Release最低26.0。
- 仓储actor调用真实OpenLXSSHCore，初始化与SQL离开MainActor；Application Support/OpenLXSSH/Data自有目录，不改Library/系统SSH配置。
- CRUD/复制/单层分组/收藏/搜索/认证元数据/设置真实持久化；无密码输入或虚假记住密码勾选。已有引用只保留，私钥列表来自登记元数据。
- UI历史0～50000，超界报错不静默截断；字体/颜色/保活有明确边界。
- session路由包含hostID与reuse/newSession，但当前只明确不可用；不启动进程、不写最近连接时间。
- 关闭重开只列表；正常退出等待repository.close，使用AppKit runloop回复terminateLater，修复了嵌套循环等待问题。
- HostProbe与生产配置分开，测试参数仅HostProbe有效，不将min15本机运行伪装成min26 runtime。

## 主管独立验证

工作目录 `/Users/liuwenshuo/Desktop/OpenLXSSH`：

```sh
/bin/bash /Users/liuwenshuo/Desktop/OpenLXSSH/Scripts/verify-app.sh all
```

退出0：

- 正式Debug/Release build-for-testing及showBuildSettings/vtool/lipo/otool检查通过，arm64/minos26.0/SDK26.2/模块名/GRDB锁/系统运行库均正确。
- HostProbe（显式min15 override）13项XCTest、0失败。
- 实际原生控件exercise14检查与新进程reopen8检查均通过；对应主机/组/收藏搜索/设置/关闭重开/退出重启真实执行，不是静态界面。
- 精确依赖GRDB7.11.1及其commit，发行Resources含MIT许可证；当前App无Homebrew动态依赖。

日志：`DerivedData/Verification/`。主管本次隔离数据/GUI报告在 `/var/folders/qh/g2p3kxks0s75gc6kz08kvtn00000gn/T/OpenLXSSH-AppSmoke-ke_21m4c/`。此为测试自有数据，不是真实用户配置；不包含秘密。

## 限制

正式macOS26运行未验证；HostProbe仅供宿主15.8.1实际运行。截图/原生控件事件不能替代人工视觉/IME/真实键盘体验，本会话模型不支持图像像素输入，未作人工视觉通过声明。

本轮证书签名关闭，工程默认Hardened Runtime不代表实际DeveloperID/公证。SSH/MFA/终端/SFTP/密钥管理/Keychain与传输退出保护尚未集成，不能由本轮UI成功替代。

下一步接真实SessionController、认证与终端，之后独立验证连接/信任/凭据/资源，保留所有远端及外部人工验收。
