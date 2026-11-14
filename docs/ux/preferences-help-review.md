# 分类设置与本地帮助：审查检查点

日期：2026-10-30（记录跨至31日零点的验证）。状态：**实现与本地模型/renderer/迁移门已审，主管独立设置/关闭/Files43项及Core18项复验通过；实际GUI仍未过。** 不将本轮称window/tab完整体验。

## 实现与范围

- 六分类统一设置：通用外观、终端、连接、文件传输、隐私诊断、快捷键关于；Cmd+,与应用菜单仍同入口。
- 字体目录仅列真实可用等宽字体，显式不可用状态；预览直接使用同NativeTerminalView/TerminalPreferences，不再把默认深色预览映为系统白底。
- 光标形状/闪烁通过固定SwiftTerm公开setCursorStyle接线；保存应用已有tab，不重连/重建owner，远端TUI仍可按协议改变光标。
- 类别/全部设置reset只改草稿，保存后生效；不影响主机、分组、密钥、信任、凭据或独立文件列布局。未增加假并发/冲突默认/超时/粘贴开关。
- 保留既有精确UTF8/BracketedPaste/256KiB；可选多行确认本轮未提供，UI如实说明。
- v4 additive仅cursorShape/cursorBlink/startupPage三非秘密字段。旧配置缺字段使用安全默认，未知字段值拒绝；已有颜色和host授权不重写。startup只vault/sftp/lastManagement，不恢复session/answer/search/output。
- SettingsEditorModel保存前同步冻结，失败保草稿，准确owner Save/Discard/Cancel；preferences overlay不覆盖长驻Vault guard，物理卸载后再审核底层dirty host，同owner稳定重注不打断pending，旧owner回答不能授权新owner。
- 帮助本地快捷键/版本/数据说明/许可，诊断仅白名单版本/系统/泛化计数/参数先预览后显式复制，无网络上传、不读用户剪贴板、Keychain或终端历史。
- Settings父窗高度有界，类别/正文独立scroll，未提高主窗minsize；实际最小窗button/viewport仍待。

13个精确源与本轮before diff：`DerivedData/UXVerification/DesktopPreferencesHelp-R1/verified-source.patch`、`verified-source-sha256.json`，统一Prefs13+Files6摘要在`verified-unified-hashes.json`。

## 主管独立源审

已读取Core Models/Schema、AppModel设置保存/关闭registry/SettingsEditorModel/TerminalPreferences/诊断/许可、Editors实际View和新测试。要求并已接回：同owner重注册不随pending取消；Settings批准只是overlay，不能绕过底层Vault；固定620表单改父高有界；不声明深Keys/Trust管理页或windowframe已恢复。

许可资源已实际核bundle和native install的固定路径存在。诊断的任意error.description/用户路径不进入预览，独立NSPasteboard测试不读general。

## 工程师实际验证

真实argv/cwd/日志索引：`verification-results.json`及同目录日志。

| 门 | 结果 |
| --- | --- |
| 正式Debug build-for-testing首次 | exit65；Files测试引用未共享DualFilesDialog；由Filesowner原样移到实际共享model，原失败保留 |
| 正式Debug第二次 | exit0，TEST BUILD SUCCEEDED |
| Core精确迁移/设置定向 | 18/0、exit0，Swift6/warnings-as-errors，显式Swift/C target26 |
| 正式App设置/关闭/认证回归 | 99/0、exit0 |
| Transport偏好及受影响renderer | 12/0、exit0，实际arm64/min26 |

App99覆盖Prefs12+旧相关4、Native25、Editor7、Reliability13、Close的10+6和Session22（其中2个关闭测试计入旧Close18），不重复累计。

Core首次仅triple的18/0实际min15，保留且不冒min26；第二次显式target后vtool核Models/Schema/Coretest/xctest均minos26.0。App/xctest/Editors/AppModel与Transport对象/xctest也实核min26。主管已独立读取三份原日志与准确count。

主管独立复验：`Primary/independent-preferences-close-files-1` **43/0、exit0**（Prefs12、CloseEditor10、CloseState6、FilesOwner15），以及 `Primary/independent-core-preferences-1` **18/0、exit0**，使用既有已核min26产物而不构建正在写入的runtime。源审、命令与实际数量均已核；独立43不是新增产品覆盖百分比。

## 尚未通过/未实现

- 实际设置GUI最小父窗/三尺寸、字体picker、许可显示、焦点与真实Save/Discard/Cancel；旧NativeSmoke单Grid设置流程需工具owner按真实分类适配，不能改产品迎合旧测试。
- window frame、分栏比例、Vault深子页恢复；标签overflow箭头/resize-reorder可见/中键/immutable批量清单；展示名称/删除配置badge与连接快照分离。这些不在本轮完成范围。
- 新Core migration与全局关闭层变化已由主管独立Core18、Prefs/Close/Files43复验；本地`0936fd6`仅提交Core模型/迁移/测试和本报告，实际设置App/UI尚未整批暂存，不冒整体完成。
- 不Release/生产/live/Keychain/Apple/最终出包；默认Direct不变，不启用未定案Native活性迁移。
