# Electron Windows 构建安全加固

用 **electron-builder** 打包 Windows 应用时，如何把启动 exe、卸载器、安装器被篡改/替换/提权植入恶意代码的风险降到最低。

本仓库不是二手转述。所有结论来自两个来源，并在文中逐条标注：

- `[实测]` — 对官方 `electron-v44.4.5-win32-x64` 二进制做 PE 级解析与 fuse 翻转验证
- `[源码]` — 阅读 electron-builder v26.15.3 / Electron v44.4.5 / electron-updater v6.8.9 的实际源码

## 三个最关键的结论

### 1. 你不需要、也不应该自己去开 `/GS` 之类的编译选项

electron-builder 产出的 `YourApp.exe` 不是它编译的 C++ 程序，而是**官方 `electron.exe` 改名后的副本**，之后只用纯 JS 库 `resedit` 改资源段，不碰代码段。

实测官方 Electron 二进制的加固已经完整：

```
DllCharacteristics = 0xC160  → HIGH_ENTROPY_VA + DYNAMIC_BASE + NX_COMPAT + GUARD_CF
SecurityCookie      = 0x14E2B6040              → /GS 已开
GuardFlags          = 0x4E22DDCD
    CF_INSTRUMENTED, CF_FUNCTION_TABLE_PRESENT, SECURITY_COOKIE_UNUSED,
    PROTECT_DELAYLOAD_IAT, CF_EXPORT_SUPPRESSION_INFO_PRESENT,
    CF_ENABLE_EXPORT_SUPPRESSION
    CFG 表项步长 (bits28-31) = 4 → 每项 4 字节（标准地址宽度）
CFG 函数表          = 207,090 个合法间接调用目标
```

**不要**事后用 `editbin` 去"补"这个 246MB 的 Chromium 二进制——会破坏它，且任何字节改动都让签名失效。

真正的风险不是 exe 没加固，而是**这个已加固的 exe 在用户机器上会被换掉**。

### 2. 默认配置下你的应用带着 5 个高危开关上线

实测官方 Electron 出厂 fuse wire = `101100011`：

| fuse | 出厂状态 | 风险 |
|---|---|---|
| `RunAsNode` | **ENABLED** | `ELECTRON_RUN_AS_NODE` 可把主程序当通用 Node 解释器用 |
| `EnableNodeOptionsEnvironmentVariable` | **ENABLED** | `NODE_OPTIONS=--require evil.js` 可在你进程内执行代码 |
| `EnableNodeCliInspectArguments` | **ENABLED** | `--inspect` 打开调试端口直接接管主进程 |
| `EnableEmbeddedAsarIntegrityValidation` | **DISABLED** | app.asar 完整性校验防线默认是关的 |
| `OnlyLoadAppFromAsar` | **DISABLED** | 校验可被 `resources\app\` 目录绕过 |
| `GrantFileProtocolExtraPrivileges` | **ENABLED** | `file://` 越权访问 |

`electronFuses` 在 electron-builder 里是**可选配置，不写就不翻转**。

### 3. 存在一条具体的本地提权链，而默认配置落在危险侧

```
nsis.perMachine 默认 false
→ 装到 %LOCALAPPDATA%\Programs\YourApp\  【用户可写】
→ 卸载器 "Uninstall YourApp.exe" 就在这个目录里
→ 攻击者替换它
→ 之后任何以管理员身份触发的卸载都会执行攻击者代码：
   · 管理员从"添加或删除程序"点卸载
   · 或企业软件清单工具执行注册表里的 QuietUninstallString "... /allusers /S"
```

缓解是一行 `nsis.perMachine: true`，但**必须同时** `allowToChangeInstallationDirectory: false`，否则用户能把应用装到 `C:\Users\Public\` 把保护重新打开。

> 核心认知：**Windows 在用户双击程序时不校验签名**。签名只在你主动校验、或 WDAC / SmartScreen 校验时才起作用。所以签名必须配合"安装目录不可被普通用户写入"才有意义——这两条是绑定的，缺一条另一条就基本失效。

## 仓库内容

| 文件 | 说明 |
|---|---|
| [`Windows构建安全加固调查报告.md`](Windows构建安全加固调查报告.md) | 调查报告。攻击面拆解、完整性链条、配置清单、剩余风险、审计工具命令。每处结论标注来源 |
| [`electron-builder.config.js`](electron-builder.config.js) | 可直接使用的加固配置模板。**已通过 electron-builder 官方 JSON Schema 校验（ajv，0 错误）**，每行注明依据与代价 |
| [`verify-win-hardening.mjs`](verify-win-hardening.mjs) | 构建后验收脚本（CI 发布门禁），零依赖 |
| [`research/reference/`](research/reference/) | 调查用的一手资料：Chromium 编译参数 GN 文件、`MSVC.cpp`、BinSkim 规则源码、Microsoft 文档存档 |
| [`research/reference/pecheck.py`](research/reference/pecheck.py) | 独立 PE 解析实现，用于交叉验证验收脚本 |

## 验收脚本

没有验证的加固只是信仰。这个脚本在真实二进制上做过双向验证：

```
未加固（官方 Electron 原样）        → exit=1，FAIL=7，逐条列出缺失项
加固后（fuses 翻转 + Integrity 注入）→ exit=0，PASS=21，FAIL=0
```

检查项：

1. **PE 缓解措施** — ASLR / HighEntropyVA / DEP / CFG，以及 Load Config 里的 `SecurityCookie`（`/GS`）、`GuardFlags`（确认 CFG **真的被插桩**而不只是置了个标志位）、`EH_CONTINUATION_TABLE_PRESENT`、CFG 合法目标表大小
2. **Electron Fuses** — 9 个 fuse 逐个对照，区分 FAIL（安全相关）与 WARN（性能相关）
3. **ASAR 完整性** — 资源存在性 **+ 哈希与磁盘上 app.asar 的一致性**（防"资源陈旧"或"张冠李戴"）
4. **危险残留** — `elevate.exe`、侧加载 DLL 面、未签名 PE 清单
5. **Authenticode** — Windows 上验签，检查有效性、**时间戳**、证书主体匹配

```bash
node verify-win-hardening.mjs dist/win-unpacked --expect-publisher "Your Company Ltd."
```

```yaml
# CI 门禁
- name: Verify Windows hardening
  shell: pwsh
  run: node verify-win-hardening.mjs dist/win-unpacked --expect-publisher "Your Company Ltd."
  # 非 0 退出 → 阻断发布
```

它能抓住那些"配了但没生效"的情况：构建缓存复用旧 exe、`signAndEditExecutable: false` 导致资源没写进去、证书过期、忘了配 `publisherName` 导致更新验签被静默跳过。

## 调查中纠正的四个技术误区

写在这里是因为它们都会导致真实的错误实现：

**1. ASAR header 哈希的输入范围。**
Electron 校验的是 **pickle 解码后的 header 字符串**，**不含**文件里 8 字节对齐的填充块。实测样本：508 字节字符串 vs 512 字节对齐块，尾部 4 个 `0x00` 让哈希完全不同（`2e90a55f…` vs `054719ad…`）。本仓库的验收脚本第一版就因此误报。自己实现构建或校验时，必须先读 pickle 的字符串长度再取字节。

**2. PE 里 `VirtualSize = 0` 的 section 会破坏朴素的 RVA→文件偏移映射。**
用 `max(VirtualSize, RawSize)` 做范围匹配时，一个 `RawSize` 高达 2.5GB 的 section 会吞掉整个地址空间并抢到错误映射，导致 `GuardFlags` 读成 `0x48000007` 而非正确的 `0x4E22DDCD`，误报"CFG 未插桩"。正确做法：**只用 `VirtualSize` 判定归属，多候选取虚拟范围最小者**。

**3. `SafeSEH` 在 x64 上无意义。**
它只对 32 位 x86 有效。x64 用表驱动的展开信息，`SEHandlerTable` 为空是**正常**的。不要因为 BinSkim 报 `BA2018` 就以为 x64 有问题。

**4. `GuardFlags` 的位定义不能凭记忆，必须查权威来源。**
本仓库 v1 在这里出过错：把 `EH_CONTINUATION_TABLE_PRESENT` 写成 `0x00200000`（**正确值是 `0x00400000`**），据此把 v44 的 `/guard:ehcont` 报成"已开启"——实际 v44 该位未设置。同时 bits 28-31（`0xF0000000`）是 `CF_FUNCTION_TABLE_SIZE_MASK`（CFG 表项步长），**不是标志位**。
正确依据是 LLVM 的 [`llvm/BinaryFormat/COFF.h`](https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/COFF.h) 中的 `GuardFlags` 枚举。除已定义的位之外还有大量位（实测 v41 命中 `0x0C940035`、v44 命中 `0x0E2200CD`，散布在 bit0-7 与 bit17-27）在任何公开文档中都没有定义——**不要给它们编造名字**。验收脚本已改为动态计算"未映射位"（取已定义位的补集），不再硬编码掩码。

## 兼容 Electron 41

`electron@41.10.7` 与 `44.4.5` 的实测对比：

| 项目 | 41.10.7 | 44.4.5 |
|---|---|---|
| **fuse wire** | `101100011` | `101100011`（**逐位相同**） |
| DllCharacteristics | 0xC160 | 0xC160 |
| ASLR / HighEntropyVA / DEP / CFG | 全开 | 全开 |
| SecurityCookie（`/GS`） | 0x14CDE4040 | 0x14E2B6040 |
| CFG 函数表规模 | 191,452 | 207,090 |
| `CF_FUNCTION_TABLE_PRESENT` | 未置位 | 已置位 |

**本仓库的 `electronFuses` 加固配置对 41 完全适用，一个字都不用改**；"5 个高危开关默认开启"的结论对 41 同样成立。就本仓库关心的威胁模型（防替换、防篡改）而言，41 与 44 **没有实质区别**。

> ⚠️ **但 Electron 41 已于 2026-08-24 EOL。** 官方支持策略是最新 3 个稳定大版本（当前为 44 / 43 / 42，其中 42 将在 2026-10-20 EOL）。EOL 意味着 Chromium 146 与 Node 24.18 之后发现的漏洞都不会再为 41.x 修复——仍可构建、仍可发布，但暴露在未修补的漏洞之下。这在等保 / ISO 27001 / 客户安全问卷里通常也会被直接判定为不符合项。

另外建议把所用 Electron 版本**归档到你自己的存储**：EOL 不影响 GitHub Releases 上的产物存在（本次实测直接下载成功），但不要依赖上游长期保留。

## 已知的未解权衡

诚实记录，避免给出虚假的安全感：

- **`perMachine: true` 与 `packElevateHelper: false` 冲突。** 源码里 `perMachine: true` 会忽略后者并告警，因为 per-machine 更新需要 `elevate.exe` 提权。想彻底移除它只能选 per-user 安装，但那又引入上面的提权链。**没有完美解。**
- **更新验签有三个弱点**（源码确认）：`publisherName` 没配则校验直接返回 `null`（视为通过）；只比证书主体**不比哈希**，等于把证书私钥变成整条更新链的单点信任根；Windows 7/8/Server 2008 R2 上会跳过校验。
- **`nsis.script` 自定义脚本会导致卸载器不被签名**（源码里直接短路）。
- **`app.asar.unpacked` 的文件**不受 header 整体保护。
- **管理员权限的攻击者**：签名和 ACL 都挡不住，需要 WDAC / AppLocker。

历史提醒：`CVE-2024-46992`（Electron 30.0.0–30.0.4 的 ASAR 完整性绕过）说明完整性校验本身也曾经有 bug。**这正是它必须和 `perMachine: true` 叠加使用的原因**——单靠它不够。

## 快速开始

```bash
# 1. 复制配置模板
cp electron-builder.config.js /path/to/your-project/

# 2. 改掉这几处占位符
#    APP_ID / PUBLISHER_NAME / publish.owner / publish.repo

# 3. 删掉 package.json 里的 "build" 字段（否则与外部配置文件冲突）

# 4. 设置签名证书（走环境变量，绝不入库）
export CSC_LINK="base64 的 pfx 或文件路径"
export CSC_KEY_PASSWORD="..."

# 5. 构建
npx electron-builder --win --publish never

# 6. 验收
node verify-win-hardening.mjs dist/win-unpacked --expect-publisher "Your Company Ltd."
```

## 行动清单（按投入产出比）

| # | 动作 | 挡住的风险 | 成本 |
|---|---|---|---|
| 1 | 配 `electronFuses`（8 项） | 代码替换、调试端口、环境变量注入 | 5 分钟；需改 `child_process.fork` |
| 2 | `nsis.perMachine: true` + `allowToChangeInstallationDirectory: false` | **本地提权链** | 安装需管理员 |
| 3 | `win.forceCodeSigning: true` + 代码签名证书 | 篡改检测、SmartScreen | 证书费用 |
| 4 | `signtoolOptions.publisherName` + `rfc3161TimeStampServer` | 恶意更新、签名过期 | 5 分钟 |
| 5 | 显式写死 `publish.owner/repo` | 更新源被抢注 | 2 分钟 |
| 6 | 验收脚本接入 CI | 所有"配了但没生效"的情况 | 10 分钟 |
| 7 | 升级 `electron` 到最新稳定版 | 已知 CVE | 回归测试 |
| 8 | 企业环境部署 WDAC/AppLocker | 管理员权限以下的全面防护 | 需 IT 配合 |

## 基线版本

`electron@44.4.5` · `electron-builder@26.15.3` · `@electron/fuses@2.1.3` · `electron-updater@6.8.9`

已对 `electron@41.10.7` 做完整实测对比，结论见上文「兼容 Electron 41」。

electron-builder v27 有几项安全默认值会变化（web installer 默认禁用、移除隐式 `--publish`、`latest*.yml` 的 Ed25519 签名等），升级前请对照报告第 0 节与官方 v27 Breaking Changes。

## 参考

- [electron-builder — Security & Hardening](https://www.electron.build/docs/features/security/)
- [Electron — Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [Electron — ASAR Integrity](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [Electron — Security Checklist](https://www.electronjs.org/docs/latest/tutorial/security)
- [GHSA-xw5q-g62x-2qjc / CVE-2024-46992](https://github.com/electron/electron/security/advisories/GHSA-xw5q-g62x-2qjc)

## 许可

文档与脚本采用 [MIT License](LICENSE)。`research/reference/` 下的第三方资料（Chromium 源码片段、Microsoft 文档、BinSkim 规则源码）版权归各自所有者，仅作查证留档。
