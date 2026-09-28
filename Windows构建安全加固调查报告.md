# electron-builder 构建 Windows 应用的安全加固调查报告

**调查日期**：2026-09-28
**基线版本**：`electron-builder@26.15.3` / `electron@44.4.5` / `@electron/fuses@2.1.3` / `electron-updater@6.8.9`
**方法**：阅读 electron-builder 与 Electron 的实际源码 + 对官方 Electron Windows 二进制做 PE 级实测。所有结论标注了来源，`[实测]` 表示本机验证过，`[源码]` 表示读代码确认。

---

## 0. 先直接回答你最关心的两个问题

### 问题一：启动 exe / 卸载 exe 怎么防止被篡改、植入恶意代码、提权？

**结论：没有任何单一手段能做到，必须靠一条"信任链"叠加。按重要性排序：**

| 优先级 | 手段 | 挡住什么 | 挡不住什么 |
|---|---|---|---|
| **P0** | **Authenticode 签名 + RFC3161 时间戳** | 签名后任何字节改动都会让签名失效 | 整体替换成"另一个也合法签名"的文件；DLL 侧加载；环境变量操纵 |
| **P0** | **`perMachine: true`（装到 Program Files）** | **普通用户直接改写 exe/卸载器的能力** ← 这是提权链的根 | 管理员权限的攻击者；篡改安装包本身 |
| **P0** | **`forceCodeSigning: true`** | 构建机没配好证书时"静默产出未签名包" | — |
| **P1** | **`EnableEmbeddedAsarIntegrityValidation` + `OnlyLoadAppFromAsar`** 两个 fuse | 换掉/改写 `app.asar`、往里塞后门代码 | exe 本体被替换；`app.asar.unpacked` 里的文件 |
| **P1** | **其余 6 个 fuse** | `ELECTRON_RUN_AS_NODE`、`NODE_OPTIONS`、`--inspect` 等"合法进程被武器化"的路径 | — |
| **P2** | **`packElevateHelper: false`** | 少一个放在磁盘上、会被 `spawn` 的提权辅助程序 | — |
| **P2** | WDAC / AppLocker / Smart App Control | 在 OS 层强制"只允许签名且受信的程序运行" | 需要企业侧部署；消费级场景只有 Smart App Control |
| **无效** | 运行时自己哈希 exe 比对 | 几乎什么都挡不住（自校验可被 patch，且有 TOCTOU 窗口） | — |

**最关键的一句话**：签名的意义**不是**"防止运行"，而是"让任何改动都可被检测"。Windows 在用户双击一个程序时**不会**校验签名——签名只在你主动校验、或由 WDAC/AppLocker/SmartScreen 校验时才起作用。所以**签名必须配合"安装目录不可被普通用户写入"才有意义**。这两条是绑定的，缺一条另一条就基本失效。

### 问题二：启动 exe 怎么开启 `/GS` 之类的安全编译选项？

**结论：你不需要、也不应该自己去做这件事——因为编译选项早已在 Electron 官方发布二进制里全部打开了。**

`[实测]` 我对 `electron-v44.4.5-win32-x64` 的 `electron.exe` 做了 PE 解析，结果：

```
machine             : x64 (AMD64)
subsystem           : GUI (Windows GUI)     ← 不是 Console，无控制台窗口
DllCharacteristics  : 0xC160
    [ON ] HIGH_ENTROPY_VA        (0x0020)
    [ON ] DYNAMIC_BASE (ASLR)    (0x0040)
    [ON ] NX_COMPAT (DEP)        (0x0100)
    [ON ] GUARD_CF (Control Flow Guard) (0x4000)
    [ON ] TERMINAL_SERVER_AWARE  (0x8000)
Load Config         : present (320 bytes)
    SecurityCookie      : 0x14e2b6040   → /GS 栈保护 cookie 已存在
    GuardCFCheckFunction: 0x14e22df70   → CFG 检查函数已就位
    GuardCFDispatch     : 0x14e22df78
    CFG 函数表          : 207,090 个合法间接调用目标
    GuardFlags          : 0x4E22DDCD
        [ON ] CF_INSTRUMENTED                    ← 二进制真的被 CFG 插桩了
        [ON ] CF_FUNCTION_TABLE_PRESENT
        [ON ] CF_ENABLE_EXPORT_SUPPRESSION
        [ON ] CF_LONGJUMP_TABLE_PRESENT
        [ON ] RF_INSTRUMENTED
        [ON ] EH_CONTINUATION_TABLE_PRESENT       ← /guard:ehcont 也开了
```

**关键机制（这一点必须理解清楚）**：electron-builder 产出的 `YourApp.exe` **不是** electron-builder 自己编译的 C++ 程序，而是**把官方 `electron.exe` 改名后的副本**。

`[源码]` `app-builder-lib/out/electron/ElectronFramework.js:44-51`：
```js
const executable = path.join(appOutDir, `${packager.appInfo.productFilename}.exe`);
await fs.rename(path.join(appOutDir, `${electronBranding.projectName}.exe`), executable);
if (options.asarIntegrity) {
  await addWinAsarIntegrity(executable, options.asarIntegrity);
}
```

后续的"编辑"只是用纯 JS 库 `resedit` 改 **PE 资源段**（图标、版本信息、`requestedExecutionLevel` 清单、Integrity 资源），**完全不碰代码段**：

`[源码]` `app-builder-lib/out/winPackager.js:196-198`：
```js
await editWindowsResources(opts);   // resedit：只改资源
await this.signIf(file);            // 签名
```

**因此：**

1. `/GS`、`/guard:cf`、`/DYNAMICBASE`、`/NXCOMPAT`、`/guard:ehcont` 这些**已经在官方二进制里了，你没有任何开关需要打开**。
2. 你**也无法**通过 electron-builder 配置去改这些——因为不重新编译 Electron 源码就不可能改。
3. **绝对不要**事后用 `editbin.exe /GS` 之类工具去"补"这个二进制。往一个 246MB 的 Chromium 二进制里插桩会破坏它，而且**任何字节改动都会让签名失效**——你会得到一个既不能用又不可信的产物。
4. 如果你真的需要自己控制编译选项，唯一正规路径是从源码构建 Electron（`electronDist` 指向自建产物），成本极高，对绝大多数项目不划算。

**所以你的问题应该重新聚焦**：不是"怎么给 exe 开 `/GS`"，而是"**怎么保证这个已经加固好的 exe 在用户机器上不被换掉**"。这才是真正的风险所在，下文全部围绕它展开。

`[实测]` 顺带确认：**官方 Electron 发布二进制不带 Authenticode 签名**（证书表目录 size = 0）。也就是说，如果你不签名，你的应用就是一个**完全未签名**的产物。

---

## 1. 攻击面拆解：三个 exe 各自的风险

先纠正一个常见误解——你说的"应用启动 exe"和"应用卸载 exe"是**两类完全不同的东西**：

| 文件 | 本质 | 生成时机 | 是否被 electron-builder 签名 |
|---|---|---|---|
| `YourApp Setup 1.0.0.exe` | NSIS 安装器 | 构建时 | ✅ 是 `[源码]` NsisTarget.js:302 |
| `YourApp.exe` | **改名后的官方 electron.exe** | 构建时 | ✅ 是 `[源码]` winPackager.js:247 |
| `Uninstall YourApp.exe` | **NSIS 生成的卸载器** | **构建时先跑一遍安装器生成** | ✅ 是 `[源码]` NsisTarget.js:376 |
| `resources\elevate.exe` | 第三方提权辅助程序 | 构建时从 nsis toolset 复制 | ✅ 是（可关闭）`[源码]` nsisUtil.js:77-83 |

### 1.1 卸载器的重要事实：它是构建时生成并签名的

很多人以为卸载器是用户机器上生成的。**在 electron-builder 里不是**。

`[源码]` `app-builder-lib/out/targets/nsis/NsisTarget.js:339-380`（`computeScriptAndSignUninstaller`）：
```js
const uninstallerPath = path.join(this.outDir, `${path.basename(installerPath, "exe")}__uninstaller.exe`);
defines.BUILD_UNINSTALLER = null;
defines.UNINSTALLER_OUT_FILE = isWin ? uninstallerPath : path.win32.join("Z:", uninstallerPath);
await this.executeMakensis(defines, commands, ...);   // 第一遍：用一个只做 WriteUninstaller 的脚本生成卸载器
...
await packager.signIf(uninstallerPath);               // ★ 签名卸载器
delete defines.BUILD_UNINSTALLER;
defines.UNINSTALLER_OUT_FILE = uninstallerPath;       // 第二遍：把签好名的卸载器嵌进安装器
```

**但有两个重要例外，必须知道：**

1. **`[源码]` 如果你提供了自定义 NSIS 脚本（`nsis.script`），卸载器不会被签名。** 代码里直接短路返回：
   ```js
   if (customScriptPath != null) {
     log.info({ reason: "custom NSIS script is used" }, "uninstaller is not signed by electron-builder");
     return { script, isCustomScript: true };
   }
   ```
   → **如果你用了 `nsis.script`，你就失去了卸载器的签名保护。** 这时你需要自己在 `artifactBuildCompleted` 或构建后阶段补签，或者接受这个风险。

2. `[源码]` 卸载器被安装到 **`$INSTDIR\Uninstall YourApp.exe`**（`common.nsh:17`: `!define UNINSTALL_FILENAME "Uninstall ${PRODUCT_FILENAME}.exe"`，`include/installer.nsh:121`: `StrCpy $2 "$INSTDIR\${UNINSTALL_FILENAME}"`），注册表 `UninstallString` 指向它。

### 1.2 真正的提权链：per-user 安装 + 卸载器

这是**最需要重视的实际风险**，也是 `perMachine: true` 之所以是 P0 的原因：

```
1. 应用以 per-user 方式安装到 %LOCALAPPDATA%\Programs\YourApp\
   （这是 electron-builder 的默认行为！[源码] nsisOptions.d.ts:87 perMachine 默认 false）
2. 卸载器落在同一个目录 → 普通用户对它【有写权限】
3. 低权限攻击者把 "Uninstall YourApp.exe" 替换成恶意程序
4. 之后任何一个【以管理员身份】触发卸载的动作：
   - 管理员用户自己从"添加或删除程序"点卸载
   - 某个以高权限运行的运维脚本/软件清单工具遍历卸载项并静默卸载
     （注册表里的 QuietUninstallString = '"$INSTDIR\Uninstall YourApp.exe" /allusers /S'
      [源码] include/installer.nsh:122-123）
5. → 攻击者的代码以管理员权限执行 = 本地提权
```

注意第 4 步的攻击者不需要是"用户主动配合"——**企业环境里的软件资产扫描/静默卸载工具会自动做这件事**，这正是一大类卸载器 LPE 漏洞的成因。

**同理**：`per-user` 安装下，`YourApp.exe` 本身也在用户可写目录里。攻击者可以替换它来劫持你的应用（持久化、窃取用户在你应用里输入的凭据、以你的应用身份访问资源）。这**不是**提权，但属于严重的完整性/信任问题。

**缓解措施（三条一起上）**：
```js
nsis: { perMachine: true, oneClick: true, allowToChangeInstallationDirectory: false }
```
`allowToChangeInstallationDirectory: false` 很重要——否则用户可以（或被诱导）把应用装到 `C:\Users\Public\` 这类全员可写目录，把 `perMachine` 的保护重新打开成漏洞。

### 1.3 `elevate.exe`：一个放在磁盘上、会被 spawn 的提权辅助程序

`[源码]` `app-builder-lib/out/targets/nsis/nsisUtil.js:77-83`：
```js
promise = getNsisElevatePath(...).then(elevatePath => {
  const outFile = path.join(appOutDir, "resources", "elevate.exe");
  const promise = copyFile(elevatePath, outFile, false);
  if (signAndEditExecutable !== false && signExecutable !== false) {
    return promise.then(() => target.packager.signIf(outFile));   // 会签名
  }
  return promise;
});
```

它被 electron-updater 这样使用，`[源码]` `electron-updater/out/NsisUpdater.js:101-130`：
```js
doInstall(options) {
  const installerPath = this.installerPath;       // ← 刚下载并【已验签】的文件
  const args = ["--updated"];
  if (options.isSilent) args.push("/S");
  ...
  const callUsingElevation = () => {
    this.spawnLog(path.join(process.resourcesPath, "elevate.exe"), [installerPath].concat(args))
  };
  if (options.isAdminRightsRequired) {
    this._logger.info("isAdminRightsRequired is set to true, run installer using elevate.exe");
    callUsingElevation();
    return true;
  }
  this.spawnLog(installerPath, args).catch((e) => { ... EACCES → callUsingElevation() ... });
}
```

**评估**：
- 好消息：`installerPath` 是**本次刚下载并已验证签名**的文件，所以"把安装包换掉再提权"这条路被签名校验堵住了。
- 风险点：`elevate.exe` 自身位于 `process.resourcesPath`，即 `$INSTDIR\resources\`。**如果 `$INSTDIR` 是用户可写的（per-user 安装），攻击者就能替换 `elevate.exe`**，等应用下次尝试提权更新时执行任意代码。这个文件虽然会被签名，但替换成另一个文件后签名就失效了——而 `Node` 的 `spawn` 不会检查签名。
- **处置**：用 `perMachine: true` 让 `$INSTDIR` 不可写（根治），并可用 `nsis.packElevateHelper: false` 直接移除它（`[源码]` nsisOptions.d.ts:207-211，默认 true）。
  - ⚠️ 代价：per-machine + 需要提权的更新场景会失去提权能力。`packElevateHelper` 的官方注释就是"required for electron-updater if per-machine installer used"。**如果你用 per-machine 安装且需要自动更新，保留它**；如果不需要自动更新或更新由管理员推送，就关掉。
  - `[源码]` 另外注意：`packElevateHelper: false` 在 `perMachine: true` 时会被**忽略**并告警：
    ```js
    if (isPackElevateHelper === false && target.options.perMachine === true) {
      isPackElevateHelper = true;
      log.warn("`packElevateHelper = false` is ignored, because `perMachine` is set to `true`");
    }
    ```
    → **这两条配置是冲突的。** `perMachine: true` 会自动保留 `elevate.exe`。想彻底移除它只能选 per-user 安装，但那又引入了 1.2 的提权链。**这是一个真实的、无完美解的权衡**，我的建议是选 `perMachine: true` 并保留 `elevate.exe`（因为 per-machine 下它不可被普通用户写入，风险已被消除）。

### 1.4 自动更新链的签名校验，以及它的已知弱点

`[源码]` `electron-updater/out/NsisUpdater.js:52-57`：
```js
const signatureVerificationStatus = await this.verifySignature(destinationFile);
if (signatureVerificationStatus != null) {
  await removeTempDirIfAny();
  throw newError(`New version ${...} is not signed by the application owner: ...`,
                 "ERR_UPDATER_INVALID_SIGNATURE");
}
```
`[源码]` `windowsExecutableCodeSignatureVerifier.js` 用 PowerShell 的 `Get-AuthenticodeSignature` 读签名，然后把证书 `Subject` 与 `app-update.yml` 里的 `publisherName` 逐字段比对。

**必须知情的三个弱点：**

1. **`publisherName` 没配 = 不校验。** `[源码]` `NsisUpdater.js:84-100`：
   ```js
   async verifySignature(tempUpdateFile) {
     let publisherName;
     try {
       publisherName = (await this.configOnDisk.value).publisherName;
       if (publisherName == null) return null;      // ← null 表示"校验通过"
     } catch (e) {
       if (e.code === "ENOENT") return null;        // ← app-update.yml 不存在也视为通过
       throw e;
     }
     ...
   }
   ```
   → 所以 `win.signtoolOptions.publisherName` **必须**配置，否则这条防线形同虚设。

2. **只比证书主体，不比哈希。** 任何由你的证书签名的东西都会被接受。这实际上把"证书私钥"变成了整条更新链的**单点信任根**。私钥一旦泄露，攻击者可以给所有已安装用户推送任意代码。

3. **老系统上会静默跳过校验。** `[源码]` `windowsExecutableCodeSignatureVerifier.js:120-122`：
   ```js
   if (isOldWin6()) {
     logger.warn(`Cannot execute Get-AuthenticodeSignature: .... Ignoring signature validation due to unsupported powershell version.`);
     return;   // ← 直接返回，不 reject
   }
   ```
   `isOldWin6()` 的判定是 `os.release().startsWith("6.") && !startsWith("6.3")`，即 **Windows 7 (6.1)、Windows 8 (6.2)、Server 2008 R2 (6.1)** 这些系统上校验被跳过（Windows 8.1 是 6.3，Windows 10/11 是 10.0，不受影响）。这些系统均已停止支持，但如果有客户仍在用，更新链会缺少这一层校验。

**另一个值得注意的点**：electron-builder 的 `latest.yml` 里带 `isAdminRightsRequired` 字段，它决定了 electron-updater 是否走 `elevate.exe` 提权路径。`[源码]` `NsisTarget.js:311-313`：
```js
if (updateInfo != null && isPerMachine && (oneClick || options.packElevateHelper)) {
  updateInfo.isAdminRightsRequired = true;
}
```
→ 用的是 `latest.yml` 自己的内容。这个文件是**发布在你控制的服务器上的**（配合 `latest.yml` 的 Ed25519 签名机制，见 `[文档]` electron-builder v27 Signed Update Manifests），所以要保护好发布通道。

### 1.5 `nsis-web` 会把安装器副本写进用户可写目录

`[源码]` `templates/nsis/include/installer.nsh:93`：
```nsis
!insertmacro copyFile "$EXEPATH" "$LOCALAPPDATA\${APP_INSTALLER_STORE_FILE}"
```
即安装器会把自己复制到 `%LOCALAPPDATA%\<updaterCacheDirName>\`。这个路径**用户可写**。

**评估**：正常更新流程中 `NsisUpdater` 执行的是 `installerPath`（刚下载+验签的文件），而不是这个缓存副本（`[源码]` `NsisUpdater.js:102`），所以这条路径不是主执行路径。但：
- 这个缓存副本可作为差分更新的基线，被篡改会影响差分下载的正确性（差分失败会回退全量下载，不会导致代码执行）。
- `[源码]` 在你当前使用的 `electron-updater@6.8.9` 里，`disableWebInstaller` **默认是 `false`**（`AppUpdater.js:147`），也就是说 web installer 更新**默认是被允许的**；代码里还会为此打印告警：
  ```
  "disableWebInstaller is set to false, you should set it to true if you do not plan on using a web installer. This will default to true in a future version."
  ```
  `[文档]` 到 electron-builder v27 时该默认值将翻转为 `true`，并在 v28 变为 fail-closed（`ERR_UPDATER_WEB_INSTALLER_DISABLED`）。原因正是"web installer 的 payload 可能不经过签名校验"（`NsisUpdater.js:40-46`：web installer 会额外下载并校验 `packageFile` 的 sha512，但主安装包与 payload 是两条不同路径）。

**建议**：除非确有必要，**不要用 `nsis-web`**。用完整的 `nsis` 安装器；如果你确实在用，显式设置 `autoUpdater.disableWebInstaller = true`（前提是你不用 web installer 更新），或至少按官方告警设置成 `true` 以收紧默认行为。

---

## 2. 完整性链条：从构建到启动的完整校验路径

这是本报告的技术核心。理解这条链，才能知道每一环缺失会导致什么后果。

### 2.1 构建时的执行顺序（顺序至关重要）

`[源码]` `app-builder-lib/out/platformPackager.js:218-256`：

```
1. 拷贝应用文件、打包 app.asar
2. 计算所有 asar 的 header SHA256  → asarIntegrity
   （由 integrity.js 的 computeData() 完成）
3. addWinAsarIntegrity()：把哈希写进 exe 的 PE 资源 Integrity/ElectronAsar
   ★ 注意这一步是"改 exe 字节"，所以必须在签名之前
4. afterPack 钩子
5. doAddElectronFuses()：用 @electron/fuses 翻转 fuse 位
   ★ 源码注释原文："the fuses MUST be flipped right before signing"
6. doSignAfterPack()：Authenticode 签名
   → 从此 exe 的任何字节改动都会使签名失效
```

顺序的意义：**fuse 位和 Integrity 哈希都被"冻结"在签名之内**。攻击者想让应用加载恶意代码，就必须同时改 exe（破坏签名）或改 asar（破坏哈希）。这就是 fuses 文档说的"因为位是在签名前翻转的，OS 负责保证它们不被翻回去"。

### 2.2 ASAR 完整性校验的确切算法

`[实测 + 源码]` 这一节是我实际验证过的，很多博客写错了，请注意：

**Electron 侧**，`[源码]` `shell/common/asar/archive.cc:244-272`：
```cpp
std::string header;
if (!base::PickleIterator(base::Pickle::WithData(buf)).ReadString(&header)) { ... }

if (electron::fuses::IsEmbeddedAsarIntegrityValidationEnabled() && RelativePath().has_value()) {
  std::optional<IntegrityPayload> integrity = HeaderIntegrity();
  if (!integrity.has_value()) {
    LOG(FATAL) << "Failed to get integrity for validatable asar archive: " << ...;
  }
  if (integrity->algorithm != HashAlgorithm::kNone) {
    ValidateIntegrityOrDie(base::as_byte_span(header), *integrity, "<header>");
  } else {
    LOG(FATAL) << "No eligible hash for validatable asar archive: " << ...;
  }
}
```

`[源码]` `shell/common/asar/asar_util.cc:297-306`：
```cpp
void ValidateIntegrityOrDie(base::span<const uint8_t> input, const IntegrityPayload& integrity, std::string_view what) {
  if (integrity.algorithm == HashAlgorithm::kSHA256) {
    const std::string hex_hash = base::ToLowerASCII(base::HexEncode(crypto::hash::Sha256(input)));
    if (integrity.hash != hex_hash) {
      LOG(FATAL) << "Integrity check failed for asar archive entry '" << what << "' ...";
    }
  }
}
```

**⚠️ 三个关键细节（自己实现构建系统时最容易踩的坑）：**

1. **哈希输入是"pickle 解码后的 header 字符串字节"，不是文件里的对齐填充块。**
   `[实测]` 我构造的测试 asar 里：pickle 声明的字符串长度 508 字节，而文件中的对齐块是 512 字节（尾部 4 个 `0x00` 填充）。
   - 对 **508 字节**求哈希 = `2e90a55f9e8f1aca7416b4cbf0f2608ffb83fb333c2c855cebc4640486c319f5` ✅ Electron 期望这个
   - 对 **512 字节**求哈希 = `054719ad45b0db9e0f87bc036a7836f11de380bf577e201b056c8dff3a3f6fe9` ❌ 完全不同

   我在写验证脚本时**真的踩了这个坑**，第一次跑出来就是误报"哈希不一致"。所以这个提醒不是理论性的。

2. **资源查找失败是 FATAL。** `[源码]` `archive_win.cc:50-54`：`FindResource` 失败直接 `PLOG(FATAL)`。
   → **推论：一旦你打开了 `enableEmbeddedAsarIntegrityValidation` 但没有注入 Integrity 资源，应用会 100% 启动即崩溃。** 反过来，`disableAsarIntegrity` 之类的"优化"会造成同样的后果。
   - `[实测]` 我的验收脚本专门检查了这一项：在只翻转 fuses 而未注入资源的夹具上，正确报出 `FAIL: Integrity/ElectronAsar 资源未找到`。

3. **Windows 上资源名比较不区分大小写。** `[源码]` `archive_win.cc:25-26` 用 `L"Integrity"` / `L"ElectronAsar"`，而 `[源码]` electron-builder `electronWin.js:28-29` 写入的是 `'INTEGRITY'` / `'ELECTRONASAR'`。`FindResource` 是大小写不敏感的，所以能匹配上。
   另外文件路径键也会被小写化：`[源码]` `archive_win.cc:119` `cache.insert_or_assign(base::ToLowerASCII(*file), ...)`，`archive_win.cc:137` 查找时同样 `ToLowerASCII`。

**Windows 上资源的确切格式**（`[源码]` `archive_win.cc:73-121` 解析逻辑 + electron-builder 写入逻辑）：
```json
[ { "file": "resources\\app.asar", "alg": "sha256", "value": "<sha256 hex>" } ]
```
- `file` 必须是**相对于 DIR_ASSETS 的路径**（Windows 上即 exe 所在目录），用反斜杠。
- `alg` 只支持 `sha256`，其他值会被跳过并告警。
- 非法条目会被 `LOG(WARNING)` 跳过而不是崩溃——**但请注意**：如果所有条目都被跳过，`HeaderIntegrity()` 会返回 `nullopt`，然后 `archive.cc:255` 就 `LOG(FATAL)`。所以"写了资源但格式不对"同样会导致启动崩溃。

### 2.3 `OnlyLoadAppFromAsar` 为什么必须和完整性校验一起开

`[源码]` `shell/common/node_bindings.cc:839-858`：
```cpp
if (browser_env_ == BrowserEnvironment::kBrowser) {
  const std::vector<std::string> search_paths = {"app.asar", "app", "default_app.asar"};
  const std::vector<std::string> app_asar_search_paths = {"app.asar"};
  ctx->Global()->SetPrivate(ctx, v8::Private::ForApi(isolate, ...("appSearchPaths")...),
      gin::ConvertToV8(isolate,
          electron::fuses::IsOnlyLoadAppFromAsarEnabled() ? app_asar_search_paths : search_paths));
  ...
}
```

**如果只开完整性校验、不开 `onlyLoadAppFromAsar`**：攻击者不需要改 `app.asar`，只要在 `resources\` 下创建 `app\` 目录（含 `package.json` + 恶意代码），Electron 的搜索顺序 `app.asar → app → default_app.asar` 会在找不到... 实际上 `app.asar` 存在且校验通过，Electron 会用 `app.asar`。

**这里需要精确表述**：Electron 的 JS 侧选择逻辑是"第一个存在的路径"，`app.asar` 存在就会被选中，所以单纯放一个 `app\` 目录**不一定**能劫持。但风险在于：
- 如果 `app.asar` 因为任何原因不可用（损坏、被杀软隔离、被删除），加载会回退到 `app\`。攻击者可以主动制造这个条件。
- Electron 官方文档明确把这两个 fuse 视为**必须配对使用**："When combined with the `embeddedAsarIntegrityValidation` fuse, this fuse ensures that it is impossible to load non-validated code."（`[文档]` Electron Fuses）

**结论：不要分开评估这两个 fuse，它们是一对。全开。**

### 2.4 官方 Electron 出厂 fuse 状态（实测）

`[实测]` 在 `electron.exe` 中定位 sentinel `dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`，读到 fuse wire：

```
version=1  length=9  wire=101100011

#  fuse                                        wire  状态
0  RunAsNode                                   1     ENABLED    ← 危险
1  EnableCookieEncryption                      0     DISABLED
2  EnableNodeOptionsEnvironmentVariable        1     ENABLED    ← 危险
3  EnableNodeCliInspectArguments               1     ENABLED    ← 危险
4  EnableEmbeddedAsarIntegrityValidation       0     DISABLED   ← 危险（你要的防线是关的）
5  OnlyLoadAppFromAsar                         0     DISABLED   ← 危险
6  LoadBrowserProcessSpecificV8Snapshot        0     DISABLED
7  GrantFileProtocolExtraPrivileges            1     ENABLED    ← 危险
8  WasmTrapHandlers                            1     ENABLED
```

`[源码]` 与 `electron@v44.4.5` 的 `build/fuses/fuses.json5` 默认值完全一致。

**这是本报告最可操作的发现**：`electron-builder@26` 里 `electronFuses` 是**可选配置**，默认不设置就不翻转。所以**默认配置下构建出来的应用带着 5 个高危开关**。你必须显式配置。

`[实测]` 我用 `@electron/fuses` 对真实二进制做了翻转并读回，验证了端到端可行：
```
翻转前 wire: 101100011
翻转后 wire: 010011001
→ RunAsNode=0, CookieEncryption=1, NodeOptions=0, NodeCliInspect=0,
  AsarIntegrityValidation=1, OnlyLoadAppFromAsar=1,
  BrowserV8Snapshot=0, FileProtocolPrivileges=0, WasmTrapHandlers=1
```

### 2.5 `WasmTrapHandlers` 的一个实操陷阱

`[源码]` electron-builder 的 `FuseOptionsV1` 类型（`configuration.d.ts`）**不包含** `wasmTrapHandlers`，`generateFuseConfig()` 也不处理它。

这意味着：
- 用 `electronFuses` 配置时，`WasmTrapHandlers` 这一位**保持出厂值 `1`**，正确。
- 但如果你改用 `afterPack` 钩子 + `addElectronFuses()` 传完整的 `FuseConfig`，你必须**显式包含全部 9 个 fuse**，否则 `@electron/fuses` 会报 `the fuse wire in this version of Electron is not long enough`。一旦漏掉 `wasmTrapHandlers`，你会把它关掉——**降低 WASM 越界访问的防护**（V8 会退回显式边界检查，代码更大更慢且更容易被利用）。

**建议**：优先用 `electronFuses` 配置项，不要用 `afterPack`，除非你需要 `strictlyRequireAllFuses` 之类的进阶能力。

---

## 3. 加固配置清单

完整的、可直接使用的配置文件见同目录的 **`electron-builder.config.js`**，每一行都注明了依据。核心如下：

```js
module.exports = {
  appId: 'com.yourcompany.yourapp',
  asar: true,                          // 必须开，且绝不要 disableIntegrity

  // ★ 最核心：把 Electron 的危险能力焊死
  electronFuses: {
    runAsNode: false,
    enableCookieEncryption: true,
    enableNodeOptionsEnvironmentVariable: false,
    enableNodeCliInspectArguments: false,
    enableEmbeddedAsarIntegrityValidation: true,   // ★
    onlyLoadAppFromAsar: true,                     // ★ 必须与上一条配对
    loadBrowserProcessSpecificV8Snapshot: false,
    grantFileProtocolExtraPrivileges: false,
  },

  win: {
    target: [{ target: 'nsis', arch: ['x64'] }],
    requestedExecutionLevel: 'asInvoker',          // 绝不 highestAvailable
    forceCodeSigning: true,                        // ★ 没证书就构建失败，不静默产出未签名包
    signAndEditExecutable: true,                   // 保证 Integrity 资源被写入
    signtoolOptions: {
      rfc3161TimeStampServer: 'http://timestamp.digicert.com',  // ★ 时间戳
      publisherName: ['CN=Your Company Ltd., O=..., C=CN'],     // ★ 驱动更新验签
      signingHashAlgorithms: ['sha256'],
    },
  },

  nsis: {
    perMachine: true,                       // ★★ 装到 Program Files，切断提权链
    oneClick: true,
    allowToChangeInstallationDirectory: false,  // ★ 否则保护可被用户绕过
    allowElevation: true,
    runAfterFinish: false,
    deleteAppDataOnUninstall: false,
    // packElevateHelper: false  ← 注意：perMachine:true 时此设置会被忽略并告警
  },

  publish: [
    { provider: 'github', owner: 'your-org', repo: 'your-repo' },  // ★ 显式写死
  ],

  files: ['!**/*.map', '!**/{test,tests,__tests__}/**', '!**/*.{md,ts,tsx}'],
}
```

### 几个必须理解透的权衡

| 配置 | 收益 | 代价 |
|---|---|---|
| `runAsNode: false` | 阻断 `ELECTRON_RUN_AS_NODE` 攻击 | 主进程 `child_process.fork` 失效 → 改用 `utilityProcess` |
| `grantFileProtocolExtraPrivileges: false` | 取消 `file://` 越权访问 | 仍用 `file://` 加载页面可能白屏 → 迁移到自定义协议 |
| `perMachine: true` | 切断提权链 | 安装需要管理员；`packElevateHelper: false` 会被忽略 |
| `forceCodeSigning: true` | 杜绝"以为签了其实没签" | CI 必须正确配置证书，否则构建失败 |
| `publisherName` | 更新包验签生效 | 证书轮换时需同时列新旧，否则老用户无法更新 |
| `oneClick: true` | 减少社工面 | 用户不能选安装路径（这里正是我们想要的） |

### 关于 `requestedExecutionLevel`

electron-builder 会把它写进 exe 的**清单资源**（`[源码]` winPackager.js:162 传给 `editWindowsResources`）。`[源码]` 类型定义只允许三个值：`"asInvoker" | "highestAvailable" | "requireAdministrator"`，默认 `asInvoker`。

**永远不要用后两个**：
- `requireAdministrator` 会让你的应用每次启动都弹 UAC，用户会习惯性点"是"，等于训练用户忽略 UAC。
- 更严重的：应用以高完整性级别运行时，**它加载的每一个 DLL、它启动的每一个子进程都继承这个级别**。Electron 应用会加载几十个 Chromium DLL、启动渲染进程/GPU 进程/utility 进程——把这一整片攻击面都提到管理员级别。这是极其糟糕的安全设计。
- 如果确实需要管理员权限做特定操作，正确做法是**把那个操作拆成一个独立的、单独的、最小化的提权辅助程序**，只在该操作发生时调用。

---

## 4. 验证：加固不能靠信仰

同目录提供了 **`verify-win-hardening.mjs`**，一个零依赖（仅签名校验用 PowerShell）的构建后验收脚本。

### 它检查什么

| 检查区 | 内容 |
|---|---|
| **1. PE 缓解措施** | ASLR / HighEntropyVA / DEP / CFG，以及 Load Config 里的 `SecurityCookie`（`/GS`）、`GuardFlags`（确认 CFG **真的被插桩**而不只是置了个标志位）、`EH_CONTINUATION_TABLE_PRESENT`（`/guard:ehcont`）、CFG 合法目标表大小 |
| **2. Electron Fuses** | 9 个 fuse 逐个对照期望值，区分 FAIL（安全相关）与 WARN（性能相关） |
| **3. ASAR 完整性** | 资源存在性 **+ 哈希与磁盘上 app.asar 的一致性**（防止"资源陈旧"或"张冠李戴"） |
| **4. 危险残留** | `elevate.exe` 是否残留、侧加载 DLL 面、未签名 PE 文件清单 |
| **5. Authenticode** | 在 Windows 上调 `Get-AuthenticodeSignature`，检查签名有效性、**时间戳是否存在**、证书主体是否匹配 |

### 实测验证结果

`[实测]` 我在真实二进制上做了双向验证：

**A. 未加固（官方 Electron 原样）→ 正确报错**
```
PASS=10  WARN=6  FAIL=7  SKIP=1
未通过项：
  - [Fuses] RunAsNode: 期望 DISABLED，实际 ENABLED
  - [Fuses] EnableNodeOptionsEnvironmentVariable: 期望 DISABLED，实际 ENABLED
  - [Fuses] EnableNodeCliInspectArguments: 期望 DISABLED，实际 ENABLED
  - [Fuses] EnableEmbeddedAsarIntegrityValidation: 期望 ENABLED，实际 DISABLED
  - [Fuses] OnlyLoadAppFromAsar: 期望 ENABLED，实际 DISABLED
  - [ASAR] Integrity/ElectronAsar 资源: 未找到
  exit=1
```

**B. 加固后（fuses 翻转 + 注入真实 Integrity 资源）→ 全部通过**
```
PASS=21  WARN=3  FAIL=0  SKIP=1
  [PASS] CFG 插桩明细 — GuardFlags=0x4e22ddcd → CF_INSTRUMENTED, CF_FUNCTION_TABLE_PRESENT,
         CF_ENABLE_EXPORT_SUPPRESSION, RF_INSTRUMENTED, EH_CONTINUATION_TABLE_PRESENT
  [PASS] CFG 函数表 — 207090 个合法间接调用目标
  [PASS] /GS 栈保护 cookie — SecurityCookie=0x14e2b6040
  [PASS] EnableEmbeddedAsarIntegrityValidation — ENABLED
  [PASS] 哈希输入 (resources/app.asar) — pickle 字符串=508B，对齐块=512B，填充=0B
  [PASS] 哈希一致: resources/app.asar — 2e90a55f9e8f1aca7416b4cb…
  exit=0
```

### 在 CI 里作为发布门禁

```yaml
- name: Build Windows
  run: npx electron-builder --win --publish never

- name: Verify Windows hardening
  shell: pwsh
  run: node verify-win-hardening.mjs dist/win-unpacked --expect-publisher "Your Company Ltd."
  # 非 0 退出 → 阻断发布
```

**这个 gate 的价值**：它能抓住那些"看起来很安全但实际没生效"的情况。比如：
- 配了 `electronFuses` 但构建缓存复用了旧的 exe；
- 配了 fuses 但 `signAndEditExecutable: false` 导致 Integrity 资源没写进去（应用会启动即崩）；
- 证书过期导致签名无效但不报错；
- 忘了配 `publisherName` 导致更新验签被跳过。

---

## 5. 剩余风险与纵深防御

以下是我**无法通过 electron-builder 配置解决**的风险，需要诚实说明：

### 5.1 残留风险清单

| 风险 | 说明 | 建议 |
|---|---|---|
| **DLL 侧加载** | 应用根目录有 `ffmpeg.dll`、`d3dcompiler_47.dll`、`vk_swiftshader.dll`、`vulkan-1.dll`、`dxcompiler.dll` 等。这些是 Chromium 的正常组件，但如果安装目录可写，攻击者可以放同名 DLL 劫持加载 | 靠 `perMachine: true` 让目录不可写（根治）；不要用 `allowToChangeInstallationDirectory` |
| **管理员权限攻击者** | 签名和 ACL 都挡不住已经拿到管理员权限的攻击者 | WDAC / AppLocker 做应用白名单 |
| **证书私钥泄露** | 因为更新校验只比主体不比哈希，私钥泄露 = 可向所有用户推任意代码 | HSM / 云签名服务（Azure Trusted Signing）；证书轮换机制；`publisherName` 支持数组正是为轮换准备的 |
| **`app.asar.unpacked` 内容** | `[源码]` Electron 只校验 asar 的 **header**；header 里含每个文件的 `integrity` 字段，但 `app.asar.unpacked` 出来的文件在磁盘上是独立文件 | 尽量少 unpack（只 unpack `.node`）；不要把敏感逻辑放在 unpacked 里 |
| **首次运行的 TOCTOU** | 安装完成到第一次启动之间，如果目录可写，仍存在窗口 | `perMachine: true` |
| **SmartScreen 声誉** | 新证书没有声誉积累，用户会看到警告 | EV 证书（即时声誉）或 Azure Trusted Signing；时间戳保证签名长期有效 |
| **自定义 NSIS 脚本** | `[源码]` 用 `nsis.script` 会导致卸载器**不被签名** | 如果必须自定义脚本，自己补签卸载器 |
| **`nsis-web`** | 安装器副本写入 `%LOCALAPPDATA%`；v27 已默认禁用 web installer | 用完整 `nsis` 安装器 |
| **asar 之外的代码路径** | 如果 `onlyLoadAppFromAsar` 因任何原因未生效，`resources\app\` 目录是可加载的代码路径 | 两个 fuse 必须配对开启 |

### 5.2 纵深防御：超越 electron-builder 的层面

1. **应用层**（Electron 安全清单，与打包同等重要）
   - `contextIsolation: true`、`nodeIntegration: false`、`sandbox: true`
   - 严格 CSP；`webPreferences` 里禁用 `webviewTag`、`allowRunningInsecureContent`
   - 校验所有 `ipcMain` 消息的发送方（`event.senderFrame`）
   - 用自定义协议代替 `file://`（这样 `grantFileProtocolExtraPrivileges: false` 才能安全落地）
   - `app.enableSandbox()`
   - 参考 `[文档]` Electron Security Checklist

2. **OS 层强制**（企业部署）
   - **WDAC（Windows Defender Application Control）**：最有效，可基于签名者规则只允许你的证书签名的程序运行。这是唯一能"强制"签名被校验的机制。
   - **AppLocker**：可基于发布者规则做白名单。
   - **Smart App Control（Windows 11）**：消费级场景的自动版本，只允许受信签名程序。

3. **发布通道**
   - 服务端存储启用版本控制 + 不可变对象锁（防"发布后被替换"）
   - 使用 electron-builder v27 的 **Signed Update Manifests**（Ed25519 签名 `latest*.yml`，`[文档]` 明确说"在下载任何东西之前"就校验，且配置了密钥后**fail-closed**）
   - **显式写死 publish 的 `owner`/`repo`**——这是 v27 文档专门警告的问题：GitHub 的用户名/仓库名一旦改名、转移或删除，**任何人都能重新注册该名字**，然后给所有已安装用户推送一个"合法"的恶意更新
   - CI 密钥隔离：签名证书/私钥只在高权限 release job 中可用，PR 构建拿不到
   - 构建机加固：构建机能改 exe 也能签名，它本身就是高价值目标

4. **构建供应链**
   - `[文档]` electron-builder 下载的外部工具链（NSIS、winCodeSign、Wine、FPM 等）会做 checksum 校验；自定义 toolset 的远程 `url` **必须**提供 `checksum`
   - 锁定 `electron` 与 `electron-builder` 版本，使用 lockfile + `npm ci`
   - `electron` 版本至少 ≥ 30.0.5 / 31.0.0-beta.1

5. **必须知道的历史漏洞：CVE-2024-46992**
   `[文档]` OSV/GHSA-xw5q-g62x-2qjc：Electron `30.0.0-alpha.1` ~ `30.0.4`、`31.0.0-alpha.1` ~ `31.0.0-alpha.5` 存在 **ASAR 完整性绕过**（CWE-354）。只影响开启了 `embeddedAsarIntegrityValidation` **且** `onlyLoadAppFromAsar` 的应用，且仅限 Windows；攻击者需要对安装目录有写权限。已修复于 `30.0.5` 和 `31.0.0-beta.1`。
   **教训**：ASAR 完整性校验本身也曾经有 bug。**这就是为什么它必须和 `perMachine: true`（不可写目录）叠加使用**——单靠它不够。

---

## 6. 最小行动清单

按投入产出比排序：

| # | 动作 | 挡住的风险 | 成本 |
|---|---|---|---|
| 1 | 配 `electronFuses`（8 项，见配置文件） | 代码替换、调试端口、环境变量注入 | 5 分钟；需改 `child_process.fork` |
| 2 | 配 `nsis.perMachine: true` + `allowToChangeInstallationDirectory: false` | **本地提权链** | 安装需管理员 |
| 3 | 配 `win.forceCodeSigning: true` + Azure Trusted Signing / 代码签名证书 | 篡改检测、SmartScreen | 证书费用/订阅 |
| 4 | 配 `signtoolOptions.publisherName` + `rfc3161TimeStampServer` | 恶意更新、签名过期 | 5 分钟 |
| 5 | 显式写死 `publish.owner/repo` | 更新源被抢注 | 2 分钟 |
| 6 | 把 `verify-win-hardening.mjs` 接进 CI 作为发布门禁 | 所有"配了但没生效"的情况 | 10 分钟 |
| 7 | 升级 `electron` 到最新稳定版 | 已知 CVE | 回归测试 |
| 8 | 企业环境部署 WDAC/AppLocker | 管理员权限以下的全面防护 | 需 IT 配合 |
| 9 | 审计应用层 Electron 安全配置 | XSS→RCE 链 | 视代码规模 |

---

## 附录 A：调查过程中纠正的三个技术误解

这三点我在验证时都亲自踩到或差点踩到，值得单独列出：

1. **ASAR header 哈希的输入范围。** 我最初对文件里的 8 字节对齐块（512B）求哈希，得到 `054719ad...`；正确值是对 pickle 字符串（508B）求哈希得到 `2e90a55f...`。**尾部的 `0x00` 填充会完全改变哈希值。** 自己实现构建或校验时，必须先读 pickle 的字符串长度再取字节。

2. **PE 里 `VirtualSize = 0` 的 section 会破坏朴素的 RVA→文件偏移映射。** 我在写解析器时先用 `max(VirtualSize, RawSize)` 做范围匹配，结果一个 `RawSize` 高达 2.5GB 的 section 吞掉了整个地址空间并抢到了错误的映射，导致 `GuardFlags` 读成 `0x48000007` 而不是正确的 `0x4E22DDCD`，并误报"CFG 未插桩"。**正确做法：只用 `VirtualSize` 判定归属，多候选取虚拟范围最小者。** 修正后与独立实现逐字段一致。

3. **`SafeSEH` 在 x64 上是无意义的。** 它只对 32 位 x86 有效（基于栈的 SEH）。在 x64 上异常处理用表驱动的展开信息，`SEHandlerTable` 为空是**正常**的，不是缺陷。不要因为 BinSkim 报 `BA2018` 就以为 x64 有问题。

## 附录 B：手工审计工具

```powershell
# 1. Microsoft BinSkim（官方 PE 缓解措施审计器，CI 友好）
winget install Microsoft.BinSkim
binskim analyze YourApp.exe --verbose
# 关注规则：BA2001(LoadImage/ASLR) BA2008(CFG) BA2015(HighEntropyVA)
#           BA2018(SafeSEH, x86 only) BA2022(签名+时间戳)

# 2. winchecksec（Trail of Bits，轻量快速）
winchecksec.exe -j YourApp.exe

# 3. dumpbin（VS 自带），确认 CFG
dumpbin /headers YourApp.exe | findstr /i "Control Flow Guard"
dumpbin /loadconfig YourApp.exe

# 4. 读 fuses
npx @electron/fuses read --app "C:\Path\To\YourApp.exe"

# 5. 读 ASAR Integrity 资源
# 用 Resource Hacker 打开 exe → INTEGRITY → ELECTRONASAR

# 6. 验证签名与时间戳
Get-AuthenticodeSignature "C:\Path\To\YourApp.exe" | Format-List Status, SignerCertificate, TimeStamperCertificate

# 7. 运行时缓解措施（实际生效的，含系统策略）
# Process Explorer → 选中进程 → 右键 Properties → Mitigation 页
# 或 Get-ProcessMitigation -Name YourApp
```

`[重要]` BinSkim 报 `BA2008`（CFG）时要注意：它检查的是 PE 标志位。而**系统级的 CFG 强制需要 Windows 的"Exploit Protection"设置开启**。可以用 `Get-ProcessMitigation -Name YourApp.exe` 看 `CFG` 的实际强制状态。

---

## 附录 C：本次调查使用的验证方法（可复现）

```bash
# 1. 取官方 Electron Windows 二进制
curl -L -o electron-win.zip \
  https://github.com/electron/electron/releases/download/v44.4.5/electron-v44.4.5-win32-x64.zip
unzip -q electron-win.zip -d elwin

# 2. 读 PE 缓解措施（本报告附录 B 的工具，或本目录的 verify-win-hardening.mjs）
node verify-win-hardening.mjs elwin

# 3. 读 fuse wire（sentinel: dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX，后跟 version、length、wire）
node -e "
const b=require('fs').readFileSync('elwin/electron.exe');
const i=b.indexOf(Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX'));
console.log('version',b[i+48],'length',b[i+49],'wire',b.slice(i+50,i+50+b[i+49]).toString());
"
# → version 1 length 9 wire 101100011

# 4. 翻转 fuses 并读回验证
npm i @electron/fuses
node -e "
const {flipFuses,FuseVersion,FuseV1Options,getCurrentFuseWire}=require('@electron/fuses');
(async()=>{
  await flipFuses('./elwin/electron.exe',{version:FuseVersion.V1,
    [FuseV1Options.RunAsNode]:false,
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]:false,
    [FuseV1Options.EnableNodeCliInspectArguments]:false,
    [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]:true,
    [FuseV1Options.OnlyLoadAppFromAsar]:true,
    [FuseV1Options.GrantFileProtocolExtraPrivileges]:false});
  console.log(await getCurrentFuseWire('./elwin/electron.exe'));
})();
"
```

## 附录 D：参考资料

**本次产出物的权威校验**：`electron-builder.config.js` 已用 electron-builder 官方 JSON Schema（取自 `app-builder-lib` 的 `scheme.json`）做过 `ajv` 校验，**0 错误通过**。该 schema 同时确认了几个容易记错的默认值：

| 选项 | Schema 中的默认值 | 安全含义 |
|---|---|---|
| `nsis.perMachine` | **`false`** | 默认装到 `%LOCALAPPDATA%`，即 §1.2 提权链的默认状态 |
| `nsis.oneClick` | `true` | 默认即一键安装 |
| `nsis.allowToChangeInstallationDirectory` | `false` | 仅 assisted 安装器有效 |
| `nsis.packElevateHelper` | `true`（"Ignored if `perMachine` is set to `true`"） | 印证 §1.3 的冲突 |
| `win.signAndEditExecutable` | `true` | 保持开启才能写入 Integrity 资源 |
| `win.requestedExecutionLevel` | `asInvoker` | 默认值就是安全的 |
| `win.verifyUpdateCodeSignature` | `true` | 但**需要 `publisherName` 才真正生效** |
| `electronFuses` | **未设置（= 完全不翻转）** | 默认带着 5 个高危开关，见 §2.4 |

Schema 里 `electronFuses` 支持的键正好是 9 个中的 8 个 + `resetAdHocDarwinSignature`，**不含 `wasmTrapHandlers`**，与 §2.5 的分析一致。

**electron-builder**
- [Security & Hardening（v27 文档，包含各项默认值变更）](https://www.electron.build/docs/features/security/)
- [Adding Electron Fuses（v26）](https://www.electron.build/v26/docs/tutorials/adding-electron-fuses/)
- [Build Lifecycle（v26，含各阶段顺序与钩子）](https://www.electron.build/v26/docs/features/build-lifecycle/)
- [Application Contents](https://www.electron.build/concepts/application-contents)

**Electron 官方**
- [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [ASAR Integrity](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [Electron Security Checklist](https://www.electronjs.org/docs/latest/tutorial/security)
- [GHSA-xw5q-g62x-2qjc / CVE-2024-46992（ASAR 完整性绕过）](https://github.com/electron/electron/security/advisories/GHSA-xw5q-g62x-2qjc)

**源码（本次实际阅读的位置）**
- `app-builder-lib/out/winPackager.js` — 签名与资源编辑流程
- `app-builder-lib/out/electron/ElectronFramework.js` — exe 改名 + Integrity 资源注入
- `app-builder-lib/out/electron/electronWin.js` — `addWinAsarIntegrity()` 实现
- `app-builder-lib/out/asar/integrity.js` — header 哈希计算
- `app-builder-lib/out/platformPackager.js` — 构建阶段顺序
- `app-builder-lib/out/targets/nsis/NsisTarget.js` — 卸载器生成与签名
- `app-builder-lib/templates/nsis/*` — NSIS 脚本（安装路径、卸载项注册表）
- `electron/shell/common/asar/archive.cc` / `archive_win.cc` / `asar_util.cc` — 完整性校验
- `electron/shell/common/node_bindings.cc` — 应用代码搜索路径
- `electron-updater/out/NsisUpdater.js` — 更新安装与提权
- `electron-updater/out/windowsExecutableCodeSignatureVerifier.js` — 更新包验签

**本目录产出物**
- `electron-builder.config.js` — 可直接使用的加固配置模板（已通过官方 schema 校验）
- `verify-win-hardening.mjs` — 构建后验收脚本（CI 门禁，已在真实二进制上双向验证）

**本目录 `research/reference/` 中保存的一手资料**（供后续查证）
- `eb/abl/package/scheme.json` — electron-builder 完整 JSON Schema（本报告默认值结论的来源）
- `eb/*.ts` — electron-builder 的 TypeScript 源码片段
- `src/chromium_*.gn` / `src/MSVC.cpp` — Chromium/Electron 的编译参数定义（`/GS`、`/guard:cf`、`/CETCOMPAT` 等）
- `msdocs/`、`msdocs2/` — Microsoft Learn 的相关文档存档（`/GS`、CFG、SafeSEH、`/guard:ehcont`、PE 格式、Load Config 结构、Exploit Protection）
- `binskim/` — BinSkim 各条 BA 规则的源码（含 `BA2008.EnableControlFlowGuard.cs`、`BA2011.EnableStackProtection.cs`）
- `tools/winchecksec_README.md` — winchecksec 用法
- `pecheck.py` — 本报告使用的独立 PE 解析实现（用于交叉验证 `verify-win-hardening.mjs`）
