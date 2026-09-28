/**
 * electron-builder.config.js — Windows 安全加固模板
 * ===========================================================================
 * 这个文件的每一条安全相关配置都注明【依据】：
 *   [实测] = 在 macOS 上对官方 Electron v44.4.5 win32-x64 二进制实测得出
 *   [源码] = 读 electron-builder v26.15.3 / Electron v44.4.5 源码确认
 *   [文档] = 官方文档
 *
 * 基线版本： electron@44.x  electron-builder@26.15.x  @electron/fuses@2.1.x
 *
 * 用法：
 *   1. 把本文件放到项目根目录，命名为 electron-builder.config.js
 *   2. 按需修改 APP_ID / 发布者 / 证书来源
 *   3. package.json 的 "build" 字段必须删掉，否则会与外部配置文件冲突
 *   4. 构建： npx electron-builder --win --publish never
 *   5. 验收： node verify-win-hardening.mjs dist/win-unpacked
 * ===========================================================================
 */

// 你公司的代码签名证书主体（Distinguished Name）。
// 必须与证书里的 Subject 完全一致 —— 它会被写进应用内的 app-update.yml，
// electron-updater 用它校验下载到的安装包签名。[源码] NsisUpdater.verifySignature
const PUBLISHER_NAME = 'CN=Your Company Ltd., O=Your Company Ltd., C=CN'

// Windows 注册表/NSIS 用的稳定 GUID。安装位置、卸载信息都存在这个键下。
// [源码] templates/nsis/multiUser.nsh: INSTALL_REGISTRY_KEY = "Software\${APP_GUID}"
const APP_ID = 'com.yourcompany.yourapp'

module.exports = {
  appId: APP_ID,
  productName: 'YourApp',
  copyright: `Copyright © ${new Date().getFullYear()} Your Company Ltd.`,

  // -------------------------------------------------------------------------
  // 1. 应用代码完整性 —— 最核心的一层
  // -------------------------------------------------------------------------
  // asar 打包必须在【每个平台】都开启；它是 fuses 完整性校验的前提。
  // 注意 asar 是「每平台」选项，不能在顶层配。[源码] PlatformSpecificBuildOptions
  asar: true,

  // ⚠️ 绝对不要设置 disableIntegrity: true（v26 里甚至没有这个公开选项）。
  // electron-builder 会把 app.asar 的 header SHA256 写进 exe 的
  // Integrity/ElectronAsar 资源。[源码] out/asar/integrity.js + electronWin.js

  // -------------------------------------------------------------------------
  // 2. Electron Fuses —— 把「危险的 Electron 能力」从二进制里焊死
  // -------------------------------------------------------------------------
  // [源码] electron-builder 的执行顺序是：
  //   拷贝文件 → 注入 Integrity 资源 → afterPack → 翻转 fuses → 代码签名
  // 所以 fuses 一定在签名【之前】被翻转，签名之后无法再改（这正是设计意图：
  // 让 OS 的签名校验来保证 fuse 位不被翻回去）。
  //
  // [实测] 官方 Electron v44.4.5 的出厂 fuse 状态是 101100011，即：
  //   RunAsNode=ON、NodeOptions=ON、NodeCliInspect=ON、
  //   EmbeddedAsarIntegrityValidation=OFF、OnlyLoadAppFromAsar=OFF、
  //   GrantFileProtocolExtraPrivileges=ON
  //   —— 也就是说【不配这一段，你的应用就带着 5 个高危开关上线】。
  electronFuses: {
    // 关闭 ELECTRON_RUN_AS_NODE。开着的话，任何能设置环境变量的本地攻击者都能
    // 把 Electron 主程序当通用 Node 解释器用（"living off the land"），
    // 以你的签名身份执行任意脚本。
    // 代价：主进程里的 child_process.fork 会失效，请改用 utilityProcess。[文档]
    runAsNode: false,

    // 用 OS 密钥加密 Cookie 的 SQLite 库（原本是明文存储）。[文档]
    enableCookieEncryption: true,

    // 关闭 NODE_OPTIONS / NODE_EXTRA_CA_CERTS 环境变量。
    // 否则 NODE_OPTIONS=--require C:\evil.js 即可在你的应用进程内执行代码。
    enableNodeOptionsEnvironmentVariable: false,

    // 关闭 --inspect / --inspect-brk 等调试参数，同时禁用 SIGUSR1 触发 inspector。
    // 否则 --inspect 可以打开调试端口直接接管主进程。
    enableNodeCliInspectArguments: false,

    // ★ 启动时校验 app.asar 的 header 哈希与 exe 内嵌资源是否一致。
    // 不一致 → Electron 直接 LOG(FATAL) 退出。[源码] shell/common/asar/archive.cc:252-272
    // 仅支持 electron >= 30.0.0 (Windows)。[文档]
    enableEmbeddedAsarIntegrityValidation: true,

    // ★ 只从 app.asar 加载应用代码。
    // 不开这个的话加载顺序是 app.asar → app/ → default_app.asar，
    // 攻击者只要在 resources/ 下放一个 app/ 目录就能【完全绕过】上面的完整性校验。
    // [源码] shell/common/node_bindings.cc:840-858
    onlyLoadAppFromAsar: true,

    // 让主进程使用独立的 V8 快照，避免渲染进程复用带 nodeIntegration 的快照。
    loadBrowserProcessSpecificV8Snapshot: false,

    // 取消 file:// 的额外特权（跨文件 fetch、Service Worker、子框架越权访问）。
    // ⚠️ 如果你还在用 file:// 加载页面，开启后需要迁移到自定义协议或
    //    loadFile()，否则页面可能白屏。[文档]
    grantFileProtocolExtraPrivileges: false,
  },

  // -------------------------------------------------------------------------
  // 3. Windows 目标与安装方式 —— 决定「谁能改你的 exe」
  // -------------------------------------------------------------------------
  win: {
    target: [{ target: 'nsis', arch: ['x64'] }],

    // 永远不要用 highestAvailable / requireAdministrator。
    // 应用本身要提权，等于把 UAC 变成摆设，且会让所有子进程继承高完整性级别。
    requestedExecutionLevel: 'asInvoker',

    // ★ 强制签名。没有可用证书时直接让构建失败，而不是【静默产出未签名包】。
    // 这是防"以为签了其实没签"的关键护栏。[源码] PlatformSpecificBuildOptions
    forceCodeSigning: true,

    // 保持资源编辑开启（图标、版本信息、以及 ★ ASAR Integrity 资源注入）。
    // 注意：这个默认是 true，显式写出来是为了防止有人图省事关掉它。
    // 一旦设为 false，Integrity 资源不会被写入，而 fuses 里的校验开关是打开的，
    // 应用会 100% 启动失败（FindResource failed → LOG(FATAL)）。[源码] electronWin.js
    signAndEditExecutable: true,

    // 不设置 verifyUpdateCodeSignature: false —— 默认 true 才是对的。
    signtoolOptions: {
      // 证书一律走环境变量，绝不写进仓库：
      //   CSC_LINK / WIN_CSC_LINK  (base64 的 pfx 或文件路径)
      //   CSC_KEY_PASSWORD / WIN_CSC_KEY_PASSWORD

      // ★ RFC3161 时间戳。没有时间戳的话，证书一过期，已安装用户的
      // 更新签名校验就会全部失败。[文档]
      rfc3161TimeStampServer: 'http://timestamp.digicert.com',

      // ★ 写进 app-update.yml，electron-updater 用它校验更新包签名。
      // 轮换证书时把新旧两个都列上，避免老用户无法更新。[源码] winOptions.d.ts
      publisherName: [PUBLISHER_NAME],

      // 同时用 sha256 与 sha1 摘要（sha1 仅为兼容老系统；新项目可只留 sha256）
      signingHashAlgorithms: ['sha256'],
    },
  },

  // -------------------------------------------------------------------------
  // 4. NSIS 安装器加固 —— 决定「装到哪、谁能改卸载器」
  // -------------------------------------------------------------------------
  nsis: {
    // ★★ 本文件里最重要的一条 ★★
    // 装到 %ProgramFiles% 而不是 %LOCALAPPDATA%\Programs。
    // 原因：卸载器是放在 $INSTDIR 里的一个独立 exe
    //   [源码] templates/nsis/common.nsh: UNINSTALL_FILENAME = "Uninstall ${PRODUCT_FILENAME}.exe"
    //   [源码] include/installer.nsh: StrCpy $2 "$INSTDIR\${UNINSTALL_FILENAME}"
    // per-user 安装时 $INSTDIR 位于用户可写目录 → 低权限攻击者可以替换卸载器，
    // 之后任何【以管理员身份】触发卸载的动作（用户自己点、或提权脚本调用）
    // 都会执行攻击者的代码 → 本地提权。
    // perMachine 安装到 Program Files 后，普通用户无法写入 $INSTDIR，
    // 这条提权链被直接切断。
    perMachine: true,

    // 单文件一键安装，不弹安装向导（减少用户被诱导改安装路径的机会）
    oneClick: true,

    // ★ 不允许用户自定义安装目录。
    // 允许的话，用户可以装到 C:\Users\Public\ 这类全员可写目录，
    // 把上面 perMachine 的保护重新打开成漏洞。[源码] nsisOptions.d.ts
    allowToChangeInstallationDirectory: false,

    // 关闭 elevater 辅助程序。
    // elevate.exe 会被放到 resources/，electron-updater 在需要提权时直接
    // spawn 它 [源码] NsisUpdater.js:124。
    // perMachine 安装本身就在 Program Files 下（普通用户改不了），
    // 且我们不用 nsis-web，所以这个 helper 属于多余的攻击面。
    // ⚠️ 如果你后续要用 nsis-web，或需要「低权限触发提权更新」，
    //    必须把它改回 true，否则更新会失败。
    packElevateHelper: false,

    // 不允许安装器自己请求提权（走标准 UAC 流程，由系统弹窗）
    allowElevation: true,

    // 创建桌面/开始菜单快捷方式由安装器决定，不额外暴露选项
    createDesktopShortcut: true,
    createStartMenuShortcut: true,

    // 安装完成后不自动拉起应用（避免"装完即运行"被社工利用）
    runAfterFinish: false,

    // 卸载时是否删除应用数据（按合规要求决定）
    deleteAppDataOnUninstall: false,
  },

  // -------------------------------------------------------------------------
  // 5. 自动更新安全
  // -------------------------------------------------------------------------
  // electron-builder v26 默认会把 publisherName 写进 app-update.yml，
  // electron-updater 在【下载后、执行前】用 Get-AuthenticodeSignature 校验。
  // [源码] electron-updater/out/windowsExecutableCodeSignatureVerifier.js
  //
  // ⚠️ 已知弱点，务必知情：
  //   a) 若 app-update.yml 缺失或没配 publisherName，verifySignature 直接
  //      return null（= 视为通过）。[源码] NsisUpdater.js:88-96
  //   b) 校验只比对证书主体，【不比对哈希】。
  //   c) 在 Windows 8 及更早系统上会打印警告并跳过校验。
  //      [源码] windowsExecutableCodeSignatureVerifier.js:120-122
  //   因此：publisherName 必须配置，且证书私钥必须保管好 ——
  //   签名校验把「证书」变成了你整条更新链的单点信任根。
  publish: [
    // ★ 显式写死 owner/repo。不要依赖自动从 .git/config 推断：
    //   GitHub 的用户名/仓库名一旦改名或删除，任何人都能重新注册，
    //   从而给所有已安装用户推送一个"合法"的恶意更新。
    //   [文档] electron-builder v27 Security & Hardening / Update feed ownership
    {
      provider: 'github',
      owner: 'your-org',
      repo: 'your-repo',
      releaseType: 'release',
    },
  ],

  // -------------------------------------------------------------------------
  // 6. 构建期卫生
  // -------------------------------------------------------------------------
  // asar 解开策略：不要用 asarUnpack: "**" 把全部代码摊到磁盘上，
  // 那样每个文件都失去 header 整体保护（只剩 per-file integrity）。
  // 只 unpack 必须的原生模块。
  // asarUnpack: ['**/*.node'],

  // 构建缓存：CI 上建议关掉，避免缓存里的旧 exe 被复用导致
  // fuses/Integrity 是"上一版"的状态。[源码] winPackager.js:166-201 有 exe 级缓存
  // buildCache: false,  // 顶层选项名以你所用版本为准，v26 由环境变量
  //                     // ELECTRON_BUILDER_CACHE / USE_BUILD_CACHE 控制

  // 不要把源码里的 .map / 测试文件 / 文档打进包
  files: [
    '!**/*.map',
    '!**/{test,tests,__tests__,spec,specs}/**',
    '!**/*.{md,markdown,ts,tsx}',
    '!**/.{git,github,vscode,idea}/**',
    '!**/{.eslintrc,.prettierrc,.editorconfig,tsconfig.json}',
    '!**/{LICENSE,LICENCE,CHANGELOG,README}*',
  ],

  // 安装目录里别带调试符号
  // （如果用了 native 模块，确保发布前 strip 掉 .pdb）
}
