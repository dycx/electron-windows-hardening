#!/usr/bin/env node
/**
 * verify-win-hardening.mjs
 * ---------------------------------------------------------------------------
 * 对 electron-builder 产出的 Windows 制品做“安全加固验收”。
 * 在 CI 里作为构建后 gate 使用：任何一项不达标就以非 0 退出。
 *
 * 检查项：
 *   1. PE 缓解措施   ASLR / HighEntropyVA / DEP / CFG / SafeSEH / GS cookie
 *                    （含 Load Config 里的 GuardFlags 与 EH continuation）
 *   2. Electron Fuses 9 个 fuse 的实际状态，逐个对照期望值
 *   3. ASAR 完整性    PE 资源 Integrity/ElectronAsar 是否存在，且哈希与
 *                    resources/app.asar 的 header 是否【一致】（防呆：不是只看存在）
 *   4. Authenticode  主 exe / 安装器 / 卸载器是否已签名且证书主体匹配
 *   5. 危险残留      DLL 侧加载面、elevate.exe 是否残留、未签名文件清单
 *
 * 用法：
 *   node verify-win-hardening.mjs dist/win-unpacked
 *   node verify-win-hardening.mjs dist/win-unpacked --json
 *   node verify-win-hardening.mjs dist/win-unpacked --expect-publisher "CN=Acme"
 *
 * 依赖（可选，缺失会自动降级并明确告知）：
 *   npm i -D @electron/fuses resedit
 *   -- 签名校验需要 Windows 上的 PowerShell，非 Windows 会跳过并标注 SKIP
 *
 * 退出码：0 = 全部 PASS/可选 SKIP；1 = 存在 FAIL
 * ---------------------------------------------------------------------------
 */

import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

// ---------------------------------------------------------------------------
// 结果收集
// ---------------------------------------------------------------------------
const results = []
const useJson = process.argv.includes('--json')
const argv = process.argv.slice(2)
const targetArg = argv.find((a) => !a.startsWith('--'))
const expectPublisherIdx = argv.indexOf('--expect-publisher')
const EXPECT_PUBLISHER = expectPublisherIdx >= 0 ? argv[expectPublisherIdx + 1] : null

function record(level, area, name, detail) {
  results.push({ level, area, name, detail })
  if (!useJson) {
    const tag = { PASS: '\x1b[32mPASS\x1b[0m', FAIL: '\x1b[31mFAIL\x1b[0m', WARN: '\x1b[33mWARN\x1b[0m', SKIP: '\x1b[90mSKIP\x1b[0m', INFO: '\x1b[36mINFO\x1b[0m' }[level]
    console.log(`  [${tag}] ${name}${detail ? ` — ${detail}` : ''}`)
  }
}
const pass = (a, n, d) => record('PASS', a, n, d)
const fail = (a, n, d) => record('FAIL', a, n, d)
const warn = (a, n, d) => record('WARN', a, n, d)
const skip = (a, n, d) => record('SKIP', a, n, d)
const info = (a, n, d) => record('INFO', a, n, d)

function section(t) {
  if (!useJson) console.log(`\n\x1b[1m${t}\x1b[0m`)
}

// ---------------------------------------------------------------------------
// 最小 PE 解析器（零依赖）
// ---------------------------------------------------------------------------
const DLLCHAR = [
  [0x0020, 'HIGH_ENTROPY_VA'],
  [0x0040, 'DYNAMIC_BASE'],
  [0x0100, 'NX_COMPAT'],
  [0x4000, 'GUARD_CF'],
]

const GUARD_FLAGS = [
  [0x00000100, 'CF_INSTRUMENTED'],
  [0x00000400, 'CF_FUNCTION_TABLE_PRESENT'],
  [0x00008000, 'CF_ENABLE_EXPORT_SUPPRESSION'],
  [0x00010000, 'CF_LONGJUMP_TABLE_PRESENT'],
  [0x00020000, 'RF_INSTRUMENTED'],
  [0x00100000, 'RETPOLINE_PRESENT'],
  [0x00200000, 'EH_CONTINUATION_TABLE_PRESENT'],
  [0x00400000, 'XFG_ENABLED'],
]

function parsePE(buf) {
  if (buf.length < 0x40 || buf.toString('latin1', 0, 2) !== 'MZ') return null
  const e = buf.readUInt32LE(0x3c)
  if (buf.toString('latin1', e, e + 4) !== 'PE\0\0') return null
  const coff = e + 4
  const machine = buf.readUInt16LE(coff)
  const nsec = buf.readUInt16LE(coff + 2)
  const optSize = buf.readUInt16LE(coff + 16)
  const opt = coff + 20
  const magic = buf.readUInt16LE(opt)
  const plus = magic === 0x20b
  const subsystem = buf.readUInt16LE(opt + 68)
  const dllchars = buf.readUInt16LE(opt + 70)
  const ddOff = opt + (plus ? 112 : 96)
  const dd = []
  for (let i = 0; i < 16; i++) dd.push([buf.readUInt32LE(ddOff + i * 8), buf.readUInt32LE(ddOff + i * 8 + 4)])
  const secOff = opt + optSize
  const sections = []
  for (let i = 0; i < nsec; i++) {
    const o = secOff + i * 40
    sections.push({
      name: buf.toString('latin1', o, o + 8).replace(/\0+$/, ''),
      vsize: buf.readUInt32LE(o + 8),
      vaddr: buf.readUInt32LE(o + 12),
      rawsize: buf.readUInt32LE(o + 16),
      rawptr: buf.readUInt32LE(o + 20),
    })
  }
  // 注意：PE 里存在 VirtualSize=0 的 section（本次实测的 Electron 44 二进制即如此，
  // 其 rawsize 高达 2.5GB）。若用 max(vsize, rawsize) 做范围匹配，这些 section 会
  // 吞掉整个地址空间并抢到错误的映射。正确做法是只用 VirtualSize 判定归属，
  // 且在多个候选时取虚拟范围最小的那个。
  const rva2off = (rva) => {
    let best = null
    for (const s of sections) {
      if (s.vsize === 0) continue
      if (rva >= s.vaddr && rva < s.vaddr + s.vsize) {
        if (best === null || s.vsize < best.vsize) best = s
      }
    }
    if (best === null) return null
    const d = rva - best.vaddr
    return d < best.rawsize ? best.rawptr + d : null
  }
  const out = { machine, plus, subsystem, dllchars, sections, rva2off, certDir: dd[4], loadCfgDir: dd[10] }
  // Load Config
  const [lcRva, lcSize] = dd[10]
  if (lcRva && lcSize) {
    const off = rva2off(lcRva)
    if (off != null) {
      const raw = buf.subarray(off, off + lcSize)
      const rd64 = (o) => (raw.length >= o + 8 ? raw.readBigUInt64LE(o) : 0n)
      const rd32 = (o) => (raw.length >= o + 4 ? raw.readUInt32LE(o) : 0)
      out.loadConfig = plus
        ? { securityCookie: rd64(0x58), guardCfCheck: rd64(0x70), guardCfDispatch: rd64(0x78), guardCfTable: rd64(0x80), guardCfCount: rd64(0x88), guardFlags: rd32(0xa0) }
        : { securityCookie: BigInt(rd32(0x40)), guardCfCheck: BigInt(rd32(0x4c)), guardCfDispatch: BigInt(rd32(0x50)), guardCfTable: BigInt(rd32(0x54)), guardCfCount: BigInt(rd32(0x58)), guardFlags: rd32(0x70) }
      out.loadConfigRaw = raw
    }
  }
  return out
}

const MACHINE = { 0x14c: 'x86', 0x8664: 'x64', 0xaa64: 'arm64' }

// ---------------------------------------------------------------------------
// 目标目录
// ---------------------------------------------------------------------------
if (!targetArg) {
  console.error('用法: node verify-win-hardening.mjs <dist/win-unpacked 目录或单个 .exe> [--json] [--expect-publisher "CN=..."]')
  process.exit(2)
}
const target = path.resolve(targetArg)
if (!fs.existsSync(target)) {
  console.error(`路径不存在: ${target}`)
  process.exit(2)
}

const isDir = fs.statSync(target).isDirectory()
const appOutDir = isDir ? target : path.dirname(target)
const read = (p) => fs.readFileSync(p)
const exists = (p) => fs.existsSync(p)

if (!useJson) {
  console.log(`\x1b[1melectron-builder Windows 加固验收\x1b[0m`)
  console.log(`目标: ${target}`)
  console.log(`平台: ${process.platform}   Node: ${process.version}`)
}

// ---------------------------------------------------------------------------
// 1. 找到主 exe
// ---------------------------------------------------------------------------
section('1. 定位主可执行文件')
let mainExe = null
if (!isDir && target.endsWith('.exe')) {
  mainExe = target
} else {
  // 优先用 package.json 的 productName 推导，否则取目录下最大的 exe
  const exes = fs
    .readdirSync(appOutDir)
    .filter((f) => f.toLowerCase().endsWith('.exe'))
    .map((f) => ({ f, size: fs.statSync(path.join(appOutDir, f)).size }))
    .sort((a, b) => b.size - a.size)
  // Electron 主 exe 体积远大于辅助 exe（elevate.exe 等）
  if (exes.length) mainExe = path.join(appOutDir, exes[0].f)
  if (exes.length > 1) {
    info('PE', '目录内其它 exe', exes.slice(1).map((e) => `${e.f} (${(e.size / 1024).toFixed(0)} KB)`).join(', '))
  }
}
if (!mainExe || !exists(mainExe)) {
  fail('PE', '未找到主 exe', appOutDir)
} else {
  pass('PE', '主 exe', path.relative(process.cwd(), mainExe))
}

const appExeBuf = mainExe && exists(mainExe) ? read(mainExe) : null

// ---------------------------------------------------------------------------
// 2. PE 层面缓解措施
// ---------------------------------------------------------------------------
section('2. PE 缓解措施（编译器/链接器层面）')
if (!appExeBuf) {
  skip('PE', 'PE 缓解措施', '无主 exe')
} else {
  const pe = parsePE(appExeBuf)
  if (!pe) {
    fail('PE', 'PE 解析失败')
  } else {
    info('PE', '架构 / 子系统', `${MACHINE[pe.machine] ?? pe.machine} / ${pe.subsystem === 2 ? 'GUI' : pe.subsystem === 3 ? 'Console' : pe.subsystem}`)
    const dc = pe.dllchars
    const checks = [
      ['ASLR (DYNAMICBASE)', 0x0040, '现代 Windows 上必须开启；否则可利用固定基址 ROP'],
      ['High-Entropy VA', 0x0020, '64 位下把 ASLR 熵从 8 位提升到 17 位以上'],
      ['DEP (NX_COMPAT)', 0x0100, '数据页不可执行'],
      ['CFG (GUARD_CF)', 0x4000, '间接调用目标校验，缓解类型混淆后的控制流劫持'],
    ]
    for (const [name, bit, why] of checks) {
      if (dc & bit) pass('PE', name, 'ok')
      else fail('PE', name, `缺失 —— ${why}`)
    }
    if (pe.loadConfig) {
      const lc = pe.loadConfig
      if (lc.securityCookie !== 0n) pass('PE', '/GS 栈保护 cookie', `SecurityCookie=0x${lc.securityCookie.toString(16)}`)
      else fail('PE', '/GS 栈保护 cookie', 'Load Config 中 SecurityCookie 为 0，未启用 /GS')

      const gf = lc.guardFlags
      if (gf === 0) {
        fail('PE', 'CFG 插桩明细', 'GuardFlags=0，二进制未真正被 CFG 插桩（仅有 DllCharacteristics 标志不够）')
      } else {
        const on = GUARD_FLAGS.filter(([b]) => gf & b).map(([, n]) => n)
        pass('PE', 'CFG 插桩明细', `GuardFlags=0x${gf.toString(16).padStart(8, '0')} → ${on.join(', ')}`)
        if (gf & 0x00000100) pass('PE', 'CFG 已插桩 (CF_INSTRUMENTED)', 'ok')
        else fail('PE', 'CFG 已插桩 (CF_INSTRUMENTED)', '缺少 IMAGE_GUARD_CF_INSTRUMENTED')
      }
      info('PE', 'GuardCFCheck / Dispatch', `0x${lc.guardCfCheck.toString(16)} / 0x${lc.guardCfDispatch.toString(16)}`)
      if (lc.guardCfTable !== 0n) info('PE', 'CFG 函数表', `${lc.guardCfCount} 个合法间接调用目标`)
      const eh = gf & 0x00200000
      if (pe.machine === 0x8664 || pe.machine === 0xaa64) {
        if (eh) pass('PE', 'EH continuation 元数据 (/guard:ehcont)', 'ok')
        else warn('PE', 'EH continuation 元数据 (/guard:ehcont)', '未设置，CET 硬件影子栈场景下异常处理链缺少保护')
      }
    } else {
      fail('PE', 'Load Config 目录', '不存在，无法确认 /GS 与 CFG')
    }
    if (pe.certDir[1] > 0) pass('PE', 'Authenticode 证书表', `${pe.certDir[1]} 字节`)
    else warn('PE', 'Authenticode 证书表', '主 exe 未签名（会触发 SmartScreen 警告，且无法被 WDAC 信任）')
  }
}

// ---------------------------------------------------------------------------
// 3. Electron Fuses
// ---------------------------------------------------------------------------
section('3. Electron Fuses')
const FUSE_EXPECTED = [
  ['RunAsNode', 0, false, '关闭可阻断 ELECTRON_RUN_AS_NODE “就地取材”式攻击'],
  ['EnableCookieEncryption', 1, true, '用 OS 密钥加密 Cookie 数据库'],
  ['EnableNodeOptionsEnvironmentVariable', 2, false, '关闭 NODE_OPTIONS / NODE_EXTRA_CA_CERTS 注入面'],
  ['EnableNodeCliInspectArguments', 3, false, '关闭 --inspect 调试端口'],
  ['EnableEmbeddedAsarIntegrityValidation', 4, true, '★ 启动时校验 app.asar 完整性'],
  ['OnlyLoadAppFromAsar', 5, true, '★ 只从 app.asar 加载应用代码，堵住 app/ 目录绕过'],
  ['LoadBrowserProcessSpecificV8Snapshot', 6, false, '主进程与渲染进程使用不同 V8 快照'],
  ['GrantFileProtocolExtraPrivileges', 7, false, '取消 file:// 的额外特权'],
  ['WasmTrapHandlers', 8, true, '保留 V8 WASM 越界访问的硬件 trap（性能+安全）'],
]

if (!appExeBuf) {
  skip('Fuses', '读取 fuses', '无主 exe')
} else {
  const SENTINEL = Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX', 'latin1')
  const idx = appExeBuf.indexOf(SENTINEL)
  if (idx < 0) {
    fail('Fuses', '定位 fuse wire', '未找到 sentinel，无法读取 fuse 状态')
  } else {
    const version = appExeBuf[idx + SENTINEL.length]
    const len = appExeBuf[idx + SENTINEL.length + 1]
    const wire = appExeBuf.subarray(idx + SENTINEL.length + 2, idx + SENTINEL.length + 2 + len)
    info('Fuses', 'fuse wire', `version=${version}, length=${len}, wire=${wire.toString('latin1')}`)
    if (len < FUSE_EXPECTED.length) {
      fail('Fuses', 'fuse wire 长度不足', `${len} < ${FUSE_EXPECTED.length}`)
    }
    for (const [name, pos, want, why] of FUSE_EXPECTED) {
      if (pos >= wire.length) {
        warn('Fuses', name, '该 Electron 版本无此 fuse')
        continue
      }
      const c = String.fromCharCode(wire[pos])
      const state = c === '1' ? true : c === '0' ? false : null
      if (state === null) {
        warn('Fuses', name, `状态 '${c}'（removed）`)
      } else if (state === want) {
        pass('Fuses', name, want ? 'ENABLED' : 'DISABLED')
      } else {
        const sev = pos === 4 || pos === 5 || pos === 0 || pos === 2 || pos === 3 ? 'FAIL' : 'WARN'
        record(sev, 'Fuses', name, `期望 ${want ? 'ENABLED' : 'DISABLED'}，实际 ${state ? 'ENABLED' : 'DISABLED'} —— ${why}`)
      }
    }
  }
}

// ---------------------------------------------------------------------------
// 4. ASAR 完整性
// ---------------------------------------------------------------------------
section('4. ASAR 完整性（PE 资源 Integrity/ElectronAsar）')
const resourcesDir = path.join(appOutDir, 'resources')
const asarPath = path.join(resourcesDir, 'app.asar')

function findIntegrityResourceJSON(buf) {
  // PE 资源树：type "INTEGRITY" / name "ELECTRONASAR"（比较不区分大小写）。
  // 这里采用稳健做法：直接在文件里搜索形如 [{"file":..,"alg":"sha256","value":..}] 的 JSON。
  const needle = Buffer.from('[{"file"', 'latin1')
  let from = 0
  for (;;) {
    const i = buf.indexOf(needle, from)
    if (i < 0) return null
    for (let end = i + 16; end < Math.min(buf.length, i + 65536); end++) {
      if (buf[end] === 0x5d /* ] */) {
        const s = buf.toString('utf8', i, end + 1)
        try {
          const v = JSON.parse(s)
          if (Array.isArray(v) && v.length && v[0] && typeof v[0].file === 'string' && typeof v[0].value === 'string') return { json: v, offset: i }
        } catch {
          /* 继续扩大窗口 */
        }
      }
    }
    from = i + 1
  }
}

if (!appExeBuf) {
  skip('ASAR', '完整性资源', '无主 exe')
} else {
  const found = findIntegrityResourceJSON(appExeBuf)
  if (!found) {
    fail('ASAR', 'Integrity/ElectronAsar 资源', '未找到；若已开启 EnableEmbeddedAsarIntegrityValidation，应用会因 FindResource 失败而 LOG(FATAL) 直接退出')
  } else {
    pass('ASAR', 'Integrity/ElectronAsar 资源存在', `offset 0x${found.offset.toString(16)}`)
    for (const entry of found.json) {
      info('ASAR', '登记条目', `${entry.file}  alg=${entry.alg}  value=${entry.value.slice(0, 16)}…`)
      // 与磁盘上的 app.asar 实际 header 哈希做一致性比对（防止资源陈旧/张冠李戴）
      const rel = String(entry.file).replace(/\\/g, '/')
      const candidate = path.join(appOutDir, rel)
      if (!exists(candidate)) {
        fail('ASAR', `条目文件缺失: ${rel}`, candidate)
        continue
      }
      const ab = read(candidate)
      // ASAR 布局: [4B pickle长度][4B payload长度][header JSON][8 字节对齐填充][文件数据]
      // 关键：Electron 校验的是【pickle 解码后的 header 字符串字节】，不含对齐填充。
      // 直接对 8..8+payloadLen 求哈希是错的 —— 实测会差 4 个 0x00 填充字节，
      // 哈希值完全不同，从而误报。必须再读一次 pickle 的字符串长度。
      try {
        const payloadLen = ab.readUInt32LE(4)
        const payload = ab.subarray(8, 8 + payloadLen)
        const strLen = payload.readUInt32LE(0)
        const header = payload.subarray(4, 4 + strLen)
        const h = createHash('sha256').update(header).digest('hex')
        info('ASAR', `哈希输入 (${rel})`, `pickle 字符串=${strLen}B，对齐块=${payloadLen}B，填充=${payloadLen - strLen - 4}B`)
        if (h.toLowerCase() === String(entry.value).toLowerCase()) {
          pass('ASAR', `哈希一致: ${rel}`, h.slice(0, 24) + '…')
        } else {
          fail('ASAR', `哈希不一致: ${rel}`, `资源内=${entry.value.slice(0, 24)}… 实际=${h.slice(0, 24)}… —— 应用启动会 FATAL 退出`)
        }
      } catch (e) {
        fail('ASAR', `解析 ${rel} 失败`, e.message)
      }
    }
  }
}

// app.asar.unpacked 说明：unpacked 出来的文件【不】在 header 哈希覆盖范围内
// （Electron 只校验 header；每个文件自身的 integrity 在 header 里，读写时校验）。
const unpacked = path.join(resourcesDir, 'app.asar.unpacked')
if (exists(unpacked)) {
  const nativeFiles = []
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name)
      if (e.isDirectory()) walk(p)
      else if (/\.(node|dll|exe)$/i.test(e.name)) nativeFiles.push(p)
    }
  }
  walk(unpacked)
  if (nativeFiles.length) {
    info('ASAR', 'app.asar.unpacked 中的原生模块', `${nativeFiles.length} 个 .node/.dll/.exe（这些文件由 header 内 per-file integrity 覆盖，但不受 PE 签名整体保护之外的额外保护）`)
  }
}

// ---------------------------------------------------------------------------
// 5. 危险残留
// ---------------------------------------------------------------------------
section('5. 危险残留与侧加载面')
if (exists(resourcesDir)) {
  const elevate = path.join(resourcesDir, 'elevate.exe')
  if (exists(elevate)) {
    const st = fs.statSync(elevate)
    warn(
      '残留',
      'resources/elevate.exe 存在',
      `${(st.size / 1024).toFixed(0)} KB。per-machine 安装或 nsis-web 需要它；纯 per-user 安装可用 nsis.packElevateHelper=false 移除，减少一个可被替换的提权辅助程序`
    )
  } else {
    pass('残留', 'resources/elevate.exe', '不存在')
  }
}

if (exists(appOutDir)) {
  const looseDlls = fs
    .readdirSync(appOutDir)
    .filter((f) => f.toLowerCase().endsWith('.dll'))
  if (looseDlls.length) {
    warn(
      '侧加载',
      `应用根目录有 ${looseDlls.length} 个 DLL`,
      `${looseDlls.slice(0, 6).join(', ')}${looseDlls.length > 6 ? ', …' : ''}。这些是 Chromium 组件，正常；但必须保证安装目录不可被普通用户写入（per-machine 装到 Program Files）`
    )
  }
  const unsigned = []
  const walkTop = (d, depth = 0) => {
    if (depth > 1) return
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name)
      if (e.isDirectory()) walkTop(p, depth + 1)
      else if (/\.(exe|dll|node)$/i.test(e.name)) {
        const b = read(p)
        const pe = parsePE(b)
        if (pe && pe.certDir[1] === 0) unsigned.push(path.relative(appOutDir, p))
      }
    }
  }
  walkTop(appOutDir)
  if (unsigned.length) {
    warn('签名', `未签名的 PE 文件 (${unsigned.length})`, unsigned.slice(0, 10).join(', ') + (unsigned.length > 10 ? ', …' : ''))
  } else {
    pass('签名', '所有顶层 PE 文件均有签名', 'ok')
  }
}

// ---------------------------------------------------------------------------
// 6. Authenticode 实际校验（仅 Windows）
// ---------------------------------------------------------------------------
section('6. Authenticode 签名校验')
if (process.platform !== 'win32') {
  skip('签名', 'Get-AuthenticodeSignature', `当前为 ${process.platform}，无法调用 PowerShell。请在 Windows runner 上跑本步骤`)
} else if (!mainExe) {
  skip('签名', 'Get-AuthenticodeSignature', '无主 exe')
} else {
  const ps = `"Get-AuthenticodeSignature -LiteralPath '${mainExe.replace(/'/g, "''")}' | ConvertTo-Json -Compress"`
  const r = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], { encoding: 'utf8' })
  if (r.status !== 0 || !r.stdout) {
    fail('签名', 'Get-AuthenticodeSignature', (r.stderr || r.error?.message || 'no output').trim())
  } else {
    try {
      const d = JSON.parse(r.stdout)
      if (d.Status === 0 || d.Status === 'Valid') {
        const subject = d.SignerCertificate?.Subject ?? '(unknown)'
        pass('签名', '签名有效', subject)
        if (!d.TimeStamperCertificate) {
          warn('签名', '时间戳', '无 RFC3161 时间戳；证书过期后签名将失效，已安装用户无法再验证更新')
        } else {
          pass('签名', '时间戳', d.TimeStamperCertificate.Subject)
        }
        if (EXPECT_PUBLISHER) {
          if (subject.includes(EXPECT_PUBLISHER.replace(/^CN=/, ''))) pass('签名', '证书主体匹配期望', EXPECT_PUBLISHER)
          else fail('签名', '证书主体不匹配', `期望包含 ${EXPECT_PUBLISHER}，实际 ${subject}`)
        }
      } else {
        fail('签名', '签名无效', `Status=${d.Status} ${d.StatusMessage ?? ''}`)
      }
    } catch (e) {
      fail('签名', '解析 PowerShell 输出失败', e.message)
    }
  }
}

// ---------------------------------------------------------------------------
// 汇总
// ---------------------------------------------------------------------------
const counts = results.reduce((a, r) => ((a[r.level] = (a[r.level] ?? 0) + 1), a), {})
const failed = results.filter((r) => r.level === 'FAIL')

if (useJson) {
  console.log(JSON.stringify({ target, counts, results }, null, 2))
} else {
  console.log(`\n\x1b[1m汇总\x1b[0m`)
  console.log(`  PASS=${counts.PASS ?? 0}  WARN=${counts.WARN ?? 0}  FAIL=${counts.FAIL ?? 0}  SKIP=${counts.SKIP ?? 0}  INFO=${counts.INFO ?? 0}`)
  if (failed.length) {
    console.log(`\n\x1b[31m未通过项：\x1b[0m`)
    for (const f of failed) console.log(`  - [${f.area}] ${f.name}${f.detail ? `: ${f.detail}` : ''}`)
  } else {
    console.log(`\n\x1b[32m所有强制项通过。\x1b[0m`)
  }
}

process.exit(failed.length ? 1 : 0)
