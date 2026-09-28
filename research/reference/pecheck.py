#!/usr/bin/env python3
"""Minimal PE hardening auditor - reads PE headers + load config directly.

Prints: machine, DllCharacteristics (decoded), load-config GuardFlags (decoded),
GuardCFFunctionTable/Count, SecurityCookie, SEHandlerTable/Count, and
checksum/debug/rich info needed for a hardening report.
"""
import struct
import sys

DLLCHAR = [
    (0x0001, "HIGH_ENTROPY_VA"),          # note: actual bit is 0x0020; 0x0001 = reserved
    (0x0020, "HIGH_ENTROPY_VA"),
    (0x0040, "DYNAMIC_BASE"),
    (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT"),
    (0x0200, "NO_ISOLATION"),
    (0x0400, "NO_SEH"),
    (0x0800, "NO_BIND"),
    (0x1000, "APPCONTAINER"),
    (0x2000, "WDM_DRIVER"),
    (0x4000, "GUARD_CF"),
    (0x8000, "TERMINAL_SERVER_AWARE"),
]

GUARD_FLAGS = [
    (0x00000100, "IMAGE_GUARD_CF_INSTRUMENTED"),
    (0x00000200, "IMAGE_GUARD_CFW_INSTRUMENTED"),
    (0x00000400, "IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT"),
    (0x00000800, "IMAGE_GUARD_SECURITY_COOKIE_UNUSED"),
    (0x00001000, "IMAGE_GUARD_PROTECT_DELAYLOAD_IAT"),
    (0x00002000, "IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION"),
    (0x00004000, "IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT"),
    (0x00008000, "IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION"),
    (0x00010000, "IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT"),
    (0x00020000, "IMAGE_GUARD_RF_INSTRUMENTED"),
    (0x00040000, "IMAGE_GUARD_RF_ENABLE"),
    (0x00080000, "IMAGE_GUARD_RF_STRICT"),
    (0x00100000, "IMAGE_GUARD_RETPOLINE_PRESENT"),
    (0x00200000, "IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT"),
    (0x00400000, "IMAGE_GUARD_XFG_ENABLED"),
    (0x00800000, "IMAGE_GUARD_CASTGUARD_PRESENT"),
    (0x01000000, "IMAGE_GUARD_MEMCPY_PRESENT"),
]

MACHINE = {
    0x014C: "I386 (x86)", 0x8664: "AMD64 (x64)", 0xAA64: "ARM64",
    0x01C4: "ARMNT", 0xA641: "ARM64EC",
}


def decode(value, table):
    out = [name for bit, name in table if value & bit]
    unknown = value & ~sum(bit for bit, _ in table)
    if unknown:
        out.append(f"<unknown bits 0x{unknown:x}>")
    return out


def main(path):
    data = open(path, "rb").read()
    if data[:2] != b"MZ":
        sys.exit("not MZ")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[e_lfanew:e_lfanew + 4] == b"PE\0\0", "no PE sig"
    coff = e_lfanew + 4
    machine, nsec, _, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    is64 = magic == 0x20B
    print(f"file                : {path}  ({len(data):,} bytes)")
    print(f"machine             : 0x{machine:04X} {MACHINE.get(machine, '?')}")
    print(f"COFF characteristics: 0x{chars:04X} "
          f"{decode(chars, [(0x0002,'EXECUTABLE_IMAGE'),(0x0020,'LARGE_ADDRESS_AWARE'),(0x0100,'32BIT_MACHINE'),(0x2000,'DLL')])}")
    print(f"optional header magic: 0x{magic:04X} {'PE32+' if is64 else 'PE32'}")

    # DllCharacteristics offset: PE32 -> 0x46, PE32+ -> 0x46 as well (after 0x18 base+... )
    # Standard: PE32: Magic(2)+MajorLinker(1)+MinorLinker(1)+SizeCode(4)+SizeInit(4)+SizeUninit(4)+Entry(4)+BaseCode(4)+BaseData(4)
    #                +ImageBase(4)+SectionAlign(4)+FileAlign(4)+OSVer(4)+ImgVer(4)+SubsysVer(4)+Win32Ver(4)
    #                +SizeImage(4)+SizeHeaders(4)+Checksum(4)+Subsystem(2)+DllCharacteristics(2)
    if is64:
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    else:
        image_base = struct.unpack_from("<I", data, opt + 28)[0]
    dllchar = struct.unpack_from("<H", data, opt + 0x46)[0]
    checksum = struct.unpack_from("<I", data, opt + 0x40)[0]
    size_headers = struct.unpack_from("<I", data, opt + 0x3C)[0]
    print(f"image base          : 0x{image_base:X}")
    print(f"DllCharacteristics  : 0x{dllchar:04X}")
    for n in decode(dllchar, DLLCHAR):
        print(f"    - {n}")
    print(f"CheckSum field      : 0x{checksum:08X} {'(set)' if checksum else '(zero)'}")

    # data directories
    dd_off = opt + (112 if is64 else 96)
    n_dd = struct.unpack_from("<I", data, opt + (108 if is64 else 92))[0]
    dirs = []
    for i in range(min(n_dd, 16)):
        rva, size = struct.unpack_from("<II", data, dd_off + i * 8)
        dirs.append((rva, size))
    names = ["export", "import", "resource", "exception", "certificate", "reloc",
             "debug", "arch", "globalptr", "tls", "load_config", "bound_import",
             "iat", "delay_import", "clr", "reserved"]
    # sections
    sec_off = opt + opt_size
    secs = []
    for i in range(nsec):
        o = sec_off + i * 40
        nm = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, o + 8)
        schar = struct.unpack_from("<I", data, o + 36)[0]
        secs.append((nm, vaddr, vsize, raddr, rsize, schar))
    print("sections            : " + ", ".join(f"{s[0]}(0x{s[5]:X})" for s in secs))

    def rva2off(rva):
        for nm, vaddr, vsize, raddr, rsize, _ in secs:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return raddr + (rva - vaddr)
        return None

    lc_rva, lc_size = dirs[10]
    print(f"\n--- Load Config Directory: RVA 0x{lc_rva:X}, size {lc_size} ---")
    if lc_rva == 0:
        print("  ABSENT (no load config directory)")
        return
    off = rva2off(lc_rva)
    if off is None:
        print("  RVA not mapped")
        return
    lc = data[off:off + lc_size]
    lcsize_field = struct.unpack_from("<I", lc, 0)[0]
    print(f"  Size field        : {lcsize_field}")

    def f32(name, field_off):
        if len(lc) >= field_off + 4:
            v = struct.unpack_from("<I", lc, field_off)[0]
            print(f"  {name:<34}: 0x{v:08X}")
            return v
        return None

    def f64(name, field_off):
        if len(lc) >= field_off + 8:
            v = struct.unpack_from("<Q", lc, field_off)[0]
            print(f"  {name:<34}: 0x{v:016X}")
            return v
        return None

    if is64:
        # IMAGE_LOAD_CONFIG_DIRECTORY64: note CodeIntegrity (12 bytes) sits at 0x94,
        # so the Guard*Table fields start at 0xA0, not 0x98.
        f64("SecurityCookie", 0x58)
        f64("SEHandlerTable", 0x60)
        f64("SEHandlerCount", 0x68)
        f64("GuardCFCheckFunctionPointer", 0x70)
        f64("GuardCFDispatchFunctionPointer", 0x78)
        f64("GuardCFFunctionTable", 0x80)
        f64("GuardCFFunctionCount", 0x88)
        gf = f32("GuardFlags", 0x90)
        f64("GuardAddressTakenIatEntryTable", 0xA0)
        f64("GuardAddressTakenIatEntryCount", 0xA8)
        f64("GuardLongJumpTargetTable", 0xB0)
        f64("GuardLongJumpTargetCount", 0xB8)
        f64("GuardEHContinuationTable", 0x108)
        f64("GuardEHContinuationCount", 0x110)
        f64("GuardXFGCheckFunctionPointer", 0x118)
        f64("GuardXFGDispatchFunctionPointer", 0x120)
        f64("GuardXFGTableDispatchFunctionPointer", 0x128)
        f64("CastGuardOsDeterminedFailureMode", 0x130)
        f64("GuardMemcpyFunctionPointer", 0x138)
    else:
        f32("SecurityCookie", 0x40)
        f32("SEHandlerTable", 0x44)
        f32("SEHandlerCount", 0x48)
        f32("GuardCFCheckFunctionPointer", 0x4C)
        f32("GuardCFDispatchFunctionPointer", 0x50)
        f32("GuardCFFunctionTable", 0x54)
        f32("GuardCFFunctionCount", 0x58)
        gf = f32("GuardFlags", 0x5C)

    print(f"  GuardFlags decoded:")
    if gf is not None:
        for n in decode(gf, GUARD_FLAGS):
            print(f"      - {n}")
        if gf == 0:
            print("      (none)")

    # ---- debug directory: CET extended DLL characteristics -------------------
    dbg_rva, dbg_size = dirs[6]
    print(f"\n--- Debug Directory: RVA 0x{dbg_rva:X}, size {dbg_size} ---")
    if dbg_rva == 0 or dbg_size == 0:
        print("  ABSENT")
        return
    doff = rva2off(dbg_rva)
    n_entries = dbg_size // 28
    ex_cet = None
    for i in range(n_entries):
        o = doff + i * 28
        dchars, tds, maj, minr, dtype, dsize, araw, praw = struct.unpack_from("<IIHHIIII", data, o)
        print(f"  entry[{i}] Type={dtype} SizeOfData={dsize} PointerToRawData=0x{praw:X}")
        if dtype == 20:  # IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
            ex = struct.unpack_from("<H", data, praw)[0]
            ex_cet = ex
    if ex_cet is None:
        print("  NO IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS entry "
              "=> binary is NOT marked CET Shadow Stack compatible (/CETCOMPAT absent)")
    else:
        print(f"  IMAGE_DLLCHARACTERISTICS_EX = 0x{ex_cet:04X}")
        print("    CET_COMPAT (/CETCOMPAT): "
              f"{'SET' if ex_cet & 0x1 else 'not set'}")


if __name__ == "__main__":
    main(sys.argv[1])
