#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ARM64 ELF(.so) 静态分析器：符号表 / 反汇编 / 字符串引用解析。

用法:
  python zeekr_so_analyze.py <so> symbols [filter]     # 列函数符号
  python zeekr_so_analyze.py <so> dis <sym|0xADDR>     # 反汇编一个函数
  python zeekr_so_analyze.py <so> strings <sec>        # 列某段字符串
  python zeekr_so_analyze.py <so> xref <addr>          # 找谁引用了该地址
只读，不修改任何文件。
"""
import re
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_OP_IMM, CS_OP_REG
from elftools.elf.elffile import ELFFile


class SoFile:
    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb")
        self.elf = ELFFile(self.f)
        self.data = open(path, "rb").read()
        self._load_syms()
        self._load_sections()

    def _load_sections(self):
        self.secs = {}
        for s in self.elf.iter_sections():
            if s["sh_size"]:
                self.secs[s.name] = (s["sh_addr"], s["sh_offset"], s["sh_size"])

    def _load_syms(self):
        self.syms = []  # (addr, size, name, type, bind)
        for secname in (".symtab", ".dynsym"):
            sec = self.elf.get_section_by_name(secname)
            if sec is None:
                continue
            for sym in sec.iter_symbols():
                if not sym.name:
                    continue
                a = sym["st_value"]
                sz = sym["st_size"]
                self.syms.append((a, sz, sym.name, sym["st_info"]["type"], sym["st_info"]["bind"]))
        self.by_name = {}
        for a, sz, n, t, b in self.syms:
            self.by_name.setdefault(n, []).append((a, sz, t, b))
        self.funcs = sorted([s for s in self.syms if s[3] == "STT_FUNC" and s[0]], key=lambda x: x[0])

    # --- 地址 <-> 文件偏移 ---
    def addr_to_off(self, addr):
        for name, (va, off, size) in self.secs.items():
            if va and va <= addr < va + size:
                return off + (addr - va)
        return None

    def off_to_addr(self, off):
        for name, (va, o, size) in self.secs.items():
            if o and o <= off < o + size:
                return va + (off - o)
        return None

    def read_str_at_va(self, va, maxlen=200):
        off = self.addr_to_off(va)
        if off is None:
            return None
        end = self.data.find(b"\0", off)
        if end < 0:
            return None
        raw = self.data[off:min(end, off + maxlen)]
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1")


def list_symbols(so: SoFile, filt=None, funcs_only=True):
    src = so.funcs if funcs_only else sorted(so.syms, key=lambda x: x[0])
    for a, sz, n, t, b in src:
        if filt and filt.lower() not in n.lower():
            continue
        print(f"  {a:#010x}  size={sz:<7} {t:<11} {b:<9} {n}")


def find_sym(so: SoFile, key: str):
    if key.startswith("0x"):
        target = int(key, 16)
        cands = [s for s in so.funcs if s[0] == target]
        if not cands:
            # 允许落在某函数体内
            for a, sz, n, t, b in so.funcs:
                if a <= target < a + sz:
                    cands = [(a, sz, n, t, b)]
                    break
        return cands
    out = []
    for a, sz, n, t, b in so.syms:
        if key == n:
            out.append((a, sz, n, t, b))
    if not out:
        for a, sz, n, t, b in so.syms:
            if key in n:
                out.append((a, sz, n, t, b))
    return out


def disas(so: SoFile, key: str, max_insn=600):
    cands = find_sym(so, key)
    if not cands:
        print(f"symbol not found: {key}")
        return
    a, sz, n, t, b = cands[0]
    print(f"=== {n}  @ {a:#x}  size={sz}  ({t}/{b}) ===")
    off = so.addr_to_off(a)
    if off is None:
        print("cannot map address to file offset")
        return
    code = so.data[off:off + (sz if sz else max_insn * 4)]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    regs = {}          # reg -> ("page", addr) | ("val", addr)
    annot = {}

    for insn in md.disasm(code, a):
        # 追踪 ADRP / ADD / LDR 立即数
        try:
            m, ops = insn.mnemonic, list(insn.operands)
        except Exception:
            m, ops = insn.mnemonic, []
        # ADRP xN, #page  -> 只有 1 个立即数 (page)
        if m == "adrp" and len(ops) >= 2:
            reg = insn.reg_name(ops[0].reg)
            page = ops[1].imm
            regs[reg] = ("page", page)
        elif m in ("add", "ldr", "adr") and len(ops) >= 2:
            # add xD, xN, #imm   或  ldr xD, [xN, #imm]
            dst = insn.reg_name(ops[0].reg)
            src = None
            imm = 0
            if len(ops) >= 3 and ops[1].type == CS_OP_REG and ops[2].type == CS_OP_IMM:
                src = insn.reg_name(ops[1].reg)
                imm = ops[2].imm
            elif len(ops) >= 2 and ops[1].type == CS_OP_REG and ops[1].type == CS_OP_REG:
                # ldr xD, [xN, #imm]
                pass
            if m == "add" and src is not None:
                if src in regs and regs[src][0] == "page":
                    va = regs[src][1] + imm
                    regs[dst] = ("val", va)
                else:
                    regs[dst] = ("raw", None)
            elif m == "ldr":
                # ldr xD, [xN, #imm]
                if len(ops) >= 2 and ops[1].type == 0x3:  # CS_OP_MEM
                    base = insn.reg_name(ops[1].mem.base)
                    disp = ops[1].mem.disp
                    if base in regs and regs[base][0] == "val":
                        tgt = regs[base][1] + disp
                        regs[dst] = ("ptr", tgt)
                    elif base in regs and regs[base][0] == "page":
                        regs[dst] = ("cand", regs[base][1] + disp)
                    else:
                        regs[dst] = ("raw", None)
        elif m in ("adr",) and len(ops) >= 2:
            dst = insn.reg_name(ops[0].reg)
            regs[dst] = ("val", ops[1].imm)

        line = f"{insn.address:#010x}: {insn.bytes.hex():<10} {insn.mnemonic:<10} {insn.op_str}"
        # 附加注释：寄存器当前指向的字符串
        notes = []
        for reg, (kind, va) in regs.items():
            if va is None:
                continue
            if kind in ("val", "ptr", "cand"):
                s = so.read_str_at_va(va)
                if s is not None and len(s) >= 1 and all(0x20 <= ord(c) < 0x7f for c in s):
                    notes.append(f"{reg}->\"{s}\"")
        if notes:
            line += "        ; " + " | ".join(notes[:3])
        print(line)
    print()


def dump_section_strings(so: SoFile, secname: str, minlen=4):
    if secname not in so.secs:
        print(f"no section {secname}")
        return
    va, off, size = so.secs[secname]
    blob = so.data[off:off + size]
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % minlen)
    for m in pat.finditer(blob):
        s = m.group(0).decode("ascii")
        print(f"  {va + m.start():#010x}  \"{s}\"")


def xref(so: SoFile, addr_hex: str):
    target = int(addr_hex, 16)
    page = target & ~0xFFF
    page_off = target - page
    print(f"search refs to {target:#x} (page {page:#x}, off {page_off:#x})")
    pat = struct.pack("<I", 0x90000000)  # not enough; brute scan decoded insns is easier
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    hits = []
    step = 4
    blob = so.data
    # adrp 是 4 字节对齐，扫描可执行段
    for secname in (".text",):
        if secname not in so.secs:
            continue
        va, off, size = so.secs[secname]
        for i in range(0, size - 4, step):
            b = blob[off + i:off + i + 4]
            if len(b) < 4:
                break
            # adrp 编码: 1xx10000 immlo(2) immhi(19) Rd(5)
            w = struct.unpack("<I", b)[0]
            if (w & 0x9F000000) != 0x90000000:
                continue
            # 解码
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm = ((immhi << 2) | immlo) << 12
            if imm & (1 << 32):
                imm -= (1 << 33)
            pc = va + i
            val = (pc & ~0xFFF) + imm
            if val == page:
                hits.append(pc)
    for h in hits[:60]:
        print(f"  adrp @ {h:#x}")
    print(f"  total {len(hits)} adrp-page hits")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return
    so = SoFile(sys.argv[1])
    cmd = sys.argv[2]
    if cmd == "symbols":
        list_symbols(so, sys.argv[3] if len(sys.argv) > 3 else None,
                     funcs_only=(not (len(sys.argv) > 4 and sys.argv[4] == "all")))
    elif cmd == "dis":
        disas(so, sys.argv[3])
    elif cmd == "strings":
        dump_section_strings(so, sys.argv[3], int(sys.argv[4]) if len(sys.argv) > 4 else 4)
    elif cmd == "xref":
        xref(so, sys.argv[3])
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
