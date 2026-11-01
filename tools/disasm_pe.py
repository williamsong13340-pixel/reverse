"""Disassemble [start, end) RVA range of a PE with import/string annotations.
usage: dis.py <pe> <start_hex> <end_hex>
"""
import sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

path = sys.argv[1]
start, end = int(sys.argv[2], 16), int(sys.argv[3], 16)
pe = pefile.PE(path)
img = pe.get_memory_mapped_image()
base = pe.OPTIONAL_HEADER.ImageBase
iat = {}
for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
    for imp in entry.imports:
        iat[imp.address - base] = imp.name.decode() if imp.name else "ord%d" % imp.ordinal

def annot_str(rva):
    b = img[rva:rva + 200]
    e = b.find(b"\0")
    if e >= 3 and all(0x20 <= c < 0x7f or c in (9, 10, 13) for c in b[:e]):
        return "'%s'" % b[:e].decode()
    j = 0
    while j + 1 < len(b) and (b[j] or b[j + 1]):
        j += 2
    if j >= 4:
        try:
            s = b[:j].decode("utf-16le")
            if all(c.isprintable() for c in s):
                return "L'%s'" % s
        except Exception:
            pass
    return None

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
for insn in md.disasm(img[start:end], base + start):
    rva = insn.address - base
    note = ""
    for op in insn.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            t = insn.address + insn.size + op.mem.disp - base
            if t in iat:
                note = "  ; [%s]" % iat[t]
            else:
                s = annot_str(t)
                note = "  ; ->%x %s" % (t, s if s else "")
    if insn.mnemonic in ("mov", "movabs") and len(insn.operands) == 2 and insn.operands[1].type == 2:
        v = insn.operands[1].imm & 0xFFFFFFFFFFFFFFFF
        bs = v.to_bytes(8, "little").rstrip(b"\0")
        if len(bs) >= 2 and all(0x20 <= c < 0x7f for c in bs):
            note += "  ; '%s'" % bs.decode()
    if insn.mnemonic == "call" and insn.operands[0].type == 2:
        note += "  ; sub_%x" % (insn.operands[0].imm - base)
    print("%08x: %-8s %s%s" % (rva, insn.mnemonic, insn.op_str, note))
