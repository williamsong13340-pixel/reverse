"""Light-weight x64 PE cross-referencer: per function (from .pdata) list import calls, string refs, direct calls.
Builds a pickle DB used by later queries.
usage: xref.py <pe> <db.pkl>
"""
import sys, pickle, re, struct
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_REG_RIP

path, dbpath = sys.argv[1], sys.argv[2]
pe = pefile.PE(path)
img = pe.get_memory_mapped_image()
base = pe.OPTIONAL_HEADER.ImageBase

iat = {}
for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
    for imp in entry.imports:
        name = imp.name.decode() if imp.name else "ord%d" % imp.ordinal
        iat[imp.address - base] = "%s!%s" % (entry.dll.decode().lower(), name)

sections = [(s.Name.rstrip(b"\0").decode(), s.VirtualAddress, s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)) for s in pe.sections]
def sec_name(rva):
    for n, a, b in sections:
        if a <= rva < b:
            return n
    return None

def read_str(rva):
    """Return (kind, text) if a plausible ASCII or UTF-16 string starts at rva."""
    if sec_name(rva) not in (".rdata", ".data"):
        return None
    b = img[rva:rva + 1024]
    if len(b) < 4:
        return None
    # ASCII first: no NUL in first 3 bytes, printable until NUL
    end = b.find(b"\0")
    if end >= 3:
        s = b[:end]
        if all(0x20 <= c < 0x7f or c in (9, 10, 13) for c in s):
            return ("A", s.decode())
    # UTF-16LE
    end = 0
    while end + 1 < len(b) and (b[end] or b[end + 1]):
        end += 2
    if end >= 4:
        try:
            s = b[:end].decode("utf-16le")
        except Exception:
            return None
        def okc(c):
            o = ord(c)
            return (0x20 <= o < 0x7f) or c in "\r\n\t" or 0x4e00 <= o <= 0x9fff or 0x3000 <= o <= 0x303f or 0xff00 <= o <= 0xffef or 0x2000 <= o <= 0x206f
        if all(okc(c) for c in s):
            return ("U", s)
    return None

funcs = []
for rf in pe.DIRECTORY_ENTRY_EXCEPTION:
    funcs.append((rf.struct.BeginAddress, rf.struct.EndAddress))
funcs = sorted(set(funcs))

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
db = {}
for (start, end) in funcs:
    code = img[start:end]
    info = {"start": start, "end": end, "imports": [], "strings": [], "calls": [], "data_refs": [], "imm": []}
    for insn in md.disasm(code, base + start):
        rva = insn.address - base
        for op in insn.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                target = insn.address + insn.size + op.mem.disp - base
                if target in iat:
                    info["imports"].append((rva, insn.mnemonic, iat[target]))
                else:
                    s = read_str(target)
                    if s:
                        info["strings"].append((rva, target, s[0], s[1]))
                    else:
                        info["data_refs"].append((rva, insn.mnemonic, target))
            elif op.type == X86_OP_IMM and insn.mnemonic in ("call", "jmp") and insn.group(2) is False:
                pass
        if insn.mnemonic == "call" and insn.operands and insn.operands[0].type == X86_OP_IMM:
            info["calls"].append((rva, insn.operands[0].imm - base))
        if insn.mnemonic == "jmp" and insn.operands and insn.operands[0].type == X86_OP_IMM:
            t = insn.operands[0].imm - base
            if not (start <= t < end):
                info["calls"].append((rva, t))  # tail call
        if insn.mnemonic in ("mov", "cmp", "xor", "add", "sub", "movabs") and len(insn.operands) == 2 and insn.operands[1].type == X86_OP_IMM:
            v = insn.operands[1].imm & 0xFFFFFFFFFFFFFFFF
            if v > 0xFFFF:
                info["imm"].append((rva, v))
    db[start] = info

pickle.dump({"funcs": db, "iat": iat, "base": base}, open(dbpath, "wb"))
print("functions:", len(db))
