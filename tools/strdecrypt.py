"""Recover all MINSTD-XOR obfuscated strings in an x64 PE by tracking stack writes after a key marker.
Layout used by the obfuscator: [rsp+X] = key (dword), [rsp+X+4 ...] = encrypted bytes.
usage: strdecrypt.py <pe> <key_hex>
"""
import sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_OP_REG, X86_REG_RIP, X86_REG_RSP, X86_REG_RBP

path = sys.argv[1]
KEY = int(sys.argv[2], 16)
pe = pefile.PE(path)
img = pe.get_memory_mapped_image()
base = pe.OPTIONAL_HEADER.ImageBase
text = [s for s in pe.sections if s.Name.startswith(b".text")][0]
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def dec(data, key):
    s = key
    out = bytearray()
    for b in data:
        out.append(b ^ (s & 0xFF))
        s = ((s * 48271) & 0xFFFFFFFF) % 0x7FFFFFFF
    return bytes(out)

def as_text(p):
    # ASCII
    z = p.find(b"\0")
    a = p[:z] if z >= 0 else p
    ascii_ok = len(a) >= 2 and all(0x20 <= c < 0x7f or c in (9, 10, 13) for c in a)
    # UTF-16LE
    w = None
    for i in range(0, len(p) - 1, 2):
        if p[i] == 0 and p[i + 1] == 0:
            w = p[:i]
            break
    if w is None:
        w = p[: len(p) // 2 * 2]
    wide_ok = False
    if len(w) >= 4 and all(w[i + 1] == 0 for i in range(0, len(w), 2)):
        try:
            ws = w.decode("utf-16le")
            wide_ok = all(c.isprintable() or c in "\r\n\t" for c in ws)
        except Exception:
            pass
    if wide_ok and (len(w) // 2 > len(a)):
        return "L\"%s\"" % w.decode("utf-16le"), z
    if ascii_ok:
        return "\"%s\"" % a.decode(), z
    # CJK UTF-16 (no zero high bytes)
    try:
        ws = w.decode("utf-16le")
        if len(ws) >= 2 and all(0x4e00 <= ord(c) <= 0x9fff or 0x20 <= ord(c) < 0x7f or 0x3000 <= ord(c) <= 0x303f or 0xff00 <= ord(c) <= 0xffef for c in ws):
            return "L\"%s\"" % ws, z
    except Exception:
        pass
    return None, z

REG32 = {}
results = {}
funcs = sorted(set([rf.struct.BeginAddress for rf in pe.DIRECTORY_ENTRY_EXCEPTION]))
# include leaf gaps: sweep whole .text in pdata-delimited chunks
chunks = sorted(set(funcs + [text.VirtualAddress]))
end_text = text.VirtualAddress + text.Misc_VirtualSize

for ci, st in enumerate(chunks):
    en = chunks[ci + 1] if ci + 1 < len(chunks) else end_text
    regs = {}     # reg name -> int value
    xmm = {}      # xmm name -> bytes
    stack = {}    # rsp offset -> byte
    markers = {}  # rsp offset of key -> best string
    for insn in md.disasm(img[st:en], base + st):
        m = insn.mnemonic
        ops = insn.operands
        if m in ("ret", "jmp") and not (m == "jmp" and ops and ops[0].type == X86_OP_IMM):
            pass
        if m == "call":
            for r in ("rax","eax","rcx","ecx","rdx","edx","r8","r8d","r9","r9d","r10","r10d","r11","r11d"):
                regs.pop(r, None)
            for r in ("xmm0","xmm1","xmm2","xmm3","xmm4","xmm5"):
                xmm.pop(r, None)
            continue
        if len(ops) == 2:
            d, s = ops
            # register loads
            if d.type == X86_OP_REG and m in ("mov", "movabs") and s.type == X86_OP_IMM:
                regs[insn.reg_name(d.reg)] = s.imm & 0xFFFFFFFFFFFFFFFF
                continue
            if d.type == X86_OP_REG and m == "mov" and s.type == X86_OP_REG:
                v = regs.get(insn.reg_name(s.reg))
                if v is not None:
                    regs[insn.reg_name(d.reg)] = v
                else:
                    regs.pop(insn.reg_name(d.reg), None)
                continue
            if d.type == X86_OP_REG and m in ("movdqa", "movdqu", "movups", "movaps") and s.type == X86_OP_MEM and s.mem.base == X86_REG_RIP:
                t = insn.address + insn.size + s.mem.disp - base
                xmm[insn.reg_name(d.reg)] = bytes(img[t:t + 16])
                continue
            if d.type == X86_OP_REG and m in ("movdqa", "movdqu", "movups", "movaps") and s.type == X86_OP_REG:
                v = xmm.get(insn.reg_name(s.reg))
                if v is not None:
                    xmm[insn.reg_name(d.reg)] = v
                continue
            # stack writes
            if d.type == X86_OP_MEM and d.mem.base in (X86_REG_RSP, X86_REG_RBP) and d.mem.index == 0:
                off = d.mem.disp + (0 if d.mem.base == X86_REG_RSP else 0x100000)
                sz = d.size
                val = None
                if s.type == X86_OP_IMM:
                    val = (s.imm & ((1 << (8 * sz)) - 1)).to_bytes(sz, "little")
                elif s.type == X86_OP_REG:
                    rn = insn.reg_name(s.reg)
                    if rn.startswith("xmm"):
                        val = xmm.get(rn)
                        sz = 16
                    else:
                        v = regs.get(rn)
                        if v is None:
                            # try 64-bit parent for 32-bit regs
                            v = regs.get({"r15d": "r15", "r14d": "r14", "r13d": "r13", "r12d": "r12", "eax": "rax", "ecx": "rcx", "edx": "rdx", "r8d": "r8", "r9d": "r9", "ebx": "rbx", "esi": "rsi", "edi": "rdi"}.get(rn, ""), None)
                        if v is not None:
                            val = (v & ((1 << (8 * sz)) - 1)).to_bytes(sz, "little")
                if val is None:
                    for k in range(sz):
                        stack.pop(off + k, None)
                    continue
                for k in range(len(val)):
                    stack[off + k] = val[k]
                if len(val) == 4 and int.from_bytes(val, "little") == KEY:
                    markers[off] = insn.address
                # attempt decrypt for markers adjacent to this write
                for mo in list(markers):
                    start = mo + 4
                    buf = bytearray()
                    o = start
                    while o in stack and len(buf) < 600:
                        buf.append(stack[o]); o += 1
                    if len(buf) >= 2:
                        p = dec(bytes(buf), KEY)
                        t, z = as_text(p)
                        if t:
                            key_id = (st, mo, markers[mo])
                            prev = results.get(key_id)
                            if prev is None or len(t) > len(prev[1]):
                                results[key_id] = (insn.address - base, t)
                continue

seen = set()
for (fs, mo, inst), (rva, t) in sorted(results.items(), key=lambda kv: kv[1][0]):
    if (rva, t) in seen:
        continue
    seen.add((rva, t))
    print("%08x  (func %x)  %s" % (rva, fs, t))
