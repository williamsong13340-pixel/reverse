"""Emulate selected functions of an x64 PE inside Unicorn with all imports stubbed (nothing touches the host OS).
Logs GetModuleHandle/LoadLibrary/GetProcAddress names and which .data globals receive resolved pointers.
usage: emu.py <pe> <func_rva_hex>[,<func_rva_hex>...] [maxinsn] [rcx_global_rva_hex]
  rcx_global_rva_hex: optional RVA of a global object passed in RCX (e.g. an API table),
  so writes of resolved API pointers into .data can be attributed to fixed addresses.
"""
import sys, struct
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_UNMAPPED, UC_PROT_ALL, UcError
from unicorn.x86_const import *

path = sys.argv[1]
targets = [int(x, 16) for x in sys.argv[2].split(",")]
MAXI = int(sys.argv[3]) if len(sys.argv) > 3 else 3_000_000
RCX_GLOBAL = int(sys.argv[4], 16) if len(sys.argv) > 4 else None

pe = pefile.PE(path)
base = pe.OPTIONAL_HEADER.ImageBase
img = bytearray(pe.get_memory_mapped_image())
size = (pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & ~0xFFF

STUB = 0x7FF000000000
FAKEAPI = 0x7FF100000000
FAKEMOD = 0x7FF200000000
STACK, STACK_SZ = 0x10000000, 0x200000
HEAP, HEAP_SZ = 0x20000000, 0x4000000
TEB = 0x30000000
RET_SENTINEL = 0xDEAD0000

stub_names = {}
idx = 0
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        name = imp.name.decode() if imp.name else "ord%d" % imp.ordinal
        addr = STUB + idx * 16
        stub_names[addr] = name
        struct.pack_into("<Q", img, imp.address - base, addr)
        idx += 1

uc = Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(base, size, UC_PROT_ALL)
uc.mem_write(base, bytes(img[:size]))
uc.mem_map(STUB, 0x10000, UC_PROT_ALL); uc.mem_write(STUB, b"\xc3" * 0x10000)
uc.mem_map(FAKEAPI, 0x100000, UC_PROT_ALL); uc.mem_write(FAKEAPI, b"\xc3" * 0x100000)
uc.mem_map(STACK, STACK_SZ, UC_PROT_ALL)
uc.mem_map(HEAP, HEAP_SZ, UC_PROT_ALL)
uc.mem_map(TEB, 0x10000, UC_PROT_ALL)
uc.mem_map(RET_SENTINEL, 0x1000, UC_PROT_ALL); uc.mem_write(RET_SENTINEL, b"\xf4" * 0x1000)
# TEB: self pointer, TLS array pointer at gs:[0x58]
uc.mem_write(TEB + 0x30, struct.pack("<Q", TEB))
uc.mem_write(TEB + 0x58, struct.pack("<Q", TEB + 0x1000))
for i in range(64):
    uc.mem_write(TEB + 0x1000 + 8 * i, struct.pack("<Q", TEB + 0x2000 + 0x200 * i))
uc.reg_write(UC_X86_REG_GS_BASE, TEB)

heap_ptr = [HEAP + 0x1000]
def alloc(n):
    p = heap_ptr[0]
    heap_ptr[0] += (n + 0x2F) & ~0xF
    return p

def rd_cstr(a, wide=False, maxlen=512):
    if a == 0:
        return None
    try:
        b = bytes(uc.mem_read(a, maxlen * (2 if wide else 1)))
    except UcError:
        return "<bad ptr %x>" % a
    if wide:
        for i in range(0, len(b) - 1, 2):
            if b[i] == 0 and b[i + 1] == 0:
                return b[:i].decode("utf-16le", "replace")
        return b.decode("utf-16le", "replace")
    e = b.find(b"\0")
    return b[:e if e >= 0 else len(b)].decode("latin-1")

fake_apis = {}
fake_mods = {}
log = []
globals_written = {}

def api_ret(v):
    uc.reg_write(UC_X86_REG_RAX, v)

def hook_code(uc, address, size, user):
    if STUB <= address < STUB + 0x10000:
        name = stub_names.get(address, "?")
        rcx, rdx, r8, r9 = (uc.reg_read(r) for r in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9))
        if name in ("GetModuleHandleA", "LoadLibraryA", "GetModuleHandleW", "LoadLibraryW", "LoadLibraryExW"):
            s = rd_cstr(rcx, wide=name.endswith("W"))
            h = fake_mods.setdefault(s, FAKEMOD + 0x100000 * (len(fake_mods) + 1))
            log.append("%s(%r) -> %x" % (name, s, h))
            api_ret(h)
        elif name == "GetProcAddress":
            mod = next((k for k, v in fake_mods.items() if v == rcx), "%x" % rcx)
            s = rd_cstr(rdx) if rdx > 0xFFFF else "ord%d" % rdx
            p = fake_apis.setdefault((mod, s), FAKEAPI + 0x10 * (len(fake_apis) + 1))
            log.append("GetProcAddress(%s, %r) -> %x" % (mod, s, p))
            api_ret(p)
        elif name in ("HeapAlloc",):
            api_ret(alloc(r8))
        elif name in ("HeapReAlloc",):
            n = alloc(r9)
            api_ret(n)
        elif name in ("HeapFree", "HeapSize"):
            api_ret(1)
        elif name in ("GetProcessHeap",):
            api_ret(0x5000)
        elif name in ("EncodePointer", "DecodePointer"):
            api_ret(rcx)
        else:
            log.append("[stub] %s(rcx=%x, rdx=%x)" % (name, rcx, rdx))
            api_ret(0)
        return
    if FAKEAPI <= address < FAKEAPI + 0x100000:
        n = next((k for k, v in fake_apis.items() if v == address), None)
        log.append("[called resolved API] %s" % (n,))
        api_ret(0)
        return
    if address == RET_SENTINEL:
        uc.emu_stop()

data_sec = [s for s in pe.sections if s.Name.startswith(b".data")][0]
DATA_LO, DATA_HI = base + data_sec.VirtualAddress, base + data_sec.VirtualAddress + data_sec.Misc_VirtualSize

def hook_write(uc, access, address, size, value, user):
    if DATA_LO <= address < DATA_HI and size == 8:
        v = value & 0xFFFFFFFFFFFFFFFF
        if FAKEAPI <= v < FAKEAPI + 0x100000:
            n = next((k for k, vv in fake_apis.items() if vv == v), None)
            globals_written[address - base] = n

def hook_unmapped(uc, access, address, size, value, user):
    log.append("[unmapped access] type=%d addr=%x rip=%x" % (access, address, uc.reg_read(UC_X86_REG_RIP) - base))
    return False

uc.hook_add(UC_HOOK_CODE, hook_code, begin=STUB, end=STUB + 0x10000)
uc.hook_add(UC_HOOK_CODE, hook_code, begin=FAKEAPI, end=FAKEAPI + 0x100000)
uc.hook_add(UC_HOOK_CODE, hook_code, begin=RET_SENTINEL, end=RET_SENTINEL + 1)
uc.hook_add(UC_HOOK_MEM_WRITE, hook_write, begin=DATA_LO, end=DATA_HI)
uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped)

for t in targets:
    log.append("==== emulate func %x ====" % t)
    rsp = STACK + STACK_SZ - 0x10000
    uc.mem_write(rsp, struct.pack("<Q", RET_SENTINEL))
    flag = alloc(0x100)
    uc.mem_write(flag, b"\0" * 0x100)
    uc.reg_write(UC_X86_REG_RSP, rsp)
    for r in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9):
        uc.reg_write(r, flag)
    if RCX_GLOBAL is not None:
        uc.reg_write(UC_X86_REG_RCX, base + RCX_GLOBAL)
    try:
        uc.emu_start(base + t, RET_SENTINEL, count=MAXI)
    except UcError as e:
        log.append("[emu error] %s at rip=%x" % (e, uc.reg_read(UC_X86_REG_RIP) - base))
    log.append("[end] rip=%x rax=%x" % (uc.reg_read(UC_X86_REG_RIP) - base, uc.reg_read(UC_X86_REG_RAX)))

print("\n".join(log))
print("\n==== .data globals receiving resolved API pointers ====")
for g, n in sorted(globals_written.items()):
    print("  [0x%x] = %s!%s" % (g, n[0], n[1]))
