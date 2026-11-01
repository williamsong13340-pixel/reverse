"""PE triage: headers, sections (+entropy), overlay, data dirs, imports, TLS, debug, Rich header, version info.
usage: pe_overview.py <pe>
"""
import sys, math, datetime, hashlib
import pefile

path = sys.argv[1]
data = open(path, "rb").read()
pe = pefile.PE(data=data)

def entropy(b):
    if not b:
        return 0.0
    freq = [0] * 256
    for x in b:
        freq[x] += 1
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in freq if c)

fh = pe.FILE_HEADER
oh = pe.OPTIONAL_HEADER
print("== FILE HEADER ==")
print("Machine        : 0x%x" % fh.Machine)
print("TimeDateStamp  : 0x%x  (%s UTC)" % (fh.TimeDateStamp, datetime.datetime.utcfromtimestamp(fh.TimeDateStamp)))
print("Characteristics: 0x%x" % fh.Characteristics)
print("== OPTIONAL HEADER ==")
print("Magic          : 0x%x" % oh.Magic)
print("Linker         : %d.%d" % (oh.MajorLinkerVersion, oh.MinorLinkerVersion))
print("ImageBase      : 0x%x" % oh.ImageBase)
print("EntryPoint RVA : 0x%x" % oh.AddressOfEntryPoint)
ep_sec = pe.get_section_by_rva(oh.AddressOfEntryPoint)
print("EP section     : %s" % (ep_sec.Name.rstrip(b"\0").decode(errors="replace") if ep_sec else None))
print("Subsystem      : %d   DllCharacteristics: 0x%x" % (oh.Subsystem, oh.DllCharacteristics))
print("SizeOfImage    : 0x%x  Checksum(hdr)=0x%x  Checksum(calc)=0x%x" % (oh.SizeOfImage, oh.CheckSum, pe.generate_checksum()))
print("OS version     : %d.%d  Subsys ver %d.%d" % (oh.MajorOperatingSystemVersion, oh.MinorOperatingSystemVersion, oh.MajorSubsystemVersion, oh.MinorSubsystemVersion))
print()
print("== SECTIONS ==")
print("%-10s %10s %10s %10s %10s %8s  %s" % ("Name", "VirtAddr", "VirtSize", "RawOff", "RawSize", "Entropy", "Flags"))
for s in pe.sections:
    name = s.Name.rstrip(b"\0").decode(errors="replace")
    raw = s.get_data()
    flags = []
    c = s.Characteristics
    if c & 0x20000000: flags.append("X")
    if c & 0x40000000: flags.append("R")
    if c & 0x80000000: flags.append("W")
    print("%-10s 0x%08x 0x%08x 0x%08x 0x%08x %8.3f  %s  md5=%s" % (name, s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData, entropy(raw), "".join(flags), hashlib.md5(raw).hexdigest()))

last = max(pe.sections, key=lambda s: s.PointerToRawData + s.SizeOfRawData)
end_of_sections = last.PointerToRawData + last.SizeOfRawData
sec_dir = oh.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
print()
print("File size      : %d" % len(data))
print("End of sections: %d" % end_of_sections)
print("Security dir   : off=0x%x size=0x%x" % (sec_dir.VirtualAddress, sec_dir.Size))
overlay = pe.get_overlay()
if overlay:
    print("Overlay        : offset=0x%x size=%d entropy=%.3f head=%r" % (pe.get_overlay_data_start_offset(), len(overlay), entropy(overlay), overlay[:32]))
else:
    print("Overlay        : none")
print("Whole-file entropy: %.3f" % entropy(data))
print()
print("== DATA DIRECTORIES ==")
for i, d in enumerate(oh.DATA_DIRECTORY):
    if d.Size:
        print("  %-40s rva=0x%08x size=0x%x" % (d.name, d.VirtualAddress, d.Size))

print()
print("== IMPORTS ==")
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        names = []
        for imp in entry.imports:
            names.append(imp.name.decode() if imp.name else "ord#%d" % imp.ordinal)
        print("[%s] (%d)" % (entry.dll.decode(), len(names)))
        print("    " + ", ".join(names))
else:
    print("  (no import directory)")
if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
    print("== DELAY IMPORTS ==")
    for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
        names = [imp.name.decode() if imp.name else "ord#%d" % imp.ordinal for imp in entry.imports]
        print("[%s] (%d)" % (entry.dll.decode(), len(names)))
        print("    " + ", ".join(names))
if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
    print("== EXPORTS ==")
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        print("   ", e.ordinal, e.name)
if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
    tls = pe.DIRECTORY_ENTRY_TLS.struct
    print("== TLS ==")
    print("  AddressOfCallBacks: 0x%x" % tls.AddressOfCallBacks)
    if tls.AddressOfCallBacks:
        cb_rva = tls.AddressOfCallBacks - oh.ImageBase
        i = 0
        while True:
            v = pe.get_qword_at_rva(cb_rva + 8 * i)
            if not v:
                break
            print("    callback[%d] = 0x%x" % (i, v))
            i += 1
if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
    print("== DEBUG ==")
    for d in pe.DIRECTORY_ENTRY_DEBUG:
        print("  type=%d ts=0x%x" % (d.struct.Type, d.struct.TimeDateStamp), end="")
        if d.entry is not None and hasattr(d.entry, "PdbFileName"):
            print(" pdb=%r" % d.entry.PdbFileName, end="")
        print()
if hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER:
    print("== RICH HEADER ==")
    vals = pe.RICH_HEADER.values
    for i in range(0, len(vals), 2):
        comp = vals[i]
        print("  prodid=%3d build=%5d count=%d" % (comp >> 16, comp & 0xFFFF, vals[i + 1]))
if hasattr(pe, "VS_VERSIONINFO") and hasattr(pe, "FileInfo"):
    print("== VERSION INFO ==")
    for fi in pe.FileInfo:
        for entry in fi:
            if hasattr(entry, "StringTable"):
                for st in entry.StringTable:
                    for k, v in st.entries.items():
                        print("  %s: %s" % (k.decode(errors="replace"), v.decode(errors="replace")))
