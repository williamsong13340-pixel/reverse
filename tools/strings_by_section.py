"""Extract ASCII and UTF-16LE strings (incl. CJK) per PE section, printing file offset + RVA + section."""
import sys, re
import pefile

path = sys.argv[1]
minlen = int(sys.argv[2]) if len(sys.argv) > 2 else 5
only = sys.argv[3].split(",") if len(sys.argv) > 3 else None
pe = pefile.PE(path)
data = open(path, "rb").read()

def sec_of(off):
    for s in pe.sections:
        if s.PointerToRawData <= off < s.PointerToRawData + s.SizeOfRawData:
            return s
    return None

out = []
for m in re.finditer(rb"[\x20-\x7e\t\r\n]{%d,}" % minlen, data):
    out.append((m.start(), "A", m.group().decode("ascii", "replace")))

# UTF-16LE: sequences of 2-byte units that are printable (ASCII or CJK / fullwidth / general punctuation)
i = 0
n = len(data) - 1
def ok(cp):
    return (0x20 <= cp < 0x7f) or cp in (9, 10, 13) or (0x2000 <= cp <= 0x206f) or (0x3000 <= cp <= 0x303f) or (0x4e00 <= cp <= 0x9fff) or (0xff00 <= cp <= 0xffef) or (0x2190 <= cp <= 0x21ff) or cp == 0x221a
while i < n:
    start = i
    chars = []
    while i < n:
        cp = data[i] | (data[i + 1] << 8)
        if ok(cp):
            chars.append(chr(cp)); i += 2
        else:
            break
    if len(chars) >= minlen:
        s = "".join(chars)
        # skip pure-ASCII-run artifacts of ASCII text (every other byte zero handled by ok() anyway)
        out.append((start, "U", s))
        continue
    i = start + 1 if i == start else i
    if i == start:
        i += 1

out.sort()
for off, kind, s in out:
    sec = sec_of(off)
    name = sec.Name.rstrip(b"\0").decode() if sec else "hdr/ovl"
    if only and name not in only:
        continue
    rva = sec.VirtualAddress + (off - sec.PointerToRawData) if sec else off
    print("%08x rva=%08x %-8s %s %s" % (off, rva, name, kind, s.replace("\n", "\\n").replace("\r", "\\r")))
