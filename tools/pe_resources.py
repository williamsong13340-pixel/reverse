"""Walk and dump every PE resource to <outdir>, printing size, entropy, magic and md5.
usage: pe_resources.py <pe> <outdir>
"""
import sys, math, os, hashlib
import pefile

path = sys.argv[1]
outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)
pe = pefile.PE(path)

def entropy(b):
    if not b:
        return 0.0
    freq = [0] * 256
    for x in b:
        freq[x] += 1
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in freq if c)

def magic(b):
    sigs = [
        (b"MZ", "PE/MZ"), (b"\x89PNG", "PNG"), (b"\xff\xd8\xff", "JPEG"), (b"GIF8", "GIF"),
        (b"PK\x03\x04", "ZIP"), (b"RIFF", "RIFF(WAV?)"), (b"\x1f\x8b", "GZIP"), (b"BM", "BMP"),
        (b"7z\xbc\xaf", "7Z"), (b"\x00\x00\x01\x00", "ICO"), (b"<?xml", "XML"), (b"\xef\xbb\xbf<", "XML(BOM)"),
        (b"\x78\x9c", "ZLIB"), (b"\x78\xda", "ZLIB"), (b"\x28\xb5\x2f\xfd", "ZSTD"), (b"\x04\x22\x4d\x18", "LZ4"),
        (b"\x5d\x00\x00", "LZMA?"), (b"wOFF", "WOFF"), (b"OTTO", "OTF"), (b"\x00\x01\x00\x00", "TTF?"),
    ]
    for s, n in sigs:
        if b.startswith(s):
            return n
    return "?"

def walk(entries, path_parts):
    for e in entries:
        name = str(e.name) if e.name is not None else (pefile.RESOURCE_TYPE.get(e.id, e.id) if not path_parts else e.id)
        if hasattr(e, "directory"):
            walk(e.directory.entries, path_parts + [str(name)])
        else:
            d = e.data.struct
            blob = pe.get_memory_mapped_image()[d.OffsetToData:d.OffsetToData + d.Size]
            label = "/".join(path_parts + [str(name)])
            fn = label.replace("/", "_").replace("\\", "_").replace(" ", "_")
            with open(os.path.join(outdir, fn + ".bin"), "wb") as f:
                f.write(blob)
            print("%-45s size=%8d  ent=%.3f  magic=%-10s md5=%s head=%s" % (
                label, d.Size, entropy(blob), magic(blob), hashlib.md5(blob).hexdigest(), blob[:16].hex()))

walk(pe.DIRECTORY_ENTRY_RESOURCE.entries, [])
