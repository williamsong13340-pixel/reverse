"""Dump .NET metadata of an assembly: assembly info, refs, P/Invoke imports, types/methods, user strings, resources."""
import sys
import dnfile

path = sys.argv[1]
pe = dnfile.dnPE(path)
md = pe.net.mdtables

def s(x):
    try:
        return str(x)
    except Exception:
        return repr(x)

print("== CLR header ==")
print("  runtime:", pe.net.struct.MajorRuntimeVersion, pe.net.struct.MinorRuntimeVersion, " flags: 0x%x" % pe.net.struct.Flags)
print("  metadata version:", pe.net.metadata.struct.Version if pe.net.metadata else None)

if md.Assembly:
    for a in md.Assembly:
        print("== Assembly ==", a.Name, "%d.%d.%d.%d" % (a.MajorVersion, a.MinorVersion, a.BuildNumber, a.RevisionNumber), "culture=", a.Culture)
if md.Module:
    for m in md.Module:
        print("  Module:", m.Name, m.Mvid)

print("== AssemblyRef ==")
for a in (md.AssemblyRef or []):
    print("  ", a.Name, "%d.%d.%d.%d" % (a.MajorVersion, a.MinorVersion, a.BuildNumber, a.RevisionNumber))

print("== ModuleRef (native DLLs) ==")
for m in (md.ModuleRef or []):
    print("  ", m.Name)

print("== P/Invoke (ImplMap) ==")
for im in (md.ImplMap or []):
    mf = im.MemberForwarded
    try:
        target = mf.row.Name
    except Exception:
        target = "?"
    mod = im.ImportScope.row.Name if im.ImportScope and im.ImportScope.row else "?"
    print("   %-20s %-35s (managed name: %s)" % (mod, im.ImportName, target))

print("== TypeRef (external types used) ==")
refs = set()
for t in (md.TypeRef or []):
    refs.add("%s.%s" % (t.TypeNamespace, t.TypeName))
for r in sorted(refs):
    print("  ", r)

print("== MemberRef (external members used) ==")
mrefs = set()
for m in (md.MemberRef or []):
    try:
        cls = m.Class.row
        cname = "%s.%s" % (getattr(cls, "TypeNamespace", ""), getattr(cls, "TypeName", getattr(cls, "Name", "?")))
    except Exception:
        cname = "?"
    mrefs.add("%s::%s" % (cname, m.Name))
for r in sorted(mrefs):
    print("  ", r)

print("== TypeDef / MethodDef ==")
for t in (md.TypeDef or []):
    print("  type %s.%s  (flags 0x%x)" % (t.TypeNamespace, t.TypeName, t.Flags.value if hasattr(t.Flags, "value") else 0))
    for mi in t.MethodList:
        m = mi.row
        print("      method %-40s rva=0x%x" % (m.Name, m.Rva))

print("== ManifestResource ==")
for r in (md.ManifestResource or []):
    print("  ", r.Name, "offset=", r.Offset, "impl=", r.Implementation)

print("== CustomAttributes (types) ==")
ca_types = set()
for ca in (md.CustomAttribute or []):
    try:
        t = ca.Type.row
        cls = t.Class.row
        ca_types.add("%s.%s" % (getattr(cls, "TypeNamespace", ""), getattr(cls, "TypeName", "?")))
    except Exception:
        pass
for c in sorted(ca_types):
    print("  ", c)

print("== #US user strings ==")
us = pe.net.user_strings
if us:
    off = 1
    data = us.get_data() if hasattr(us, "get_data") else None
    # iterate using dnfile helper
    seen = 0
    i = 1
    size = us.sizeof() if hasattr(us, "sizeof") else 0
    while i < size:
        try:
            item = us.get(i)
        except Exception:
            break
        if item is None:
            break
        val = item.value if hasattr(item, "value") else item
        raw_len = item.raw_size if hasattr(item, "raw_size") else None
        print("   0x%06x: %r" % (i, val))
        # advance: compressed length prefix + data
        b0 = us.get_data_at_offset(i, 1)[0] if hasattr(us, "get_data_at_offset") else None
        if b0 is None:
            break
        if b0 & 0x80 == 0:
            ln, hdr = b0, 1
        elif b0 & 0xC0 == 0x80:
            b = us.get_data_at_offset(i, 2)
            ln, hdr = ((b[0] & 0x3F) << 8) | b[1], 2
        else:
            b = us.get_data_at_offset(i, 4)
            ln, hdr = ((b[0] & 0x1F) << 24) | (b[1] << 16) | (b[2] << 8) | b[3], 4
        i += hdr + ln
