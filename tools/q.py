"""Query the xref DB.
q.py db imp <regex>      -> functions calling imports matching regex (with their strings)
q.py db str <regex>      -> functions referencing strings matching regex
q.py db fn <hex rva>     -> dump info for the function containing rva
q.py db callers <hex>    -> functions that call the function at rva
"""
import sys, pickle, re
db = pickle.load(open(sys.argv[1], "rb"))
F = db["funcs"]
cmd, arg = sys.argv[2], sys.argv[3]

def containing(rva):
    for s, f in F.items():
        if f["start"] <= rva < f["end"]:
            return f
    return None

def show(f, full=False):
    print("== func 0x%x-0x%x  (size %d)" % (f["start"], f["end"], f["end"] - f["start"]))
    imps = []
    for r, m, n in f["imports"]:
        if n not in imps:
            imps.append(n)
    print("   imports:", ", ".join(i.split("!")[1] for i in imps))
    for r, t, k, s in f["strings"]:
        print("   str @%x -> %x %s %r" % (r, t, k, s[:150]))
    if full:
        print("   calls:", " ".join("%x" % c for _, c in f["calls"]))
        for r, m, t in f["data_refs"][:60]:
            print("   data @%x %s -> %x" % (r, m, t))

if cmd == "imp":
    rx = re.compile(arg, re.I)
    for s in sorted(F):
        f = F[s]
        if any(rx.search(n) for _, _, n in f["imports"]):
            show(f)
elif cmd == "str":
    rx = re.compile(arg, re.I)
    for s in sorted(F):
        f = F[s]
        if any(rx.search(x[3]) for x in f["strings"]):
            show(f)
elif cmd == "fn":
    f = containing(int(arg, 16))
    show(f, full=True) if f else print("not found")
elif cmd == "callers":
    t = int(arg, 16)
    for s in sorted(F):
        f = F[s]
        if any(c == t for _, c in f["calls"]):
            print("caller: 0x%x-0x%x" % (f["start"], f["end"]))
