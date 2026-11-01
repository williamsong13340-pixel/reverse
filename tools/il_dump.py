"""Disassemble every method body of a .NET assembly to CIL with resolved tokens (strings, fields, methods, types)."""
import sys
import dnfile
from dnfile.enums import MetadataTables
from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBase
from dncil.cil.error import MethodBodyFormatError
from dncil.clr.token import Token, StringToken, InvalidToken

path = sys.argv[1]
pe = dnfile.dnPE(path)
md = pe.net.mdtables


class Reader(CilMethodBodyReaderBase):
    def __init__(self, pe, rva):
        self.pe = pe
        self.offset = pe.get_offset_from_rva(rva)

    def read(self, n):
        data = self.pe.get_data(self.pe.get_rva_from_offset(self.offset), n)
        self.offset += n
        return data

    def tell(self):
        return self.offset

    def seek(self, off):
        self.offset = off
        return self.offset


def type_name(row):
    if row is None:
        return "?"
    ns = getattr(row, "TypeNamespace", "") or ""
    nm = getattr(row, "TypeName", None) or getattr(row, "Name", "?")
    return ("%s.%s" % (ns, nm)) if ns else str(nm)


typedef_of_method = {}
typedef_of_field = {}
for ti, t in enumerate(md.TypeDef or [], 1):
    for mi in t.MethodList:
        typedef_of_method[mi.row_index] = type_name(t)
    for fi in t.FieldList:
        typedef_of_field[fi.row_index] = type_name(t)


def resolve(tok):
    if isinstance(tok, StringToken):
        try:
            us = pe.net.user_strings.get(tok.rid)
            return repr(us.value if hasattr(us, "value") else us)
        except Exception:
            return "<string 0x%x>" % tok.rid
    if isinstance(tok, InvalidToken):
        return "<invalid>"
    table = tok.table
    rid = tok.rid
    try:
        if table == MetadataTables.MethodDef.value:
            m = md.MethodDef[rid - 1]
            return "%s::%s" % (typedef_of_method.get(rid, "?"), m.Name)
        if table == MetadataTables.MemberRef.value:
            m = md.MemberRef[rid - 1]
            cls = m.Class.row
            if cls is not None and hasattr(cls, "Signature") and not hasattr(cls, "TypeName"):
                cname = "TypeSpec"
            else:
                cname = type_name(cls)
            return "%s::%s" % (cname, m.Name)
        if table == MetadataTables.Field.value:
            f = md.Field[rid - 1]
            return "%s::%s" % (typedef_of_field.get(rid, "?"), f.Name)
        if table == MetadataTables.TypeRef.value:
            return type_name(md.TypeRef[rid - 1])
        if table == MetadataTables.TypeDef.value:
            return type_name(md.TypeDef[rid - 1])
        if table == MetadataTables.MethodSpec.value:
            ms = md.MethodSpec[rid - 1]
            inner = ms.Method
            return "MethodSpec(%s)" % resolve(Token(inner.table.number << 24 | inner.row_index) if hasattr(inner, "table") and inner.table is not None else tok)
        if table == MetadataTables.TypeSpec.value:
            return "TypeSpec#%d" % rid
        if table == MetadataTables.StandAloneSig.value:
            return "Sig#%d" % rid
    except Exception as e:
        return "<tok 0x%08x err %s>" % (tok.value, e)
    return "<tok 0x%08x>" % tok.value


for rid, m in enumerate(md.MethodDef or [], 1):
    owner = typedef_of_method.get(rid, "?")
    print("\n.method %s::%s  (rid=%d rva=0x%x)" % (owner, m.Name, rid, m.Rva))
    if not m.Rva:
        print("    // no body (abstract / pinvoke / runtime)")
        continue
    try:
        body = CilMethodBody(Reader(pe, m.Rva))
    except MethodBodyFormatError as e:
        print("    // body format error", e)
        continue
    for insn in body.instructions:
        operand = ""
        if isinstance(insn.operand, Token):
            operand = resolve(insn.operand)
        elif insn.operand is not None:
            operand = str(insn.operand)
        print("    IL_%04x: %-12s %s" % (insn.offset, insn.opcode.name, operand))
