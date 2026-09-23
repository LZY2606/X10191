package compass.dwarf

data class AttrSpec(val name: Int, val form: Int, val implicitConst: Long = 0)

data class AbbrevDecl(val code: Int, val tag: Int, val hasChildren: Boolean, val attrs: List<AttrSpec>)

object AbbrevParser {
    private const val MAX_DECLS = 4096
    private const val MAX_ATTRS = 256

    /** Parses the abbrev table at [offset] in .debug_abbrev. */
    fun parse(data: ByteArray, offset: Int, bigEndian: Boolean = false): Map<Int, AbbrevDecl> {
        if (offset < 0 || offset >= data.size && data.isNotEmpty()) throw DwarfException(".debug_abbrev: offset 0x${offset.toString(16)} out of bounds")
        val r = Reader(data, ".debug_abbrev", offset, bigEndian)
        val out = LinkedHashMap<Int, AbbrevDecl>()
        while (!r.eof()) {
            val code = r.uleb128()
            if (code == 0L) break
            if (out.size >= MAX_DECLS) throw DwarfException(".debug_abbrev: too many declarations")
            val tag = r.uleb128()
            if (tag > 0xFFFF) throw DwarfException(".debug_abbrev: implausible tag $tag")
            val hasChildren = r.u8() != 0
            val attrs = mutableListOf<AttrSpec>()
            while (true) {
                if (attrs.size >= MAX_ATTRS) throw DwarfException(".debug_abbrev: too many attributes")
                val name = r.uleb128()
                val form = r.uleb128()
                if (name == 0L && form == 0L) break
                if (form > 0xFFFF) throw DwarfException(".debug_abbrev: implausible form $form")
                val implicit = if (form.toInt() == Dw.FORM_implicit_const) r.sleb128() else 0
                attrs.add(AttrSpec(name.toInt(), form.toInt(), implicit))
            }
            out[code.toInt()] = AbbrevDecl(code.toInt(), tag.toInt(), hasChildren, attrs)
        }
        return out
    }
}
