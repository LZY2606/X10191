package compass.dwarf

import compass.elf.ElfFile

/** All debug sections needed for one import, optionally accompanied by a split (dwo/dwp) file. */
class SectionBundle(
    val elf: ElfFile,
    val split: ElfFile? = null,
    val splitNameResolved: Boolean = split != null
) {
    val le: Boolean get() = elf.littleEndian
    val addrSize: Int get() = elf.addressSize

    fun section(name: String, allowSplit: Boolean = false): ByteArray? {
        elf.sectionBytes(name)?.let { return it }
        if (allowSplit && split != null) split.sectionBytes(name)?.let { return it }
        return null
    }

    fun reader(name: String, allowSplit: Boolean = false, offsetSize: Int = 4): SectionReader? =
        section(name, allowSplit)?.let {
            SectionReader(it, name, if (allowSplit) (split?.littleEndian ?: le) else le, 0, offsetSize)
        }

    /** Read a section choosing main or split depending on where bytes live. */
    fun bytesFromAny(name: String): Pair<ByteArray, Boolean>? {
        elf.sectionBytes(name)?.let { return it to false }
        split?.sectionBytes(name)?.let { return it to true }
        return null
    }
}

data class AttrSpec(val name: Int, val form: Int, val implicitConst: Long? = null)

data class AbbrevDecl(val code: Long, val tag: Int, val hasChildren: Boolean, val attrs: List<AttrSpec>)

class AbbrevTables(private val tables: Map<Long, List<AbbrevDecl>>) {
    fun tableAt(offset: Long): List<AbbrevDecl>? = tables[offset]
    val offsets: Set<Long> get() = tables.keys
}

object AbbrevParser {
    fun parse(data: ByteArray?, le: Boolean, diagnostics: MutableList<ParseDiagnostic>): AbbrevTables {
        if (data == null) return AbbrevTables(emptyMap())
        val r = SectionReader(data, ".debug_abbrev", le)
        val tables = LinkedHashMap<Long, MutableList<AbbrevDecl>>()
        try {
            while (r.pos < r.size) {
                val tableStart = r.pos.toLong()
                val decls = mutableListOf<AbbrevDecl>()
                while (true) {
                    val code = r.uleb()
                    if (code == 0L) break
                    val tag = r.uleb().toInt()
                    val hasChildren = r.u8() == 1
                    val attrs = mutableListOf<AttrSpec>()
                    while (true) {
                        val attr = r.uleb().toInt()
                        val form = r.uleb().toInt()
                        if (attr == 0 && form == 0) break
                        val implicit = if (form == DW_FORM.IMPLICIT_CONST) r.sleb() else null
                        attrs.add(AttrSpec(attr, form, implicit))
                    }
                    decls.add(AbbrevDecl(code, tag, hasChildren, attrs))
                }
                tables[tableStart] = decls
            }
        } catch (e: DwarfBoundsException) {
            diagnostics.add(ParseDiagnostic("WARNING", "ABBREV_TRUNCATED", e.message ?: "abbrev 表截断", ".debug_abbrev", r.pos.toLong()))
        }
        return AbbrevTables(tables)
    }
}
