package compass.dwarf

import compass.elf.ByteReader
import compass.elf.ElfFile

data class AbbrevAttr(val attr: Int, val form: Int, val implicitConst: Long)
data class Abbreviation(val code: ULong, val tag: Int, val hasChildren: Boolean, val attrs: List<AbbrevAttr>)

class AbbrevTable(val data: ByteArray, val bigEndian: Boolean) {
    private val byOffset = HashMap<Int, Map<ULong, Abbreviation>>()

    fun tableAt(offset: Int): Map<ULong, Abbreviation> = byOffset.getOrPut(offset) { parse(offset) }

    private fun parse(start: Int): Map<ULong, Abbreviation> {
        val r = ByteReader(data, bigEndian, ".debug_abbrev")
        r.seek(start)
        val out = HashMap<ULong, Abbreviation>()
        var guard = 0
        while (r.remaining() > 0 && guard++ < 1_000_000) {
            val code = r.uleb128()
            if (code == 0UL) break
            val tag = r.uleb128().toInt()
            val hasChildren = r.u8() == 1
            val attrs = ArrayList<AbbrevAttr>()
            var aguard = 0
            while (aguard++ < 100_000) {
                val attr = r.uleb128().toInt()
                val form = r.uleb128().toInt()
                if (attr == 0 && form == 0) break
                val implicit = if (form == DW.FORM_IMPLICIT_CONST) r.sleb128() else 0L
                attrs.add(AbbrevAttr(attr, form, implicit))
            }
            out[code] = Abbreviation(code, tag, hasChildren, attrs)
        }
        return out
    }
}

/** All DWARF sections extracted from an ELF (executable or separate debug file). Missing = null. */
class DebugBundle(val elf: ElfFile) {
    val info: ByteArray? = elf.section(".debug_info")?.bytes
    val abbrev: ByteArray? = elf.section(".debug_abbrev")?.bytes
    val line: ByteArray? = elf.section(".debug_line")?.bytes
    val valLineStr: ByteArray? = elf.section(".debug_line_str")?.bytes
    val str: ByteArray? = elf.section(".debug_str")?.bytes
    val strOffsets: ByteArray? = elf.section(".debug_str_offsets")?.bytes
    val ranges: ByteArray? = elf.section(".debug_ranges")?.bytes
    val rnglists: ByteArray? = elf.section(".debug_rnglists")?.bytes
    val addr: ByteArray? = elf.section(".debug_addr")?.bytes
    val infoDwo: ByteArray? = elf.section(".debug_info.dwo")?.bytes
    val abbrevDwo: ByteArray? = elf.section(".debug_abbrev.dwo")?.bytes
    val strDwo: ByteArray? = elf.section(".debug_str.dwo")?.bytes
    val strOffsetsDwo: ByteArray? = elf.section(".debug_str_offsets.dwo")?.bytes
    val lineDwo: ByteArray? = elf.section(".debug_line.dwo")?.bytes
    val lineStrDwo: ByteArray? = elf.section(".debug_line_str.dwo")?.bytes
    val rnglistsDwo: ByteArray? = elf.section(".debug_rnglists.dwo")?.bytes

    val abbrevTable: AbbrevTable? = abbrev?.let { AbbrevTable(it, elf.bigEndian) }
    val abbrevDwoTable: AbbrevTable? = abbrevDwo?.let { AbbrevTable(it, elf.bigEndian) }

    val sectionHashes: Map<String, String> = buildMap {
        listOf(
            ".debug_info", ".debug_abbrev", ".debug_line", ".debug_line_str", ".debug_str",
            ".debug_str_offsets", ".debug_ranges", ".debug_rnglists", ".debug_addr",
            ".debug_info.dwo", ".debug_abbrev.dwo", ".debug_str.dwo", ".debug_str_offsets.dwo",
            ".debug_line.dwo", ".debug_line_str.dwo", ".debug_rnglists.dwo"
        ).forEach { name -> elf.sectionDigest(name)?.let { put(name, it) } }
    }

    fun reader(data: ByteArray, name: String) = ByteReader(data, elf.bigEndian, name)
}
