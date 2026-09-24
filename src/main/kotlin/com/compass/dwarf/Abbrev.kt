package com.compass.dwarf

data class AbbrevAttribute(val attr: Int, val form: Int, val implicit: Long? = null)
data class AbbrevEntry(val code: Long, val tag: Int, val hasChildren: Boolean, val attributes: List<AbbrevAttribute>)

class AbbrevTable(private val section: BinaryCursor?) {
    private val cache = mutableMapOf<Long, Map<Long, AbbrevEntry>>()
    private val bad = mutableSetOf<Long>()

    fun read(offset: Long): Map<Long, AbbrevEntry>? {
        cache[offset]?.let { return it }
        if (offset in bad || section == null) return null
        return try {
            section.seek(offset, "debug_abbrev offset")
            val entries = mutableMapOf<Long, AbbrevEntry>()
            repeat(1_000_000) {
                val start = section.absolutePosition()
                val code = section.uleb()
                if (code == 0L) {
                    cache[offset] = entries
                    return entries
                }
                val tag = section.uleb().toInt()
                val hasChildren = section.u8() == 1
                val attrs = mutableListOf<AbbrevAttribute>()
                while (true) {
                    val attr = section.uleb().toInt()
                    val form = section.uleb().toInt()
                    if (attr == 0 && form == 0) break
                    val implicit = if (form == DwarfConst.DW_FORM_IMPLICIT_CONST) section.sleb() else null
                    attrs += AbbrevAttribute(attr, form, implicit)
                    if (attrs.size > 1000) throw DwarfParseException("Too many abbreviation attributes at $start")
                }
                entries[code] = AbbrevEntry(code, tag, hasChildren, attrs)
            }
            throw DwarfParseException("Abbreviation table too long")
        } catch (e: Exception) {
            bad += offset
            null
        }
    }
}
