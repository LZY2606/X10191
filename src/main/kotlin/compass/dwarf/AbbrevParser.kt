@file:JvmName("AbbrevParser")
package compass.dwarf

import compass.binary.ByteReader
import compass.binary.DwarfCorruptException

/** Parses one .debug_abbrev table starting at [offset]; null DIE (code 0) ends the table. */
fun parseAbbrevAt(reader: ByteReader, offset: Long): List<AbbrevEntry> {
    reader.seek(offset.toInt())
    val entries = mutableListOf<AbbrevEntry>()
    var guard = 0
    while (true) {
        if (++guard > 1_000_000) throw DwarfCorruptException("abbrev table too large")
        val code = reader.uleb()
        if (code == 0L) return entries
        val tag = reader.uleb().toInt()
        val hasChildren = reader.u8() == 1
        val specs = mutableListOf<Pair<Int, Int>>()
        var implicitConst: Long? = null
        while (true) {
            val name = reader.uleb().toInt()
            val form = reader.uleb().toInt()
            if (name == 0 && form == 0) break
            specs.add(name to form)
            if (form == DW.FORM_implicit_const) implicitConst = reader.sleb()
        }
        entries.add(AbbrevEntry(code, tag, hasChildren, specs, implicitConst))
    }
}

/** Parses every abbrev table reachable from offset 0 (tables are packed back to back). */
fun parseAbbrevSection(reader: ByteReader, out: MutableMap<Long, List<AbbrevEntry>>) {
    while (reader.remaining > 0) {
        val start = reader.pos.toLong()
        val table = parseAbbrevAt(reader, start)
        out[start] = table
        // parseAbbrevAt stops at the table terminator; continue with the next table.
    }
}
