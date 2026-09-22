package compass.dwarf

import compass.binfmt.Cursor
import compass.binfmt.DwarfParseException

/** Resolves DW_AT string values, including strx indices via .debug_str_offsets. */
class StringResolver(private val sections: DwarfSections, private val littleEndian: Boolean) {

    fun stringOf(cu: CompUnit, v: AttrValue): String? = when (v) {
        is AttrValue.Str -> v.v
        is AttrValue.StrRef -> when (v.section) {
            "debug_str" -> sections.stringAt(v.offset)
            "debug_line_str" -> sections.lineStringAt(v.offset)
            else -> null
        }
        is AttrValue.Strx -> {
            val headerBase = cu.root?.at(Dw.AT_str_offsets_base)?.asLong()
                ?: cu.root?.at(0x72)?.asLong()
            val base = v.base ?: headerBase
            if (base == null) null else {
                val off = readOffsetEntry(base + v.index * entrySize(cu))
                sections.stringAt(off)
            }
        }
        else -> null
    }

    private fun entrySize(cu: CompUnit) = if (cu.is64Bit) 8 else 4

    fun readOffsetEntry(absOff: Long): Long {
        val d = sections.strOffsets ?: sections.strOffsetsDwo ?: return -1L
        if (absOff < 0 || absOff >= d.size) return -1L
        val c = Cursor(d, absOff.toIntExact(), d.size, absOff.toIntExact(), littleEndian)
        return if (d.size - absOff.toIntExact() >= 8) c.u64() else c.u32()
    }

    /** Parse the str_offsets header and return absolute offset of index 0 entries. */
    fun strOffsetsBase(cu: CompUnit, rawBase: Long?): Long? {
        rawBase ?: return null
        val d = sections.strOffsets ?: sections.strOffsetsDwo ?: return null
        if (rawBase < 0 || rawBase >= d.size) return null
        val c = Cursor(d, rawBase.toIntExact(), d.size, rawBase.toIntExact(), littleEndian)
        return try {
            val (len, is64) = readInitialLen(c)
            c.u16(); c.u16() // version, padding
            c.u8() // offset size
            c.u8() // padding
            c.pos.toLong()
        } catch (_: Exception) {
            if (cu.version < 5) rawBase else null
        }.also { @Suppress("UNUSED_EXPRESSION") it }
    }

    private fun readInitialLen(c: Cursor): Pair<Long, Boolean> {
        val first = c.u32()
        if (first == 0xffffffffL) return c.u64() to true
        return first to false
    }
}

private fun Long.toIntExact(): Int {
    if (this < 0 || this > Int.MAX_VALUE) throw DwarfParseException("offset out of range: $this")
    return toInt()
}
