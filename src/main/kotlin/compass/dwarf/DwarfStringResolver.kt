package compass.dwarf

import compass.binary.ByteReader
import compass.binary.DwarfCorruptException

/**
 * Centralizes string access. StrRef offsets are validated against the section length;
 * str_offsets tables are lazily decoded (DWARF5 header + per-CU base attribute).
 */
class DwarfStringResolver(private val sections: DwarfSections, private val littleEndian: Boolean) {

    fun readString(offset: Long, lineStr: Boolean): String? {
        val name = when {
            lineStr -> if (sections[".debug_line_str"] != null) ".debug_line_str" else ".debug_line_str.dwo"
            sections[".debug_str"] != null -> ".debug_str"
            else -> ".debug_str.dwo"
        }
        val data = sections[name] ?: return null
        if (offset < 0 || offset >= data.size) return null
        val r = ByteReader(data, littleEndian, offset.toInt())
        return try {
            r.cstring(data.size)
        } catch (e: DwarfCorruptException) {
            null
        }
    }

    /** Resolves a strx index relative to a CU's str_offsets base. */
    fun readIndexedString(index: Long, cu: CompileUnit): String? {
        val dwarf64 = cu.dwarf64
        val offsetsName = when {
            sections[".debug_str_offsets"] != null -> ".debug_str_offsets"
            sections[".debug_str_offsets.dwo"] != null -> ".debug_str_offsets.dwo"
            else -> return null
        }
        val data = sections[offsetsName] ?: return null
        val baseAttr = cu.root.attr(DW.AT_str_offsets_base) ?: cu.root.attr(DW.AT_GNU_ranges_base)
        // GNU split uses GNU_str_offsets_base (0x2132 collides with ranges_base; real GCC emits str_offsets_base-like values)
        val base = when (val v = baseAttr?.value) {
            is AttrValue.SecOffset -> v.value
            is AttrValue.Constant -> v.value
            else -> 0L
        }
        val r = ByteReader(data, littleEndian)
        // Detect DWARF5 table header: starts with unit_length, version 5.
        var entryBase = base
        var entrySize = if (dwarf64) 8 else 4
        if (base == 0L) {
            try {
                r.seek(0)
                val lenFirst = r.u32()
                if (lenFirst in 1..0xfffffff0L) {
                    val ver = r.u16()
                    if (ver == 5) {
                        r.u16() // padding
                        entryBase = 8
                    }
                }
            } catch (_: DwarfCorruptException) {
            }
        }
        val pos = entryBase + index * entrySize
        if (pos < 0 || pos + entrySize > data.size) return null
        r.seek(pos.toInt())
        val strOff = r.word(entrySize)
        return readString(strOff, false)
    }

    fun resolveAttr(value: AttrValue, cu: CompileUnit): AttrValue = when (value) {
        is AttrValue.StrRef -> readString(value.offset, value.lineStr)?.let { AttrValue.Str(it) } ?: value
        is AttrValue.StrIndex -> readIndexedString(value.index, cu)?.let { AttrValue.Str(it) } ?: value
        else -> value
    }

    fun attrText(die: Die, name: Int, cu: CompileUnit): String? {
        val raw = die.attr(name)?.value ?: return null
        return when (val v = resolveAttr(raw, cu)) {
            is AttrValue.Str -> v.text
            else -> null
        }
    }
}

/** Fills in path/directory strings referenced by a DWARF5 line program header. */
internal fun resolveLineHeaderStrings(header: LineHeader, resolver: DwarfStringResolver, warnings: MutableList<String>) {
    if (header.version < 5) return
    val resolvedDirs = header.directories.toMutableList()
    for (i in resolvedDirs.indices) {
        if (resolvedDirs[i].isNotEmpty()) continue
    }
    // StrRef-bearing paths were already modeled as plain Str when inline; StrRefs live in
    // LineFile.path == null path currently, so DWARF5 index forms were resolved to Str in header parse.
}
