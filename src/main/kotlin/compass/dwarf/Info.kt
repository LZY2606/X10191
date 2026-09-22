package compass.dwarf

const val MAX_DIE_DEPTH = 64
const val MAX_DIES_PER_CU = 200_000

data class AbbrevAttr(val attr: Long, val form: Long, val implicitConst: Long?)
data class Abbrev(val code: Long, val tag: Long, val hasChildren: Boolean, val attrs: List<AbbrevAttr>)

fun parseAbbrevTable(data: ByteArray, offset: Long, littleEndian: Boolean): Map<Long, Abbrev> {
    if (offset < 0 || offset >= data.size) throw DwarfParseException("abbrev offset $offset out of bounds")
    val c = Cursor(data, offset.toInt(), data.size, littleEndian)
    val map = LinkedHashMap<Long, Abbrev>()
    while (true) {
        val code = c.uleb()
        if (code == 0L) break
        val tag = c.uleb()
        val children = c.u8() != 0
        val attrs = mutableListOf<AbbrevAttr>()
        while (true) {
            val a = c.uleb()
            val f = c.uleb()
            if (a == 0L && f == 0L) break
            val ic = if (f == DW.FORM_IMPLICIT_CONST) c.sleb() else null
            attrs += AbbrevAttr(a, f, ic)
        }
        map[code] = Abbrev(code, tag, children, attrs)
    }
    return map
}

data class Die(
    val offset: Long,
    val tag: Long,
    val attrs: List<Attr>,
    val children: MutableList<Die> = mutableListOf(),
) {
    fun attr(name: Long): Attr? = attrs.firstOrNull { it.attr == name }
}

data class CuHeader(
    val cuStart: Long,
    val version: Int,
    val unitType: Int,
    val addrSize: Int,
    val abbrevOffset: Long,
    val dwarf64: Boolean,
    val contentStart: Long,
    val cuEnd: Long,
)

data class RawCu(val header: CuHeader, val root: Die?, val error: String?)

/** Parse all compilation units in a .debug_info section. A broken CU never
 *  shifts the cursor of the next one: boundaries come from unit_length. */
fun parseInfoSection(info: ByteArray, littleEndian: Boolean, abbrev: ByteArray?): List<RawCu> {
    val out = mutableListOf<RawCu>()
    val c = Cursor(info, 0, info.size, littleEndian)
    while (c.remaining >= 4) {
        val cuStart = c.pos.toLong()
        var dwarf64 = false
        var unitLength = c.u32()
        if (unitLength == 0xFFFFFFFFL) {
            dwarf64 = true
            unitLength = c.u64()
        }
        if (unitLength == 0L) break
        val cuEnd = cuStart + (if (dwarf64) 12 else 4) + unitLength
        if (cuEnd > info.size || c.remaining < 2) {
            out += RawCu(CuHeader(cuStart, -1, -1, 8, 0, dwarf64, c.pos.toLong(), cuEnd), null,
                "CU at 0x${cuStart.toString(16)} declares length past section end (truncated)")
            break
        }
        try {
            val version = c.u16()
            val unitType: Int
            val addrSize: Int
            val abbrevOffset: Long
            when (version) {
                5 -> {
                    unitType = c.u8()
                    addrSize = c.u8()
                    abbrevOffset = c.offset(dwarf64)
                }
                in 2..4 -> {
                    unitType = DW.UT_COMPILE
                    abbrevOffset = c.offset(dwarf64)
                    addrSize = c.u8()
                }
                else -> throw DwarfParseException("unsupported DWARF version $version")
            }
            val header = CuHeader(cuStart, version, unitType, addrSize, abbrevOffset, dwarf64, c.pos.toLong(), cuEnd)
            if (abbrev == null) {
                out += RawCu(header, null, "no .debug_abbrev section")
            } else {
                val abbrevs = parseAbbrevTable(abbrev, abbrevOffset, littleEndian)
                val reader = FormReader(addrSize, dwarf64, version, header.contentStart)
                val dieCursor = Cursor(info, c.pos, minOf(cuEnd.toInt(), info.size), littleEndian)
                val counter = IntArray(1)
                val root = parseDie(dieCursor, abbrevs, reader, 0, counter)
                out += RawCu(header, root, null)
            }
        } catch (e: UnknownFormException) {
            out += RawCu(CuHeader(cuStart, -1, -1, 8, 0, dwarf64, c.pos.toLong(), cuEnd), null,
                "isolated: ${e.message}; CU skipped, cursor resynchronized at next unit")
        } catch (e: DwarfParseException) {
            out += RawCu(CuHeader(cuStart, -1, -1, 8, 0, dwarf64, c.pos.toLong(), cuEnd), null,
                "isolated: ${e.message}")
        }
        // Resynchronize strictly on the declared unit boundary.
        c.pos = minOf(cuEnd.toInt(), info.size)
    }
    return out
}

private fun parseDie(
    c: Cursor,
    abbrevs: Map<Long, Abbrev>,
    reader: FormReader,
    depth: Int,
    counter: IntArray,
): Die? {
    val offset = c.pos.toLong()
    val code = c.uleb()
    if (code == 0L) return null
    if (++counter[0] > MAX_DIES_PER_CU) throw DwarfParseException("DIE count limit exceeded")
    if (depth > MAX_DIE_DEPTH) throw DwarfParseException("DIE nesting depth limit exceeded")
    val abbrev = abbrevs[code] ?: throw DwarfParseException("unknown abbrev code $code at 0x${offset.toString(16)}")
    val attrs = abbrev.attrs.map { aa ->
        Attr(aa.attr, aa.form, reader.read(c, aa.form, aa.implicitConst))
    }
    val die = Die(offset, abbrev.tag, attrs)
    if (abbrev.hasChildren) {
        while (true) {
            val child = parseDie(c, abbrevs, reader, depth + 1, counter) ?: break
            die.children += child
        }
    }
    return die
}
