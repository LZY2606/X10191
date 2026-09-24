package luopan.dwarf

/**
 * 原始 DIE：
 * - offset: 在 .debug_info 中的全局偏移（供引用解析）
 * 解析采取两遍：先在严格边界内读完整棵 CU 树；任一未知 form 或越界，
 * 整个 CU 标记 parseError 并隔离（绝不基于半棵树产出地址结论）。
 */
class RawDie(
    val offset: Long,
    val tag: Int,
    val attrs: Map<Int, FormValue>,
    val hasChildren: Boolean,
    val children: MutableList<RawDie> = ArrayList(),
    var parent: RawDie? = null
)

data class ParsedUnit(
    val header: UnitHeader,
    val root: RawDie?,
    val parseError: String?
)

data class UnitHeader(
    val version: Int,
    val unitType: Int,
    val addressSize: Int,
    val dwarf64: Boolean,
    val abbrevOffset: Long,
    val startOffset: Long,
    val nextOffset: Long,
    val dwoId: Long?
)

class InfoParser(private val sections: DebugSections) {

    fun parseAllUnits(maxUnits: Int = 100_000): List<ParsedUnit> {
        val mainInfo = sections.bytes(".debug_info")
        val data = mainInfo ?: sections.bytes(".debug_info.dwo") ?: return emptyList()
        val r = ByteReader.of(data, sections.littleEndian)
        val units = ArrayList<ParsedUnit>()
        var guard = 0
        while (r.pos < r.size) {
            if (++guard > maxUnits) break
            val start = r.pos.toLong()
            try {
                val (unitLength, contentStart, dwarf64) = r.initialLength()
                val nextOffset = contentStart + unitLength
                if (nextOffset > r.size) throw DwarfBoundsException("CU extends beyond .debug_info")
                val version = r.u16()
                if (version !in 2..5) throw DwarfFormatException("unsupported CU version $version")
                var unitType = DwTag.COMPILE_UNIT
                var addressSize = 4
                var abbrevOffset: Long
                var dwoId: Long? = null
                if (version >= 5) {
                    unitType = r.u8()
                    addressSize = r.u8()
                    abbrevOffset = readOffsetRef(r, dwarf64)
                    if (unitType == DwTag.SKELETON_UNIT || unitType == DwTag.SPLIT_COMPILE_UNIT) {
                        dwoId = r.u64()
                    }
                } else {
                    abbrevOffset = readOffsetRef(r, dwarf64)
                    addressSize = r.u8()
                }
                val header = UnitHeader(
                    version, unitType, addressSize, dwarf64,
                    abbrevOffset, start, nextOffset.toLong(), dwoId
                )
                val abbrevSection = if (mainInfo != null)
                    sections.bytes(".debug_abbrev") else sections.bytes(".debug_abbrev.dwo")
                val abbrev = AbbrevParser.parse(abbrevSection, abbrevOffset)
                val root = readDieTree(r, header, abbrev, nextOffset)
                units += ParsedUnit(header, root, null)
                r.seek(nextOffset)
            } catch (e: Exception) {
                when (e) {
                    is DwarfBoundsException, is DwarfFormatException, is UnsupportedFormException -> {
                        units += ParsedUnit(
                            UnitHeader(0, 0, 4, false, 0, start, r.size.toLong(), null),
                            null, "CU@$start: ${e.message}"
                        )
                        break
                    }
                    else -> throw e
                }
            }
        }
        return units
    }

    private fun readOffsetRef(r: ByteReader, dwarf64: Boolean): Long =
        if (dwarf64) r.u64() else r.u32()

    private val dieDepthLimit = 256

    private fun readDieTree(
        r: ByteReader, h: UnitHeader, abbrev: AbbrevTable, endOffset: Int
    ): RawDie? {
        var first: RawDie? = null
        var current: RawDie? = null
        var depth = 0

        while (r.pos < endOffset) {
            val dieOffset = r.pos.toLong()
            val (code, _) = r.uleb128()
            if (code == 0L) {
                if (depth == 0) throw DwarfFormatException("unexpected null DIE at root")
                depth--
                current = current?.parent
                continue
            }
            val ab = abbrev.get(code)
                ?: throw DwarfFormatException("unknown abbrev code $code at $dieOffset")
            val attrs = LinkedHashMap<Int, FormValue>()
            for (a in ab.attrs) {
                attrs[a.attr] = FormReader(r, h.addressSize, h.dwarf64, a.implicitConst).read(a.form)
            }
            val die = RawDie(dieOffset, ab.tag, attrs, ab.hasChildren)
            if (first == null) first = die
            die.parent = current
            current?.children?.add(die)
            if (ab.hasChildren) {
                depth++
                if (depth > dieDepthLimit) throw DwarfFormatException("DIE nesting too deep")
                current = die
            }
        }
        if (depth != 0) throw DwarfFormatException("DIE tree not terminated within CU")
        return first
    }
}
