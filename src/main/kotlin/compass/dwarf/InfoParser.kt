package compass.dwarf

import compass.elf.BinaryTruncatedException
import compass.elf.Reader
import compass.model.Endian

data class CuHeader(
    val offset: Long,
    val bodyEnd: Int,
    val version: Int,
    val unitType: Int,
    val dwarf64: Boolean,
    val addrSize: Int,
    val abbrevOffset: Long,
) {
    val isTypeUnit: Boolean get() = version >= 5 && (unitType == 2 || unitType == 5)
}

class RawDie(
    val offset: Long,
    val tag: Int,
    val depth: Int,
    val parentOffset: Long?,
    val attrs: Map<Int, FormValue>,
)

class ParsedUnit(val header: CuHeader, val dies: List<RawDie>)

object InfoParser {

    const val MAX_DIE_DEPTH = 256

    fun parseSection(
        data: ByteArray,
        endian: Endian,
        sections: DebugSections,
        abbrevs: AbbrevTables,
        isSplit: Boolean,
        warnings: MutableList<String>,
    ): List<ParsedUnit> {
        if (data.isEmpty()) return emptyList()
        val r = Reader(data, endian)
        val units = ArrayList<ParsedUnit>()
        var guard = 0
        while (r.remaining() > 0) {
            if (guard++ > 100_000) throw BinaryTruncatedException("CU count guard")
            val unitStart = r.pos
            val unit = r.initialLength()
            val version = r.u16()
            if (version !in 2..5) throw BadDieStream("unsupported DWARF version $version")
            val unitType: Int
            val addrSize: Int
            val abbrevOffset: Long
            val dwarf64 = unit.dwarf64
            val ptrCtx = FormContext(endian, version, dwarf64, 8, unitStart.toLong(),
                abbrevs, sections, 0L, 0L, isSplit, warnings)
            if (version >= 5) {
                unitType = r.u8()
                addrSize = r.u8()
                abbrevOffset = Forms.readSectionPtr(r, ptrCtx.copy(addrSize = addrSize))
                if (unitType == 2 || unitType == 5) {
                    r.u64()
                    Forms.readSectionPtr(r, ptrCtx.copy(addrSize = addrSize))
                }
            } else {
                unitType = 1
                abbrevOffset = if (dwarf64) r.u64() else r.u32()
                addrSize = r.u8()
            }

            if (version >= 5 && (unitType == 2 || unitType == 5)) {
                r.seek(unit.end)
                continue
            }

            val cuOffset = unitStart.toLong()
            try {
                val dies = parseDies(r, endian, sections, abbrevs, isSplit, version,
                    dwarf64, addrSize, abbrevOffset, cuOffset, warnings)
                units.add(ParsedUnit(CuHeader(cuOffset, unit.end, version, unitType,
                    dwarf64, addrSize, abbrevOffset), dies))
            } catch (e: Exception) {
                warnings.add(
                    "CU@0x${"%x".format(cuOffset)} 解析失败（${e.message ?: e.javaClass.simpleName}）；" +
                        "该 CU 的 DIE/范围结论不可信，已按单元长度精确跳到下一个 CU，不影响其它 CU"
                )
            }
            r.seek(unit.end)
        }
        return units
    }

    private fun parseDies(
        r: Reader,
        endian: Endian,
        sections: DebugSections,
        abbrevs: AbbrevTables,
        isSplit: Boolean,
        version: Int,
        dwarf64: Boolean,
        addrSize: Int,
        abbrevOffset: Long,
        cuOffset: Long,
        warnings: MutableList<String>,
    ): List<RawDie> {
        val table = abbrevs.tableAt(abbrevOffset)

        // Pass 1: root DIE, discover .debug_str_offsets / .debug_addr bases.
        val rootStart = r.pos
        val rootCode = r.uleb128()
        val rootAbbrev = table[rootCode] ?: throw BadDieStream("root abbrev code $rootCode missing")
        var strBase = 0L
        var addrBase = 0L
        val probe = FormContext(endian, version, dwarf64, addrSize, cuOffset, abbrevs,
            sections, 0L, 0L, isSplit, warnings)
        for (a in rootAbbrev.attrs) {
            val v = Forms.read(a.form, a.implicitConst, r, probe)
            when (a.attr) {
                DW.AT_str_offsets_base, DW.AT_GNU_str_offsets_base ->
                    if (v is FormValue.Offset) strBase = v.v
                DW.AT_addr_base, DW.AT_GNU_addr_base ->
                    if (v is FormValue.Offset) addrBase = v.v
            }
        }

        // Pass 2: walk the whole DIE tree.
        r.seek(rootStart)
        val ctx = FormContext(endian, version, dwarf64, addrSize, cuOffset, abbrevs,
            sections, strBase, addrBase, isSplit, warnings)
        val out = ArrayList<RawDie>()
        val stack = ArrayDeque<Pair<Long, Boolean>>() // offset, hasChildren
        var depth = 0

        while (r.remaining() > 0) {
            val dieStart = r.pos
            val code = r.uleb128()
            if (code == 0L) {
                if (stack.isEmpty()) break
                stack.removeLast()
                depth--
                if (depth < 0) break
                continue
            }
            val ab = table[code] ?: throw BadDieStream("abbrev code $code missing")
            if (depth > MAX_DIE_DEPTH) throw BadDieStream("DIE nesting exceeds $MAX_DIE_DEPTH")
            val attrs = LinkedHashMap<Int, FormValue>()
            for (a in ab.attrs) {
                val raw = Forms.read(a.form, a.implicitConst, r, ctx)
                val v: FormValue = when (raw) {
                    is FormValue.StrIndex ->
                        FormValue.Text(StrOffsets.resolve(sections, endian, strBase, raw.index, dwarf64))
                    is FormValue.AddrIndex ->
                        FormValue.Address(AddrTable.readAddress(sections, endian, addrBase, raw.index, addrSize))
                    else -> raw
                }
                attrs[a.attr] = v
            }
            out.add(RawDie(dieStart.toLong(), ab.tag, depth, stack.lastOrNull()?.first, attrs))
            if (ab.hasChildren) {
                stack.addLast(dieStart.toLong() to true)
                depth++
            } else if (depth == 0) {
                break
            }
        }
        return out
    }
}

class BadDieStream(message: String) : RuntimeException(message)
