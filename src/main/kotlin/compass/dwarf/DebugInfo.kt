package compass.dwarf

/** All debug-relevant sections of one imported file. Any may be missing. */
class DebugSections(
    val info: ByteArray? = null,
    val abbrev: ByteArray? = null,
    val line: ByteArray? = null,
    val str: ByteArray? = null,
    val lineStr: ByteArray? = null,
    val ranges: ByteArray? = null,
    val rnglists: ByteArray? = null,
    val addr: ByteArray? = null,
    val strOffsets: ByteArray? = null,
    val littleEndian: Boolean = true
) {
    fun missingRequired(): List<String> {
        val out = ArrayList<String>()
        if (info == null) out.add(".debug_info")
        if (abbrev == null) out.add(".debug_abbrev")
        if (line == null) out.add(".debug_line")
        return out
    }
}

data class CuHeader(
    val offset: Long,
    val length: Long,
    val version: Int,
    val unitType: Int,
    val addrSize: Int,
    val isDwarf64: Boolean,
    val abbrevOffset: Long
) {
    val endOffset: Long get() = offset + length + (if (isDwarf64) 12 else 4)
}

data class DieNode(
    val offset: Long,
    val depth: Int,
    val tag: Int,
    val attrs: Map<Int, AttrValue>,
    val children: MutableList<DieNode> = mutableListOf()
)

data class CuParseResult(
    val header: CuHeader,
    val roots: List<DieNode>,
    val degraded: Boolean,
    val diagnostics: List<String>
)

object DebugInfo {
    const val MAX_DEPTH = 64
    const val MAX_DIES_PER_CU = 50_000
    const val MAX_CUS = 20_000

    fun parseCus(sections: DebugSections): List<CuParseResult> {
        val info = sections.info ?: return emptyList()
        val out = ArrayList<CuParseResult>()
        var pos = 0
        val r = Reader(info, 0, info.size, sections.littleEndian)
        while (r.remaining() >= 4) {
            if (out.size >= MAX_CUS) throw LimitExceededException("too many compilation units")
            val cuStart = r.pos
            val diagnostics = ArrayList<String>()
            try {
                out.add(parseOneCu(r, cuStart, sections, diagnostics))
            } catch (e: DwarfParseException) {
                diagnostics.add("CU at 0x${cuStart.toString(16)} isolated: ${e.message}")
                // Resynchronize: if we at least read the unit length, jump to its end.
                val rescued = resync(info, cuStart, sections.littleEndian)
                if (rescued != null) {
                    out.add(
                        CuParseResult(rescued, emptyList(), true, diagnostics)
                    )
                    r.pos = rescued.endOffset.toInt()
                } else {
                    out.add(
                        CuParseResult(
                            CuHeader(cuStart.toLong(), 0, 0, 0, 8, false, 0),
                            emptyList(), true, diagnostics
                        )
                    )
                    break
                }
            }
        }
        return out
    }

    /** Re-read only the CU header so the cursor can jump to the next CU safely. */
    private fun resync(info: ByteArray, cuStart: Int, littleEndian: Boolean): CuHeader? {
        return try {
            val r = Reader(info, cuStart, info.size, littleEndian)
            readUnitLength(r, cuStart).first
        } catch (e: DwarfParseException) {
            null
        }
    }

    private fun readUnitLength(r: Reader, cuStart: Int): Pair<CuHeader, Boolean> {
        var unitLen = r.u32()
        val dwarf64 = unitLen == 0xFFFF_FFFFL
        if (dwarf64) unitLen = r.u64()
        val headerSize = if (dwarf64) 12 else 4
        if (unitLen < 0 || cuStart + headerSize + unitLen > r.limit) {
            throw DwarfParseException("CU length $unitLen out of bounds at 0x${cuStart.toString(16)}")
        }
        return CuHeader(cuStart.toLong(), unitLen, 0, 0, 8, dwarf64, 0) to dwarf64
    }

    private fun parseOneCu(
        r: Reader,
        cuStart: Int,
        sections: DebugSections,
        diagnostics: MutableList<String>
    ): CuParseResult {
        val info = sections.info!!
        var unitLen = r.u32()
        val dwarf64 = unitLen == 0xFFFF_FFFFL
        if (dwarf64) unitLen = r.u64()
        val headerSize = if (dwarf64) 12 else 4
        if (unitLen < 0 || cuStart + headerSize + unitLen > info.size) {
            throw DwarfParseException("CU length $unitLen out of bounds at 0x${cuStart.toString(16)}")
        }
        val cuEnd = cuStart + headerSize + unitLen.toInt()
        val version = r.u16()
        if (version < 2 || version > 5) throw DwarfParseException("unsupported DWARF version $version")
        var unitType = Dw.UT_compile
        var addrSize = 8
        var abbrevOffset: Long
        if (version >= 5) {
            unitType = r.u8()
            addrSize = r.u8()
            abbrevOffset = if (dwarf64) r.u64() else r.u32()
        } else {
            abbrevOffset = if (dwarf64) r.u64() else r.u32()
            addrSize = r.u8()
        }
        if (addrSize != 4 && addrSize != 8) {
            diagnostics.add("unusual address size $addrSize; parsing continues")
        }
        val header = CuHeader(cuStart.toLong(), unitLen, version, unitType, addrSize, dwarf64, abbrevOffset)
        val abbrevSection = sections.abbrev
            ?: throw DwarfParseException("missing .debug_abbrev")
        val table = AbbrevTable.parse(abbrevSection, abbrevOffset, sections.littleEndian)
        val ctx = FormContext(addrSize, dwarf64, version)

        val roots = ArrayList<DieNode>()
        val stack = ArrayList<DieNode>()
        var dieCount = 0
        var degraded = false
        try {
            while (r.pos < cuEnd) {
                if (dieCount >= MAX_DIES_PER_CU) throw LimitExceededException("too many DIEs in CU")
                val dieOffset = r.pos.toLong()
                val code = r.uleb()
                if (code == 0L) {
                    if (stack.isNotEmpty()) stack.removeAt(stack.size - 1)
                    continue
                }
                val abbrev = table.lookup(code)
                    ?: throw DwarfParseException("abbrev code $code not found at 0x${dieOffset.toString(16)}")
                val depth = stack.size
                if (depth >= MAX_DEPTH) throw LimitExceededException("DIE nesting deeper than $MAX_DEPTH")
                val attrs = LinkedHashMap<Int, AttrValue>()
                for (aa in abbrev.attrs) {
                    var v = Forms.read(r, aa.form, ctx, Dw.atName(aa.attr))
                    if (aa.implicitConst != null) v = AttrValue.SInt(aa.implicitConst)
                    attrs[aa.attr] = v
                }
                dieCount++
                val node = DieNode(dieOffset, depth, abbrev.tag, attrs)
                if (stack.isEmpty()) roots.add(node) else stack.last().children.add(node)
                if (abbrev.hasChildren) stack.add(node)
            }
        } catch (e: UnknownFormException) {
            diagnostics.add("unknown form isolated: ${e.message}; CU partially parsed")
            degraded = true
        } catch (e: LimitExceededException) {
            diagnostics.add("limit hit: ${e.message}; CU partially parsed")
            degraded = true
        }
        return CuParseResult(header, roots, degraded, diagnostics)
    }
}
