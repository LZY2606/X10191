package compass.dwarf

import compass.elf.Reader
import compass.elf.Truncated
import compass.model.AddressRange
import compass.model.CompilationUnit
import compass.model.DieNode
import compass.model.ParseIssue

object InfoParser {
    class Result(
        val units: List<CompilationUnit>,
        val dies: List<DieNode>,
        val issues: List<ParseIssue>,
        /** die offset (absolute in .debug_info) -> DieNode, for reference resolution */
        val dieByOffset: Map<Long, DieNode>,
        val cuByIndex: Map<Int, Long>, // cu index -> cu header offset
    )

    fun parse(info: ByteArray, sections: DwarfSections): Result {
        val issues = ArrayList<ParseIssue>()
        val units = ArrayList<CompilationUnit>()
        val dies = ArrayList<DieNode>()
        val dieByOffset = HashMap<Long, DieNode>()
        val cuByIndex = HashMap<Int, Long>()
        val bigEndian = sections.bigEndian

        var pos = 0
        var cuIndex = 0
        while (pos < info.size) {
            val cuOffset = pos
            try {
                val r = Reader(info, pos, info.size, bigEndian)
                var len = r.u32()
                val dwarf64 = len == 0xFFFFFFFFL
                if (dwarf64) len = r.u64()
                if (len == 0L) { pos += 4; continue }
                val unitEnd = (r.pos + len).toInt()
                if (unitEnd > info.size) throw Truncated("CU at $cuOffset end $unitEnd beyond .debug_info size ${info.size}")
                val version = r.u16()
                var unitType = UnitType.COMPILE
                var addrSize = 8
                var abbrevOff: Long
                if (version >= 5) {
                    unitType = r.u8()
                    addrSize = r.u8()
                    abbrevOff = if (dwarf64) r.u64() else r.u32()
                } else {
                    abbrevOff = if (dwarf64) r.u64() else r.u32()
                    addrSize = r.u8()
                }
                val abbrevData = sections.abbrev
                    ?: throw BadReference(".debug_abbrev missing; cannot decode CU at $cuOffset")
                val abbrevs = AbbrevTable.parse(abbrevData, abbrevOff.toInt(), bigEndian)

                // First pass: read the CU DIE attributes to learn table bases.
                val ctx = FormCtx(version, addrSize, dwarf64, sections = sections)
                val dieStart = r.pos
                val (cuDie, cuAttrs, childrenFollow) = readDie(r, dieStart, abbrevs, ctx, cuOffset)
                var name: String? = null
                var compDir: String? = null
                var producer: String? = null
                var dwoName: String? = null
                var stmtList: Long? = null
                var lowPc: Long? = null
                var highPc: Long? = null
                var highPcIsAddr = false
                var rangesOff: Long? = null
                var rangesBase = 0L
                var addrBase = 0L
                var strOffBase = 0L
                if (cuDie != null) {
                    for ((attr, v) in cuAttrs) {
                        when (attr) {
                            At.NAME -> name = v.str ?: name
                            At.COMP_DIR -> compDir = v.str ?: compDir
                            At.PRODUCER -> producer = v.str ?: producer
                            At.DWO_NAME -> dwoName = v.str ?: dwoName
                            At.STMT_LIST -> stmtList = v.num
                            At.LOW_PC -> lowPc = v.num
                            At.HIGH_PC -> { highPc = v.num; highPcIsAddr = v.isAddressClass }
                            At.RANGES -> rangesOff = v.num
                            At.RNG_LISTS_BASE -> rangesBase = v.num
                            At.ADDR_BASE -> addrBase = v.num
                            At.STR_OFFSETS_BASE -> strOffBase = v.num
                        }
                    }
                }
                // Second pass: full DIE tree with resolved bases.
                val ctx2 = ctx.copy(addrBase = addrBase, strOffsetsBase = strOffBase)
                val r2 = Reader(info, dieStart, unitEnd, bigEndian)
                var depth = 0
                var dieCount = 0
                var cuBase = lowPc ?: 0L
                if (lowPc != null && highPc != null && !highPcIsAddr) {
                    // high_pc as constant: nothing to add to base; base stays low_pc
                }
                while (r2.pos < unitEnd) {
                    if (++dieCount > Limits.MAX_DIES_PER_CU) throw BadReference("CU at $cuOffset exceeds DIE limit")
                    val dieOff = r2.pos.toLong()
                    val code = r2.uleb128()
                    if (code == 0L) { if (depth > 0) depth--; continue }
                    if (depth > Limits.MAX_DIE_DEPTH) throw BadReference("DIE depth exceeds ${Limits.MAX_DIE_DEPTH} at offset $dieOff")
                    val def = abbrevs[code] ?: throw BadReference("abbrev code $code not found at offset $dieOff")
                    val attrs = LinkedHashMap<Long, AttrVal>()
                    for (a in def.attrs) {
                        var v = FormReader.read(r2, a.form, ctx2)
                        if (a.form == Form.IMPLICIT_CONST) v = AttrVal(a.form, num = a.implicitConst)
                        attrs[a.attr] = v
                    }
                    var dName: String? = null
                    var dLow: Long? = null
                    var dHigh: Long? = null
                    var dHighIsAddr = false
                    var dRanges: Long? = null
                    var dRangesIsIndex = false
                    var callFile: Long? = null
                    var callLine: Long? = null
                    var callCol: Long? = null
                    var absOrigin: Long? = null
                    var spec: Long? = null
                    for ((attr, v) in attrs) {
                        when (attr) {
                            At.NAME -> dName = v.str
                            At.LOW_PC -> dLow = v.num
                            At.HIGH_PC -> { dHigh = v.num; dHighIsAddr = v.isAddressClass }
                            At.RANGES -> { dRanges = v.num; dRangesIsIndex = v.form == Form.RNGLISTX }
                            At.CALL_FILE -> callFile = v.num
                            At.CALL_LINE -> callLine = v.num
                            At.CALL_COLUMN -> callCol = v.num
                            At.ABSTRACT_ORIGIN -> absOrigin = v.num
                            At.SPECIFICATION -> spec = v.num
                        }
                    }
                    val ranges = resolveRanges(dLow, dHigh, dHighIsAddr, dRanges, dRangesIsIndex,
                        cuBase, addrSize, version, rangesBase, sections, issues, dieOff)
                    val node = DieNode(cuIndex, dieOff, depth, def.tag, dName, dLow, dHigh, dHighIsAddr,
                        ranges, callFile, callLine, callCol, absOrigin, spec)
                    dies.add(node)
                    dieByOffset[dieOff] = node // absolute offset in .debug_info
                    if (def.hasChildren) depth++
                }

                val status = when {
                    unitType == UnitType.SKELETON || unitType == UnitType.SPLIT_COMPILE -> "degraded"
                    else -> "ok"
                }
                if (unitType == UnitType.SKELETON || dwoName != null && sections.info != null && dwoMissing(sections)) {
                    issues.add(ParseIssue(".debug_info", cuOffset.toLong(), "warning",
                        "split DWARF unit (dwo=${dwoName ?: "?"}) without .dwo sections: line/inline data may be absent; ELF-level addresses remain trustworthy"))
                }
                units.add(CompilationUnit(cuIndex, cuOffset.toLong(), version, unitType, addrSize, dwarf64,
                    name, compDir, producer, dwoName, stmtList, lowPc, highPc, highPcIsAddr,
                    rangesOff, rangesBase, addrBase, strOffBase, status))
                cuByIndex[cuIndex] = cuOffset.toLong()
                cuIndex++
                pos = unitEnd
            } catch (e: UnknownForm) {
                issues.add(ParseIssue(".debug_info", cuOffset.toLong(), "error",
                    "isolated CU: ${e.message}; cursor cannot be trusted past this point, CU skipped"))
                units.add(CompilationUnit(cuIndex, cuOffset.toLong(), -1, -1, 0, false,
                    null, null, null, null, null, null, null, false, null, 0, 0, 0, "failed"))
                cuByIndex[cuIndex] = cuOffset.toLong()
                cuIndex++
                // Cannot know this CU's length reliably; stop the section walk to avoid phantom CUs.
                break
            } catch (e: Exception) {
                issues.add(ParseIssue(".debug_info", cuOffset.toLong(), "error",
                    "CU parse failed: ${e.message}"))
                units.add(CompilationUnit(cuIndex, cuOffset.toLong(), -1, -1, 0, false,
                    null, null, null, null, null, null, null, false, null, 0, 0, 0, "failed"))
                cuByIndex[cuIndex] = cuOffset.toLong()
                cuIndex++
                break
            }
        }
        return Result(units, dies, issues, dieByOffset, cuByIndex)
    }

    private fun dwoMissing(sections: DwarfSections): Boolean = true // main file never carries .dwo sections

    private fun readDie(
        r: Reader, at: Int, abbrevs: Map<Long, AbbrevDef>, ctx: FormCtx, cuOffset: Int,
    ): Triple<Long?, List<Pair<Long, AttrVal>>, Boolean> {
        val code = r.uleb128()
        if (code == 0L) return Triple(null, emptyList(), false)
        val def = abbrevs[code] ?: throw BadReference("abbrev code $code not found in CU at $cuOffset")
        val attrs = ArrayList<Pair<Long, AttrVal>>()
        for (a in def.attrs) {
            var v = FormReader.read(r, a.form, ctx)
            if (a.form == Form.IMPLICIT_CONST) v = AttrVal(a.form, num = a.implicitConst)
            attrs.add(a.attr to v)
        }
        return Triple(at.toLong(), attrs, def.hasChildren)
    }

    private fun resolveRanges(
        low: Long?, high: Long?, highIsAddr: Boolean,
        rangesOff: Long?, rangesIsIndex: Boolean,
        cuBase: Long, addrSize: Int, version: Int, rangesBase: Long,
        sections: DwarfSections, issues: MutableList<ParseIssue>, dieOff: Long,
    ): List<AddressRange> {
        if (low != null && high != null) {
            val end = if (highIsAddr) high else low + high
            return listOf(AddressRange(low, end))
        }
        if (low != null) return listOf(AddressRange(low, low))
        if (rangesOff != null) {
            try {
                return if (version >= 5 || rangesIsIndex) {
                    val data = sections.rnglists ?: throw BadReference(".debug_rnglists missing")
                    Ranges.parseRngLists(data, rangesOff, rangesIsIndex, cuBase, addrSize, sections.bigEndian, rangesBase, sections)
                } else {
                    val data = sections.ranges ?: throw BadReference(".debug_ranges missing")
                    Ranges.parseDebugRanges(data, rangesOff, cuBase, addrSize, sections.bigEndian)
                }
            } catch (e: Exception) {
                issues.add(ParseIssue(if (version >= 5) ".debug_rnglists" else ".debug_ranges", dieOff,
                    "warning", "range list resolution failed: ${e.message}"))
            }
        }
        return emptyList()
    }
}
