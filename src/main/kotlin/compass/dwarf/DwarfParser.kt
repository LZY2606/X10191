package compass.dwarf

data class InlineInfo(
    val name: String,
    val callFile: String?,
    val callLine: Long?,
    val callColumn: Long?,
    val depth: Int,
    val ranges: List<AddrRange>,
)

data class FunctionInfo(
    val name: String,
    val offset: Long,
    val depth: Int,
    val ranges: List<AddrRange>,
    val inlines: List<InlineInfo>,
)

data class ParsedCu(
    val cuOffset: Long,
    val version: Int,
    val dwarf64: Boolean,
    val unitType: Int?,
    val addrSize: Int,
    val name: String,
    val compDir: String?,
    val producer: String?,
    val dwoName: String?,
    val isSkeleton: Boolean,
    val lineProgram: LineProgramResult?,
    val functions: List<FunctionInfo>,
    val warnings: List<String>,
)

data class ParsedDebugFile(
    val cus: List<ParsedCu>,
    val warnings: List<String>,
)

object DwarfParser {

    fun parse(elf: ElfFile): ParsedDebugFile {
        val warnings = mutableListOf<String>()
        val info = elf.section(".debug_info")?.data
        val abbrev = elf.section(".debug_abbrev")?.data
        val line = elf.section(".debug_line")?.data
        val str = elf.section(".debug_str")?.data
        val lineStr = elf.section(".debug_line_str")?.data
        val ranges = elf.section(".debug_ranges")?.data
        val rnglists = elf.section(".debug_rnglists")?.data
        val addrSec = elf.section(".debug_addr")?.data
        val strOffsets = elf.section(".debug_str_offsets")?.data

        if (info == null) warnings.add("no .debug_info section")
        if (info != null && abbrev == null) warnings.add("no .debug_abbrev section; DIEs unparsable")
        if (line == null) warnings.add("no .debug_line section; file/line conclusions unavailable")

        val cus = mutableListOf<ParsedCu>()
        if (info != null && abbrev != null) {
            val r = Reader(info, ".debug_info", 0, elf.bigEndian)
            while (!r.eof()) {
                val cuOffset = r.pos.toLong()
                try {
                    val cu = parseCu(
                        r, cuOffset, abbrev, line, str, lineStr, ranges, rnglists, addrSec, strOffsets, elf.bigEndian, warnings
                    )
                    if (cu != null) cus.add(cu) else break
                } catch (e: DwarfException) {
                    warnings.add("CU at 0x${cuOffset.toString(16)}: ${e.message}; parsing stopped for remaining .debug_info")
                    break
                }
            }
        }
        return ParsedDebugFile(cus, warnings)
    }

    private fun parseCu(
        r: Reader,
        cuOffset: Long,
        abbrev: ByteArray,
        line: ByteArray?,
        str: ByteArray?,
        lineStr: ByteArray?,
        ranges: ByteArray?,
        rnglists: ByteArray?,
        addrSec: ByteArray?,
        strOffsets: ByteArray?,
        bigEndian: Boolean,
        globalWarnings: MutableList<String>,
    ): ParsedCu? {
        val warnings = mutableListOf<String>()
        val (unitLength, dwarf64) = r.initialLength()
        val unitContentStart = r.pos
        val unitEnd = (r.pos + unitLength).coerceAtMost(r.size.toLong()).toInt()
        if (r.pos + unitLength > r.size) warnings.add("unit length exceeds section; clamped")
        if (unitEnd <= unitContentStart) return null
        val version = r.u16()
        var unitType: Int? = null
        var addrSize: Int
        var abbrevOffset: Long
        if (version >= 5) {
            unitType = r.u8()
            addrSize = r.u8()
            abbrevOffset = if (dwarf64) r.u64() else r.u32()
        } else {
            abbrevOffset = if (dwarf64) r.u64() else r.u32()
            addrSize = r.u8()
        }
        if (addrSize != 4 && addrSize != 8) throw DwarfException("unsupported address size $addrSize")
        val isSkeleton = unitType == Dw.UT_skeleton || unitType == Dw.UT_split_compile

        val abbrevs = AbbrevParser.parse(abbrev, abbrevOffset.toInt(), bigEndian)
        val decoder = FormDecoder(version, addrSize, dwarf64, bigEndian)
        val dieParser = DieParser(r.data, r.pos, unitEnd, abbrevs, decoder, bigEndian = bigEndian)
        val root = dieParser.parse()
        warnings.addAll(dieParser.warnings)
        r.seek(unitEnd)

        // string resolution helpers
        fun resolveStr(v: AttrValue): String? = when (v) {
            is AttrValue.Str -> v.value
            is AttrValue.StrOffset -> {
                val tab = if (v.lineStr) lineStr else str
                if (tab == null) { warnings.add("string table missing"); null }
                else runCatching { Reader(tab, "str").cstringAt(v.offset) }.getOrNull()
            }
            is AttrValue.StrIndex -> {
                // resolve via .debug_str_offsets + .debug_str
                if (strOffsets == null || str == null) { warnings.add("strx used but .debug_str_offsets missing"); null }
                else {
                    val base = 0L // str_offsets_base attribute would refine this; header-skipped tables use base 0
                    val entrySize = if (dwarf64) 8 else 4
                    val off = base + v.index * entrySize
                    if (off < 0 || off + entrySize > strOffsets.size) { warnings.add("strx index ${v.index} out of bounds"); null }
                    else {
                        val sr = Reader(strOffsets, ".debug_str_offsets", off.toInt(), bigEndian)
                        val strOff = if (dwarf64) sr.u64() else sr.u32()
                        runCatching { Reader(str, ".debug_str").cstringAt(strOff) }.getOrNull()
                    }
                }
            }
            else -> null
        }

        fun numAttr(die: Die, name: Int): Long? = when (val v = die.attr(name)) {
            is AttrValue.Data -> v.value
            is AttrValue.SData -> v.value
            is AttrValue.Addr -> v.value
            is AttrValue.SecOffset -> v.value
            is AttrValue.AddrIndex -> null // resolved below via addr table
            else -> null
        }

        fun addrAttr(die: Die, name: Int, addrBase: Long): Long? = when (val v = die.attr(name)) {
            is AttrValue.Addr -> v.value
            is AttrValue.AddrIndex -> {
                if (addrSec == null) { warnings.add("addrx used but .debug_addr missing"); null }
                else {
                    val off = addrBase + v.index * addrSize
                    if (off < 0 || off + addrSize > addrSec.size) { warnings.add("addrx index ${v.index} out of bounds"); null }
                    else { val ar = Reader(addrSec, ".debug_addr", off.toInt(), bigEndian); if (addrSize == 8) ar.u64() else ar.u32() }
                }
            }
            else -> null
        }

        val rootDie = root ?: return ParsedCu(
            cuOffset, version, dwarf64, unitType, addrSize, "<empty>", null, null, null, isSkeleton,
            null, emptyList(), warnings
        )

        val cuName = rootDie.attr(Dw.AT_name)?.let(resolveStr) ?: "<unnamed>"
        val compDir = rootDie.attr(Dw.AT_comp_dir)?.let(resolveStr)
        val producer = rootDie.attr(Dw.AT_producer)?.let(resolveStr)
        val dwoName = (rootDie.attr(Dw.AT_dwo_name) ?: rootDie.attr(Dw.AT_GNU_dwo_name))?.let(resolveStr)
        val addrBase = numAttr(rootDie, Dw.AT_addr_base) ?: 0L
        val rnglistsBase = numAttr(rootDie, Dw.AT_rnglists_base) ?: 0L
        val cuLowPc = addrAttr(rootDie, Dw.AT_low_pc, addrBase)

        if (dwoName != null) {
            warnings.add("split DWARF: dwo='$dwoName' not imported; DIE details from dwo are unavailable")
        }

        // ---- line program ----
        var lineProgram: LineProgramResult? = null
        val stmtList = numAttr(rootDie, Dw.AT_stmt_list)
        if (stmtList != null) {
            if (line == null) {
                warnings.add("DW_AT_stmt_list present but .debug_line missing (split DWARF dwo not loaded?)")
            } else {
                try {
                    lineProgram = LineProgramParser.parse(line, stmtList, addrSize, str, lineStr, bigEndian)
                    warnings.addAll(lineProgram.warnings)
                } catch (e: DwarfException) {
                    warnings.add("line program at 0x${stmtList.toString(16)}: ${e.message}")
                }
            }
        }

        // ---- ranges for a DIE ----
        fun rangesFor(die: Die): List<AddrRange> {
            val low = addrAttr(die, Dw.AT_low_pc, addrBase)
            val highV = die.attr(Dw.AT_high_pc)
            if (low != null && highV != null) {
                // DW_AT_high_pc has two meanings: absolute address (class address) or offset from low_pc (class constant)
                val high = when (highV) {
                    is AttrValue.Addr -> highV.value
                    is AttrValue.AddrIndex -> addrAttr(die, Dw.AT_high_pc, addrBase)
                    is AttrValue.Data -> low + highV.value
                    is AttrValue.SData -> low + highV.value
                    else -> null
                }
                if (high != null) return listOf(AddrRange(low, high))
            }
            val rangesOff = numAttr(die, Dw.AT_ranges) ?: numAttr(die, Dw.AT_GNU_ranges)
            if (rangesOff != null) {
                val isRngListx = die.attr(Dw.AT_ranges) is AttrValue.Data && version >= 5 && rnglists != null
                if (rnglists != null && (version >= 5)) {
                    val absOff = if (isRngListx) RangeListParser.rnglistxOffset(rnglists, rnglistsBase, rangesOff)
                    else rnglistsBase + rangesOff
                    if (absOff != null) {
                        val res = RangeListParser.parseRngLists(rnglists, absOff, addrSize, cuLowPc ?: 0,
                            addrTable = if (addrSec != null) { idx ->
                                val off = addrBase + idx * addrSize
                                if (off < 0 || off + addrSize > addrSec.size) null
                                else { val ar = Reader(addrSec, ".debug_addr", off.toInt(), bigEndian); if (addrSize == 8) ar.u64() else ar.u32() }
                            } else null, bigEndian = bigEndian)
                        warnings.addAll(res.warnings)
                        return res.ranges
                    }
                } else if (ranges != null) {
                    val res = RangeListParser.parseDebugRanges(ranges, rangesOff, addrSize, cuLowPc ?: 0, bigEndian)
                    warnings.addAll(res.warnings)
                    return res.ranges
                } else {
                    warnings.add("DW_AT_ranges present but no .debug_ranges/.debug_rnglists section")
                }
            }
            return emptyList()
        }

        // ---- collect functions and inline sites ----
        val functions = mutableListOf<FunctionInfo>()
        val dieByOffset = HashMap<Long, Die>()
        fun indexDies(d: Die) { dieByOffset[d.offset] = d; d.children.forEach(::indexDies) }
        indexDies(rootDie)

        fun dieName(d: Die): String {
            d.attr(Dw.AT_name)?.let(resolveStr)?.let { return it }
            // follow abstract_origin / specification with jump validation
            var cur = d
            var hops = 0
            while (hops++ < 32) {
                val ref = (cur.attr(Dw.AT_abstract_origin) ?: cur.attr(Dw.AT_specification)) as? AttrValue.Ref
                    ?: return "<anon>"
                val targetOff = cuOffset + 0 // refs are section-relative
                val target = dieByOffset[ref.offset]
                if (target == null) {
                    if (ref.offset < 0 || ref.offset >= r.data.size) warnings.add("reference 0x${ref.offset.toString(16)} out of .debug_info bounds")
                    return "<anon>"
                }
                target.attr(Dw.AT_name)?.let(resolveStr)?.let { return it }
                cur = target
            }
            warnings.add("abstract_origin chain too deep; giving up")
            return "<anon>"
        }

        fun collectInlines(d: Die, out: MutableList<InlineInfo>) {
            if (d.tag == Dw.TAG_inlined_subroutine) {
                val callFileIdx = numAttr(d, Dw.AT_call_file)?.toInt()
                val callFile = callFileIdx?.let { idx ->
                    lineProgram?.files?.let { files ->
                        val i = if (lineProgram.version >= 5) idx else idx - 1
                        files.getOrNull(i)?.name
                    }
                }
                out.add(
                    InlineInfo(
                        name = dieName(d),
                        callFile = callFile,
                        callLine = numAttr(d, Dw.AT_call_line),
                        callColumn = numAttr(d, Dw.AT_call_column),
                        depth = d.depth,
                        ranges = rangesFor(d),
                    )
                )
            }
            d.children.forEach { collectInlines(it, out) }
        }

        fun collectFunctions(d: Die) {
            if (d.tag == Dw.TAG_subprogram) {
                val rgs = rangesFor(d)
                if (rgs.isNotEmpty()) {
                    val inlines = mutableListOf<InlineInfo>()
                    d.children.forEach { collectInlines(it, inlines) }
                    functions.add(FunctionInfo(dieName(d), d.offset, d.depth, rgs, inlines))
                }
            }
            d.children.forEach(::collectFunctions)
        }
        rootDie.children.forEach(::collectFunctions)

        return ParsedCu(
            cuOffset, version, dwarf64, unitType, addrSize, cuName, compDir, producer, dwoName, isSkeleton,
            lineProgram, functions, warnings
        )
    }
}
