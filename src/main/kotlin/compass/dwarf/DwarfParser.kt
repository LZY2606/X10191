package compass.dwarf

class DwarfParser(
    private val sections: Map<String, ByteArray>,
    private val littleEndian: Boolean = true,
    private val limits: DwarfLimits = DwarfLimits(),
) {
    private val issues = mutableListOf<String>()

    private fun section(name: String) = sections[name]

    private fun reader(name: String): Reader? = section(name)?.let { Reader(it, 0, littleEndian) }

    private fun cstringAt(bytes: ByteArray, off: Long): String? {
        if (off < 0 || off >= bytes.size) return null
        var end = off.toInt()
        while (end < bytes.size && bytes[end] != 0.toByte()) end++
        return String(bytes, off.toInt(), end - off.toInt(), Charsets.UTF_8)
    }

    fun parse(): ParsedDwarf {
        val units = mutableListOf<CompilationUnit>()
        parseInfoSection(".debug_info", ".debug_abbrev", units)
        // split-DWARF object sections, if present in the same file
        if (sections.containsKey(".debug_info.dwo")) {
            parseInfoSection(".debug_info.dwo", ".debug_abbrev.dwo", units)
        }
        return ParsedDwarf(units, issues.toList())
    }

    private fun parseInfoSection(infoName: String, abbrevName: String, units: MutableList<CompilationUnit>) {
        val infoBytes = section(infoName) ?: return
        val abbrevBytes = section(abbrevName)
        val info = Reader(infoBytes, 0, littleEndian)
        var guard = 0
        while (info.remaining() >= 4 && guard++ < 1_000_000) {
            val cuStart = info.pos
            try {
                parseOneUnit(info, cuStart, abbrevBytes, units)
            } catch (e: UnknownFormException) {
                // isolate: skip to CU end using the length prefix; cursor stays aligned
                issues += "CU at 0x${cuStart.toString(16)}: ${e.message}; unit isolated"
                skipToUnitEnd(info, cuStart)
                units += brokenUnit(cuStart, info, "unknown form 0x${e.form.toString(16)}")
            } catch (e: DwarfException) {
                issues += "CU at 0x${cuStart.toString(16)}: ${e.message}; unit isolated"
                if (!skipToUnitEnd(info, cuStart)) break
                units += brokenUnit(cuStart, info, e.message ?: "parse error")
            }
        }
    }

    private fun skipToUnitEnd(info: Reader, cuStart: Int): Boolean {
        try {
            val r = info.cloneAt(cuStart)
            val len0 = r.u32()
            val total = if (len0 == 0xffffffffL) 12 + r.u64() else 4 + len0
            val end = cuStart + total.toInt()
            if (total <= 0 || end > info.size || end <= info.pos && end <= cuStart) return false
            info.pos = end
            return true
        } catch (e: Exception) {
            return false
        }
    }

    private fun brokenUnit(cuStart: Int, info: Reader, why: String) = CompilationUnit(
        offset = cuStart.toLong(), version = 0, unitType = -1, addrSize = 0, dwarf64 = false,
        name = null, compDir = null, lowPc = null, ranges = emptyList(), stmtListOffset = null,
        lineVersion = null, rnglistsVersion = null, lineRows = emptyList(), inlines = emptyList(),
        dwoName = null, dwoMissing = false, truncated = true, issues = listOf("unit truncated: $why"),
    )

    private fun parseOneUnit(info: Reader, cuStart: Int, abbrevBytes: ByteArray?, units: MutableList<CompilationUnit>) {
        val unitIssues = mutableListOf<String>()
        val len0 = info.u32()
        val dwarf64 = len0 == 0xffffffffL
        val unitLen = if (dwarf64) info.u64() else len0
        if (unitLen <= 0) throw DwarfException("bad unit length")
        val headerSize = if (dwarf64) 12 else 4
        val cuEnd = cuStart + headerSize + unitLen.toInt()
        if (cuEnd > info.size) throw DwarfException("unit overruns .debug_info")
        info.dwarf64 = dwarf64
        val version = info.u16()
        if (version !in 2..5) throw DwarfException("unsupported DWARF version $version")
        val unitType: Int
        val addrSize: Int
        val abbrevOffset: Long
        if (version >= 5) {
            unitType = info.u8()
            addrSize = info.u8()
            abbrevOffset = info.offset()
        } else {
            unitType = UnitType.COMPILE // no unit_type field before v5
            abbrevOffset = info.offset()
            addrSize = info.u8()
        }
        if (addrSize != 4 && addrSize != 8) throw DwarfException("unsupported address size $addrSize")
        if (abbrevBytes == null) throw DwarfException("missing abbrev section")
        val abbrevs = AbbrevTable.parse(Reader(abbrevBytes, 0, littleEndian, dwarf64), abbrevOffset, limits)

        val die = DieParser.parse(info, cuStart, cuEnd, abbrevs, addrSize, version, limits)
        info.pos = cuEnd // align to unit boundary regardless of DIE tree end

        // --- string/address indirect resolution context ---
        val strBytes = section(".debug_str")
        val lineStrBytes = section(".debug_line_str")
        val strOffBytes = section(".debug_str_offsets")
        val addrBytes = section(".debug_addr")

        fun attrLong(d: Die, a: Int): Long? = when (val v = d.firstAttr(a)) {
            is AttrValue.Data -> v.v
            is AttrValue.SData -> v.v
            is AttrValue.SecOffset -> v.v
            else -> null
        }

        val strOffsetsBase = attrLong(die, Attr.STR_OFFSETS_BASE) ?: 0L
        val addrBase = attrLong(die, Attr.ADDR_BASE) ?: 0L
        val rnglistsBase = attrLong(die, Attr.RNGLISTS_BASE) ?: 0L

        fun resolveStrRef(v: AttrValue.StrRef): String? = when (v.table) {
            "str" -> strBytes?.let { cstringAt(it, v.offset) }
            "line_str" -> lineStrBytes?.let { cstringAt(it, v.offset) }
            else -> null
        }

        fun resolveStrx(index: Long): String? {
            val tab = strOffBytes ?: return null
            val entrySize = if (dwarf64) 8 else 4
            val pos = strOffsetsBase + index * entrySize
            if (pos < 0 || pos + entrySize > tab.size) return null
            val r = Reader(tab, pos.toInt(), littleEndian, dwarf64)
            val off = r.offset()
            return strBytes?.let { cstringAt(it, off) }
        }

        fun resolveAddrx(index: Long): Long? {
            val tab = addrBytes ?: return null
            val pos = addrBase + index * addrSize
            if (pos < 0 || pos + addrSize > tab.size) return null
            return Reader(tab, pos.toInt(), littleEndian).addr(addrSize)
        }

        fun dieString(d: Die, a: Int): String? = when (val v = d.firstAttr(a)) {
            is AttrValue.Str -> v.s
            is AttrValue.StrRef -> resolveStrRef(v) ?: run { unitIssues += "unresolved string for ${Attr.name(a)}"; null }
            is AttrValue.Indexed -> if (v.kind == "strx") resolveStrx(v.index)
                ?: run { unitIssues += "unresolved strx ${v.index} for ${Attr.name(a)}"; null } else null
            else -> null
        }

        fun dieAddress(d: Die, a: Int): Long? = when (val v = d.firstAttr(a)) {
            is AttrValue.Addr -> v.v
            is AttrValue.Indexed -> if (v.kind == "addrx") resolveAddrx(v.index)
                ?: run { unitIssues += "unresolved addrx ${v.index} for ${Attr.name(a)}"; null } else null
            else -> null
        }

        /** high_pc: address class => absolute; constant class => offset from low_pc. */
        fun highPc(d: Die, lowPc: Long?): Long? = when (val v = d.firstAttr(Attr.HIGH_PC)) {
            is AttrValue.Addr -> v.v
            is AttrValue.Indexed -> dieAddress(d, Attr.HIGH_PC)
            is AttrValue.Data -> lowPc?.plus(v.v)
            is AttrValue.SData -> lowPc?.plus(v.v)
            else -> null
        }

        val cuName = dieString(die, Attr.NAME)
        val compDir = dieString(die, Attr.COMP_DIR)
        val lowPc = dieAddress(die, Attr.LOW_PC)
        val dwoName = dieString(die, Attr.DWO_NAME)
        val stmtList = attrLong(die, Attr.STMT_LIST)

        // --- line program first (inline call_file needs its file table) ---
        var lineVersion: Int? = null
        var lineRows: List<LineRow> = emptyList()
        var lineFiles: List<Pair<Int, String>> = emptyList()
        var lineDirs: List<String> = emptyList()
        if (stmtList != null) {
            val lineSection = reader(".debug_line")
            if (lineSection == null) {
                unitIssues += "DW_AT_stmt_list present but .debug_line missing"
            } else try {
                val lp = LineProgramParser.parse(lineSection, stmtList, compDir, limits) { table, off ->
                    when (table) {
                        "str" -> strBytes?.let { cstringAt(it, off) }
                        "line_str" -> lineStrBytes?.let { cstringAt(it, off) }
                        else -> null
                    }
                }
                lineVersion = lp.header.version
                lineRows = lp.rows
                lineFiles = lp.header.files
                lineDirs = lp.header.directories
                unitIssues += lp.issues
            } catch (e: DwarfException) {
                unitIssues += "line program: ${e.message}"
            } catch (e: UnknownFormException) {
                unitIssues += "line program: ${e.message}"
            }
        }

        // --- ranges ---
        var rnglistsVersion: Int? = null
        fun rangesFor(d: Die): List<RangeEntry> {
            val low = dieAddress(d, Attr.LOW_PC)
            val high = highPc(d, low)
            if (low != null && high != null) return listOf(RangeEntry(low, high))
            return when (val v = d.firstAttr(Attr.RANGES)) {
                is AttrValue.SecOffset -> {
                    if (version >= 5 || section(".debug_rnglists") != null && section(".debug_ranges") == null) {
                        val sec = section(".debug_rnglists")
                        if (sec == null) { unitIssues += ".debug_rnglists missing"; emptyList() }
                        else {
                            rnglistsVersion = 5
                            val (rs, iss) = RangeParser.parseRnglists(
                                Reader(sec, 0, littleEndian), v.v, false, addrSize, rnglistsBase, lowPc, limits, ::resolveAddrx)
                            unitIssues += iss; rs
                        }
                    } else {
                        val sec = section(".debug_ranges")
                        if (sec == null) { unitIssues += ".debug_ranges missing"; emptyList() }
                        else {
                            val (rs, iss) = RangeParser.parseDebugRanges(Reader(sec, 0, littleEndian), v.v, addrSize, lowPc, limits)
                            unitIssues += iss; rs
                        }
                    }
                }
                is AttrValue.Indexed -> if (v.kind == "rnglistx") {
                    val sec = section(".debug_rnglists")
                    if (sec == null) { unitIssues += ".debug_rnglists missing for rnglistx"; emptyList() }
                    else {
                        rnglistsVersion = 5
                        val (rs, iss) = RangeParser.parseRnglists(
                            Reader(sec, 0, littleEndian), v.index, true, addrSize, rnglistsBase, lowPc, limits, ::resolveAddrx)
                        unitIssues += iss; rs
                    }
                } else emptyList()
                else -> emptyList()
            }
        }

        val cuRanges = rangesFor(die)

        // --- inline subroutines ---
        val dieByOffset = mutableMapOf<Long, Die>()
        fun indexDies(d: Die) {
            dieByOffset[d.offset] = d
            d.children.forEach(::indexDies)
        }
        indexDies(die)

        fun resolveOriginName(d: Die): String {
            val direct = dieString(d, Attr.NAME) ?: dieString(d, Attr.LINKAGE_NAME)
            if (direct != null) return direct
            return when (val ref = d.firstAttr(Attr.ABSTRACT_ORIGIN)) {
                is AttrValue.Ref -> {
                    // CU-relative reference; must stay inside this unit
                    val abs = cuStart + ref.offset
                    if (ref.offset < 0 || abs < cuStart || abs >= cuEnd) {
                        unitIssues += "abstract_origin reference 0x${ref.offset.toString(16)} out of CU bounds"
                        "<bad-ref>"
                    } else {
                        val target = dieByOffset[abs]
                        if (target == null) {
                            unitIssues += "abstract_origin target 0x${abs.toString(16)} not a DIE in this CU"
                            "<bad-ref>"
                        } else dieString(target, Attr.NAME) ?: dieString(target, Attr.LINKAGE_NAME) ?: "<anon>"
                    }
                }
                else -> "<anon>"
            }
        }

        fun callFileName(idx: Long): String? {
            val i = if ((lineVersion ?: 4) >= 5) idx.toInt() else idx.toInt() - 1
            val f = lineFiles.getOrNull(i) ?: return null
            val dir = if ((lineVersion ?: 4) >= 5) lineDirs.getOrNull(f.first) ?: ""
            else if (f.first == 0) compDir ?: "" else lineDirs.getOrNull(f.first - 1) ?: ""
            return if (dir.isEmpty() || f.second.startsWith("/")) f.second else "$dir/${f.second}"
        }

        val inlines = mutableListOf<InlineEntry>()
        fun walkInlines(d: Die, parentIdx: Int, depth: Int) {
            var myIdx = parentIdx
            var myDepth = depth
            if (d.tag == Tag.INLINED_SUBROUTINE) {
                val ranges = rangesFor(d)
                val callLine = attrLong(d, Attr.CALL_LINE)
                val callFile = attrLong(d, Attr.CALL_FILE)?.let { callFileName(it) }
                myIdx = inlines.size
                myDepth = depth
                inlines += InlineEntry(d.offset, parentIdx, depth, resolveOriginName(d), callFile, callLine, ranges)
            }
            for (c in d.children) walkInlines(c, myIdx, if (d.tag == Tag.INLINED_SUBROUTINE) myDepth + 1 else myDepth)
        }
        walkInlines(die, -1, 0)

        // --- split DWARF ---
        val isSkeleton = unitType == UnitType.SKELETON || dwoName != null
        val dwoMissing = isSkeleton && !sections.containsKey(".debug_info.dwo")
        if (dwoMissing) unitIssues += "split DWARF: dwo file '$dwoName' not available; only skeleton info is trustworthy"

        units += CompilationUnit(
            offset = cuStart.toLong(), version = version, unitType = unitType, addrSize = addrSize,
            dwarf64 = dwarf64, name = cuName, compDir = compDir, lowPc = lowPc, ranges = cuRanges,
            stmtListOffset = stmtList, lineVersion = lineVersion, rnglistsVersion = rnglistsVersion,
            lineRows = lineRows, inlines = inlines, dwoName = dwoName, dwoMissing = dwoMissing,
            truncated = false, issues = unitIssues,
        )
    }
}
