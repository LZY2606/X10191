package compass.dwarf

import compass.model.*

data class ParsedUnit(
    val info: CompilationUnitInfo,
    val dies: List<DieNode>,
    val lineProgramOffset: Long?,
    val strOffsetsBase: Long,
    val addrBase: Long,
    val rnglistsBase: Long
)

class InfoParseOutput(val units: List<ParsedUnit>, val issues: List<ParseIssue>)

private data class UnitHeader(
    val start: Int, val contentStart: Int, val length: Long, val format: Int,
    val version: Int, val unitType: Int, val addressSize: Int,
    val abbrevOffset: Long, val dwoId: Long?
)

class DieBuilder(
    val offset: Long,
    val tag: Int,
    val depth: Int,
    val parentOffset: Long?,
    val children: MutableList<Long> = mutableListOf()
) {
    var name: String? = null
    var linkageName: String? = null
    var compDir: String? = null
    var primaryName: String? = null
    var language: Int? = null
    var dwoName: String? = null
    var dwoId: Long? = null
    var stmtList: Long? = null
    var strOffsetsBase: Long = 0
    var addrBase: Long = 0
    var rnglistsBase: Long = 0

    var lowPc: Long? = null
    var highPc: Long? = null
    var highPcIsOffset = true
    var ranges: List<AddrRange> = emptyList()
    var rangeBasis: String = "none"
    var rangesOff: Long? = null
    var rnglistIndex: Long? = null

    var abstractOrigin: Long? = null
    var specification: Long? = null
    var declFileId: Int? = null
    var declLine: Int? = null
    var callFileId: Int? = null
    var callLine: Int? = null
    var callColumn: Int? = null
    var inlineCode: Int? = null
    var declaration = false
    var external = false
    var attrs: Map<Int, AttrVal> = emptyMap()
    var rawAttrList: List<RawAttr> = emptyList()
}

class InfoParser(private val sec: DebugSections) {
    private val endian: Endian = sec.elf?.endian ?: Endian.LITTLE
    private val issues = mutableListOf<ParseIssue>()
    private val abbrevTables: Map<Long, Map<Long, AbbrevDecl>> =
        parseAbbrev(sec.abbrev).also { it.second.forEach { e -> issues += ParseIssue("error", "abbrev", e) } }.first

    fun parse(): InfoParseOutput {
        if (sec.info == null) return InfoParseOutput(emptyList(), issues)
        val r = ByteReader(sec.info)
        val units = ArrayList<ParsedUnit>()
        var guard = 0
        while (r.remaining > 4 && guard++ < 200_000) {
            val unitStart = r.pos
            units += parseOneUnit(r, unitStart, units.size)
        }
        if (r.remaining in 1..4)
            issues += ParseIssue("warn", "info", "${r.remaining} trailing bytes in .debug_info", r.pos.toLong())
        return InfoParseOutput(units, issues)
    }

    private fun parseOneUnit(r: ByteReader, unitStart: Int, index: Int): ParsedUnit {
        val local = mutableListOf<ParseIssue>()
        var trust = TrustLevel.FULL

        val hdr = readHeader(r, unitStart)
        val absEnd = hdr.start + (hdr.contentStart - hdr.start) + hdr.length.toInt()
        val body = ByteReader(sec.info!!, hdr.contentStart, absEnd - hdr.contentStart)

        val builders = LinkedHashMap<Long, DieBuilder>()
        var splitNeeded = false

        var lineStmtOffset: Long? = null
        var strOffsetsBase = 0L
        var addrBase = 0L
        var rnglistsBase = 0L

        try {
            val stack = ArrayDeque<DieBuilder>()
            var terminated = false
            var dieGuard = 0
            while (body.remaining > 0 && !terminated) {
                if (dieGuard++ > 5_000_000) {
                    local += ParseIssue("error", "info", "DIE limit exceeded, aborting CU", unitStart.toLong())
                    trust = TrustLevel.UNTRUSTED; break
                }
                val dieAbsOff = hdr.contentStart + body.pos
                val code = body.readULEB128()
                if (code == 0L) {
                    if (stack.isEmpty()) { terminated = true; break }
                    stack.removeLast()
                    continue
                }
                val abbr = abbrevTables[hdr.abbrevOffset]?.get(code)
                if (abbr == null) {
                    local += ParseIssue("error", "abbrev", "code $code unresolved at base 0x${hdr.abbrevOffset.toString(16)}", dieAbsOff.toLong())
                    trust = TrustLevel.UNTRUSTED
                    break
                }

                val depth = stack.size
                val parent = stack.lastOrNull()
                val b = DieBuilder(dieAbsOff.toLong(), abbr.tag, depth, parent?.offset)
                val raw = ArrayList<RawAttr>()
                val attrMap = HashMap<Int, AttrVal>()
                for ((attr, form) in abbr.attrs) {
                    val v = try {
                        FormReader(body, endian, hdr.format, hdr.addressSize).read(form, abbr.implicitConst[attr])
                    } catch (e: UnknownFormException) {
                        local += ParseIssue("warn", "forms",
                            "unknown DW_FORM 0x${e.form.toString(16)} (attr 0x${attr.toString(16)}); CU DIE scan aborted to avoid cursor drift",
                            body.pos.toLong())
                        trust = TrustLevel.UNTRUSTED
                        throw e
                    }
                    raw += RawAttr(dwAtName(attr), dwFormName(form), displayAttr(v))
                    attrMap[attr] = v
                }
                b.attrs = attrMap
                b.rawAttrList = raw
                fillBuilder(b, attrMap, strOffsetsBasePending = 0L)
                if (depth == 0) {
                    lineStmtOffset = b.stmtList
                    strOffsetsBase = b.strOffsetsBase
                    addrBase = b.addrBase
                    rnglistsBase = b.rnglistsBase
                    if (b.dwoName != null || hdr.unitType == DW_UT.SKELETON) splitNeeded = true
                }
                parent?.children?.add(b.offset)
                builders[b.offset] = b
                if (abbr.hasChildren) stack.addLast(b)
            }
        } catch (e: UnknownFormException) {
            trust = TrustLevel.UNTRUSTED
        } catch (e: BoundsException) {
            local += ParseIssue("error", "info", "bounds error: ${e.message}", unitStart.toLong())
            trust = TrustLevel.UNTRUSTED
        }

        resolveRanges(builders.values, hdr, addrBase, rnglistsBase, local)

        val dies = builders.values.map { it.toNode() }
        val root = it_root(builders)
        if (trust == TrustLevel.FULL && local.any { it.severity == "error" }) trust = TrustLevel.UNTRUSTED

        val info = CompilationUnitInfo(
            index, unitStart.toLong(), hdr.version, hdr.format, hdr.unitType,
            DW_UT.name(hdr.unitType), hdr.addressSize, hdr.dwoId ?: root?.dwoId,
            hdr.abbrevOffset, dies.size, root?.name, root?.compDir, root?.primaryName,
            root?.language, trust, local, false, splitNeeded
        )
        return ParsedUnit(info, dies, lineStmtOffset, strOffsetsBase, addrBase, rnglistsBase)
    }

    private fun it_root(m: Map<Long, DieBuilder>): DieBuilder? = m.values.firstOrNull { it.depth == 0 }

    private fun readHeader(r: ByteReader, unitStart: Int): UnitHeader {
        val (len, fmt, contentStartRel) = r.readInitialLength(endian)
        val contentStart = unitStart + contentStartRel
        val sub = ByteReader(sec.info!!, contentStart, minOf(len.toInt(), sec.info.size - contentStart))
        val version = sub.readU16(endian)
        var unitType = DW_UT.COMPILE
        var addressSize: Int
        var abbrevOffset: Long
        var dwoId: Long? = null
        if (version >= 5) {
            unitType = sub.readByte()
            addressSize = sub.readByte()
            abbrevOffset = sub.readBytesOf(fmt, endian)
            if (unitType == DW_UT.SKELETON || unitType == DW_UT.SPLIT_COMPILE) dwoId = sub.readU64(endian)
            else if (unitType == DW_UT.TYPE || unitType == DW_UT.SPLIT_TYPE) {
                sub.readU64(endian)
                sub.readBytesOf(fmt, endian)
            }
        } else {
            abbrevOffset = sub.readU32(endian)
            addressSize = sub.readByte()
        }
        r.seek((contentStart + len).toInt())
        return UnitHeader(unitStart, contentStart, len, fmt, version, unitType, addressSize, abbrevOffset, dwoId)
    }

    private fun strOffsetsSectionOffset(cuStrOffsetsBase: Long, idx: Long, endian: Endian): Long {
        val data = sec.strOffsets ?: return -1L
        // DWARF5 str_offsets_base 指向贡献块头部之后的数组起点
        val entrySize = 4 // 简化：支持 32 位偏移；64 位贡献按头读
        val off = (cuStrOffsetsBase + idx * entrySize).toInt()
        if (off < 0 || off + 4 > data.size) return -1L
        return ByteReader(data, off, 4).readU32(endian)
    }

    private fun resolveString(v: AttrVal, strOffsetsBase: Long): String? = when (v) {
        is AttrVal.InlineStr -> v.v
        is AttrVal.InSectionStr -> readCString(sec.str, v.off)
        is AttrVal.InLineStr -> readCString(sec.lineStr, v.off)
        is AttrVal.StrIndex -> {
            val so = strOffsetsSectionOffset(strOffsetsBase, v.idx, endian)
            if (so < 0) null else readCString(sec.str, so)
        }
        else -> null
    }

    private fun readCString(data: ByteArray?, off: Long): String? {
        if (data == null || off < 0 || off >= data.size) return null
        var e = off.toInt()
        while (e < data.size && data[e].toInt() != 0) e++
        return String(data, off.toInt(), e - off.toInt(), Charsets.UTF_8)
    }

    private fun fillBuilder(b: DieBuilder, attrs: Map<Int, AttrVal>, strOffsetsBasePending: Long) {
        fun av(k: Int) = attrs[k]
        b.primaryName = av(DW_AT.NAME)?.let { resolveString(it, 0) }
        b.name = b.primaryName
        b.linkageName = av(DW_AT.LINKAGE_NAME)?.let { resolveString(it, 0) } ?: b.linkageName
        b.compDir = av(DW_AT.COMP_DIR)?.let { resolveString(it, 0) }
        b.language = (av(DW_AT.LANGUAGE) as? AttrVal.UConstant)?.v?.toInt()
        b.dwoName = (av(DW_AT.DWO_NAME) ?: av(DW_AT.GNU_DWO_NAME))?.let { resolveString(it, 0) }
        b.dwoId = when (val x = av(DW_AT.DWO_ID) ?: av(DW_AT.GNU_DWO_ID)) {
            is AttrVal.UConstant -> x.v; is AttrVal.Address -> x.v; else -> null
        }
        b.stmtList = when (val x = av(DW_AT.STMT_LIST)) { is AttrVal.SecOffset -> x.v; is AttrVal.UConstant -> x.v; else -> null }
        b.strOffsetsBase = (av(DW_AT.STR_OFF_SETS_BASE) as? AttrVal.SecOffset)?.v ?: 0L
        b.addrBase = (av(DW_AT.ADDR_BASE) as? AttrVal.SecOffset)?.v ?: 0L
        b.rnglistsBase = (av(DW_AT.RNGLISTS_BASE) as? AttrVal.SecOffset)?.v ?: 0L

        b.lowPc = when (val x = av(DW_AT.LOW_PC)) { is AttrVal.Address -> x.v; is AttrVal.UConstant -> x.v; else -> b.lowPc }
        when (val x = av(DW_AT.HIGH_PC)) {
            is AttrVal.Address -> { b.highPc = x.v; b.highPcIsOffset = false }
            is AttrVal.UConstant -> { b.highPc = x.v; b.highPcIsOffset = true }
            else -> {}
        }
        when (val x = av(DW_AT.RANGES)) {
            is AttrVal.SecOffset -> b.rangesOff = x.v
            is AttrVal.RngListIndex -> b.rnglistIndex = x.idx
            else -> {}
        }
        b.abstractOrigin = refOffset(av(DW_AT.ABSTRACT_ORIGIN))
        b.specification = refOffset(av(DW_AT.SPECIFICATION))
        b.declFileId = uconst(av(DW_AT.DECL_FILE))
        b.declLine = uconst(av(DW_AT.DECL_LINE))
        b.callFileId = uconst(av(DW_AT.CALL_FILE))
        b.callLine = uconst(av(DW_AT.CALL_LINE))
        b.callColumn = uconst(av(DW_AT.CALL_COLUMN))
        b.inlineCode = uconst(av(DW_AT.INLINE))
        b.declaration = (av(DW_AT.DECLARATION) as? AttrVal.Bool)?.v == true
        b.external = (av(DW_AT.EXTERNAL) as? AttrVal.Bool)?.v == true
    }

    private fun uconst(v: AttrVal?): Int? = when (v) {
        is AttrVal.UConstant -> v.v.toInt(); is AttrVal.SConstant -> v.v.toInt(); else -> null
    }

    private fun refOffset(v: AttrVal?): Long? = when (v) {
        is AttrVal.RefInfo -> v.off; else -> null
    }

    private fun resolveRanges(
        builders: Collection<DieBuilder>,
        hdr: UnitHeader,
        addrBase: Long,
        rnglistsBase: Long,
        local: MutableList<ParseIssue>
    ) {
        val contributions = parseRngListContributions(sec.rnglists, endian)
        for (b in builders) {
            // high_pc 两种含义：constant（长度）或 address（绝对地址）
            val low = b.lowPc
            if (low != null && b.highPc != null) {
                val high = if (b.highPcIsOffset) low + (b.highPc ?: 0L) else b.highPc!!
                b.ranges = listOf(if (high == low) AddrRange(low, high, zeroLength = true, source = "low_pc/high_pc")
                                  else AddrRange(low, high, source = "low_pc/high_pc"))
                b.rangeBasis = if (b.highPcIsOffset) "high_pc=constant" else "high_pc=address"
            }
            val rangesOff = b.rangesOff
            val rngIdx = b.rnglistIndex
            if (rangesOff != null || rngIdx != null) {
                try {
                    val ctx = RangeListContext(
                        endian, hdr.addressSize, 0,
                        sec.ranges, sec.rnglists, contributions, sec.addr, addrBase, hdr.version
                    )
                    b.ranges = when {
                        hdr.version >= 5 && rngIdx != null -> {
                            val contrib = contributions.firstOrNull { it.offset == rnglistsBase } ?: contributions.firstOrNull()
                            val tableOff = if (contrib != null) {
                                val arrOff = (contrib.offsetEntryOff + rngIdx * 4L).toInt()
                                ByteReader(sec.rnglists!!, arrOff, 4).readU32(endian) + contrib.dataStart
                            } else rngIdx
                            ctx.readV5RangeList(tableOff)
                        }
                        hdr.version >= 5 -> ctx.readV5RangeList(rangesOff!!)
                        else -> ctx.readV4RangeList(rangesOff!!)
                    }
                    b.rangeBasis = "ranges"
                } catch (e: BoundsException) {
                    local += ParseIssue("warn", "ranges", "DIE 0x${b.offset.toString(16)} ranges unreadable: ${e.message}", b.offset)
                }
            }
        }
    }

    private fun DieBuilder.toNode(): DieNode = DieNode(
        offset = offset,
        tag = tag,
        tagName = DW_TAG.name(tag),
        depth = depth,
        parentOffset = parentOffset,
        childOffsets = children.toList(),
        name = name,
        linkageName = linkageName,
        ranges = ranges,
        rangeBasis = rangeBasis,
        abstractOriginOffset = abstractOrigin,
        specificationOffset = specification,
        declFileId = declFileId,
        declLine = declLine,
        callFileId = callFileId,
        callLine = callLine,
        callColumn = callColumn,
        inlineCode = inlineCode,
        declaration = declaration,
        external = external,
        unknownForm = false,
        rawAttrs = rawAttrList
    )
}

private fun displayAttr(v: AttrVal): String = when (v) {
    is AttrVal.Address -> "0x${v.v.toString(16)}"
    is AttrVal.UConstant -> v.v.toString()
    is AttrVal.SConstant -> v.v.toString()
    is AttrVal.Bool -> v.v.toString()
    is AttrVal.InlineStr -> v.v
    is AttrVal.InSectionStr -> "str+0x${v.off.toString(16)}"
    is AttrVal.InLineStr -> "line_str+0x${v.off.toString(16)}"
    is AttrVal.RefInfo -> "info+0x${v.off.toString(16)}"
    is AttrVal.SecOffset -> "sec+0x${v.v.toString(16)}"
    is AttrVal.StrIndex -> "strx${v.idx}"
    is AttrVal.AddrIndex -> "addrx${v.idx}"
    is AttrVal.RngListIndex -> "rnglistx${v.idx}"
    is AttrVal.RefSig -> "sig8 0x${v.v.toString(16)}"
    is AttrVal.Block -> "<block ${v.v.size}>"
    is AttrVal.Expr -> "<expr ${v.v.size}>"
    is AttrVal.Unknown -> "<unsupported form 0x${v.form.toString(16)}>"
}
