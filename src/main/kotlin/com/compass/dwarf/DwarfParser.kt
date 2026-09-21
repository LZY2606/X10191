package com.compass.dwarf

/** Per-CU context needed to decode DWARF5 indexed forms and offsets. */
class CuContext(
    val cu: Buf,
    val version: Int,
    val dwarf64: Boolean,
    val unitType: Int,
    val cuStart: Int,
    val cuLength: Int,
    val addressSize: Int,
    val strOffsetsBase: Long?,
    val addrBase: Long?,
    val rnglistsBase: Long?,
    val isDwo: Boolean,
    val sections: SectionSet
) {
    fun readAddr(buf: Buf): Long = buf.unsigned(addressSize).toLong()
}

fun AttrValue?.asOffset(): Long? = when (this) {
    is AttrValue.SecOffset -> offset
    is AttrValue.Num -> v
    is AttrValue.Addr -> v
    else -> null
}

/** Accessor bundle for all debug sections with missing ones represented as empty. */
class SectionSet(elf: ElfFile) {
    private val map = HashMap<String, Section>()
    init {
        for (name in listOf(".debug_info", ".debug_types", ".debug_abbrev", ".debug_str",
            ".debug_line", ".debug_line_str", ".debug_ranges", ".debug_rnglists",
            ".debug_addr", ".debug_str_offsets", ".debug_str_offsets.dwo",
            ".debug_addr.dwo", ".debug_abbrev.dwo", ".debug_info.dwo", ".debug_line.dwo",
            ".debug_rnglists.dwo", ".debug_ranges.dwo")) {
            elf.section(name)?.let { map[name] = it }
        }
    }
    fun bytes(name: String): ByteArray = map[name]?.data ?: ByteArray(0)
    fun section(name: String): Section? = map[name]
    fun has(name: String) = map.containsKey(name)
    fun names(): List<String> = map.keys.sorted()
}

object Dwarf {
    fun parse(elf: ElfFile): ParsedDebug = DwarfParser(elf).parse()
}

class DwarfParser(private val elf: ElfFile) {
    private val sections = SectionSet(elf)
    private val strings = StringTables(SectionSet(elf))
    private val issues = mutableListOf<ParseIssue>()
    private val abbrevCache = HashMap<Long, AbbrevTable>()

    fun parse(): ParsedDebug {
        val isDwo = sections.has(".debug_info.dwo")
        val infoName = if (isDwo) ".debug_info.dwo" else ".debug_info"
        val info = sections.bytes(infoName)
        val cus = mutableListOf<CuInfo>()
        if (info.isEmpty()) {
            // A split DWO without .debug_info.dwo or object without debug info:
            // still report section inventory.
            return finish(isDwo, cus)
        }
        val buf = Buf(info)
        while (buf.pos < buf.size) {
            val unitStart = buf.pos
            try {
                val cu = parseCu(buf, unitStart, isDwo)
                if (cu != null) cus += cu
                else break
            } catch (e: ParseException) {
                issues += ParseIssue("debug_info@${unitStart}", e.message ?: "parse error", "error")
                break
            }
            if (buf.pos <= unitStart) {
                issues += ParseIssue("debug_info@${unitStart}", "CU parser failed to advance cursor", "error")
                break
            }
        }
        return finish(isDwo, cus)
    }

    private fun finish(isDwo: Boolean, cus: List<CuInfo>): ParsedDebug {
        val parsed = sections.names().filter {
            it in setOf(".debug_info", ".debug_info.dwo", ".debug_abbrev", ".debug_abbrev.dwo",
                ".debug_str", ".debug_line", ".debug_line.dwo", ".debug_line_str",
                ".debug_ranges", ".debug_ranges.dwo", ".debug_rnglists", ".debug_rnglists.dwo",
                ".debug_addr", ".debug_addr.dwo", ".debug_str_offsets", ".debug_str_offsets.dwo")
        }
        val dwoIds = cus.mapNotNull { it.dwoId }.toSet()
        return ParsedDebug(elf, cus, issues + cus.flatMap { it.issues }, parsed, isDwo, dwoIds)
    }

    private fun parseCu(buf: Buf, unitStart: Int, isDwo: Boolean): CuInfo? {
        val lenBuf = Buf(buf.a, buf.absolutePos, 12)
        val first = buf.u32()
        val dwarf64: Boolean
        val unitLength: Long
        if (first == 0xffff_ffffL) {
            dwarf64 = true
            unitLength = buf.u64()
        } else {
            dwarf64 = false
            unitLength = first
        }
        if (unitLength <= 0 || unitLength > Int.MAX_VALUE.toLong()) {
            throw ParseException("bad CU length $unitLength at $unitStart")
        }
        val headerStart = buf.pos
        val cuEnd = headerStart + unitLength.toInt()
        if (cuEnd > buf.size) throw ParseException("CU extends past .debug_info ($cuEnd > ${buf.size})")
        val cuBuf = buf.sliceAt(headerStart, unitLength.toInt())

        val version = cuBuf.u16()
        val unitType: Int
        val addressSize: Int
        var abbrevOffset: Long
        if (version >= 5) {
            unitType = cuBuf.u8()
            addressSize = cuBuf.u8()
            abbrevOffset = if (dwarf64) cuBuf.u64() else cuBuf.u32()
        } else {
            unitType = if (isDwo) DW_TAG_skeleton_unit else DW_TAG_compile_unit
            abbrevOffset = if (dwarf64) cuBuf.u64() else cuBuf.u32()
            addressSize = cuBuf.u8()
        }
        // type/signature fields for type units are skipped before reading root DIE.
        var typeSig: Long? = null
        if (unitType == DW_TAG_type_unit || unitType == 0x42 /* split_type */) {
            typeSig = cuBuf.u64()
            if (dwarf64) cuBuf.u64() else cuBuf.u32() // type offset
        }

        // First pass: read DIEs with the per-CU abbreviation table.
        val abbrevName = if (isDwo) ".debug_abbrev.dwo" else ".debug_abbrev"
        val abbrev = abbrevCache.getOrPut(abbrevOffset) {
            AbbrevReader.read(Buf(sections.bytes(abbrevName)), abbrevOffset.toInt())
        }
        val cuIssues = mutableListOf<ParseIssue>()

        // We need str_offsets_base / addr_base, which live on the root DIE.
        // Strategy: parse DIEs raw; but forms strx/addrx need the bases.
        // The root DIE is parsed first, so parse the root partially up front.
        val rootStart = cuBuf.pos
        val rootCode = cuBuf.uleb().toLong()
        val rootDecl = abbrev.decls[rootCode]
            ?: throw ParseException("CU@$unitStart root abbrev code $rootCode not found")
        val rootAttrs = LinkedHashMap<Int, AttrValue>()
        val provisionalCtx = CuContext(cuBuf, version, dwarf64, unitType, unitStart,
            unitLength.toInt(), addressSize, null, null, null, isDwo, sections)
        for ((name, form, implicit) in rootDecl.attrs) {
            rootAttrs[name] = FormReader.read(strings, provisionalCtx, cuBuf, form, implicit, cuIssues)
        }
        val strBase = rootAttrs[DW_AT_str_offsets_base].asOffset()
        val addrBase = (rootAttrs[DW_AT_addr_base] ?: rootAttrs[DW_AT_GNU_addr_base]).asOffset()
        val rngBase = rootAttrs[DW_AT_rnglists_base].asOffset()
        val ctx = CuContext(cuBuf, version, dwarf64, unitType, unitStart, unitLength.toInt(),
            addressSize, strBase, addrBase, rngBase, isDwo, sections)
        // Re-read root attrs with full context (to resolve strx/addrx).
        cuBuf.seek(rootStart)
        cuBuf.uleb()
        val rootAttrsFull = LinkedHashMap<Int, AttrValue>()
        for ((name, form, implicit) in rootDecl.attrs) {
            rootAttrsFull[name] = FormReader.read(strings, ctx, cuBuf, form, implicit, cuIssues)
        }

        val dies = mutableListOf<DieRecord>()
        dies += DieRecord(unitStart, rootDecl.tag, -1, 0, rootAttrsFull)
        var parseError: ParseException? = null
        try {
            readDies(ctx, cuBuf, abbrev, unitStart, depth = 1, parent = unitStart, dies, cuIssues)
        } catch (e: ParseException) {
            parseError = e
            cuIssues += ParseIssue("CU@$unitStart", "DIE parse truncated: ${e.message}", "error")
        }

        // Resolve ranges for every DIE that can carry code ranges.
        val resolver = RangeResolver(ctx, cuIssues)
        val rootLow = (rootAttrsFull[DW_AT_low_pc] as? AttrValue.Addr)?.v
        for (die in dies) {
            die.ranges = resolver.resolve(die, rootLow ?: 0L)
        }
        val rootRanges = dies.first().ranges

        val name = strings.resolve(rootAttrsFull[DW_AT_name], ctx)
        val compDir = strings.resolve(rootAttrsFull[DW_AT_comp_dir], ctx)
        val dwoId = resolveDwoId(rootAttrsFull)

        // Line program.
        val lineTable = (rootAttrsFull[DW_AT_stmt_list] as? AttrValue.SecOffset)?.let { so ->
            val secName = if (isDwo) ".debug_line.dwo" else ".debug_line"
            val lineBytes = sections.bytes(secName)
            try {
                LineProgramParser(sections, cuIssues).parse(so.offset, lineBytes, addressSize)
            } catch (e: ParseException) {
                cuIssues += ParseIssue("line@0x${so.offset.toString(16)}", e.message ?: "line parse error", "error")
                null
            }
        }

        // Resolve human-readable names now while the CU context (strx bases)
        // is available; abstract_origin/specification refs are followed with a
        // hop limit.
        resolveNames(dies, strings, ctx, lineTable, cuIssues)

        // Advance outer cursor to cuEnd regardless of inner truncation.
        buf.seek(cuEnd)
        return CuInfo(unitStart.toLong(), version, dwarf64, unitType, isDwo, dwoId,
            compDir, name, rootLow, rootRanges, dies, lineTable, cuIssues)
    }

    private fun resolveDwoId(attrs: Map<Int, AttrValue>): Long? {
        val v = attrs[DW_AT_dwo_id] ?: attrs[DW_AT_GNU_dwo_id] ?: return null
        return when (v) {
            is AttrValue.Addr -> v.v
            is AttrValue.Num -> v.v
            is AttrValue.UNum -> v.v.toLong()
            else -> null
        }
    }

    private fun readDies(ctx: CuContext, buf: Buf, abbrev: AbbrevTable, cuOffset: Int,
                         depth: Int, parent: Int, out: MutableList<DieRecord>,
                         issues: MutableList<ParseIssue>) {
        if (depth > Limits.MAX_DEPTH) throw ParseException("DIE nesting exceeds ${Limits.MAX_DEPTH}")
        var curParent = parent
        var curDepth = depth
        while (buf.pos < buf.size) {
            if (out.size >= Limits.MAX_DIES_PER_CU) {
                issues += ParseIssue("CU@$cuOffset", "DIE cap ${Limits.MAX_DIES_PER_CU} reached", "warn")
                return
            }
            val dieStart = ctx.cuStart + buf.pos
            val code = buf.uleb().toLong()
            if (code == 0L) {
                // End of children at curDepth: next sibling belongs to the
                // parent at curDepth-1.
                if (curDepth <= 1) return
                curDepth--
                // Walk to the last DIE at the new depth; its parent is our parent.
                val parentDie = out.lastOrNull { it.depth == curDepth - 1 }
                curParent = parentDie?.offset ?: ctx.cuStart
                continue
            }
            val decl = abbrev.decls[code]
                ?: throw ParseException("unknown abbrev code $code at 0x${dieStart.toString(16)}")
            val attrs = LinkedHashMap<Int, AttrValue>()
            for ((name, form, implicit) in decl.attrs) {
                attrs[name] = FormReader.read(strings, ctx, buf, form, implicit, issues)
            }
            val rec = DieRecord(dieStart, decl.tag, curParent, curDepth, attrs)
            out += rec
            if (decl.hasChildren) {
                curDepth++
                curParent = dieStart
            }
        }
    }

    private fun resolveNames(dies: List<DieRecord>, strings: StringTables, ctx: CuContext,
                             line: LineTable?, issues: MutableList<ParseIssue>) {
        val byOff = dies.associateBy { it.offset }
        fun direct(d: DieRecord): String? {
            val v = d.attr(DW_AT_name) ?: d.attr(DW_AT_linkage_name) ?: d.attr(DW_AT_MIPS_linkage_name)
            return v?.let { strings.resolve(it, ctx) }
        }
        for (d in dies) {
            d.resolvedName = direct(d)
            d.linkageName = d.attr(DW_AT_linkage_name)?.let { strings.resolve(it, ctx) }
            val callFile = (d.attr(DW_AT_call_file) as? AttrValue.Num)?.v?.toInt()
            if (callFile != null && line != null) {
                d.callFileResolved = line.resolveFile(callFile.coerceAtLeast(0))
            }
        }
        // Follow abstract_origin / specification for unnamed inlined instances.
        for (d in dies) {
            if (d.resolvedName != null) continue
            val ref = d.attr(DW_AT_abstract_origin) ?: d.attr(DW_AT_specification) ?: continue
            if (ref is AttrValue.Ref) {
                var hops = 0
                var cur = byOff[ref.offset]
                while (cur != null && cur.resolvedName == null && hops < Limits.MAX_REF_HOPS) {
                    val nxt = cur.attr(DW_AT_abstract_origin) ?: cur.attr(DW_AT_specification)
                    if (nxt is AttrValue.Ref) { cur = byOff[nxt.offset]; hops++ } else break
                }
                d.resolvedName = cur?.resolvedName
            }
        }
        for (d in dies) if (d.resolvedName == null &&
            (d.tag == DW_TAG_subprogram || d.tag == DW_TAG_inlined_subroutine)) {
            d.resolvedName = "<anonymous ${d.tagName}>"
        }
    }
}
