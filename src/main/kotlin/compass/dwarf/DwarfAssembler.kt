package compass.dwarf

import compass.elf.Reader
import compass.model.CompilationUnit
import compass.model.DieNode
import compass.model.DieRange
import compass.model.LineSequence
import compass.model.SectionWarning

class Assembly(
    val cus: MutableList<CompilationUnit> = mutableListOf(),
    val dies: MutableList<DieNode> = mutableListOf(),
    val ranges: MutableList<DieRange> = mutableListOf(),
    val sequences: MutableList<LineSequence> = mutableListOf(),
    val warnings: MutableList<SectionWarning> = mutableListOf(),
)

/**
 * Turns raw DWARF sections into the domain model. Pure/local parsing; never
 * invokes addr2line or any system debugger. Main and split (.dwo) bundles
 * are assembled separately and merged by [DwarfImporter].
 */
class DwarfAssembler(
    private val sections: DebugSections,
    private val endian: compass.model.Endian,
    private val isSplit: Boolean,
    private val sourceLabel: String,
) {
    private val warningText = ArrayList<String>()

    private class Built(
        val unit: ParsedUnit,
        val cu: CompilationUnit,
        val rows: MutableList<Row>,
    )
    private class Row(val raw: RawDie, val die: DieNode, val rr: MutableList<RawRange>)

    fun assemble(): Assembly {
        val out = Assembly()
        val abbrevName = when {
            isSplit && !sections.require(".debug_abbrev.dwo").isEmpty() -> ".debug_abbrev.dwo"
            else -> ".debug_abbrev"
        }
        val infoName = if (isSplit) ".debug_info.dwo" else ".debug_info"
        val abbrevs = AbbrevTables(sections.require(abbrevName), endian.big)
        val units = InfoParser.parseSection(sections.require(infoName), endian, sections,
            abbrevs, isSplit, warningText)

        var dieSeq = 0L
        var rangeSeq = 0L
        var seqSeq = 0L
        val built = ArrayList<Built>()

        for (unit in units) {
            val root = unit.dies.firstOrNull() ?: continue
            val cu = CompilationUnit(
                id = out.cus.size.toLong(),
                offset = unit.header.offset,
                version = unit.header.version,
                dwarf64 = unit.header.dwarf64,
                compDir = text(root, DW.AT_comp_dir),
                name = text(root, DW.AT_name),
                language = const(root, DW.AT_language)?.let(DW::languageName),
                lowPc = address(root, DW.AT_low_pc),
                isSkeleton = root.tag == DW.TAG_skeleton_unit ||
                    text(root, DW.AT_dwo_name) != null || text(root, DW.AT_GNU_dwo_name) != null,
                dwoName = text(root, DW.AT_dwo_name) ?: text(root, DW.AT_GNU_dwo_name),
                dwoId = const(root, DW.AT_dwo_id),
                skeletonForId = null,
                producer = text(root, DW.AT_producer),
            )
            out.cus.add(cu)

            val offToId = HashMap<Long, Long>()
            val rows = ArrayList<Row>()
            for (raw in unit.dies) {
                val interesting = raw.depth == 0 ||
                    raw.tag == DW.TAG_subprogram || raw.tag == DW.TAG_inlined_subroutine
                if (!interesting) continue
                val highAttr = raw.attrs[DW.AT_high_pc]
                val die = DieNode(
                    id = dieSeq++,
                    cuId = cu.id,
                    bundle = sourceLabel,
                    offset = raw.offset,
                    tag = raw.tag,
                    tagName = DW.tagName(raw.tag),
                    depth = raw.depth,
                    parentId = raw.parentOffset?.let { offToId[it] },
                    name = text(raw, DW.AT_name),
                    linkageName = text(raw, DW.AT_linkage_name),
                    lowPc = address(raw, DW.AT_low_pc),
                    highPc = (highAttr as? FormValue.Constant)?.v ?: (highAttr as? FormValue.Address)?.v,
                    highPcIsAddress = highAttr is FormValue.Address,
                    rangesOffset = (raw.attrs[DW.AT_ranges] as? FormValue.Offset)?.v,
                    rangesBase = (raw.attrs[DW.AT_rnglists_base] as? FormValue.Offset)?.v,
                    inlineValue = (const(raw, DW.AT_inline) ?: 0L).toInt(),
                    callFile = filePlaceholder(raw, DW.AT_call_file, cu),
                    callLine = (const(raw, DW.AT_call_line) ?: 0L).toInt(),
                    declFile = filePlaceholder(raw, DW.AT_decl_file, cu),
                    declLine = (const(raw, DW.AT_decl_line) ?: 0L).toInt(),
                    abstractOrigin = (raw.attrs[DW.at_abstract_origin] as? FormValue.Reference)?.globalOffset,
                    specification = (raw.attrs[DW.at_specification] as? FormValue.Reference)?.globalOffset,
                    external = (raw.attrs[DW.AT_external] as? FormValue.Flag)?.v ?: false,
                )
                offToId[raw.offset] = die.id
                out.dies.add(die)
                rows.add(Row(raw, die, ArrayList()))
            }
            built.add(Built(unit, cu, rows))
        }

        val globalByKey = HashMap<Long, DieNode>()
        for (b in built) for (row in b.rows) globalByKey[b.unit.header.offset + row.die.offset] = row.die

        for (b in built) {
            val hdr = b.unit.header
            for (row in b.rows) buildDieRanges(b, row, out, hdr, rangeSeq).also { add ->
                rangeSeq += add
            }
            buildLinePrograms(b, out) { seqSeq++ }
        }

        warningText.forEach { out.warnings.add(SectionWarning(sourceLabel, null, it)) }
        return out
    }

    /** Adds DieRange rows for one DIE; returns how many were appended. */
    private fun buildDieRanges(b: Built, row: Row, out: Assembly, hdr: CuHeader, startId: Long): Int {
        val die = row.die
        val raw = row.raw
        val low = die.lowPc
        val high = die.highPc
        var source = "high_pc"
        if (low != null && high != null) {
            val end = if (die.highPcIsAddress) high else low + high
            row.rr.add(RawRange(0L, low, end))
        }
        when (val attr = raw.attrs[DW.AT_ranges]) {
            is FormValue.Offset -> {
                source = if (hdr.version >= 5 && sections[".debug_rnglists"] != null) "rnglists5" else "rnglist"
                runCatching {
                    if (source == "rnglists5") {
                        row.rr.addAll(parseV5Direct(hdr, attr.v))
                    } else {
                        row.rr.addAll(RangesV4.parse(sections.require(".debug_ranges"), attr.v,
                            endian, hdr.addrSize, hdr.dwarf64, low ?: b.cu.lowPc ?: 0L))
                    }
                }.onFailure {
                    warningText.add("DIE@0x${"%x".format(hdr.offset + raw.offset)} 范围解析失败: ${it.message}")
                }
            }
            is FormValue.RngListIndex -> {
                source = "rnglists5"
                runCatching { row.rr.addAll(parseV5Indexed(b, hdr, die, attr.index)) }
                    .onFailure {
                        warningText.add("DIE@0x${"%x".format(hdr.offset + raw.offset)} rnglistx 失败: ${it.message}")
                    }
            }
            else -> {}
        }
        row.rr.forEachIndexed { idx, rr ->
            out.ranges.add(DieRange(startId + idx, die.id, b.cu.id, rr.start, rr.end, source, idx))
        }
        return row.rr.size
    }

    private fun parseV5Direct(hdr: CuHeader, listOffset: Long): List<RawRange> {
        val data = sections.require(".debug_rnglists")
        return RngListsV5.parse(data, listOffset, endian, hdr.addrSize, 0) {
            throw IllegalStateException("base_addressx in a direct-offset rnglist")
        }
    }

    private fun parseV5Indexed(b: Built, hdr: CuHeader, die: DieNode, index: Long): List<RawRange> {
        val data = sections.require(".debug_rnglists")
        val tableBase = die.rangesBase
            ?: throw IllegalStateException("DW_FORM_rnglistx without DW_AT_rnglists_base")
        val headerPreamble = if (hdr.dwarf64) 20 else 12
        val headerStart = tableBase - headerPreamble
        val h = RngListsV5.header(data, headerStart, endian)
        if (index < 0 || index >= h.offsetEntryCount)
            throw IndexOutOfBoundsException("rnglistx $index >= ${h.offsetEntryCount}")
        val er = Reader(data, endian)
        er.seek((h.offsetTableStart + index * h.offsetSize).toInt())
        val rel = if (h.offsetSize == 4) er.u32() else er.u64()
        val root = b.unit.dies.first()
        val addrBase = (root.attrs[DW.AT_addr_base] as? FormValue.Offset)?.v
            ?: (root.attrs[DW.AT_GNU_addr_base] as? FormValue.Offset)?.v ?: 0L
        return RngListsV5.parse(data, headerStart + rel, endian, h.addrSize, h.segmentSize) { idx2 ->
            AddrTable.readAddress(sections, endian, addrBase, idx2, h.addrSize)
        }
    }

    private fun buildLinePrograms(b: Built, out: Assembly, nextSeqId: () -> Long) {
        val root = b.unit.dies.firstOrNull() ?: return
        val stmtList = (root.attrs[DW.AT_stmt_list] as? FormValue.Offset)?.v ?: return
        val lineSection = when {
            isSplit && sections[".debug_line.dwo"] != null -> ".debug_line.dwo"
            sections[".debug_line"] != null -> ".debug_line"
            isSplit -> ".debug_line.dwo"
            else -> ".debug_line"
        }
        val lp = runCatching {
            LineProgram.parse(sections, lineSection, stmtList, endian, b.unit.header.addrSize,
                b.cu.name, b.cu.compDir)
        }.getOrElse {
            warningText.add("CU@0x${"%x".format(b.unit.header.offset)} line program: ${it.message}")
            return
        } ?: return
        for (ps in lp.sequences) {
            val id = nextSeqId()
            out.sequences.add(LineSequence(id, b.cu.id, lp.version,
                ps.startAddress, ps.endAddress, ps.rows))
        }
    }

    private fun text(d: RawDie, a: Int): String? = (d.attrs[a] as? FormValue.Text)?.v
    private fun const(d: RawDie, a: Int): Long? = (d.attrs[a] as? FormValue.Constant)?.v
    private fun address(d: RawDie, a: Int): Long? = (d.attrs[a] as? FormValue.Address)?.v
    private fun filePlaceholder(d: RawDie, a: Int, cu: CompilationUnit): String? {
        val idx = const(d, a) ?: return null
        return if (idx == 0L) cu.name else "file#$idx"
    }
}
