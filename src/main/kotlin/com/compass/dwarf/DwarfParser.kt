package com.compass.dwarf

class DwarfParser(private val sections: Map<String, ByteArray>, private val elf: ElfSummary, private val littleEndian: Boolean) {
    private val warnings = mutableListOf<String>()
    private val abbrev = AbbrevTable(sectionCursor(".debug_abbrev"))
    private val info = sectionCursor(".debug_info")!!

    fun parse(): DebugDocument {
        val cus = mutableListOf<CompilationUnit>()
        if (info == null) return DebugDocument(elf, emptyList(), listOf("Missing .debug_info"))
        while (info.remaining() > 0) {
            val start = info.absolutePosition()
            try {
                parseUnit(start, cus)
            } catch (e: DwarfParseException) {
                warnings += "CU at 0x${start.toString(16)} partially ignored: ${e.message}"
                if (info.remaining() == 0) break
                break
            }
        }
        return DebugDocument(elf, cus, warnings.distinct())
    }

    private fun parseUnit(start: Long, cus: MutableList<CompilationUnit>) {
        info!!.seek(start)
        val initial = info.u32()
        val dwarf64 = initial == 0xffffffffL
        val length = if (dwarf64) info.u64() else initial
        val end = start + 4 + (if (dwarf64) 12 else 4) + length
        if (length <= 0 || end > info.size.toLong()) throw DwarfParseException("Bad CU length")
        val version = info.u16()
        if (version !in 2..5) throw DwarfParseException("Unsupported DWARF version $version")
        val unitType = if (version >= 5) info.u8() else 1
        val addressSize = if (version >= 5) info.u8() else info.u32().toInt()
        val abbrevOffset = if (dwarf64) info.u64() else info.u32()
        var segmentSize = 0
        var dwoId: Long? = null
        if (version < 5) segmentSize = info.u8()
        if (version >= 5 && unitType == DwarfConst.DW_UT_SKELETON) dwoId = info.u64()
        if (version >= 5 && unitType == DwarfConst.DW_UT_SPLIT_COMPILE) dwoId = info.u64()
        val table = abbrev.read(abbrevOffset) ?: throw DwarfParseException("Missing abbrev table at $abbrevOffset")
        val context = UnitContext(start, end, dwarf64, version, unitType, addressSize, segmentSize, table)
        val dies = readDies(context)
        val root = dies.firstOrNull()
        val ranges = RangeResolver(sections, context, dies, littleEndian).resolve()
        val lineOffset = root?.number(DwarfConst.DW_AT_STMT_LIST) ?: 0L
        val line = runCatching {
            LineProgramReader(sections, context, lineOffset, littleEndian).parse()
        }.onFailure { warnings += "Line program for CU at 0x${start.toString(16)} ignored: ${it.message}" }.getOrNull()
        val dwoName = root?.text(DwarfConst.DW_AT_DWO_NAME) ?: root?.text(DwarfConst.DW_AT_GNU_DWO_NAME)
        val isSkeleton = unitType == DwarfConst.DW_UT_SKELETON || dwoName != null && !context.splitUnit
        val isSplit = unitType == DwarfConst.DW_UT_SPLIT_COMPILE || context.splitUnit
        if (dwoName != null && !hasSplitPeer(dwoName, dwoId, cus)) warnings += "Split DWARF companion for '${dwoName}' was not imported"
        cus += CompilationUnit(
            start, length, version, dwarf64, unitType, addressSize, segmentSize, abbrevOffset,
            root?.text(DwarfConst.DW_AT_NAME), root?.text(DwarfConst.DW_AT_COMP_DIR),
            dwoName, dwoId ?: root?.number(DwarfConst.DW_AT_GNU_DWO_ID), lineOffset,
            isSkeleton, isSplit, ranges, line, dies, context.warnings.toList()
        )
        info.seek(end)
    }

    private fun hasSplitPeer(name: String, id: Long?, cus: List<CompilationUnit>): Boolean {
        if (id != null && cus.any { it.dwoId == id && it.isSplit }) return true
        return sections.keys.any { it.endsWith(name.substringAfterLast('/')) }
    }

    private fun readDies(ctx: UnitContext): List<DieNode> {
        val out = mutableListOf<DieNode>()
        val stack = ArrayDeque<Int>()
        while (info!!.absolutePosition() < ctx.end) {
            val offset = info.absolutePosition()
            val depth = stack.size
            val code = info.uleb()
            if (code == 0L) {
                stack.removeLastOrNull()
                continue
            }
            val entry = ctx.abbrev[code] ?: throw DwarfParseException("Unknown abbrev code $code")
            val attrs = entry.attributes.map { readAttribute(ctx, it) }
            val node = DieNode(offset, entry.tag, depth, stack.lastOrNull()?.let { out[it].offset }, attrs)
            out += node
            stack.addLast(out.lastIndex)
            if (!entry.hasChildren) stack.removeLast()
            if (out.size > 200_000) throw DwarfParseException("Too many DIEs")
        }
        return out
    }

    private fun readAttribute(ctx: UnitContext, spec: AbbrevAttribute): DieAttribute {
        val form = when (spec.form) {
            DwarfConst.DW_FORM_INDIRECT -> info!!.uleb().toInt()
            else -> spec.form
        }
        val value = readForm(ctx, form, spec.implicit)
        return DieAttribute(spec.attr, form, value)
    }

    private fun readForm(ctx: UnitContext, form: Int, implicit: Long?): AttrValue = when (form) {
        DwarfConst.DW_FORM_ADDR -> AttrValue.AddressValue(readAddress(ctx.addressSize))
        DwarfConst.DW_FORM_DATA1, DwarfConst.DW_FORM_REF1, DwarfConst.DW_FORM_ADDRX1, DwarfConst.DW_FORM_STRX1 -> AttrValue.NumberValue(info!!.u8().toLong())
        DwarfConst.DW_FORM_DATA2, DwarfConst.DW_FORM_REF2, DwarfConst.DW_FORM_ADDRX2, DwarfConst.DW_FORM_STRX2 -> AttrValue.NumberValue(info.u16().toLong())
        DwarfConst.DW_FORM_DATA4, DwarfConst.DW_FORM_REF4, DwarfConst.DW_FORM_ADDRX4, DwarfConst.DW_FORM_STRX4 -> AttrValue.NumberValue(info.u32())
        DwarfConst.DW_FORM_DATA8, DwarfConst.DW_FORM_REF8, DwarfConst.DW_FORM_REF_SIG8, DwarfConst.DW_FORM_ADDRX, DwarfConst.DW_FORM_STRX -> AttrValue.NumberValue(info!!.u64())
        DwarfConst.DW_FORM_UDATA, DwarfConst.DW_FORM_REF_UDATA, DwarfConst.DW_FORM_SEC_OFFSET, DwarfConst.DW_FORM_ADDRX3, DwarfConst.DW_FORM_STRX3 -> AttrValue.NumberValue(info.uleb())
        DwarfConst.DW_FORM_SDATA -> AttrValue.NumberValue(info.sleb())
        DwarfConst.DW_FORM_STRING -> AttrValue.TextValue(info.cString())
        DwarfConst.DW_FORM_STRP -> readString(if (ctx.dwarf64) info.u64() else info.u32(), ".debug_str")
        DwarfConst.DW_FORM_LINE_STRP -> readString(if (ctx.dwarf64) info.u64() else info.u32(), ".debug_line_str")
        DwarfConst.DW_FORM_FLAG -> AttrValue.BooleanValue(info.u8() != 0)
        DwarfConst.DW_FORM_FLAG_PRESENT -> AttrValue.BooleanValue(true)
        DwarfConst.DW_FORM_IMPLICIT_CONST -> AttrValue.NumberValue(implicit ?: 0)
        DwarfConst.DW_FORM_BLOCK1 -> readBlock(info.u8())
        DwarfConst.DW_FORM_BLOCK2 -> readBlock(info.u16())
        DwarfConst.DW_FORM_BLOCK4 -> readBlock(info.u32().toInt())
        DwarfConst.DW_FORM_BLOCK -> readBlock(info.uleb().toInt())
        DwarfConst.DW_FORM_DATA16 -> readBlock(16)
        DwarfConst.DW_FORM_EXPRLOC -> readBlock(info.uleb().toInt())
        DwarfConst.DW_FORM_REF_ADDR -> AttrValue.ReferenceValue(if (ctx.dwarf64) info.u64() else info.u32())
        DwarfConst.DW_FORM_RNGLISTX, DwarfConst.DW_FORM_LOC_LISTX -> AttrValue.NumberValue(info.uleb())
        else -> throw DwarfParseException("Unknown DWARF form 0x${form.toString(16)}")
    }

    private fun readAddress(size: Int): Long = when (size) {
        1 -> info!!.u8().toLong(); 2 -> info.u16().toLong(); 4 -> info.u32(); 8 -> info.u64()
        else -> throw DwarfParseException("Bad address size $size")
    }

    private fun readBlock(size: Int): AttrValue.BytesValue {
        if (size < 0 || size > 1_000_000) throw DwarfParseException("Block too large")
        return AttrValue.BytesValue(info!!.bytes(size))
    }

    private fun readString(offset: Long, sectionName: String): AttrValue.TextValue {
        val section = sectionCursor(sectionName) ?: throw DwarfParseException("Missing $sectionName")
        return AttrValue.TextValue(section.cStringAt(offset))
    }

    private fun sectionCursor(name: String): BinaryCursor? = sections[name]?.let { BinaryCursor(it, 0, littleEndian) }
}

data class UnitContext(
    val start: Long, val end: Long, val dwarf64: Boolean, val version: Int,
    val unitType: Int, val addressSize: Int, val segmentSize: Int,
    val abbrev: Map<Long, AbbrevEntry>, val warnings: MutableList<String> = mutableListOf()
) {
    val splitUnit get() = unitType == DwarfConst.DW_UT_SPLIT_COMPILE || unitType == DwarfConst.DW_UT_SPLIT_TYPE
}
