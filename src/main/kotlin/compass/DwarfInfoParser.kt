package compass

import java.math.BigInteger

object DwarfInfoParser {
    private const val DW_UT_compile = 1
    private const val DW_UT_skeleton = 4
    private const val DW_UT_split_compile = 5
    private const val DW_UT_partial = 3
    private const val DW_UT_type = 2
    private const val DW_UT_split_type = 6
    private const val MAX_NODES = 500_000
    private const val MAX_UNIT_SIZE = 100_000_000L

    fun parse(elf: ElfFile): DwarfInfo {
        val warnings = mutableListOf<Warning>()
        val infoBytes = elf.sectionBytes(".debug_info")
        val abbrevBytes = elf.sectionBytes(".debug_abbrev")
        val lineBytes = elf.sectionBytes(".debug_line")
        val lineStrBytes = elf.sectionBytes(".debug_line_str")
        val strBytes = elf.sectionBytes(".debug_str")
        val rangesBytes = elf.sectionBytes(".debug_ranges")
        val rnglistsBytes = elf.sectionBytes(".debug_rnglists")
        val split = elf.section(".debug_info.dwo") != null
        val units = mutableListOf<DwarfUnit>()
        if (infoBytes.isNotEmpty()) {
            val reader = ByteReader(infoBytes)
            var ordinal = 0
            while (reader.remaining() > 0) {
                val unitStart = reader.pos
                try {
                    val header = readUnitHeader(reader, elf.endian)
                    val unitEnd = (unitStart + header.totalLength).coerceAtMost(infoBytes.size)
                    val abbrev = runCatching { AbbrevParser.parseTable(abbrevBytes, header.abbrevOffset) }.getOrElse {
                        throw CursorException("abbreviation table at ${header.abbrevOffset} is unreadable: ${it.message}")
                    }
                    val nodes = mutableListOf<DwarfNode>()
                    val depthStack = ArrayDeque<Long>()
                    var nodeOrdinal = 0
                    var lowPc: Long? = null
                    var lineOffset: Long? = null
                    var name: String? = null
                    var compDir: String? = null
                    var dwoName: String? = null
                    var dwoId: Long? = null
                    var rangeOffset: Long? = null
                    var rnglistsBase: Long? = null
                    while (reader.pos < unitEnd && nodeOrdinal < MAX_NODES) {
                        val dieStart = reader.pos
                        val code = reader.uleb()
                        if (code == 0L) {
                            if (depthStack.isNotEmpty()) depthStack.removeLast()
                            if (depthStack.isEmpty()) break
                            continue
                        }
                        val abbr = abbrev[code] ?: throw CursorException("abbreviation $code missing at CU ${header.offset}", dieStart.toLong())
                        val attrs = mutableListOf<DieAttr>()
                        val values = linkedMapOf<Int, AttrValue>()
                        var unknown: UnknownFormException? = null
                        for (attrSpec in abbr.attributes) {
                            val start = reader.pos
                            try {
                                val formValue = if (attrSpec.form == DwarfConstants.DW_FORM_implicit_const)
                                    FormValue(AttrValue("implicit_const", BigInteger.valueOf(attrSpec.implicit ?: 0)))
                                else FormReader.read(reader, attrSpec.form, header.version, header.addressSize, elf.endian)
                                val raw = formValue.value
                                val resolved = resolveString(raw, attrSpec.attr, strBytes, lineStrBytes, elf.endian, header.version)
                                attrs += DieAttr(DwarfConstants.attrName(attrSpec.attr), attrSpec.attr, attrSpec.form, resolved)
                                values[attrSpec.attr] = resolved
                            } catch (error: UnknownFormException) {
                                unknown = error
                                warnings += Warning("dwarf", "unknown form 0x${error.form.toString(16)} in DIE $dieStart; CU tail treated as untrusted", dieStart.toLong(), "error")
                                break
                            }
                        }
                        if (unknown != null) break
                        val depth = depthStack.size
                        val parent = depthStack.lastOrNull()
                        val low = values[DwarfConstants.DW_AT_low_pc]?.raw?.toLong()
                        val highAttr = values[DwarfConstants.DW_AT_high_pc]?.raw?.toLong()
                        val rangesAttr = values[DwarfConstants.DW_AT_ranges]?.raw?.toLong()
                        val ownRangeOffset = rangesAttr ?: if (values[DwarfConstants.DW_AT_rnglists_base] != null) values[DwarfConstants.DW_AT_rnglists_base]?.raw?.toLong() else null
                        val dieRanges = if (low != null && highAttr != null) {
                            val end = if (values[DwarfConstants.DW_AT_high_pc]?.form in setOf("addr")) low + highAttr else highAttr
                            listOf(RangeEdge(low, if (end < low) low else end))
                        } else if (low != null) listOf(RangeEdge(low, low))
                        else if (rangesAttr != null) readDwarfRanges(elf, header, rangesAttr, low ?: 0L, rangesBytes, rnglistsBytes, warnings, dieStart)
                        else emptyList()
                        val node = DwarfNode(
                            ordinal = nodeOrdinal++,
                            offset = dieStart.toLong(),
                            tag = abbr.tag,
                            tagName = DwarfConstants.tagName(abbr.tag),
                            depth = depth,
                            parentOffset = parent,
                            name = values[DwarfConstants.DW_AT_name]?.text,
                            linkageName = values[DwarfConstants.DW_AT_linkage_name]?.text ?: values[0x6f]?.text,
                            lowPc = low,
                            highPc = highAttr,
                            rangesOffset = ownRangeOffset,
                            callFile = values[DwarfConstants.DW_AT_call_file]?.raw?.toInt(),
                            callLine = values[DwarfConstants.DW_AT_call_line]?.raw?.toInt(),
                            inlineValue = values[DwarfConstants.DW_AT_inline]?.raw?.toInt(),
                            abstractOrigin = values[DwarfConstants.DW_AT_abstract_origin]?.raw?.toLong(),
                            specification = values[DwarfConstants.DW_AT_specification]?.raw?.toLong(),
                            attributes = attrs,
                            ranges = dieRanges
                        )
                        nodes += node
                        if (depth == 0) {
                            lowPc = low
                            lineOffset = values[DwarfConstants.DW_AT_stmt_list]?.raw?.toLong()
                            name = values[DwarfConstants.DW_AT_name]?.text
                            compDir = values[DwarfConstants.DW_AT_comp_dir]?.text
                            dwoName = values[DwarfConstants.DW_AT_dwo_name]?.text ?: values[DwarfConstants.DW_AT_GNU_dwo_name]?.text
                            dwoId = values[DwarfConstants.DW_AT_dwo_id]?.raw?.toLong() ?: values[DwarfConstants.DW_AT_GNU_dwo_id]?.raw?.toLong()
                            rangeOffset = ownRangeOffset
                            rnglistsBase = values[DwarfConstants.DW_AT_rnglists_base]?.raw?.toLong()
                        }
                        if (abbr.hasChildren) depthStack.addLast(dieStart.toLong())
                        while (reader.pos > unitEnd) throw CursorException("DIE crossed CU boundary")
                    }
                    reader.pos = unitEnd.toInt()
                    val splitStatus = when {
                        split -> "split-package"
                        dwoName != null -> "skeleton-missing-dwo"
                        else -> "complete"
                    }
                    units += DwarfUnit(
                        ordinal = ordinal++, offset = header.offset, size = header.totalLength, headerSize = header.headerSize,
                        version = header.version, unitType = header.unitType, addressSize = header.addressSize, segmentSize = header.segmentSelectorSize,
                        abbrevOffset = header.abbrevOffset, lineOffset = lineOffset, lowPc = lowPc, name = name, compDir = compDir,
                        dwoName = dwoName, dwoId = dwoId, splitStatus = splitStatus, rangeOffset = rangeOffset, nodes = resolveReferences(nodes)
                    )
                } catch (error: Exception) {
                    warnings += Warning("cu", "compilation unit at $unitStart isolated: ${error.message}", unitStart.toLong(), "error")
                    reader.pos = recoverUnit(infoBytes, unitStart, elf.endian)
                    if (reader.pos <= unitStart) break
                }
            }
        } else warnings += Warning("dwarf", ".debug_info is absent", null, "info")
        val lines = if (lineBytes.isNotEmpty()) parseAllLines(elf, units, lineStrBytes, warnings) else emptyMap()
        return DwarfInfo(units, lines, warnings)
    }

    private data class UnitHeader(val offset: Long, val totalLength: Long, val version: Int, val unitType: Int, val addressSize: Int, val segmentSelectorSize: Int, val abbrevOffset: Long, val headerSize: Int)

    private fun readUnitHeader(reader: ByteReader, endian: Int): UnitHeader {
        val offset = reader.pos.toLong()
        val first = reader.u32(endian)
        val is64 = first == 0xffffffffL
        val length = if (is64) reader.u64(endian) else first
        if (length < 1 || length > MAX_UNIT_SIZE) throw CursorException("invalid CU length $length", offset)
        val version = reader.u16(endian)
        if (version !in 2..5) throw CursorException("unsupported DWARF version $version")
        var unitType = if (version >= 5) reader.u8() else DW_UT_compile
        var addressSize = if (version >= 5) reader.u8() else 4
        var segmentSelectorSize = 0
        val abbrevOffset: Long
        if (version < 5) {
            abbrevOffset = reader.u32(endian)
            addressSize = reader.u8()
        } else {
            abbrevOffset = when (reader.u8()) {
                4 -> reader.u32(endian)
                8 -> reader.u64(endian)
                else -> throw CursorException("unsupported debug_info offset size")
            }
            if (unitType == DW_UT_skeleton || unitType == DW_UT_split_compile) reader.readBytes(8)
            if (unitType == DW_UT_type || unitType == DW_UT_split_type) reader.readBytes(if (is64) 8 else 4)
        }
        return UnitHeader(offset, length + (if (is64) 12 else 4), version, unitType, addressSize, segmentSelectorSize, abbrevOffset, reader.pos - offset.toInt())
    }

    private fun resolveString(value: AttrValue, attr: Int, strings: ByteArray, lineStrings: ByteArray, endian: Int, version: Int): AttrValue {
        if (value.text != null) return value
        val bytes = if (value.form == "line_strp") lineStrings else strings
        return when (value.form) {
            "strp", "line_strp" -> value.copy(text = runCatching { ByteReader(bytes).stringAt(value.raw?.toLong() ?: -1) }.getOrElse { "<invalid-string>" })
            else -> value
        }
    }

    private fun readDwarfRanges(elf: ElfFile, header: UnitHeader, offset: Long, low: Long, ranges: ByteArray, rnglists: ByteArray, warnings: MutableList<Warning>, dieStart: Int): List<RangeEdge> {
        return try {
            if (header.version >= 5 && elf.section(".debug_rnglists") != null) {
                val tableHeader = findEnclosingV5Table(rnglists, offset, elf.endian) ?: 0L
                RangesParser.parseV5(rnglists, tableHeader, offset - (tableHeader + RangesParser.parseV5Header(rnglists, tableHeader, elf.endian).entriesOffset), low, header.addressSize, header.segmentSelectorSize, elf.endian)
            } else RangesParser.parseV4(ranges, offset, low, header.addressSize, elf.endian, header.segmentSelectorSize)
        } catch (error: Exception) {
            warnings += Warning("ranges", "DIE $dieStart ranges offset $offset unreadable: ${error.message}", dieStart.toLong(), "error")
            emptyList()
        }
    }

    private fun findEnclosingV5Table(bytes: ByteArray, targetOffset: Long, endian: Int): Long? {
        var pos = 0L
        while (pos < bytes.size) {
            val headerOffset = pos
            val result = runCatching {
                val reader = ByteReader(bytes); reader.pos = pos.toInt()
                val first = reader.u32(endian)
                val is64 = first == 0xffffffffL
                val length = if (is64) reader.u64(endian) else first
                val table = RangesParser.parseV5Header(bytes, headerOffset, endian)
                Triple(length, table.entriesOffset, headerOffset + 4 + (if (is64) 8 else 0) + length)
            }.getOrNull() ?: return null
            if (targetOffset in headerOffset until result.third) return headerOffset
            pos = result.third
        }
        return null
    }

    private fun resolveReferences(nodes: List<DwarfNode>): List<DwarfNode> {
        val byOffset = nodes.associateBy { it.offset }
        return nodes.map { node ->
            val origin = node.abstractOrigin?.let(byOffset::get) ?: node.specification?.let(byOffset::get)
            if (origin == null) node else node.copy(
                name = node.name ?: origin.name,
                linkageName = node.linkageName ?: origin.linkageName,
                ranges = node.ranges.ifEmpty { origin.ranges },
                callFile = node.callFile ?: origin.callFile,
                callLine = node.callLine ?: origin.callLine
            )
        }
    }

    private fun recoverUnit(bytes: ByteArray, failedStart: Int, endian: Int): Int {
        val first = runCatching { ByteReader(bytes).also { it.pos = failedStart }.u32(endian) }.getOrNull() ?: return bytes.size
        val length = if (first == 0xffffffffL) runCatching { ByteReader(bytes).also { it.pos = failedStart + 4 }.u64(endian) }.getOrNull() ?: return bytes.size else first
        val headerLen = if (first == 0xffffffffL) 12 else 4
        val next = failedStart + headerLen + length
        return if (next > failedStart && next <= bytes.size) next.toInt() else bytes.size
    }

    private fun parseAllLines(elf: ElfFile, units: List<DwarfUnit>, lineStrings: ByteArray, warnings: MutableList<Warning>): Map<Int, UnitLines> {
        return units.mapNotNull { unit ->
            unit.lineOffset?.let { offset ->
                val parsed = runCatching { LineProgramParser.parse(elf.sectionBytes(".debug_line"), offset, unit, elf.endian, lineStrings, elf.sectionBytes(".debug_str")) }
                    .getOrElse {
                        warnings += Warning("line", "CU ${unit.ordinal} line program isolated: ${it.message}", offset, "error")
                        null
                    }
                parsed?.let { unit.ordinal to it }
            }
        }.toMap()
    }
}
