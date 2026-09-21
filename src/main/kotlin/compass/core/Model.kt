package compass.core

import compass.dwarf.*
import compass.elf.ElfFile
import java.nio.ByteOrder

data class SectionInfo(
    val name: String,
    val size: Long,
    val sha256: String,
    val present: Boolean,
)

data class Scope(
    val dieOffset: Long,
    val tag: Int,
    val name: String?,
    val ranges: List<AddrRange>,
    val depth: Int,
)

data class InlineSite(
    val dieOffset: Long,
    val name: String?,
    val callFile: String?,
    val callLine: Long?,
    val callColumn: Long?,
    val ranges: List<AddrRange>,
    val depth: Int,
)

class CuModel(
    val index: Int,
    val offset: Long,
    val version: Int,
    val unitType: Int,
    val name: String,
    val compDir: String,
    val producer: String?,
    val dwoName: String?,
    val isolated: Boolean,
    val error: String?,
    val notes: List<String>,
    val lineVersion: Int?,
    val lineRows: List<LineRow>,
    val lineNotes: List<String>,
    val scopes: List<Scope>,
    val inlines: List<InlineSite>,
    val ranges: List<AddrRange>,
)

class DebugFileModel(
    val name: String,
    val elfClass: String,
    val sections: List<SectionInfo>,
    val cus: List<CuModel>,
    val notes: List<String>,
) {
    /** File-level trust assessment, surfaced with every query. */
    val trustNotes: List<String> = buildList {
        addAll(notes)
        for (cu in cus.filter { it.dwoName != null }) {
            add("CU '${cu.name}' 是 split DWARF (dwo='${cu.dwoName}')，未提供 .dwo 文件：" +
                "地址范围与骨架信息仍可信，名称/行号等细节可能缺失。")
        }
        for (cu in cus.filter { it.isolated }) {
            add("CU '${cu.name}' @0x${cu.offset.toString(16)} 被隔离 (${cu.error})：其结论不参与查询。")
        }
        for (cu in cus.filter { !it.isolated && it.lineVersion == null }) {
            add("CU '${cu.name}' 缺少可用行号表：仅地址范围结论可信。")
        }
    }
}

/** Ties ELF sections and DWARF parsers together into a queryable model. */
object ModelBuilder {

    fun build(name: String, elf: ElfFile): DebugFileModel {
        val order = elf.order
        val notes = mutableListOf<String>()
        val sectionInfos = elf.sections.map {
            SectionInfo(it.name, it.size, ElfFile.digest(elf.sectionBytes(it)), true)
        }

        val debugInfo = elf.sectionBytes(".debug_info")
        val debugAbbrev = elf.sectionBytes(".debug_abbrev")
        val debugLine = elf.sectionBytes(".debug_line")
        val debugStr = elf.sectionBytes(".debug_str")
        val debugLineStr = elf.sectionBytes(".debug_line_str")
        val debugAddr = elf.sectionBytes(".debug_addr")
        val debugStrOffsets = elf.sectionBytes(".debug_str_offsets")
        val debugRanges = elf.sectionBytes(".debug_ranges")
        val debugRnglists = elf.sectionBytes(".debug_rnglists")

        if (debugInfo == null) notes += "缺少 .debug_info：无法解析编译单元。"
        if (debugAbbrev == null && debugInfo != null) notes += "缺少 .debug_abbrev：所有 CU 被隔离。"

        val cus = mutableListOf<CuModel>()
        if (debugInfo != null) {
            val parser = DebugInfoParser(debugInfo, debugAbbrev, { version, addrSize, is64 ->
                FormContext(version, addrSize, order, debugStr, debugLineStr, debugAddr,
                    0, debugStrOffsets, 0, is64)
            }, order)
            val units = try { parser.parse() } catch (e: DwarfParseException) {
                notes += ".debug_info 解析中止: ${e.message}"; emptyList()
            }
            notes += parser.globalNotes
            units.forEachIndexed { idx, unit ->
                cus += buildCu(idx, unit, debugInfo, debugLine, debugRanges, debugRnglists, order)
            }
        }
        val elfClass = (if (elf.is64) "ELF64" else "ELF32") +
            (if (order == ByteOrder.LITTLE_ENDIAN) " LE" else " BE")
        return DebugFileModel(name, elfClass, sectionInfos, cus, notes)
    }

    private fun buildCu(
        idx: Int,
        unit: CompilationUnit,
        debugInfo: ByteArray,
        debugLine: ByteArray?,
        debugRanges: ByteArray?,
        debugRnglists: ByteArray?,
        order: ByteOrder,
    ): CuModel {
        val cuNotes = mutableListOf<String>()
        cuNotes += unit.notes
        val root = unit.roots.firstOrNull()
        val name = root?.name() ?: "<unnamed>"
        val compDir = root?.attr(Dw.AT_comp_dir)?.asString() ?: ""
        val producer = root?.attr(Dw.AT_producer)?.asString()
        val dwoName = root?.attr(Dw.AT_dwo_name)?.asString()

        // Index DIEs by section offset for reference resolution.
        val dieIndex = HashMap<Long, Die>()
        fun indexDie(d: Die) {
            dieIndex[d.offset] = d
            d.children.forEach(::indexDie)
        }
        unit.roots.forEach(::indexDie)

        fun resolveRef(off: Long): Die? {
            if (off < 0 || off >= debugInfo.size) {
                cuNotes += "引用 0x${off.toString(16)} 越界 (.debug_info 大小 0x${debugInfo.size.toString(16)})，已忽略"
                return null
            }
            val target = dieIndex[off]
            if (target == null) cuNotes += "引用 0x${off.toString(16)} 未指向已知 DIE，已忽略"
            return target
        }

        fun referencedName(d: Die): String? {
            var current: Die? = d
            var jumps = 0
            while (current != null) {
                current.name()?.let { return it }
                if (++jumps > Dw.MAX_REF_JUMPS) {
                    cuNotes += "abstract_origin 跳转超过上限 (${Dw.MAX_REF_JUMPS})，放弃"
                    return null
                }
                val ref = current.attr(Dw.AT_abstract_origin)?.asLong() ?: return null
                current = resolveRef(ref)
            }
            return null
        }

        // Line program (parsed before DIE walk so call_file indexes resolve).
        var lineVersion: Int? = null
        var lineRows: List<LineRow> = emptyList()
        var lineFiles: List<String> = emptyList()
        val lineNotes = mutableListOf<String>()
        val stmtList = root?.attr(Dw.AT_stmt_list)?.asLong()
        if (stmtList != null) {
            if (debugLine == null) {
                lineNotes += "DW_AT_stmt_list 指向 .debug_line，但该 section 缺失"
            } else {
                val lp = LineProgramParser.parse(debugLine, stmtList.toInt(), order, unit.addrSize)
                if (lp.error != null) lineNotes += "行号表错误: ${lp.error}"
                lineNotes += lp.notes
                lineVersion = if (lp.error == null || lp.rows.isNotEmpty()) lp.version else null
                lineRows = lp.rows
                lineFiles = lp.files
            }
        }

        fun fileTableName(idx1Based: Long): String? {
            // DWARF <=4 file table is 1-based; DWARF5 is 0-based.
            val i = if (unit.version >= 5) idx1Based.toInt() else (idx1Based - 1).toInt()
            return lineFiles.getOrNull(i)
        }

        fun dieRanges(d: Die): List<AddrRange> {
            val low = d.attr(Dw.AT_low_pc)?.asLong()
            val highAttr = d.attr(Dw.AT_high_pc)
            if (low != null && highAttr != null) {
                // DW_AT_high_pc has two meanings: address class => absolute,
                // constant class => offset from low_pc.
                val high = when (highAttr) {
                    is AttrValue.Addr -> highAttr.v
                    else -> low + (highAttr.asLong() ?: 0L)
                }
                return listOf(AddrRange(low, high))
            }
            return when (val rv = d.attr(Dw.AT_ranges)) {
                is AttrValue.Data -> {
                    if (unit.version >= 5 && debugRnglists != null) {
                        val base = root?.attr(Dw.AT_rnglists_base)?.asLong() ?: 0L
                        val r = Ranges.parseRngLists(debugRnglists, base + rv.v, unit.addrSize, order) { null }
                        cuNotes += r.notes
                        r.ranges
                    } else if (debugRanges != null) {
                        val r = Ranges.parseDebugRanges(debugRanges, rv.v, unit.addrSize, order)
                        cuNotes += r.notes
                        r.ranges
                    } else {
                        cuNotes += "DIE @0x${d.offset.toString(16)} 有 DW_AT_ranges 但缺少 .debug_ranges/.debug_rnglists"
                        emptyList()
                    }
                }
                is AttrValue.Index -> {
                    if (rv.kind == "rnglistx" && debugRnglists != null) {
                        val base = root?.attr(Dw.AT_rnglists_base)?.asLong() ?: 0L
                        val headerSize = 4 + 2 + 1 + 1 + 4 // v5 32-bit header
                        val r = Ranges.parseRngLists(debugRnglists, base + headerSize + rv.idx * 4,
                            unit.addrSize, order) { null }
                        cuNotes += r.notes
                        r.ranges
                    } else emptyList()
                }
                else -> emptyList()
            }
        }

        val scopes = mutableListOf<Scope>()
        val inlines = mutableListOf<InlineSite>()
        fun walk(d: Die) {
            val ranges = dieRanges(d)
            when (d.tag) {
                Dw.TAG_subprogram, Dw.TAG_lexical_block ->
                    if (ranges.isNotEmpty()) {
                        scopes += Scope(d.offset, d.tag, referencedName(d), ranges, d.depth)
                    }
                Dw.TAG_inlined_subroutine ->
                    if (ranges.isNotEmpty()) {
                        val callFile = d.attr(Dw.AT_call_file)?.asLong()?.let(::fileTableName)
                        inlines += InlineSite(
                            d.offset, referencedName(d), callFile,
                            d.attr(Dw.AT_call_line)?.asLong(),
                            d.attr(Dw.AT_call_column)?.asLong(),
                            ranges, d.depth,
                        )
                    }
            }
            d.children.forEach(::walk)
        }
        unit.roots.forEach(::walk)

        val cuRanges = root?.let { dieRanges(it) } ?: emptyList()

        return CuModel(
            idx, unit.unitOffset, unit.version, unit.unitType, name, compDir, producer,
            dwoName, unit.isolated, unit.error, cuNotes.distinct(),
            lineVersion, lineRows, lineNotes.distinct(),
            scopes, inlines, cuRanges,
        )
    }
}
