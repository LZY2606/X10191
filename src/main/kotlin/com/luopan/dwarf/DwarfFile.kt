package com.luopan.dwarf

import com.luopan.elf.ElfImage
import com.luopan.elf.ElfParser
import com.luopan.elf.RelocationApplier
import com.luopan.dwarf.DwarfAttr as A
import com.luopan.dwarf.DwarfTag as T

/** 一个已解析的函数（或内联点）语义视图。 */
class FunctionInfo(
    val name: String?,
    val dieOffset: Int,
    val tag: String,
    val ranges: List<AddrRange>,
    val cuOffset: Int,
    val cuName: String,
    val declFile: String?,
    val declLine: Long?,
    val inline: Long?,
    val abstractOrigin: Int?,
    val specification: Int?,
    val depth: Int,
    val parent: Int,
    val external: Boolean,
    val declaration: Boolean,
)

/** 一个导入文件解析后的全部结构化结果（行址罗盘的数据核心）。 */
class DwarfFile(
    val elf: ElfImage,
    val sections: DwarfSections,
    val units: List<CompileUnit>,
    val splitUnits: List<CompileUnit>,
    val line: LineParseResult,
    val splitLine: LineParseResult,
    val functions: List<FunctionInfo>,
    val diagnostics: List<Diagnostic>,
    val relocationsApplied: Int,
    val dwoExpected: List<Pair<Long?, String?>>,
)

object DwarfFileParser {
    private val FUNC_TAGS = setOf(
        T.SUBPROGRAM, T.INLINED_SUBROUTINE, T.ENTRY_POINT,
    )

    fun parse(data: ByteArray): DwarfFile {
        val elf = ElfParser.parse(data)
        val rel = RelocationApplier.apply(elf)
        val sections = DwarfSections.from(rel.sections)
        val jumps = JumpBudget()
        val infoRes = InfoParser.parse(sections, useDwo = false, jumps)
        val dwoRes = if (sections.infoDwo != null)
            InfoParser.parse(sections, useDwo = true, jumps)
        else InfoParseResult(emptyList(), emptyList())
        val lineRes = LineProgramParser.parseAll(sections, infoRes.units, useDwo = false)
        val dwoLineRes = if (sections.lineDwo != null || sections.infoDwo != null)
            LineProgramParser.parseAll(sections, dwoRes.units, useDwo = true)
        else LineParseResult(emptyList(), emptyList(), emptyList(), emptyList())

        val diag = mutableListOf<Diagnostic>()
        diag.addAll(elf.diagnostics.map { Diagnostic("WARNING", "elf", it) })
        diag.addAll(rel.diagnostics.map { Diagnostic("WARNING", "relocation", it) })
        diag.addAll(infoRes.diagnostics)
        diag.addAll(dwoRes.diagnostics)
        diag.addAll(lineRes.diagnostics)
        diag.addAll(dwoLineRes.diagnostics)

        val functions = ArrayList<FunctionInfo>()
        for (cu in infoRes.units) extractFunctions(cu, sections, functions)
        for (cu in dwoRes.units) extractFunctions(cu, sections, functions)

        val dwoExpected = infoRes.units
            .filter { it.isSkeleton }
            .map { it.dwoId to it.dwoName }
            .distinct()
        if (dwoExpected.isNotEmpty() && sections.infoDwo == null) {
            diag.add(Diagnostic("WARNING", "split",
                "skeleton CU references split DWARF (.dwo) which is not present in this import; " +
                    "inlining/line info from the dwo is unavailable until it is imported"))
        }

        return DwarfFile(
            elf, sections, infoRes.units, dwoRes.units, lineRes, dwoLineRes,
            functions, diag.sortedWith(compareBy({ it.severity }, { it.scope }, { it.message })),
            rel.appliedCount, dwoExpected,
        )
    }

    private fun extractFunctions(cu: CompileUnit, sections: DwarfSections, out: MutableList<FunctionInfo>) {
        val rangeByDie = cu.ranges.groupBy { it.dieIndex }
        for (die in cu.dies) {
            if (die.tag !in FUNC_TAGS) continue
            fun str(attr: Int) = (die.attr(attr) as? AttrVal.Str)?.v
            val ranges = (rangeByDie[die.index] ?: emptyList()).map { it.range }
            out.add(
                FunctionInfo(
                    name = str(A.NAME),
                    dieOffset = die.offset,
                    tag = T.name(die.tag),
                    ranges = ranges,
                    cuOffset = cu.sectionOffset,
                    cuName = cu.name,
                    declFile = declFile(cu, die),
                    declLine = (die.attr(A.DECL_LINE) as? AttrVal.Const)?.v,
                    inline = (die.attr(A.INLINE) as? AttrVal.Const)?.v,
                    abstractOrigin = (die.attr(A.ABSTRACT_ORIGIN) as? AttrVal.Ref)?.offset,
                    specification = (die.attr(A.SPECIFICATION) as? AttrVal.Ref)?.offset,
                    depth = die.depth,
                    parent = die.parent,
                    external = (die.attr(A.EXTERNAL) as? AttrVal.Flag)?.v == true,
                    declaration = (die.attr(A.DECLARATION) as? AttrVal.Flag)?.v == true,
                )
            )
        }
    }

    private fun declFile(cu: CompileUnit, die: Die): String? {
        val v = die.attr(A.DECL_FILE) ?: return null
        val idx = (v as? AttrVal.Const)?.v?.toInt() ?: return null
        // DWARF<5: 1-based into line table file list; v5: 0-based, file 0 = comp dir
        val base = if (cu.version >= 5) 0 else 1
        if (idx == 0 && cu.version >= 5) return cu.name
        return null // 行号文件表在 resolver 处与 CU stmt_list 关联后回填
    }
}
