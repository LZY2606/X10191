package compass.dwarf

import compass.elf.ElfModel

/**
 * 解析后的逻辑 CU 视图。
 * - 普通 CU：cu == null（仅 split 孤儿场景）以外 cu/sections 都指向自身
 * - split DWARF：skeleton + split CU 合并；split 缺失时 splitCu=null，仅 skeleton 信息可信
 */
data class UnitView(
    val skeleton: CompUnit,
    val splitCu: CompUnit?,
    val sections: SectionSet,
    val splitSections: SectionSet?,
    val missingDwo: Boolean,
) {
    val version: Int get() = skeleton.version
    val lineProgram: LineProgram? get() = skeleton.lineProgram ?: splitCu?.lineProgram
    val dwoId: Long? get() = skeleton.dwoId ?: splitCu?.dwoId
    val rootName: String? get() = splitCu?.rootName ?: skeleton.rootName
    val compDir: String? get() = splitCu?.compDir ?: skeleton.compDir
    val producer: String? get() = splitCu?.producer ?: skeleton.producer
    val addressSize: Int get() = skeleton.addressSize
    val rnglistsBase: Long? get() = splitCu?.rnglistsBase ?: skeleton.rnglistsBase
    val addrBase: Long? get() = skeleton.addrBase ?: splitCu?.addrBase

    /** 用于地址/范围解析的“主 CU”：行号与 low_pc/ranges 主要在 split 侧（v5） */
    val rangeCu: CompUnit get() = splitCu ?: skeleton

    fun sectionsFor(cu: CompUnit): SectionSet = if (cu.fileIndex == splitCu?.fileIndex && cu.offset == splitCu.offset)
        splitSections ?: sections else sections

    fun dieByOffset(globalOffset: Long): Die? =
        splitCu?.dieAt(globalOffset) ?: skeleton.dieAt(globalOffset)
    fun cuOfDie(die: Die): CompUnit =
        if (splitCu != null && splitCu.dies.any { it.offset == die.offset }) splitCu else skeleton
    val isCorrupt: Boolean get() = skeleton.error != null || splitCu?.error != null
    fun errors(): List<String> = listOfNotNull(skeleton.error, splitCu?.error)
}

data class DwarfBundle(
    val fileIndex: Int,
    val elf: ElfModel,
    val sections: SectionSet,
    val units: List<UnitView>,
    val warnings: List<String>,
) {
    fun viewsFor(offset: Long): List<UnitView> = units.filter { v ->
        val cu = v.skeleton
        val end = cu.offset + cu.length
        offset in cu.offset until end
    }
}

object BundleFactory {
    /**
     * @param dwoBundles 同一版本内的其它文件（按 dwo_id 关联 split CU）
     */
    fun create(fileIndex: Int, elf: ElfModel, dwoBundles: List<DwarfBundle> = emptyList()): DwarfBundle {
        val warnings = elf.warnings.toMutableList()
        val sections = SectionSet.fromElf(elf, warnings)
        val infoName = if (sections[".debug_info"] != null) ".debug_info"
        else sections[".debug_info.dwo"] ?: throw ParseException("缺少 .debug_info")
        val infoParser = InfoParser(sections, elf, fileIndex, infoName)
        val rawCus = infoParser.parse()
        val lineParser = LineProgramParser(sections, elf.endian == 1)
        val cusWithLines = rawCus.map { cu -> attachLine(cu, lineParser) }

        // dwo 索引：dwo_id -> 提供 split CU 的 bundle
        val dwoById = HashMap<Long, DwarfBundle>()
        val allBundles = dwoBundles
        for (b in allBundles) {
            for (v in b.units) {
                val id = v.dwoId
                if (id != null && id != 0L && v.skeleton.isSplit) dwoById.putIfAbsent(id, b)
            }
        }
        // 自身内 split CU（同一文件含 .debug_info 与 .debug_info.dwo）
        val ownSplit: DwarfBundle? = if (sections[".debug_info.dwo"] != null) {
            val sp = InfoParser(sections, elf, fileIndex, ".debug_info.dwo").parse()
                .map { attachLine(it, lineParser) }
            DwarfBundle(fileIndex, elf, sections, sp.map { UnitView(it, null, sections, null, false) }, emptyList())
        } else null
        ownSplit?.let { own ->
            own.units.forEach { v -> v.dwoId?.let { id -> if (id != 0L) dwoById.putIfAbsent(id, own) } }
        }

        val views = cusWithLines.map { cu ->
            if (cu.isSkeleton) {
                val id = cu.dwoId
                val dwo = id?.let { dwoById[it] }
                if (dwo != null) {
                    val split = dwo.units.firstOrNull { it.skeleton.isSplit && it.dwoId == id }?.skeleton
                    if (split != null) UnitView(cu, split, sections, dwo.sections, false)
                    else { warnings.add("dwo_id=0x${id.toString(16)} 的 split CU 在已导入文件中未找到"); UnitView(cu, null, sections, null, true) }
                } else {
                    if (id != null && id != 0L) warnings.add("缺少 dwo（dwo_id=0x${id.toString(16)}）：内联树/部分范围不可用")
                    UnitView(cu, null, sections, null, true)
                }
            } else {
                UnitView(cu, null, sections, null, false)
            }
        }
        return DwarfBundle(fileIndex, elf, sections, views, warnings.distinct())
    }

    private fun attachLine(cu: CompUnit, parser: LineProgramParser): CompUnit {
        val off = cu.stmtList ?: return cu
        val lp = parser.parse(off, cu.offset)
        return cu.copy(lineProgram = lp)
    }
}
