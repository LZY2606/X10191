package compass.dwarf

import java.io.ByteArrayOutputStream

/** 解析入口：ELF → 重定位补丁 → DWARF section → CU/line/range。 */
class DebugParser {

    fun parse(bytes: ByteArray, dwoProvider: (String, Long) -> ParsedDebugFile? = { _, _ -> null }): ParsedDebugFile {
        val elf0 = ElfParser.parse(bytes)
        val issues = elf0.issues.toMutableList()

        // 1) 应用运行时重定位到 section 字节（同一相对地址不同加载代次由 load snapshot 处理，
        //    这里只还原“链接后/相对镜像”应有的地址值）。
        val patched = applyRelocations(elf0, issues)
        val elf = if (patched == null) elf0 else elf0.copy(sectionBytes = patched)

        val sections = DebugSections(elf)
        if (!sections.hasDwarf) {
            issues += ParseIssue(ParseIssue.Severity.ERROR, "dwarf.no_info", "文件中没有 .debug_info/.debug_types")
            return ParsedDebugFile(elf, emptyList(), RangeLists(emptyMap(), emptyMap(), issues), issues, emptyList())
        }
        val formReader = FormReader(sections)
        val lineParser = LineProgramParser(sections, formReader)
        val rangeParser = RangeListParser(sections)
        val rangeLists = rangeParser.parseAll()
        val infoParser = InfoParser(sections, formReader, lineParser, rangeParser)
        val units = infoParser.parseAll()

        // 2) 关联 split DWARF（.dwo/.dwp）
        val dwoLinks = ArrayList<DwoLink>()
        for (u in units) {
            val isSkeleton = u.version >= 5 && u.unitType == UnitType5.SKELETON ||
                (u.version < 5 && u.dwoId != null && u.dwoName != null)
            if (!isSkeleton) continue
            val id = u.dwoId ?: continue
            var resolved: ParsedDebugFile? = null
            var reason = "dwo 未导入"
            try {
                resolved = dwoProvider(u.dwoName ?: "", id)
                if (resolved == null) {
                    issues += ParseIssue(ParseIssue.Severity.WARNING, "dwo.missing",
                        "CU ${u.name.ifEmpty { "0x${u.sectionOffset.toString(16)}" }} 引用 " +
                            "${u.dwoName ?: "(dwo)"} (id=0x${id.toString(16)}) 但未导入；行号来自 skeleton，仍可信",
                        ".debug_info", u.sectionOffset)
                } else {
                    reason = "已关联"
                }
            } catch (e: Exception) {
                reason = "dwo 解析失败: ${e.message}"
                issues += ParseIssue(ParseIssue.Severity.WARNING, "dwo.bad", reason, ".debug_info", u.sectionOffset)
            }
            dwoLinks += DwoLink(u.sectionOffset, u.dwoName, id, null, reason)
        }

        val allIssues = issues + units.flatMap { it.issues } +
            units.mapNotNull { it.lineProgram?.issues?.takeIf { l -> l.isNotEmpty() } }.flatten() +
            rangeLists.issues
        return ParsedDebugFile(elf, units, rangeLists, allIssues.distinct(), dwoLinks)
    }

    /**
     * 将重定位目标值写入对应 section 字节。
     * - RELATIVE: target = bias-independent 的相对值，取 addend
     * - ABSOLUTE: target = symbol.st_value + addend
     * - UNKNOWN: 无法安全求值 → 记 issue，该位置保持原值，不产生伪地址
     */
    private fun applyRelocations(elf: ElfImage, issues: MutableList<ParseIssue>): Map<String, ByteArray>? {
        if (elf.relocations.isEmpty()) return null
        val out = elf.sectionBytes.mapValues { it.value.copyOf() }
        var changed = false
        for ((sectionName, rels) in elf.relocations) {
            val buf = out[sectionName] ?: continue
            val info = elf.sectionInfo(sectionName)
            for (r in rels) {
                val target: Long = when (r.kind) {
                    RelocKind.RELATIVE -> r.addend
                    RelocKind.ABSOLUTE -> r.symbolValue + r.addend
                    RelocKind.NONE -> continue
                    RelocKind.UNKNOWN -> {
                        issues += ParseIssue(ParseIssue.Severity.WARNING, "reloc.unknown",
                            "$sectionName+0x${r.offset.toString(16)} 存在不支持的重定位类型 ${r.type}，该地址不做改写",
                            sectionName, r.offset)
                        continue
                    }
                }
                // section 内偏移：reloc.r_offset 对可分配 section 是 sh_addr 相对（虚拟地址）
                val localOff = (r.offset - (info?.address ?: r.offset)).toInt()
                if (localOff < 0 || localOff + 8 > buf.size) {
                    issues += ParseIssue(ParseIssue.Severity.WARNING, "reloc.overflow",
                        "$sectionName+0x${r.offset.toString(16)} 重定位落点越界", sectionName, r.offset)
                    continue
                }
                writePatch(buf, localOff, target)
                changed = true
            }
        }
        return if (changed) out else null
    }

    private fun writePatch(buf: ByteArray, off: Int, value: Long) {
        // 小端写入；fixture 全部按小端生成。真实大端文件不在本次支持范围。
        for (i in 0 until 8) buf[off + i] = (value ushr (8 * i)).toByte()
    }
}
