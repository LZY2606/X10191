package compass.dwarf

import compass.dwarf.DebugDwoProvider
import compass.elf.ElfParser
import compass.model.CompilationUnit
import compass.model.DieNode
import compass.model.DieRange
import compass.model.ElfFile
import compass.model.LineSequence
import compass.model.ParsedDebugInfo
import compass.model.SectionWarning

/** Supplies .dwo bytes referenced by skeleton CUs (file system, in-memory, …). */
fun interface DebugDwoProvider {
    fun findDwo(dwoName: String, dwoId: Long?, hintDir: String?): ByteArray?
}

/**
 * Entry point for local parsing of an ELF executable / shared object and any
 * split DWARF companions. No external tools are used.
 */
object DwarfImporter {

    fun import(
        bytes: ByteArray,
        dwoProvider: DebugDwoProvider? = null,
        sourceLabel: String = "main",
    ): ParsedDebugInfo {
        val elf = ElfParser.parse(bytes)
        val sections = DebugSections.of(extractSectionBytes(elf, bytes))
        val endian = elf.endian

        val warnings = ArrayList<SectionWarning>()
        val missingDwos = LinkedHashSet<String>()

        val main = if (sections[".debug_info"] != null || sections[".debug_info.dwo"] != null) {
            DwarfAssembler(sections, endian, sections[".debug_info"] == null, sourceLabel).assemble()
        } else {
            warnings.add(SectionWarning(sourceLabel, null,
                "缺少 .debug_info：无法解析任何编译单元（section 地图与段信息仍可信）"))
            Assembly()
        }

        // Resolve split DWARF companions.
        val mergedCus = ArrayList(main.cus)
        val mergedDies = ArrayList(main.dies)
        val mergedRanges = ArrayList(main.ranges)
        val mergedSeqs = ArrayList(main.sequences)
        warnings.addAll(main.warnings)

        val dwoCache = HashMap<String, Assembly?>()
        for (skeleton in main.cus.filter { it.isSkeleton }) {
            val dwoName = skeleton.dwoName
            if (dwoName == null) {
                warnings.add(SectionWarning(sourceLabel, skeleton.offset,
                    "骨架 CU 没有 DW_AT_dwo_name，内联树/行号可能不完整；骨架自身的范围仍可信"))
                continue
            }
            val assembly = dwoCache.getOrPut(dwoName) {
                val dwoBytes = dwoProvider?.findDwo(dwoName, skeleton.dwoId, skeleton.compDir)
                if (dwoBytes == null) {
                    missingDwos.add(dwoName)
                    warnings.add(SectionWarning(sourceLabel, skeleton.offset,
                        "找不到 split 调试文件 $dwoName：该 CU 的行号/内联抽象 DIE 不可信；" +
                            "骨架中已具体化的范围（low_pc/high_pc/ranges）仍可信"))
                    null
                } else {
                    runCatching {
                        val dwoElf = ElfParser.parse(dwoBytes)
                        val dwoSections = DebugSections.of(extractSectionBytes(dwoElf, dwoBytes))
                        DwarfAssembler(dwoSections, endian, isSplit = true,
                            sourceLabel = dwoName).assemble()
                    }.getOrElse { e ->
                        missingDwos.add(dwoName)
                        warnings.add(SectionWarning(dwoName, skeleton.offset,
                            ".dwo 损坏无法解析（${e.message}）：骨架范围内具体化信息仍可信"))
                        null
                    }
                }
            } ?: continue

            // Match dwo CU to skeleton by 64-bit dwo_id when present; else by
            // single-unit assumption; else by name.
            val splitCu = assembly.cus.firstOrNull { it.dwoId != null && it.dwoId == skeleton.dwoId }
                ?: assembly.cus.singleOrNull()
                ?: assembly.cus.firstOrNull { it.name == skeleton.name }
                ?: continue

            val idOffset = mergedCus.size.toLong()
            val dieIdOffset = mergedDies.size.toLong()
            val rangeIdOffset = mergedRanges.size.toLong()
            val seqIdOffset = mergedSeqs.size.toLong()

            val newCu = splitCu.copy(id = idOffset, skeletonForId = skeleton.id, lowPc = skeleton.lowPc)
            mergedCus.add(newCu)
            skeleton.skeletonForId
            val idRemap = HashMap<Long, Long>()
            for (die in assembly.dies.filter { it.cuId == splitCu.id }) {
                val newId = dieIdOffset + (die.id - assembly.dies.first { d -> d.cuId == splitCu.id }.id)
                idRemap[die.id] = newId
            }
            // Simpler: remap by enumeration order within the CU.
            idRemap.clear()
            assembly.dies.filter { it.cuId == splitCu.id }.forEachIndexed { idx, die ->
                idRemap[die.id] = dieIdOffset + idx
            }
            for (die in assembly.dies.filter { it.cuId == splitCu.id }) {
                mergedDies.add(die.copy(
                    id = idRemap.getValue(die.id),
                    cuId = newCu.id,
                    parentId = die.parentId?.let { idRemap[it] },
                    abstractOrigin = die.abstractOrigin, // split-internal refs preserved via offset keys
                    specification = die.specification,
                ))
            }
            for (r in assembly.ranges.filter { it.cuId == splitCu.id }) {
                mergedRanges.add(r.copy(
                    id = rangeIdOffset + r.id,
                    dieId = idRemap.getValue(r.dieId),
                    cuId = newCu.id,
                ))
            }
            for (s in assembly.sequences.filter { it.cuId == splitCu.id }) {
                mergedSeqs.add(s.copy(id = seqIdOffset + s.id, cuId = newCu.id))
            }
            warnings.addAll(assembly.warnings)

            // Link skeleton to its full CU.
            val skIdx = mergedCus.indexOfFirst { it.id == skeleton.id }
            if (skIdx >= 0) mergedCus[skIdx] = skeleton.copy(skeletonForId = newCu.id)
        }

        return ParsedDebugInfo(
            elf = elf,
            cus = mergedCus,
            dies = mergedDies,
            ranges = mergedRanges,
            sequences = mergedSeqs,
            warnings = warnings,
            missingDwos = missingDwos.toList(),
        )
    }

    private fun extractSectionBytes(elf: ElfFile, bytes: ByteArray): Map<String, ByteArray> {
        val out = LinkedHashMap<String, ByteArray>()
        for (s in elf.sections) {
            if (s.name.isEmpty() || s.type == 8 || s.size == 0L) continue // SHT_NOBITS
            if (s.offset < 0 || s.offset + s.size > bytes.size) continue
            out[s.name] = bytes.copyOfRange(s.offset.toInt(), (s.offset + s.size).toInt())
        }
        return out
    }
}
