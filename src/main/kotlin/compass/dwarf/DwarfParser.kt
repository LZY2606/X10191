package compass.dwarf

import compass.elf.ElfFile
import compass.elf.ElfParser
import java.io.File

/**
 * Entry point: ELF + every DWARF section -> [DwarfImage].
 * Pure local parsing; never invokes addr2line or any system debugger.
 */
object DwarfParser {

    fun parse(main: ElfFile, split: ElfFile? = null, splitLookup: (String) -> ElfFile? = { null }): DwarfImage {
        val diagnostics = mutableListOf<ParseDiagnostic>()

        // Locate external dwo files referenced by skeleton CUs when not provided directly.
        var resolvedSplit = split
        val mainBundle = SectionBundle(main, resolvedSplit)
        val abbrev = AbbrevParser.parse(mainBundle.section(".debug_abbrev"), main.littleEndian, diagnostics)
        val cus = try {
            InfoParser(mainBundle, abbrev, diagnostics).parse()
        } catch (e: Exception) {
            diagnostics.add(ParseDiagnostic("ERROR", "INFO_FATAL", e.message ?: "info 解析异常", ".debug_info", null))
            emptyList()
        }

        // Link split CUs: explicit file first, then by dwo_name lookup, matching dwo_id.
        if (resolvedSplit == null) {
            for (cu in cus) {
                if (!cu.isSkeleton) continue
                val dwoName = cu.dwoName ?: continue
                val dwoElf = runCatching { splitLookup(dwoName) }.getOrNull()
                if (dwoElf != null) {
                    resolvedSplit = dwoElf
                    break
                }
            }
        }
        val bundle = SectionBundle(main, resolvedSplit)

        val splitCus = if (resolvedSplit != null) {
            val splitAbbrev = AbbrevParser.parse(
                bundle.section(".debug_abbrev", allowSplit = true),
                resolvedSplit!!.littleEndian, diagnostics)
            val splitBundle = SectionBundle(resolvedSplit!!, null)
            val parsed = InfoParser(splitBundle, splitAbbrev, diagnostics).parse()
            parsed.forEach { it.skeletonCu = null }
            parsed
        } else emptyList()

        linkSplitUnits(cus, splitCus, diagnostics)

        RangeResolver(bundle, diagnostics).resolve(cus)
        RangeResolver(SectionBundle(resolvedSplit ?: main, null), diagnostics).resolve(splitCus)

        val sequences = LineProgramParser(bundle, diagnostics).parseAll(cus) +
            (if (resolvedSplit != null)
                LineProgramParser(SectionBundle(resolvedSplit, null), diagnostics).parseAll(splitCus)
            else emptyList())

        reportMissingDwo(cus, diagnostics)
        return DwarfImage(main, resolvedSplit, cus, splitCus, sequences, diagnostics)
    }

    private fun linkSplitUnits(skeletons: List<CompUnit>, splits: List<CompUnit>,
                                diagnostics: MutableList<ParseDiagnostic>) {
        for (sk in skeletons.filter { it.isSkeleton }) {
            val match = splits.firstOrNull { it.dwoId != null && it.dwoId == sk.dwoId }
            if (match != null) {
                sk.splitCu = match
                match.skeletonCu = sk
                sk.dwoResolved = true
                // inherit stmt_list and root DIE ranges view: split root carries the full DIE tree
            } else {
                sk.dwoResolved = false
                diagnostics.add(ParseDiagnostic("WARNING", "DWO_MISSING",
                    "skeleton CU @${sk.offset} (dwo_id=${sk.dwoId?.toString(16)}) 引用的 " +
                        "${sk.dwoName ?: "<unknown>.dwo"} 缺失：仅有 skeleton 的地址范围/行号可信，" +
                        "完整 DIE 树与内联链不可用", sk.dwoName, sk.offset))
            }
        }
        // GNU split dwarf (DWARF 4): skeleton marked via GNU_dwo_name without unit_type
        for (cu in skeletons) {
            if (cu.isSkeleton) continue
            val gnuDwo = cu.root?.str(DW_AT.GNU_DWO_NAME) ?: continue
            val match = splits.firstOrNull {
                it.root?.str(DW_AT.GNU_DWO_NAME) == gnuDwo || it.dwoId == cu.root?.num(DW_AT.GNU_DWO_ID)
            }
            if (match != null) { cu.splitCu = match; match.skeletonCu = cu; cu.dwoResolved = true }
            else diagnostics.add(ParseDiagnostic("WARNING", "DWO_MISSING",
                "CU @${cu.offset} 引用的 GNU dwo '$gnuDwo' 缺失", gnuDwo, cu.offset))
        }
    }

    private fun reportMissingDwo(cus: List<CompUnit>, diagnostics: MutableList<ParseDiagnostic>) {
        val referenced = cus.any { it.isSkeleton || it.root?.str(DW_AT.GNU_DWO_NAME) != null }
        if (referenced && cus.none { it.dwoResolved }) {
            // already reported per-CU
        }
    }

    fun parseBytes(bytes: ByteArray, path: String? = null, splitBytes: ByteArray? = null,
                   splitPath: String? = null): DwarfImage {
        val main = ElfParser.parse(bytes, path)
        val split = splitBytes?.let { ElfParser.parse(it, splitPath) }
        return parse(main, split) { name ->
            val f = File(name)
            if (f.exists()) ElfParser.parse(f.readBytes(), name) else null
        }
    }
}

data class DwarfImage(
    val elf: ElfFile,
    val splitElf: ElfFile?,
    val cus: List<CompUnit>,
    val splitCus: List<CompUnit>,
    val sequences: List<LineSequence>,
    val diagnostics: List<ParseDiagnostic>
)
