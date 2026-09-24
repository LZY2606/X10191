package compass.dwarf

import compass.binary.ParseException
import compass.elf.ElfFile

/**
 * Entry point: turns one ELF into a [DwarfBundle], isolating broken sections
 * without poisoning the rest. Errors are recorded as corruption/warnings.
 */
object DwarfParser {
    fun parse(elf: ElfFile): DwarfBundle {
        val sections = DwarfSections.fromElf(elf)
        val warnings = mutableListOf<String>()
        val corrupt = LinkedHashMap<String, String>()

        val infoUnits = mutableListOf<CompUnit>()
        val dieIndex = LinkedHashMap<Long, DIE>()
        for (name in listOf(".debug_info", ".debug_info.dwo")) {
            if (!sections.has(name)) continue
            try {
                val (units, dies) = InfoParser.parse(sections, name)
                infoUnits.addAll(units)
                dieIndex.putAll(dies)
            } catch (e: ParseException) {
                corrupt[name] = e.message ?: "parse failed"
                warnings.add("${e.message} ($name)")
            }
        }

        // Link abstract_origin / specification chains (across units, bounded hops).
        resolveReferences(infoUnits, dieIndex, warnings)

        val linePrograms = LinkedHashMap<Long, LineProgram>()
        for (name in listOf(".debug_line", ".debug_line.dwo")) {
            if (!sections.has(name)) continue
            try {
                linePrograms.putAll(LineParser.parseAll(sections, name))
            } catch (e: ParseException) {
                corrupt[name] = e.message ?: "parse failed"
                warnings.add("${e.message} ($name)")
            }
        }

        pairSkeletons(infoUnits, warnings)

        return DwarfBundle(sections, infoUnits, dieIndex, linePrograms, corrupt, warnings)
    }

    private const val MAX_REF_HOPS = 64

    private fun resolveReferences(units: List<CompUnit>, index: Map<Long, DIE>, warnings: MutableList<String>) {
        for (cu in units) {
            if (cu.partial) continue
            cu.root.walk { die ->
                for (attrName in listOf(DW.AT.abstract_origin, DW.AT.specification)) {
                    val attr = die.attr(attrName) ?: continue
                    val ref = (attr.value as? AttrValue.Ref) ?: continue
                    val target = index[ref.offset]
                    if (target == null) {
                        // Dangling/out-of-bounds reference: record, do not fabricate a DIE.
                        die.attributes.add(Attribute(DW.AT.name, DW.FORM.string,
                            AttrValue.Str("<dangling ref 0x${ref.offset.toString(16)}>")))
                        warnings.add("DIE 0x${die.offset.toString(16)} references missing 0x${ref.offset.toString(16)}")
                    }
                }
            }
        }
    }

    /** Resolve a DIE name through specification/abstract_origin chains, hop-limited. */
    fun nameOf(die: DIE, index: Map<Long, DIE>): String? {
        var cur: DIE? = die
        var hops = 0
        while (cur != null && hops++ < MAX_REF_HOPS) {
            val direct = (cur.attrValue(DW.AT.name) as? AttrValue.Str)?.value
            if (direct != null) return direct
            val link = (cur.attrValue(DW.AT.abstract_origin) ?: cur.attrValue(DW.AT.specification))
                ?.let { it as? AttrValue.Ref } ?: return (cur.attrValue(DW.AT.linkage_name) as? AttrValue.Str)?.value
            cur = index[link.offset]
        }
        return null
    }

    private fun pairSkeletons(units: List<CompUnit>, warnings: MutableList<String>) {
        val skeletons = units.filter { it.isSkeleton && it.dwoId != null }
        val splits = units.filter { it.isSplitCompile && it.dwoId != null }.associateBy { it.dwoId }
        for (sk in skeletons) {
            val split = splits[sk.dwoId]
            if (split != null) {
                sk.splitUnit = split
                split.skeletonUnit = sk
            } else {
                warnings.add("skeleton CU '${sk.name}' (dwo_id=0x${sk.dwoId?.toString(16)}) has no imported .dwo; split conclusions unavailable")
            }
        }
    }
}
