package compass.dwarf

import compass.binfmt.DwarfParseException
import compass.elf.ElfFile

/** A single object file participating in a debug version (main executable or a .dwo). */
class LoadedObject(
    val elf: ElfFile,
    val sections: DwarfSections,
    val units: List<CompUnit>,
    val lineSequences: List<LineSequence>,
    val abbrevTables: Map<Long, Map<Long, Abbrev>>,
    val strings: StringResolver,
    val ranges: RangeParser,
    val warnings: MutableList<String> = mutableListOf(),
) {
    val diesByOffset: Map<Long, DIE> = buildMap {
        fun add(d: DIE?) {
            if (d == null) return
            put(d.offset, d)
            d.children.forEach { add(it) }
        }
        units.forEach { add(it.root) }
    }
    val isSkeletonFile: Boolean get() = units.any { it.isSkeleton }
}

data class InlineFrame(
    val die: DIE,
    val name: String?,
    val ranges: List<RangeEntry>,
    val depth: Int,
    val callFile: String?,
    val callLine: Int,
    val callColumn: Int,
    val abstract: Boolean,
)

/** Fully parsed debug bundle: main object plus separately imported dwo objects. */
class DwarfModel(
    val main: LoadedObject,
    val dwos: List<LoadedObject>,
    val fileName: String,
) {
    val allObjects: List<LoadedObject> get() = listOf(main) + dwos
    val allUnits: List<CompUnit> = allObjects.flatMap { it.units }
    val allSequences: List<LineSequence> = allObjects.flatMap { it.lineSequences }
    val allWarnings: List<String> = allObjects.flatMap { o -> o.warnings.map { "${o.elf.fileName}: $it" } }

    /** Per-DIE resolved ranges; computed once. */
    data class DieInfo(val die: DIE, val cu: CompUnit, val obj: LoadedObject, val ranges: List<RangeEntry>, val trust: List<String>)

    val dieInfos: List<DieInfo> = allObjects.flatMap { obj -> obj.units.flatMap { cu -> collectDies(obj, cu) } }

    fun nameOf(die: DIE): String? {
        val ownCu = cuOf(die)
        fun resolvedName(d: DIE): String? {
            val cu = cuOf(d) ?: ownCu
            d.at(Dw.AT_name)?.let { v -> if (cu != null) stringOf(v, cu)?.let { return it } }
            d.at(Dw.AT_linkage_name)?.let { v -> if (cu != null) stringOf(v, cu)?.let { return it } }
            return null
        }
        resolvedName(die)?.let { return it }
        // follow abstract_origin / specification chain (hop-limited)
        var cur: DIE? = die; var hops = 0
        while (cur != null && hops < 64) {
            val refAttr = cur.at(Dw.AT_abstract_origin) ?: cur.at(Dw.AT_specification) ?: break
            val target = resolveRef(refAttr) ?: break
            resolvedName(target)?.let { return it }
            cur = target; hops++
        }
        return null
    }

    fun stringOf(v: AttrValue?, cu: CompUnit): String? {
        if (v == null) return null
        val obj = objOf(cu) ?: main
        return obj.strings.stringOf(cu, v)
    }

    private val cuByDie = HashMap<Long, CompUnit>().apply {
        allObjects.forEach { obj -> obj.units.forEach { cu -> indexCu(cu) } }
    }
    private fun indexCu(cu: CompUnit) {
        fun walk(d: DIE?) { if (d == null) return; cuByDie[d.offset] = cu; d.children.forEach { walk(it) } }
        walk(cu.root)
    }
    fun cuOf(die: DIE): CompUnit? = cuByDie[die.offset]
    fun objOf(cu: CompUnit): LoadedObject? = allObjects.firstOrNull { it.units.contains(cu) }

    fun resolveRef(v: AttrValue?): DIE? {
        if (v == null) return null
        return when (v) {
            is AttrValue.RefCu -> main.diesByOffset[v.offset] ?: allObjects.mapNotNull { it.diesByOffset[v.offset] }.firstOrNull()
            is AttrValue.RefGlobal -> allObjects.mapNotNull { it.diesByOffset[v.offset] }.firstOrNull()
            else -> null
        }
    }

    /** All subprogram-ish DIEs (subprogram, inlined_subroutine, call sites). */
    fun subprograms(): List<DieInfo> = dieInfos.filter {
        it.die.tag == Dw.TAG_subprogram || it.die.tag == Dw.TAG_inlined_subroutine || it.die.tag == Dw.TAG_GNU_call_site
    }

    private fun collectDies(obj: LoadedObject, cu: CompUnit): List<DieInfo> {
        val out = mutableListOf<DieInfo>()
        val trustBase = cu.warnings.toList()
        fun walk(d: DIE?) {
            if (d == null) return
            val (ranges, notes) = rangesOf(obj, cu, d)
            if (d.tag == Dw.TAG_subprogram || d.tag == Dw.TAG_inlined_subroutine ||
                d.tag == Dw.TAG_lexical_block || d.tag == Dw.TAG_GNU_call_site ||
                d.tag == Dw.TAG_try_block || d.tag == Dw.TAG_catch_block) {
                out.add(DieInfo(d, cu, obj, ranges, trustBase + notes))
            }
            d.children.forEach { walk(it) }
        }
        walk(cu.root)
        return out
    }

    fun cuBase(obj: LoadedObject, cu: CompUnit): Long {
        // DW_AT_low_pc of the root; else min subprogram low
        val rootLow = cu.root?.at(Dw.AT_low_pc)?.asLong()
        if (rootLow != null) return rootLow
        return obj.diesByOffset.values.mapNotNull { it.at(Dw.AT_low_pc)?.asLong() }.minOrNull() ?: 0L
    }

    fun rangesOf(obj: LoadedObject, cu: CompUnit, die: DIE): Pair<List<RangeEntry>, List<String>> {
        val notes = mutableListOf<String>()
        val low = die.at(Dw.AT_low_pc)?.asLong()
        val highAttr = die.at(Dw.AT_high_pc)
        val rangesAttr = die.at(Dw.AT_ranges)
        if (low != null && highAttr != null) {
            if (highAttr is AttrValue.Number) {
                // The form class decides semantics (DWARF spec): address class => absolute
                // end PC; constant class (data/sdata/implicit_const) => size delta.
                val end = if (highAttr.constant) low + highAttr.v else highAttr.v
                return listOf(RangeEntry(low, end, low == end)) to notes
            }
            notes.add("high_pc unsupported form")
        }
        if (low != null && highAttr == null) {
            // low_pc alone: a single zero-length sentinel (common for abstract declarations)
            return listOf(RangeEntry(low, low, true)) to notes
        }
        if (rangesAttr != null) {
            val raw = rangesAttr.asLong() ?: return Pair(emptyList<RangeEntry>(), listOf("ranges attr unreadable"))
            val addrLookup: (Long) -> Long? = { idx -> resolveAddrIndex(obj, cu, idx) }
            return if (cu.version >= 5) {
                val rnglistx = die.at(Dw.AT_ranges) as? AttrValue.Rnglistx
                obj.ranges.parseV5(cu, raw, rnglistx?.index, addrLookup)
            } else {
                obj.ranges.parseV4(cu, raw, addrLookup)
            }
        }
        return Pair(emptyList<RangeEntry>(), notes)
    }

    private fun resolveAddrIndex(obj: LoadedObject, cu: CompUnit, idx: Long): Long? {
        val d = obj.sections.addr ?: obj.sections.addrDwo ?: return null
        val baseAttr = cu.root?.at(Dw.AT_addr_base)?.asLong() ?: 0L
        val entrySize = if (cu.is64Bit) 8 else cu.addressSize
        val off = (baseAttr + idx * entrySize).toInt()
        if (off + entrySize > d.size) return null
        val c = compass.binfmt.Cursor(d, off, d.size, off, obj.elf.littleEndian)
        return c.addr(entrySize)
    }
}

/** Build a [DwarfModel] from raw file bytes (main + zero or more dwo files). */
object DwarfModelLoader {
    private val DWARF_SECTIONS = setOf(
        ".debug_info", ".debug_abbrev", ".debug_line", ".debug_line_str", ".debug_str",
        ".debug_str_offsets", ".debug_ranges", ".debug_rnglists", ".debug_addr",
        ".debug_info.dwo", ".debug_abbrev.dwo", ".debug_str.dwo", ".debug_str_offsets.dwo",
        ".debug_line.dwo", ".debug_line_str.dwo", ".debug_rnglists.dwo", ".debug_addr.dwo",
    )

    fun load(mainBytes: ByteArray, dwoBytes: List<Pair<String, ByteArray>> = emptyList(), fileName: String = "a.out"): DwarfModel {
        val mainElf = ElfFile(mainBytes, fileName)
        val mainObj = loadObject(mainElf)
        val dwos = dwoBytes.map { (name, bytes) ->
            try { loadObject(ElfFile(bytes, name)) } catch (e: DwarfParseException) {
                mainObj.warnings.add("dwo $name unparseable: ${e.message}"); null
            }
        }.filterNotNull()
        val model = DwarfModel(mainObj, dwos, fileName)
        validateDwos(model)
        return model
    }

    private fun validateDwos(model: DwarfModel) {
        val skeletons = model.main.units.filter { it.isSkeleton }
        if (skeletons.isEmpty()) return
        for (cu in skeletons) {
            val dwoId = cu.root?.at(Dw.AT_GNU_dwo_id)?.asLong() ?: cu.root?.at(Dw.AT_dwo_id)?.asLong()
            val dwoName = cu.root?.at(Dw.AT_GNU_dwo_name) ?: cu.root?.at(Dw.AT_dwo_name)
            val nameHint = dwoName?.let { model.main.strings.stringOf(cu, it) }?.substringAfterLast('/')
            val match = model.dwos.firstOrNull { dwo ->
                dwo.units.any { u ->
                    u.root?.at(Dw.AT_dwo_id)?.asLong()?.let { it == dwoId } == true ||
                        u.root?.at(Dw.AT_GNU_dwo_id)?.asLong()?.let { it == dwoId } == true
                }
            } ?: model.dwos.firstOrNull { nameHint != null && it.elf.fileName.substringAfterLast('/') == nameHint }
            if (match == null) {
                cu.warnings.add("split DWARF companion (.dwo) missing" + (nameHint?.let { ": $it" } ?: "") +
                    " — line/column from skeleton line table are still valid; inline tree may be incomplete")
            }
        }
    }

    fun loadObject(elf: ElfFile): LoadedObject {
        val warnings = mutableListOf<String>()
        val s = DwarfSections(
            info = elf.sectionByName[".debug_info"]?.data,
            abbrev = elf.sectionByName[".debug_abbrev"]?.data,
            line = elf.sectionByName[".debug_line"]?.data,
            lineStr = elf.sectionByName[".debug_line_str"]?.data,
            str = elf.sectionByName[".debug_str"]?.data,
            strOffsets = elf.sectionByName[".debug_str_offsets"]?.data,
            ranges = elf.sectionByName[".debug_ranges"]?.data,
            rnglists = elf.sectionByName[".debug_rnglists"]?.data,
            addr = elf.sectionByName[".debug_addr"]?.data,
            infoDwo = elf.sectionByName[".debug_info.dwo"]?.data,
            abbrevDwo = elf.sectionByName[".debug_abbrev.dwo"]?.data,
            strDwo = elf.sectionByName[".debug_str.dwo"]?.data,
            strOffsetsDwo = elf.sectionByName[".debug_str_offsets.dwo"]?.data,
            lineDwo = elf.sectionByName[".debug_line.dwo"]?.data,
            lineStrDwo = elf.sectionByName[".debug_line_str.dwo"]?.data,
            rnglistsDwo = elf.sectionByName[".debug_rnglists.dwo"]?.data,
            addrDwo = elf.sectionByName[".debug_addr.dwo"]?.data,
        )
        // Choose .dwo payloads when the file *only* contains split sections
        val sections = if (s.info == null && s.infoDwo != null) {
            DwarfSections(
                info = s.infoDwo, abbrev = s.abbrevDwo ?: s.abbrev, line = s.lineDwo ?: s.line,
                lineStr = s.lineStrDwo ?: s.lineStr, str = s.strDwo ?: s.str,
                strOffsets = s.strOffsetsDwo ?: s.strOffsets, rnglists = s.rnglistsDwo ?: s.rnglists,
                addr = s.addrDwo ?: s.addr,
            )
        } else s
        val abbrevTables = sections.abbrev?.let {
            try { AbbrevParser.parse(it, elf.littleEndian) } catch (e: DwarfParseException) {
                warnings.add(".debug_abbrev corrupt: ${e.message}"); emptyMap()
            }
        } ?: emptyMap()
        val parser = InfoParser(sections, abbrevTables, elf.littleEndian)
        val units = if (sections.info != null && abbrevTables.isNotEmpty()) {
            try { parser.parse() } catch (e: DwarfParseException) { warnings.add(".debug_info corrupt: ${e.message}"); emptyList() }
        } else emptyList()
        val lineSeq = sections.line?.let {
            try { LineProgramParser(sections, elf.littleEndian).parseAll() } catch (e: DwarfParseException) {
                warnings.add(".debug_line corrupt: ${e.message}"); emptyList()
            }
        } ?: emptyList()
        return LoadedObject(elf, sections, units, lineSeq, abbrevTables,
            StringResolver(sections, elf.littleEndian), RangeParser(sections, elf.littleEndian), warnings)
    }
}