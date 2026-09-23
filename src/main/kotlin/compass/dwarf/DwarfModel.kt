package compass.dwarf

/** Raw view of the DWARF-bearing sections extracted from one ELF file. */
class DwarfSections(
    private val map: Map<String, ByteArray>,
    val isDwo: Boolean
) {
    operator fun get(name: String): ByteArray? = map[name]
    val names: Set<String> get() = map.keys

    companion object {
        private val DWARF_SECTIONS = listOf(
            ".debug_info", ".debug_abbrev", ".debug_line", ".debug_line_str",
            ".debug_str", ".debug_str_offsets", ".debug_addr",
            ".debug_ranges", ".debug_rnglists", ".debug_str_offsets.dwo",
            ".debug_addr.dwo", ".debug_info.dwo", ".debug_abbrev.dwo",
            ".debug_line.dwo", ".debug_str.dwo", ".debug_rnglists.dwo"
        )

        fun fromElf(elf: compass.elf.ElfFile): DwarfSections {
            val map = LinkedHashMap<String, ByteArray>()
            for (name in DWARF_SECTIONS) {
                val sec = elf.section(name) ?: continue
                val data = elf.sectionBytes(sec) ?: continue
                if (data.isNotEmpty()) map[name] = data
            }
            val isDwo = map.keys.any { it.endsWith(".dwo") } && map[".debug_info"] == null
            return DwarfSections(map, isDwo)
        }
    }
}

/** A decoded attribute value. Addresses that need split-DWARF indirection stay symbolic until resolve time. */
sealed class AttrValue {
    data class Addr(val value: Long) : AttrValue()
    data class AddrIndex(val index: Long) : AttrValue()
    data class Constant(val value: Long, val bytes: Int) : AttrValue()
    data class Str(val text: String) : AttrValue()
    data class StrRef(val offset: Long, val lineStr: Boolean) : AttrValue()
    data class StrIndex(val index: Long) : AttrValue()
    data class Block(val data: ByteArray) : AttrValue() {
        override fun equals(other: Any?) = other is Block && data.contentEquals(other.data)
        override fun hashCode() = data.contentHashCode()
    }
    /** Reference to a DIE; relative refs keep the owning CU until resolution. */
    data class Reference(val globalOffset: Long?, val cuLocal: Boolean, val localOffset: Long) : AttrValue()
    data class RngListRef(val offset: Long, val indexed: Boolean, val index: Long) : AttrValue()
    data class SecOffset(val value: Long) : AttrValue()
    data object FlagTrue : AttrValue()
    data class Flag(val value: Boolean) : AttrValue()
}

data class Attribute(val name: Int, val form: Int, val value: AttrValue)

data class Die(
    val offset: Long,
    val tag: Int,
    val children: MutableList<Die> = mutableListOf(),
    val attributes: MutableList<Attribute> = mutableListOf()
) {
    fun attr(name: Int): Attribute? = attributes.firstOrNull { it.name == name }
    var parent: Die? = null
}

data class AbbrevEntry(
    val code: Long,
    val tag: Int,
    val hasChildren: Boolean,
    val specs: List<Pair<Int, Int>>,
    val implicitConst: Long?
)

data class LineFile(var path: String?, val directoryIndex: Int?, val pendingStrRef: Long? = null, val pendingLineStr: Boolean = false)

data class LineHeader(
    val offset: Long,
    val version: Int,
    val addressSize: Int,
    val segmentSelectorSize: Int,
    val minInstructionLength: Int,
    val maxOpsPerInstruction: Int,
    val defaultIsStmt: Int,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val standardOpcodeLengths: IntArray,
    val directories: List<String>,
    val files: List<LineFile>,
    val fileIndexBase: Int,
    val programOffset: Long,
    val unitLength: Long
) {
    override fun equals(other: Any?): Boolean = other is LineHeader && offset == other.offset
    override fun hashCode(): Int = offset.hashCode()

    fun fileName(index: Int): String? {
        val i = index - fileIndexBase
        if (i < 0 || i >= files.size) return null
        return files[i].path
    }

    fun filePath(index: Int): String? {
        val i = index - fileIndexBase
        if (i < 0 || i >= files.size) return null
        val file = files[i]
        val name = file.path ?: return null
        val dirIdx = file.directoryIndex ?: return name
        val dir = directories.getOrNull(dirIdx)
        return if (dir.isNullOrEmpty() || dir == ".") name else "$dir/$name"
    }
}

data class LineRow(
    val address: Long,
    val segment: Long,
    val file: Int,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val endSequence: Boolean,
    val basicBlock: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Int,
    val discriminator: Int
)

data class LineSequence(val header: LineHeader, val rows: List<LineRow>) {
    val startAddress: Long get() = rows.firstOrNull()?.address ?: 0L
    val endAddress: Long get() = rows.lastOrNull()?.address ?: 0L
    val segments: List<LineRow> get() = rows
}

data class CompileUnit(
    val offset: Long,
    val version: Int,
    val unitType: Int,
    val addressSize: Int,
    val dwarf64: Boolean,
    val headerSize: Int,
    val endOffset: Long,
    val root: Die,
    val dies: List<Die>,
    val dwoId: Long?,
    val isSkeleton: Boolean,
    val corruptAfter: Long?,
    val warnings: List<String>
) {
    val name: String?
        get() = (root.attr(DW.AT_name)?.value as? AttrValue.Str)?.text
    val compDir: String?
        get() = (root.attr(DW.AT_comp_dir)?.value as? AttrValue.Str)?.text
}

/** Parsed view of every DWARF section in an artifact. */
class DwarfBundle(
    val sections: DwarfSections,
    val littleEndian: Boolean,
    val compileUnits: List<CompileUnit>,
    val linePrograms: List<LineSequence>,
    val lineHeaders: List<LineHeader>,
    val abbrevs: Map<Long, List<AbbrevEntry>>,
    val parseWarnings: List<String>
) {
    fun cuAtOffset(offset: Long): CompileUnit? = compileUnits.firstOrNull {
        offset >= it.offset && offset < it.endOffset
    }
    fun dieByGlobalOffset(offset: Long): Die? {
        for (cu in compileUnits) {
            if (offset >= cu.offset && offset < cu.endOffset) {
                return cu.dies.firstOrNull { it.offset == offset }
            }
        }
        return null
    }
}
