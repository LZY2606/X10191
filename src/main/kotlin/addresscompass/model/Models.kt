package addresscompass.model

/** Segmented address: a selector plus an offset within that selector space. */
data class Addr(val selector: Int, val offset: Long) : Comparable<Addr> {
    override fun compareTo(other: Addr): Int {
        if (selector != other.selector) return selector.compareTo(other.selector)
        return offset.compareTo(other.offset)
    }
    companion object {
        fun of(offset: Long, selector: Int = 0) = Addr(selector, offset)
    }
}

/** Half-open [low, high). Zero length (low == high) is legal but matches nothing. */
data class AddrRange(val selector: Int, val low: Long, val high: Long) {
    val width: Long get() = high - low
    val isEmpty: Boolean get() = high == low
    fun contains(selector: Int, off: Long): Boolean =
        this.selector == selector && off >= low && off < high
    fun contains(a: Addr): Boolean = contains(a.selector, a.offset)
}

enum class Trust { FULL, PARTIAL, UNRELIABLE }

enum class Severity { WARNING, ERROR }

data class ParseIssue(
    val severity: Severity,
    val section: String,
    val offset: Long,
    val message: String,
    val isolated: Boolean = false,
)

data class SectionSummary(
    val name: String,
    val type: Long,
    val flags: Long,
    val addr: Long,
    val fileOffset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val entsize: Long,
    val nobits: Boolean,
    val sha256: String?,
)

data class ElfSegment(val type: Long, val flags: Long, val offset: Long, val vaddr: Long,
                      val filesz: Long, val memsz: Long) {
    fun containsFileVaddr(off: Long): Boolean = off >= vaddr && off < vaddr + memsz
}

// ---------- DWARF attribute values ----------

sealed interface FormValue {
    data class AddrV(val v: Long) : FormValue
    data class Udata(val v: Long) : FormValue
    data class Sdata(val v: Long) : FormValue
    data class Str(val s: String) : FormValue
    data class Flag(val v: Boolean) : FormValue
    /** Offset inside a target section (.debug_info, .debug_ranges, .debug_rnglists, ...). */
    data class SecOffset(val v: Long) : FormValue
    data class Block(val bytes: ByteArray) : FormValue
    /** Index into .debug_addr / str offsets / rnglists; size semantics depend on the form. */
    data class Indexed(val index: Long) : FormValue
    /** External (supplementary/.dwo alt) reference that cannot be followed in this file. */
    data class External(val raw: Long) : FormValue
}

data class AttrVal(val attr: Int, val form: Int, val value: FormValue)

class DIE(
    val offset: Long,
    val tag: Int,
    val hasChildren: Boolean,
    val attrs: List<AttrVal>,
    val depth: Int,
) {
    val children = mutableListOf<DIE>()
    var parent: DIE? = null

    /** Resolved after parsing; ranges use absolute file vaddrs (selector aware). */
    var ranges: List<AddrRange> = emptyList()

    fun attr(a: Int): AttrVal? = attrs.firstOrNull { it.attr == a }
    fun flag(a: Int): Boolean = (attr(a)?.value as? FormValue.Flag)?.v ?: false
    fun udata(a: Int): Long? = when (val v = attr(a)?.value) {
        is FormValue.Udata -> v.v
        is FormValue.Sdata -> v.v
        is FormValue.AddrV -> v.v
        else -> null
    }
    fun string(): String? = (attr(0x03)?.value as? FormValue.Str)?.s       // DW_AT_name
    fun declFile(): Long? = udata(0x3a)                                    // DW_AT_decl_file
    fun declLine(): Long? = udata(0x3b)                                    // DW_AT_decl_line
}

// ---------- line program ----------

data class LineFile(val name: String, val dirIndex: Int, val compDir: String?) {
    fun fullPath(compDirFallback: String?): String {
        val dir = compDir ?: compDirFallback
        return when {
            name.startsWith('/') -> name
            dir.isNullOrEmpty() -> name
            dir.endsWith('/') -> dir + name
            else -> "$dir/$name"
        }
    }
}

data class LineRow(
    val address: Addr,
    val file: Int,
    val line: Int,
    val column: Int,
    val opIndex: Int,
    val isa: Int,
    val discriminator: Int,
    val prologueEnd: Boolean,
    val endSequence: Boolean,
)

data class LineStep(
    val ord: Int,
    val opName: String,
    val address: Addr,
    val file: Int,
    val line: Int,
    val column: Int,
    val opIndex: Int,
    val isStmt: Boolean,
    val prologueEnd: Boolean,
    val emitted: Boolean,
    val endSequence: Boolean,
)

data class LineSequence(
    val index: Int,
    val stmtListOffset: Long,
    val rows: List<LineRow>,
    val endAddress: Addr,
) {
    val startAddress: Addr get() = rows.firstOrNull()?.address ?: endAddress
    fun covers(a: Addr): Boolean {
        val first = rows.firstOrNull()?.address ?: return false
        return a.selector == endAddress.selector && a.offset >= first.offset && a.offset < endAddress.offset
    }
}

data class LineProgram(
    val cuOffset: Long,
    val sectionOffset: Long,
    val version: Int,
    val addressSize: Int,
    val minInstructionLength: Int,
    val maxOpsPerInstruction: Int,
    val defaultIsStmt: Boolean,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val compDir: String?,
    val dirs: List<String>,
    val files: List<LineFile>,
    val sequences: List<LineSequence>,
    val steps: List<LineStep>,
    val issues: List<ParseIssue>,
) {
    fun fileText(index: Int): String? {
        if (index <= 0 || index > files.size) return null
        val f = files[index - 1]
        val dir = if (f.dirIndex in dirs.indices) dirs[f.dirIndex] else compDir
        return f.fullPath(dir)
    }
}

// ---------- compilation units ----------

data class CompileUnit(
    val id: Int,
    val sectionOffset: Long,
    val unitLength: Long,
    val version: Int,
    val dwarf64: Boolean,
    val unitType: Int,
    val addressSize: Int,
    val abbrevOffset: Long,
    val root: DIE?,
    val name: String?,
    val compDir: String?,
    val stmtListOffset: Long?,
    val lowPc: Long?,
    val dwoId: Long?,
    val dwoName: String?,
    val isSkeleton: Boolean,
    val isSplit: Boolean,
    val rnglistsBase: Long?,
    val addrBase: Long?,
    val strOffsetsBase: Long?,
    val issues: MutableList<ParseIssue>,
    var trust: Trust,
) {
    private val dieByOffset = HashMap<Long, DIE>()

    fun indexDies() {
        dieByOffset.clear()
        fun walk(d: DIE) {
            dieByOffset[d.offset] = d
            d.children.forEach(::walk)
        }
        root?.let(::walk)
    }

    fun dieAtRelative(rel: Long): DIE? = dieByOffset[rel]
    val key: String get() = "cu@0x${sectionOffset.toString(16)}"
    val unitTypeName: String get() = UnitTypes.name(unitType, version)
}

data class ParsedDebug(
    val fileName: String,
    val sha256: String,
    val elfClass: Int,
    val endian: String,
    val machine: Int,
    val elfType: Int,
    val buildId: String?,
    val preferredBase: Long,
    val endOfImage: Long,
    val sections: List<SectionSummary>,
    val segments: List<ElfSegment>,
    val cus: List<CompileUnit>,
    val linePrograms: Map<Long, LineProgram>,
    val issues: List<ParseIssue>,
    val missingDwos: List<String>,
)
