package compass.dwarf

/** A half-open address range [start, end). Zero-length ranges are kept but match nothing. */
data class AddressRange(val start: Long, val end: Long) {
    val size: Long get() = end - start
    fun contains(addr: Long): Boolean = addr >= start && addr < end
}

/** Typed attribute value. Indirect forms stay unresolved until a CU context resolves them. */
sealed class AttrValue {
    data class Addr(val v: Long) : AttrValue()
    data class UInt(val v: Long) : AttrValue()
    data class SInt(val v: Long) : AttrValue()
    data class Str(val s: String) : AttrValue()
    data class Strp(val offset: Long) : AttrValue()
    data class LineStrp(val offset: Long) : AttrValue()
    data class StrIndex(val index: Long) : AttrValue()
    data class Ref(val offset: Long) : AttrValue()
    data class Block(val bytes: ByteArray) : AttrValue()
    data class Flag(val v: Boolean) : AttrValue()
    data class SecOffset(val v: Long) : AttrValue()
    data class AddrIndex(val index: Long) : AttrValue()
    data class RngListIndex(val index: Long) : AttrValue()
    data class Unknown(val form: Int) : AttrValue()
}

class Die(
    val offset: Long,
    val tag: Int,
    val depth: Int,
    val abbrevCode: Long,
) {
    val attrs = LinkedHashMap<Int, AttrValue>()
    val children = ArrayList<Die>()
    var parent: Die? = null
    /** Parsing of this DIE stopped early (unknown form / truncation). */
    var truncated: Boolean = false

    fun attr(code: Int): AttrValue? = attrs[code]

    fun allDescendants(out: MutableList<Die> = ArrayList()): List<Die> {
        for (c in children) {
            out.add(c)
            c.allDescendants(out)
        }
        return out
    }
}

class CompilationUnit(
    val offset: Long,
    val version: Int,
    val unitType: Int,
    val addressSize: Int,
    val abbrevOffset: Long,
    val isDwarf64: Boolean,
    val index: Int,
) {
    var root: Die? = null
    var addrBase: Long = 0
    var strOffsetsBase: Long = 0
    var rnglistsBase: Long = 0
    var lowPc: Long? = null
    var rangesOffset: AttrValue? = null
    var name: String? = null
    var compDir: String? = null
    var producer: String? = null
    var dwoName: String? = null
    var stmtList: Long? = null
    var lineProgram: LineProgram? = null
    /** CU finished parsing without structural errors. */
    var degraded: Boolean = false
    val notes = ArrayList<String>()
}

class LineFile(val name: String, val dirIndex: Long, val dirName: String?)

class LineHeader(
    val version: Int,
    val addressSize: Int,
    val segmentSelectorSize: Int,
    val minInstructionLength: Int,
    val maxOpsPerInstruction: Int,
    val defaultIsStmt: Boolean,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val standardOpcodeLengths: IntArray,
    val directories: List<String>,
    val files: List<LineFile>,
    val programStart: Int,
    val programEnd: Int,
)

class LineRow(
    val address: Long,
    val file: Int,
    val line: Long,
    val column: Long,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val endSequence: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Long,
    val discriminator: Long,
    val opIndex: Long,
    val sequence: Int,
)

class LineSequence(val index: Int, val rows: List<LineRow>) {
    val start: Long get() = rows.first().address
    val end: Long get() = rows.last().address
    fun contains(addr: Long): Boolean = addr >= start && addr < end
}

class LineProgram(
    val header: LineHeader,
    val sequences: List<LineSequence>,
    val notes: List<String>,
) {
    fun fileName(index: Int): String? {
        val files = header.files
        val i = if (header.version >= 5) index else index - 1
        if (i < 0 || i >= files.size) return null
        val f = files[i]
        val dir = if (f.dirName != null) f.dirName
        else if (f.dirIndex == 0L && header.version >= 5) header.directories.getOrNull(0)
        else header.directories.getOrNull((f.dirIndex - 1).toInt())
        return if (dir.isNullOrEmpty()) f.name else "$dir/${f.name}"
    }
}
