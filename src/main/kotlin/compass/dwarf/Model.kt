package compass.dwarf

/** 属性值的类别（决定 high_pc 等语义解释）。 */
enum class AttrClass { ADDRESS, CONSTANT, STRING, FLAG, REFERENCE, BLOCK, EXPRLOC, UNRESOLVED }

data class AttrValue(
    val cls: AttrClass,
    val num: Long? = null,
    val str: String? = null,
    val blob: ByteArray? = null,
) {
    override fun toString(): String = when (cls) {
        AttrClass.ADDRESS -> hexU(num ?: 0)
        AttrClass.CONSTANT -> "${num}"
        AttrClass.STRING -> "\"$str\""
        AttrClass.FLAG -> "${num != 0L}"
        AttrClass.REFERENCE -> "ref@${hexU(num ?: 0)}"
        AttrClass.BLOCK, AttrClass.EXPRLOC -> "block(${blob?.size ?: 0}B)"
        AttrClass.UNRESOLVED -> "unresolved(${num})"
    }
}

class Die(
    val offset: Long,          // 在 .debug_info section 内的绝对偏移
    val tag: Int,
    val depth: Int,
    val attrs: Map<Int, AttrValue>,
) {
    val children = mutableListOf<Die>()

    val tagName: String get() = Dw.tagName(tag)
    fun num(at: Int): Long? = attrs[at]?.num
    fun str(at: Int): String? = attrs[at]?.str
    val name: String? get() = str(Dw.AT_name) ?: str(Dw.AT_linkage_name)

    /** 深度优先遍历（含自身）。 */
    fun walk(out: MutableList<Die> = mutableListOf()): List<Die> {
        out.add(this)
        for (c in children) c.walk(out)
        return out
    }
}

data class AddressRange(val start: Long, val end: Long, val source: String) {
    val width: Long get() = end - start // 位模式差；调用方保证 end>=start（无符号）
    val zeroLength: Boolean get() = start == end
    fun contains(a: Long): Boolean = rangeContains(start, end, a)
}

data class LineFile(val name: String, val dirIndex: Long, val dir: String?) {
    val fullPath: String get() = if (dir.isNullOrEmpty()) name else "$dir/$name"
}

data class LineRow(
    val sequence: Int,
    val address: Long,
    var endAddress: Long,   // 解析完成后回填：同 sequence 下一行地址
    val file: Int,
    val fileName: String,
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
) {
    fun contains(a: Long): Boolean = !endSequence && rangeContains(address, endAddress, a)
}

/** 解码后的单条行程序指令（用于界面展示状态变化）。 */
data class LineOp(val offset: Int, val text: String)

class LineProgram(
    val version: Int,
    val addressSize: Int,
    val dirs: List<String>,
    val files: List<LineFile>,
    val rows: List<LineRow>,
    val ops: List<LineOp>,
    val warnings: List<String>,
) {
    val sequenceCount: Int get() = (rows.maxOfOrNull { it.sequence } ?: -1) + 1
    fun fileAt(register: Int): LineFile? {
        // DWARF5：file 寄存器是 file_names 的 0 基索引；DWARF2-4：1 基。
        val idx = if (version >= 5) register else register - 1
        return files.getOrNull(idx)
    }
}

class ParsedUnit(
    val sectionName: String,
    val unitOffset: Long,
    val version: Int,
    val unitType: Int?,
    val addressSize: Int,
    val offsetSize: Int,
) {
    val isDwo: Boolean get() = sectionName.endsWith(".dwo")
    var isSkeleton: Boolean = false
    var dwoName: String? = null
    var cuName: String? = null
    var compDir: String? = null
    var lowPc: Long? = null
    var stmtList: Long? = null
    var rnglistsBase: Long = 0L
    val ranges = mutableListOf<AddressRange>()
    val roots = mutableListOf<Die>()
    val dieByOffset = mutableMapOf<Long, Die>()
    var lineProgram: LineProgram? = null
    var status: String = "ok"          // ok | degraded
    var error: String? = null
    val notes = mutableListOf<String>()

    val label: String
        get() = (cuName ?: "CU@${hexU(unitOffset)}") +
                " [DWARF$version${if (isDwo) " dwo" else ""}${if (isSkeleton) " skeleton" else ""}]"

    fun contains(a: Long): Boolean = ranges.any { it.contains(a) }
}

class ParsedFile(
    val fileName: String,
    val elf: compass.elf.ElfFile,
    val units: List<ParsedUnit>,
    val warnings: List<String>,
)
