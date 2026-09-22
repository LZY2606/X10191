package compass.dwarf

/** 解析诊断：缺 dwo、损坏 section、越界引用、未知 form 都落在这里，绝不静默。 */
data class Diagnostic(
    val severity: String, // ERROR | WARNING | INFO
    val area: String,     // elf | info:<cu> | line:<cu> | ranges | abbrev
    val message: String
)

data class SectionInfo(
    val name: String,
    val type: Long,
    val fileOffset: Long,
    val size: Long,
    val link: Int,
    val addressAlign: Long,
    val dataDigest: String, // 原始字节摘要（SHA-256 前 16 字节）
    val present: Boolean
)

data class ProgramSegment(
    val type: Long,
    val flags: Long,
    val offset: Long,
    val vaddr: Long,
    val fileSize: Long,
    val memSize: Long
)

data class ElfInfo(
    val elfClass: Int, // 1 = 32, 2 = 64
    val endian: Int,   // 1 = little
    val machine: Int,
    val entry: Long,
    val type: Int,
    val sections: List<SectionInfo>,
    val segments: List<ProgramSegment>,
    val buildId: String?,
    val fileDigest: String
) {
    fun section(name: String): SectionInfo? = sections.firstOrNull { it.name == name && it.present }
}

data class DAttr(val attr: Int, val form: Int, val value: Any?)

/** DW_AT_form 原始值的包装；第二次扫描再解释 strx/addrx/strp 等。 */
object Raw {
    data class StrPtr(val offset: Long)            // .debug_str / .debug_line_str
    data class StrIndex(val index: Long)           // strx*
    data class AddrIndex(val index: Long)          // addrx*
    data class DieRef(val globalOffset: Long)      // ref_* 已换算为全局偏移
    data class Blob(val bytes: ByteArray)
}

data class Die(
    val offset: Long,           // .debug_info 全局偏移
    val tag: Int,
    val depth: Int,
    val abbrevCode: Long,
    val attrs: MutableList<DAttr> = mutableListOf(),
    val children: MutableList<Die> = mutableListOf(),
    var cuIndex: Int = -1
) {
    fun attr(name: Int): DAttr? = attrs.firstOrNull { it.attr == name }
    fun num(name: Int): Long? = (attr(name)?.value as? Long)
}

data class AddrRange(
    val segment: Long,
    val lo: Long,      // 无符号 64 位语义，用 Long 位模式保存
    val hi: Long,      // 半开区间 [lo, hi)，允许 lo == hi（零长度范围）
    val source: String,
    val zeroLength: Boolean
)

data class LineFile(val index: Int, val directory: String, val name: String) {
    val path: String get() = if (directory.isEmpty() || directory == ".") name else "$directory/$name"
}

data class LineRow(
    val order: Int,
    val segment: Long,
    val address: Long,
    val fileIndex: Int,
    val line: Int,
    val column: Int,
    val isa: Int,
    val discriminator: Int,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val endSequence: Boolean,
    val prologueEnd: Boolean
)

data class LineEvent(
    val order: Int,
    val opcode: String,
    val segment: Long,
    val address: Long,
    val fileIndex: Int,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val endSequence: Boolean,
    val note: String
)

data class LineSequence(val index: Int, val segment: Long, val start: Long, val end: Long, val rowCount: Int)

data class LineProgram(
    val version: Int,
    val minInstructionLength: Int,
    val maxOpsPerInstruction: Int,
    val defaultIsStmt: Boolean,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val standardOpcodeLengths: List<Int>,
    val directories: List<String>,
    val files: List<LineFile>,
    val segmentSelectorSize: Int,
    val addressSize: Int,
    val rows: List<LineRow>,
    val events: List<LineEvent>,
    val sequences: List<LineSequence>,
    val diagnostics: List<Diagnostic>
)

data class CompileUnit(
    val globalOffset: Long,
    val length: Long,
    val version: Int,
    val is64: Boolean,
    val unitType: Int,
    val addressSize: Int,
    val abbrevOffset: Long,
    val root: Die?,
    val diesFlat: List<Die>,
    val ranges: List<AddrRange>,
    val lineProgram: LineProgram?,
    val dwoName: String?,
    val dwoId: Long?,
    val name: String?,
    val compDir: String?,
    val producer: String?,
    val language: Long?,
    val stmtList: Long?,
    val lowPc: Long?,
    val dieRanges: Map<Long, List<AddrRange>>,
    val poisoned: Boolean,
    val diagnostics: List<Diagnostic>
)

data class ParseResult(
    val elf: ElfInfo,
    val units: List<CompileUnit>,
    val diagnostics: List<Diagnostic>,
    /** section 名 -> 原始字节（仅调试相关 section），供查询阶段二次解析。 */
    val sectionBytes: Map<String, ByteArray>
)
