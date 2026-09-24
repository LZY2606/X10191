package compass.dwarf

/** 分段地址（selector 默认为 0） */
data class SegAddr(val segment: Int, val offset: Long)

data class AddrRange(val start: Long, val end: Long, val explicit: Boolean) {
    val length: Long get() = end - start
    fun contains(a: Long): Boolean = if (start == end) a == start else a in start until end
}

sealed class AttrValue {
    data class Addr(val v: Long) : AttrValue()
    data class Data(val v: Long) : AttrValue()
    data class Str(val v: String) : AttrValue()
    data class Block(val v: ByteArray) : AttrValue()
    data class ExprLoc(val v: ByteArray) : AttrValue()
    /** DW_FORM_ref* 已解析为 .debug_info 全局偏移 */
    data class Ref(val globalOffset: Long) : AttrValue()
    data class Signature(val v: Long) : AttrValue()
    /** addrX 索引（运行期地址，位于 .debug_addr） */
    data class AddrIndex(val index: Long) : AttrValue()
    /** strX 索引（位于 .debug_str_offsets） */
    data class StrIndex(val index: Long) : AttrValue()
}

/** 属性值 + 原始 form（用于区分 sec_offset / rnglistx 等） */
data class AtVal(val form: Int, val value: AttrValue)

data class Die(
    val offset: Long,
    val tag: Int,
    val depth: Int,
    val parentOffset: Long?,
    val childOffsets: MutableList<Long> = mutableListOf(),
    val attrs: Map<Int, AtVal>,
) {
    fun attr(a: Int): AttrValue? = attrs[a]?.value
    fun atVal(a: Int): AtVal? = attrs[a]
    val name: String?
        get() = (attr(DW_AT.NAME) as? AttrValue.Str)?.v
            ?: (attr(DW_AT.LINKAGE_NAME) as? AttrValue.Str)?.v
}

data class FileEntry(val name: String, val dirIndex: Int)

data class LineRow(
    val address: Long,
    val segment: Int,
    val fileIndex: Int,
    val line: Int,
    val column: Int,
    val opIndex: Int,
    val isa: Int,
    val discriminator: Int,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val endSequence: Boolean,
    val sequenceIndex: Int,
)

data class LineSequence(val index: Int, val startRow: Int, val endRow: Int, val lowPc: Long, val highPc: Long)

data class LineProgram(
    val offset: Long,
    val version: Int,
    val dwarf64: Boolean,
    val addressSize: Int,
    val segmentSize: Int,
    val directories: List<String>,
    val files: List<FileEntry>,
    val rows: List<LineRow>,
    val sequences: List<LineSequence>,
    val cuOffset: Long?,
    val error: String? = null,
) {
    fun fileName(index: Int): String? {
        if (index == 0) return null
        val f = files.getOrNull(index - 1) ?: return null
        val dir = directories.getOrNull(f.dirIndex)
        return if (dir.isNullOrEmpty() || dir == "/") f.name else "$dir/${f.name}".replace("//", "/")
    }
}

data class CompUnit(
    val index: Int,
    val fileIndex: Int,
    val offset: Long,
    val length: Long,
    val dwarf64: Boolean,
    val version: Int,
    val unitType: Int,
    val addressSize: Int,
    val abbrevOffset: Long,
    val dwoId: Long?,
    val stmtList: Long?,
    val strOffsetsBase: Long?,
    val addrBase: Long?,
    val rnglistsBase: Long?,
    val rootName: String?,
    val compDir: String?,
    val producer: String?,
    val dies: List<Die>,
    val lineProgram: LineProgram?,
    val error: String?,
) {
    val isSkeleton: Boolean get() = version >= 5 && unitType == DW_UT.SKELETON
    val isSplit: Boolean get() = unitType == DW_UT.SPLIT_COMPILE || unitType == DW_UT.SPLIT_TYPE
    fun dieAt(globalOffset: Long): Die? = dies.firstOrNull { it.offset == globalOffset }
    val root: Die? get() = dies.firstOrNull()
}
