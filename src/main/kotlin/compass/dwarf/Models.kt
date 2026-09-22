@file:Suppress("unused")
package compass.dwarf

/** Decoded value of a DIE attribute. */
sealed class AttrValue {
    data class Address(val v: Long) : AttrValue()
    data class Constant(val v: Long) : AttrValue()
    data class StringVal(val v: String) : AttrValue()
    data class Flags(val v: Boolean) : AttrValue()
    /** Section-relative reference (debug_info) resolved lazily. */
    data class Reference(val globalOffset: Int) : AttrValue()
    /** Unresolved index form (strx/addrx/rnglistx) kept for diagnostics. */
    data class Indexed(val index: ULong, val form: Int) : AttrValue()
    /** Block/expr bytes — opaque but consumed so cursor stays aligned. */
    data class Block(val bytes: ByteArray) : AttrValue()
    /** Form could not be decoded (unknown); the attribute is dropped, but scan continued. */
    data object Unsupported : AttrValue()
}

data class DieNode(
    val offset: Int,
    val tag: Int,
    val attrs: Map<Int, AttrValue>,
    val depth: Int,
    val children: List<DieNode> = emptyList()
) {
    fun attr(a: Int): AttrValue? = attrs[a]
    fun name(): String? = (attr(DW.AT_NAME) as? AttrValue.StringVal)?.v
    fun walk(visitor: (DieNode) -> Unit) {
        visitor(this)
        children.forEach { it.walk(visitor) }
    }
}

data class RangeEntry(val start: Long, val end: Long) {
    val length: Long get() = end - start
    fun contains(vma: Long): Boolean = vma in start until end
}

data class LineFile(val dir: String, val name: String) {
    val fullPath: String get() = if (dir.isEmpty() || dir == ".") name else "$dir/$name"
}

data class LineRow(
    val address: Long,
    val endSequence: Boolean,
    val file: LineFile?,
    val fileIndex: Int,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val opIndex: Int,
    val isa: Int,
    val discriminator: Int
)

data class LineSequence(val rows: List<LineRow>, val cuOffset: Int) {
    val startAddress: Long get() = rows.firstOrNull()?.address ?: 0L
    fun rowFor(vma: Long): LineRow? {
        var best: LineRow? = null
        for (row in rows) {
            if (row.address <= vma && !row.endSequence) best = row
            else if (row.endSequence && row.address <= vma) return best
            else if (row.address > vma) return best
        }
        return best
    }
    fun covers(vma: Long): Boolean {
        if (rows.isEmpty()) return false
        val first = rows.first().address
        val last = rows.last()
        return vma in first until last.address
    }
}

data class CompileUnit(
    val offset: Int,
    val version: Int,           // 4 or 5
    val unitType: Int,          // DW_UT_* (0 for v4)
    val is64: Boolean,
    val die: DieNode,
    val name: String?,
    val compDir: String?,
    val producer: String?,
    val language: Long?,
    val stmtListOffset: Long?,
    val rangesOffset: Long?,
    val dwoName: String?,
    val skeletonFor: Boolean,   // DW_UT_skeleton (DWARF5 split)
    val split: Boolean,         // DW_UT_split_compile
    val addressSize: Int,
    val strOffsetsBase: Long,
    val addrBase: Long,
    val rangesBase: Long,
    val ranges: List<RangeEntry>,
    val sequences: List<LineSequence>,
    val notes: List<String>,
    val allDies: List<DieNode>
)
