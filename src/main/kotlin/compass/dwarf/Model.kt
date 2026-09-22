package compass.dwarf

/** Resolved value of a DIE attribute after all sections/CUs were parsed. */
sealed interface AttrValue {
    data class Addr(val value: Long) : AttrValue
    data class IntValue(val value: Long) : AttrValue
    data class Str(val value: String) : AttrValue
    data class Ref(val globalOffset: Long) : AttrValue
    data class RangeRef(val sectionOffset: Long, val indexed: Boolean) : AttrValue
    data class SectionOffset(val section: String, val offset: Long) : AttrValue
    data class Unknown(val formCode: Int) : AttrValue
}

/** Raw attribute kept while parsing; resolved later when CU bases are known. */
data class RawAttr(val name: Int, val form: Int, val raw: Any)

data class Die(
    val globalOffset: Long,
    val abbrevCode: Long,
    val tag: Int,
    val children: MutableList<Die> = mutableListOf(),
    var parent: Die? = null,
    val attrs: MutableMap<Int, AttrValue> = mutableMapOf(),
    val rawAttrs: MutableList<RawAttr> = mutableListOf()
) {
    val name: String? get() = (attrs[DwAttr.NAME] as? AttrValue.Str)?.value
    val lowPc: Long? get() = (attrs[DwAttr.LOW_PC] as? AttrValue.Addr)?.value
    val rangesRef: AttrValue.RangeRef? get() = attrs[DwAttr.RANGES] as? AttrValue.RangeRef
    val depth: Int get() = 1 + (parent?.depth ?: 0)
}

/** One [start,end) (or [start,start] zero-length) range plus an optional segment selector. */
data class AddrRange(val start: Long, val end: Long, val segment: Int = 0) {
    fun contains(addr: Long, seg: Int = 0): Boolean =
        seg == segment && if (start == end) addr == start else addr >= start && addr < end

    val length: Long get() = end - start
}

data class LineFile(val index: Int, val name: String, val dirIndex: Int)

data class LineRow(
    val address: Long,
    val segment: Int,
    val fileIndex: Int,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val endSequence: Boolean,
    val discriminator: Int,
    val opIndex: Int = 0
)

data class LineStep(
    val index: Int,
    val opcode: String,
    val address: Long,
    val fileIndex: Int,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val endSequence: Boolean,
    val emitted: Boolean,
    val note: String = ""
)

data class LineSequence(
    val index: Int,
    val startAddress: Long,
    val endAddress: Long,
    val segment: Int,
    val rows: List<LineRow>
) {
    /** Last row whose address <= target (or zero-length exact hit), within this sequence. */
    fun rowFor(target: Long, seg: Int = 0): LineRow? {
        if (seg != segment) return null
        if (rows.isEmpty()) return null
        if (target < startAddress) return null
        if (startAddress == endAddress) return rows.firstOrNull { it.address == target && !it.endSequence }
        if (target > endAddress) return null
        var best: LineRow? = null
        for (row in rows) {
            if (!row.endSequence && row.address <= target) best = row
        }
        // End-sequence row at exactly target still denotes that address.
        if (best == null) {
            val last = rows.last()
            if (last.endSequence && last.address == target) best = last
        }
        return best
    }
}

data class LineProgram(
    val cuOffset: Long,
    val sectionOffset: Long,
    val version: Int,
    val directoryTable: List<String>,
    val fileTable: List<LineFile>,
    val sequences: List<LineSequence>,
    val steps: List<LineStep>,
    val defaultIsStmt: Boolean,
    val stepsTruncated: Boolean,
    val opcodesBase: Int,
    val issues: List<String> = emptyList()
) {
    fun fileName(index: Int): String? = fileTable.firstOrNull { it.index == index }?.name
    fun filePath(index: Int): String? {
        val f = fileTable.firstOrNull { it.index == index } ?: return null
        val dir = directoryTable.getOrNull(f.dirIndex) ?: return f.name
        return if (dir.isEmpty() || dir == ".") f.name else "$dir/${f.name}"
    }
}

data class RngListHeader(
    val sectionOffset: Long,
    val offsetEntryCount: Long,
    val offsetArray: List<Long>,
    val version: Int
)

data class CompilationUnit(
    val sectionOffset: Long,
    val headerLength: Long,
    val endOffset: Long,
    val version: Int,
    val unitType: Int,
    val is64BitDwarf: Boolean,
    val abbrevOffset: Long,
    val addressSize: Int,
    val littleEndian: Boolean,
    val root: Die?,
    val lineProgram: LineProgram?,
    val ranges: List<AddrRange>,
    val dwoId: Long?,
    val dwoName: String?,
    val isSkeleton: Boolean,
    val isSplit: Boolean,
    val issues: MutableList<String>,
    val trust: MutableSet<String>,
    val sectionName: String
) {
    val name: String? get() = root?.name ?: lineProgram?.fileTable?.firstOrNull()?.name
    val compDir: String? get() = (root?.attrs?.get(DwAttr.COMP_DIR) as? AttrValue.Str)?.value
}

/** One diagnostic note attached to an import. */
data class SectionIssue(val severity: String, val where: String, val message: String)
