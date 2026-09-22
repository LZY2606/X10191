package compass.dwarf

sealed class AttrValue {
    data class Number(val v: Long, val constant: Boolean = false) : AttrValue()
    data class Str(val v: String) : AttrValue()
    data class Bytes(val v: ByteArray) : AttrValue()
    data class StrRef(val section: String, val offset: Long) : AttrValue() // resolved lazily
    data class RefCu(val offset: Long) : AttrValue()                        // CU-relative offset
    data class RefGlobal(val offset: Long) : AttrValue()                    // .debug_info global offset
    data class RefAlt(val offset: Long) : AttrValue()                       // supplemental/dwp
    data class RefSig(val signature: Long) : AttrValue()                    // type-unit signature
    data class Strx(val index: Long, val base: Long?) : AttrValue()
    data class Addrx(val index: Long, val base: Long?) : AttrValue()
    data class Rnglistx(val index: Long) : AttrValue()
    data class UnknownForm(val code: Int) : AttrValue()
    fun asLong(): Long? = when (this) { is AttrValue.Number -> v; else -> null }
}

data class AttributeSpec(val name: Int, val form: Int, val implicitConst: Long? = null)

class Abbrev(
    val code: Long,
    val tag: Int,
    val hasChildren: Boolean,
    val specs: List<AttributeSpec>,
)

class DIE(
    val offset: Long,                 // global .debug_info offset of the DIE
    val tag: Int,
    val abbrevCode: Long,
    val attrs: Map<Int, AttrValue>,
    var parent: DIE? = null,
    val children: MutableList<DIE> = mutableListOf(),
) {
    fun at(name: Int): AttrValue? = attrs[name]
    val name: String? get() = at(Dw.AT_name)?.let { (it as? AttrValue.StrRef)?.let { null } ?: (it as? AttrValue.Number)?.let { null } }
}

/** A single [start,end) pair. Zero-length ranges are legal and kept (start == end). */
data class RangeEntry(val start: Long, val end: Long, val zeroLength: Boolean = start == end) {
    fun contains(addr: Long): Boolean = addr in start until end
    val width: Long get() = end - start
}

class CompUnit(
    val headerOffset: Long,
    val unitLength: Long,             // length field value (excluding the initial 4/12 bytes)
    val version: Int,
    val unitType: Int,
    val is64Bit: Boolean,
    val addressSize: Int,
    val debugAbbrevOffset: Long,
    val dieOffset: Long,              // offset of first DIE in .debug_info
    val globalOffsetSize: Int,        // 4 or 8 (ref_addr / str_offsets sizes in v5)
    val dwoId: Long?,                 // DW_AT_dwo_id / GNU_dwo_id
    var root: DIE? = null,
    /** Non-fatal notes collected while parsing this unit (unknown forms, bad refs...). */
    val warnings: MutableList<String> = mutableListOf(),
) {
    val isSkeleton: Boolean get() = unitType == UNIT_SKELETON || unitType == UNIT_SKELETON_DWP
    val name: String get() = root?.at(Dw.AT_name)?.let { null } ?: ""
    val endOffset: Long get() = headerOffset + (if (is64Bit) 12 else 4) + unitLength

    companion object {
        const val UNIT_COMPILE = 0x01
        const val UNIT_TYPE = 0x02
        const val UNIT_PARTIAL = 0x03
        const val UNIT_SKELETON = 0x04
        const val UNIT_SPLIT_COMPILE = 0x05
        const val UNIT_SKELETON_DWP = 0x06
        const val UNIT_SPLIT_TYPE = 0x07
    }
}

data class LineFile(val name: String?, val directoryIndex: Int, val timestamp: Long, val size: Long)

data class LineRow(
    val address: Long,
    val segment: Long,
    val fileIndex: Int,
    val line: Int,
    val column: Int,
    val isStatement: Boolean,
    val basicBlock: Boolean,
    val endSequence: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Int,
    val discriminator: Int,
    val opIndex: Int,
)

class LineSequence(
    val unitOffset: Long,
    val cuVersion: Int,
    val headerOffset: Long,
    val files: List<LineFile>,
    val directories: List<String?>,
    val compDir: String?,
    val rows: List<LineRow>,
) {
    val startAddress: Long = rows.firstOrNull()?.address ?: 0L
    val endAddress: Long get() {
        val es = rows.lastOrNull { it.endSequence }?.address
        if (es != null) return es
        return rows.maxOfOrNull { it.address } ?: 0L
    }
    fun contains(addr: Long): Boolean {
        // end_sequence rows carry the first address *after* the sequence
        val first = rows.firstOrNull()?.address ?: return false
        val end = endAddress
        return if (rows.any { it.endSequence }) addr >= first && addr < end
        else rows.any { it.address == addr }
    }
}

class Section(
    var name: String,
    val shOffset: Long,
    val shType: Long,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Long,
    val addralign: Long,
    val data: ByteArray,
)
