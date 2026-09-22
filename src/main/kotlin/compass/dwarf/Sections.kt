package compass.dwarf

import compass.model.BoundedReader
import compass.model.ElfFile

/**
 * Raw debug sections sliced out of an ELF. Compressed (.zdebug) sections are
 * reported as missing-with-issue instead of silently mis-parsed.
 */
class DebugSections(val elf: ElfFile) {
    val info: ByteArray? = elf.sectionData(".debug_info")
    val abbrev: ByteArray? = elf.sectionData(".debug_abbrev")
    val line: ByteArray? = elf.sectionData(".debug_line")
    val lineStr: ByteArray? = elf.sectionData(".debug_line_str")
    val str: ByteArray? = elf.sectionData(".debug_str")
    val strOffsets: ByteArray? = elf.sectionData(".debug_str_offsets")
    val addr: ByteArray? = elf.sectionData(".debug_addr")
    val ranges: ByteArray? = elf.sectionData(".debug_ranges")
    val rnglists: ByteArray? = elf.sectionData(".debug_rnglists")
    val loclists: ByteArray? = elf.sectionData(".debug_loclists")

    val compressed: List<String> = elf.sections
        .filter { it.name.startsWith(".zdebug") }
        .map { it.name }

    fun reader(data: ByteArray?): BoundedReader? = data?.let {
        BoundedReader(it, 0, it.size, if (elf.littleEndian) java.nio.ByteOrder.LITTLE_ENDIAN else java.nio.ByteOrder.BIG_ENDIAN)
    }
}

data class AbbrevDecl(
    val code: Long,
    val tag: Int,
    val hasChildren: Boolean,
    /** attr name -> form code pairs */
    val specs: List<Pair<Int, Int>>,
)

class AbbrevTable(val decls: Map<Long, AbbrevDecl>) {
    fun get(code: Long): AbbrevDecl? = decls[code]
}

object AbbrevParser {
    fun parseTable(data: ByteArray, offset: Long, littleEndian: Boolean): AbbrevTable {
        val r = BoundedReader(
            data,
            base = offset.toInt().coerceAtLeast(0),
            limit0 = data.size,
            order = if (littleEndian) java.nio.ByteOrder.LITTLE_ENDIAN else java.nio.ByteOrder.BIG_ENDIAN,
        )
        val map = LinkedHashMap<Long, AbbrevDecl>()
        while (true) {
            val code = r.uleb()
            if (code == 0L) break
            val tag = r.uleb().toInt()
            val hasChildren = r.u8() == 1
            val specs = ArrayList<Pair<Int, Int>>()
            while (true) {
                val attr = r.uleb().toInt()
                val form = r.uleb().toInt()
                if (attr == 0 && form == 0) break
                specs += attr to form
            }
            map[code] = AbbrevDecl(code, tag, hasChildren, specs)
        }
        return AbbrevTable(map)
    }
}
