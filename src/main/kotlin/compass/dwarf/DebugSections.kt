package compass.dwarf

import compass.elf.ElfFile

/** 一次解析所需的所有 section 字节；executable 与分离 debug / dwo 可分别提供。 */
class DebugSections(
    val elf: ElfFile?,
    val info: ByteArray?,
    val abbrev: ByteArray?,
    val line: ByteArray?,
    val ranges: ByteArray?,
    val rnglists: ByteArray?,
    val addr: ByteArray?,
    val str: ByteArray?,
    val lineStr: ByteArray?,
    val strOffsets: ByteArray?,
    val sourceName: String
) {
    companion object {
        private fun pick(vararg pairs: Pair<String, ByteArray?>): ByteArray? {
            for ((_, b) in pairs) if (b != null && b.isNotEmpty()) return b
            return null
        }

        fun fromElves(elves: List<ElfFile>): DebugSections {
            fun firstSection(name: String): ByteArray? {
                for (e in elves) {
                    val b = e.sectionBytes(name)
                    if (b != null && b.isNotEmpty()) return b
                }
                return null
            }
            val primary = elves.firstOrNull()
            return DebugSections(
                primary,
                firstSection(".debug_info"),
                firstSection(".debug_abbrev"),
                pick(".debug_line" to firstSection(".debug_line"), ".debug_line" to firstSection(".zdebug_line")),
                firstSection(".debug_ranges"),
                firstSection(".debug_rnglists"),
                firstSection(".debug_addr"),
                firstSection(".debug_str"),
                firstSection(".debug_line_str"),
                firstSection(".debug_str_offsets"),
                elves.joinToString(" + ") { it.fileName }
            )
        }
    }
}
