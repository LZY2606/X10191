package compass.dwarf

import compass.core.ByteCursor

/** 一次解析所需的全部 debug section（可来自 .debug_* 或 .zdebug，这里只支持未压缩）。 */
class DebugSections(private val elf: ElfImage) {
    private val cache = HashMap<String, ByteCursor?>()

    fun raw(name: String): ByteArray? = elf.section(name)
    fun cursor(name: String): ByteCursor? = cache.getOrPut(name) {
        elf.section(name)?.let { ByteCursor(it) }
    }

    fun cString(name: String, off: Long): String? =
        cursor(name)?.let { return try { it.readCStringAt(off) } catch (e: Exception) { null } }

    /** 对 .debug_info / .debug_types 内的引用按绝对 section 偏移取值。 */
    fun sliceCursor(name: String, off: Long, len: Int): ByteCursor? {
        val b = raw(name) ?: return null
        if (off < 0 || len < 0 || off + len > b.size) return null
        return ByteCursor(b, off.toInt(), len)
    }

    val hasDwarf: Boolean get() = raw(".debug_info") != null || raw(".debug_types") != null
}
