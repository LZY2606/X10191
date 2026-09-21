package compass.dwarf

import compass.elf.Cursor
import compass.elf.ElfFile
import java.security.MessageDigest

/** A raw [start,end) address interval. Zero-length ranges are retained deliberately. */
data class AddrRange(val start: ULong, val end: ULong) {
    val length: ULong get() = if (end >= start) end - start else 0UL
    fun contains(addr: ULong): Boolean = addr in start until end
}

data class ByteDigest(val sha256: String, val size: Long, val crc32: Long) {
    companion object {
        fun of(bytes: ByteArray): ByteDigest {
            val md = MessageDigest.getInstance("SHA-256").digest(bytes)
            return ByteDigest(md.joinToString("") { "%02x".format(it) }, bytes.size.toLong(), crc32(bytes))
        }

        private val crcTable = LongArray(256).also { tab ->
            for (n in 0 until 256) {
                var c = n.toLong()
                repeat(8) { c = if (c and 1L != 0L) 0xEDB88320L xor (c ushr 1) else c ushr 1 }
                tab[n] = c
            }
        }

        fun crc32(bytes: ByteArray): Long {
            var c = 0xFFFFFFFFL
            for (b in bytes) {
                c = crcTable[((c xor b.toLong()) and 0xFF).toInt()] xor (c ushr 8)
            }
            return c xor 0xFFFFFFFFL
        }
    }
}

data class SectionInfo(
    val name: String,
    val size: Long,
    val addr: ULong,
    val allocated: Boolean,
    val digest: ByteDigest?,
    val present: Boolean = true,
    val error: String? = null,
)

/**
 * Access to every raw debug section the parser reads, plus a place to report
 * recoverable problems ("this section is truncated", "dwo missing"). Conclusions
 * drawn despite such problems are still returned, tagged with warnings.
 */
class DwarfData(val elf: ElfFile) {
    val warnings = mutableListOf<String>()
    val sectionErrors = mutableMapOf<String, String>()
    val sectionInfos = mutableListOf<SectionInfo>()
    val littleEndian: Boolean get() = elf.littleEndian

    private fun gather(name: String): ByteArray? {
        val secs = elf.sectionsNamed(name)
        if (secs.isEmpty()) {
            // .debug_* may also appear as X, not only X, for compressed support elsewhere.
            return null
        }
        if (secs.size > 1) warnings += "section $name appears ${secs.size} times; using the largest"
        val sec = secs.maxByOrNull { it.size }!!
        val digest = if (sec.bytes.isNotEmpty()) ByteDigest.of(sec.bytes) else null
        sectionInfos.add(SectionInfo(name, sec.size, sec.addr, sec.isAllocated, digest))
        return sec.bytes
    }

    val debugAbbrev: ByteArray? = gather(".debug_abbrev")
    val debugInfo: ByteArray? = gather(".debug_info")
    val debugLine: ByteArray? = gather(".debug_line")
    val debugStr: ByteArray? = gather(".debug_str")
    val debugStrOffsets: ByteArray? = gather(".debug_str_offsets")
    val debugAddr: ByteArray? = gather(".debug_addr")
    val debugRanges: ByteArray? = gather(".debug_ranges")
    val debugRnglists: ByteArray? = gather(".debug_rnglists")
    val debugLineStr: ByteArray? = gather(".debug_line_str")
    val debugAbbrevDwo: ByteArray? = gather(".debug_abbrev.dwo")
    val debugInfoDwo: ByteArray? = gather(".debug_info.dwo")
    val debugStrDwo: ByteArray? = gather(".debug_str.dwo")
    val debugStrOffsetsDwo: ByteArray? = gather(".debug_str_offsets.dwo")
    val debugAddrDwo: ByteArray? = gather(".debug_addr.dwo")
    val debugRnglistsDwo: ByteArray? = gather(".debug_rnglists.dwo")
    val debugLineDwo: ByteArray? = gather(".debug_line.dwo")

    fun cursor(bytes: ByteArray): Cursor = Cursor(bytes, 0, bytes.size, littleEndian)

    fun readString(bytes: ByteArray?, offset: Int): String? {
        if (bytes == null || offset < 0 || offset >= bytes.size) return null
        return try {
            Cursor(bytes, offset, bytes.size - offset, littleEndian).zeroString()
        } catch (e: Exception) {
            null
        }
    }

    val sectionMap: Map<String, ByteArray?> = mapOf(
        "debug_abbrev" to debugAbbrev,
        "debug_info" to debugInfo,
        "debug_line" to debugLine,
        "debug_str" to debugStr,
        "debug_str_offsets" to debugStrOffsets,
        "debug_addr" to debugAddr,
        "debug_ranges" to debugRanges,
        "debug_rnglists" to debugRnglists,
        "debug_line_str" to debugLineStr,
        "debug_abbrev.dwo" to debugAbbrevDwo,
        "debug_info.dwo" to debugInfoDwo,
        "debug_str.dwo" to debugStrDwo,
        "debug_str_offsets.dwo" to debugStrOffsetsDwo,
        "debug_addr.dwo" to debugAddrDwo,
        "debug_rnglists.dwo" to debugRnglistsDwo,
        "debug_line.dwo" to debugLineDwo,
    )
}
