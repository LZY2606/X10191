package compass.dwarf

import compass.elf.ElfFile
import java.security.MessageDigest

/** 已导入文件集合的 DWARF section 视图（主文件 + 可选 .dwo/.dwp）。 */
class SectionData(
    val debugInfo: ByteArray?,
    val debugAbbrev: ByteArray?,
    val debugLine: ByteArray?,
    val debugStr: ByteArray?,
    val debugStrOffsets: ByteArray?,
    val debugRanges: ByteArray?,
    val debugRnglists: ByteArray?,
    val debugAddr: ByteArray?,
    val debugLineStr: ByteArray?,
    val debugStrDwo: ByteArray?,
    val debugStrOffsetsDwo: ByteArray?,
    val debugAddrDwo: ByteArray?,
    val debugInfoDwo: ByteArray?,
    val debugAbbrevDwo: ByteArray?,
    val debugLineDwo: ByteArray?,
    val debugRnglistsDwo: ByteArray?,
    /** 本 bundle 中参与解析的文件（用于摘要展示）。 */
    val files: List<ElfFile>
) {
    val isSplit: Boolean get() = debugInfoDwo != null || debugStrDwo != null

    fun readString(section: ByteArray?, offset: Long): String? {
        if (section == null) return null
        val start = offset.toIntSafeR()
        if (start < 0 || start >= section.size) return null
        var end = start
        while (end < section.size && section[end].toInt() != 0) end++
        return String(section, start, end - start, Charsets.UTF_8)
    }

    fun resolveStrx(index: Long, strOffsetsBase: Long, useDwo: Boolean): String? {
        val so = if (useDwo) debugStrOffsetsDwo ?: debugStrOffsets else debugStrOffsets
        val ss = if (useDwo) debugStrDwo ?: debugStr else debugStr
        if (so == null || ss == null) return null
        val entryPos = (strOffsetsBase + index * 4).toIntSafeR()
        if (entryPos < 0 || entryPos + 4 > so.size) return null
        val off = (so[entryPos].toLong() and 0xff) or
            ((so[entryPos + 1].toLong() and 0xff) shl 8) or
            ((so[entryPos + 2].toLong() and 0xff) shl 16) or
            ((so[entryPos + 3].toLong() and 0xff) shl 24)
        return readString(ss, off)
    }

    fun readAddr(index: Long, base: Long, addressSize: Int, useDwo: Boolean): Long? {
        val a = if (useDwo) debugAddrDwo ?: debugAddr else debugAddr
        a ?: return null
        val pos = (base + index * addressSize).toIntSafeR()
        if (pos < 0 || pos + addressSize > a.size) return null
        var v = 0L
        for (i in 0 until addressSize) v = v or ((a[pos + i].toLong() and 0xff) shl (i * 8))
        return v
    }

    companion object {
        fun fromElves(main: ElfFile, dwo: ElfFile? = null, dwp: ElfFile? = null): SectionData {
            fun sec(e: ElfFile?, name: String): ByteArray? = e?.sectionBytes(name)?.takeIf { it.isNotEmpty() }
            return SectionData(
                debugInfo = sec(main, ".debug_info"),
                debugAbbrev = sec(main, ".debug_abbrev"),
                debugLine = sec(main, ".debug_line"),
                debugStr = sec(main, ".debug_str"),
                debugStrOffsets = sec(main, ".debug_str_offsets"),
                debugRanges = sec(main, ".debug_ranges"),
                debugRnglists = sec(main, ".debug_rnglists"),
                debugAddr = sec(main, ".debug_addr"),
                debugLineStr = sec(main, ".debug_line_str"),
                debugStrDwo = sec(dwo, ".debug_str.dwo") ?: sec(dwo, ".debug_str") ?: sec(dwp, ".debug_str.dwo"),
                debugStrOffsetsDwo = sec(dwo, ".debug_str_offsets") ?: sec(dwp, ".debug_str_offsets.dwo"),
                debugAddrDwo = sec(dwo, ".debug_addr"),
                debugInfoDwo = sec(dwo, ".debug_info.dwo") ?: sec(dwo, ".debug_info"),
                debugAbbrevDwo = sec(dwo, ".debug_abbrev.dwo") ?: sec(dwo, ".debug_abbrev"),
                debugLineDwo = sec(dwo, ".debug_line.dwo") ?: sec(dwo, ".debug_line"),
                debugRnglistsDwo = sec(dwo, ".debug_rnglists.dwo") ?: sec(dwo, ".debug_rnglists"),
                files = listOfNotNull(main, dwo, dwp)
            )
        }

        fun sectionDigests(elves: List<ElfFile>): Map<String, SectionDigest> {
            val out = LinkedHashMap<String, SectionDigest>()
            val md5 = MessageDigest.getInstance("SHA-256")
            for (e in elves) {
                for (s in e.sections) {
                    if (!s.name.startsWith(".debug") && s.name != ".note.gnu.build-id") continue
                    val bytes = s.sectionBytes
                    val present = s.type == ElfFile.SHT_NOBITS || bytes != null
                    val digest = if (bytes != null && bytes.isNotEmpty())
                        md5.digest(bytes).joinToString("") { "%02x".format(it) } else ""
                    val head = bytes?.take(16)?.joinToString("") { "%02x".format(it) } ?: ""
                    out.putIfAbsent(s.name, SectionDigest(s.name, s.size, digest, head, present))
                }
            }
            return out
        }
    }
}

internal fun Long.toIntSafeR(): Int {
    if (this < 0 || this > Int.MAX_VALUE) return -1
    return toInt()
}
