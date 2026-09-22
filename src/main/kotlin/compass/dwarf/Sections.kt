package compass.dwarf

/** Resolved DWARF section byte payloads for one object (ELF or dwo). */
class DwarfSections(
    val info: ByteArray? = null,
    val abbrev: ByteArray? = null,
    val line: ByteArray? = null,
    val lineStr: ByteArray? = null,
    val str: ByteArray? = null,
    val strOffsets: ByteArray? = null,
    val ranges: ByteArray? = null,
    val rnglists: ByteArray? = null,
    val addr: ByteArray? = null,
    val abbrevDwo: ByteArray? = null,
    val infoDwo: ByteArray? = null,
    val strDwo: ByteArray? = null,
    val strOffsetsDwo: ByteArray? = null,
    val lineDwo: ByteArray? = null,
    val lineStrDwo: ByteArray? = null,
    val rnglistsDwo: ByteArray? = null,
    val addrDwo: ByteArray? = null,
) {
    fun stringAt(off: Long): String? = readZ(str, off) ?: readZ(strDwo, off)
    fun lineStringAt(off: Long): String? = readZ(lineStr, off) ?: readZ(lineStrDwo, off)
    fun stringAtOrError(off: Long): String =
        stringAt(off) ?: throw compass.binfmt.DwarfParseException("string offset out of bounds: $off")

    companion object {
        fun readZ(data: ByteArray?, off: Long): String? {
            if (data == null || off < 0 || off >= data.size) return null
            val begin = off.toInt()
            var end = begin
            while (end < data.size && data[end].toInt() != 0) end++
            if (end >= data.size) return null
            return String(data, begin, end - begin, Charsets.UTF_8)
        }
    }
}
